# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G038: Zaman Senkronizasyonu ve NTP Güvenlik Denetçisi (NTP & Time Synchronization Auditor)

Bu modül, kurumsal ağlardaki zaman senkronizasyonu durumunu, NTP (Network Time Protocol),
Chrony ve Windows Zaman Servisi (w32time) yapılandırmalarını; saat kayması (Clock Skew / Offset),
Kerberos 5 dakika sınırı, SIEM adli bilişim zaman çizelgesi tutarlılığı, Stratum hiyerarşisi,
NTP Amplification DDoS (monlist) açıkları ve NTS (Network Time Security) ekseninde denetler.
"""

# İşletim sistemi fonksiyonları için os modülünü içeri aktarıyoruz.
import os

# Sistem argümanları ve standart giriş/çıkış akışları için sys modülünü dahil ediyoruz.
import sys

# Yapılandırılmış telemetri verilerini okumak ve dönüştürmek için json kütüphanesini kullanıyoruz.
import json

# Komut satırı bayraklarını güvenle işlemek için argparse modülünü içeri aktarıyoruz.
import argparse

# Zaman hesaplamaları ve ISO standartlarında UTC damgaları için datetime ve timezone modüllerini alıyoruz.
from datetime import datetime, timezone

# Tip belirteçleri ve statik kod analizi için typing yapılarını dahil ediyoruz.
from typing import Dict, Any, List, Optional, Tuple


# Zaman senkronizasyonu telemetrisindeki yapısal bozuklukları bildiren özel istisna sınıfı.
class NtpTelemetryValidationError(Exception):
    """
    NTP ve zaman telemetri verisinde tespit edilen şema ve sınır hataları için istisna.
    """
    # Kurucu metod ile gelen hata açıklamasını temel Exception sınıfına aktarıyoruz.
    def __init__(self, message: str) -> None:
        # Üst sınıf olan Exception kurucusunu çağırıyoruz.
        super().__init__(message)


# Zaman senkronizasyonu ve NTP güvenliğini denetleyen uzman sınıfı tanımlıyoruz.
class NtpTimeSyncAuditor:
    """
    NTP servislerini, saat kaymasını, Kerberos uyumluluğunu ve protokol zaaflarını denetleyen motor.
    """

    # Kerberos kimlik doğrulamasının kabul ettiği azami saat kayması eşiği (300 saniye = 300,000 milisaniye).
    KERBEROS_MAX_TOLERABLE_SKEW_MS: float = 300000.0

    # SIEM korelasyonu ve TLS sertifika doğrulaması için kritik saat kayması eşiği (1000 milisaniye = 1 saniye).
    SIEM_TIMELINE_CRITICAL_SKEW_MS: float = 1000.0

    # Finansal işlemler ve dağıtık veri tabanları için hassas saat kayması uyarısı (100 milisaniye).
    FINANCIAL_AUDIT_WARNING_SKEW_MS: float = 100.0

    # Güvenilir bir NTP istemcisinin iletişim kurması önerilen asgari zaman sunucusu sayısı (Byzantine Fault Tolerance).
    MIN_RECOMMENDED_UPSTREAM_SERVERS: int = 3

    # Sınıf kurucu metodunu başlatıyoruz.
    def __init__(self) -> None:
        # Denetim bulgularını depolayacağımız dinamik listeyi başlatıyoruz.
        self.findings: List[Dict[str, Any]] = []

    # Telemetri girdisinin şematik ve mantıksal geçerliliğini denetleyen fonksiyon.
    def validate_telemetry_schema(self, data: Dict[str, Any]) -> bool:
        """
        Telemetri verisinde zorunlu sistem alanlarını, tipleri ve mantıksal sınırları doğrular.
        """
        # Kök nesnenin sözlük olduğunu kontrol ediyoruz.
        if not isinstance(data, dict):
            # Sözlük değilse doğrulama hatası veriyoruz.
            raise NtpTelemetryValidationError("Telemetri verisi kök düzeyde bir JSON nesnesi (dict) olmalıdır.")

        # Zorunlu systems anahtarının varlığını sınıyoruz.
        if "systems" not in data:
            # Eksik systems anahtarında hata fırlatıyoruz.
            raise NtpTelemetryValidationError("Telemetri verisinde zorunlu 'systems' anahtarı bulunamadı.")

        # systems alanının liste tipinde olduğunu denetliyoruz.
        if not isinstance(data["systems"], list):
            # Liste değilse hata veriyoruz.
            raise NtpTelemetryValidationError("'systems' alanı bir liste (array) olmalıdır.")

        # Her bir sistem kaydını tek tek inceliyoruz.
        for sys_idx, system in enumerate(data["systems"]):
            # Sistem kaydının sözlük olduğunu kontrol ediyoruz.
            if not isinstance(system, dict):
                # Sözlük değilse hata fırlatıyoruz.
                raise NtpTelemetryValidationError(f"Sistem indeksi {sys_idx} geçerli bir JSON nesnesi değil.")

            # Hostname alanının varlığını ve tipini kontrol ediyoruz.
            hostname = system.get("hostname")
            # Hostname string değilse hata fırlatıyoruz.
            if not isinstance(hostname, str):
                # Hata fırlatıyoruz.
                raise NtpTelemetryValidationError(f"Sistem indeksi {sys_idx} için 'hostname' metin olmalıdır.")

            # Stratum değerini alıyoruz.
            stratum = system.get("stratum")
            # Stratum değerinin tamsayı olduğunu denetliyoruz.
            if not isinstance(stratum, int):
                # Sayısal olmayan stratum için hata fırlatıyoruz.
                raise NtpTelemetryValidationError(f"Sistem '{hostname}' için 'stratum' tamsayı olmalıdır.")

            # Stratum sınırlarını kontrol ediyoruz (1 ile 16 arasında olmalıdır).
            if stratum < 1 or stratum > 16:
                # Geçersiz stratum sınırında hata fırlatıyoruz.
                raise NtpTelemetryValidationError(f"Sistem '{hostname}' için 'stratum' 1 ile 16 arasında olmalıdır: {stratum}")

            # Offset değerini alıyoruz.
            offset_ms = system.get("offset_ms")
            # Offset değerinin sayısal (int veya float) olduğunu kontrol ediyoruz.
            if not isinstance(offset_ms, (int, float)):
                # Sayısal olmayan offset için hata veriyoruz.
                raise NtpTelemetryValidationError(f"Sistem '{hostname}' için 'offset_ms' sayısal olmalıdır.")

            # Jitter değerini alıyoruz.
            jitter_ms = system.get("jitter_ms")
            # Jitter değerinin sayısal olduğunu sınıyoruz.
            if not isinstance(jitter_ms, (int, float)):
                # Sayısal olmayan jitter için hata veriyoruz.
                raise NtpTelemetryValidationError(f"Sistem '{hostname}' için 'jitter_ms' sayısal olmalıdır.")

            # Jitter değerinin negatif olamayacağını denetliyoruz.
            if jitter_ms < 0:
                # Negatif jitter mantıksız olduğundan hata veriyoruz.
                raise NtpTelemetryValidationError(f"Sistem '{hostname}' için 'jitter_ms' negatif olamaz: {jitter_ms}")

            # Üst sunucular (upstream_servers) listesini alıyoruz.
            upstream = system.get("upstream_servers", [])
            # Liste olduğunu denetliyoruz.
            if not isinstance(upstream, list):
                # Liste değilse hata veriyoruz.
                raise NtpTelemetryValidationError(f"Sistem '{hostname}' için 'upstream_servers' bir liste olmalıdır.")

        # Tüm doğrulamalardan başarıyla geçildiyse True döndürüyoruz.
        return True

    # Saat kayması (offset) ve Kerberos / TLS risklerini denetleyen fonksiyon.
    def audit_clock_skew_and_authentication(self, systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Saat kaymasını hesaplar; Kerberos 5 dakika kuralını ve TLS/SIEM zaman sapmalarını analiz eder.
        """
        # Yerel bulgu listesini oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her sistemi tarıyoruz.
        for sys_entry in systems:
            # Hostname alıyoruz.
            host = sys_entry.get("hostname", "Bilinmeyen_Host")
            # Saat kaymasını (offset) alıyoruz.
            offset_ms = float(sys_entry.get("offset_ms", 0.0))
            # Mutlak saat kaymasını hesaplıyoruz.
            abs_offset_ms = abs(offset_ms)
            # Saniye cinsine çeviriyoruz.
            offset_seconds = abs_offset_ms / 1000.0

            # 1. Kerberos Kritik Eşik Aşımı (5 Dakika = 300 Saniye):
            if abs_offset_ms >= self.KERBEROS_MAX_TOLERABLE_SKEW_MS:
                # Kritik seviyede Kerberos çöküş bulgusu oluşturuyoruz.
                finding = {
                    "category": "KERBEROS_AUTHENTICATION_FAILURE",
                    "target": host,
                    "severity": "CRITICAL",
                    "title": "Kritik Saat Kayması — Kerberos Kimlik Doğrulama Çöküşü (KRB_AP_ERR_SKEW)",
                    "description": (
                        f"'{host}' sisteminde saat kayması {offset_seconds:.1f} saniyedir ({abs_offset_ms:.1f} ms). "
                        "Active Directory ve Kerberos protokolü, yeniden oynatma saldırılarını (replay attacks) önlemek için "
                        "en fazla 5 dakikalık (300 saniye) saat farkına izin verir. Bu eşik aşıldığında etki alanı kullanıcıları "
                        "oturum açamaz, bilet (TGT) alamaz ve tüm kimlik doğrulama süreçleri felç olur."
                    ),
                    "remediation": "Sistem saatini acilen NTP sunucusuyla eşitleyin (`w32tm /resync` veya `chronyc makestep`)."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 2. SIEM Korelasyonu ve TLS Sertifika Doğrulama Riski (1 Saniye üzeri):
            elif abs_offset_ms >= self.SIEM_TIMELINE_CRITICAL_SKEW_MS:
                # Yüksek önem derecesinde bulgu oluşturuyoruz.
                finding = {
                    "category": "SIEM_AND_TLS_TIME_SKEW",
                    "target": host,
                    "severity": "HIGH",
                    "title": "Yüksek Saat Sapması — Olay Korelasyonu ve Sertifika Riski",
                    "description": (
                        f"'{host}' sisteminde saat kayması {offset_seconds:.2f} saniyedir ({abs_offset_ms:.1f} ms). "
                        "1 saniyeden büyük saat farkları; SIEM üzerinde olay zaman çizelgelerinin (incident timelines) "
                        "ters sıralanmasına, adli analizde delil güvenilirliğinin yitirilmesine ve TLS/X.509 sertifika "
                        "geçerlilik tarihlerinin (NotBefore / NotAfter) hatalı değerlendirilmesine yol açar."
                    ),
                    "remediation": "NTP servisinin sürekli senkronizasyon modunda çalıştığını ve çekirdek saat disiplinini doğrulayın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 3. Finansal ve Dağıtık Veritabanı Sapması (100 ms üzeri):
            elif abs_offset_ms >= self.FINANCIAL_AUDIT_WARNING_SKEW_MS:
                # Uyarı seviyesinde bulgu oluşturuyoruz.
                finding = {
                    "category": "DISTRIBUTED_TRANSACTION_SKEW",
                    "target": host,
                    "severity": "WARNING",
                    "title": "Hassas Zaman Sapması Uyarısı",
                    "description": (
                        f"'{host}' sisteminde saat kayması {abs_offset_ms:.1f} milisaniyedir. "
                        "100 ms üzeri sapmalar dağıtık veritabanlarında işlem çakışmalarına (transaction conflict) sebep olabilir."
                    ),
                    "remediation": "NTP sunucularına olan ağ gecikmesini (RTT) ve jitter değerlerini optimize edin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Stratum seviyesi ve senkronizasyon durumunu denetleyen fonksiyon.
    def audit_stratum_and_synchronization(self, systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Stratum değerlerini ve senkronizasyon durumunu inceler; Stratum 16 veya senkronize olmayan sistemleri yakalar.
        """
        # Yerel bulgu listesini oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Sistemleri dolaşıyoruz.
        for sys_entry in systems:
            # Hostname alıyoruz.
            host = sys_entry.get("hostname", "Bilinmeyen_Host")
            # Senkronizasyon bayrağını alıyoruz.
            is_sync = sys_entry.get("is_synchronized", False)
            # Stratum değerini alıyoruz.
            stratum = int(sys_entry.get("stratum", 16))
            # Referans eşini alıyoruz.
            peer = sys_entry.get("reference_peer", "none")

            # Sistem senkronize değilse veya Stratum 16 (Unsynchronized) ise:
            if not is_sync or stratum == 16:
                # Kritik önemde eşzamanlama kaybı bulgusu oluşturuyoruz.
                finding = {
                    "category": "NTP_SYNCHRONIZATION_LOSS",
                    "target": host,
                    "severity": "CRITICAL",
                    "title": "NTP Senkronizasyon Kaybı — Serbest Dönen Sistem Saati (Stratum 16)",
                    "description": (
                        f"'{host}' sistemi şu anda hiçbir zaman kaynağına senkronize değildir (is_synchronized: false, "
                        f"stratum: {stratum}, referans: '{peer}'). Donanım saati (RTC) zamanla sapacak ve sistem "
                        "tüm güvenlik protokollerinde uyumsuz hale gelecektir."
                    ),
                    "remediation": "NTP servis durumunu kontrol edin (`systemctl status chrony` veya `w32tm /query /status`), UDP 123 erişimini açın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # Eğer Stratum 5'ten büyükse mimari kalite uyarısı veriyoruz:
            elif stratum > 5:
                # Orta seviyede bulgu oluşturuyoruz.
                finding = {
                    "category": "STRATUM_HIERARCHY_QUALITY",
                    "target": host,
                    "severity": "MEDIUM",
                    "title": "Yüksek Stratum Seviyesi — Güvenilirlik Kaybı",
                    "description": (
                        f"'{host}' sistemi Stratum {stratum} seviyesindedir. Stratum mesafesi arttıkça ağ gecikmesi "
                        "ve kümülatif zaman hatası katlanarak artar."
                    ),
                    "remediation": "Sistemi Stratum 1 veya Stratum 2 seviyesindeki güvenilir kurumsal zaman kaynaklarına yönlendirin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Üst sunucu sayısı ve yedeklilik (Redundancy) durumunu denetleyen fonksiyon.
    def audit_upstream_redundancy(self, systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Zaman sunucusu sayısını inceler; tek sunucu kullanımını tek arıza noktası (SPOF) ve sahtecilik riski olarak raporlar.
        """
        # Yerel bulgu listesi başlatıyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her sistemi kontrol ediyoruz.
        for sys_entry in systems:
            # Hostname alıyoruz.
            host = sys_entry.get("hostname", "Bilinmeyen_Host")
            # Üst sunucu listesini alıyoruz.
            servers = sys_entry.get("upstream_servers", [])

            # Eğer üst sunucu sayısı 3'ten az ise (Byzantine Fault Tolerance yok):
            if len(servers) < self.MIN_RECOMMENDED_UPSTREAM_SERVERS:
                # Yüksek seviyede yedeklilik eksikliği bulgusu oluşturuyoruz.
                finding = {
                    "category": "NTP_REDUNDANCY_AND_SPOF",
                    "target": host,
                    "severity": "HIGH",
                    "title": "Yetersiz NTP Üst Sunucu Sayısı — Tek Hata Noktası (SPOF) Riski",
                    "description": (
                        f"'{host}' yalnızca {len(servers)} adet zaman sunucusuyla ({servers}) yapılandırılmıştır. "
                        "Marzullo algoritması ve Bizans hata toleransı (Byzantine Fault Tolerance) gereği, hatalı veya "
                        "saldırıya uğramış bir zaman sunucusunu (false-ticker) tespit edebilmek için en az 3, tercihen 4 bağımsız "
                        "zaman kaynağı tanımlanmalıdır. Tek bir sunucuya bağımlılık, saldırganın sahte zaman paketleriyle sistemi "
                        "kolayca manipüle etmesine yol açar."
                    ),
                    "remediation": "Yapılandırmaya en az 3-4 adet bağımsız NTP sunucusu veya kurumsal havuz adresi ekleyin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # NTP protokol güvenliğini ve DDoS zafiyetlerini (monlist / NTS) denetleyen fonksiyon.
    def audit_protocol_security_and_dos(self, systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        NTP monlist yükseltme saldırılarını (DDoS) ve Network Time Security (NTS) durumunu inceler.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Sistemleri tarıyoruz.
        for sys_entry in systems:
            # Hostname alıyoruz.
            host = sys_entry.get("hostname", "Bilinmeyen_Host")
            # monlist açık mı kontrol ediyoruz.
            monlist_on = sys_entry.get("monlist_enabled", False)
            # NTS veya kriptografik doğrulama var mı kontrol ediyoruz.
            nts_active = sys_entry.get("nts_or_authenticated", False)

            # Eğer monlist etkinse doğrudan HIGH bulgu oluşturuyoruz:
            if monlist_on:
                # DDoS amplifikasyon bulgusu oluşturuyoruz.
                finding = {
                    "category": "NTP_AMPLIFICATION_DDOS_RISK",
                    "target": host,
                    "severity": "HIGH",
                    "title": "NTP 'monlist' Açığı Etkin — DDoS Yükseltme Saldırısı Riski",
                    "description": (
                        f"'{host}' üzerindeki NTP servisinde 'monlist' (Mode 6) sorguları açıktır. "
                        "Saldırganlar IP sahteciliği (IP spoofing) ile küçük bir UDP paketi göndererek sunucudan yüzlerce kat "
                        "büyük yanıtlar ürettirebilir ve hedef hedeflere karşı devasa NTP Yükseltme (Amplification) DDoS "
                        "saldırıları gerçekleştirebilir."
                    ),
                    "remediation": "NTP konfigürasyonuna `disable monitor` ve `noquery` kısıtlamalarını ekleyin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # Eğer NTS veya şifreleme yoksa (düz UDP 123):
            if not nts_active:
                # Ortadaki Adam (MitM) zaman manipülasyonu uyarısı veriyoruz.
                finding = {
                    "category": "UNAUTHENTICATED_TIME_SYNC",
                    "target": host,
                    "severity": "MEDIUM",
                    "title": "Şifresiz ve Doğrulanmamış NTP İletişimi (NTS Eksikliği)",
                    "description": (
                        f"'{host}' zaman senkronizasyonunu düz metin UDP 123 üzerinden yürütmektedir. "
                        "Ağda yerel saldırgan (MitM) ARP zehirlemesi veya DNS saptırmasıyla zaman paketlerini değiştirip "
                        "sistemin saatini geriye veya ileriye alabilir."
                    ),
                    "remediation": "Modern NTS (Network Time Security) protokolüne veya simetrik anahtarlı NTP kimlik doğrulamasına geçin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # İki veya daha fazla sistem arasındaki saat farkını (Cross-Host Skew) karşılaştıran fonksiyon.
    def compare_multi_system_timeline(self, systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sistemler arası saat farkını karşılaştırarak dağıtık sistem SIEM korelasyon riskini tespit eder.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Eğer incelenen sistem sayısı 2'den az ise karşılaştırma yapılamaz.
        if len(systems) < 2:
            # Boş liste dönüyoruz.
            return local_findings

        # Sistem çiftlerini karşılaştırıyoruz.
        for i in range(len(systems)):
            # İkinci indeksi başlatıyoruz.
            for j in range(i + 1, len(systems)):
                # Birinci sistemi alıyoruz.
                sys_a = systems[i]
                # İkinci sistemi alıyoruz.
                sys_b = systems[j]

                # İki sistemin offset değerlerini alıyoruz.
                offset_a = float(sys_a.get("offset_ms", 0.0))
                offset_b = float(sys_b.get("offset_ms", 0.0))

                # İki sistem arasındaki mutlak saat farkını hesaplıyoruz.
                delta_ms = abs(offset_a - offset_b)

                # Eğer sistemler arası fark 1 saniyeden (1000 ms) büyükse:
                if delta_ms >= self.SIEM_TIMELINE_CRITICAL_SKEW_MS:
                    # Dağıtık korelasyon bulgusu oluşturuyoruz.
                    delta_sec = delta_ms / 1000.0
                    # Bulgu sözlüğünü hazırlıyoruz.
                    finding = {
                        "category": "DISTRIBUTED_TIMELINE_MISMATCH",
                        "target": f"{sys_a.get('hostname')} <-> {sys_b.get('hostname')}",
                        "severity": "CRITICAL" if delta_ms >= self.KERBEROS_MAX_TOLERABLE_SKEW_MS else "HIGH",
                        "title": "Sistemler Arası Kritik Zaman Uyumsuzluğu",
                        "description": (
                            f"'{sys_a.get('hostname')}' ile '{sys_b.get('hostname')}' sistemleri arasında "
                            f"{delta_sec:.1f} saniyelik ({delta_ms:.1f} ms) saat farkı tespit edildi. "
                            "Bu durum dağıtık sistemlerde kimlik doğrulama reddine, log analizinde olay sıralamasının "
                            "çökmesine ve adli bilişim zincirinin (chain of custody) bozulmasına yol açar."
                        ),
                        "remediation": "Tüm etki alanı ve DMZ sunucularını ortak bir kurumsal iç NTP kaynağına bağlayın."
                    }
                    # Listeye ekliyoruz.
                    local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Tüm denetim adımlarını icra eden ve güvenlik puanını hesaplayan ana metod.
    def execute_full_audit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tüm denetimleri çalıştırır, puanı hesaplar ve yapılandırılmış rapor döner.
        """
        # Telemetri şemasını doğruluyoruz.
        self.validate_telemetry_schema(data)

        # Sistem listesini alıyoruz.
        systems = data.get("systems", [])

        # Önceki bulguları sıfırlıyoruz.
        self.findings = []

        # 1. Saat kayması ve Kerberos kimlik denetimi:
        self.findings.extend(self.audit_clock_skew_and_authentication(systems))

        # 2. Stratum ve senkronizasyon durumu denetimi:
        self.findings.extend(self.audit_stratum_and_synchronization(systems))

        # 3. Üst sunucu yedeklilik denetimi:
        self.findings.extend(self.audit_upstream_redundancy(systems))

        # 4. Protokol güvenliği ve monlist DDoS denetimi:
        self.findings.extend(self.audit_protocol_security_and_dos(systems))

        # 5. Sistemler arası zaman karşılaştırma denetimi:
        self.findings.extend(self.compare_multi_system_timeline(systems))

        # Başlangıç puanı 100 olarak belirlenir.
        security_score = 100
        # Kritik bulguları sayıyoruz.
        crit_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        # Yüksek seviyeli bulguları sayıyoruz.
        high_count = sum(1 for f in self.findings if f["severity"] == "HIGH")
        # Orta seviyeli bulguları sayıyoruz.
        med_count = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        # Uyarı seviyeli bulguları sayıyoruz.
        warn_count = sum(1 for f in self.findings if f["severity"] == "WARNING")

        # Puan kırma kuralları: Kritik -20, Yüksek -10, Orta -5, Uyarı -2.
        security_score -= (crit_count * 20)
        security_score -= (high_count * 10)
        security_score -= (med_count * 5)
        security_score -= (warn_count * 2)

        # Puanın 0'ın altına inmesini engelliyoruz.
        security_score = max(0, security_score)

        # Durum belirteci atıyoruz.
        overall_status = "SECURE" if security_score >= 85 else ("WARNING" if security_score >= 60 else "CRITICAL")

        # Rapor sözlüğünü döndürüyoruz.
        return {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "audit_metadata": data.get("audit_metadata", {}),
            "security_score": security_score,
            "overall_status": overall_status,
            "metrics": {
                "total_systems_analyzed": len(systems),
                "critical_findings": crit_count,
                "high_findings": high_count,
                "medium_findings": med_count,
                "warning_findings": warn_count,
                "total_findings": len(self.findings)
            },
            "findings": self.findings
        }

    # Denetim sonucunu Markdown formatına çeviren raporlama fonksiyonu.
    def export_markdown_report(self, audit_result: Dict[str, Any]) -> str:
        """
        Denetim sonucunu insan tarafından okunabilir Markdown formatında biçimlendirir.
        """
        # Satır listesi başlatıyoruz.
        lines: List[str] = []

        # Lisans başlığını ekliyoruz.
        lines.append("<!--")
        lines.append("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR")
        lines.append("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)")
        lines.append("Bu yazılım ve ilgili tüm dosyalar ('Yazılım') yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.")
        lines.append("-->\n")

        # Rapor başlığı:
        lines.append("# Zaman Senkronizasyonu ve NTP Güvenlik Denetim Raporu\n")

        # Üstbilgiler:
        lines.append(f"**Denetim Tarihi:** `{audit_result.get('audit_timestamp', 'N/A')}`  ")
        lines.append(f"**Güvenlik Puanı:** `{audit_result.get('security_score', 0)} / 100`  ")
        lines.append(f"**Genel Durum:** `{audit_result.get('overall_status', 'UNKNOWN')}`\n")

        # Metrik tablosu:
        metrics = audit_result.get("metrics", {})
        lines.append("## 📊 Denetim Metrikleri Özeti\n")
        lines.append("| Metrik | Değer |")
        lines.append("| :--- | :---: |")
        lines.append(f"| İncelenen Sistem Sayısı | {metrics.get('total_systems_analyzed', 0)} |")
        lines.append(f"| Kritik (CRITICAL) Bulgular | {metrics.get('critical_findings', 0)} |")
        lines.append(f"| Yüksek (HIGH) Seviye Bulgular | {metrics.get('high_findings', 0)} |")
        lines.append(f"| Orta (MEDIUM) Seviye Bulgular | {metrics.get('medium_findings', 0)} |")
        lines.append(f"| Uyarı (WARNING) Bulgular | {metrics.get('warning_findings', 0)} |")
        lines.append(f"| **Toplam Güvenlik Bulgusu** | **{metrics.get('total_findings', 0)}** |\n")

        # Bulgular bölümü:
        lines.append("## 🔍 Güvenlik Bulguları ve İyileştirme Reçetesi\n")
        findings = audit_result.get("findings", [])

        # Eğer bulgu yoksa temiz bildiriyoruz.
        if not findings:
            lines.append("✅ *Tüm sistemler zaman senkronizasyonu ve NTP güvenlik standartlarına tam uygundur.*\n")
        else:
            # Bulguları numaralandırarak ekliyoruz.
            for i, f in enumerate(findings, 1):
                lines.append(f"### {i}. [{f['severity']}] {f['title']}")
                lines.append(f"- **Hedef:** `{f['target']}`")
                lines.append(f"- **Kategori:** `{f['category']}`")
                lines.append(f"- **Açıklama:** {f['description']}")
                lines.append(f"- **🛡️ İyileştirme:** {f['remediation']}\n")

        # Birleştirip metin olarak döndürüyoruz.
        return "\n".join(lines)


# Komut satırı giriş noktası:
def main() -> None:
    """
    CLI yürütme giriş noktası.
    """
    # Windows konsolunda UTF-8 çıktı güvencesi sağlıyoruz.
    if hasattr(sys.stdout, "reconfigure"):
        # Standart çıktıyı UTF-8 yapıyoruz.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # Standart hatayı da UTF-8 yapıyoruz.
    if hasattr(sys.stderr, "reconfigure"):
        # Standart hata akışını ayarlıyoruz.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    # Argüman ayrıştırıcı tanımlıyoruz.
    parser = argparse.ArgumentParser(description="G038: Zaman Senkronizasyonu ve NTP Güvenlik Denetçisi")
    # Telemetri yolu argümanı:
    parser.add_argument("--telemetry", type=str, required=True, help="İncelenecek JSON telemetri dosyasının yolu")
    # Çıktı dosyası opsiyonel argümanı:
    parser.add_argument("--output", type=str, default="", help="Markdown raporunun kaydedileceği dosya yolu")

    # Argümanları ayrıştırıyoruz.
    args = parser.parse_args()

    # Dosya varlık kontrolü:
    if not os.path.exists(args.telemetry):
        # Hata mesajı yazıp çıkıyoruz.
        print(f"HATA: Telemetri dosyası bulunamadı: {args.telemetry}", file=sys.stderr)
        # Çıkış kodu 1 ile sonlandırıyoruz.
        sys.exit(1)

    # Telemetri dosyasını açıyoruz.
    with open(args.telemetry, "r", encoding="utf-8") as f:
        # JSON ayrıştırıyoruz.
        telemetry_data = json.load(f)

    # Denetçi nesnesini oluşturuyoruz.
    auditor = NtpTimeSyncAuditor()
    # Tam denetimi çalıştırıyoruz.
    audit_result = auditor.execute_full_audit(telemetry_data)
    # Raporu üretiyoruz.
    report_md = auditor.export_markdown_report(audit_result)

    # Ekrana basıyoruz.
    print(report_md)

    # Çıktı dosyası istendiyse kaydediyoruz:
    if args.output:
        # Dosyaya yazıyoruz.
        with open(args.output, "w", encoding="utf-8") as out_f:
            # İçeriği kaydediyoruz.
            out_f.write(report_md)
        # Bilgi mesajı yazdırıyoruz.
        print(f"\nRapor başarıyla kaydedildi: {args.output}")


# Doğrudan icra durumunda main çağrılır.
if __name__ == "__main__":
    # main'i çağırıyoruz.
    main()
