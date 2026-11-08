# -*- coding: utf-8 -*-
"""
Uç Nokta Risk Panosu ve Güvenlik Duruşu Yönetimi (Endpoint Risk Dashboard / Posture Management)
Hafta 22 / Mini Proje 21 - Gün 153

Bu motor; kurumsal filodaki uç noktaların (Windows, Linux, macOS) telemetrilerini
(EDR sağlığı, Uygulama Kontrolü/Sandbox, Disk Şifreleme & TPM, Yedek Güvenliği,
Yapılandırma Sapması ve Zafiyet/Yama Durumu) analiz ederek çok vektörlü risk
skorları hesaplar, filo seviyesinde özetler ve yönetici panosu üretir.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import json
import math


class RiskBand(str, Enum):
    """Uç nokta risk seviyesi sınıflandırması."""
    # 0.0 - 19.9 arası: Düşük risk, sağlam güvenlik duruşu
    LOW = "DUSUK"
    # 20.0 - 44.9 arası: Orta risk, iyileştirme tavsiye edilir
    MEDIUM = "ORTA"
    # 45.0 - 69.9 arası: Yüksek risk, acil müdahale gerekir
    HIGH = "YUKSEK"
    # 70.0 - 100.0 arası: Kritik risk, sistem derhal izole edilmelidir
    CRITICAL = "KRITIK"


@dataclass
class EndpointTelemetry:
    """Tek bir uç noktanın çok vektörlü güvenlik telemetrisi."""
    # Uç nokta benzersiz ana bilgisayar adı
    hostname: str
    # Uç noktanın birincil IP adresi
    ip_address: str
    # İşletim sistemi platformu ve sürümü
    operating_system: str
    # Cihazın ait olduğu kurumsal departman
    department: str
    # Kritik varlık mı (Etki Alanı Denetleyicisi, DB, Yönetici vb.)
    is_critical_asset: bool
    
    # EDR / AV telemetri vektörü
    edr_installed: bool
    edr_running: bool
    tamper_protection: bool
    signatures_age_hours: int
    
    # Uygulama denetimi ve sandbox vektörü
    app_control_mode: str  # "Enforce", "Audit", "Disabled"
    unapproved_executables_detected: int
    
    # Disk şifreleme ve TPM donanım kökü vektörü
    disk_encrypted: bool
    tpm_version: str  # "2.0", "1.2", "None"
    pcr_binding_valid: bool
    recovery_key_escrowed: bool
    
    # Yedekleme ve kurtarma doğrulaması vektörü
    last_backup_hours_ago: int
    backup_immutable: bool
    last_restore_tested: bool
    
    # Yapılandırma sapması ve kimlik hijyeni vektörü
    cis_compliance_percentage: float  # 0.0 - 100.0
    unauthorized_local_admins: int
    uac_or_aslr_active: bool
    
    # Zafiyet ve yama yönetimi vektörü
    critical_cves: int
    high_cves: int
    days_since_os_patch: int


@dataclass
class VectorScores:
    """Farklı güvenlik alanlarının ceza puanı dağılımı (0-100 arası ceza puanı)."""
    # EDR ve telemetri zayıflığı ceza puanı
    edr_penalty: float
    # Disk şifreleme ve TPM donanım açığı ceza puanı
    disk_encryption_penalty: float
    # Yedekleme eksikliği ve değiştirilebilirlik açığı ceza puanı
    backup_penalty: float
    # CIS sıkılaştırma sapması ve kimlik açığı ceza puanı
    hardening_penalty: float
    # Zafiyet ve gecikmiş yama açığı ceza puanı
    vulnerability_penalty: float
    # Uygulama kontrolü eksikliği ceza puanı
    app_control_penalty: float


@dataclass
class HostRiskAssessment:
    """Tek bir uç noktanın risk değerlendirme çıktısı."""
    # Değerlendirilen ana bilgisayar adı
    hostname: str
    # Cihazın IP adresi
    ip_address: str
    # Cihaz departmanı
    department: str
    # İşletim sistemi
    operating_system: str
    # Kritik varlık bayrağı
    is_critical: bool
    # Hesaplanan nihai risk skoru (0.0 - 100.0)
    risk_score: float
    # Risk seviyesi bandı
    risk_band: RiskBand
    # Güvenlik duruş puanı (100 - risk_score)
    posture_score: float
    # Vektör bazlı ceza puanı dökümü
    vector_scores: VectorScores
    # Uç nokta için tespit edilen kritik bulgular listesi
    findings: List[str]
    # Acil öncelikli iyileştirme adımları
    remediations: List[str]


@dataclass
class FleetRiskDashboard:
    """Tüm kurumsal filonun güvenlik duruşu ve risk özeti."""
    # Toplam taranan uç nokta sayısı
    total_endpoints: int
    # Düşük riskli uç nokta sayısı
    low_risk_count: int
    # Orta riskli uç nokta sayısı
    medium_risk_count: int
    # Yüksek riskli uç nokta sayısı
    high_risk_count: int
    # Kritik riskli uç nokta sayısı
    critical_risk_count: int
    # Filo genel ortalama risk skoru
    fleet_average_risk: float
    # Filo genel ortalama güvenlik duruş skoru
    fleet_average_posture: float
    # Kritik varlıkların ortalama risk skoru
    critical_assets_average_risk: float
    # Departman bazlı risk sıralaması
    department_risk_summary: Dict[str, float]
    # En yüksek riskli ilk 5 uç nokta listesi
    top_riskiest_hosts: List[Dict[str, Any]]
    # En yaygın sistemik güvenlik açıkları
    systemic_weaknesses: List[str]
    # Tüm uç noktaların detaylı değerlendirme listesi
    host_assessments: List[HostRiskAssessment] = field(default_factory=list)


class EndpointRiskEngine:
    """Çok vektörlü uç nokta risk analizi ve filo duruş hesaplama motoru."""

    # EDR vektör ağırlığı (%25)
    WEIGHT_EDR = 0.25
    # Disk şifreleme ve TPM ağırlığı (%15)
    WEIGHT_DISK = 0.15
    # Yedekleme ve kurtarma ağırlığı (%15)
    WEIGHT_BACKUP = 0.15
    # Sıkılaştırma ve sapma ağırlığı (%20)
    WEIGHT_HARDENING = 0.20
    # Zafiyet ve yama ağırlığı (%15)
    WEIGHT_VULNERABILITY = 0.15
    # Uygulama kontrolü ağırlığı (%10)
    WEIGHT_APP_CONTROL = 0.10

    def assess_host(self, host: EndpointTelemetry) -> HostRiskAssessment:
        """Tek bir uç noktanın güvenlik telemetrisini değerlendirir ve risk skoru üretir."""
        # Tespit edilen bulguları saklamak için dinamik liste başlatılır
        findings: List[str] = []
        # Öncelikli iyileştirme adımlarını saklamak için liste başlatılır
        remediations: List[str] = []

        # -------------------------------------------------------------
        # 1. EDR & Telemetri Vektörü (0 - 100 Ceza Puanı)
        # -------------------------------------------------------------
        # EDR ceza puanı başlangıçta sıfır kabul edilir
        edr_pen = 0.0
        # Ajan hiç kurulu değilse en ağır ceza uygulanır
        if not host.edr_installed:
            # EDR ajanı bulunamadı cezası
            edr_pen += 60.0
            # Kritik bulgu listesine eklenir
            findings.append("EDR ajanı yüklü değil (Uç nokta telemetrisi tamamen kör).")
            # Öncelikli aksiyon önerisi eklenir
            remediations.append("Merkezi dağıtım ile kurumsal EDR ajanını derhal yükleyin.")
        elif not host.edr_running:
            # Ajan yüklü ama servisi durdurulmuş
            edr_pen += 45.0
            # Bulgu eklenir
            findings.append("EDR servisi çalışmıyor veya durdurulmuş.")
            # İyileştirme önerisi
            remediations.append("EDR servisini 'Otomatik (Gecikmeli Başlatma)' moduna alıp başlatın.")
        
        # Kurcalamaya karşı koruma kapalıysa ceza eklenir
        if host.edr_installed and not host.tamper_protection:
            # Tamper protection kapalı cezası
            edr_pen += 20.0
            # Bulgu listesine işlenir
            findings.append("EDR Kurcalamaya Karşı Koruma (Tamper Protection) devre dışı.")
            # İyileştirme aksiyonu
            remediations.append("GPO veya EDR konsolundan Tamper Protection politikasını zorlayın.")

        # İmza ve kural tabanı güncelliği kontrol edilir
        if host.signatures_age_hours > 72:
            # 3 günden eski imzalara yüksek ceza
            edr_pen += 25.0
            # Bulgu eklenir
            findings.append(f"Zararlı yazılım imza veri tabanı {host.signatures_age_hours} saat eski (>72 saat).")
            # İyileştirme önerisi
            remediations.append("İmza güncelleme sunucusu bağlantısını kontrol edin ve anlık güncelleme tetikleyin.")
        elif host.signatures_age_hours > 24:
            # 24 saatten eski imzalara orta ceza
            edr_pen += 10.0
        
        # EDR ceza puanı 100 ile sınırlandırılır
        edr_pen = min(100.0, edr_pen)

        # -------------------------------------------------------------
        # 2. Disk Şifreleme & TPM Donanım Kökü (0 - 100 Ceza Puanı)
        # -------------------------------------------------------------
        # Disk şifreleme ceza puanı sıfırlanır
        disk_pen = 0.0
        # Disk tamamen şifresiz ise kritik ceza verilir
        if not host.disk_encrypted:
            # Şifresiz disk cezası
            disk_pen += 70.0
            # Kritik bulgu eklenir
            findings.append("Sistem diski şifrelenmemiş (BitLocker / LUKS kapalı).")
            # İyileştirme adımı
            remediations.append("Sistem biriminde XTS-AES-256 disk şifrelemeyi derhal etkinleştirin.")
        else:
            # Disk şifreli ama TPM yoksa veya eskiyse ceza eklenir
            if host.tpm_version != "2.0":
                # TPM 2.0 eksikliği cezası
                disk_pen += 20.0
                # Bulgu eklenir
                findings.append(f"TPM 2.0 donanım kökü eksik (Mevcut sürüm: {host.tpm_version}).")
            # PCR bağlama doğrulanmamışsa ceza eklenir
            if not host.pcr_binding_valid:
                # PCR doğrulama hatası cezası
                disk_pen += 15.0
                # Bulgu eklenir
                findings.append("TPM PCR 0,2,4,7 ölçüm zinciri doğrulanmamış (Önyükleme kurcalanma riski).")
            # Kurtarma anahtarı yedeklenmemişse ceza eklenir
            if not host.recovery_key_escrowed:
                # Kurtarma anahtarı escrow eksikliği cezası
                disk_pen += 15.0
                # Bulgu eklenir
                findings.append("Disk kurtarma anahtarı (Recovery Key) AD/Entra ID üzerinde yedeklenmemiş.")
                # İyileştirme önerisi
                remediations.append("BitLocker kurtarma anahtarını merkezi etki alanına yedekleyin.")
        
        # Disk ceza puanı 100 ile tavanlanır
        disk_pen = min(100.0, disk_pen)

        # -------------------------------------------------------------
        # 3. Yedekleme ve Kurtarma Doğrulaması (0 - 100 Ceza Puanı)
        # -------------------------------------------------------------
        # Yedek ceza puanı sıfırlanır
        backup_pen = 0.0
        # Son yedekleme 1 haftadan (168 saat) eskiyse yüksek ceza
        if host.last_backup_hours_ago > 168:
            # 1 haftayı aşan yedeksizlik cezası
            backup_pen += 60.0
            # Bulgu eklenir
            findings.append(f"Son başarılı yedekleme {host.last_backup_hours_ago} saat önce alınmış (>168 saat).")
            # İyileştirme adımı
            remediations.append("Yedekleme ajanını kontrol ederek tam/artımlı yedekleme görevini tetikleyin.")
        elif host.last_backup_hours_ago > 24:
            # 24 saati aşan yedeksizlik cezası
            backup_pen += 30.0
            # Bulgu eklenir
            findings.append(f"Son yedekleme 24 saati aşmış ({host.last_backup_hours_ago} saat önce).")

        # Yedek havuzu değiştirilemez (WORM/Immutable) değilse fidye risk cezası
        if not host.backup_immutable:
            # Değiştirilemez depolama eksikliği cezası
            backup_pen += 25.0
            # Bulgu eklenir
            findings.append("Yedek depolama birimi değiştirilemez (WORM/Immutable) değil; fidye yazılımı imhasına açık.")
            # İyileştirme önerisi
            remediations.append("S3 Object Lock COMPLIANCE modu veya WORM yedek deposunu devreye alın.")

        # Geri yükleme testi yapılmamışsa ceza eklenir
        if not host.last_restore_tested:
            # Geri yükleme doğrulanmamış cezası
            backup_pen += 15.0
            # Bulgu eklenir
            findings.append("Yedekten geri yükleme (Restore Drill) periyodik olarak doğrulanmamış.")
        
        # Yedek ceza puanı 100 ile sınırlandırılır
        backup_pen = min(100.0, backup_pen)

        # -------------------------------------------------------------
        # 4. Sıkılaştırma & Sapma & Kimlik Hijyeni (0 - 100 Ceza Puanı)
        # -------------------------------------------------------------
        # Sıkılaştırma ceza puanı sıfırlanır
        hard_pen = 0.0
        # CIS uyumluluk yüzdesi düşüklüğü cezası orantısal hesaplanır
        cis_deficit = max(0.0, 100.0 - host.cis_compliance_percentage)
        # CIS uyumsuzluk oranı ceza puanına dönüştürülür
        hard_pen += cis_deficit * 0.5

        # Yetkisiz yerel yönetici hesabı varsa ağır ceza kesilir
        if host.unauthorized_local_admins > 0:
            # Her yetkisiz yönetici hesabı için 20 puan ceza
            admin_penalty = min(50.0, host.unauthorized_local_admins * 20.0)
            # Ceza eklenir
            hard_pen += admin_penalty
            # Bulgu eklenir
            findings.append(f"Yerel Administrators grubunda {host.unauthorized_local_admins} yetkisiz hesap tespit edildi.")
            # İyileştirme adımı
            remediations.append("Yetkisiz yerel yönetici hesaplarını tespit edip Administrators grubundan çıkarın.")

        # UAC veya ASLR kapalıysa savunma zayıflatma cezası
        if not host.uac_or_aslr_active:
            # Savunma zayıflatma cezası
            hard_pen += 30.0
            # Bulgu eklenir
            findings.append("Kritik çekirdek savunması (UAC / ASLR) devre dışı bırakılmış.")
            # İyileştirme adımı
            remediations.append("UAC (EnableLUA=1) veya ASLR (randomize_va_space=2) zorlamasını yeniden açın.")

        # Sıkılaştırma ceza puanı 100 ile sınırlandırılır
        hard_pen = min(100.0, hard_pen)

        # -------------------------------------------------------------
        # 5. Zafiyet & Yama Durumu (0 - 100 Ceza Puanı)
        # -------------------------------------------------------------
        # Zafiyet ceza puanı sıfırlanır
        vuln_pen = 0.0
        # Kritik CVE başına 25 puan ceza
        vuln_pen += min(60.0, host.critical_cves * 25.0)
        # Kritik zafiyet varsa bulgu eklenir
        if host.critical_cves > 0:
            # Bulgu eklenir
            findings.append(f"{host.critical_cves} adet çözülmemiş KRİTİK CVE zafiyeti mevcut.")
            # İyileştirme adımı
            remediations.append("Kritik CVE güvenlik yamalarını acil bakım döngüsünde uygulayın.")

        # Yüksek CVE başına 10 puan ceza
        vuln_pen += min(30.0, host.high_cves * 10.0)
        # Yüksek zafiyet varsa bulgu eklenir
        if host.high_cves > 0:
            # Bulgu eklenir
            findings.append(f"{host.high_cves} adet YÜKSEK seviye CVE zafiyeti mevcut.")

        # Yama gecikmesi kontrol edilir (30 günden eski yamalar)
        if host.days_since_os_patch > 60:
            # 60 günden eski yama cezası
            vuln_pen += 25.0
            # Bulgu eklenir
            findings.append(f"İşletim sistemi güncellemesi {host.days_since_os_patch} gündür yapılmamış (>60 gün).")
            # İyileştirme adımı
            remediations.append("İşletim sistemi kümülatif güvenlik güncelleştirmelerini yükleyin.")
        elif host.days_since_os_patch > 30:
            # 30 günden eski yama cezası
            vuln_pen += 10.0
            # Bulgu eklenir
            findings.append(f"İşletim sistemi güvenlik güncellemesi 30 günü aşmış ({host.days_since_os_patch} gün).")

        # Zafiyet ceza puanı 100 ile sınırlandırılır
        vuln_pen = min(100.0, vuln_pen)

        # -------------------------------------------------------------
        # 6. Uygulama Kontrolü Vektörü (0 - 100 Ceza Puanı)
        # -------------------------------------------------------------
        # Uygulama kontrolü ceza puanı sıfırlanır
        app_pen = 0.0
        # Uygulama denetim modu değerlendirilir
        if host.app_control_mode == "Disabled":
            # Tamamen kapalıysa yüksek ceza
            app_pen += 60.0
            # Bulgu eklenir
            findings.append("Uygulama beyaz listesi (AppLocker/WDAC) devre dışı.")
            # İyileştirme adımı
            remediations.append("AppLocker veya WDAC politikasını en azından 'Denetim' modunda başlatın.")
        elif host.app_control_mode == "Audit":
            # Yalnızca denetim modundaysa orta ceza
            app_pen += 20.0

        # Onaysız çalıştırılabilir dosya tespit edilmişse ceza eklenir
        if host.unapproved_executables_detected > 0:
            # Onaysız dosya cezası
            app_pen += min(40.0, host.unapproved_executables_detected * 10.0)
            # Bulgu eklenir
            findings.append(f"{host.unapproved_executables_detected} adet onaylanmamış/engellenmesi gereken çalıştırılabilir dosya saptandı.")
            # İyileştirme önerisi
            remediations.append("Onaysız ikili dosyaları karantinaya alın ve hash kurallarını güncelleyin.")

        # Uygulama ceza puanı 100 ile tavanlanır
        app_pen = min(100.0, app_pen)

        # -------------------------------------------------------------
        # Ağırlıklı Risk Skoru Birleştirmesi (Weighted Fusion)
        # -------------------------------------------------------------
        # Ağırlıklı toplam hesaplanır
        base_risk_score = (
            (edr_pen * self.WEIGHT_EDR) +
            (disk_pen * self.WEIGHT_DISK) +
            (backup_pen * self.WEIGHT_BACKUP) +
            (hard_pen * self.WEIGHT_HARDENING) +
            (vuln_pen * self.WEIGHT_VULNERABILITY) +
            (app_pen * self.WEIGHT_APP_CONTROL)
        )

        # Kritik varlık ise (Domain Controller, Finans DB vb.) risk çarpanı uygulanır
        if host.is_critical_asset:
            # Kritik varlıklarda zafiyetlerin iş etkisi daha yıkıcıdır (+%15 çarpan)
            base_risk_score = min(100.0, base_risk_score * 1.15)

        # Risk skoru 0-100 arasında sınırlandırılır
        final_risk_score = round(max(0.0, min(100.0, base_risk_score)), 1)
        # Güvenlik duruş puanı (100 - risk)
        posture_score = round(max(0.0, 100.0 - final_risk_score), 1)

        # Risk bandı belirlenir
        if final_risk_score < 20.0:
            # Düşük risk
            risk_band = RiskBand.LOW
        elif final_risk_score < 45.0:
            # Orta risk
            risk_band = RiskBand.MEDIUM
        elif final_risk_score < 70.0:
            # Yüksek risk
            risk_band = RiskBand.HIGH
        else:
            # Kritik risk
            risk_band = RiskBand.CRITICAL

        # Vektör skorları nesnesi oluşturulur
        vector_scores = VectorScores(
            edr_penalty=round(edr_pen, 1),
            disk_encryption_penalty=round(disk_pen, 1),
            backup_penalty=round(backup_pen, 1),
            hardening_penalty=round(hard_pen, 1),
            vulnerability_penalty=round(vuln_pen, 1),
            app_control_penalty=round(app_pen, 1),
        )

        # Uç nokta değerlendirme nesnesi döndürülür
        return HostRiskAssessment(
            hostname=host.hostname,
            ip_address=host.ip_address,
            department=host.department,
            operating_system=host.operating_system,
            is_critical=host.is_critical_asset,
            risk_score=final_risk_score,
            risk_band=risk_band,
            posture_score=posture_score,
            vector_scores=vector_scores,
            findings=findings,
            remediations=remediations,
        )

    def assess_fleet(self, telemetry_list: List[EndpointTelemetry]) -> FleetRiskDashboard:
        """Tüm uç noktaları tarar, filo seviyesinde özetler ve yönetici panosu oluşturur."""
        # Telemetri listesi boş ise ValueError fırlatılır
        if not telemetry_list:
            raise ValueError("Filo telemetri listesi boş olamaz.")

        # Değerlendirme sonuçlarını saklayacak liste
        assessments: List[HostRiskAssessment] = []
        # Risk seviyesi sayaçları başlatılır
        low_count = 0
        med_count = 0
        high_count = 0
        crit_count = 0

        # Skor toplamları
        total_risk_sum = 0.0
        critical_assets_risk_sum = 0.0
        critical_assets_count = 0

        # Departman bazlı skor toplama sözlükleri
        dept_scores: Dict[str, List[float]] = {}
        # Zafiyet frekans sayacı
        weakness_counts: Dict[str, int] = {}

        # Her bir uç nokta sırayla değerlendirilir
        for telemetry in telemetry_list:
            # Tekil uç nokta değerlendirmesi yapılır
            assessment = self.assess_host(telemetry)
            # Listeye eklenir
            assessments.append(assessment)

            # Risk toplamı artırılır
            total_risk_sum += assessment.risk_score

            # Kritik varlık kontrolü
            if assessment.is_critical:
                critical_assets_risk_sum += assessment.risk_score
                critical_assets_count += 1

            # Risk bandı sayaçları güncellenir
            if assessment.risk_band == RiskBand.LOW:
                low_count += 1
            elif assessment.risk_band == RiskBand.MEDIUM:
                med_count += 1
            elif assessment.risk_band == RiskBand.HIGH:
                high_count += 1
            elif assessment.risk_band == RiskBand.CRITICAL:
                crit_count += 1

            # Departman listesi güncellenir
            dept = assessment.department
            if dept not in dept_scores:
                dept_scores[dept] = []
            dept_scores[dept].append(assessment.risk_score)

            # Bulgulardan sistemik zayıflık tespiti
            for finding in assessment.findings:
                # Zayıflık frekansı artırılır
                weakness_counts[finding] = weakness_counts.get(finding, 0) + 1

        # Filo toplam cihaz sayısı
        total_hosts = len(telemetry_list)
        # Filo genel ortalama risk skoru hesaplanır
        fleet_avg_risk = round(total_risk_sum / total_hosts, 1)
        # Filo genel ortalama duruş puanı (100 - risk)
        fleet_avg_posture = round(100.0 - fleet_avg_risk, 1)

        # Kritik varlıkların ortalama risk skoru hesaplanır
        if critical_assets_count > 0:
            crit_avg_risk = round(critical_assets_risk_sum / critical_assets_count, 1)
        else:
            crit_avg_risk = 0.0

        # Departman ortalamaları hesaplanır
        dept_summary: Dict[str, float] = {}
        for dept, scores in dept_scores.items():
            dept_summary[dept] = round(sum(scores) / len(scores), 1)

        # En riskli ilk 5 uç nokta belirlenir (risk skoruna göre azalan sıralama)
        sorted_by_risk = sorted(assessments, key=lambda a: a.risk_score, reverse=True)
        top_5_riskiest: List[Dict[str, Any]] = []
        for h in sorted_by_risk[:5]:
            top_5_riskiest.append({
                "hostname": h.hostname,
                "ip_address": h.ip_address,
                "department": h.department,
                "risk_score": h.risk_score,
                "risk_band": h.risk_band.value,
                "is_critical": h.is_critical,
                "primary_findings": h.findings[:2],
            })

        # En yaygın sistemik zayıflıklar (en az 2 cihazda görülen veya en sık olan ilk 3)
        sorted_weaknesses = sorted(weakness_counts.items(), key=lambda x: x[1], reverse=True)
        systemic: List[str] = [f"{w} ({c} cihazda tespit edildi)" for w, c in sorted_weaknesses[:4]]

        # Filo yönetim panosu nesnesi oluşturulur ve döndürülür
        return FleetRiskDashboard(
            total_endpoints=total_hosts,
            low_risk_count=low_count,
            medium_risk_count=med_count,
            high_risk_count=high_count,
            critical_risk_count=crit_count,
            fleet_average_risk=fleet_avg_risk,
            fleet_average_posture=fleet_avg_posture,
            critical_assets_average_risk=crit_avg_risk,
            department_risk_summary=dept_summary,
            top_riskiest_hosts=top_5_riskiest,
            systemic_weaknesses=systemic,
            host_assessments=assessments,
        )

    def export_dashboard_to_dict(self, dashboard: FleetRiskDashboard) -> Dict[str, Any]:
        """Pano nesnesini serileştirilebilir Python sözlüğüne dönüştürür."""
        # asdict ile veri modelleri sözlüğe çevrilir
        data = asdict(dashboard)
        # RiskBand Enum değerleri metin karşılıklarıyla güncellenir
        for h in data.get("host_assessments", []):
            if isinstance(h.get("risk_band"), RiskBand):
                h["risk_band"] = h["risk_band"].value
        # Sözlük döndürülür
        return data

    def generate_ascii_dashboard_report(self, dashboard: FleetRiskDashboard) -> str:
        """Yönetici sunumları ve konsol çıktısı için görsel ASCII risk panosu oluşturur."""
        # Rapor satırları listesi başlatılır
        lines: List[str] = []
        # Üst başlık çizgisi
        lines.append("=" * 82)
        lines.append(" KURUMSAL UÇ NOKTA RİSK PANOSU VE GÜVENLİK DURUŞ RAPORU (MINI PROJE 21)")
        lines.append("=" * 82)
        # Temel metrikler
        lines.append(f" Toplam Uç Nokta   : {dashboard.total_endpoints:<6} | Filo Ortalama Risk Skoru  : {dashboard.fleet_average_risk:>5.1f} / 100")
        lines.append(f" Filo Duruş Puanı  : {dashboard.fleet_average_posture:>5.1f} / 100 | Kritik Varlık Risk Skoru : {dashboard.critical_assets_average_risk:>5.1f} / 100")
        lines.append("-" * 82)
        # Risk seviye dağılımı görsel çubuğu
        lines.append(" RISK DAĞILIMI:")
        lines.append(f"   [DUSUK]   {dashboard.low_risk_count:>3} cihaz ({round(dashboard.low_risk_count/dashboard.total_endpoints*100, 1)}%)")
        lines.append(f"   [ORTA]    {dashboard.medium_risk_count:>3} cihaz ({round(dashboard.medium_risk_count/dashboard.total_endpoints*100, 1)}%)")
        lines.append(f"   [YUKSEK]  {dashboard.high_risk_count:>3} cihaz ({round(dashboard.high_risk_count/dashboard.total_endpoints*100, 1)}%)")
        lines.append(f"   [KRITIK]  {dashboard.critical_risk_count:>3} cihaz ({round(dashboard.critical_risk_count/dashboard.total_endpoints*100, 1)}%)")
        lines.append("-" * 82)
        # Departman sıralaması
        lines.append(" DEPARTMAN BAZLI ORTALAMA RİSK SKORLARI (Yüksekten Düşüğe):")
        sorted_dept = sorted(dashboard.department_risk_summary.items(), key=lambda x: x[1], reverse=True)
        for dept, score in sorted_dept:
            bar = "#" * int(score // 5)
            lines.append(f"   - {dept:<22} : {score:>5.1f} | {bar}")
        lines.append("-" * 82)
        # En riskli ilk 5 uç nokta tablosu
        lines.append(" EN YÜKSEK RİSKLİ UÇ NOKTALAR (TOP 5):")
        lines.append(f"   {'HOSTNAME':<16} {'IP ADRESİ':<15} {'DEPARTMAN':<15} {'RİSK':<8} {'KRİTİK':<7}")
        for host in dashboard.top_riskiest_hosts:
            crit_badge = "EVET" if host["is_critical"] else "HAYIR"
            lines.append(f"   {host['hostname']:<16} {host['ip_address']:<15} {host['department']:<15} {host['risk_score']:<8.1f} {crit_badge:<7}")
        lines.append("-" * 82)
        # Sistemik zayıflıklar
        lines.append(" EN YAYGIN SİSTEMİK GÜVENLİK ZAYIFLIKLARI:")
        for weak in dashboard.systemic_weaknesses:
            lines.append(f"   * {weak}")
        lines.append("=" * 82)
        # Tüm satırlar birleştirilip döndürülür
        return "\n".join(lines)

    def generate_prioritized_remediation_script(self, dashboard: FleetRiskDashboard) -> str:
        """Kritik ve yüksek riskli uç noktalar için otomatik PowerShell düzeltme betiği üretir."""
        # Betik satırları listesi başlatılır
        script_lines: List[str] = [
            "# PowerShell Otomatik İyileştirme Betiği - Kurumsal Uç Nokta Risk Panosu",
            "# Hedef: Yüksek ve Kritik Riskli Uç Noktaların Güvenlik Açıklarını Giderme",
            f"# Üretim Zamanı: Filo Ortalama Risk: {dashboard.fleet_average_risk}/100",
            "$ErrorActionPreference = 'Stop'",
            "",
            "Write-Host '[*] Kurumsal Uç Nokta İyileştirme Başlatılıyor...' -ForegroundColor Cyan",
            "",
        ]

        # Sadece HIGH ve CRITICAL uç noktalar için aksiyon üretilir
        urgent_hosts = [h for h in dashboard.host_assessments if h.risk_band in (RiskBand.HIGH, RiskBand.CRITICAL)]

        # Acil müdahale gereken cihaz yoksa bilgilendirme eklenir
        if not urgent_hosts:
            script_lines.append("Write-Host '[+] Tebrikler! Filoda acil müdahale gerektiren yüksek riskli uç nokta yok.' -ForegroundColor Green")
            return "\n".join(script_lines)

        # Her acil uç nokta için blok oluşturulur
        for host in urgent_hosts:
            script_lines.append(f"# -------------------------------------------------------------")
            script_lines.append(f"# Uç Nokta: {host.hostname} ({host.ip_address}) - Risk Skoru: {host.risk_score} ({host.risk_band.value})")
            script_lines.append(f"# -------------------------------------------------------------")
            
            # EDR kapalıysa başlatma komutu
            if host.vector_scores.edr_penalty > 0:
                script_lines.append(f"Write-Host '[!] {host.hostname}: EDR servisi başlatılıyor...' -ForegroundColor Yellow")
                script_lines.append(f"Invoke-Command -ComputerName '{host.hostname}' -ScriptBlock {{")
                script_lines.append("    Start-Service -Name 'Sense' -ErrorAction SilentlyContinue")
                script_lines.append("    Set-Service -Name 'Sense' -StartupType Automatic")
                script_lines.append("}")
            
            # Disk şifresiz ise BitLocker açma komutu
            if host.vector_scores.disk_encryption_penalty > 0:
                script_lines.append(f"Write-Host '[!] {host.hostname}: BitLocker şifrelemesi tetikleniyor...' -ForegroundColor Yellow")
                script_lines.append(f"Invoke-Command -ComputerName '{host.hostname}' -ScriptBlock {{")
                script_lines.append("    Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector")
                script_lines.append("}")

            # UAC veya ASLR kapalıysa düzeltme
            if host.vector_scores.hardening_penalty > 20:
                script_lines.append(f"Write-Host '[!] {host.hostname}: UAC ve Güvenli Yapılandırma zorlanıyor...' -ForegroundColor Yellow")
                script_lines.append(f"Invoke-Command -ComputerName '{host.hostname}' -ScriptBlock {{")
                script_lines.append("    Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1")
                script_lines.append("}")

            script_lines.append("")

        script_lines.append("Write-Host '[+] Tüm kritik uç noktalar için iyileştirme komutları tamamlandı.' -ForegroundColor Green")
        # Betik metni döndürülür
        return "\n".join(script_lines)
