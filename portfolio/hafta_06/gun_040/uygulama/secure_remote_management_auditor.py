# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G040: Güvenli Uzaktan Yönetim ve Erişim Matrisi Güvenlik Denetçisi (Secure Remote Management Auditor)

Bu modül, kurumsal ağlardaki uzaktan yönetim servislerini (SSH, RDP, WinRM, Telnet);
düz metin protokoller (plaintext protocols), internete doğrudan açılma (perimeter exposure),
sıçrama sunucusu (Bastion / Jump Host) zorunluluğu, kimlik doğrulama sertleştirmesi
(Root login, SSH anahtar zorunluluğu, RDP NLA, MFA), kaba kuvvet (brute-force) koruması
ve oturum denetim günlükleri (session logging) ekseninde denetler.
"""

# İşletim sistemi ve dosya yolu operasyonları için os modülünü içeri aktarıyoruz.
import os

# Sistem argümanları ve standart giriş/çıkış akışları için sys modülünü dahil ediyoruz.
import sys

# JSON matris ve telemetri dosyalarını ayrıştırmak için json kütüphanesini kullanıyoruz.
import json

# Komut satırı bayraklarını işlemek için argparse modülünü içeri aktarıyoruz.
import argparse

# Zaman damgaları ve UTC tarih formatı için datetime ve timezone modüllerini alıyoruz.
from datetime import datetime, timezone

# Statik kod analizi ve tip güvenliği için typing bileşenlerini dahil ediyoruz.
from typing import Dict, Any, List, Optional, Tuple


# Uzaktan yönetim matrisi telemetrisindeki bozuklukları bildiren özel istisna sınıfı.
class RemoteAccessValidationError(Exception):
    """
    Uzaktan yönetim erişim matrisi verisinde tespit edilen şema ve sınır hataları için istisna.
    """
    # Kurucu metod ile gelen hata açıklamasını temel Exception sınıfına aktarıyoruz.
    def __init__(self, message: str) -> None:
        # Üst sınıf Exception kurucusuna hata iletisini aktarıyoruz.
        super().__init__(message)


# Uzaktan yönetim güvenliğini denetleyen uzman sınıfı tanımlıyoruz.
class SecureRemoteManagementAuditor:
    """
    SSH, RDP, WinRM ve eski protokolleri güvenlik matrisine göre denetleyen motor.
    """

    # Şifresiz çalışan ve derhal yasaklanması gereken eski protokoller kümesi.
    LEGACY_INSECURE_PROTOCOLS: List[str] = ["TELNET", "RLOGIN", "RSH", "VNC_PLAIN"]

    # Sınıf kurucu metodunu başlatıyoruz.
    def __init__(self) -> None:
        # Denetim bulgularını saklayacağımız dinamik listeyi başlatıyoruz.
        self.findings: List[Dict[str, Any]] = []

    # Erişim matrisi girdisinin şematik ve mantıksal geçerliliğini denetleyen fonksiyon.
    def validate_matrix_schema(self, data: Dict[str, Any]) -> bool:
        """
        Matris verisinde zorunlu alanları, port sınırlarını ve mantıksal tipleri doğrular.
        """
        # Kök verinin sözlük olup olmadığını sınıyoruz.
        if not isinstance(data, dict):
            # Sözlük değilse doğrulama hatası fırlatıyoruz.
            raise RemoteAccessValidationError("Erişim matrisi verisi kök düzeyde bir JSON nesnesi (dict) olmalıdır.")

        # Zorunlu remote_services anahtarının varlığını kontrol ediyoruz.
        if "remote_services" not in data:
            # Eksik anahtarda doğrudan hata fırlatıyoruz.
            raise RemoteAccessValidationError("Matris verisinde zorunlu 'remote_services' anahtarı bulunamadı.")

        # remote_services alanının liste olduğunu sınıyoruz.
        if not isinstance(data["remote_services"], list):
            # Liste değilse tip hatası veriyoruz.
            raise RemoteAccessValidationError("'remote_services' alanı bir liste olmalıdır.")

        # Her bir uzaktan yönetim servisini tek tek inceliyoruz.
        for svc_idx, service in enumerate(data["remote_services"]):
            # Servis girdisinin sözlük olduğunu sınıyoruz.
            if not isinstance(service, dict):
                # Sözlük değilse hata fırlatıyoruz.
                raise RemoteAccessValidationError(f"Servis indeksi {svc_idx} geçerli bir JSON nesnesi değil.")

            # Servis kimliğini alıyoruz.
            sid = service.get("service_id")
            # Kimliğin string olduğunu denetliyoruz.
            if not isinstance(sid, str):
                # String değilse hata veriyoruz.
                raise RemoteAccessValidationError(f"Servis indeksi {svc_idx} için 'service_id' metin olmalıdır.")

            # Protokol adını alıyoruz.
            proto = service.get("protocol")
            # Protokolün metin olduğunu sınıyoruz.
            if not isinstance(proto, str):
                # Metin değilse hata fırlatıyoruz.
                raise RemoteAccessValidationError(f"Servis '{sid}' için 'protocol' metin olmalıdır.")

            # Port numarasını alıyoruz.
            port = service.get("port")
            # Portun tamsayı olduğunu sınıyoruz.
            if not isinstance(port, int):
                # Tamsayı değilse hata veriyoruz.
                raise RemoteAccessValidationError(f"Servis '{sid}' için 'port' tamsayı olmalıdır.")

            # TCP/UDP port sınırlarını denetliyoruz (1 ile 65535 arasında olmalıdır).
            if port < 1 or port > 65535:
                # Geçersiz port numarasında hata fırlatıyoruz.
                raise RemoteAccessValidationError(f"Servis '{sid}' için 'port' 1 ile 65535 arasında olmalıdır: {port}")

            # Hedef sunucu adını kontrol ediyoruz.
            host = service.get("target_hostname")
            # Sunucu adının metin olduğunu sınıyoruz.
            if not isinstance(host, str):
                # Metin değilse hata veriyoruz.
                raise RemoteAccessValidationError(f"Servis '{sid}' için 'target_hostname' metin olmalıdır.")

        # Tüm doğrulamalar başarıyla geçildiyse True döndürüyoruz.
        return True

    # Şifresiz çalışan eski protokolleri (Telnet, rlogin) denetleyen fonksiyon.
    def audit_legacy_plaintext_protocols(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Şifresiz eski protokolleri (Telnet vb.) tespit eder; kimlik bilgisi koklama (sniffing) riskini raporlar.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her servisi tarıyoruz.
        for svc in services:
            # Servis kimliği, sunucu ve protokolü alıyoruz.
            sid = svc.get("service_id", "Bilinmeyen_Servis")
            # Sunucu adını alıyoruz.
            host = svc.get("target_hostname", "Bilinmeyen_Host")
            # Protokolü büyük harfe çevirerek alıyoruz.
            proto = svc.get("protocol", "").upper()
            # Portu alıyoruz.
            port = svc.get("port", 0)
            # Açık metin bayrağını alıyoruz.
            is_legacy = bool(svc.get("is_legacy_plaintext_protocol", False))

            # Eğer protokol yasaklı eski listedeyse veya bayrak true ise:
            if proto in self.LEGACY_INSECURE_PROTOCOLS or is_legacy or port == 23:
                # Kritik önemde şifresiz protokol bulgusu oluşturuyoruz.
                finding = {
                    "category": "PLAINTEXT_PROTOCOL_EXPOSURE",
                    "target": f"{sid} ({host}:{port})",
                    "severity": "CRITICAL",
                    "title": f"Şifresiz ve Güvensiz Protokol Tespiti ({proto}) — Kimlik Bilgisi Koklama Riski",
                    "description": (
                        f"'{host}' üzerinde çalışan '{proto}' (Port {port}) servisi tüm oturum trafiğini, "
                        "kullanıcı adlarını ve parolaları ağ üzerinden açık metin (cleartext) olarak iletmektedir. "
                        "Yerel ağdaki herhangi bir saldırgan veya pasif dinleyici (Wireshark/tcpdump), "
                        "tüm yönetim oturumunu ve şifreleri tek bir paket yakalama işlemiyle ele geçirebilir."
                    ),
                    "remediation": f"'{proto}' servisini derhal kapatın (`systemctl disable --now telnet.socket`), yerine modern SSHv2 veya WinRM over HTTPS (TLS) kurun."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Ağ çevresi ve doğrudan internete açılma (Perimeter Exposure) durumunu denetleyen fonksiyon.
    def audit_perimeter_exposure_and_bastion(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Yönetim portlarının internete (0.0.0.0/0) doğrudan açılmasını ve Bastion/VPN eksikliğini analiz eder.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her servisi inceliyoruz.
        for svc in services:
            # Servis kimliği, sunucu ve protokolü alıyoruz.
            sid = svc.get("service_id", "Bilinmeyen_Servis")
            # Sunucu adını alıyoruz.
            host = svc.get("target_hostname", "Bilinmeyen_Host")
            # Protokolü alıyoruz.
            proto = svc.get("protocol", "").upper()
            # Portu alıyoruz.
            port = svc.get("port", 0)
            # İnternete açık mı bayrağını alıyoruz.
            exposed_internet = bool(svc.get("is_exposed_to_internet", False))
            # İzinli CIDR listesini alıyoruz.
            allowed_cidrs = svc.get("allowed_cidrs", [])
            # Bastion zorunlu mu bayrağını alıyoruz.
            requires_bastion = bool(svc.get("requires_bastion_or_vpn", False))

            # Eğer internete doğrudan açıksa veya izinli CIDR 0.0.0.0/0 içeriyorsa ve Bastion/VPN yoksa:
            if (exposed_internet or "0.0.0.0/0" in allowed_cidrs) and not requires_bastion:
                # Kritik seviyede doğrudan ağ çevresi açığı bulgusu oluşturuyoruz.
                finding = {
                    "category": "PERIMETER_MANAGEMENT_EXPOSURE",
                    "target": f"{sid} ({host}:{port})",
                    "severity": "CRITICAL",
                    "title": f"Yönetim Portu İnternete Doğrudan Açık ({proto}:{port}) — Kaba Kuvvet ve İstismar Riski",
                    "description": (
                        f"'{host}' üzerindeki '{proto}' yönetim servisi (Port {port}), hiçbir VPN veya Bastion/Jump Host "
                        "koruması olmaksızın doğrudan genel internete (0.0.0.0/0) maruz bırakılmıştır. "
                        "Bu durum botnet'ler, otomatik parola deneme (brute-force) saldırıları ve sıfır-gün "
                        "istismarları (örn. RDP BlueKeep CVE-2019-0708) için en kolay hedefi oluşturur."
                    ),
                    "remediation": "Portu genel internete kapatın; erişimi yalnızca IPsec/WireGuard VPN veya kurumsal Bastion Jump Host arkasına alın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Kimlik doğrulama sertleştirmesini (Root Login, SSH Key, RDP NLA, MFA) denetleyen fonksiyon.
    def audit_authentication_hardening(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        SSH root girişi, parola kullanımı, RDP Ağ Düzeyinde Kimlik Doğrulama (NLA) ve MFA durumunu denetler.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her servisi sınıyoruz.
        for svc in services:
            # Servis kimliği, sunucu ve protokolü alıyoruz.
            sid = svc.get("service_id", "Bilinmeyen_Servis")
            # Sunucu adını alıyoruz.
            host = svc.get("target_hostname", "Bilinmeyen_Host")
            # Protokolü alıyoruz.
            proto = svc.get("protocol", "").upper()
            # Portu alıyoruz.
            port = svc.get("port", 0)

            # SSH Protokolü için Sertleştirme Denetimleri:
            if proto == "SSH":
                # Root girişi açık mı?
                permit_root = bool(svc.get("permit_root_login", False))
                # Parola ile giriş açık mı?
                pwd_auth = bool(svc.get("password_auth_allowed", True))
                # Anahtar zorunlu mu?
                key_auth = bool(svc.get("public_key_auth_enforced", False))
                # MFA var mı?
                mfa = bool(svc.get("mfa_enforced", False))

                # 1. Root Girişi Denetimi:
                if permit_root:
                    # Kritik bulgu: Doğrudan root girişi açıktır.
                    finding = {
                        "category": "SSH_ROOT_LOGIN_PERMITTED",
                        "target": f"{sid} ({host}:{port})",
                        "severity": "CRITICAL",
                        "title": "SSH Doğrudan Root Girişi İzinli (PermitRootLogin: yes)",
                        "description": (
                            f"'{host}' üzerinde SSH servisine doğrudan 'root' kullanıcısıyla oturum açılmasına izin verilmektedir. "
                            "Saldırganlar kullanıcı adını tahmin etmeye gerek kalmadan tüm güçlerini 'root' parolasını kırmaya odaklarlar. "
                            "Ayrıca kimin hangi işlemi yaptığını izleyen denetim izi (accountability) yok olur."
                        ),
                        "remediation": "/etc/ssh/sshd_config dosyasında `PermitRootLogin no` ayarını yapın ve 'sudo' yetkili bireysel hesaplar kullanın."
                    }
                    # Listeye ekliyoruz.
                    local_findings.append(finding)

                # 2. Parola ile Giriş ve Anahtar Eksikliği:
                if pwd_auth and not key_auth:
                    # Yüksek önemde parola kaba kuvvet riski bulgusu:
                    finding = {
                        "category": "SSH_PASSWORD_AUTH_UNHARDENED",
                        "target": f"{sid} ({host}:{port})",
                        "severity": "HIGH",
                        "title": "SSH Parola ile Giriş Açık — Kriptografik Anahtar Zorunluluğu Yok",
                        "description": (
                            f"'{host}' üzerindeki SSH servisi parola ile girişe izin vermekte, açık anahtarlı kimlik doğrulamayı "
                            "(Public Key Authentication - Ed25519/RSA) zorunlu kılmamaktadır. Parolalar tahmin edilebilir, "
                            "oltalama ile çalınabilir veya kaba kuvvetle kırılabilir."
                        ),
                        "remediation": "`PasswordAuthentication no` ve `PubkeyAuthentication yes` ayarlarını uygulayın."
                    }
                    # Listeye ekliyoruz.
                    local_findings.append(finding)

                # 3. Yönetimsel Erişimde MFA Eksikliği:
                if not mfa:
                    # Orta seviyede MFA uyarısı:
                    finding = {
                        "category": "REMOTE_ACCESS_MFA_MISSING",
                        "target": f"{sid} ({host}:{port})",
                        "severity": "MEDIUM",
                        "title": "SSH Yönetimsel Oturumunda Çok Faktörlü Kimlik Doğrulama (MFA) Yok",
                        "description": (
                            f"'{host}' sistemine bağlanan yönetim oturumlarında MFA (Google Authenticator / Duo / FIDO2) aranmamaktadır."
                        ),
                        "remediation": "SSH PAM modülüne `pam_google_authenticator` veya FIDO2 donanım anahtarı zorunluluğu ekleyin."
                    }
                    # Listeye ekliyoruz.
                    local_findings.append(finding)

            # RDP Protokolü için Sertleştirme Denetimleri:
            elif proto == "RDP":
                # NLA (Ağ Düzeyinde Kimlik Doğrulama) açık mı?
                nla_on = svc.get("nla_enforced", True)
                # MFA var mı?
                mfa = bool(svc.get("mfa_enforced", False))

                # 1. NLA Eksikliği Denetimi (Ölümcül BlueKeep / DoS Açığı):
                if nla_on is False:
                    # Kritik seviyede NLA eksikliği bulgusu:
                    finding = {
                        "category": "RDP_NLA_DISABLED_VULNERABILITY",
                        "target": f"{sid} ({host}:{port})",
                        "severity": "CRITICAL",
                        "title": "RDP Ağ Düzeyinde Kimlik Doğrulama (NLA) Devre Dışı — Ön-Yetkilendirme İstismar Riski",
                        "description": (
                            f"'{host}' üzerindeki Uzak Masaüstü (RDP) servisinde NLA (Network Level Authentication) kapalıdır. "
                            "NLA kapalı olduğunda sunucu, kullanıcı kimliğini doğrulamadan önce tüm RDP grafik oturumunu ve "
                            "bellek yapılarını başlatır. Bu durum BlueKeep (CVE-2019-0708) gibi kimlik doğrulamasız uzaktan "
                            "kod çalıştırma (RCE) açıklarına ve DoS saldırılarına zemin hazırlar."
                        ),
                        "remediation": "Windows Sistem Özellikleri veya Grup İlkesi (GPO) üzerinden 'Yalnızca Ağ Düzeyinde Kimlik Doğrulama ile bağlanan bilgisayarlardan bağlantılara izin ver' kuralını etkinleştirin."
                    }
                    # Listeye ekliyoruz.
                    local_findings.append(finding)

                # 2. RDP MFA Eksikliği:
                if not mfa:
                    # Yüksek seviyede RDP MFA eksikliği:
                    finding = {
                        "category": "RDP_MFA_MISSING",
                        "target": f"{sid} ({host}:{port})",
                        "severity": "HIGH",
                        "title": "RDP Uzak Masaüstü Oturumunda MFA Eksikliği",
                        "description": (
                            f"'{host}' RDP erişiminde tek faktörlü (yalnızca kullanıcı adı ve parola) oturum açılmaktadır. "
                            "Fidye yazılımı aktörlerinin en yaygın ilk erişim (initial access) yöntemi çalınmış RDP parolalarıdır."
                        ),
                        "remediation": "RDP Gateway üzerinde Azure MFA veya kurumsal Duo Security entegrasyonu uygulayın."
                    }
                    # Listeye ekliyoruz.
                    local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Kaba kuvvet (Brute-Force) koruması ve oturum denetim günlüklerini (Logging) denetleyen fonksiyon.
    def audit_brute_force_and_logging(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fail2ban, hesap kilitleme eşikleri ve oturum kayıtlarının SIEM'e aktarılma durumunu analiz eder.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her servisi tarıyoruz.
        for svc in services:
            # Servis kimliği, sunucu ve protokolü alıyoruz.
            sid = svc.get("service_id", "Bilinmeyen_Servis")
            # Sunucu adını alıyoruz.
            host = svc.get("target_hostname", "Bilinmeyen_Host")
            # Protokolü alıyoruz.
            proto = svc.get("protocol", "").upper()
            # Portu alıyoruz.
            port = svc.get("port", 0)
            # Kaba kuvvet koruması var mı?
            has_brute_prot = bool(svc.get("brute_force_protection", False))
            # Oturum günlükleme açık mı?
            has_logging = bool(svc.get("session_logging_enabled", False))

            # 1. Kaba Kuvvet Koruması Yokluğu:
            if not has_brute_prot:
                # Yüksek önemde kaba kuvvet koruma eksikliği bulgusu:
                finding = {
                    "category": "BRUTE_FORCE_PROTECTION_MISSING",
                    "target": f"{sid} ({host}:{port})",
                    "severity": "HIGH",
                    "title": f"Otomatik Kaba Kuvvet (Brute-Force) Koruması Yok ({proto})",
                    "description": (
                        f"'{host}' üzerinde çalışan '{proto}' servisinde başarısız oturum denemelerini engelleyen "
                        "bir mekanizma (Fail2ban, pam_tally2/pam_faillock veya Windows Hesap Kilitleme Eşiği) bulunmamaktadır. "
                        "Saldırganlar sözlük saldırıları (dictionary attack) ile milyonlarca parolayı sınırsızca deneyebilir."
                    ),
                    "remediation": "Linux'ta `fail2ban` servisini etkinleştirin; Windows'ta 'Account lockout threshold' değerini 5 olarak ayarlayın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 2. Oturum Günlükleme Eksikliği:
            if not has_logging:
                # Orta seviyede günlükleme eksikliği uyarısı:
                finding = {
                    "category": "SESSION_AUDIT_LOGGING_MISSING",
                    "target": f"{sid} ({host}:{port})",
                    "severity": "MEDIUM",
                    "title": f"Oturum Denetim Günlükleme (Session Audit Logging) Kapalı ({proto})",
                    "description": (
                        f"'{host}' uzaktan yönetim oturumlarının açılış, kapanış ve yetki yükseltme kayıtları "
                        "merkezi SIEM sistemine aktarılmamaktadır. Bir ihlal durumunda adli iz sürülemez."
                    ),
                    "remediation": "Olay günlüklerini (Linux /var/log/auth.log, Windows Event ID 4624/4625) syslog ile SIEM'e yönlendirin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Tüm denetimleri yürüten ve genel güvenlik puanını hesaplayan ana icra metodu.
    def execute_full_audit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tüm denetimleri çalıştırır, puanı hesaplar ve yapılandırılmış rapor döner.
        """
        # Şemayı doğruluyoruz.
        self.validate_matrix_schema(data)

        # Servis listesini alıyoruz.
        services = data.get("remote_services", [])

        # Önceki bulguları sıfırlıyoruz.
        self.findings = []

        # 1. Şifresiz eski protokol denetimi:
        self.findings.extend(self.audit_legacy_plaintext_protocols(services))

        # 2. Ağ çevresi ve doğrudan internete maruz kalma denetimi:
        self.findings.extend(self.audit_perimeter_exposure_and_bastion(services))

        # 3. Kimlik doğrulama sertleştirme denetimi:
        self.findings.extend(self.audit_authentication_hardening(services))

        # 4. Kaba kuvvet koruması ve denetim günlükleme:
        self.findings.extend(self.audit_brute_force_and_logging(services))

        # Başlangıç puanı 100:
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

        # Puanın sıfırın altına düşmesini engelliyoruz.
        security_score = max(0, security_score)

        # Genel güvenlik durumunu belirliyoruz.
        overall_status = "SECURE" if security_score >= 85 else ("WARNING" if security_score >= 60 else "CRITICAL")

        # Rapor sözlüğünü döndürüyoruz.
        return {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "matrix_metadata": data.get("matrix_metadata", {}),
            "security_score": security_score,
            "overall_status": overall_status,
            "metrics": {
                "total_services_analyzed": len(services),
                "critical_findings": crit_count,
                "high_findings": high_count,
                "medium_findings": med_count,
                "warning_findings": warn_count,
                "total_findings": len(self.findings)
            },
            "findings": self.findings
        }

    # Denetim sonucunu Markdown formatına dönüştüren raporlama fonksiyonu.
    def export_markdown_report(self, audit_result: Dict[str, Any]) -> str:
        """
        Denetim sonucunu insan tarafından okunabilir Markdown formatında biçimlendirir.
        """
        # Boş satır listesi başlatıyoruz.
        lines: List[str] = []

        # Lisans başlığını ekliyoruz.
        lines.append("<!--")
        lines.append("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR")
        lines.append("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)")
        lines.append("Bu yazılım ve ilgili tüm dosyalar ('Yazılım') yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.")
        lines.append("-->\n")

        # Rapor başlığı:
        lines.append("# Güvenli Uzaktan Yönetim ve Erişim Matrisi Denetim Raporu\n")

        # Üst bilgiler:
        lines.append(f"**Denetim Tarihi:** `{audit_result.get('audit_timestamp', 'N/A')}`  ")
        lines.append(f"**Güvenlik Puanı:** `{audit_result.get('security_score', 0)} / 100`  ")
        lines.append(f"**Genel Durum:** `{audit_result.get('overall_status', 'UNKNOWN')}`\n")

        # Metrik tablosu:
        metrics = audit_result.get("metrics", {})
        lines.append("## 📊 Denetim Metrikleri Özeti\n")
        lines.append("| Metrik | Değer |")
        lines.append("| :--- | :---: |")
        lines.append(f"| İncelenen Yönetim Servisi Sayısı | {metrics.get('total_services_analyzed', 0)} |")
        lines.append(f"| Kritik (CRITICAL) Bulgular | {metrics.get('critical_findings', 0)} |")
        lines.append(f"| Yüksek (HIGH) Seviye Bulgular | {metrics.get('high_findings', 0)} |")
        lines.append(f"| Orta (MEDIUM) Seviye Bulgular | {metrics.get('medium_findings', 0)} |")
        lines.append(f"| Uyarı (WARNING) Bulgular | {metrics.get('warning_findings', 0)} |")
        lines.append(f"| **Toplam Güvenlik Bulgusu** | **{metrics.get('total_findings', 0)}** |\n")

        # Bulgular bölümü:
        lines.append("## 🔍 Güvenlik Bulguları ve İyileştirme Reçetesi\n")
        findings = audit_result.get("findings", [])

        # Bulgu yoksa temiz bildiriyoruz.
        if not findings:
            lines.append("✅ *Tüm uzaktan yönetim servisleri kurumsal güvenlik standartlarına, ağ sınırlarına ve kimlik doğrulama politikalarına tam uygundur.*\n")
        else:
            # Bulguları listeliyoruz.
            for i, f in enumerate(findings, 1):
                lines.append(f"### {i}. [{f['severity']}] {f['title']}")
                lines.append(f"- **Hedef:** `{f['target']}`")
                lines.append(f"- **Kategori:** `{f['category']}`")
                lines.append(f"- **Açıklama:** {f['description']}")
                lines.append(f"- **🛡️ İyileştirme:** {f['remediation']}\n")

        # Satırları birleştirip döndürüyoruz.
        return "\n".join(lines)


# Komut satırı giriş noktası:
def main() -> None:
    """
    CLI yürütme giriş noktası.
    """
    # Windows konsolunda UTF-8 güvencesi sağlıyoruz.
    if hasattr(sys.stdout, "reconfigure"):
        # Standart çıktıyı UTF-8 yapıyoruz.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # Standart hatayı da UTF-8 yapıyoruz.
    if hasattr(sys.stderr, "reconfigure"):
        # Standart hata akışını ayarlıyoruz.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    # Argüman ayrıştırıcı oluşturuyoruz.
    parser = argparse.ArgumentParser(description="G040: Güvenli Uzaktan Yönetim ve Erişim Matrisi Denetçisi")
    # Telemetri yolu argümanı:
    parser.add_argument("--telemetry", type=str, required=True, help="İncelenecek JSON uzaktan erişim matrisi dosyasının yolu")
    # Çıktı dosyası argümanı:
    parser.add_argument("--output", type=str, default="", help="Markdown raporunun kaydedileceği dosya yolu")

    # Argümanları ayrıştırıyoruz.
    args = parser.parse_args()

    # Dosya varlık kontrolü:
    if not os.path.exists(args.telemetry):
        # Hata mesajı basıp çıkıyoruz.
        print(f"HATA: Erişim matrisi dosyası bulunamadı: {args.telemetry}", file=sys.stderr)
        # Çıkış kodu 1 ile sonlandırıyoruz.
        sys.exit(1)

    # Dosyayı okuyoruz.
    with open(args.telemetry, "r", encoding="utf-8") as f:
        # JSON ayrıştırıyoruz.
        matrix_data = json.load(f)

    # Denetçi nesnesini oluşturuyoruz.
    auditor = SecureRemoteManagementAuditor()
    # Denetimi icra ediyoruz.
    audit_result = auditor.execute_full_audit(matrix_data)
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
