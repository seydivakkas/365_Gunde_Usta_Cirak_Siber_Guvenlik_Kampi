# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 20 / Gün 140 - Mini Proje 19: Linux Sertleştirme Kontrolü (Hardening Audit Engine).
Bu modül, CIS Linux Benchmark v2.0.0 ve kurumsal güvenlik standartlarını temel alarak;
Sudo, PAM/Oturum, Systemd İzolasyonu, SSH, Firewall ve Audit/Journal bileşenlerini
bütünleşik olarak denetleyen, puanlayan ve otomatik sıkılaştırma betiği üreten motordur.
"""

# İşletim sistemi fonksiyonları ve dosya yolları işlemleri için standart kütüphane
import os
# Sistem girdi/çıktı akışları ve argüman yönetimi
import sys
# Yapılandırılmış JSON verisi ayrıştırma ve seri hale getirme
import json
# Düzenli ifadeler ile metin desen eşleştirme
import re
# Kriptografik özetleme ve bütünlük hesaplama işlemleri
import hashlib
# Zaman damgaları ve rapor oluşturma tarihi için datetime modülü
from datetime import datetime
# Veri yapılarını nesne yönelimli temsil etmek için dataclass modülü
from dataclasses import dataclass, field, asdict
# Tip ipuçları ve statik analiz desteği
from typing import Dict, List, Any, Optional, Tuple


@dataclass
class AuditFinding:
    """
    Denetim sırasında tespit edilen güvenlik bulgusu veri modeli.
    Her bulgu; domain, kural kodu, önem derecesi, açıklama ve çözüm önerisi içerir.
    """
    domain: str                     # Denetim alanı (SUDO, PAM, SYSTEMD, SSH, FIREWALL, AUDIT)
    rule_id: str                    # CIS veya kurum kural kimliği (örn: CIS-1.3.1)
    title: str                      # Bulgunun kısa başlığı
    severity: str                   # Önem derecesi: CRITICAL, HIGH, MEDIUM, LOW
    status: str                     # Denetim durumu: PASS, FAIL, WARNING
    current_value: Any              # Sistemde tespit edilen mevcut değer
    expected_value: Any             # Olması gereken güvenli referans değer
    remediation: str                # Çözüm ve sıkılaştırma adımı


@dataclass
class DomainAuditResult:
    """
    Belirli bir denetim alanına (Domain) ait toplu değerlendirme sonucu.
    """
    domain_name: str                # Alan adı
    total_checks: int = 0           # Toplam kontrol sayısı
    passed_checks: int = 0          # Başarılı kontrol sayısı
    failed_checks: int = 0          # Başarısız kontrol sayısı
    warning_checks: int = 0         # Uyarı kontrol sayısı
    score: float = 0.0              # Alandan kazanılan başarı puanı (0-100)
    findings: List[AuditFinding] = field(default_factory=list)  # Tespit edilen bulgular


@dataclass
class OverallHardeningReport:
    """
    Sistemin tüm alanlarını kapsayan konsolide denetim ve uyumluluk raporu.
    """
    target_host: str                # Denetlenen hedef sunucu adı veya IP'si
    scan_timestamp: str             # Denetimin gerçekleştirildiği zaman damgası
    compliance_score: float         # Ağırlıklı genel uyumluluk puanı (0-100)
    overall_status: str             # Genel sonuç: COMPLIANT, NON-COMPLIANT, AT_RISK
    domain_results: Dict[str, DomainAuditResult] = field(default_factory=dict)
    summary_counts: Dict[str, int] = field(default_factory=dict)
    remediation_steps: List[str] = field(default_factory=list)


class LinuxHardeningAuditEngine:
    """
    Bütünleşik Linux Sertleştirme ve Uyumluluk Denetim Motoru.
    CIS Linux Benchmark v2.0.0 standartlarında 6 temel güvenlik alanını denetler.
    """

    # GTFOBins listesinde yer alan ve sudo ile doğrudan kabuk açabilen riskli komutlar
    GTFOBINS_SHELL_ESCAPES = {
        "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh",
        "bash", "sh", "vim", "vi", "nano", "find", "nmap",
        "less", "more", "awk", "python", "perl", "ruby", "gdb", "man"
    }

    # Ağda dinlenmesi kesinlikle yasaklanmış güvensiz servisler (CIS 2.1)
    PROHIBITED_SERVICES = {
        "telnet", "rsh", "rlogin", "ypbind", "tftp", "vsftpd", "xinetd", "cups"
    }

    def __init__(self, inventory_data: Optional[Dict[str, Any]] = None):
        """
        Denetim motorunu başlatır. İsteğe bağlı olarak envanter verisini alır.
        """
        # Hedef sistemin konfigürasyon envanterini depolar
        self.inventory = inventory_data or {}
        # Denetim bulgularını ve sonuçlarını saklar
        self.report: Optional[OverallHardeningReport] = None

    def load_inventory_from_file(self, file_path: str) -> None:
        """
        JSON dosyasından sistem envanter verisini güvenli bir şekilde yükler.
        """
        # Dosyanın varlığını işletim sistemi seviyesinde kontrol et
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Envanter dosyası bulunamadı: {file_path}")
        # Dosyayı UTF-8 karakter seti ile aç ve JSON olarak ayrıştır
        with open(file_path, "r", encoding="utf-8") as fp:
            self.inventory = json.load(fp)

    # -------------------------------------------------------------------------
    # 1. ALAN: SUDO VE AYRICALIK DEVRİ GÜVENLİĞİ (CIS 1.3 / 5.3)
    # -------------------------------------------------------------------------
    def audit_sudo_security(self) -> DomainAuditResult:
        """
        Sudoers kurallarını, NOPASSWD risklerini, dosya izinlerini ve default direktiflerini denetler.
        """
        # Domain sonuç nesnesini oluştur
        domain = DomainAuditResult(domain_name="SUDO_PRIVILEGE_MANAGEMENT")
        sudo_data = self.inventory.get("sudo_spec", {})

        # Kontrol 1: /etc/sudoers dosya izinleri kontrolü (0440 olmalı)
        mode = sudo_data.get("file_mode", "0777")
        if mode in ["0440", "0400"]:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.1", title="Sudoers Dosya İzinleri",
                severity="HIGH", status="PASS", current_value=mode, expected_value="0440/0400",
                remediation="Dosya izinleri güvenli."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.1", title="Sudoers Dosya İzinleri Güvensiz",
                severity="CRITICAL", status="FAIL", current_value=mode, expected_value="0440",
                remediation="chmod 0440 /etc/sudoers komutu ile izinleri sıkılaştırın."
            ))

        # Kontrol 2: env_reset direktifinin varlığı
        defaults = sudo_data.get("defaults", [])
        has_env_reset = any("env_reset" in d for d in defaults)
        if has_env_reset:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.2", title="Sudo Ortam Değişkeni Sıfırlama (env_reset)",
                severity="MEDIUM", status="PASS", current_value="Var", expected_value="Var",
                remediation="Ortam değişkenleri güvenli şekilde sıfırlanıyor."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.2", title="Sudo env_reset Eksik",
                severity="HIGH", status="FAIL", current_value="Yok", expected_value="Defaults env_reset",
                remediation="/etc/sudoers dosyasına 'Defaults env_reset' satırını ekleyin."
            ))

        # Kontrol 3: secure_path direktifinin varlığı
        has_secure_path = any("secure_path" in d for d in defaults)
        if has_secure_path:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.3", title="Sudo Güvenli Yürütme Yolu (secure_path)",
                severity="MEDIUM", status="PASS", current_value="Var", expected_value="Var",
                remediation="Güvenli PATH tanımlı."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.3", title="Sudo secure_path Eksik",
                severity="HIGH", status="FAIL", current_value="Yok", expected_value="Defaults secure_path=...",
                remediation="/etc/sudoers içerisine güvenli sistem yollarını sabitleyen secure_path ekleyin."
            ))

        # Kontrol 4: NOPASSWD ve Wildcard (*) Yetkilendirmeleri
        rules = sudo_data.get("rules", [])
        has_wildcard_nopasswd = False
        has_shell_escape_nopasswd = False

        for r in rules:
            r_str = str(r).strip()
            # NOPASSWD ile ALL veya kontrolsüz joker karakter kullanımı
            if "NOPASSWD:" in r_str and ("ALL" in r_str or "*" in r_str):
                has_wildcard_nopasswd = True
            # GTFOBins kabuk komutlarına şifresiz yetki verilmiş mi?
            if "NOPASSWD:" in r_str:
                for shell_cmd in self.GTFOBINS_SHELL_ESCAPES:
                    if shell_cmd in r_str:
                        has_shell_escape_nopasswd = True
                        break

        if not has_wildcard_nopasswd and not has_shell_escape_nopasswd:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.4", title="Sudo NOPASSWD / Shell Escape İncelemesi",
                severity="CRITICAL", status="PASS", current_value="Güvenli Kısıtlamalar",
                expected_value="Parolasız Kabuk Yok", remediation="Kritik parolasız yetki saptanmadı."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SUDO", rule_id="CIS-1.3.4", title="Tehlikeli NOPASSWD Yetkilendirmesi Tespit Edildi",
                severity="CRITICAL", status="FAIL",
                current_value=f"Wildcard: {has_wildcard_nopasswd}, Shell Escape: {has_shell_escape_nopasswd}",
                expected_value="NOPASSWD Kısıtlanmalı",
                remediation="Sudoers kurallarından tehlikeli NOPASSWD: ALL ve kabuk tetikleyici komutları kaldırın."
            ))

        # İstatistik ve puan hesaplama
        self._calculate_domain_stats(domain)
        return domain

    # -------------------------------------------------------------------------
    # 2. ALAN: PAM VE OTURUM POLİTİKASI GÜVENLİĞİ (CIS 5.4 / 5.5)
    # -------------------------------------------------------------------------
    def audit_pam_session_security(self) -> DomainAuditResult:
        """
        Parola karmaşıklığı (pam_pwquality), hesap kilitleme (pam_faillock) ve boşta kalma süresini denetler.
        """
        domain = DomainAuditResult(domain_name="PAM_SESSION_SECURITY")
        pam_data = self.inventory.get("pam_spec", {})

        # Kontrol 1: Parola minimum uzunluğu (minlen >= 14 olmalı)
        pwquality = pam_data.get("pwquality", {})
        minlen = int(pwquality.get("minlen", 0))
        if minlen >= 14:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.4.1", title="Parola Minimum Uzunluk Politikası",
                severity="HIGH", status="PASS", current_value=minlen, expected_value=">= 14",
                remediation="Parola uzunluğu standarda uygun."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.4.1", title="Yetersiz Parola Uzunluğu",
                severity="HIGH", status="FAIL", current_value=minlen, expected_value=">= 14",
                remediation="/etc/security/pwquality.conf dosyasına 'minlen = 14' direktifini tanımlayın."
            ))

        # Kontrol 2: Karakter çeşitliliği (dcredit, ucredit, lcredit, ocredit <= -1)
        credits_ok = (
            int(pwquality.get("dcredit", 0)) <= -1 and
            int(pwquality.get("ucredit", 0)) <= -1 and
            int(pwquality.get("lcredit", 0)) <= -1 and
            int(pwquality.get("ocredit", 0)) <= -1
        )
        if credits_ok:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.4.2", title="Parola Karakter Çeşitlilik Zorunluluğu",
                severity="MEDIUM", status="PASS", current_value="Zorunlu", expected_value="Tüm sınıflar <= -1",
                remediation="Rakam, büyük harf, küçük harf ve özel karakter şartı etkin."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.4.2", title="Eksik Karakter Karmaşıklığı Politikası",
                severity="MEDIUM", status="FAIL", current_value="Gevşek", expected_value="dcredit=-1 ucredit=-1...",
                remediation="pwquality.conf dosyasında dcredit, ucredit, lcredit, ocredit değerlerini -1 olarak ayarlayın."
            ))

        # Kontrol 3: Hesap kilitleme politikası (deny <= 5, unlock_time >= 900)
        faillock = pam_data.get("faillock", {})
        deny = int(faillock.get("deny", 999))
        unlock_time = int(faillock.get("unlock_time", 0))
        if deny <= 5 and unlock_time >= 900:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.4.3", title="Hesap Kilitleme Politikası (pam_faillock)",
                severity="HIGH", status="PASS", current_value=f"deny={deny}, unlock={unlock_time}s",
                expected_value="deny<=5, unlock>=900s", remediation="Kaba kuvvet koruması etkin."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.4.3", title="Yetersiz Hesap Kilitleme Koruması",
                severity="HIGH", status="FAIL", current_value=f"deny={deny}, unlock={unlock_time}s",
                expected_value="deny<=5, unlock>=900s",
                remediation="/etc/security/faillock.conf içinde 'deny = 5' ve 'unlock_time = 900' yapılandırın."
            ))

        # Kontrol 4: Oturum boşta kalma süresi (TMOUT <= 900 saniye)
        tmout = int(pam_data.get("tmout_seconds", 9999))
        if 0 < tmout <= 900:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.5.1", title="Kabuk Oturum Boşta Kalma Zaman Aşımı (TMOUT)",
                severity="MEDIUM", status="PASS", current_value=f"{tmout} saniye", expected_value="<= 900 saniye",
                remediation="Oturum zaman aşımı etkin."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="PAM", rule_id="CIS-5.5.1", title="Oturum Boşta Kalma Süresi Çok Yüksek veya Tanımsız",
                severity="MEDIUM", status="FAIL", current_value=f"{tmout} saniye", expected_value="<= 900 saniye",
                remediation="/etc/profile.d/tmout.sh dosyasına 'readonly TMOUT=900; export TMOUT' ekleyin."
            ))

        self._calculate_domain_stats(domain)
        return domain

    # -------------------------------------------------------------------------
    # 3. ALAN: LİNUX SERVİSLERİ VE SYSTEMD SANDBOXING (CIS 2.1 / 2.2)
    # -------------------------------------------------------------------------
    def audit_systemd_services(self) -> DomainAuditResult:
        """
        Yasaklanmış legacy servisleri ve kritik systemd servislerinin izolasyon direktiflerini denetler.
        """
        domain = DomainAuditResult(domain_name="SYSTEMD_SANDBOXING_SECURITY")
        systemd_data = self.inventory.get("systemd_spec", {})

        # Kontrol 1: Güvensiz / Yasaklanmış servislerin çalıştırılmaması
        running_services = set(systemd_data.get("running_services", []))
        prohibited_detected = running_services.intersection(self.PROHIBITED_SERVICES)
        if not prohibited_detected:
            domain.findings.append(AuditFinding(
                domain="SYSTEMD", rule_id="CIS-2.1.1", title="Yasaklanmış Eski Servisler Kontrolü",
                severity="CRITICAL", status="PASS", current_value="Yok", expected_value="Hiçbiri çalışmamalı",
                remediation="Sistemde güvensiz eski servis tespit edilmedi."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SYSTEMD", rule_id="CIS-2.1.1", title="Güvensiz Servisler Tespit Edildi",
                severity="CRITICAL", status="FAIL", current_value=list(prohibited_detected),
                expected_value="Devre dışı bırakılmalı",
                remediation=f"Şu servisleri kaldırın ve durdurun: {', '.join(prohibited_detected)}"
            ))

        # Kontrol 2: Kritik daemon servislerinin kum havuzu (sandboxing) direktifleri
        critical_units = systemd_data.get("monitored_units", {})
        sandboxing_passed = True
        missing_sandboxes = []

        for unit_name, directives in critical_units.items():
            # NoNewPrivileges ve ProtectSystem kontrolü
            no_new_privs = directives.get("NoNewPrivileges", False)
            protect_sys = directives.get("ProtectSystem", "no")
            private_tmp = directives.get("PrivateTmp", False)
            if not no_new_privs or protect_sys not in ["strict", "full", "yes"] or not private_tmp:
                sandboxing_passed = False
                missing_sandboxes.append(unit_name)

        if sandboxing_passed and critical_units:
            domain.findings.append(AuditFinding(
                domain="SYSTEMD", rule_id="CIS-2.2.1", title="Systemd Kum Havuzu (Sandboxing) İzolasyonu",
                severity="HIGH", status="PASS", current_value="Tüm birimler izole",
                expected_value="NoNewPrivileges=yes, ProtectSystem=strict, PrivateTmp=yes",
                remediation="Servis izolasyonu mükemmel seviyede."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SYSTEMD", rule_id="CIS-2.2.1", title="Eksik Systemd Servis İzolasyonu",
                severity="HIGH", status="FAIL", current_value=f"Korumasız birimler: {missing_sandboxes}",
                expected_value="NoNewPrivileges=yes, ProtectSystem=strict, PrivateTmp=yes",
                remediation="Birim .service dosyalarına [Service] altında NoNewPrivileges=yes ve ProtectSystem=strict ekleyin."
            ))

        self._calculate_domain_stats(domain)
        return domain

    # -------------------------------------------------------------------------
    # 4. ALAN: SSH ANAHTAR VE DAEMON GÜVENLİĞİ (CIS 5.2)
    # -------------------------------------------------------------------------
    def audit_ssh_security(self) -> DomainAuditResult:
        """
        SSH daemon parametrelerini (sshd_config) ve anahtar politikalarını denetler.
        """
        domain = DomainAuditResult(domain_name="SSH_CRYPTOGRAPHY_SECURITY")
        ssh_data = self.inventory.get("ssh_spec", {})
        sshd_config = ssh_data.get("sshd_config", {})

        # Kontrol 1: PermitRootLogin no
        root_login = str(sshd_config.get("PermitRootLogin", "yes")).lower()
        if root_login == "no":
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.1", title="SSH Doğrudan Root Girişi Engelleme",
                severity="CRITICAL", status="PASS", current_value="no", expected_value="no",
                remediation="Doğrudan root erişimi kapalı."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.1", title="SSH Root Girişi Açık",
                severity="CRITICAL", status="FAIL", current_value=root_login, expected_value="no",
                remediation="/etc/ssh/sshd_config içinde 'PermitRootLogin no' tanımlayın."
            ))

        # Kontrol 2: PasswordAuthentication no (Yalnızca anahtar tabanlı kimlik doğrulama)
        pass_auth = str(sshd_config.get("PasswordAuthentication", "yes")).lower()
        if pass_auth == "no":
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.2", title="SSH Parola ile Kimlik Doğrulama Kısıtlaması",
                severity="HIGH", status="PASS", current_value="no", expected_value="no",
                remediation="Parolalı oturum açma devre dışı."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.2", title="SSH Parolalı Giriş Açık (Kaba Kuvvet Riski)",
                severity="HIGH", status="FAIL", current_value=pass_auth, expected_value="no",
                remediation="sshd_config dosyasında 'PasswordAuthentication no' olarak yapılandırın."
            ))

        # Kontrol 3: MaxAuthTries <= 4
        max_tries = int(sshd_config.get("MaxAuthTries", 6))
        if max_tries <= 4:
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.3", title="SSH Maksimum Kimlik Doğrulama Denemesi",
                severity="MEDIUM", status="PASS", current_value=max_tries, expected_value="<= 4",
                remediation="Deneme sayısı sınırlandırılmış."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.3", title="SSH MaxAuthTries Değeri Çok Yüksek",
                severity="MEDIUM", status="FAIL", current_value=max_tries, expected_value="<= 4",
                remediation="sshd_config içinde 'MaxAuthTries 3' olarak ayarlayın."
            ))

        # Kontrol 4: SSH Özel Anahtar Dosya İzinleri (0600 olmalı)
        key_mode = ssh_data.get("private_key_mode", "0644")
        if key_mode == "0600":
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.4", title="SSH Özel Anahtar Dosya İzinleri",
                severity="HIGH", status="PASS", current_value=key_mode, expected_value="0600",
                remediation="Anahtar izinleri güvenli."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="SSH", rule_id="CIS-5.2.4", title="SSH Özel Anahtar Dosya İzinleri Güvensiz",
                severity="HIGH", status="FAIL", current_value=key_mode, expected_value="0600",
                remediation="chmod 0600 ~/.ssh/id_* komutuyla özel anahtar izinlerini kısıtlayın."
            ))

        self._calculate_domain_stats(domain)
        return domain

    # -------------------------------------------------------------------------
    # 5. ALAN: LINUX FIREWALL VE AĞ GÜVENLİĞİ (CIS 3.4 / 3.5)
    # -------------------------------------------------------------------------
    def audit_firewall_security(self) -> DomainAuditResult:
        """
        Linux güvenlik duvarı durumunu, varsayılan politikayı (DROP) ve açık portları denetler.
        """
        domain = DomainAuditResult(domain_name="FIREWALL_NETWORK_SECURITY")
        fw_data = self.inventory.get("firewall_spec", {})

        # Kontrol 1: Güvenlik duvarının aktifliği
        active = fw_data.get("active", False)
        backend = fw_data.get("backend", "none")
        if active and backend in ["nftables", "ufw", "iptables"]:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.1", title="Ağ Güvenlik Duvarı Durumu",
                severity="CRITICAL", status="PASS", current_value=f"{backend} aktif", expected_value="Aktif",
                remediation="Güvenlik duvarı servisi çalışıyor."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.1", title="Güvenlik Duvarı Devre Dışı veya Tanımsız",
                severity="CRITICAL", status="FAIL", current_value=f"active={active}", expected_value="Aktif",
                remediation="systemctl enable --now nftables veya ufw enable komutunu çalıştırın."
            ))

        # Kontrol 2: Varsayılan Giriş Politikası (Default Policy = DROP)
        default_policy = str(fw_data.get("default_input_policy", "ACCEPT")).upper()
        if default_policy in ["DROP", "REJECT"]:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.2", title="Varsayılan Giriş Trafiği Politikası (Default Policy)",
                severity="HIGH", status="PASS", current_value=default_policy, expected_value="DROP/REJECT",
                remediation="Varsayılan engelleme politikası etkin."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.2", title="Varsayılan Giriş Politikası Geçirgen (ACCEPT)",
                severity="HIGH", status="FAIL", current_value=default_policy, expected_value="DROP",
                remediation="Güvenlik duvarı varsayılan politikasını DROP olarak sabitleyin."
            ))

        # Kontrol 3: Durumlu Bağlantı Takibi (Stateful conntrack established/related)
        conntrack = fw_data.get("stateful_conntrack", False)
        if conntrack:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.3", title="Durumlu Bağlantı Takibi (Conntrack)",
                severity="HIGH", status="PASS", current_value="Aktif", expected_value="Aktif",
                remediation="Established/Related durumlu filtre devrede."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.3", title="Durumlu Bağlantı Filtresi Eksik",
                severity="HIGH", status="FAIL", current_value="Kapalı", expected_value="Aktif",
                remediation="Güvenlik duvarına 'ct state established,related accept' kuralını ekleyin."
            ))

        # Kontrol 4: Tehlikeli açık portların kontrolü (21/FTP, 23/Telnet, 69/TFTP)
        listening_ports = fw_data.get("listening_ports", [])
        dangerous_ports = {21, 23, 69, 513, 514}
        open_dangerous = [p for p in listening_ports if p in dangerous_ports]

        if not open_dangerous:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.4", title="Tehlikeli ve Düz Metin Açık Port Denetimi",
                severity="HIGH", status="PASS", current_value="Temiz", expected_value="Açık port yok",
                remediation="Güvensiz iletişim portu tespit edilmedi."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="FIREWALL", rule_id="CIS-3.4.4", title="Açık Tehlikeli Ağ Portu Bulundu",
                severity="HIGH", status="FAIL", current_value=open_dangerous, expected_value="Kapalı olmalı",
                remediation=f"Şu portları dinleyen servisleri sonlandırın ve portları kapatın: {open_dangerous}"
            ))

        self._calculate_domain_stats(domain)
        return domain

    # -------------------------------------------------------------------------
    # 6. ALAN: LINUX AUDIT VE JOURNAL GÜVENLİĞİ (CIS 4.1 / 4.2)
    # -------------------------------------------------------------------------
    def audit_logging_security(self) -> DomainAuditResult:
        """
        Auditd değiştirilemezlik modunu (-e 2), dosya izlemelerini ve journald FSS'i denetler.
        """
        domain = DomainAuditResult(domain_name="AUDIT_JOURNAL_INTEGRITY")
        audit_data = self.inventory.get("audit_spec", {})
        journal_data = self.inventory.get("journal_spec", {})

        # Kontrol 1: Audit Değiştirilemezlik Bayrağı (-e 2)
        immutable = audit_data.get("immutable_flag_enabled", False)
        if immutable:
            domain.findings.append(AuditFinding(
                domain="AUDIT", rule_id="CIS-4.1.18", title="Audit Kuralları Değiştirilemezlik Modu (-e 2)",
                severity="CRITICAL", status="PASS", current_value="-e 2 Aktif", expected_value="-e 2 Aktif",
                remediation="Çekirdek seviyesinde kurcalanamazlık devrede."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="AUDIT", rule_id="CIS-4.1.18", title="Audit Kuralları Kilitlenmemiş (Root Müdahale Edebilir)",
                severity="CRITICAL", status="FAIL", current_value="Kilitli Değil", expected_value="-e 2",
                remediation="/etc/audit/rules.d/audit.rules sonuna '-e 2' ekleyin ve sistemi yeniden başlatın."
            ))

        # Kontrol 2: Kritik Kimlik Dosyalarının İzlenmesi (/etc/shadow, /etc/passwd)
        watched_files = set(audit_data.get("watched_files", []))
        critical_files = {"/etc/shadow", "/etc/passwd", "/etc/sudoers"}
        missing_watches = critical_files.difference(watched_files)
        if not missing_watches:
            domain.findings.append(AuditFinding(
                domain="AUDIT", rule_id="CIS-4.1.4", title="Kritik Kimlik ve Yetki Dosyaları İzleme Kuralları",
                severity="HIGH", status="PASS", current_value="Tüm kritik dosyalar izleniyor",
                expected_value="/etc/shadow, /etc/passwd, /etc/sudoers",
                remediation="Dosya erişim denetimleri eksiksiz."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="AUDIT", rule_id="CIS-4.1.4", title="Kritik Dosyalarda Eksik Audit İzleme Kuralı",
                severity="HIGH", status="FAIL", current_value=list(missing_watches),
                expected_value="Tüm kritik dosyalar izlenmeli",
                remediation=f"Audit kurallarına şu dosyalar için izleme ekleyin: {', '.join(missing_watches)}"
            ))

        # Kontrol 3: Dinamik Çekirdek Modülü Yükleme/Kaldırma Çağrıları (init_module, delete_module)
        monitored_syscalls = set(audit_data.get("monitored_syscalls", []))
        required_syscalls = {"init_module", "delete_module"}
        missing_syscalls = required_syscalls.difference(monitored_syscalls)
        if not missing_syscalls:
            domain.findings.append(AuditFinding(
                domain="AUDIT", rule_id="CIS-4.1.16", title="Çekirdek Modülü Sistem Çağrısı Denetimi (LKM Rootkit)",
                severity="HIGH", status="PASS", current_value="init_module, delete_module izleniyor",
                expected_value="İzlenmeli", remediation="Rootkit yükleme denemeleri kaydediliyor."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="AUDIT", rule_id="CIS-4.1.16", title="Çekirdek Modülü Sistem Çağrıları İzlenmiyor",
                severity="HIGH", status="FAIL", current_value=list(missing_syscalls), expected_value="İzlenmeli",
                remediation="audit.rules dosyasına init_module ve delete_module syscall kurallarını ekleyin."
            ))

        # Kontrol 4: systemd-journald İleri Yönde Kriptografik Mühürleme (Forward Secure Sealing - FSS)
        seal = journal_data.get("Seal", False)
        storage = journal_data.get("Storage", "volatile")
        if seal and storage == "persistent":
            domain.findings.append(AuditFinding(
                domain="JOURNAL", rule_id="CIS-4.2.1", title="Journald Kalıcı Depolama ve Kriptografik Mühürleme (FSS)",
                severity="HIGH", status="PASS", current_value=f"Storage={storage}, Seal={seal}",
                expected_value="Storage=persistent, Seal=yes", remediation="Log bütünlüğü FSS ile mühürleniyor."
            ))
        else:
            domain.findings.append(AuditFinding(
                domain="JOURNAL", rule_id="CIS-4.2.1", title="Journald Kriptografik Mühürleme veya Kalıcı Depolama Eksik",
                severity="HIGH", status="FAIL", current_value=f"Storage={storage}, Seal={seal}",
                expected_value="Storage=persistent, Seal=yes",
                remediation="/etc/systemd/journald.conf içinde 'Storage=persistent' ve 'Seal=yes' yapılandırın."
            ))

        self._calculate_domain_stats(domain)
        return domain

    # -------------------------------------------------------------------------
    # GENEL DEĞERLENDİRME VE RAPORLAMA METOTLARI
    # -------------------------------------------------------------------------
    def run_full_hardening_audit(self) -> OverallHardeningReport:
        """
        Tüm 6 güvenlik alanını sırasıyla çalıştırarak genel uyumluluk raporunu üretir.
        """
        # Her bir domain için denetimi icra et
        sudo_res = self.audit_sudo_security()
        pam_res = self.audit_pam_session_security()
        systemd_res = self.audit_systemd_services()
        ssh_res = self.audit_ssh_security()
        fw_res = self.audit_firewall_security()
        log_res = self.audit_logging_security()

        # Domain sonuçlarını sözlüğe bağla
        domain_dict = {
            "SUDO": sudo_res,
            "PAM": pam_res,
            "SYSTEMD": systemd_res,
            "SSH": ssh_res,
            "FIREWALL": fw_res,
            "LOGGING": log_res
        }

        # Ağırlıklı genel puanı hesapla (Tüm domainler eşit ağırlıklı: 100/6)
        total_score = sum(d.score for d in domain_dict.values())
        compliance_score = round(total_score / len(domain_dict), 2)

        # İstatistiksel sayaçları derle
        summary_counts = {
            "total_checks": sum(d.total_checks for d in domain_dict.values()),
            "passed_checks": sum(d.passed_checks for d in domain_dict.values()),
            "failed_checks": sum(d.failed_checks for d in domain_dict.values()),
            "warning_checks": sum(d.warning_checks for d in domain_dict.values())
        }

        # Durum değerlendirmesi
        if compliance_score >= 90.0 and summary_counts["failed_checks"] == 0:
            overall_status = "COMPLIANT"
        elif compliance_score >= 70.0:
            overall_status = "AT_RISK"
        else:
            overall_status = "NON-COMPLIANT"

        # İyileştirme adımlarını derle
        remediations = []
        for d in domain_dict.values():
            for f in d.findings:
                if f.status == "FAIL":
                    remediations.append(f"[{f.domain}] {f.rule_id} - {f.title}: {f.remediation}")

        # Konsolide rapor nesnesini inşa et
        self.report = OverallHardeningReport(
            target_host=self.inventory.get("host_info", {}).get("hostname", "unknown-endpoint"),
            scan_timestamp=datetime.now().isoformat(),
            compliance_score=compliance_score,
            overall_status=overall_status,
            domain_results=domain_dict,
            summary_counts=summary_counts,
            remediation_steps=remediations
        )

        return self.report

    def generate_remediation_script(self, output_path: Optional[str] = None) -> str:
        """
        Denetimde başarısız olan kontroller için otomatik Bash sıkılaştırma betiği üretir.
        """
        if not self.report:
            self.run_full_hardening_audit()

        script_lines = [
            "#!/usr/bin/env bash",
            "# =============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Mini Proje 19: Otomatik Linux Sıkılaştırma ve Düzeltme Betiği",
            "# =============================================================================",
            "set -euo pipefail",
            "",
            "echo '[+] Linux Sertleştirme Düzeltme Betiği Başlatılıyor...'",
            ""
        ]

        # Tespit edilen her başarısızlık için kabuk komutları ekle
        for domain_name, d_res in self.report.domain_results.items():
            failed_in_domain = [f for f in d_res.findings if f.status == "FAIL"]
            if not failed_in_domain:
                continue

            script_lines.append(f"# --- {domain_name} Alanı Sıkılaştırma Önlemleri ---")
            for f in failed_in_domain:
                script_lines.append(f"# Kural: {f.rule_id} ({f.title})")
                if f.rule_id == "CIS-1.3.1":
                    script_lines.append("chmod 0440 /etc/sudoers")
                elif f.rule_id == "CIS-1.3.2":
                    script_lines.append("grep -q 'Defaults env_reset' /etc/sudoers || echo 'Defaults env_reset' >> /etc/sudoers")
                elif f.rule_id == "CIS-1.3.3":
                    script_lines.append("grep -q 'Defaults secure_path' /etc/sudoers || echo 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"' >> /etc/sudoers")
                elif f.rule_id == "CIS-1.3.4":
                    script_lines.append("# UYARI: Lütfen /etc/sudoers içindeki tehlikeli NOPASSWD satırlarını manuel olarak kaldırın.")
                elif f.rule_id == "CIS-5.4.1":
                    script_lines.append("sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf || echo 'minlen = 14' >> /etc/security/pwquality.conf")
                elif f.rule_id == "CIS-5.4.3":
                    script_lines.append("echo 'deny = 5' >> /etc/security/faillock.conf")
                    script_lines.append("echo 'unlock_time = 900' >> /etc/security/faillock.conf")
                elif f.rule_id == "CIS-5.5.1":
                    script_lines.append("echo 'readonly TMOUT=900; export TMOUT' > /etc/profile.d/tmout.sh")
                elif f.rule_id == "CIS-2.1.1":
                    script_lines.append("systemctl stop telnet rsh vsftpd xinetd 2>/dev/null || true")
                    script_lines.append("systemctl disable telnet rsh vsftpd xinetd 2>/dev/null || true")
                elif f.rule_id == "CIS-5.2.1":
                    script_lines.append("sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
                elif f.rule_id == "CIS-5.2.2":
                    script_lines.append("sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")
                elif f.rule_id == "CIS-3.4.1":
                    script_lines.append("systemctl enable --now nftables")
                elif f.rule_id == "CIS-3.4.2":
                    script_lines.append("nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'")
                elif f.rule_id == "CIS-4.1.18":
                    script_lines.append("grep -q '^-e 2' /etc/audit/rules.d/audit.rules || echo '-e 2' >> /etc/audit/rules.d/audit.rules")
                elif f.rule_id == "CIS-4.2.1":
                    script_lines.append("sed -i 's/^#\\?Seal=.*/Seal=yes/' /etc/systemd/journald.conf")
                    script_lines.append("sed -i 's/^#\\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf")
                script_lines.append("")

        script_lines.append("echo '[+] Otomatik sertleştirme adımları başarıyla tamamlandı. Yeniden başlatma önerilir.'")
        content = "\n".join(script_lines)

        if output_path:
            # Hedef dizinin varlığından emin ol
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fp:
                fp.write(content)

        return content

    def export_report_json(self, output_path: str) -> None:
        """
        Denetim raporunu standart JSON formatında diske yazar.
        """
        if not self.report:
            self.run_full_hardening_audit()

        # Dataclass hiyerarşisini sözlüğe çevir
        report_dict = asdict(self.report)
        report_dict["_lisans"] = "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)."

        # Hedef dizini garanti altına al ve dosyayı UTF-8 formatında yaz
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(report_dict, fp, indent=2, ensure_ascii=False)

    def _calculate_domain_stats(self, domain: DomainAuditResult) -> None:
        """
        Domain içindeki kontrolleri sayar ve başarı yüzdesini hesaplar.
        """
        domain.total_checks = len(domain.findings)
        domain.passed_checks = sum(1 for f in domain.findings if f.status == "PASS")
        domain.failed_checks = sum(1 for f in domain.findings if f.status == "FAIL")
        domain.warning_checks = sum(1 for f in domain.findings if f.status == "WARNING")

        if domain.total_checks > 0:
            domain.score = round((domain.passed_checks / domain.total_checks) * 100.0, 2)
        else:
            domain.score = 0.0
