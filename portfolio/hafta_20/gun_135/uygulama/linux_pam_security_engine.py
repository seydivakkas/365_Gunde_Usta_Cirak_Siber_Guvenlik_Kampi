# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux PAM (Pluggable Authentication Modules) ve Oturum Politikası Güvenlik Motoru.

Bu modül; /etc/pam.d/ modül zincirlerini, pam_faillock hesap kilitleme mekanizmasını (CWE-307),
pam_pwquality parola karmaşıklığı kurallarını (CWE-521), pam_pwhistory parola geçmişini (CWE-262),
pam_unix nullok boş parola zafiyetlerini (CWE-258) ve TMOUT oturum zaman aşımı politikalarını
(CWE-613) CIS Linux Benchmark standartlarında denetler ve puanlar.
"""

# Veri modelleri tanımlamak için dataclass dekoratörü içe aktarılıyor
from dataclasses import dataclass, field
# Tip güvenliği için gerekli typing modülleri içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any, Set
# Düzenli ifadeler ile metin ayrıştırma işlemleri için re modülü içe aktarılıyor
import re
# Dosya sistemi ve yol denetimleri için os modülü içe aktarılıyor
import os
# JSON formatlama ve ayrıştırma için json modülü içe aktarılıyor
import json


@dataclass
class AccountLockoutSpec:
    """pam_faillock veya pam_tally2 hesap kilitleme politikasını modelleyen sınıf."""
    # Hesap kilitleme modülünün aktif olup olmadığı
    enabled: bool = True
    # Kullanılan modül adı (pam_faillock veya pam_tally2)
    module_name: str = "pam_faillock"
    # Hesabın kilitleneceği başarısız deneme sayısı (CIS: <= 5)
    deny: int = 5
    # Kilidin açık kalacağı süre (saniye) (CIS: >= 900 saniye / 15 dk)
    unlock_time: int = 900
    # Başarısız denemelerin sayılacağı zaman aralığı (saniye) (CIS: >= 900)
    fail_interval: int = 900
    # Root kullanıcısının da kilitlenip kilitlenmeyeceği (even_deny_root)
    even_deny_root: bool = True


@dataclass
class PasswordQualitySpec:
    """pam_pwquality parola karmaşıklığı politikasını modelleyen sınıf."""
    # Minimum parola uzunluğu (CIS: >= 14)
    minlen: int = 14
    # Gerekli en az rakam sayısı (kredi mantığı: -1 = en az 1 rakam)
    dcredit: int = -1
    # Gerekli en az büyük harf sayısı (-1 = en az 1 büyük harf)
    ucredit: int = -1
    # Gerekli en az küçük harf sayısı (-1 = en az 1 küçük harf)
    lcredit: int = -1
    # Gerekli en az özel karakter sayısı (-1 = en az 1 özel karakter)
    ocredit: int = -1
    # Yanlış girişte izin verilen tekrar deneme sayısı
    retry: int = 3
    # Parola kurallarının root kullanıcısına da zorunlu kılınması
    enforce_for_root: bool = True


@dataclass
class SessionPolicySpec:
    """Oturum zaman aşımı ve parola geçmişi politikasını modelleyen sınıf."""
    # Boşta kalma (inactivity) zaman aşımı süresi TMOUT (saniye) (CIS: <= 900)
    inactivity_timeout_tmout: int = 900
    # pam_pwhistory ile hatırlanacak eski parola sayısı (CIS: >= 5)
    pwhistory_remember: int = 5
    # pam_unix satırlarında nullok (boş şifre izni) bulunup bulunmadığı
    nullok_present: bool = False
    # Eşzamanlı maksimum oturum sayısı (limits.conf maxlogins)
    maxlogins: int = 10


@dataclass
class PamFilePermSpec:
    """PAM ve güvenlik yapılandırma dosyalarının dosya izinleri modeli."""
    # Dosya yolu
    file_path: str
    # Dosya sahibi
    owner: str = "root"
    # Dosya grubu
    group: str = "root"
    # Sekizlik izin modu (0644 olmalıdır)
    mode_octal: str = "0644"
    # Diğer kullanıcılar tarafından yazılabilir mi
    is_writable_by_others: bool = False


@dataclass
class PamVulnerability:
    """Tespit edilen tekil bir PAM veya oturum politikası zafiyetini modelleyen sınıf."""
    # Zafiyetin ait olduğu bileşen veya dosya
    target: str
    # İlgili CWE kimliği
    cwe_id: str
    # İlgili MITRE ATT&CK tekniği
    mitre_id: str
    # Önem derecesi: CRITICAL, HIGH, MEDIUM, LOW
    severity: str
    # Zafiyet başlığı
    title: str
    # Teknik açıklama
    description: str
    # Düzeltici aksiyon
    remediation: str
    # Ceza puanı
    penalty: float


class LinuxPamSecurityEngine:
    """
    Linux PAM ve Oturum Politikası Güvenlik Denetim ve Sıkılaştırma Motoru.
    
    CIS Linux Benchmark (Section 5.4 - User Accounts and Environment) standartlarında çalışır.
    """

    def __init__(self) -> None:
        """Denetim motorunu başlatır."""
        # Başlangıç tam puanı
        self.base_score: float = 100.0
        # Tespit edilen bulguları saklayan liste
        self.findings: List[PamVulnerability] = []
        # Analiz sonuç raporu
        self.audit_report: Dict[str, Any] = {}

    def audit_account_lockout(self, lockout: AccountLockoutSpec) -> List[PamVulnerability]:
        """pam_faillock hesap kilitleme mekanizmasını denetler (CWE-307 / MITRE T1110.001)."""
        lockout_findings: List[PamVulnerability] = []

        # Kontrol 1: Hesap Kilitleme Tamamen Devre Dışı mı?
        if not lockout.enabled:
            lockout_findings.append(
                PamVulnerability(
                    target="/etc/pam.d/system-auth & password-auth",
                    cwe_id="CWE-307",
                    mitre_id="T1110.001",
                    severity="CRITICAL",
                    title="Hesap Kilitleme Koruması (pam_faillock) Devre Dışı",
                    description=(
                        "Sistemde başarısız oturum açma denemelerine karşı hesap kilitleme mekanizması kapalıdır. "
                        "Saldırganlar sınırsız kaba kuvvet (brute-force) ve parola deneme saldırısı gerçekleştirebilir."
                    ),
                    remediation=(
                        "authselect select sssd with-faillock veya /etc/security/faillock.conf yapılandırmasıyla "
                        "pam_faillock modülünü aktifleştirin."
                    ),
                    penalty=25.0,
                )
            )
            return lockout_findings

        # Kontrol 2: Gevşek Başarısız Deneme Eşiği (deny > 5)
        if lockout.deny > 5 or lockout.deny <= 0:
            lockout_findings.append(
                PamVulnerability(
                    target="faillock.conf: deny",
                    cwe_id="CWE-307",
                    mitre_id="T1110.001",
                    severity="HIGH",
                    title=f"Yetersiz Hesap Kilitleme Eşiği (deny={lockout.deny})",
                    description=f"CIS standardı en fazla 5 başarısız denemeye izin verir. Mevcut değer: {lockout.deny}.",
                    remediation="/etc/security/faillock.conf dosyasına 'deny = 5' satırını ekleyin.",
                    penalty=10.0,
                )
            )

        # Kontrol 3: Yetersiz Kilit Süresi (unlock_time < 900 saniye)
        if lockout.unlock_time < 900 and lockout.unlock_time != 0:
            lockout_findings.append(
                PamVulnerability(
                    target="faillock.conf: unlock_time",
                    cwe_id="CWE-307",
                    mitre_id="T1110.001",
                    severity="HIGH",
                    title=f"Yetersiz Hesap Kilit Kalma Süresi (unlock_time={lockout.unlock_time}s)",
                    description=(
                        f"Kilit süresi {lockout.unlock_time} saniyedir. CIS standardı en az 900 saniye (15 dakika) "
                        f"veya yönetici müdahalesine kadar kilitli kalmayı (0) şart koşar."
                    ),
                    remediation="/etc/security/faillock.conf dosyasına 'unlock_time = 900' satırını ekleyin.",
                    penalty=10.0,
                )
            )

        # Kontrol 4: Root Kullanıcısının Hariç Tutulması (even_deny_root eksikliği)
        if not lockout.even_deny_root:
            lockout_findings.append(
                PamVulnerability(
                    target="faillock.conf: even_deny_root",
                    cwe_id="CWE-307",
                    mitre_id="T1110.001",
                    severity="MEDIUM",
                    title="Root Kullanıcısı İçin Hesap Kilitleme Koruması Kapalı",
                    description="even_deny_root direktifinin olmaması, root hesabına yönelik kaba kuvvet saldırılarını engellemez.",
                    remediation="/etc/security/faillock.conf dosyasına 'even_deny_root' parametresini ekleyin.",
                    penalty=5.0,
                )
            )

        return lockout_findings

    def audit_password_quality(self, quality: PasswordQualitySpec) -> List[PamVulnerability]:
        """pam_pwquality parola karmaşıklığı kurallarını denetler (CWE-521)."""
        quality_findings: List[PamVulnerability] = []

        # Kontrol 5: Yetersiz Minimum Parola Uzunluğu (minlen < 14)
        if quality.minlen < 14:
            quality_findings.append(
                PamVulnerability(
                    target="/etc/security/pwquality.conf: minlen",
                    cwe_id="CWE-521",
                    mitre_id="T1201",
                    severity="HIGH",
                    title=f"Yetersiz Minimum Parola Uzunluğu (minlen={quality.minlen})",
                    description=f"CIS standardı minimum 14 karakter parola uzunluğu gerektirir. Mevcut değer: {quality.minlen}.",
                    remediation="/etc/security/pwquality.conf dosyasına 'minlen = 14' direktifini ekleyin.",
                    penalty=10.0,
                )
            )

        # Kontrol 6: Eksik Karakter Türü Zorunlulukları (dcredit, ucredit, lcredit, ocredit)
        credits_missing = []
        if quality.dcredit > -1:
            credits_missing.append("Rakam (dcredit)")
        if quality.ucredit > -1:
            credits_missing.append("Büyük Harf (ucredit)")
        if quality.lcredit > -1:
            credits_missing.append("Küçük Harf (lcredit)")
        if quality.ocredit > -1:
            credits_missing.append("Özel Karakter (ocredit)")

        if credits_missing:
            missing_str = ", ".join(credits_missing)
            quality_findings.append(
                PamVulnerability(
                    target="/etc/security/pwquality.conf: credits",
                    cwe_id="CWE-521",
                    mitre_id="T1201",
                    severity="HIGH",
                    title=f"Eksik Parola Karmaşıklık Kredileri ({missing_str})",
                    description=(
                        f"Parola karmaşıklık kurallarında şu gereksinimler zorunlu tutulmamış: {missing_str}. "
                        f"CIS uyarınca dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1 ayarlanmalıdır."
                    ),
                    remediation="pwquality.conf içinde 'dcredit = -1', 'ucredit = -1', 'lcredit = -1', 'ocredit = -1' değerlerini tanımlayın.",
                    penalty=10.0,
                )
            )

        # Kontrol 7: Root İçin Parola Zorunluluğu Kapalı mı?
        if not quality.enforce_for_root:
            quality_findings.append(
                PamVulnerability(
                    target="/etc/security/pwquality.conf: enforce_for_root",
                    cwe_id="CWE-521",
                    mitre_id="T1201",
                    severity="MEDIUM",
                    title="Root Kullanıcısı İçin Parola Karmaşıklık Kontrolü Kapalı",
                    description="enforce_for_root bayrağının eksik olması root kullanıcısının zayıf parola belirlemesine izin verir.",
                    remediation="/etc/security/pwquality.conf dosyasına 'enforce_for_root' satırını ekleyin.",
                    penalty=5.0,
                )
            )

        return quality_findings

    def audit_session_policy(self, session: SessionPolicySpec) -> List[PamVulnerability]:
        """Oturum zaman aşımı, boş parola (nullok) ve parola geçmişi politikalarını denetler."""
        session_findings: List[PamVulnerability] = []

        # Kontrol 8: Boş Parola Giriş İzni (nullok) (CWE-258 / MITRE T1078)
        if session.nullok_present:
            session_findings.append(
                PamVulnerability(
                    target="/etc/pam.d/* (pam_unix.so nullok)",
                    cwe_id="CWE-258",
                    mitre_id="T1078",
                    severity="CRITICAL",
                    title="Boş Parola ile Giriş İzni (nullok Bayrağı Aktif)",
                    description=(
                        "pam_unix modülünde 'nullok' parametresi etkindir. Parolası olmayan hesaplar parola girmeden "
                        "sisteme oturum açabilir. Bu durum sistemde ciddi kimlik doğrulama bypass açığı yaratır."
                    ),
                    remediation="/etc/pam.d/ altındaki tüm yapılandırma dosyalarından 'nullok' argümanını kaldırın.",
                    penalty=25.0,
                )
            )

        # Kontrol 9: Parola Geçmişi ve Tekrar Kullanım Kısıtı (pwhistory_remember < 5) (CWE-262)
        if session.pwhistory_remember < 5:
            session_findings.append(
                PamVulnerability(
                    target="/etc/pam.d/system-auth: pam_pwhistory.so",
                    cwe_id="CWE-262",
                    mitre_id="T1201",
                    severity="HIGH",
                    title=f"Yetersiz Parola Geçmişi Koruması (remember={session.pwhistory_remember})",
                    description=(
                        f"Sistem son {session.pwhistory_remember} parolayı hatırlamaktadır. CIS standardı en az son 5 parolanın "
                        f"tekrar kullanımının engellenmesini şart koşar."
                    ),
                    remediation="/etc/pam.d/password-auth ve system-auth dosyalarına 'password required pam_pwhistory.so remember=5' satırını ekleyin.",
                    penalty=15.0,
                )
            )

        # Kontrol 10: Oturum Boşta Kalma Zaman Aşımı (TMOUT > 900 veya tanımsız) (CWE-613)
        if session.inactivity_timeout_tmout > 900 or session.inactivity_timeout_tmout <= 0:
            session_findings.append(
                PamVulnerability(
                    target="/etc/profile.d/timeout.sh: TMOUT",
                    cwe_id="CWE-613",
                    mitre_id="T1078",
                    severity="HIGH",
                    title=f"Yetersiz Oturum Zaman Aşımı (TMOUT={session.inactivity_timeout_tmout}s)",
                    description=(
                        f"Kabuk boşta kalma zaman aşımı (TMOUT) {session.inactivity_timeout_tmout} saniyedir veya tanımsızdır. "
                        f"CIS standardı boşta kalan oturumların en fazla 900 saniye (15 dakika) içinde sonlandırılmasını gerektirir."
                    ),
                    remediation=(
                        "echo 'readonly TMOUT=900 ; export TMOUT' > /etc/profile.d/timeout.sh && chmod 0644 /etc/profile.d/timeout.sh"
                    ),
                    penalty=15.0,
                )
            )

        return session_findings

    def audit_pam_permissions(self, perms: List[PamFilePermSpec]) -> List[PamVulnerability]:
        """PAM ve güvenlik yapılandırma dosyalarının izinlerini denetler (CWE-732)."""
        perm_findings: List[PamVulnerability] = []

        for p in perms:
            # Sahip veya grup root değilse
            if p.owner != "root" or p.group != "root":
                perm_findings.append(
                    PamVulnerability(
                        target=p.file_path,
                        cwe_id="CWE-732",
                        mitre_id="T1548",
                        severity="CRITICAL",
                        title=f"PAM Dosyası Root Sahipliğinde Değil ({p.file_path})",
                        description=f"'{p.file_path}' dosyasının sahibi {p.owner}:{p.group} olarak ayarlanmış. Mutlaka root:root olmalıdır.",
                        remediation=f"chown root:root {p.file_path}",
                        penalty=25.0,
                    )
                )

            # Dosya başkaları tarafından yazılabilirse veya modu 0644/0600 değilse
            if p.is_writable_by_others or p.mode_octal not in ["0644", "0600", "0440", "0400"]:
                perm_findings.append(
                    PamVulnerability(
                        target=p.file_path,
                        cwe_id="CWE-732",
                        mitre_id="T1548",
                        severity="CRITICAL",
                        title=f"Gevşek PAM Dosya İzni ({p.file_path} - Mod: {p.mode_octal})",
                        description=(
                            f"'{p.file_path}' dosyasının izin modu {p.mode_octal} olarak ayarlanmış. "
                            f"Yetkisiz kullanıcılar PAM kurallarını değiştirerek kimlik doğrulamayı bypass edebilir."
                        ),
                        remediation=f"chmod 0644 {p.file_path}",
                        penalty=25.0,
                    )
                )

        return perm_findings

    def run_pam_audit(self, inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Tüm PAM ve oturum envanterini denetler, güvenlik skorunu hesaplar ve rapor üretir."""
        self.findings.clear()

        # 1. Hesap Kilitleme Denetimi
        lockout_data = inventory.get("account_lockout", {})
        lockout_spec = AccountLockoutSpec(
            enabled=lockout_data.get("enabled", True),
            module_name=lockout_data.get("module_name", "pam_faillock"),
            deny=lockout_data.get("deny", 5),
            unlock_time=lockout_data.get("unlock_time", 900),
            fail_interval=lockout_data.get("fail_interval", 900),
            even_deny_root=lockout_data.get("even_deny_root", True),
        )
        self.findings.extend(self.audit_account_lockout(lockout_spec))

        # 2. Parola Karmaşıklık Denetimi
        pwq_data = inventory.get("password_quality", {})
        pwq_spec = PasswordQualitySpec(
            minlen=pwq_data.get("minlen", 14),
            dcredit=pwq_data.get("dcredit", -1),
            ucredit=pwq_data.get("ucredit", -1),
            lcredit=pwq_data.get("lcredit", -1),
            ocredit=pwq_data.get("ocredit", -1),
            retry=pwq_data.get("retry", 3),
            enforce_for_root=pwq_data.get("enforce_for_root", True),
        )
        self.findings.extend(self.audit_password_quality(pwq_spec))

        # 3. Oturum Politikası Denetimi
        sess_data = inventory.get("session_policy", {})
        sess_spec = SessionPolicySpec(
            inactivity_timeout_tmout=sess_data.get("inactivity_timeout_tmout", 900),
            pwhistory_remember=sess_data.get("pwhistory_remember", 5),
            nullok_present=sess_data.get("nullok_present", False),
            maxlogins=sess_data.get("maxlogins", 10),
        )
        self.findings.extend(self.audit_session_policy(sess_spec))

        # 4. Dosya İzinleri Denetimi
        perms_data = inventory.get("file_permissions", [])
        perms_specs = [
            PamFilePermSpec(
                file_path=p.get("file_path", "/etc/pam.d/system-auth"),
                owner=p.get("owner", "root"),
                group=p.get("group", "root"),
                mode_octal=p.get("mode_octal", "0644"),
                is_writable_by_others=p.get("is_writable_by_others", False),
            )
            for p in perms_data
        ]
        self.findings.extend(self.audit_pam_permissions(perms_specs))

        # Toplam Puan Hesaplaması
        total_penalties = sum(f.penalty for f in self.findings)
        final_score = max(0.0, round(self.base_score - total_penalties, 2))

        # Uyum Durumu
        if final_score >= 85.0:
            status = "SECURE"
        elif final_score >= 60.0:
            status = "WARNING"
        else:
            status = "CRITICAL"

        # Şiddet Dağılımı
        severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            if f.severity in severity_summary:
                severity_summary[f.severity] += 1

        self.audit_report = {
            "audit_metadata": {
                "standard": "CIS Linux Benchmark (Section 5.4 - User Accounts and PAM Policy)",
                "auditor": "Seydi Eryılmaz (@seydivakkas)",
                "timestamp": "2026-11-02T14:15:00Z",
            },
            "summary": {
                "score": final_score,
                "max_score": 100.0,
                "status": status,
                "total_vulnerabilities": len(self.findings),
                "severity_breakdown": severity_summary,
            },
            "findings_detail": [
                {
                    "target": f.target,
                    "cwe_id": f.cwe_id,
                    "mitre_id": f.mitre_id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                    "penalty": f.penalty,
                }
                for f in self.findings
            ],
        }

        return self.audit_report

    def generate_bash_remediation_script(self) -> str:
        """Tespit edilen PAM ve oturum zafiyetleri için otomatik Bash iyileştirme betiği üretir."""
        lines = [
            "#!/bin/bash",
            "# ===========================================================================",
            "# Linux PAM ve Oturum Politikası Otomatik Sıkılaştırma Betiği",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) - Tüm Hakları Saklıdır",
            "# ===========================================================================",
            "set -euo pipefail",
            "",
            "echo '[*] Linux PAM ve Oturum Güvenliği Sıkılaştırma Başlatılıyor...'",
            "",
            "# 1. PAM Dosya İzinlerinin Sıkılaştırılması",
            "chown -R root:root /etc/pam.d/ /etc/security/",
            "chmod 0755 /etc/pam.d/ /etc/security/",
            "find /etc/pam.d/ -type f -exec chmod 0644 {} +",
            "find /etc/security/ -type f -exec chmod 0644 {} +",
            "echo '[+] PAM ve security dosyaları 0644 (root:root) olarak mühürlendi.'",
            "",
            "# 2. Oturum Zaman Aşımı (TMOUT = 900s / 15 dk)",
            "cat << 'EOF' > /etc/profile.d/timeout.sh",
            "# Oturum Inactivity Zaman Asimi (CIS Kurali)",
            "readonly TMOUT=900",
            "export TMOUT",
            "EOF",
            "chmod 0644 /etc/profile.d/timeout.sh",
            "echo '[+] Oturum zaman aşımı (TMOUT=900) /etc/profile.d/timeout.sh dosyasına yazıldı.'",
            "",
            "# 3. Parola Karmaşıklığı (pwquality.conf)",
            "if [ -f /etc/security/pwquality.conf ]; then",
            "    sed -i '/^minlen/d' /etc/security/pwquality.conf",
            "    sed -i '/^dcredit/d' /etc/security/pwquality.conf",
            "    sed -i '/^ucredit/d' /etc/security/pwquality.conf",
            "    sed -i '/^lcredit/d' /etc/security/pwquality.conf",
            "    sed -i '/^ocredit/d' /etc/security/pwquality.conf",
            "    sed -i '/^enforce_for_root/d' /etc/security/pwquality.conf",
            "    echo 'minlen = 14' >> /etc/security/pwquality.conf",
            "    echo 'dcredit = -1' >> /etc/security/pwquality.conf",
            "    echo 'ucredit = -1' >> /etc/security/pwquality.conf",
            "    echo 'lcredit = -1' >> /etc/security/pwquality.conf",
            "    echo 'ocredit = -1' >> /etc/security/pwquality.conf",
            "    echo 'enforce_for_root' >> /etc/security/pwquality.conf",
            "    echo '[+] pwquality.conf başarıyla güncellendi.'",
            "fi",
            "",
            "# 4. Hesap Kilitleme (faillock.conf)",
            "if [ -f /etc/security/faillock.conf ]; then",
            "    sed -i '/^deny/d' /etc/security/faillock.conf",
            "    sed -i '/^unlock_time/d' /etc/security/faillock.conf",
            "    sed -i '/^fail_interval/d' /etc/security/faillock.conf",
            "    sed -i '/^even_deny_root/d' /etc/security/faillock.conf",
            "    echo 'deny = 5' >> /etc/security/faillock.conf",
            "    echo 'unlock_time = 900' >> /etc/security/faillock.conf",
            "    echo 'fail_interval = 900' >> /etc/security/faillock.conf",
            "    echo 'even_deny_root' >> /etc/security/faillock.conf",
            "    echo '[+] faillock.conf başarıyla güncellendi.'",
            "fi",
            "",
            "echo '[+] PAM ve oturum güvenlik sıkılaştırması başarıyla tamamlandı!'",
        ]
        return "\n".join(lines)
