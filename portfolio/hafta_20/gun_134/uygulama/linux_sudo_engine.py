# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Sudo ve Ayrıcalık Devri Güvenlik Denetim Motoru.

Bu modül; Linux işletim sistemlerinde /etc/sudoers ve /etc/sudoers.d/ yapılandırmalarını,
tehlikeli NOPASSWD izinlerini, GTFOBins kabuk kaçış (shell escape) açıklarını,
env_keep kütüphane enjeksiyon risklerini (LD_PRELOAD), Defaults sıkılaştırma direktiflerini
ve sudoers dosya izinlerini (CWE-250, CWE-732, CWE-426) kapsamlı olarak denetler.
"""

# Veri sınıfları oluşturmak için dataclass dekoratörü içe aktarılıyor
from dataclasses import dataclass, field
# Tip güvenliği ve açıklamaları için typing modülü içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any, Set
# Düzenli ifadeler ile sözdizimi ayrıştırma işlemleri için re modülü içe aktarılıyor
import re
# Dosya ve dizin yolu manipülasyonu için os modülü içe aktarılıyor
import os
# JSON formatlama ve ayrıştırma için json modülü içe aktarılıyor
import json

# GTFOBins uyarınca sudo ayrıcalığıyla çalıştırıldığında kabuk kaçışı (shell escape),
# yetkisiz dosya okuma veya yazma sağlayarak yetki yükseltmeye (LPE) olanak tanıyan ikili dosyalar
GTFOBINS_EXPLOITABLE_BINARIES = {
    "vim": "Vim editörü (:!/bin/sh veya :set shell=/bin/sh ile root kabuğu açar)",
    "vi": "Vi editörü (:!/bin/sh ile doğrudan root kabuğu açar)",
    "nano": "Nano editörü (^R^X ile harici komut çalıştırarak yetki yükseltir)",
    "find": "Find komutu (-exec /bin/sh \\; parametresiyle doğrudan root kabuğu açar)",
    "awk": "AWK betik motoru (system(\"/bin/sh\") çağrısıyla root kabuğu üretir)",
    "gawk": "GNU AWK (system çağrısı ile root kabuğu üretir)",
    "mawk": "Mawk yorumlayıcısı (system çağrısıyla root kabuğu üretir)",
    "less": "Less sayfalayıcısı (!/bin/sh komutuyla kabuk kaçışı sağlar)",
    "more": "More sayfalayıcısı (!/bin/sh komutuyla kabuk kaçışı sağlar)",
    "python": "Python yorumlayıcısı (pty.spawn(\"/bin/bash\") ile root kabuğu açar)",
    "python3": "Python 3 yorumlayıcısı (pty.spawn(\"/bin/bash\") ile root kabuğu açar)",
    "perl": "Perl yorumlayıcısı (exec(\"/bin/sh\") ile root kabuğu açar)",
    "ruby": "Ruby yorumlayıcısı (exec(\"/bin/sh\") ile root kabuğu açar)",
    "lua": "Lua yorumlayıcısı (os.execute(\"/bin/sh\") ile root kabuğu açar)",
    "php": "PHP CLI (pcntl_exec veya system ile root kabuğu açar)",
    "bash": "Bash kabuğu (Doğrudan root ayrıcalıklı interaktif kabuk sağlar)",
    "sh": "Sh kabuğu (Doğrudan root ayrıcalıklı kabuk sağlar)",
    "zsh": "Zsh kabuğu (Doğrudan root ayrıcalıklı kabuk sağlar)",
    "tar": "Tar arşivleme aracı (--to-command veya checkpoint script ile kod çalıştırır)",
    "zip": "Zip aracı (--unzip-command ile harici komut tetikler)",
    "nmap": "Nmap aracı (--script veya eski sürümlerde !sh interaktif modu ile root kabuğu açar)",
    "tcpdump": "Tcpdump aracı (-z parametresi ile pcap dosyası sonrasında rastgele script çalıştırır)",
    "env": "Env komutu (env /bin/sh ile doğrudan yetkili kabuk açar)",
    "tee": "Tee komutu (/etc/passwd veya /etc/sudoers dosyasına yetkisiz yazma sağlar)",
    "chmod": "Chmod aracı (/etc/shadow veya dosya izinlerini manipüle eder)",
    "chown": "Chown aracı (Kritik sistem dosyalarının sahipliğini değiştirir)",
}

# Sudo ortamında asla saklanmaması (env_keep) gereken tehlikeli çevre değişkenleri (CWE-426)
DANGEROUS_ENV_VARIABLES = {
    "LD_PRELOAD": "Paylaşımlı kütüphane enjeksiyonu sağlayarak root yetkisinde kod çalıştırır",
    "LD_LIBRARY_PATH": "Özel kütüphane arama yolunu manipüle ederek zararlı kütüphane yükler",
    "PYTHONPATH": "Python modül arama yolunu ezerek yetkili süreçte zararlı modül yükler",
    "RUBYOPT": "Ruby yürütme parametrelerini manipüle ederek kod enjekte eder",
    "PERL5OPT": "Perl çalıştırma seçeneklerini manipüle ederek kod çalıştırır",
    "GLIBC_TUNABLES": "Glibc zafiyetlerini (Looney Tunables vb.) tetiklemek için kullanılabilir",
}


@dataclass
class SudoRuleSpec:
    """Tekil bir sudoers kuralını temsil eden veri modeli."""
    # Kuralın uygulandığı kullanıcı, grup veya kullanıcı alias'ı
    user_or_group: str
    # Kuralın geçerli olduğu ana bilgisayarlar (Örn: ALL, localhost)
    hosts: str = "ALL"
    # Komutun hangi kullanıcı yetkisiyle çalışacağı (Örn: (ALL), (root))
    runas_user: str = "ALL"
    # Kural etiketleri (Örn: NOPASSWD, PASSWD, NOEXEC)
    tags: List[str] = field(default_factory=list)
    # Yetki verilen komutlar listesi (Örn: ['/usr/bin/find', '/bin/cat /var/log/*'])
    commands: List[str] = field(default_factory=list)


@dataclass
class SudoDefaultsSpec:
    """Sudoers 'Defaults' genel yapılandırma direktiflerini modelleyen sınıf."""
    # Çevre değişkenlerinin sıfırlanması zorunluluğu (En kritik güvenlik direktifi)
    env_reset: bool = True
    # Güvenli PATH arama listesi
    secure_path: str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    # Sudo işlemlerinin sahte tty içerisinde yürütülmesi (Anti-injection)
    use_pty: bool = True
    # Başarısız parola denemelerinin yöneticiye e-postalanması
    mail_badpass: bool = True
    # Sudo işlem günlük dosyası yolu
    logfile: str = "/var/log/sudo.log"
    # Kimlik doğrulama önbellek süresi (dakika)
    timestamp_timeout: int = 15
    # env_keep listesinde tutulan çevre değişkenleri
    env_keep: List[str] = field(default_factory=list)


@dataclass
class SudoFilePermSpec:
    """Sudoers dosyalarının dosya sistemi izinlerini denetleyen model."""
    # Dosya yolu (Örn: /etc/sudoers veya /etc/sudoers.d/01-devops)
    file_path: str
    # Dosya sahibi kullanıcı (root olmalıdır)
    owner: str = "root"
    # Dosya grubu (root olmalıdır)
    group: str = "root"
    # Sekizlik izin modu (0440 veya 0400 olmalıdır)
    mode_octal: str = "0440"
    # Diğer kullanıcılar (others) tarafından yazılabilir mi
    is_writable_by_others: bool = False


@dataclass
class SudoVulnerability:
    """Tespit edilen tekil bir Linux Sudo zafiyetini modelleyen sınıf."""
    # Zafiyetin ait olduğu hedef kural, direktif veya dosya
    target: str
    # İlgili CWE numarası
    cwe_id: str
    # İlgili MITRE ATT&CK tekniği
    mitre_id: str
    # Önem derecesi: CRITICAL, HIGH, MEDIUM, LOW
    severity: str
    # Zafiyet başlığı
    title: str
    # Derinlemesine teknik açıklama
    description: str
    # Düzeltici visudo / bash aksiyonu
    remediation: str
    # Puan düşümü
    penalty: float


class LinuxSudoSecurityEngine:
    """
    Linux Sudo ve Ayrıcalık Devri Güvenlik Denetim, Puanlama ve Sıkılaştırma Motoru.
    
    CIS Linux Benchmark, GTFOBins ve MITRE ATT&CK T1548.003 standartlarında denetim yapar.
    """

    def __init__(self) -> None:
        """Denetim motorunu başlatır."""
        # Başlangıç tam puanı
        self.base_score: float = 100.0
        # Tespit edilen tüm zafiyetler listesi
        self.findings: List[SudoVulnerability] = []
        # Denetim rapor sözlüğü
        self.audit_report: Dict[str, Any] = {}

    def extract_binary_name(self, command_path: str) -> str:
        """Komut yolundan ikili dosya (binary) adını çıkarır."""
        # Yol başındaki ve sonundaki boşluklar temizlenir
        clean_cmd = command_path.strip()
        # İlk boşluğa kadar olan çalıştırılabilir dosya yolu alınır
        executable_part = clean_cmd.split()[0] if clean_cmd else ""
        # Yoldaki son bileşen dosya adı olarak döndürülür
        return os.path.basename(executable_part).lower()

    def audit_sudo_rules(self, rules: List[SudoRuleSpec]) -> List[SudoVulnerability]:
        """Sudo yetkilendirme kurallarını GTFOBins, NOPASSWD ve Wildcard açısından denetler."""
        rule_findings: List[SudoVulnerability] = []

        for rule in rules:
            has_nopasswd = "NOPASSWD" in rule.tags
            target_user = rule.user_or_group

            # Kontrol 1: Tehlikeli NOPASSWD: ALL İzni (CWE-250 / T1548.003)
            if "ALL" in rule.commands and has_nopasswd:
                rule_findings.append(
                    SudoVulnerability(
                        target=f"Rule: {target_user} -> ALL",
                        cwe_id="CWE-250",
                        mitre_id="T1548.003",
                        severity="CRITICAL",
                        title=f"Şifresiz Tam Root Yetkisi (NOPASSWD: ALL) [{target_user}]",
                        description=(
                            f"'{target_user}' kullanıcısı/grubuna parola girmeden tüm komutları root olarak "
                            f"çalıştırma izni verilmiş. Bu durum parola bariyerini kaldırarak anında root yükseltmesi sağlar."
                        ),
                        remediation=f"/etc/sudoers dosyasında '{target_user}' için NOPASSWD etiketini kaldırın ve komutları kısıtlayın.",
                        penalty=30.0,
                    )
                )

            # Her bir komut ayrı ayrı GTFOBins ve Wildcard taramasından geçirilir
            for cmd in rule.commands:
                # Sadece ALL değilse komut incelemesi yapılır
                if cmd == "ALL":
                    continue

                binary_name = self.extract_binary_name(cmd)

                # Kontrol 2: GTFOBins Zafiyetli İkili Dosya İzni (CWE-250 / T1548.003)
                if binary_name in GTFOBINS_EXPLOITABLE_BINARIES:
                    exploit_desc = GTFOBINS_EXPLOITABLE_BINARIES[binary_name]
                    # NOPASSWD ile birleştiğinde kritik, parolalı ise yüksek risk
                    severity_level = "CRITICAL" if has_nopasswd else "HIGH"
                    penalty_amount = 25.0 if has_nopasswd else 15.0

                    rule_findings.append(
                        SudoVulnerability(
                            target=f"Rule: {target_user} -> {cmd}",
                            cwe_id="CWE-250",
                            mitre_id="T1548.003",
                            severity=severity_level,
                            title=f"GTFOBins Kabuk Kaçışı Zafiyeti ({binary_name}) [{target_user}]",
                            description=(
                                f"'{target_user}' kullanıcısına '{cmd}' komutunu sudo ile çalıştırma izni verilmiş. "
                                f"{exploit_desc}. Bu ikili dosya kısıtlamasız çalıştırılarak root kabuğu elde edilebilir."
                            ),
                            remediation=(
                                f"'{binary_name}' ikili dosyasını doğrudan sudoers içerisine eklemeyin. "
                                f"İhtiyaç duyulan işlevi özel bir kısıtlı script içerisine alarak NOEXEC etiketi uygulayın."
                            ),
                            penalty=penalty_amount,
                        )
                    )

                # Kontrol 3: Komut Argümanlarında Tehlikeli Wildcard (*) Kullanımı (CWE-88)
                if "*" in cmd:
                    rule_findings.append(
                        SudoVulnerability(
                            target=f"Rule: {target_user} -> {cmd}",
                            cwe_id="CWE-88",
                            mitre_id="T1548.003",
                            severity="MEDIUM",
                            title=f"Komut Yolunda Denetimsiz Wildcard (*) Kullanımı [{target_user}]",
                            description=(
                                f"'{cmd}' komutunda joker karakter (*) kullanılmış. Saldırgan araya parametre veya dosya adı "
                                f"enjeksiyonu yaparak yetkisiz dizinleri veya komut satırı anahtarlarını tetikleyebilir."
                            ),
                            remediation="Wildcard yerine tam ve kesin dosya yolları tanımlayın veya regex doğrulayıcı wrapper script kullanın.",
                            penalty=10.0,
                        )
                    )

        return rule_findings

    def audit_sudo_defaults(self, defaults: SudoDefaultsSpec) -> List[SudoVulnerability]:
        """Sudo 'Defaults' direktiflerini sıkılaştırma standartları açısından denetler."""
        defaults_findings: List[SudoVulnerability] = []

        # Kontrol 4: env_reset Direktifi Eksikliği (CWE-250 / T1548.003)
        if not defaults.env_reset:
            defaults_findings.append(
                SudoVulnerability(
                    target="Defaults env_reset",
                    cwe_id="CWE-250",
                    mitre_id="T1548.003",
                    severity="HIGH",
                    title="Defaults env_reset Direktifi Kapalı",
                    description=(
                        "env_reset direktifinin devre dışı olması, kullanıcının çağıran kabuk çevre değişkenlerini "
                        "root sürecine aktarmasına imkan tanır. Bu durum çevre değişkeni manipülasyonuyla yetki yükseltmeye yol açar."
                    ),
                    remediation="/etc/sudoers dosyasına 'Defaults env_reset' satırını ekleyin.",
                    penalty=15.0,
                )
            )

        # Kontrol 5: env_keep İçerisinde Tehlikeli Kütüphane Değişkenleri (CWE-426 / T1574.006)
        dangerous_kept = [v for v in defaults.env_keep if v in DANGEROUS_ENV_VARIABLES]
        if dangerous_kept:
            kept_str = ", ".join(dangerous_kept)
            defaults_findings.append(
                SudoVulnerability(
                    target=f"Defaults env_keep += '{kept_str}'",
                    cwe_id="CWE-426",
                    mitre_id="T1574.006",
                    severity="CRITICAL",
                    title="Tehlikeli Çevre Değişkeni Koruması (env_keep Injection)",
                    description=(
                        f"env_keep listesinde şu ölümcül kütüphane değişkenleri korunmaktadır: {kept_str}. "
                        f"Saldırgan LD_PRELOAD ile kendi derlediği .so kütüphanesini root sürecine enjekte ederek anında root olur."
                    ),
                    remediation=f"env_keep listesinden {kept_str} değişkenlerini derhal kaldırın.",
                    penalty=25.0,
                )
            )

        # Kontrol 6: Güvensiz secure_path Tanımı (CWE-426)
        if "." in defaults.secure_path.split(":") or "/tmp" in defaults.secure_path:
            defaults_findings.append(
                SudoVulnerability(
                    target="Defaults secure_path",
                    cwe_id="CWE-426",
                    mitre_id="T1574.007",
                    severity="HIGH",
                    title="Güvensiz Sudo secure_path Yapılandırması",
                    description=(
                        f"secure_path değeri ({defaults.secure_path}) göreceli dizin (nokta '.') veya geçici "
                        f"dizin (/tmp) içermektedir. Araya bırakılan sahte binary'lerin root olarak çalıştırılmasına neden olur."
                    ),
                    remediation="secure_path değerini standart sistem dizinleri ile sınırlayın: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    penalty=15.0,
                )
            )

        # Kontrol 7: use_pty Direktifi Eksikliği (CWE-284)
        if not defaults.use_pty:
            defaults_findings.append(
                SudoVulnerability(
                    target="Defaults use_pty",
                    cwe_id="CWE-284",
                    mitre_id="T1548.003",
                    severity="MEDIUM",
                    title="Defaults use_pty Direktifi Tanımlanmamış",
                    description="use_pty eksikliği, alt süreçlerin ana terminal girdisine komut enjekte etmesine (TIOCSTI ioctl injection) zemin hazırlar.",
                    remediation="/etc/sudoers dosyasına 'Defaults use_pty' direktifini ekleyin.",
                    penalty=5.0,
                )
            )

        # Kontrol 8: logfile Tanımlanmamış (CWE-778)
        if not defaults.logfile:
            defaults_findings.append(
                SudoVulnerability(
                    target="Defaults logfile",
                    cwe_id="CWE-778",
                    mitre_id="T1083",
                    severity="LOW",
                    title="Sudo Özel Günlükleme Dosyası (logfile) Eksik",
                    description="Sudo ile çalıştırılan komutlar özel bir denetim günlüğüne (/var/log/sudo.log) kaydedilmemektedir.",
                    remediation="/etc/sudoers dosyasına 'Defaults logfile=\"/var/log/sudo.log\"' direktifini ekleyin.",
                    penalty=5.0,
                )
            )

        return defaults_findings

    def audit_sudoers_permissions(self, perm_specs: List[SudoFilePermSpec]) -> List[SudoVulnerability]:
        """Sudoers ve sudoers.d dosyalarının erişim izinlerini denetler (CWE-732)."""
        perm_findings: List[SudoVulnerability] = []

        for p in perm_specs:
            # Sahip veya grup root değilse
            if p.owner != "root" or p.group != "root":
                perm_findings.append(
                    SudoVulnerability(
                        target=p.file_path,
                        cwe_id="CWE-732",
                        mitre_id="T1548.003",
                        severity="CRITICAL",
                        title=f"Sudoers Dosyası Root Sahipliğinde Değil ({p.file_path})",
                        description=f"'{p.file_path}' dosyasının sahibi {p.owner}:{p.group} olarak ayarlanmış. Dosya mutlaka root:root olmalıdır.",
                        remediation=f"chown root:root {p.file_path}",
                        penalty=30.0,
                    )
                )

            # İzin modu 0440 veya 0400 değilse veya others tarafından yazılabilirse
            if p.is_writable_by_others or p.mode_octal not in ["0440", "0400"]:
                perm_findings.append(
                    SudoVulnerability(
                        target=p.file_path,
                        cwe_id="CWE-732",
                        mitre_id="T1548.003",
                        severity="CRITICAL",
                        title=f"Gevşek Sudoers Dosya İzni ({p.file_path} - Mod: {p.mode_octal})",
                        description=(
                            f"'{p.file_path}' dosyasının izin modu {p.mode_octal} olarak ayarlanmış. "
                            f"Dosya yetkisiz kullanıcılar tarafından değiştirilebilir ve kalıcı root ayrıcalığı elde edilebilir."
                        ),
                        remediation=f"chmod 0440 {p.file_path}",
                        penalty=30.0,
                    )
                )

        return perm_findings

    def run_sudo_audit(self, audit_inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Tüm kuralları, direktifleri ve izinleri birleşik denetimden geçirerek rapor üretir."""
        self.findings.clear()

        # 1. Kuralları Dönüştür ve Denetle
        rules_data = audit_inventory.get("rules", [])
        rules_specs = [
            SudoRuleSpec(
                user_or_group=r.get("user_or_group", ""),
                hosts=r.get("hosts", "ALL"),
                runas_user=r.get("runas_user", "ALL"),
                tags=r.get("tags", []),
                commands=r.get("commands", []),
            )
            for r in rules_data
        ]
        self.findings.extend(self.audit_sudo_rules(rules_specs))

        # 2. Defaults Direktiflerini Denetle
        def_data = audit_inventory.get("defaults", {})
        defaults_spec = SudoDefaultsSpec(
            env_reset=def_data.get("env_reset", True),
            secure_path=def_data.get("secure_path", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            use_pty=def_data.get("use_pty", True),
            mail_badpass=def_data.get("mail_badpass", True),
            logfile=def_data.get("logfile", "/var/log/sudo.log"),
            timestamp_timeout=def_data.get("timestamp_timeout", 15),
            env_keep=def_data.get("env_keep", []),
        )
        self.findings.extend(self.audit_sudo_defaults(defaults_spec))

        # 3. Dosya İzinlerini Denetle
        perm_data = audit_inventory.get("file_permissions", [])
        perm_specs = [
            SudoFilePermSpec(
                file_path=p.get("file_path", "/etc/sudoers"),
                owner=p.get("owner", "root"),
                group=p.get("group", "root"),
                mode_octal=p.get("mode_octal", "0440"),
                is_writable_by_others=p.get("is_writable_by_others", False),
            )
            for p in perm_data
        ]
        self.findings.extend(self.audit_sudoers_permissions(perm_specs))

        # Puanlama Hesaplaması
        total_penalties = sum(f.penalty for f in self.findings)
        final_score = max(0.0, round(self.base_score - total_penalties, 2))

        # Sistem Durumu
        if final_score >= 85.0:
            status = "SECURE"
        elif final_score >= 60.0:
            status = "WARNING"
        else:
            status = "CRITICAL"

        # Şiddet Dağılımı
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        self.audit_report = {
            "audit_metadata": {
                "standard": "CIS Linux Benchmark (Section 5.3) & GTFOBins Privilege Escalation Matrix",
                "auditor": "Seydi Eryılmaz (@seydivakkas)",
                "timestamp": "2026-11-02T13:10:00Z",
            },
            "summary": {
                "score": final_score,
                "max_score": 100.0,
                "status": status,
                "total_vulnerabilities": len(self.findings),
                "severity_breakdown": severity_counts,
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

    def generate_hardened_sudoers_config(self) -> str:
        """Sıkılaştırılmış ve standartlara tam uyumlu bir /etc/sudoers yapılandırma taslağı üretir."""
        config_lines = [
            "# ===========================================================================",
            "# SIKILAŞTIRILMIŞ VE GÜVENLİ /etc/sudoers YAPILANDIRMASI",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) - Tüm Hakları Saklıdır",
            "# ===========================================================================",
            "# Bu dosya mutlaka 'visudo' aracı ile düzenlenmelidir.",
            "",
            "# 1. GÜVENLİ DEFAULTS DİREKTİFLERİ",
            "Defaults env_reset",
            "Defaults mail_badpass",
            'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
            "Defaults use_pty",
            'Defaults logfile="/var/log/sudo.log"',
            "Defaults timestamp_timeout=15",
            "",
            "# 2. KULLANICI VE GRUP ALIAS TANIMLARI",
            "User_Alias ADMINS = %wheel, %sudo",
            "",
            "# 3. GÜVENLİ AYRICALIK TANIMLARI",
            "# Root kullanıcısı tam yetkiye sahiptir",
            "root ALL=(ALL:ALL) ALL",
            "",
            "# Yöneticiler parola girerek komut çalıştırabilir (NOPASSWD KESİNLİKLE YASAKTIR)",
            "%wheel ALL=(ALL:ALL) ALL",
            "",
            "# 4. EK YAPILANDIRMA DİZİNİ",
            "#include /etc/sudoers.d",
        ]
        return "\n".join(config_lines)

    def generate_bash_remediation_script(self) -> str:
        """Tespit edilen zafiyetlerin düzeltilmesi için çalıştırılabilir Bash iyileştirme betiği üretir."""
        bash_lines = [
            "#!/bin/bash",
            "# ===========================================================================",
            "# Linux Sudo Güvenlik Sıkılaştırma ve Otomatik İyileştirme Betiği",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) - Tüm Hakları Saklıdır",
            "# ===========================================================================",
            "set -euo pipefail",
            "",
            "echo '[*] Linux Sudoers Güvenlik İyileştirmesi Başlatılıyor...'",
            "",
            "# 1. Sudoers Dosya İzinlerinin Kilitlenmesi",
            "if [ -f /etc/sudoers ]; then",
            "    chown root:root /etc/sudoers",
            "    chmod 0440 /etc/sudoers",
            "    echo '[+] /etc/sudoers izinleri 0440 (root:root) olarak mühürlendi.'",
            "fi",
            "",
            "if [ -d /etc/sudoers.d ]; then",
            "    chown -R root:root /etc/sudoers.d",
            "    chmod 0750 /etc/sudoers.d",
            "    find /etc/sudoers.d -type f -exec chmod 0440 {} +",
            "    echo '[+] /etc/sudoers.d dizin izinleri sıkılaştırıldı.'",
            "fi",
            "",
        ]

        # Tespit edilen spesifik bulgulara göre düzeltici yönergeler eklenir
        for idx, f in enumerate(self.findings, 1):
            bash_lines.append(f"# Adım {idx}: {f.title} ({f.cwe_id})")
            bash_lines.append(f"echo '[>] Düzeltme Notu: {f.remediation}'")

        bash_lines.append("")
        bash_lines.append("# Sudoers Sözdizimi Doğrulaması (Syntax Check)")
        bash_lines.append("if command -v visudo >/dev/null 2>&1; then")
        bash_lines.append("    visudo -c")
        bash_lines.append("    echo '[+] visudo sözdizimi doğrulaması BAŞARILI!'")
        bash_lines.append("fi")
        bash_lines.append("")
        bash_lines.append("echo '[+] Sudo güvenlik sıkılaştırması tamamlandı!'")

        return "\n".join(bash_lines)
