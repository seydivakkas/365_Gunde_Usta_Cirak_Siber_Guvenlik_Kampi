# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Denetim (auditd) ve Journal (journald) Güvenlik Motoru (LinuxAuditJournalSecurityEngine)
Bu modül, Linux işletim sisteminde çekirdek denetim altyapısını (auditd), dosya izleme
(watch) kurallarını, sistem çağrısı (syscall) filtrelerini, kuralların değiştirilemezlik (-e 2)
kilidini ve systemd-journald kalıcı loglama/mühürleme (Seal/FSS) ayarlarını CIS Linux Benchmark
Section 4.1 ve 4.2 standartlarına göre denetler.
"""

# Tip ipuçları için standart kütüphane sınıfları dahil edilir
from typing import Dict, List, Any, Optional
# Nesne yönelimli veri modelleri için dataclass modülü dahil edilir
from dataclasses import dataclass, field
# Düzenli ifade işlemleri için re modülü dahil edilir
import re
# Dosya ve sistem yolu işlemleri için os modülü dahil edilir
import os
# JSON formatlama ve ayrıştırma için json modülü dahil edilir
import json


@dataclass
class AuditWatchRule:
    """
    Belirli bir dosya veya dizin üzerindeki erişim ve değişiklikleri izleyen kuralı temsil eder (-w).
    """
    # İzlenen dosya veya dizin yolu (Örn: /etc/shadow, /etc/passwd, /etc/sudoers)
    path: str
    # İzlenen izin türleri (w: write, a: attribute change, r: read, x: execute)
    permissions: str = "wa"
    # Kuralı etiketleyen anahtar kelime (Örn: identity, actions, pam)
    key: str = ""


@dataclass
class AuditSyscallRule:
    """
    Belirli sistem çağrılarını (syscalls) çekirdek seviyesinde filtreleyen kuralı temsil eder (-a).
    """
    # Kural tetiklenme anı (always,exit)
    action: str = "always,exit"
    # İzlenen sistem çağrıları listesi (Örn: ["init_module", "delete_module"])
    syscalls: List[str] = field(default_factory=list)
    # Donanım mimarisi (b64 veya b32)
    arch: str = "b64"
    # Kural anahtarı
    key: str = ""


@dataclass
class AuditdConfig:
    """
    auditd servisinin çalışma yapılandırmasını ve kurallarını temsil eder.
    """
    # auditd servisinin aktif ve çalışır olup olmadığı
    is_active: bool = True
    # Sistem açılışında otomatik başlatılıp başlatılmadığı
    is_enabled_on_boot: bool = True
    # Maksimum log dosyası boyutu (MB cinsinden)
    max_log_file: int = 50
    # Dosya dolduğunda uygulanacak aksiyon (keep_logs, rotate, ignore)
    max_log_file_action: str = "keep_logs"
    # Disk alanı azaldığında uygulanacak aksiyon (email, suspend, halt)
    space_left_action: str = "email"
    # Yönetici disk eşiği aşıldığında uygulanacak aksiyon (halt, single)
    admin_space_left_action: str = "halt"
    # Disk tamamen dolduğunda uygulanacak aksiyon (halt, single, ignore)
    disk_full_action: str = "halt"
    # Audit log dosyasının disk üzerindeki mutlak yolu
    log_file: str = "/var/log/audit/audit.log"
    # Log dosyasının sekizli dosya modu (Örn: 0600 veya 0640)
    log_file_mode: str = "0600"
    # Kuralların yeniden başlatma olmaksızın kilitlenmesi bayrağı (-e 2)
    immutable_flag: bool = True
    # Tanımlı dosya izleme kuralları
    watch_rules: List[AuditWatchRule] = field(default_factory=list)
    # Tanımlı sistem çağrısı kuralları
    syscall_rules: List[AuditSyscallRule] = field(default_factory=list)


@dataclass
class JournaldConfig:
    """
    systemd-journald günlükleme servisinin yapılandırmasını temsil eder.
    """
    # Günlüklerin depolama türü (persistent, volatile, auto, none)
    storage: str = "persistent"
    # Logların sıkıştırılıp sıkıştırılmayacağı
    compress: bool = True
    # Forward Secure Sealing (FSS) ile kriptografik mühürleme
    seal: bool = True
    # Logların Syslog / SIEM sistemine iletilmesi bayrağı
    forward_to_syslog: bool = True
    # Journald servisinin aktif olup olmadığı
    is_active: bool = True


@dataclass
class SecurityFinding:
    """
    Denetim sırasında tespit edilen her bir audit veya journal zafiyetini temsil eder.
    """
    rule_id: str
    target: str
    cwe: str
    mitre_attack: str
    severity: str
    title: str
    description: str
    remediation_advice: str
    deduction_points: float


class LinuxAuditJournalSecurityEngine:
    """
    Linux auditd ve systemd-journald yapılandırmalarını inceleyen, CIS Benchmark
    kriterlerine göre puanlayan ve otomatik sertleştirme betikleri üreten motor.
    """

    # İzlenmesi zorunlu olan kritik kimlik ve sistem dosyaları (CIS 4.1.4 - 4.1.15)
    MANDATORY_WATCH_PATHS = {
        "/etc/shadow": "Kullanıcı parola özetleri ve hesap kısıtlamaları (CIS 4.1.4)",
        "/etc/passwd": "Kullanıcı hesapları ve UID tanımları (CIS 4.1.4)",
        "/etc/gshadow": "Grup parola özetleri (CIS 4.1.4)",
        "/etc/group": "Grup üyelikleri ve GID tanımları (CIS 4.1.4)",
        "/etc/sudoers": "Sudo ayrıcalık devri kuralları (CIS 4.1.14)",
        "/etc/pam.d": "PAM kimlik doğrulama modülleri (CIS 4.1.13)"
    }

    def __init__(self) -> None:
        """
        Güvenlik motorunu başlatır ve tespit listesini hazırlar.
        """
        self.findings: List[SecurityFinding] = []

    def audit_environment(self, auditd: AuditdConfig, journald: JournaldConfig) -> Dict[str, Any]:
        """
        auditd ve journald yapılandırmalarını kurallara göre denetler.
        """
        self.findings.clear()

        # 1. Kural: auditd Servisinin Aktifliği (CIS 4.1.1 / CWE-778 / T1562.002)
        if not auditd.is_active or not auditd.is_enabled_on_boot:
            self.findings.append(SecurityFinding(
                rule_id="AUD-001",
                target="auditd servisi",
                cwe="CWE-778",
                mitre_attack="T1562.002",
                severity="CRITICAL",
                title="auditd Denetim Servisi Devre Dışı veya Durdurulmuş",
                description="Linux çekirdek denetim servisi aktif değil veya açılışta başlamıyor. Güvenlik olayları ve dosya erişimleri izlenemez.",
                remediation_advice="auditd servisini başlatın ve etkinleştirin: systemctl enable --now auditd",
                deduction_points=25.0
            ))

        # 2. Kural: Kritik Kimlik Dosyalarının İzlenmesi (CIS 4.1.4 / CWE-778 / T1003)
        configured_paths = [w.path for w in auditd.watch_rules]
        missing_identity_paths = [p for p in ["/etc/shadow", "/etc/passwd"] if p not in configured_paths]
        if missing_identity_paths:
            self.findings.append(SecurityFinding(
                rule_id="AUD-002",
                target=", ".join(missing_identity_paths),
                cwe="CWE-778",
                mitre_attack="T1003",
                severity="CRITICAL",
                title="Kritik Kimlik Dosyalarında Audit İzleme Kuralı Eksik",
                description=f"Şu kritik dosyalar audit kuralları ile izlenmemektedir: {', '.join(missing_identity_paths)}. Parola tahrifatı tespit edilemez.",
                remediation_advice="audit.rules dosyasına '-w /etc/shadow -p wa -k identity' ve '-w /etc/passwd -p wa -k identity' satırlarını ekleyin.",
                deduction_points=20.0
            ))

        # 3. Kural: Sudoers Dosyalarının İzlenmesi (CIS 4.1.14 / CWE-778 / T1548.003)
        if "/etc/sudoers" not in configured_paths:
            self.findings.append(SecurityFinding(
                rule_id="AUD-003",
                target="/etc/sudoers",
                cwe="CWE-778",
                mitre_attack="T1548.003",
                severity="HIGH",
                title="Sudoers Dosyalarında Audit İzleme Kuralı Eksik",
                description="/etc/sudoers dosyasındaki değişiklikler audit edilmemektedir. Yetki yükseltme kuralları tahrif edilebilir.",
                remediation_advice="audit.rules içine '-w /etc/sudoers -p wa -k actions' satırını ekleyin.",
                deduction_points=15.0
            ))

        # 4. Kural: Çekirdek Modülü Yükleme/Çıkarma Syscall İzleme (CIS 4.1.16 / CWE-778 / T1547.006)
        all_monitored_syscalls: List[str] = []
        for sys_rule in auditd.syscall_rules:
            all_monitored_syscalls.extend(sys_rule.syscalls)

        module_syscalls = ["init_module", "delete_module"]
        missing_module_syscalls = [sc for sc in module_syscalls if sc not in all_monitored_syscalls]
        if missing_module_syscalls:
            self.findings.append(SecurityFinding(
                rule_id="AUD-004",
                target="init_module / delete_module syscalls",
                cwe="CWE-778",
                mitre_attack="T1547.006",
                severity="HIGH",
                title="Çekirdek Modülü (LKM) Yükleme/Çıkarma Syscall Audit Kuralı Eksik",
                description="Çekirdeğe modül yükleme (init_module) veya silme (delete_module) sistem çağrıları denetlenmemektedir (Rootkit riski).",
                remediation_advice="audit.rules içine '-a always,exit -F arch=b64 -S init_module,delete_module -k modules' ekleyin.",
                deduction_points=15.0
            ))

        # 5. Kural: Journald Kalıcı Depolama (Storage=persistent) (CIS 4.2.1.2 / CWE-778)
        if journald.storage.lower() != "persistent":
            self.findings.append(SecurityFinding(
                rule_id="AUD-005",
                target="journald:Storage",
                cwe="CWE-778",
                mitre_attack="T1562.002",
                severity="HIGH",
                title="Journald Günlükleri Kalıcı Olarak Saklanmıyor (Storage!=persistent)",
                description=f"journald storage değeri '{journald.storage}'. Sistem yeniden başladığında loglar silinecektir.",
                remediation_advice="/etc/systemd/journald.conf içinde 'Storage=persistent' direktifini yapılandırın.",
                deduction_points=15.0
            ))

        # 6. Kural: Audit Kurallarında Değiştirilemezlik (-e 2) Kilidi (CIS 4.1.18 / CWE-345)
        if not auditd.immutable_flag:
            self.findings.append(SecurityFinding(
                rule_id="AUD-006",
                target="audit.rules:immutable_flag",
                cwe="CWE-345",
                mitre_attack="T1562.002",
                severity="MEDIUM",
                title="Audit Kurallarında Değiştirilemezlik Kilidi (-e 2) Eksik",
                description="Audit kurallarının sonunda '-e 2' tanımlanmamış. Saldırgan root yetkisi aldığında kuralları silebilir.",
                remediation_advice="audit.rules dosyasının en sonuna '-e 2' satırını ekleyerek kuralları kilitleyin.",
                deduction_points=10.0
            ))

        # 7. Kural: Disk Dolum Aksiyonları (CIS 4.1.2 / CWE-778)
        if auditd.disk_full_action.lower() in ["ignore", "none", ""]:
            self.findings.append(SecurityFinding(
                rule_id="AUD-007",
                target="auditd.conf:disk_full_action",
                cwe="CWE-778",
                mitre_attack="T1562.002",
                severity="MEDIUM",
                title="Audit Disk Dolum Aksiyonu Yetersiz veya Tanımsız",
                description="Audit diski dolduğunda alınacak aksiyon 'ignore' olarak atanmış. Log diski dolduğunda loglama duracaktır.",
                remediation_advice="auditd.conf içinde 'disk_full_action = halt' veya 'single' olarak ayarlayın.",
                deduction_points=10.0
            ))

        # 8. Kural: Audit Log Dosya İzinleri (CIS 4.1.3 / CWE-732)
        if auditd.log_file and self._is_mode_too_permissive(auditd.log_file_mode, threshold=0o640):
            self.findings.append(SecurityFinding(
                rule_id="AUD-008",
                target=auditd.log_file,
                cwe="CWE-732",
                mitre_attack="T1565.001",
                severity="LOW",
                title="Gevşek Audit Log Dosyası İzinleri",
                description=f"'{auditd.log_file}' izinleri '{auditd.log_file_mode}'. Yetkisiz kullanıcılar denetim loglarını okuyabilir.",
                remediation_advice=f"Log dosyası izinlerini sınırlandırın: chmod 0600 {auditd.log_file} && chown root:root {auditd.log_file}",
                deduction_points=5.0
            ))

        # Puanlama hesabı
        total_deductions = sum(f.deduction_points for f in self.findings)
        final_score = max(0.0, min(100.0, 100.0 - total_deductions))

        if final_score >= 80.0:
            status_text = "GÜVENLİ (STANDARTLARA UYGUN)"
        elif final_score >= 60.0:
            status_text = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            status_text = "KRİTİK RİSK (ACİL MÜDAHALE GEREKLİ)"

        return {
            "guvenlik_skoru": round(final_score, 1),
            "durum": status_text,
            "auditd_aktiflik": auditd.is_active,
            "journald_depolama": journald.storage,
            "toplam_watch_kural": len(auditd.watch_rules),
            "toplam_syscall_kural": len(auditd.syscall_rules),
            "toplam_bulgu": len(self.findings),
            "kritik_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "yuksek_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "HIGH"),
            "orta_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "dusuk_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "LOW"),
            "bulgular": [
                {
                    "rule_id": f.rule_id,
                    "target": f.target,
                    "cwe": f.cwe,
                    "mitre_attack": f.mitre_attack,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation_advice": f.remediation_advice,
                    "deduction_points": f.deduction_points
                }
                for f in self.findings
            ]
        }

    def _is_mode_too_permissive(self, mode_str: str, threshold: int = 0o640) -> bool:
        """
        Sekizli izin modunun eşik değerden gevşek olup olmadığını sınar.
        """
        try:
            mode_int = int(mode_str, 8)
            if mode_int & 0o007:
                return True
            if mode_int & 0o020:
                return True
            return mode_int > threshold
        except (ValueError, TypeError):
            return True

    def parse_inventory_json(self, json_data: Dict[str, Any]) -> tuple[AuditdConfig, JournaldConfig]:
        """
        JSON tabanlı envanteri ayrıştırarak AuditdConfig ve JournaldConfig nesneleri döner.
        """
        a_data = json_data.get("auditd", {})
        j_data = json_data.get("journald", {})

        watch_rules: List[AuditWatchRule] = []
        for w in a_data.get("watch_rules", []):
            watch_rules.append(AuditWatchRule(
                path=w.get("path", ""),
                permissions=w.get("permissions", "wa"),
                key=w.get("key", "")
            ))

        syscall_rules: List[AuditSyscallRule] = []
        for s in a_data.get("syscall_rules", []):
            syscall_rules.append(AuditSyscallRule(
                action=s.get("action", "always,exit"),
                syscalls=s.get("syscalls", []),
                arch=s.get("arch", "b64"),
                key=s.get("key", "")
            ))

        auditd = AuditdConfig(
            is_active=a_data.get("is_active", True),
            is_enabled_on_boot=a_data.get("is_enabled_on_boot", True),
            max_log_file=a_data.get("max_log_file", 50),
            max_log_file_action=a_data.get("max_log_file_action", "keep_logs"),
            space_left_action=a_data.get("space_left_action", "email"),
            admin_space_left_action=a_data.get("admin_space_left_action", "halt"),
            disk_full_action=a_data.get("disk_full_action", "halt"),
            log_file=a_data.get("log_file", "/var/log/audit/audit.log"),
            log_file_mode=a_data.get("log_file_mode", "0600"),
            immutable_flag=a_data.get("immutable_flag", True),
            watch_rules=watch_rules,
            syscall_rules=syscall_rules
        )

        journald = JournaldConfig(
            storage=j_data.get("storage", "persistent"),
            compress=j_data.get("compress", True),
            seal=j_data.get("seal", True),
            forward_to_syslog=j_data.get("forward_to_syslog", True),
            is_active=j_data.get("is_active", True)
        )

        return auditd, journald

    def generate_audit_rules_conf(self) -> str:
        """
        CIS Linux Benchmark Section 4.1 uyumlu kurumsal audit.rules yapılandırması üretir.
        """
        lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# CIS Linux Benchmark v2.0.0 Uyumlu Kurumsal audit.rules Şablonu",
            "# ==============================================================================",
            "# Önceki kuralları temizle",
            "-D",
            "# Tampon bellek sınırını artır (Yoğun olay trafiği için)",
            "-b 8192",
            "# Hata durumunda sistem aksiyonu (1 = printk uyarı, 2 = panic)",
            "-f 1",
            "",
            "# --- 1. Kritik Kimlik ve Kullanıcı Dosyaları (CIS 4.1.4) ---",
            "-w /etc/group -p wa -k identity",
            "-w /etc/passwd -p wa -k identity",
            "-w /etc/gshadow -p wa -k identity",
            "-w /etc/shadow -p wa -k identity",
            "-w /etc/security/opasswd -p wa -k identity",
            "",
            "# --- 2. Ayrıcalık Devri ve Sudo Yapılandırması (CIS 4.1.14) ---",
            "-w /etc/sudoers -p wa -k actions",
            "-w /etc/sudoers.d/ -p wa -k actions",
            "",
            "# --- 3. PAM Kimlik Doğrulama Modülleri (CIS 4.1.13) ---",
            "-w /etc/pam.d/ -p wa -k pam",
            "-w /etc/security/ -p wa -k pam",
            "",
            "# --- 4. Zaman Manipülasyonu Syscall Denetimi (CIS 4.1.3) ---",
            "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change",
            "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change",
            "",
            "# --- 5. Çekirdek Modülü Yükleme/Çıkarma Syscall Denetimi (CIS 4.1.16) ---",
            "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules",
            "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules",
            "",
            "# --- 6. Yetkisiz Başarısız Dosya Erişimleri (EACCES/EPERM) (CIS 4.1.10) ---",
            "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access",
            "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access",
            "",
            "# --- 7. Kuralları Yeniden Başlatma Olmaksızın Değiştirilemez Kıl (CIS 4.1.18) ---",
            "# DİKKAT: -e 2 eklendiğinde kurallar sunucu reboot edilmeden silinemez!",
            "-e 2"
        ]
        return "\n".join(lines)

    def generate_journald_conf(self) -> str:
        """
        CIS Linux Benchmark Section 4.2 uyumlu journald.conf yapılandırması üretir.
        """
        lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# CIS Linux Benchmark v2.0.0 Uyumlu Kurumsal journald.conf Şablonu",
            "# ==============================================================================",
            "[Journal]",
            "# Logların diske kalıcı olarak yazılması zorunludur (CIS 4.2.1.2)",
            "Storage=persistent",
            "# Log dosyalarının sıkıştırılması",
            "Compress=yes",
            "# Forward Secure Sealing (FSS) ile kriptografik mühürleme (CIS 4.2.1.3)",
            "Seal=yes",
            "# Logların Syslog / SIEM sistemine iletilmesi",
            "ForwardToSyslog=yes",
            "# Maksimum disk kullanım sınırı",
            "SystemMaxUse=2G",
            "SystemKeepFree=1G",
            "# Hız sınırlaması (Log flood saldırılarına karşı)",
            "RateLimitIntervalSec=30s",
            "RateLimitBurst=10000"
        ]
        return "\n".join(lines)

    def generate_remediation_script(self, auditd: AuditdConfig, journald: JournaldConfig) -> str:
        """
        Denetlenen sunucu için tespit edilen açıkları kapatacak çalıştırılabilir Bash betiği üretir.
        """
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Linux Audit ve Journal Güvenliği Otomatik İyileştirme Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "echo '[+] Audit ve Journald güvenlik sertleştirmesi başlatılıyor...'",
            "",
            "# --- 1. Adım: audit.rules Yapılandırmasını Uygula ---",
            "cat << 'EOF' > /etc/audit/rules.d/audit.rules",
            self.generate_audit_rules_conf(),
            "EOF",
            "chmod 0640 /etc/audit/rules.d/audit.rules",
            "chown root:root /etc/audit/rules.d/audit.rules",
            "",
            "# --- 2. Adım: auditd.conf Ayarlarını Sıkılaştır ---",
            "AUDITD_CONF='/etc/audit/auditd.conf'",
            "if [ -f \"$AUDITD_CONF\" ]; then",
            "    sed -i 's/^space_left_action =.*/space_left_action = email/' \"$AUDITD_CONF\"",
            "    sed -i 's/^admin_space_left_action =.*/admin_space_left_action = halt/' \"$AUDITD_CONF\"",
            "    sed -i 's/^disk_full_action =.*/disk_full_action = halt/' \"$AUDITD_CONF\"",
            "    sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' \"$AUDITD_CONF\"",
            "fi",
            "",
            "# --- 3. Adım: journald.conf Yapılandırmasını Uygula ---",
            "cat << 'EOF' > /etc/systemd/journald.conf",
            self.generate_journald_conf(),
            "EOF",
            "chmod 0644 /etc/systemd/journald.conf",
            "chown root:root /etc/systemd/journald.conf",
            "",
            "# --- 4. Adım: Servisleri Etkinleştir ve Yeniden Yükle ---",
            "systemctl enable auditd",
            "systemctl restart auditd || service auditd restart",
            "systemctl restart systemd-journald",
            "augenrules --load || true",
            "echo '[✓] Audit ve Journald servisleri başarıyla sertleştirildi ve devreye alındı.'"
        ]
        return "\n".join(lines)
