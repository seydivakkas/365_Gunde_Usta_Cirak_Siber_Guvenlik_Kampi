# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Audit ve Journal Güvenliği Birim Testleri
Bu test takımı, LinuxAuditJournalSecurityEngine sınıfının auditd kurallarını,
kimlik izleme (watch) tetikleyicilerini, sistem çağrısı filtrelerini, değiştirilemezlik kilidini
ve systemd-journald kalıcı depolama politikalarını 15 birim test ile doğrular.
"""

# Birim test kütüphanesi dahil edilir
import unittest
# Dosya yolu ve sistem kütüphaneleri dahil edilir
import os
import sys

# Test edilecek motor ve sınıflar arama yoluna eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))
from linux_audit_engine import (
    LinuxAuditJournalSecurityEngine,
    AuditdConfig,
    JournaldConfig,
    AuditWatchRule,
    AuditSyscallRule
)


class TestLinuxAuditSecurity(unittest.TestCase):
    """
    Audit ve Journal güvenlik motorunu test eden sınıf.
    """

    def setUp(self) -> None:
        """
        Her test öncesi temiz bir motor örneği oluşturur.
        """
        self.engine = LinuxAuditJournalSecurityEngine()

    def test_01_fully_hardened_audit_journal_score_100(self) -> None:
        """
        Test 1: Tam sıkılaştırılmış auditd ve journald ortamı 100/100 tam puan almalıdır.
        """
        auditd = AuditdConfig(
            is_active=True,
            is_enabled_on_boot=True,
            disk_full_action="halt",
            log_file_mode="0600",
            immutable_flag=True,
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        journald = JournaldConfig(
            storage="persistent",
            compress=True,
            seal=True,
            forward_to_syslog=True,
            is_active=True
        )

        report = self.engine.audit_environment(auditd, journald)
        self.assertEqual(report["guvenlik_skoru"], 100.0)
        self.assertEqual(report["toplam_bulgu"], 0)
        self.assertIn("GÜVENLİ", report["durum"])

    def test_02_inactive_auditd_detection(self) -> None:
        """
        Test 2: auditd kapalıysa AUD-001 (CRITICAL / CWE-778) üretilmelidir.
        """
        auditd = AuditdConfig(is_active=False)
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-001", rule_ids)
        self.assertGreaterEqual(report["kritik_bulgu_sayisi"], 1)

    def test_03_disabled_on_boot_auditd(self) -> None:
        """
        Test 3: auditd açılışta başlamıyorsa AUD-001 üretilmelidir.
        """
        auditd = AuditdConfig(is_active=True, is_enabled_on_boot=False)
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-001", rule_ids)

    def test_04_missing_shadow_watch(self) -> None:
        """
        Test 4: /etc/shadow izlenmiyorsa AUD-002 (CRITICAL) tespit edilmelidir.
        """
        auditd = AuditdConfig(
            watch_rules=[
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-002", rule_ids)

    def test_05_missing_passwd_watch(self) -> None:
        """
        Test 5: /etc/passwd izlenmiyorsa AUD-002 tespit edilmelidir.
        """
        auditd = AuditdConfig(
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-002", rule_ids)

    def test_06_missing_sudoers_watch(self) -> None:
        """
        Test 6: /etc/sudoers izlenmiyorsa AUD-003 (HIGH) üretilmelidir.
        """
        auditd = AuditdConfig(
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-003", rule_ids)

    def test_07_missing_kernel_module_syscalls(self) -> None:
        """
        Test 7: init_module / delete_module sistem çağrıları izlenmiyorsa AUD-004 üretilmelidir.
        """
        auditd = AuditdConfig(
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[]  # Syscall kuralı yok
        )
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-004", rule_ids)

    def test_08_journald_storage_volatile_or_auto(self) -> None:
        """
        Test 8: journald storage='volatile' ise AUD-005 (HIGH) tespit edilmelidir.
        """
        auditd = AuditdConfig(
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        journald = JournaldConfig(storage="volatile")
        report = self.engine.audit_environment(auditd, journald)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-005", rule_ids)

    def test_09_journald_storage_none(self) -> None:
        """
        Test 9: journald storage='none' ise AUD-005 üretilmelidir.
        """
        auditd = AuditdConfig(
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        journald = JournaldConfig(storage="none")
        report = self.engine.audit_environment(auditd, journald)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-005", rule_ids)

    def test_10_missing_immutable_flag(self) -> None:
        """
        Test 10: -e 2 değiştirilemezlik kilidi kapalıysa AUD-006 (MEDIUM) tespit edilmelidir.
        """
        auditd = AuditdConfig(
            immutable_flag=False,
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-006", rule_ids)

    def test_11_disk_full_action_ignore(self) -> None:
        """
        Test 11: disk_full_action='ignore' ise AUD-007 (MEDIUM) üretilmelidir.
        """
        auditd = AuditdConfig(
            disk_full_action="ignore",
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-007", rule_ids)

    def test_12_loose_audit_log_permissions(self) -> None:
        """
        Test 12: log_file_mode='0666' ise AUD-008 (LOW) tespit edilmelidir.
        """
        auditd = AuditdConfig(
            log_file_mode="0666",
            watch_rules=[
                AuditWatchRule(path="/etc/shadow", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/passwd", permissions="wa", key="identity"),
                AuditWatchRule(path="/etc/sudoers", permissions="wa", key="actions")
            ],
            syscall_rules=[
                AuditSyscallRule(action="always,exit", syscalls=["init_module", "delete_module"], key="modules")
            ]
        )
        report = self.engine.audit_environment(auditd, JournaldConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("AUD-008", rule_ids)

    def test_13_audit_rules_template_generation(self) -> None:
        """
        Test 13: generate_audit_rules_conf fonksiyonu CIS standartlarında kurallar üretmelidir.
        """
        tmpl = self.engine.generate_audit_rules_conf()
        self.assertIn("-w /etc/shadow -p wa -k identity", tmpl)
        self.assertIn("-w /etc/passwd -p wa -k identity", tmpl)
        self.assertIn("-w /etc/sudoers -p wa -k actions", tmpl)
        self.assertIn("init_module,finit_module,delete_module", tmpl)
        self.assertIn("-e 2", tmpl)

    def test_14_journald_conf_template_generation(self) -> None:
        """
        Test 14: generate_journald_conf fonksiyonu CIS uyumlu kalıcı ve mühürlü loglama şablonu üretmelidir.
        """
        tmpl = self.engine.generate_journald_conf()
        self.assertIn("Storage=persistent", tmpl)
        self.assertIn("Compress=yes", tmpl)
        self.assertIn("Seal=yes", tmpl)
        self.assertIn("ForwardToSyslog=yes", tmpl)

    def test_15_remediation_script_generation(self) -> None:
        """
        Test 15: generate_remediation_script fonksiyonu geçerli Bash sertleştirme direktifleri üretmelidir.
        """
        auditd = AuditdConfig()
        journald = JournaldConfig()
        script = self.engine.generate_remediation_script(auditd, journald)
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("systemctl enable auditd", script)
        self.assertIn("augenrules --load", script)
        self.assertIn("Storage=persistent", script)


if __name__ == "__main__":
    unittest.main()
