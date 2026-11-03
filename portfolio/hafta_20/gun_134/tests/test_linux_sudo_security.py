# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Sudo ve Ayrıcalık Devri Güvenliği Birim Testleri (15 Adet Kapsamlı Test).

Bu test paketi; /etc/sudoers kurallarını, GTFOBins istismarlarını, NOPASSWD risklerini,
çevre değişkeni manipülasyonlarını (LD_PRELOAD), Defaults direktiflerini ve dosya
izinlerini bağımsız ve deterministik olarak doğrular.
"""

# Birim test çerçevesi için standart unittest modülü
import unittest
# Dosya ve dizin yolu manipülasyonları için os modülü
import os
# Sistem arama yollarını yönetmek için sys modülü
import sys

# Üst dizin arama yoluna eklenir
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from uygulama.linux_sudo_engine import (
        LinuxSudoSecurityEngine,
        SudoRuleSpec,
        SudoDefaultsSpec,
        SudoFilePermSpec,
    )
except ImportError:
    sys.path.insert(0, os.path.join(parent_dir, "uygulama"))
    from linux_sudo_engine import (
        LinuxSudoSecurityEngine,
        SudoRuleSpec,
        SudoDefaultsSpec,
        SudoFilePermSpec,
    )


class TestLinuxSudoSecurity(unittest.TestCase):
    """Linux Sudo güvenlik motoru 15 birim testi sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz bir motor örneği oluşturur."""
        self.engine = LinuxSudoSecurityEngine()

    def get_clean_baseline_inventory(self) -> dict:
        """Güvenli ve tam puan (100.0) alması beklenen temel yapılandırmayı üretir."""
        return {
            "rules": [
                {
                    "user_or_group": "root",
                    "hosts": "ALL",
                    "runas_user": "(ALL:ALL)",
                    "tags": ["PASSWD"],
                    "commands": ["ALL"],
                },
                {
                    "user_or_group": "%wheel",
                    "hosts": "ALL",
                    "runas_user": "(ALL:ALL)",
                    "tags": ["PASSWD"],
                    "commands": ["ALL"],
                },
            ],
            "defaults": {
                "env_reset": True,
                "secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "use_pty": True,
                "mail_badpass": True,
                "logfile": "/var/log/sudo.log",
                "timestamp_timeout": 15,
                "env_keep": ["COLORS", "DISPLAY"],
            },
            "file_permissions": [
                {
                    "file_path": "/etc/sudoers",
                    "owner": "root",
                    "group": "root",
                    "mode_octal": "0440",
                    "is_writable_by_others": False,
                }
            ],
        }

    def test_01_secure_baseline_scores_100(self) -> None:
        """Test 01: Güvenli temel yapılandırma 100.0 tam puan almalı ve SECURE dönmelidir."""
        inv = self.get_clean_baseline_inventory()
        report = self.engine.run_sudo_audit(inv)
        self.assertEqual(report["summary"]["score"], 100.0)
        self.assertEqual(report["summary"]["status"], "SECURE")
        self.assertEqual(report["summary"]["total_vulnerabilities"], 0)

    def test_02_detect_nopasswd_all_critical(self) -> None:
        """Test 02: NOPASSWD: ALL kuralı CRITICAL zafiyet ve CWE-250 üretmelidir."""
        rule = SudoRuleSpec(user_or_group="intern", hosts="ALL", runas_user="(ALL)", tags=["NOPASSWD"], commands=["ALL"])
        vulns = self.engine.audit_sudo_rules([rule])
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, "CRITICAL")
        self.assertEqual(vulns[0].cwe_id, "CWE-250")
        self.assertEqual(vulns[0].mitre_id, "T1548.003")

    def test_03_detect_gtfobins_vim_nopasswd(self) -> None:
        """Test 03: NOPASSWD: /usr/bin/vim izni GTFOBins kabuk kaçışı zafiyeti üretmelidir."""
        rule = SudoRuleSpec(user_or_group="devops", hosts="ALL", runas_user="(ALL)", tags=["NOPASSWD"], commands=["/usr/bin/vim /etc/hosts"])
        vulns = self.engine.audit_sudo_rules([rule])
        self.assertEqual(len(vulns), 1)
        self.assertIn("vim", vulns[0].title)
        self.assertEqual(vulns[0].severity, "CRITICAL")

    def test_04_detect_gtfobins_find_nopasswd(self) -> None:
        """Test 04: NOPASSWD: /usr/bin/find izni CRITICAL GTFOBins zafiyeti üretmelidir."""
        rule = SudoRuleSpec(user_or_group="operator", hosts="ALL", runas_user="(ALL)", tags=["NOPASSWD"], commands=["/usr/bin/find"])
        vulns = self.engine.audit_sudo_rules([rule])
        self.assertEqual(len(vulns), 1)
        self.assertIn("find", vulns[0].title)
        self.assertEqual(vulns[0].severity, "CRITICAL")

    def test_05_detect_gtfobins_python3_nopasswd(self) -> None:
        """Test 05: NOPASSWD: python3 izni pty.spawn kabuk kaçışı uyarısı vermelidir."""
        rule = SudoRuleSpec(user_or_group="developer", hosts="ALL", runas_user="(ALL)", tags=["NOPASSWD"], commands=["/usr/bin/python3"])
        vulns = self.engine.audit_sudo_rules([rule])
        self.assertEqual(len(vulns), 1)
        self.assertIn("python3", vulns[0].title)

    def test_06_detect_gtfobins_awk_passwd(self) -> None:
        """Test 06: Parolalı dahi olsa AWK GTFOBins zafiyeti olarak HIGH derecede tespit edilmelidir."""
        rule = SudoRuleSpec(user_or_group="analyst", hosts="ALL", runas_user="(ALL)", tags=["PASSWD"], commands=["/usr/bin/awk"])
        vulns = self.engine.audit_sudo_rules([rule])
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, "HIGH")

    def test_07_detect_gtfobins_less_escape(self) -> None:
        """Test 07: /usr/bin/less yetkilendirmesi GTFOBins kabuk kaçışı olarak işaretlenmelidir."""
        rule = SudoRuleSpec(user_or_group="auditor", hosts="ALL", runas_user="(ALL)", tags=["NOPASSWD"], commands=["/usr/bin/less /var/log/messages"])
        vulns = self.engine.audit_sudo_rules([rule])
        self.assertEqual(len(vulns), 1)
        self.assertIn("less", vulns[0].title)

    def test_08_detect_wildcard_argument_injection(self) -> None:
        """Test 08: Komutta denetimsiz joker karakter (*) bulunması CWE-88 üretmelidir."""
        rule = SudoRuleSpec(user_or_group="support", hosts="ALL", runas_user="(ALL)", tags=["PASSWD"], commands=["/bin/cat /var/log/*"])
        vulns = self.engine.audit_sudo_rules([rule])
        wildcard_vulns = [v for v in vulns if v.cwe_id == "CWE-88"]
        self.assertEqual(len(wildcard_vulns), 1)

    def test_09_defaults_missing_env_reset(self) -> None:
        """Test 09: env_reset=False olması HIGH CWE-250 zafiyeti üretmelidir."""
        defaults = SudoDefaultsSpec(env_reset=False)
        vulns = self.engine.audit_sudo_defaults(defaults)
        env_vulns = [v for v in vulns if "env_reset" in v.title]
        self.assertEqual(len(env_vulns), 1)
        self.assertEqual(env_vulns[0].severity, "HIGH")

    def test_10_defaults_dangerous_env_keep_ld_preload(self) -> None:
        """Test 10: env_keep içerisinde LD_PRELOAD olması CRITICAL CWE-426 kütüphane enjeksiyonu üretmelidir."""
        defaults = SudoDefaultsSpec(env_reset=True, env_keep=["LD_PRELOAD", "HOME"])
        vulns = self.engine.audit_sudo_defaults(defaults)
        preload_vulns = [v for v in vulns if "env_keep" in v.target]
        self.assertEqual(len(preload_vulns), 1)
        self.assertEqual(preload_vulns[0].severity, "CRITICAL")
        self.assertEqual(preload_vulns[0].cwe_id, "CWE-426")

    def test_11_defaults_insecure_secure_path(self) -> None:
        """Test 11: secure_path içinde '.' veya '/tmp' olması HIGH CWE-426 üretmelidir."""
        defaults = SudoDefaultsSpec(secure_path="/usr/bin:/tmp:.")
        vulns = self.engine.audit_sudo_defaults(defaults)
        path_vulns = [v for v in vulns if "secure_path" in v.target]
        self.assertEqual(len(path_vulns), 1)
        self.assertEqual(path_vulns[0].severity, "HIGH")

    def test_12_defaults_missing_use_pty(self) -> None:
        """Test 12: use_pty=False olması MEDIUM CWE-284 uyarısı vermelidir."""
        defaults = SudoDefaultsSpec(use_pty=False)
        vulns = self.engine.audit_sudo_defaults(defaults)
        pty_vulns = [v for v in vulns if "use_pty" in v.target]
        self.assertEqual(len(pty_vulns), 1)
        self.assertEqual(pty_vulns[0].severity, "MEDIUM")

    def test_13_file_perm_writable_sudoers_0666(self) -> None:
        """Test 13: /etc/sudoers dosyasının 0666 olması CRITICAL CWE-732 üretmelidir."""
        perm = SudoFilePermSpec(file_path="/etc/sudoers", owner="root", group="root", mode_octal="0666", is_writable_by_others=True)
        vulns = self.engine.audit_sudoers_permissions([perm])
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, "CRITICAL")
        self.assertEqual(vulns[0].cwe_id, "CWE-732")

    def test_14_file_perm_non_root_owner(self) -> None:
        """Test 14: Sudoers dosyasının root harici birine ait olması CRITICAL zafiyet üretmelidir."""
        perm = SudoFilePermSpec(file_path="/etc/sudoers.d/custom", owner="john", group="users", mode_octal="0440", is_writable_by_others=False)
        vulns = self.engine.audit_sudoers_permissions([perm])
        self.assertEqual(len(vulns), 1)
        self.assertIn("Root Sahipliğinde Değil", vulns[0].title)

    def test_15_end_to_end_audit_and_script_generation(self) -> None:
        """Test 15: Çoklu zafiyet içeren envanter uçtan uca denetlenip Bash betiği üretilmelidir."""
        inv = self.get_clean_baseline_inventory()
        inv["rules"].append({"user_or_group": "bad_user", "hosts": "ALL", "runas_user": "(ALL)", "tags": ["NOPASSWD"], "commands": ["ALL"]})
        inv["defaults"]["env_keep"].append("LD_PRELOAD")

        report = self.engine.run_sudo_audit(inv)
        self.assertLess(report["summary"]["score"], 70.0)
        self.assertEqual(report["summary"]["status"], "CRITICAL")
        self.assertGreaterEqual(report["summary"]["total_vulnerabilities"], 2)

        script = self.engine.generate_bash_remediation_script()
        self.assertIn("#!/bin/bash", script)
        self.assertIn("chmod 0440 /etc/sudoers", script)
        self.assertIn("visudo -c", script)


if __name__ == "__main__":
    unittest.main()
