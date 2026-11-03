# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux PAM ve Oturum Politikası Güvenlik Birim Testleri (15 Adet Kapsamlı Test).

Bu test takımı; pam_faillock hesap kilitleme mekanizmasını, pam_pwquality parola karmaşıklığını,
pam_pwhistory parola geçmişini, pam_unix nullok açıklarını, TMOUT boşta kalma süresini ve
PAM dosya izinlerini bağımsız ve deterministik olarak doğrular.
"""

# Birim test çerçevesi için standart unittest modülü
import unittest
# Dosya ve dizin yolu manipülasyonu için standart os kütüphanesi
import os
# Sistem arama yollarını yönetmek için standart sys kütüphanesi
import sys

# Test edilen modüllere erişim için yol ayarı yapılır
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from uygulama.linux_pam_security_engine import (
        LinuxPamSecurityEngine,
        AccountLockoutSpec,
        PasswordQualitySpec,
        SessionPolicySpec,
        PamFilePermSpec,
    )
except ImportError:
    sys.path.insert(0, os.path.join(parent_dir, "uygulama"))
    from linux_pam_security_engine import (
        LinuxPamSecurityEngine,
        AccountLockoutSpec,
        PasswordQualitySpec,
        SessionPolicySpec,
        PamFilePermSpec,
    )


class TestLinuxPamSecurity(unittest.TestCase):
    """Linux PAM güvenlik denetim motoru 15 birim testi sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz bir denetim motoru örneği oluşturur."""
        self.engine = LinuxPamSecurityEngine()

    def get_clean_baseline_inventory(self) -> dict:
        """CIS Linux Benchmark uyumlu tam puan (100.0) alması beklenen envanter üretir."""
        return {
            "account_lockout": {
                "enabled": True,
                "module_name": "pam_faillock",
                "deny": 5,
                "unlock_time": 900,
                "fail_interval": 900,
                "even_deny_root": True,
            },
            "password_quality": {
                "minlen": 14,
                "dcredit": -1,
                "ucredit": -1,
                "lcredit": -1,
                "ocredit": -1,
                "retry": 3,
                "enforce_for_root": True,
            },
            "session_policy": {
                "inactivity_timeout_tmout": 900,
                "pwhistory_remember": 5,
                "nullok_present": False,
                "maxlogins": 10,
            },
            "file_permissions": [
                {
                    "file_path": "/etc/pam.d/system-auth",
                    "owner": "root",
                    "group": "root",
                    "mode_octal": "0644",
                    "is_writable_by_others": False,
                }
            ],
        }

    def test_01_secure_baseline_scores_100(self) -> None:
        """Test 01: CIS uyumlu tam yapılandırma 100.0 puan almalı ve SECURE dönmelidir."""
        inv = self.get_clean_baseline_inventory()
        report = self.engine.run_pam_audit(inv)
        self.assertEqual(report["summary"]["score"], 100.0)
        self.assertEqual(report["summary"]["status"], "SECURE")
        self.assertEqual(report["summary"]["total_vulnerabilities"], 0)

    def test_02_account_lockout_disabled_critical(self) -> None:
        """Test 02: Hesap kilitlemenin kapalı olması CRITICAL zafiyet ve CWE-307 üretmelidir."""
        lockout = AccountLockoutSpec(enabled=False)
        vulns = self.engine.audit_account_lockout(lockout)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, "CRITICAL")
        self.assertEqual(vulns[0].cwe_id, "CWE-307")
        self.assertEqual(vulns[0].mitre_id, "T1110.001")

    def test_03_account_lockout_weak_deny_threshold(self) -> None:
        """Test 03: Başarısız deneme eşiğinin 10 olması HIGH CWE-307 üretmelidir."""
        lockout = AccountLockoutSpec(enabled=True, deny=10)
        vulns = self.engine.audit_account_lockout(lockout)
        deny_vulns = [v for v in vulns if "deny" in v.target]
        self.assertEqual(len(deny_vulns), 1)
        self.assertEqual(deny_vulns[0].severity, "HIGH")

    def test_04_account_lockout_short_unlock_time(self) -> None:
        """Test 04: Kilit kalma süresinin 300s olması yetersiz süre uyarısı vermelidir."""
        lockout = AccountLockoutSpec(enabled=True, unlock_time=300)
        vulns = self.engine.audit_account_lockout(lockout)
        time_vulns = [v for v in vulns if "unlock_time" in v.target]
        self.assertEqual(len(time_vulns), 1)
        self.assertEqual(time_vulns[0].severity, "HIGH")

    def test_05_account_lockout_root_excluded(self) -> None:
        """Test 05: even_deny_root eksikliği MEDIUM derece CWE-307 uyarısı vermelidir."""
        lockout = AccountLockoutSpec(enabled=True, even_deny_root=False)
        vulns = self.engine.audit_account_lockout(lockout)
        root_vulns = [v for v in vulns if "even_deny_root" in v.target]
        self.assertEqual(len(root_vulns), 1)
        self.assertEqual(root_vulns[0].severity, "MEDIUM")

    def test_06_pwquality_short_minlen(self) -> None:
        """Test 06: Minimum parola uzunluğunun 8 olması HIGH CWE-521 üretmelidir."""
        quality = PasswordQualitySpec(minlen=8)
        vulns = self.engine.audit_password_quality(quality)
        minlen_vulns = [v for v in vulns if "minlen" in v.target]
        self.assertEqual(len(minlen_vulns), 1)
        self.assertEqual(minlen_vulns[0].cwe_id, "CWE-521")

    def test_07_pwquality_missing_credits(self) -> None:
        """Test 07: Rakam veya büyük harf zorunluluğunun olmaması karmaşıklık zafiyeti üretmelidir."""
        quality = PasswordQualitySpec(dcredit=0, ucredit=0)
        vulns = self.engine.audit_password_quality(quality)
        credit_vulns = [v for v in vulns if "credits" in v.target]
        self.assertEqual(len(credit_vulns), 1)
        self.assertIn("Rakam", credit_vulns[0].title)

    def test_08_pwquality_root_enforcement_missing(self) -> None:
        """Test 08: enforce_for_root bayrağının kapalı olması uyarı vermelidir."""
        quality = PasswordQualitySpec(enforce_for_root=False)
        vulns = self.engine.audit_password_quality(quality)
        root_vulns = [v for v in vulns if "enforce_for_root" in v.target]
        self.assertEqual(len(root_vulns), 1)
        self.assertEqual(root_vulns[0].severity, "MEDIUM")

    def test_09_session_nullok_present_critical(self) -> None:
        """Test 09: pam_unix içinde nullok bulunması CRITICAL CWE-258 üretmelidir."""
        session = SessionPolicySpec(nullok_present=True)
        vulns = self.engine.audit_session_policy(session)
        nullok_vulns = [v for v in vulns if v.cwe_id == "CWE-258"]
        self.assertEqual(len(nullok_vulns), 1)
        self.assertEqual(nullok_vulns[0].severity, "CRITICAL")
        self.assertEqual(nullok_vulns[0].mitre_id, "T1078")

    def test_10_session_pwhistory_insufficient_remember(self) -> None:
        """Test 10: remember değerinin 2 olması HIGH CWE-262 parola geçmişi zafiyeti üretmelidir."""
        session = SessionPolicySpec(pwhistory_remember=2)
        vulns = self.engine.audit_session_policy(session)
        pwhist_vulns = [v for v in vulns if v.cwe_id == "CWE-262"]
        self.assertEqual(len(pwhist_vulns), 1)
        self.assertEqual(pwhist_vulns[0].severity, "HIGH")

    def test_11_session_tmout_excessive_inactivity(self) -> None:
        """Test 11: TMOUT değerinin 3600s olması HIGH CWE-613 üretmelidir."""
        session = SessionPolicySpec(inactivity_timeout_tmout=3600)
        vulns = self.engine.audit_session_policy(session)
        tmout_vulns = [v for v in vulns if v.cwe_id == "CWE-613"]
        self.assertEqual(len(tmout_vulns), 1)
        self.assertEqual(tmout_vulns[0].severity, "HIGH")

    def test_12_session_tmout_unlimited_zero(self) -> None:
        """Test 12: TMOUT değerinin 0 (sınırsız) olması zafiyet olarak işaretlenmelidir."""
        session = SessionPolicySpec(inactivity_timeout_tmout=0)
        vulns = self.engine.audit_session_policy(session)
        tmout_vulns = [v for v in vulns if v.cwe_id == "CWE-613"]
        self.assertEqual(len(tmout_vulns), 1)

    def test_13_file_permissions_insecure_mode_0666(self) -> None:
        """Test 13: PAM dosya izninin 0666 olması CRITICAL CWE-732 üretmelidir."""
        perm = PamFilePermSpec(file_path="/etc/pam.d/system-auth", owner="root", group="root", mode_octal="0666", is_writable_by_others=True)
        vulns = self.engine.audit_pam_permissions([perm])
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, "CRITICAL")
        self.assertEqual(vulns[0].cwe_id, "CWE-732")

    def test_14_file_permissions_non_root_owner(self) -> None:
        """Test 14: PAM dosyasının root dışı kullanıcıya ait olması CRITICAL zafiyet üretmelidir."""
        perm = PamFilePermSpec(file_path="/etc/security/pwquality.conf", owner="john", group="users", mode_octal="0644", is_writable_by_others=False)
        vulns = self.engine.audit_pam_permissions([perm])
        self.assertEqual(len(vulns), 1)
        self.assertIn("Root Sahipliğinde Değil", vulns[0].title)

    def test_15_end_to_end_audit_and_script_generation(self) -> None:
        """Test 15: Çoklu PAM zafiyeti içeren envanter denetlenmeli ve Bash betiği üretilmelidir."""
        inv = self.get_clean_baseline_inventory()
        inv["account_lockout"]["enabled"] = False
        inv["session_policy"]["nullok_present"] = True

        report = self.engine.run_pam_audit(inv)
        self.assertLess(report["summary"]["score"], 60.0)
        self.assertEqual(report["summary"]["status"], "CRITICAL")
        self.assertGreaterEqual(report["summary"]["total_vulnerabilities"], 2)

        script = self.engine.generate_bash_remediation_script()
        self.assertIn("#!/bin/bash", script)
        self.assertIn("TMOUT=900", script)
        self.assertIn("pwquality.conf", script)
        self.assertIn("faillock.conf", script)


if __name__ == "__main__":
    unittest.main()
