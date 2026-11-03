# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Mini Proje 18: Bütünleşik Windows Güvenlik Denetim Platformu Birim Testleri.

Bu test modülü; 15 bağımsız birim test ile Windows Defender, UAC, NTFS ACL,
Windows Firewall ve Windows Hizmet Güvenliği alanlarının tek tek ve birleşik
olarak doğru puanlandığını, zafiyetlerin yakalandığını ve raporların üretildiğini doğrular.
"""

# Birim test çerçevesi için standart unittest modülü
import unittest
# Dosya ve dizin yolu manipülasyonu için standart os kütüphanesi
import os
# Arama yollarını yönetmek için sys kütüphanesi
import sys

# Test edilen modüllere erişim için yol ayarı
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from uygulama.windows_audit_platform_engine import WindowsAuditPlatformEngine
except ImportError:
    sys.path.insert(0, os.path.join(parent_dir, "uygulama"))
    from windows_audit_platform_engine import WindowsAuditPlatformEngine


class TestWindowsAuditPlatform(unittest.TestCase):
    """Windows Güvenlik Denetim Platformu 15 birim testi sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz bir denetim motoru başlatır."""
        self.engine = WindowsAuditPlatformEngine()

    def get_clean_compliant_spec(self) -> dict:
        """Tam uyumlu, 100 puanlık bir Windows uç nokta spesifikasyonu döndürür."""
        return {
            "defender": {
                "real_time_protection_enabled": True,
                "behavior_monitoring_enabled": True,
                "tamper_protection_enabled": True,
                "pua_protection": 1,
            },
            "uac_and_accounts": {
                "enable_lua": 1,
                "consent_prompt_behavior_admin": 2,
                "prompt_on_secure_desktop": 1,
                "guest_account_enabled": False,
            },
            "ntfs_security": {
                "writable_system_directories_for_users": [],
                "broken_inheritance_count": 0,
                "sacl_auditing_enabled": true if False else True,
            },
            "firewall": {
                "profiles": {
                    "Domain": {"enabled": True, "default_inbound_action": "Block"},
                    "Private": {"enabled": True, "default_inbound_action": "Block"},
                    "Public": {"enabled": True, "default_inbound_action": "Block"},
                },
                "public_exposed_ports": [],
            },
            "services": {
                "services": [
                    {
                        "service_name": "W32Time",
                        "image_path": '"C:\\Windows\\system32\\svchost.exe" -k LocalService',
                        "sddl": "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)",
                        "binary_permissions": {"BUILTIN\\Users": ["ReadAndExecute"]},
                        "start_type": "Automatic",
                    }
                ]
            },
        }

    def test_01_fully_compliant_baseline_scores_100(self) -> None:
        """Test 01: Tam uyumlu uç nokta spesifikasyonu 100.0 puan ve COMPLIANT durum üretmelidir."""
        spec = self.get_clean_compliant_spec()
        report = self.engine.run_full_windows_audit(spec)
        self.assertEqual(report["overall_summary"]["total_score"], 100.0)
        self.assertEqual(report["overall_summary"]["overall_status"], "COMPLIANT")
        self.assertEqual(report["overall_summary"]["total_vulnerabilities"], 0)

    def test_02_defender_domain_rtp_disabled(self) -> None:
        """Test 02: Defender RTP devre dışı bırakıldığında 10 puan kırılmalı ve CWE-693 üretilmelidir."""
        spec = {"real_time_protection_enabled": False, "behavior_monitoring_enabled": True, "tamper_protection_enabled": True, "pua_protection": 1}
        score, findings = self.engine.audit_defender_domain(spec)
        self.assertEqual(score, 10.0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-693")
        self.assertEqual(findings[0].mitre_id, "T1562.001")

    def test_03_defender_domain_tamper_protection_disabled(self) -> None:
        """Test 03: Defender Tamper Protection kapalı olduğunda bulgu üretilmelidir."""
        spec = {"real_time_protection_enabled": True, "behavior_monitoring_enabled": True, "tamper_protection_enabled": False, "pua_protection": 1}
        score, findings = self.engine.audit_defender_domain(spec)
        self.assertEqual(score, 17.0)
        self.assertTrue(any(f.target_name == "TamperProtection" for f in findings))

    def test_04_uac_domain_enable_lua_zero(self) -> None:
        """Test 04: UAC EnableLUA=0 yapıldığında 10 puan kırılmalı ve CRITICAL CWE-250 üretilmelidir."""
        spec = {"enable_lua": 0, "consent_prompt_behavior_admin": 2, "prompt_on_secure_desktop": 1, "guest_account_enabled": False}
        score, findings = self.engine.audit_uac_domain(spec)
        self.assertEqual(score, 10.0)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].cwe_id, "CWE-250")

    def test_05_uac_domain_silent_elevation(self) -> None:
        """Test 05: UAC ConsentPromptBehaviorAdmin=0 sessiz yükseltme zafiyeti oluşturmalıdır."""
        spec = {"enable_lua": 1, "consent_prompt_behavior_admin": 0, "prompt_on_secure_desktop": 1, "guest_account_enabled": False}
        score, findings = self.engine.audit_uac_domain(spec)
        self.assertEqual(score, 16.0)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_06_uac_domain_guest_account_enabled(self) -> None:
        """Test 06: Yerel Konuk (Guest) hesabı etkin olduğunda uyarı verilmelidir."""
        spec = {"enable_lua": 1, "consent_prompt_behavior_admin": 2, "prompt_on_secure_desktop": 1, "guest_account_enabled": True}
        score, findings = self.engine.audit_uac_domain(spec)
        self.assertEqual(score, 17.0)
        self.assertEqual(findings[0].target_name, "GuestAccount")

    def test_07_ntfs_domain_writable_system_directories(self) -> None:
        """Test 07: Sistem dizinlerinde kullanıcı yazma izni olması CWE-732 üretmelidir."""
        spec = {"writable_system_directories_for_users": ["C:\\Windows\\System32\\Spool"], "broken_inheritance_count": 0, "sacl_auditing_enabled": True}
        score, findings = self.engine.audit_ntfs_domain(spec)
        self.assertEqual(score, 14.0)
        self.assertEqual(findings[0].cwe_id, "CWE-732")

    def test_08_ntfs_domain_broken_inheritance(self) -> None:
        """Test 08: Kalıtımı bozulmuş dizinler kalıtım bütünlüğü uyarısı vermelidir."""
        spec = {"writable_system_directories_for_users": [], "broken_inheritance_count": 3, "sacl_auditing_enabled": True}
        score, findings = self.engine.audit_ntfs_domain(spec)
        self.assertEqual(score, 16.0)
        self.assertEqual(findings[0].target_name, "InheritanceIntegrity")

    def test_09_firewall_domain_disabled_profile(self) -> None:
        """Test 09: Güvenlik duvarı profillerinden birinin kapalı olması HIGH bulgu üretmelidir."""
        spec = {"profiles": {"Domain": {"enabled": True}, "Private": {"enabled": True}, "Public": {"enabled": False}}, "public_exposed_ports": []}
        score, findings = self.engine.audit_firewall_domain(spec)
        self.assertEqual(score, 16.0)
        self.assertEqual(findings[0].target_name, "Profile_Public")

    def test_10_firewall_domain_public_exposed_rdp(self) -> None:
        """Test 10: Public profilde 3389 RDP açık olması CRITICAL zafiyet ve T1021.001 üretmelidir."""
        spec = {"profiles": {"Public": {"enabled": True, "default_inbound_action": "Block"}}, "public_exposed_ports": [3389]}
        score, findings = self.engine.audit_firewall_domain(spec)
        self.assertEqual(score, 15.0)
        self.assertEqual(findings[0].cwe_id, "CWE-284")
        self.assertEqual(findings[0].mitre_id, "T1021.001")

    def test_11_service_domain_unquoted_path(self) -> None:
        """Test 11: Tırnaksız servis yolu CWE-428 ve T1574.009 üretmelidir."""
        spec = {"services": [{"service_name": "UnquotedSvc", "image_path": "C:\\Program Files\\App\\app.exe -run", "sddl": "", "binary_permissions": {}}]}
        score, findings = self.engine.audit_services_domain(spec)
        self.assertEqual(score, 15.0)
        self.assertEqual(findings[0].cwe_id, "CWE-428")

    def test_12_service_domain_weak_dacl_users_dc(self) -> None:
        """Test 12: SDDL içerisinde BU grubuna DC hakkı verilmesi CWE-732 üretmelidir."""
        spec = {"services": [{"service_name": "DaclSvc", "image_path": "\"C:\\App\\app.exe\"", "sddl": "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;DC;;;BU)", "binary_permissions": {}}]}
        score, findings = self.engine.audit_services_domain(spec)
        self.assertEqual(score, 14.0)
        self.assertEqual(findings[0].cwe_id, "CWE-732")

    def test_13_service_domain_writable_binary(self) -> None:
        """Test 13: Servis ikili dosyasının yazılabilir olması CRITICAL CWE-732 üretmelidir."""
        spec = {"services": [{"service_name": "WritableBinSvc", "image_path": "\"C:\\App\\bin.exe\"", "sddl": "", "binary_permissions": {"BUILTIN\\Users": ["Modify"]}}]}
        score, findings = self.engine.audit_services_domain(spec)
        self.assertEqual(score, 15.0)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_14_master_powershell_remediation_generation(self) -> None:
        """Test 14: Master iyileştirme betiği Set-MpPreference ve sc.exe komutlarını içermelidir."""
        spec = self.get_clean_compliant_spec()
        # İki zafiyet eklenir
        spec["defender"]["real_time_protection_enabled"] = False
        spec["services"]["services"].append({
            "service_name": "BadSvc",
            "image_path": "C:\\Program Files\\Bad\\bad.exe",
            "sddl": "",
            "binary_permissions": {},
        })
        self.engine.run_full_windows_audit(spec)
        script = self.engine.generate_master_remediation_powershell()
        self.assertIn("Set-MpPreference", script)
        self.assertIn("sc.exe config", script)

    def test_15_executive_markdown_report_generation(self) -> None:
        """Test 15: Markdown rapor üreticisi başlıkları, özet tablosunu ve bulguları eksiksiz üretmelidir."""
        spec = self.get_clean_compliant_spec()
        spec["uac_and_accounts"]["enable_lua"] = 0
        self.engine.run_full_windows_audit(spec)
        md_text = self.engine.generate_executive_markdown_report()
        self.assertIn("# Mini Proje 18: Bütünleşik Windows Güvenlik Denetim Raporu", md_text)
        self.assertIn("Yönetici Özeti", md_text)
        self.assertIn("Ayrıntılı Zafiyet Kataloğu", md_text)


if __name__ == "__main__":
    unittest.main()
