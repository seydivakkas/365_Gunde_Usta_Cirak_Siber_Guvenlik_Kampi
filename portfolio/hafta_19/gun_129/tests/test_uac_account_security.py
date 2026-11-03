# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 129: WINDOWS YEREL HESAPLAR VE UAC BİRİM TESTLERİ (15/15 PASS)
-----------------------------------------------------------------
Bu test paketi; EnableLUA, FilterAdministratorToken, PromptOnSecureDesktop,
ConsentPromptBehaviorAdmin/User, Guest hesabı, Administrator yeniden adlandırma,
hesap kilitleme eşiği, LAPS ve yetkisiz grup üyeliklerini kapsamlı şekilde sınar.
"""

# Birim test çerçevesi için unittest modülü
import unittest
# Sistem yolunu düzenlemek için sys ve os modülleri
import sys
import os

# Üst dizini sys.path'e ekleyerek bağımsız çalışmayı garantiye alıyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Denetim motorunu ve veri sınıflarını içe aktarıyoruz
from uygulama.uac_account_security_engine import (
    UACAccountSecurityEngine,
    LocalAccountConfig,
    UACConfig,
    LocalGroupConfig,
    EndpointAccountSpec,
    AuditSeverity
)
from uygulama.uac_security_cli import parse_spec_from_dict, build_parser


class TestUACAccountSecurityEngine(unittest.TestCase):
    """Windows Yerel Hesaplar ve UAC Güvenlik Motoru Test Sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        # Testlerde kullanılacak denetim motoru nesnesini başlatıyoruz
        self.engine = UACAccountSecurityEngine(auditor_name="Test UAC Hardener")

        # Kusursuz CIS uyumlu sertleştirilmiş temel spesifikasyon
        self.hardened_spec = EndpointAccountSpec(
            target_host="CORP-SECURE-W11",
            accounts=LocalAccountConfig(
                guest_account_enabled=False,
                builtin_admin_name="SecAdmin_Local",
                builtin_admin_disabled=True,
                account_lockout_threshold=5,
                account_lockout_duration_mins=15,
                reset_lockout_counter_mins=15,
                laps_enabled=True
            ),
            uac=UACConfig(
                enable_lua=True,
                filter_administrator_token=True,
                consent_prompt_behavior_admin=2,
                consent_prompt_behavior_user=0,
                prompt_on_secure_desktop=True,
                enable_virtualization=True,
                validate_admin_code_signatures=False
            ),
            groups=LocalGroupConfig(
                administrators_members=["SecAdmin_Local", "Domain Admins"],
                remote_desktop_members=["RDP_Operators"],
                backup_operators_members=["Backup_Service"]
            )
        )

    def test_01_hardened_cis_baseline(self):
        """Test 01: Kusursuz CIS uyumlu yapılandırma 100/100 tam puan ve sıfır bulgu üretmelidir."""
        result = self.engine.audit_endpoint(self.hardened_spec)
        self.assertEqual(result.security_score, 100.0)
        self.assertIn("PASS", result.posture_status)
        self.assertEqual(len(result.findings), 0)

    def test_02_disabled_uac_enable_lua_cwe_693(self):
        """Test 02: EnableLUA=False olması kritik CWE-693 bulgusu ve 40 puan düşüşü oluşturmalıdır."""
        spec = EndpointAccountSpec(
            target_host="VICTIM-PC",
            accounts=self.hardened_spec.accounts,
            uac=UACConfig(enable_lua=False),
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 60.0)
        cwe_ids = [f.cwe_id for f in result.findings]
        self.assertIn("CWE-693", cwe_ids)
        self.assertTrue(any("EnableLUA" in f.powershell_remediation for f in result.findings))

    def test_03_filter_administrator_token_disabled_cwe_250(self):
        """Test 03: FilterAdministratorToken=False olması Yönetici Onay Modu açığı (CWE-250) üretmelidir."""
        spec = EndpointAccountSpec(
            target_host="ADMIN-PC",
            accounts=self.hardened_spec.accounts,
            uac=UACConfig(filter_administrator_token=False),
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 80.0)
        finding = next(f for f in result.findings if "FilterAdministratorToken" in f.powershell_remediation)
        self.assertEqual(finding.severity, AuditSeverity.HIGH)
        self.assertEqual(finding.cwe_id, "CWE-250")

    def test_04_prompt_on_secure_desktop_disabled_cwe_284(self):
        """Test 04: PromptOnSecureDesktop=False olması 15 puan ceza ve CWE-284 uyarısı getirmelidir."""
        spec = EndpointAccountSpec(
            target_host="DESK-PC",
            accounts=self.hardened_spec.accounts,
            uac=UACConfig(prompt_on_secure_desktop=False),
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 85.0)
        self.assertTrue(any(f.cwe_id == "CWE-284" for f in result.findings))

    def test_05_insecure_consent_prompt_behavior_admin_cwe_250(self):
        """Test 05: Yöneticiler için sessiz yükseltme (0) veya gevşek mod (5) CWE-250 bulgusu oluşturmalıdır."""
        spec = EndpointAccountSpec(
            target_host="EASY-ADMIN-PC",
            accounts=self.hardened_spec.accounts,
            uac=UACConfig(consent_prompt_behavior_admin=0),
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 85.0)
        self.assertTrue(any("Zayıf UAC Yükseltme" in f.title for f in result.findings))

    def test_06_insecure_consent_prompt_behavior_user_cwe_284(self):
        """Test 06: Standart kullanıcılar için uygun olmayan yükseltme davranışı puan düşürmelidir."""
        spec = EndpointAccountSpec(
            target_host="USER-PC",
            accounts=self.hardened_spec.accounts,
            uac=UACConfig(consent_prompt_behavior_user=1),
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 90.0)
        self.assertTrue(any("Standart Kullanıcılar" in f.title for f in result.findings))

    def test_07_enable_virtualization_disabled_cwe_1188(self):
        """Test 07: Dosya ve kayıt defteri sanallaştırmasının kapalı olması 5 puan kırmalıdır."""
        spec = EndpointAccountSpec(
            target_host="VIRT-PC",
            accounts=self.hardened_spec.accounts,
            uac=UACConfig(enable_virtualization=False),
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 95.0)
        self.assertTrue(any("Sanallaştırması" in f.title for f in result.findings))

    def test_08_guest_account_enabled_cwe_284(self):
        """Test 08: Yerel Guest hesabının açık olması 20 puan kırılmasını ve kritik zaafı tetiklemelidir."""
        spec = EndpointAccountSpec(
            target_host="GUEST-OPEN-PC",
            accounts=LocalAccountConfig(guest_account_enabled=True),
            uac=self.hardened_spec.uac,
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 80.0)
        finding = next(f for f in result.findings if "Guest" in f.title)
        self.assertEqual(finding.severity, AuditSeverity.CRITICAL)

    def test_09_builtin_admin_default_name_and_enabled_cwe_1188(self):
        """Test 09: Yerleşik Administrator hesabının yeniden adlandırılmaması ve açık olması zafiyettir."""
        spec = EndpointAccountSpec(
            target_host="RAW-ADMIN-PC",
            accounts=LocalAccountConfig(builtin_admin_name="Administrator", builtin_admin_disabled=False),
            uac=self.hardened_spec.uac,
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 85.0)
        self.assertTrue(any("Varsayılan Adda ve Etkin" in f.title for f in result.findings))

    def test_10_account_lockout_zero_or_excessive_cwe_307(self):
        """Test 10: Hesap kilitleme eşiğinin 0 olması Brute Force uyarısı (CWE-307) üretmelidir."""
        spec = EndpointAccountSpec(
            target_host="NO-LOCK-PC",
            accounts=LocalAccountConfig(account_lockout_threshold=0),
            uac=self.hardened_spec.uac,
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 90.0)
        self.assertTrue(any(f.cwe_id == "CWE-307" for f in result.findings))

    def test_11_laps_disabled_cwe_1188(self):
        """Test 11: Windows LAPS'ın kapalı olması 10 puan düşüşü ve CWE-1188 üretmelidir."""
        spec = EndpointAccountSpec(
            target_host="NO-LAPS-PC",
            accounts=LocalAccountConfig(laps_enabled=False),
            uac=self.hardened_spec.uac,
            groups=self.hardened_spec.groups
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 90.0)
        self.assertTrue(any("LAPS" in f.title for f in result.findings))

    def test_12_unauthorized_admin_group_member_cwe_250(self):
        """Test 12: 'Everyone' grubunun Administrators'a eklenmesi kritik CWE-250 bulgusu üretmelidir."""
        spec = EndpointAccountSpec(
            target_host="OPEN-ADMIN-PC",
            accounts=self.hardened_spec.accounts,
            uac=self.hardened_spec.uac,
            groups=LocalGroupConfig(administrators_members=["SecAdmin", "Everyone"])
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 80.0)
        finding = next(f for f in result.findings if "Everyone" in f.title)
        self.assertEqual(finding.severity, AuditSeverity.CRITICAL)
        self.assertIn("Remove-LocalGroupMember", finding.powershell_remediation)

    def test_13_unauthorized_rdp_group_member_cwe_284(self):
        """Test 13: 'Users' grubunun Uzak Masaüstü grubuna eklenmesi yüksek riskli CWE-284 bulgusu üretmelidir."""
        spec = EndpointAccountSpec(
            target_host="OPEN-RDP-PC",
            accounts=self.hardened_spec.accounts,
            uac=self.hardened_spec.uac,
            groups=LocalGroupConfig(remote_desktop_members=["Users"])
        )
        result = self.engine.audit_endpoint(spec)
        self.assertEqual(result.security_score, 85.0)
        finding = next(f for f in result.findings if "Uzak Masaüstü" in f.title)
        self.assertEqual(finding.severity, AuditSeverity.HIGH)

    def test_14_markdown_report_structure(self):
        """Test 14: Markdown denetim raporunun başlık, bulgu tablosu ve PowerShell betiğini içerdiği doğrulanmalıdır."""
        spec = EndpointAccountSpec(
            target_host="AUDIT-TEST-01",
            accounts=LocalAccountConfig(guest_account_enabled=True),
            uac=UACConfig(enable_lua=False),
            groups=LocalGroupConfig()
        )
        result = self.engine.audit_endpoint(spec)
        md = self.engine.export_markdown_report(result)
        self.assertIn("# WINDOWS YEREL HESAPLAR, GRUPLAR VE UAC DENETİM RAPORU", md)
        self.assertIn("AUDIT-TEST-01", md)
        self.assertIn("PowerShell Otomatik Sıkılaştırma", md)
        self.assertIn("EnableLUA", md)

    def test_15_cli_spec_parsing_and_subcommands(self):
        """Test 15: CLI veri sözlüğü dönüştürmesi ve argüman ayrıştırıcısı beklenen formatta çalışmalıdır."""
        sample_dict = {
            "target_host": "PARSED-PC",
            "accounts": {"guest_account_enabled": False, "builtin_admin_name": "Admin_Renamed"},
            "uac": {"enable_lua": True, "prompt_on_secure_desktop": True},
            "groups": {"administrators_members": ["Admin_Renamed"]}
        }
        parsed = parse_spec_from_dict(sample_dict)
        self.assertEqual(parsed.target_host, "PARSED-PC")
        self.assertEqual(parsed.accounts.builtin_admin_name, "Admin_Renamed")
        self.assertTrue(parsed.uac.prompt_on_secure_desktop)

        parser = build_parser()
        args = parser.parse_args(["audit", "--spec", "conf.json", "--format", "json"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.format, "json")


if __name__ == "__main__":
    unittest.main()
