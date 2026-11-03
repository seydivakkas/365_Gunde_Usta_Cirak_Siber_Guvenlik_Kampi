# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 131: WINDOWS DEFENDER GÜVENLİK DUVARI BİRİM TESTLERİ (15/15 PASS)
-------------------------------------------------------------------
Bu test paketi; Domain, Private ve Public profillerinin etkinliğini, varsayılan
gelen bloklama politikasını, paket kütüklemesini, tehlikeli Any-Any kurallarını
ve genel ağda (Public) açık RDP/SMB/WinRM portlarını kapsamlı şekilde sınar.
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
from uygulama.windows_firewall_engine import (
    WindowsFirewallEngine,
    FirewallProfileType,
    FirewallAction,
    FirewallProfileConfig,
    FirewallRule,
    SystemFirewallSpec,
    AuditSeverity
)
from uygulama.firewall_cli import parse_firewall_spec_from_dict, build_parser


class TestWindowsFirewallEngine(unittest.TestCase):
    """Windows Güvenlik Duvarı Denetim Motoru Test Sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        # Testlerde kullanılacak denetim motoru nesnesini başlatıyoruz
        self.engine = WindowsFirewallEngine(auditor_name="Test Firewall Hardener")

        # Kusursuz CIS standartlarına uygun sertleştirilmiş temel profiller
        self.hardened_profiles = {
            FirewallProfileType.DOMAIN: FirewallProfileConfig(
                profile_type=FirewallProfileType.DOMAIN,
                enabled=True,
                default_inbound_action=FirewallAction.BLOCK,
                default_outbound_action=FirewallAction.ALLOW,
                log_blocked=True,
                log_file_size_kb=16384
            ),
            FirewallProfileType.PRIVATE: FirewallProfileConfig(
                profile_type=FirewallProfileType.PRIVATE,
                enabled=True,
                default_inbound_action=FirewallAction.BLOCK,
                default_outbound_action=FirewallAction.ALLOW,
                log_blocked=True,
                log_file_size_kb=16384
            ),
            FirewallProfileType.PUBLIC: FirewallProfileConfig(
                profile_type=FirewallProfileType.PUBLIC,
                enabled=True,
                default_inbound_action=FirewallAction.BLOCK,
                default_outbound_action=FirewallAction.ALLOW,
                allow_inbound_rules=False,
                log_blocked=True,
                log_file_size_kb=16384
            )
        }

        self.hardened_spec = SystemFirewallSpec(
            target_host="CORP-SECURE-W11",
            profiles=self.hardened_profiles,
            rules=[]
        )

    def test_01_hardened_cis_baseline(self):
        """Test 01: Kusursuz CIS uyumlu yapılandırma 100/100 tam puan ve sıfır bulgu üretmelidir."""
        result = self.engine.audit_firewall(self.hardened_spec)
        self.assertEqual(result.security_score, 100.0)
        self.assertIn("PASS", result.posture_status)
        self.assertEqual(len(result.findings), 0)

    def test_02_public_profile_disabled_cwe_693(self):
        """Test 02: Public profilin kapalı olması kritik CWE-693 bulgusu ve 30 puan düşüşü oluşturmalıdır."""
        profs = dict(self.hardened_profiles)
        profs[FirewallProfileType.PUBLIC] = FirewallProfileConfig(
            profile_type=FirewallProfileType.PUBLIC,
            enabled=False
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=profs)
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 70.0)
        finding = next(f for f in result.findings if "Public" in f.title)
        self.assertEqual(finding.severity, AuditSeverity.CRITICAL)
        self.assertEqual(finding.cwe_id, "CWE-693")

    def test_03_domain_profile_disabled_cwe_693(self):
        """Test 03: Domain profilinin kapalı olması 20 puan ceza ve yüksek risk oluşturmalıdır."""
        profs = dict(self.hardened_profiles)
        profs[FirewallProfileType.DOMAIN] = FirewallProfileConfig(
            profile_type=FirewallProfileType.DOMAIN,
            enabled=False
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=profs)
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 80.0)
        self.assertTrue(any("Domain" in f.title for f in result.findings))

    def test_04_default_inbound_allow_cwe_284(self):
        """Test 04: Varsayılan gelen eylemin Allow olması kritik CWE-284 bulgusu üretmelidir."""
        profs = dict(self.hardened_profiles)
        profs[FirewallProfileType.PRIVATE] = FirewallProfileConfig(
            profile_type=FirewallProfileType.PRIVATE,
            enabled=True,
            default_inbound_action=FirewallAction.ALLOW
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=profs)
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 75.0)
        finding = next(f for f in result.findings if "DefaultInboundAction" in f.powershell_remediation)
        self.assertEqual(finding.severity, AuditSeverity.CRITICAL)

    def test_05_log_blocked_disabled_cwe_778(self):
        """Test 05: Engellenen paket kütüklemesinin kapalı olması 10 puan ceza ve CWE-778 getirmelidir."""
        profs = dict(self.hardened_profiles)
        profs[FirewallProfileType.DOMAIN] = FirewallProfileConfig(
            profile_type=FirewallProfileType.DOMAIN,
            enabled=True,
            log_blocked=False
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=profs)
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 90.0)
        self.assertTrue(any(f.cwe_id == "CWE-778" for f in result.findings))

    def test_06_log_size_below_minimum_cwe_778(self):
        """Test 06: Kütük dosya boyutunun 16 MB altında olması düşük ciddiyetli bulgu üretmelidir."""
        profs = dict(self.hardened_profiles)
        profs[FirewallProfileType.DOMAIN] = FirewallProfileConfig(
            profile_type=FirewallProfileType.DOMAIN,
            enabled=True,
            log_file_size_kb=4096
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=profs)
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 95.0)
        self.assertTrue(any("Boyutu Yetersiz" in f.title for f in result.findings))

    def test_07_inbound_any_any_rule_cwe_284(self):
        """Test 07: Any-Any gelen izin kuralı tanımlanması kritik 25 puan düşüşü oluşturmalıdır."""
        bad_rule = FirewallRule(
            rule_name="OpenAllTraffic",
            direction="Inbound",
            action=FirewallAction.ALLOW,
            remote_address="Any",
            local_port="Any"
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=self.hardened_profiles, rules=[bad_rule])
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 75.0)
        finding = next(f for f in result.findings if "Any-to-Any" in f.title)
        self.assertEqual(finding.severity, AuditSeverity.CRITICAL)

    def test_08_public_profile_rdp_port_open_cwe_284(self):
        """Test 08: Public profil üzerinde 3389 (RDP) portunun açık olması kritik T1021.001 uyarısı üretmelidir."""
        rdp_rule = FirewallRule(
            rule_name="AllowRDP_Public",
            direction="Inbound",
            action=FirewallAction.ALLOW,
            profiles=[FirewallProfileType.PUBLIC],
            local_port="3389",
            remote_address="Any"
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=self.hardened_profiles, rules=[rdp_rule])
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 80.0)
        finding = next(f for f in result.findings if "RDP" in f.title)
        self.assertEqual(finding.severity, AuditSeverity.CRITICAL)
        self.assertIn("T1021.001", finding.mitre_technique_id)

    def test_09_public_profile_smb_port_open_cwe_284(self):
        """Test 09: Public profilde 445 (SMB) portunun açık olması 20 puan ceza getirmelidir."""
        smb_rule = FirewallRule(
            rule_name="AllowSMB_Public",
            direction="Inbound",
            action=FirewallAction.ALLOW,
            profiles=[FirewallProfileType.PUBLIC],
            local_port="445",
            remote_address="Any"
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=self.hardened_profiles, rules=[smb_rule])
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 80.0)
        self.assertTrue(any("SMB" in f.title for f in result.findings))

    def test_10_public_profile_winrm_port_open_cwe_284(self):
        """Test 10: Public profilde WinRM (5985) portunun açık olması kritik zaaf olarak yakalanmalıdır."""
        winrm_rule = FirewallRule(
            rule_name="AllowWinRM_Public",
            direction="Inbound",
            action=FirewallAction.ALLOW,
            profiles=[FirewallProfileType.PUBLIC],
            local_port="5985",
            remote_address="Any"
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=self.hardened_profiles, rules=[winrm_rule])
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 80.0)
        self.assertTrue(any("WinRM" in f.title for f in result.findings))

    def test_11_private_profile_isolated_rule_passes(self):
        """Test 11: Yalnızca Private profilde açık olan bir kural Public profil uyarısı tetiklememelidir."""
        safe_private_rule = FirewallRule(
            rule_name="AllowInternalService",
            direction="Inbound",
            action=FirewallAction.ALLOW,
            profiles=[FirewallProfileType.PRIVATE],
            local_port="3389",
            remote_address="192.168.1.0/24"
        )
        spec = SystemFirewallSpec(target_host="TEST-HOST", profiles=self.hardened_profiles, rules=[safe_private_rule])
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 100.0)
        self.assertEqual(len(result.findings), 0)

    def test_12_cumulative_penalty_and_floor(self):
        """Test 12: Birden fazla kritik açığın puanı sıfırın altına düşürmeden KRİTİK_ZAFİYET seviyesine indirdiği sınanmalıdır."""
        profs = {
            pt: FirewallProfileConfig(profile_type=pt, enabled=False)
            for pt in FirewallProfileType
        }
        spec = SystemFirewallSpec(target_host="RUINED-HOST", profiles=profs)
        result = self.engine.audit_firewall(spec)
        self.assertEqual(result.security_score, 30.0)
        self.assertIn("KRİTİK_ZAFİYET", result.posture_status)

    def test_13_markdown_report_structure(self):
        """Test 13: Markdown raporunun başlık, bulgu tablosu ve Set-NetFirewallProfile kod bloğunu içerdiği doğrulanmalıdır."""
        profs = dict(self.hardened_profiles)
        profs[FirewallProfileType.PUBLIC] = FirewallProfileConfig(profile_type=FirewallProfileType.PUBLIC, enabled=False)
        spec = SystemFirewallSpec(target_host="AUDIT-HOST-01", profiles=profs)
        result = self.engine.audit_firewall(spec)
        md = self.engine.export_markdown_report(result)
        self.assertIn("# WINDOWS DEFENDER GÜVENLİK DUVARI (FIREWALL) DENETİM RAPORU", md)
        self.assertIn("AUDIT-HOST-01", md)
        self.assertIn("Set-NetFirewallProfile", md)

    def test_14_cli_spec_parsing_and_conversion(self):
        """Test 14: JSON sözlük yapısının SystemFirewallSpec nesnesine hatasız dönüştüğü sınanmalıdır."""
        sample_dict = {
            "target_host": "PARSED-FW",
            "profiles": {
                "Domain": {"enabled": True, "default_inbound_action": "Block"},
                "Public": {"enabled": False}
            },
            "rules": [
                {"rule_name": "TestRule", "direction": "Inbound", "action": "Allow", "profiles": ["Public"], "local_port": "3389"}
            ]
        }
        spec = parse_firewall_spec_from_dict(sample_dict)
        self.assertEqual(spec.target_host, "PARSED-FW")
        self.assertTrue(spec.profiles[FirewallProfileType.DOMAIN].enabled)
        self.assertFalse(spec.profiles[FirewallProfileType.PUBLIC].enabled)
        self.assertEqual(len(spec.rules), 1)

    def test_15_cli_parser_and_subcommands(self):
        """Test 15: CLI argüman ayrıştırıcısının audit, remediate ve profiles-info alt komutlarını tanıdığı doğrulanmalıdır."""
        parser = build_parser()
        args_audit = parser.parse_args(["audit", "--spec", "fw.json", "--format", "json"])
        self.assertEqual(args_audit.command, "audit")
        self.assertEqual(args_audit.format, "json")

        args_info = parser.parse_args(["profiles-info"])
        self.assertEqual(args_info.command, "profiles-info")


if __name__ == "__main__":
    unittest.main()
