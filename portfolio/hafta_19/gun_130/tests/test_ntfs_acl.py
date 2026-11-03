# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 130: NTFS ERİŞİM KONTROL LİSTELERİ BİRİM TESTLERİ (15/15 PASS)
----------------------------------------------------------------
Bu test paketi; NTFS DACL/SACL kurallarını, tehlikeli yazma haklarını (CWE-732),
genel zayıf izinleri (CWE-276), unquoted service path zaaflarını (CWE-428),
standart kullanıcı sahipliğini ve kanonik ACE sıralamasını sınar.
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
from uygulama.ntfs_acl_engine import (
    NTFSACLEngine,
    NTFSSecurityDescriptor,
    NTFSACE,
    ACEType,
    NTFSPermission,
    AuditSeverity
)
from uygulama.ntfs_cli import parse_descriptors_from_dict, build_parser


class TestNTFSACLEngine(unittest.TestCase):
    """NTFS ACL Denetim Motoru Test Sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        # Testlerde kullanılacak denetim motoru nesnesini başlatıyoruz
        self.engine = NTFSACLEngine(auditor_name="Test NTFS Hardener")

        # Kusursuz CIS standartlarına uygun sertleştirilmiş temel tanımlayıcı
        self.hardened_descriptor = NTFSSecurityDescriptor(
            path="C:\\Program Files\\SecureApp\\bin",
            is_directory=True,
            owner="BUILTIN\\Administrators",
            group="BUILTIN\\Administrators",
            are_access_rules_protected=True,
            dacl=[
                NTFSACE(
                    identity="NT AUTHORITY\\SYSTEM",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.FULL_CONTROL],
                    is_inherited=False
                ),
                NTFSACE(
                    identity="BUILTIN\\Administrators",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.FULL_CONTROL],
                    is_inherited=False
                ),
                NTFSACE(
                    identity="BUILTIN\\Users",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.READ_AND_EXECUTE, NTFSPermission.READ],
                    is_inherited=False
                )
            ]
        )

    def test_01_hardened_cis_baseline(self):
        """Test 01: Kusursuz CIS uyumlu NTFS yapılandırması 100/100 tam puan ve sıfır bulgu üretmelidir."""
        result = self.engine.audit_security_descriptors(
            target_system="CORP-SECURE-W11",
            descriptors=[self.hardened_descriptor]
        )
        self.assertEqual(result.security_score, 100.0)
        self.assertIn("PASS", result.posture_status)
        self.assertEqual(len(result.findings), 0)

    def test_02_dangerous_write_on_system32_cwe_732(self):
        """Test 02: Everyone grubuna sistem ikilisinde FullControl verilmesi kritik CWE-732 bulgusu üretmelidir."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\Windows\\System32\\critical_service.exe",
            is_directory=False,
            owner="BUILTIN\\Administrators",
            dacl=[
                NTFSACE(
                    identity="Everyone",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.FULL_CONTROL]
                )
            ]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        self.assertEqual(result.security_score, 75.0)
        finding = result.findings[0]
        self.assertEqual(finding.severity, AuditSeverity.CRITICAL)
        self.assertEqual(finding.cwe_id, "CWE-732")
        self.assertIn("T1574.009", finding.mitre_technique_id)

    def test_03_dangerous_modify_on_program_files_cwe_732(self):
        """Test 03: BUILTIN\\Users grubuna Program Files altında Modify hakkı verilmesi 25 puan kırmalıdır."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\Program Files\\ERPApp\\app_module.dll",
            is_directory=False,
            owner="BUILTIN\\Administrators",
            dacl=[
                NTFSACE(
                    identity="BUILTIN\\Users",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.MODIFY]
                )
            ]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        self.assertEqual(result.security_score, 75.0)
        self.assertTrue(any("Modify" in f.current_rights for f in result.findings))

    def test_04_unprivileged_owner_on_critical_binary_cwe_284(self):
        """Test 04: Standart bir kullanıcının sistem dosyasının sahibi olması CWE-284 uyarısı üretmelidir."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\Program Files\\App\\driver.dll",
            is_directory=False,
            owner="BUILTIN\\Users",
            dacl=[]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        self.assertEqual(result.security_score, 85.0)
        finding = next(f for f in result.findings if "Sahipliği" in f.title)
        self.assertEqual(finding.severity, AuditSeverity.HIGH)
        self.assertIn("takeown", finding.powershell_remediation)

    def test_05_unquoted_service_path_vulnerability_cwe_428(self):
        """Test 05: Boşluklu servis yolunda yazılabilir üst dizin olması kritik CWE-428 bulgusu üretmelidir."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\Program Files\\My Service App\\service.exe",
            is_directory=False,
            owner="BUILTIN\\Administrators",
            dacl=[
                NTFSACE(
                    identity="Everyone",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.WRITE]
                )
            ]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        # Hem CWE-732 (25 puan) hem de CWE-428 (20 puan) cezası uygulanır
        self.assertEqual(result.security_score, 55.0)
        cwe_ids = [f.cwe_id for f in result.findings]
        self.assertIn("CWE-428", cwe_ids)

    def test_06_non_canonical_ace_ordering_cwe_284(self):
        """Test 06: Explicit Allow'un Explicit Deny'den önce gelmesi bozuk kural sıralaması bulgusu üretmelidir."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\Data\\Shared",
            is_directory=True,
            dacl=[
                NTFSACE(
                    identity="BUILTIN\\Users",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.READ],
                    is_inherited=False
                ),
                NTFSACE(
                    identity="Guest",
                    ace_type=ACEType.ACCESS_DENIED,
                    rights=[NTFSPermission.FULL_CONTROL],
                    is_inherited=False
                )
            ]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        self.assertEqual(result.security_score, 90.0)
        self.assertTrue(any("Kanonik Olmayan" in f.title for f in result.findings))

    def test_07_authenticated_users_dangerous_write_cwe_732(self):
        """Test 07: Authenticated Users grubunun sistem dizininde Write iznine sahip olması zafiyettir."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\ProgramData\\App\\bin",
            is_directory=True,
            dacl=[
                NTFSACE(
                    identity="Authenticated Users",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.WRITE]
                )
            ]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        self.assertEqual(result.security_score, 75.0)
        self.assertTrue(any(f.cwe_id == "CWE-732" for f in result.findings))

    def test_08_read_and_execute_permission_passes(self):
        """Test 08: Standart kullanıcıya yalnızca ReadAndExecute verilmesi güvenlik açığı oluşturmamalıdır."""
        safe_desc = NTFSSecurityDescriptor(
            path="C:\\Program Files\\StandardApp",
            is_directory=True,
            dacl=[
                NTFSACE(
                    identity="BUILTIN\\Users",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.READ_AND_EXECUTE, NTFSPermission.READ]
                )
            ]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [safe_desc])
        self.assertEqual(result.security_score, 100.0)
        self.assertEqual(len(result.findings), 0)

    def test_09_general_weak_permission_on_data_path_cwe_276(self):
        """Test 09: Sistem dizinleri dışındaki genel bir yolda zayıf izin bulunması CWE-276 olarak etiketlenmelidir."""
        vuln_desc = NTFSSecurityDescriptor(
            path="D:\\CompanyShare\\Public",
            is_directory=True,
            dacl=[
                NTFSACE(
                    identity="Everyone",
                    ace_type=ACEType.ACCESS_ALLOWED,
                    rights=[NTFSPermission.MODIFY]
                )
            ]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        self.assertEqual(result.security_score, 85.0)
        finding = result.findings[0]
        self.assertEqual(finding.cwe_id, "CWE-276")

    def test_10_multiple_violations_cumulative_penalty(self):
        """Test 10: Birden çok kritik açığın puanı kümülatif olarak düşürdüğü ve sıfırın altına inemeyeceği doğrulanmalıdır."""
        descriptors = [
            NTFSSecurityDescriptor(
                path=f"C:\\Windows\\System32\\app_{i}.exe",
                dacl=[NTFSACE(identity="Everyone", rights=[NTFSPermission.FULL_CONTROL])]
            )
            for i in range(5)
        ]
        result = self.engine.audit_security_descriptors("HOST-SEVERAL-FLAWS", descriptors)
        self.assertEqual(result.security_score, 0.0)
        self.assertIn("KRİTİK_ZAFİYET", result.posture_status)

    def test_11_icacls_remediation_generation(self):
        """Test 11: Otomatik düzeltme betiğinin doğru icacls /remove komutlarını içerdiği doğrulanmalıdır."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\Program Files\\Vendor\\lib.dll",
            dacl=[NTFSACE(identity="BUILTIN\\Users", rights=[NTFSPermission.WRITE])]
        )
        result = self.engine.audit_security_descriptors("TEST-HOST", [vuln_desc])
        self.assertIn("icacls \"C:\\Program Files\\Vendor\\lib.dll\" /remove:g \"BUILTIN\\Users\"", result.remediation_script)

    def test_12_markdown_report_structure(self):
        """Test 12: Markdown raporunun başlık, bulgu tablosu ve icacls kod bloğunu içerdiği doğrulanmalıdır."""
        vuln_desc = NTFSSecurityDescriptor(
            path="C:\\Program Files\\Tools\\tool.exe",
            dacl=[NTFSACE(identity="Everyone", rights=[NTFSPermission.MODIFY])]
        )
        result = self.engine.audit_security_descriptors("AUDIT-SYSTEM-01", [vuln_desc])
        md = self.engine.export_markdown_report(result)
        self.assertIn("# NTFS ERİŞİM KONTROL LİSTELERİ (ACL/DACL/SACL) DENETİM RAPORU", md)
        self.assertIn("AUDIT-SYSTEM-01", md)
        self.assertIn("icacls", md)

    def test_13_cli_dict_parsing_accuracy(self):
        """Test 13: JSON sözlük yapısının NTFSSecurityDescriptor nesnelerine doğru dönüştüğü sınanmalıdır."""
        sample_dict = {
            "descriptors": [
                {
                    "path": "C:\\MyApp",
                    "is_directory": True,
                    "owner": "BUILTIN\\Administrators",
                    "dacl": [
                        {
                            "identity": "BUILTIN\\Users",
                            "ace_type": "AccessAllowed",
                            "rights": ["ReadAndExecute", "Read"]
                        }
                    ]
                }
            ]
        }
        parsed = parse_descriptors_from_dict(sample_dict)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].path, "C:\\MyApp")
        self.assertEqual(parsed[0].dacl[0].rights[0], NTFSPermission.READ_AND_EXECUTE)

    def test_14_takeown_and_setowner_remediation(self):
        """Test 14: Sahiplik zafiyetinde takeown ve icacls /setowner komutlarının üretildiği doğrulanmalıdır."""
        desc = NTFSSecurityDescriptor(path="C:\\Windows\\system.ini", owner="Guest")
        result = self.engine.audit_security_descriptors("TEST-HOST", [desc])
        finding = result.findings[0]
        self.assertIn("takeown /f 'C:\\Windows\\system.ini' /a", finding.powershell_remediation)
        self.assertIn("icacls \"C:\\Windows\\system.ini\" /setowner \"BUILTIN\\Administrators\"", finding.icacls_remediation)

    def test_15_cli_parser_and_subcommands(self):
        """Test 15: CLI argüman ayrıştırıcısının audit, remediate ve ace-help alt komutlarını tanıdığı doğrulanmalıdır."""
        parser = build_parser()
        args_audit = parser.parse_args(["audit", "--spec", "ntfs.json", "--format", "json"])
        self.assertEqual(args_audit.command, "audit")
        self.assertEqual(args_audit.format, "json")

        args_help = parser.parse_args(["ace-help"])
        self.assertEqual(args_help.command, "ace-help")


if __name__ == "__main__":
    unittest.main()
