# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 145: Group Policy Güvenlik Etkileri Birim Test Paketi.
Active Directory GPO güvenlik mimarisi, miras (inheritance) hiyerarşisi,
LSDOU önceliği, SYSVOL cpassword zafiyeti ve LAPS ilkelerini 15 testle doğrular.
"""

# Standart Python birim test modülü içe aktarılır.
import unittest
# Derin kopyalama için copy modülü içe aktarılır.
import copy
# Test edilen GPO motoru ve veri sınıfları içe aktarılır.
from uygulama.gpo_security_engine import (
    GpoSecurityEngine,
    GpoLinkScope,
    SeverityLevel,
)


class TestGpoSecurityEngine(unittest.TestCase):
    """
    GPO güvenlik ve sertleştirme motoru için 15 kapsamlı birim testi sınıfı.
    """

    def setUp(self) -> None:
        """
        Her test öncesinde temel temiz bir GPO spesifikasyonu hazırlar.
        """
        self.base_spec = {
            "domain": "kurum.local",
            "gpo_list": [
                {
                    "guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
                    "display_name": "Default Domain Policy",
                    "scope": "DOMAIN",
                    "target_path": "DC=kurum,DC=local",
                    "is_enforced": False,
                    "is_enabled": True,
                    "acl_permissions": {
                        "Domain Admins": ["GenericAll"],
                        "Authenticated Users": ["Read"]
                    },
                    "has_cpassword_leak": False,
                    "enforces_laps": False,
                    "user_rights": {},
                    "scripts": []
                },
                {
                    "guid": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
                    "display_name": "GPO-Enforce-Windows-LAPS",
                    "scope": "OU",
                    "target_path": "OU=Workstations,DC=kurum,DC=local",
                    "is_enforced": True,
                    "is_enabled": True,
                    "acl_permissions": {
                        "Domain Admins": ["GenericAll"],
                        "Authenticated Users": ["Read"]
                    },
                    "has_cpassword_leak": False,
                    "enforces_laps": True,
                    "user_rights": {
                        "SeDebugPrivilege": ["Administrators"]
                    },
                    "scripts": [
                        {"name": "inventory.ps1", "path": "\\\\kurum.local\\sysvol\\scripts\\inventory.ps1"}
                    ]
                }
            ],
            "organizational_units": {
                "OU=Workstations,DC=kurum,DC=local": {
                    "name": "Workstations",
                    "block_inheritance": False
                },
                "OU=Isolated,DC=kurum,DC=local": {
                    "name": "Isolated",
                    "block_inheritance": True
                }
            }
        }

    def test_01_clean_spec_full_audit_pass(self) -> None:
        """
        1. Test: Temiz ve sertleştirilmiş bir GPO ortamının 100 tam puan almasını doğrular.
        """
        engine = GpoSecurityEngine(self.base_spec)
        summary = engine.run_full_gpo_audit()
        self.assertEqual(summary.security_score, 100.0, "Temiz ortam 100 tam puan almalıdır")
        self.assertEqual(summary.failed_checks, 0, "Sıfır hata olmalıdır")
        self.assertEqual(summary.critical_findings_count, 0)

    def test_02_sysvol_cpassword_leak_detected(self) -> None:
        """
        2. Test: SYSVOL tercih dosyasında cpassword sızıntısı olduğunda CRITICAL açık verilmelidir.
        """
        spec = copy.deepcopy(self.base_spec)
        spec["gpo_list"][0]["has_cpassword_leak"] = True
        engine = GpoSecurityEngine(spec)
        finding = engine.audit_sysvol_cpassword_leak()
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.CRITICAL)
        self.assertIn("cpassword", finding.description)

    def test_03_sysvol_clean_cpassword_pass(self) -> None:
        """
        3. Test: cpassword içermeyen temiz GPO dosyalarının PASS almasını doğrular.
        """
        engine = GpoSecurityEngine(self.base_spec)
        finding = engine.audit_sysvol_cpassword_leak()
        self.assertEqual(finding.status, "PASS")

    def test_04_gpo_acl_writedacl_delegation_abuse(self) -> None:
        """
        4. Test: Authenticated Users grubuna WriteDacl izni verildiğinde CRITICAL açık raporlanmalıdır.
        """
        spec = copy.deepcopy(self.base_spec)
        spec["gpo_list"][0]["acl_permissions"]["Authenticated Users"] = ["Read", "WriteDacl"]
        engine = GpoSecurityEngine(spec)
        finding = engine.audit_gpo_delegation_abuse()
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.CRITICAL)

    def test_05_gpo_acl_genericall_abuse(self) -> None:
        """
        5. Test: Domain Users grubuna GenericAll izni verildiğinde GPO Hijacking riski yakalanmalıdır.
        """
        spec = copy.deepcopy(self.base_spec)
        spec["gpo_list"][1]["acl_permissions"]["Domain Users"] = ["GenericAll"]
        engine = GpoSecurityEngine(spec)
        finding = engine.audit_gpo_delegation_abuse()
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.CRITICAL)

    def test_06_gpo_acl_admin_only_pass(self) -> None:
        """
        6. Test: Yalnızca Domain Admins grubunun yazma yetkisine sahip olduğu temiz ACL'in PASS almasını doğrular.
        """
        engine = GpoSecurityEngine(self.base_spec)
        finding = engine.audit_gpo_delegation_abuse()
        self.assertEqual(finding.status, "PASS")

    def test_07_laps_enforcement_detected_pass(self) -> None:
        """
        7. Test: Etki alanında aktif LAPS ilkesi tanımlı olduğunda PASS verilmelidir.
        """
        engine = GpoSecurityEngine(self.base_spec)
        finding = engine.audit_laps_enforcement()
        self.assertEqual(finding.status, "PASS")

    def test_08_laps_missing_fail(self) -> None:
        """
        8. Test: LAPS ilkesi tanımlanmadığında HIGH önem derecesinde FAIL verilmelidir.
        """
        spec = copy.deepcopy(self.base_spec)
        for g in spec["gpo_list"]:
            g["enforces_laps"] = False
        engine = GpoSecurityEngine(spec)
        finding = engine.audit_laps_enforcement()
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.HIGH)

    def test_09_user_rights_sedebugprivilege_abuse(self) -> None:
        """
        9. Test: SeDebugPrivilege yetkisi Domain Users grubuna verildiğinde açık yakalanmalıdır.
        """
        spec = copy.deepcopy(self.base_spec)
        spec["gpo_list"][1]["user_rights"]["SeDebugPrivilege"] = ["Administrators", "Domain Users"]
        engine = GpoSecurityEngine(spec)
        finding = engine.audit_user_rights_assignment()
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.HIGH)

    def test_10_user_rights_clean_assignment_pass(self) -> None:
        """
        10. Test: Tehlikeli hakların yalnızca Administrators grubunda olması durumunda PASS alınmalıdır.
        """
        engine = GpoSecurityEngine(self.base_spec)
        finding = engine.audit_user_rights_assignment()
        self.assertEqual(finding.status, "PASS")

    def test_11_insecure_http_startup_script_fail(self) -> None:
        """
        11. Test: Başlangıç betiği güvensiz HTTP üzerinden çağrıldığında MEDIUM zafiyet raporlanmalıdır.
        """
        spec = copy.deepcopy(self.base_spec)
        spec["gpo_list"][1]["scripts"] = [{"name": "bad.bat", "path": "http://malicious.local/bad.bat"}]
        engine = GpoSecurityEngine(spec)
        finding = engine.audit_gpo_scripts_security()
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, SeverityLevel.MEDIUM)

    def test_12_secure_sysvol_startup_script_pass(self) -> None:
        """
        12. Test: SYSVOL içindeki güvenli betik yollarının PASS almasını doğrular.
        """
        engine = GpoSecurityEngine(self.base_spec)
        finding = engine.audit_gpo_scripts_security()
        self.assertEqual(finding.status, "PASS")

    def test_13_lsdou_inheritance_precedence(self) -> None:
        """
        13. Test: Normal bir OU'da LSDOU önceliğine göre Domain GPO'sunun OU GPO'sundan önce gelmesini doğrular.
        """
        engine = GpoSecurityEngine(self.base_spec)
        chain = engine.evaluate_lsdou_effective_policies("OU=Workstations,DC=kurum,DC=local")
        self.assertEqual(len(chain), 2)
        # LSDOU sırası: 1. Default Domain Policy, 2. GPO-Enforce-Windows-LAPS
        self.assertEqual(chain[0][0], "Default Domain Policy")
        self.assertEqual(chain[1][0], "GPO-Enforce-Windows-LAPS")

    def test_14_lsdou_block_inheritance_filtered(self) -> None:
        """
        14. Test: Block Inheritance olan bir OU'da Enforced olmayan Domain GPO'sunun elenmesini test eder.
        """
        engine = GpoSecurityEngine(self.base_spec)
        # Isolated OU'sunda block_inheritance = True ve Default Domain Policy is_enforced = False
        chain = engine.evaluate_lsdou_effective_policies("OU=Isolated,DC=kurum,DC=local")
        # Enforced olmayan Default Domain Policy filtrelenmeli
        names = [item[0] for item in chain]
        self.assertNotIn("Default Domain Policy", names)

    def test_15_lsdou_enforced_gpo_overrides_block(self) -> None:
        """
        15. Test: Enforced (NoOverride) olan bir Domain GPO'sunun Block Inheritance engelini aşarak uygulanmasını doğrular.
        """
        spec = copy.deepcopy(self.base_spec)
        # Default Domain Policy'yi Enforced yapıyoruz
        spec["gpo_list"][0]["is_enforced"] = True
        engine = GpoSecurityEngine(spec)
        chain = engine.evaluate_lsdou_effective_policies("OU=Isolated,DC=kurum,DC=local")
        names = [item[0] for item in chain]
        # Enforced olduğu için Block Inheritance'a rağmen listelenmelidir
        self.assertIn("Default Domain Policy", names)


if __name__ == "__main__":
    unittest.main()
