# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 143 - Active Directory Etki Alanı Güvenliği Birim Test Paketi.
15 kapsamlı birim testi ile orman fonksiyonel seviyelerini, Kerberos şifrelemeyi,
krbtgt parola yaşını, NTLMv1 engelini, LDAP/SMB imzasını, Kerberoasting, AS-REP Roasting,
delegasyon risklerini ve PowerShell sıkılaştırma betiği üretimini doğrular.
"""

# Birim testleri için standart Python unittest kütüphanesi
import unittest
# Dosya yolları ve işletim sistemi fonksiyonları
import os
# Sistem çalışma yolu yönetimi
import sys
# JSON verisi manipülasyonu
import json
# Geçici dosya oluşturma
import tempfile

# Uygulama kaynak kod dizinini sys.path içerisine ekle
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.abspath(os.path.join(current_dir, "..", "uygulama"))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

# AD güvenlik motorunu import et
from ad_domain_security_engine import AdDomainSecurityEngine, AdFinding, AdAuditSummary


class TestAdDomainSecurityEngine(unittest.TestCase):
    """
    Active Directory Etki Alanı Güvenlik ve Denetim Motoru Test Sınıfı.
    """

    def setUp(self):
        """
        Her test öncesinde temiz referans spesifikasyon verisini hazırlar.
        """
        self.ref_spec_path = os.path.abspath(
            os.path.join(current_dir, "..", "ornek_veri", "enterprise_ad_domain_spec.json")
        )
        self.engine = AdDomainSecurityEngine()
        if os.path.exists(self.ref_spec_path):
            self.engine.load_spec_from_file(self.ref_spec_path)

    def test_01_load_spec_valid(self):
        """Test 01: Geçerli AD spesifikasyon dosyasının doğru yüklendiğini test eder."""
        self.assertIsNotNone(self.engine.spec)
        self.assertEqual(self.engine.spec["architecture"]["domain_name"], "corp.internal")

    def test_02_load_spec_missing_file(self):
        """Test 02: Mevcut olmayan bir dosya yüklendiğinde FileNotFoundError fırlatıldığını doğrular."""
        dummy = AdDomainSecurityEngine()
        with self.assertRaises(FileNotFoundError):
            dummy.load_spec_from_file("olmayan_ad_spec.json")

    def test_03_audit_architecture_pass(self):
        """Test 03: Modern Windows Server 2016+ seviyesinin PASS aldığını doğrular."""
        self.engine.audit_domain_architecture()
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-ARCH-01")
        self.assertEqual(finding.status, "PASS")

    def test_04_audit_architecture_fail_legacy_level(self):
        """Test 04: Windows 2008 R2 gibi eski seviyelerin FAIL ürettiğini doğrular."""
        self.engine.spec["architecture"]["domain_functional_level"] = "Windows2008R2Domain"
        self.engine.spec["architecture"]["forest_functional_level"] = "Windows2008R2Forest"
        self.engine.audit_domain_architecture()
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-ARCH-01")
        self.assertEqual(finding.status, "FAIL")

    def test_05_audit_kerberos_ciphers_pass_aes(self):
        """Test 05: Yalnızca AES şifreleme türlerinin etkin olmasının PASS aldığını test eder."""
        self.engine.audit_kerberos_security(ref_date_str="2026-11-02")
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-KERB-01")
        self.assertEqual(finding.status, "PASS")

    def test_06_audit_kerberos_ciphers_fail_rc4(self):
        """Test 06: RC4-HMAC veya DES açıkken CRITICAL düzeyinde FAIL verildiğini doğrular."""
        self.engine.spec["kerberos_policy"]["supported_encryption_types"].append("RC4-HMAC")
        self.engine.audit_kerberos_security(ref_date_str="2026-11-02")
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-KERB-01")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_07_audit_krbtgt_password_age_pass(self):
        """Test 07: krbtgt parolası 180 günden taze olduğunda PASS aldığını doğrular."""
        # 2026-10-01 tarihi 2026-11-02 itibariyle 32 gündür (<= 180)
        self.engine.audit_kerberos_security(ref_date_str="2026-11-02")
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-KERB-02")
        self.assertEqual(finding.status, "PASS")

    def test_08_audit_krbtgt_password_age_fail_overdue(self):
        """Test 08: krbtgt parolası 180 günden eski olduğunda Golden Ticket riskiyle FAIL aldığını test eder."""
        self.engine.spec["krbtgt_account"]["password_last_set"] = "2025-01-01"
        self.engine.audit_kerberos_security(ref_date_str="2026-11-02")
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-KERB-02")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_09_audit_ntlm_level_pass_5(self):
        """Test 09: LmCompatibilityLevel = 5 (Yalnızca NTLMv2) ayarının PASS aldığını doğrular."""
        self.engine.audit_ntlm_security()
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-NTLM-01")
        self.assertEqual(finding.status, "PASS")

    def test_10_audit_ntlm_level_fail_ntlmv1(self):
        """Test 10: LmCompatibilityLevel < 5 olduğunda NTLMv1 riskiyle FAIL aldığını test eder."""
        self.engine.spec["ntlm_policy"]["lm_compatibility_level"] = 1
        self.engine.audit_ntlm_security()
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-NTLM-01")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_11_audit_ldap_and_smb_signing_pass(self):
        """Test 11: LDAP imzalama ve SMB imzalama zorunluluklarının PASS aldığını doğrular."""
        self.engine.audit_ldap_smb_signing()
        ldap_finding = next(f for f in self.engine.findings if f.rule_id == "AD-LDAP-01")
        smb_finding = next(f for f in self.engine.findings if f.rule_id == "AD-SMB-01")
        self.assertEqual(ldap_finding.status, "PASS")
        self.assertEqual(smb_finding.status, "PASS")

    def test_12_audit_kerberoasting_admin_spn(self):
        """Test 12: Domain Admin hesabında SPN tanımlandığında Kerberoasting riskiyle FAIL üretildiğini test eder."""
        # Yönetici hesabına SPN ekle
        self.engine.spec["accounts"][0]["service_principal_names"] = ["MSSQLSvc/dc01"]
        self.engine.audit_account_and_delegation_risks()
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-ACC-01")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_13_audit_asrep_roasting_preauth(self):
        """Test 13: DONT_REQ_PREAUTH bayrağı aktif bir hesap olduğunda AS-REP Roasting FAIL üretildiğini test eder."""
        self.engine.spec["accounts"].append({
            "sam_account_name": "vuln_user",
            "is_privileged_admin": False,
            "service_principal_names": [],
            "dont_req_preauth": True,
            "delegation_type": "None"
        })
        self.engine.audit_account_and_delegation_risks()
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-ACC-02")
        self.assertEqual(finding.status, "FAIL")

    def test_14_audit_unconstrained_delegation(self):
        """Test 14: Sınırsız delegasyona (Unconstrained Delegation) sahip nesnede FAIL üretildiğini doğrular."""
        self.engine.spec["accounts"].append({
            "sam_account_name": "web_server_iis",
            "is_privileged_admin": False,
            "service_principal_names": ["HTTP/portal"],
            "dont_req_preauth": False,
            "delegation_type": "Unconstrained"
        })
        self.engine.audit_account_and_delegation_risks()
        finding = next(f for f in self.engine.findings if f.rule_id == "AD-ACC-03")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_15_generate_powershell_hardening_script(self):
        """Test 15: Otomatik PowerShell sıkılaştırma betiğinin üretildiğini ve kayıt defteri komutlarını içerdiğini doğrular."""
        # Birkaç ayarı bilinçli olarak FAIL yap
        self.engine.spec["kerberos_policy"]["supported_encryption_types"].append("RC4-HMAC")
        self.engine.spec["ntlm_policy"]["lm_compatibility_level"] = 1
        self.engine.spec["ldap_smb_policy"]["ldap_server_integrity"] = 0

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".ps1") as tmp:
            tmp_path = tmp.name

        try:
            content = self.engine.generate_powershell_hardening_script(output_path=tmp_path)
            self.assertIn("SupportedEncryptionTypes", content)
            self.assertIn("LmCompatibilityLevel", content)
            self.assertIn("LDAPServerIntegrity", content)
            self.assertTrue(os.path.exists(tmp_path))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
