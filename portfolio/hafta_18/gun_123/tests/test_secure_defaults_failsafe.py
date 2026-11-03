# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 123: Güvenli Varsayılanlar ve Fail-Safe / Fail-Secure Birim Testleri.
15 birim test senaryosu: Saltzer-Schroeder Default-Deny, CWE-1188 güvenli olmayan varsayılanlar,
CWE-636 Fail-Closed denetimi, arıza simülasyonları ve kurumsal yönetişim doğrulamaları.
"""

# Standart unittest çerçevesi içe aktarılıyor
import unittest
# Sistem yolu ve dosya işlemleri için sys ve os içe aktarılıyor
import sys
import os

# Uygulama dizini arama yoluna ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
sys.path.insert(0, app_dir)

# Test edilecek motor sınıfları ve istisnalar içe aktarılıyor
from secure_defaults_failsafe_engine import (
    FailSafeSecurityManager,
    ResourceConfig,
    PolicyRule,
    AccessRequest,
    DecisionOutcome,
    FailureHandlingMode,
    FailureType,
    SecurityDefaultIssue,
    InsecureFailOpenForbiddenError,
    InsecureDefaultDetectedError,
    DuplicateResourceError,
    DuplicatePolicyRuleError,
    InvalidResourceConfigurationError
)


class TestSecureDefaultsFailSafe(unittest.TestCase):
    """Güvenli Varsayılanlar ve Fail-Safe motoru test takımı."""

    def setUp(self):
        """Her testten önce standart bir test ortamı kurar."""
        self.manager = FailSafeSecurityManager(
            system_name="Test Güvenlik Sistemi",
            failure_mode=FailureHandlingMode.FAIL_SECURE
        )
        # Standart güvenli bir kaynak kaydedilir
        self.secure_resource = ResourceConfig(
            resource_id="RES-SECURE-01",
            name="Güvenli Ödeme API",
            default_access="DENY",
            debug_mode=False,
            enforce_tls=True,
            is_default_credential_changed=True,
            cors_allow_all=False,
            storage_encrypted=True
        )
        self.manager.register_resource(self.secure_resource)

    def test_01_default_deny_when_no_rules_match(self):
        """Hiçbir açık izin kuralı eşleşmediğinde Saltzer-Schroeder Default-Deny kuralı işlemelidir."""
        req = AccessRequest(
            request_id="REQ-01",
            subject_id="user_alice",
            subject_role="intern",
            resource_id="RES-SECURE-01",
            action="write"
        )
        result = self.manager.evaluate_access(req)
        # Karar REDDEDİLDİ olmalıdır
        self.assertEqual(result.decision, DecisionOutcome.DENY)
        self.assertIn("Fail-Safe Defaults", result.reason)
        self.assertIsNone(result.matched_rule_id)

    def test_02_explicit_rule_permits_access(self):
        """Açıkça tanımlanmış bir kural eşleştiğinde erişim onaylanmalıdır."""
        rule = PolicyRule(
            rule_id="RULE-ADMIN-WRITE",
            subject_role="admin",
            resource_id="RES-SECURE-01",
            action="write",
            effect=DecisionOutcome.PERMIT
        )
        self.manager.add_policy_rule(rule)
        req = AccessRequest(
            request_id="REQ-02",
            subject_id="admin_bob",
            subject_role="admin",
            resource_id="RES-SECURE-01",
            action="write"
        )
        result = self.manager.evaluate_access(req)
        self.assertEqual(result.decision, DecisionOutcome.PERMIT)
        self.assertEqual(result.matched_rule_id, "RULE-ADMIN-WRITE")

    def test_03_unknown_resource_default_denied(self):
        """Sistemde tanımlı olmayan bir kaynağa erişim talebi güvenli varsayılanla reddedilmelidir."""
        req = AccessRequest(
            request_id="REQ-03",
            subject_id="user_charlie",
            subject_role="admin",
            resource_id="RES-NON-EXISTENT",
            action="read"
        )
        result = self.manager.evaluate_access(req)
        self.assertEqual(result.decision, DecisionOutcome.DENY)
        self.assertIn("tanımlı değil", result.reason)

    def test_04_cwe_1188_debug_mode_detection(self):
        """Debug modu açık bırakılmış kaynak CWE-1188 zaafiyeti olarak tespit edilmelidir."""
        bad_res = ResourceConfig(
            resource_id="RES-DEBUG",
            name="Geliştirme Sunucusu",
            debug_mode=True
        )
        issues = bad_res.validate_defaults()
        self.assertIn(SecurityDefaultIssue.DEBUG_MODE_ENABLED, issues)

    def test_05_cwe_1188_default_credentials_active_detection(self):
        """Varsayılan parola değiştirilmemiş kaynak CWE-1188 olarak bayraklanmalıdır."""
        bad_res = ResourceConfig(
            resource_id="RES-DEF-PWD",
            name="Fabrika Çıkışlı Firewall",
            is_default_credential_changed=False
        )
        issues = bad_res.validate_defaults()
        self.assertIn(SecurityDefaultIssue.DEFAULT_CREDENTIALS_ACTIVE, issues)

    def test_06_cwe_1188_permissive_cors_detection(self):
        """Herkese açık CORS (*) yapılandırması CWE-1188 olarak yakalanmalıdır."""
        bad_res = ResourceConfig(
            resource_id="RES-OPEN-CORS",
            name="Açık API",
            cors_allow_all=True
        )
        issues = bad_res.validate_defaults()
        self.assertIn(SecurityDefaultIssue.PERMISSIVE_CORS, issues)

    def test_07_cwe_1188_unencrypted_storage_detection(self):
        """Durağan depolaması şifresiz kaynak CWE-1188 olarak yakalanmalıdır."""
        bad_res = ResourceConfig(
            resource_id="RES-NO-ENC",
            name="Şifresiz DB",
            storage_encrypted=False
        )
        issues = bad_res.validate_defaults()
        self.assertIn(SecurityDefaultIssue.UNENCRYPTED_STORAGE, issues)

    def test_08_cwe_1188_default_permit_access_detection(self):
        """Varsayılan erişimi ALLOW (İzinli) yapılmış kaynak zaafiyet olarak işaretlenmelidir."""
        bad_res = ResourceConfig(
            resource_id="RES-DEF-ALLOW",
            name="Açık Kapı Servisi",
            default_access="ALLOW"
        )
        issues = bad_res.validate_defaults()
        self.assertIn(SecurityDefaultIssue.DEFAULT_PERMIT_ACCESS, issues)

    def test_09_enforce_secure_defaults_raises_insecure_default_detected(self):
        """Güvensiz varsayılana sahip kaynak varken enforce çağrıldığında InsecureDefaultDetectedError fırlatılmalıdır."""
        bad_res = ResourceConfig("RES-BAD", "Kötü Yapılandırma", debug_mode=True)
        self.manager.register_resource(bad_res)
        with self.assertRaises(InsecureDefaultDetectedError):
            self.manager.enforce_secure_defaults()

    def test_10_fail_secure_on_database_down(self):
        """Veritabanı arızalandığında Fail-Secure mekanizması erişimi reddetmelidir (CWE-636)."""
        # Normalde izinli bir kural eklenir
        rule = PolicyRule("R-OK", "admin", "RES-SECURE-01", "read", DecisionOutcome.PERMIT)
        self.manager.add_policy_rule(rule)
        req = AccessRequest("REQ-FAIL-1", "admin_bob", "admin", "RES-SECURE-01", "read")

        # Veritabanı kesintisi simüle edilir
        result = self.manager.evaluate_access(req, simulate_failure=FailureType.DATABASE_DOWN)
        self.assertEqual(result.decision, DecisionOutcome.DENY)
        self.assertTrue(result.is_fail_secure_intervention)
        self.assertEqual(result.failure_encountered, FailureType.DATABASE_DOWN)
        self.assertIn("Fail-Secure ilkesi gereğince", result.reason)

    def test_11_fail_secure_on_auth_service_timeout(self):
        """Kimlik servisi zaman aşımına uğradığında Fail-Secure devreye girmelidir."""
        req = AccessRequest("REQ-FAIL-2", "user_dan", "user", "RES-SECURE-01", "read")
        result = self.manager.evaluate_access(req, simulate_failure=FailureType.AUTH_SERVICE_TIMEOUT)
        self.assertEqual(result.decision, DecisionOutcome.DENY)
        self.assertTrue(result.is_fail_secure_intervention)

    def test_12_fail_secure_on_unhandled_exception(self):
        """Beklenmeyen kod istisnasında Fail-Secure kapıları kapatmalıdır."""
        req = AccessRequest("REQ-FAIL-3", "user_dan", "user", "RES-SECURE-01", "read")
        result = self.manager.evaluate_access(req, simulate_failure=FailureType.UNHANDLED_EXCEPTION)
        self.assertEqual(result.decision, DecisionOutcome.DENY)
        self.assertTrue(result.is_fail_secure_intervention)

    def test_13_cwe_636_unauthorized_fail_open_forbidden(self):
        """Yetkisiz FAIL_OPEN yapılandırmasında arıza simüle edilirse InsecureFailOpenForbiddenError fırlatılmalıdır."""
        mgr_open = FailSafeSecurityManager(
            system_name="Tehlikeli Açık Sistem",
            failure_mode=FailureHandlingMode.FAIL_OPEN,
            safety_override_token=None  # Token YOK!
        )
        mgr_open.register_resource(self.secure_resource)
        req = AccessRequest("REQ-FAIL-OPEN", "attacker", "anonymous", "RES-SECURE-01", "read")

        with self.assertRaises(InsecureFailOpenForbiddenError):
            mgr_open.evaluate_access(req, simulate_failure=FailureType.NETWORK_PARTITION)

    def test_14_authorized_safety_fail_open_emergency(self):
        """Geçerli can güvenliği acil durum token'ı varsa kontrollü Fail-Open çalışabilmelidir."""
        mgr_emergency = FailSafeSecurityManager(
            system_name="Yangın Tahliye Kapı Sistemi",
            failure_mode=FailureHandlingMode.FAIL_OPEN,
            safety_override_token="EMERGENCY_LIFE_SAFETY_OVERRIDE"
        )
        mgr_emergency.register_resource(self.secure_resource)
        req = AccessRequest("REQ-EMERGENCY", "civilian", "public", "RES-SECURE-01", "exit")

        result = mgr_emergency.evaluate_access(req, simulate_failure=FailureType.NETWORK_PARTITION)
        self.assertEqual(result.decision, DecisionOutcome.PERMIT)
        self.assertIn("Acil durum can güvenliği istisnası", result.reason)

    def test_15_resilient_secure_defaults_audit_and_report(self):
        """Tam uyumlu mimarinin denetimi ve Markdown rapor üretimi doğrulanır."""
        passed, violations = self.manager.audit_secure_defaults()
        self.assertTrue(passed)
        self.assertEqual(len(violations), 0)
        # enforce hata vermemelidir
        self.manager.enforce_secure_defaults()
        # Markdown raporu oluşturulur
        report = self.manager.generate_failsafe_report()
        self.assertIn("TAM UYUMLU", report)
        self.assertIn("RES-SECURE-01", report)
        self.assertIn("FAIL_SECURE", report)


if __name__ == "__main__":
    unittest.main()
