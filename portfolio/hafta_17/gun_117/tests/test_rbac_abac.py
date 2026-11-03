# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 117: RBAC ve ABAC Erişim Kontrolü Birim Test Paketi.
15 Kapsamlı Test Senaryosu (NIST ANSI 359 & NIST SP 800-162 Standartları).
"""

# Birim test çerçevesi için standart unittest kütüphanesi
import unittest
# Zaman işlemleri için datetime kütüphanesi
import datetime
# Test edilecek modeller ve güvenlik motorlarının içe aktarılması
from uygulama.rbac_abac_engine import (
    RBACEngine,
    ABACPolicyEngine,
    HybridAccessManager,
    SubjectContext,
    ResourceContext,
    ActionContext,
    EnvironmentContext,
    RBACPermissionDeniedError,
    RBACSoDRuleConflictError,
    ABACPolicyDeniedError,
    EnvironmentalConstraintError,
    MultiTenantIsolationBreachError,
    ClassificationClearanceInsufficientError
)


class TestRBACandABACSecurity(unittest.TestCase):
    """RBAC, ABAC ve Hibrit Erişim Kontrol Güvenlik Testleri."""

    def setUp(self) -> None:
        """Her testten önce temiz ve standart bir erişim denetim ortamı kurar."""
        # 1. Temiz RBAC motoru oluşturulur
        self.rbac = RBACEngine()
        # Hiyerarşi kurulur: admin > manager > staff > user
        self.rbac.add_role_hierarchy("admin", {"manager", "auditor"})
        # Manager hiyerarşisi
        self.rbac.add_role_hierarchy("manager", {"staff"})
        # Staff hiyerarşisi
        self.rbac.add_role_hierarchy("staff", {"user"})

        # Rol izinleri atanır
        self.rbac.assign_permissions_to_role("admin", {"*:*"})
        # Auditor izinleri
        self.rbac.assign_permissions_to_role("auditor", {"audit_log:read", "financial_report:read", "compliance:read"})
        # Manager izinleri
        self.rbac.assign_permissions_to_role("manager", {"financial_report:read", "financial_report:write", "financial_ledger:write", "project_doc:delete"})
        # Staff izinleri
        self.rbac.assign_permissions_to_role("staff", {"project_doc:read", "project_doc:write"})
        # User izinleri
        self.rbac.assign_permissions_to_role("user", {"public_doc:read", "profile:read", "profile:write"})

        # SoD Kuralı: Satın alma başlatan (purchaser) ve onaylayan (approver) çatışır
        self.rbac.add_sod_conflict("purchaser", "approver")

        # 2. Temiz ABAC motoru oluşturulur (Kurumsal iç ağ: 10.0.0.0/8, 127.0.0.1)
        self.abac = ABACPolicyEngine(corporate_cidrs=["10.0.0.0/8", "127.0.0.1/32"])

        # 3. Hibrit yönetici oluşturulur
        self.manager = HybridAccessManager(self.rbac, self.abac)

        # Standart meşru çevre bağlamı (Mesai saatinde, kurumsal ağda, düşük risk)
        self.standard_env = EnvironmentContext(
            timestamp=datetime.datetime(2026, 11, 2, 10, 30),
            is_business_hours=True,
            is_corporate_network=True,
            risk_score=15
        )

    def test_01_rbac_direct_role_permission(self) -> None:
        """TEST 01: Doğrudan role sahip kullanıcının izni başarıyla onaylanmalıdır."""
        # Staff rolüne sahip kullanıcı nesnesi oluşturulur
        subject = SubjectContext(user_id="u1", roles={"staff"})
        # Değerlendirme icra edilir
        allowed, reason = self.rbac.evaluate(subject, resource_type="project_doc", action="read")
        # İzin verilmiş olmalıdır
        self.assertTrue(allowed)
        # Gerekçede izin belirtilmelidir
        self.assertIn("RBAC İzin Verildi", reason)

    def test_02_rbac_hierarchical_inheritance(self) -> None:
        """TEST 02: Hiyerarşik mirasta üst rol (manager), alt rolün (user) yetkilerini miras almalıdır."""
        # Sadece manager rolüne sahip kullanıcı oluşturulur
        subject = SubjectContext(user_id="u2", roles={"manager"})
        # Manager rolünün user iznine ('public_doc:read') erişimi test edilir
        allowed, reason = self.rbac.evaluate(subject, resource_type="public_doc", action="read")
        # Miras yoluyla izin verilmelidir
        self.assertTrue(allowed)

    def test_03_rbac_wildcard_permission(self) -> None:
        """TEST 03: Admin rolü wildcard (*:*) izni sayesinde her türlü işleme izin almalıdır."""
        # Admin kullanıcısı oluşturulur
        subject = SubjectContext(user_id="root", roles={"admin"})
        # Rastgele bilinmeyen bir kaynak ve eylem denenir
        allowed, _ = self.rbac.evaluate(subject, resource_type="nuclear_control", action="launch")
        # Wildcard ile izin verilmelidir
        self.assertTrue(allowed)

    def test_04_rbac_permission_denied(self) -> None:
        """TEST 04: Rolünde izin bulunmayan işlem RBACPermissionDeniedError üretmelidir (CWE-862)."""
        # Sıradan user kullanıcısı oluşturulur
        subject = SubjectContext(user_id="u3", roles={"user"})
        # Kaynak nesnesi oluşturulur
        resource = ResourceContext(resource_id="doc1", resource_type="financial_report", department_owner="finance")
        # Eylem tanımlanır
        action = ActionContext(name="write")
        # Hibrit yönetici çağrılır ve RBAC hatası beklenir
        with self.assertRaises(RBACPermissionDeniedError):
            self.manager.enforce_access(subject, resource, action, self.standard_env)

    def test_05_rbac_sod_conflict_detection(self) -> None:
        """TEST 05: Görevler Ayrılığı (SoD) çatışması yaşayan kullanıcı engellenmelidir (CWE-863)."""
        # Hem purchaser hem approver rolüne sahip kötü niyetli kullanıcı
        subject = SubjectContext(user_id="fraud_user", roles={"purchaser", "approver"})
        # Kaynak tanımlanır
        resource = ResourceContext(resource_id="po_99", resource_type="purchase_order", department_owner="finance")
        # Eylem tanımlanır
        action = ActionContext(name="approve")
        # SoD hatası fırlatılmalıdır
        with self.assertRaises(RBACSoDRuleConflictError):
            self.manager.enforce_access(subject, resource, action, self.standard_env)

    def test_06_abac_tenant_isolation_breach(self) -> None:
        """TEST 06: Farklı kiracıya ait kaynağa erişim MultiTenantIsolationBreachError vermelidir (CWE-284)."""
        # Tenant A kullanıcısı (admin olsa dahi!)
        subject = SubjectContext(user_id="admin_a", roles={"admin"}, tenant_id="tenant_alpha")
        # Tenant B'ye ait kaynak
        resource = ResourceContext(
            resource_id="res_beta",
            resource_type="customer_db",
            department_owner="it",
            tenant_id="tenant_beta"
        )
        action = ActionContext(name="read")
        # Çok kiracılı izolasyon ihlali fırlatılmalıdır
        with self.assertRaises(MultiTenantIsolationBreachError):
            self.manager.enforce_access(subject, resource, action, self.standard_env)

    def test_07_abac_classification_clearance_insufficient(self) -> None:
        """TEST 07: Gizlilik derecesi kullanıcının yetki derecesinden yüksekse engellenmelidir (CWE-285)."""
        # Clearance Seviye 1 olan manager
        subject = SubjectContext(user_id="mgr_low", roles={"manager"}, clearance_level=1, department="finance")
        # Classification Seviye 3 olan finans raporu
        resource = ResourceContext(
            resource_id="fin_secret",
            resource_type="financial_report",
            department_owner="finance",
            classification=3
        )
        action = ActionContext(name="read")
        # Yetersiz yetki seviyesi hatası fırlatılmalıdır
        with self.assertRaises(ClassificationClearanceInsufficientError):
            self.manager.enforce_access(subject, resource, action, self.standard_env)

    def test_08_abac_department_isolation_idor(self) -> None:
        """TEST 08: Başka departmana ait gizli belgeye erişim IDOR engeline takılmalıdır (CWE-639)."""
        # Finans personeli
        subject = SubjectContext(user_id="fin_staff", roles={"staff"}, department="finance", clearance_level=3)
        # İK (HR) departmanına ait gizli kaynak (classification=2)
        resource = ResourceContext(
            resource_id="hr_salaries",
            resource_type="project_doc",
            department_owner="hr",
            classification=2
        )
        action = ActionContext(name="read")
        # Departman izolasyon engeli beklenir
        with self.assertRaises(ABACPolicyDeniedError) as ctx:
            self.manager.enforce_access(subject, resource, action, self.standard_env)
        self.assertIn("Departman İzolasyon İhlali", str(ctx.exception))

    def test_09_abac_auditor_cross_department_exception(self) -> None:
        """TEST 09: Auditor rolü istisna olarak diğer departmanların gizli verilerini denetleyebilmelidir."""
        # Auditor kullanıcısı (departmanı audit)
        subject = SubjectContext(user_id="auditor_01", roles={"auditor"}, department="compliance", clearance_level=3)
        # Finans departmanına ait gizli rapor
        resource = ResourceContext(
            resource_id="fin_audit_target",
            resource_type="financial_report",
            department_owner="finance",
            classification=2
        )
        action = ActionContext(name="read")
        # Auditor istisnası devreye girip erişime izin vermelidir
        decision = self.manager.enforce_access(subject, resource, action, self.standard_env)
        self.assertTrue(decision.is_allowed)

    def test_10_abac_locked_resource_modification(self) -> None:
        """TEST 10: Arşivlenmiş/kilitli kaynağı değiştirme veya silme engellenmelidir (CWE-863)."""
        # Manager rolündeki yetkili personel
        subject = SubjectContext(user_id="mgr_01", roles={"manager"}, department="finance", clearance_level=2)
        # Kilitli kaynak
        resource = ResourceContext(
            resource_id="closed_q4_report",
            resource_type="financial_report",
            department_owner="finance",
            is_locked=True
        )
        action = ActionContext(name="write")
        # Kilitli kaynak koruması devreye girmelidir
        with self.assertRaises(ABACPolicyDeniedError) as ctx:
            self.manager.enforce_access(subject, resource, action, self.standard_env)
        self.assertIn("Kaynak Kilitli", str(ctx.exception))

    def test_11_abac_mfa_requirement_for_deletion(self) -> None:
        """TEST 11: Kritik silme (delete) işleminde MFA oturumu yoksa engellenmelidir (CWE-308)."""
        # Manager kullanıcısı (MFA doğrulaması yapmamış)
        subject = SubjectContext(user_id="mgr_nomfa", roles={"manager"}, department="finance", mfa_authenticated=False)
        resource = ResourceContext(resource_id="pdoc1", resource_type="project_doc", department_owner="finance")
        action = ActionContext(name="delete")
        # MFA eksikliği hatası fırlatılmalıdır
        with self.assertRaises(ABACPolicyDeniedError) as ctx:
            self.manager.enforce_access(subject, resource, action, self.standard_env)
        self.assertIn("MFA Doğrulaması Zorunlu", str(ctx.exception))

    def test_12_abac_mfa_requirement_success(self) -> None:
        """TEST 12: Kritik silme işleminde MFA doğrulanmışsa erişime izin verilmelidir."""
        # Manager kullanıcısı (MFA doğrulanmış)
        subject = SubjectContext(user_id="mgr_mfa_ok", roles={"manager"}, department="finance", mfa_authenticated=True)
        resource = ResourceContext(resource_id="pdoc1", resource_type="project_doc", department_owner="finance")
        action = ActionContext(name="delete")
        # İşlem onaylanmalıdır
        decision = self.manager.enforce_access(subject, resource, action, self.standard_env)
        self.assertTrue(decision.is_allowed)

    def test_13_abac_after_hours_financial_write(self) -> None:
        """TEST 13: Mesai saati dışında finansal kayıtlarda yazma engellenmelidir (CWE-284)."""
        # Finans yöneticisi
        subject = SubjectContext(user_id="cfo", roles={"manager"}, department="finance", clearance_level=3)
        resource = ResourceContext(resource_id="ledger_01", resource_type="financial_ledger", department_owner="finance")
        action = ActionContext(name="write")
        # Mesai saati dışı çevresel bağlam
        after_hours_env = EnvironmentContext(
            timestamp=datetime.datetime(2026, 11, 2, 23, 45),
            is_business_hours=False,
            is_corporate_network=True,
            risk_score=20
        )
        # Mesai kısıtlaması hatası fırlatılmalıdır
        with self.assertRaises(EnvironmentalConstraintError) as ctx:
            self.manager.enforce_access(subject, resource, action, after_hours_env)
        self.assertIn("Mesai Saati Kısıtlaması", str(ctx.exception))

    def test_14_abac_untrusted_ip_high_risk(self) -> None:
        """TEST 14: Dış/güvensiz ağdan gelen ve yüksek risk skoruna sahip istek engellenmelidir (CWE-284)."""
        # Kullanıcı dış IP'den geliyor
        subject = SubjectContext(
            user_id="remote_user",
            roles={"staff"},
            department="it",
            ip_address="203.0.113.88" # Dış internet IP'si
        )
        resource = ResourceContext(resource_id="asset1", resource_type="project_doc", department_owner="it")
        action = ActionContext(name="read")
        # Yüksek riskli çevresel bağlam
        high_risk_env = EnvironmentContext(
            timestamp=datetime.datetime(2026, 11, 2, 14, 0),
            is_business_hours=True,
            is_corporate_network=False,
            risk_score=75 # Yüksek risk
        )
        # Ağ ve risk engeli beklenir
        with self.assertRaises(EnvironmentalConstraintError) as ctx:
            self.manager.enforce_access(subject, resource, action, high_risk_env)
        self.assertIn("Ağ Güvenlik ve Risk Engeli", str(ctx.exception))

    def test_15_hybrid_full_pass_and_audit_log(self) -> None:
        """TEST 15: Tüm RBAC ve ABAC ilkelerini sağlayan istek izin almalı ve audit log üretmelidir."""
        # Meşru ve yetkili personel
        subject = SubjectContext(
            user_id="dev_lead",
            roles={"staff"},
            department="it",
            clearance_level=2,
            mfa_authenticated=True,
            ip_address="10.0.1.100"
        )
        resource = ResourceContext(
            resource_id="backend_repo",
            resource_type="project_doc",
            department_owner="it",
            classification=2
        )
        action = ActionContext(name="write")

        # İstek çalıştırılır
        decision = self.manager.enforce_access(subject, resource, action, self.standard_env)
        # Karar doğrulanır
        self.assertTrue(decision.is_allowed)
        self.assertEqual(decision.model_used, "HYBRID (RBAC + ABAC)")
        self.assertTrue(decision.audit_id.startswith("AUD-"))

        # Denetim loglarının bellekte biriktiği teyit edilir
        audit_json = self.manager.export_audit_logs_json()
        self.assertIn("AUD-", audit_json)
        self.assertIn("dev_lead", audit_json)
        self.assertIn("PERMITTED", audit_json)


if __name__ == "__main__":
    # Testler çalıştırılır
    unittest.main()
