# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 119: Mini Proje 16 — Rol Tabanlı Erişim Simülatörü Birim Test Paketi.
15 Kapsamlı Test Senaryosu (NIST ANSI/INCITS 359-2004 Standartları).
"""

# Birim test çatısı için unittest kütüphanesi
import unittest
# Test edilecek modeller ve simülatör motorunun içe aktarılması
from uygulama.rbac_simulator_engine import (
    RBACSimulatorEngine,
    SimulationRequest,
    StaticSoDViolationError,
    DynamicSoDViolationError,
    RoleHierarchyCycleDetectedError,
    UnassignedRoleActivationError,
    PrivilegeCreepWarningError,
    SessionInvalidOrExpiredError
)


class TestEnterpriseRBACSimulator(unittest.TestCase):
    """Mini Proje 16: Kurumsal RBAC Simülatör ve Politika Doğrulama Testleri."""

    def setUp(self) -> None:
        """Her testten önce temiz bir simülasyon ortamı kurar."""
        # Azami rol eşiği 3 olan simülatör inşa edilir
        self.sim = RBACSimulatorEngine(max_roles_per_user=3)

        # Temel roller tanımlanır
        self.sim.define_role("admin", {"*:*"})
        self.sim.define_role("sec_officer", {"audit_log:read", "policy:write", "policy:read"})
        self.sim.define_role("finance_director", {"budget:approve", "financial_report:read", "financial_report:write"})
        self.sim.define_role("accountant", {"invoice:create", "invoice:read", "financial_report:read"})
        self.sim.define_role("cashier", {"payment:execute", "invoice:read"})
        self.sim.define_role("developer", {"repo:read", "repo:write", "ci_build:trigger"})
        self.sim.define_role("employee", {"profile:read", "public_wiki:read"})

        # Hiyerarşik miras grafı oluşturulur
        self.sim.add_hierarchy_edge("finance_director", "accountant")
        self.sim.add_hierarchy_edge("accountant", "employee")
        self.sim.add_hierarchy_edge("developer", "employee")

        # SoD Kuralları eklenir
        # SSD: Muhasebeci ile Kasiyer aynı kişiye verilemez
        self.sim.add_ssd_conflict("accountant", "cashier")
        # DSD: Güvenlik yetkilisi ile Geliştirici aynı oturumda açılamaz
        self.sim.add_dsd_conflict("sec_officer", "developer")

        # Örnek kullanıcılar kaydedilir
        self.sim.register_user("cfo_ali", "Ali Vural", "Finance")
        self.sim.assign_role_to_user("cfo_ali", "finance_director")

        self.sim.register_user("dev_can", "Can Demir", "IT")
        self.sim.assign_role_to_user("dev_can", "developer")

    def test_01_role_definition_and_direct_permission(self) -> None:
        """TEST 01: Doğrudan tanımlı rol izni simülasyonda başarıyla onaylanmalıdır."""
        req = SimulationRequest(
            request_id="REQ-01",
            user_id="dev_can",
            target_object="repo",
            action="read"
        )
        res = self.sim.evaluate_access(req)
        self.assertTrue(res.is_permitted)
        self.assertEqual(res.security_event, "ACCESS_PERMITTED")

    def test_02_hierarchical_inheritance_chain(self) -> None:
        """TEST 02: Hiyerarşik mirasta üst rol (finance_director) en alt rolün (employee) yetkisini almalıdır."""
        # finance_director -> accountant -> employee ('public_wiki:read')
        req = SimulationRequest(
            request_id="REQ-02",
            user_id="cfo_ali",
            target_object="public_wiki",
            action="read"
        )
        res = self.sim.evaluate_access(req)
        self.assertTrue(res.is_permitted)

    def test_03_wildcard_permission_match(self) -> None:
        """TEST 03: Wildcard (*:*) iznine sahip admin rolü her işlemi başarıyla yürütmelidir."""
        self.sim.register_user("root_usr", "Sistem Yöneticisi", "IT")
        self.sim.assign_role_to_user("root_usr", "admin")
        req = SimulationRequest(
            request_id="REQ-03",
            user_id="root_usr",
            target_object="quantum_core",
            action="reboot"
        )
        res = self.sim.evaluate_access(req)
        self.assertTrue(res.is_permitted)

    def test_04_permission_denied_cwe_862(self) -> None:
        """TEST 04: Yetkisi bulunmayan işlem ACCESS_DENIED_CWE_862 ile reddedilmelidir."""
        # Geliştirici bütçe onaylayamaz
        req = SimulationRequest(
            request_id="REQ-04",
            user_id="dev_can",
            target_object="budget",
            action="approve"
        )
        res = self.sim.evaluate_access(req)
        self.assertFalse(res.is_permitted)
        self.assertEqual(res.security_event, "ACCESS_DENIED_CWE_862")

    def test_05_static_sod_violation_prevention(self) -> None:
        """TEST 05: Statik SoD çakışması olan roller aynı kullanıcıya atanamaz (CWE-863)."""
        u = self.sim.register_user("staff_fraud", "Mehmet Fatura", "Finance")
        self.sim.assign_role_to_user("staff_fraud", "accountant")
        # Aynı kişiye cashier rolü atanamaz
        with self.assertRaises(StaticSoDViolationError):
            self.sim.assign_role_to_user("staff_fraud", "cashier")

    def test_06_dynamic_sod_violation_session(self) -> None:
        """TEST 06: Dinamik SoD çakışması olan roller aynı oturumda açılamaz (CWE-863)."""
        # Kullanıcı hem sec_officer hem developer rollerine sahip olsun (SSD yasağı yok, DSD var)
        u = self.sim.register_user("super_sec_dev", "Ece Güven", "SecOps")
        self.sim.assign_role_to_user("super_sec_dev", "sec_officer")
        self.sim.assign_role_to_user("super_sec_dev", "developer")

        # Aynı anda ikisini birden içeren oturum açılamaz
        with self.assertRaises(DynamicSoDViolationError):
            self.sim.create_session("super_sec_dev", roles_to_activate={"sec_officer", "developer"})

    def test_07_unassigned_role_activation_blocked(self) -> None:
        """TEST 07: Kullanıcı sahip olmadığı bir rolü oturumda etkinleştiremez (CWE-285)."""
        # dev_can kullanıcısı admin rolünü açmaya çalışır
        with self.assertRaises(UnassignedRoleActivationError):
            self.sim.create_session("dev_can", roles_to_activate={"admin"})

    def test_08_hierarchy_cycle_detection(self) -> None:
        """TEST 08: Hiyerarşik döngü oluşturan miras ilişkisi engellenmelidir (CWE-674)."""
        # employee -> finance_director bağı eklenmeye çalışılırsa döngü oluşur
        with self.assertRaises(RoleHierarchyCycleDetectedError):
            self.sim.add_hierarchy_edge("employee", "finance_director")

    def test_09_privilege_creep_threshold_exceeded(self) -> None:
        """TEST 09: Azami rol sayısını aşan yetki birikimi engellenmelidir (CWE-250)."""
        # max_roles_per_user = 3
        u = self.sim.register_user("greedy_user", "Açgözlü Kullanıcı", "General")
        self.sim.assign_role_to_user("greedy_user", "employee")
        self.sim.assign_role_to_user("greedy_user", "developer")
        self.sim.assign_role_to_user("greedy_user", "sec_officer")
        # 4. rol ataması eşik aşımı hatası vermelidir
        with self.assertRaises(PrivilegeCreepWarningError):
            self.sim.assign_role_to_user("greedy_user", "accountant")

    def test_10_role_revocation_effect(self) -> None:
        """TEST 10: Geri alınan rolün sağladığı izinler derhal hükümsüz kalmalıdır."""
        # dev_can'ın developer rolü geri alınır
        self.sim.revoke_role_from_user("dev_can", "developer")
        req = SimulationRequest(
            request_id="REQ-REVOKE",
            user_id="dev_can",
            target_object="repo",
            action="read"
        )
        res = self.sim.evaluate_access(req)
        self.assertFalse(res.is_permitted)

    def test_11_session_scoped_access_evaluation(self) -> None:
        """TEST 11: Oturum düzeyinde sadece seçilen rol aktifleşmeli, diğer roller kapsam dışı kalmalıdır."""
        u = self.sim.register_user("multi_user", "Çok Rolü Olan", "Cross")
        self.sim.assign_role_to_user("multi_user", "sec_officer")
        self.sim.assign_role_to_user("multi_user", "employee")

        # Yalnızca employee rolünün aktif olduğu bir oturum açılır
        session = self.sim.create_session("multi_user", roles_to_activate={"employee"})

        # employee yetkisi geçerli olmalıdır
        req1 = SimulationRequest("REQ-S1", "multi_user", "public_wiki", "read", session_id=session.session_id)
        self.assertTrue(self.sim.evaluate_access(req1).is_permitted)

        # sec_officer yetkisi bu oturumda reddedilmelidir (Least Privilege oturumu)
        req2 = SimulationRequest("REQ-S2", "multi_user", "policy", "write", session_id=session.session_id)
        self.assertFalse(self.sim.evaluate_access(req2).is_permitted)

    def test_12_invalid_session_id_rejection(self) -> None:
        """TEST 12: Geçersiz veya sahte oturum kimliği SessionInvalidOrExpiredError vermelidir (CWE-613)."""
        req = SimulationRequest("REQ-FAKE-SES", "cfo_ali", "budget", "approve", session_id="SES-FAKE-999")
        with self.assertRaises(SessionInvalidOrExpiredError):
            self.sim.evaluate_access(req)

    def test_13_batch_simulation_processing(self) -> None:
        """TEST 13: Toplu simülasyon paketi her bir istek için doğru karar üretmelidir."""
        reqs = [
            SimulationRequest("B-01", "cfo_ali", "budget", "approve"),
            SimulationRequest("B-02", "dev_can", "repo", "write"),
            SimulationRequest("B-03", "dev_can", "budget", "approve"),
        ]
        results = self.sim.run_batch_simulation(reqs)
        self.assertEqual(len(results), 3)
        self.assertTrue(results[0].is_permitted)
        self.assertTrue(results[1].is_permitted)
        self.assertFalse(results[2].is_permitted)

    def test_14_user_not_found_safety(self) -> None:
        """TEST 14: Tanımsız kullanıcı sorgusu çökmeksizin USER_NOT_FOUND dönmelidir."""
        req = SimulationRequest("REQ-NO-USER", "ghost_user", "anything", "read")
        res = self.sim.evaluate_access(req)
        self.assertFalse(res.is_permitted)
        self.assertEqual(res.security_event, "USER_NOT_FOUND")

    def test_15_audit_trail_and_export(self) -> None:
        """TEST 15: Simülatör tüm işlemleri denetim kütüğüne yazmalı ve JSON olarak dışa aktarabilmelidir."""
        audit_json = self.sim.export_audit_log_json()
        self.assertIn("ROLE_DEFINED", audit_json)
        self.assertIn("ROLE_ASSIGNED", audit_json)
        self.assertIn("cfo_ali", audit_json)


if __name__ == "__main__":
    unittest.main()
