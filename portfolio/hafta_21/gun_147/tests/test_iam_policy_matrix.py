"""
Gün 147: Mini Proje 20 — IAM Politika Matrisi Birim Testleri
============================================================
Bu test paketi; Katman İzolasyonunu (Tier 0-2), RBAC ve ABAC politikalarını,
Kerberos yetki devrini, SoD çatışmalarını ve yetim hesap korumalarını
15 kapsamlı test senaryosuyla %100 doğrular.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

import unittest
import sys
import os

# Uygulama modülünü arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

from iam_policy_matrix_engine import (
    IAMPolicyMatrixEngine,
    SubjectContext,
    ResourceTarget,
    TierLevel,
    DecisionType,
    DelegationType,
    Severity,
    SoDRule
)


class TestIAMPolicyMatrixEngine(unittest.TestCase):
    """IAM Politika Matrisi ve Karar Motoru Birim Test Sınıfı."""

    def setUp(self):
        """Her testten önce temiz bir motor ve standart kurumsal nesneler hazırlar."""
        self.engine = IAMPolicyMatrixEngine()

        # Standart SoD Kuralı: Fatura Oluşturan != Ödeme Onaylayan
        self.engine.register_sod_rule(SoDRule(
            rule_id="SOD-FIN-001",
            role_a="ROLE_FIN_INVOICE_CREATE",
            role_b="ROLE_FIN_PAYMENT_APPROVE",
            description="Fatura kesen personel kendi faturasının ödemesini onaylayamaz.",
            severity=Severity.CRITICAL
        ))

        # Standart Kaynaklar (Tier-0 DC, Tier-1 DB, Tier-2 Workstation)
        self.res_t0_dc = ResourceTarget(
            resource_id="RES-DC-01",
            name="DC01.kurum.local",
            target_tier=TierLevel.TIER_0,
            service_type="AD_DC",
            spn="ldap/dc01.kurum.local",
            delegation_type=DelegationType.RBCD,
            requires_mfa=True,
            allowed_roles=["ROLE_DOMAIN_ADMIN"]
        )
        self.res_t1_sql = ResourceTarget(
            resource_id="RES-SQL-01",
            name="SQL01.kurum.local",
            target_tier=TierLevel.TIER_1,
            service_type="SQL_DATABASE",
            spn="MSSQLSvc/sql01.kurum.local:1433",
            delegation_type=DelegationType.CONSTRAINED_S4U,
            requires_mfa=True,
            allowed_roles=["ROLE_DBA_ADMIN", "ROLE_APP_BACKEND"]
        )
        self.res_t2_pc = ResourceTarget(
            resource_id="RES-PC-01",
            name="WS-FIN-101.kurum.local",
            target_tier=TierLevel.TIER_2,
            service_type="WORKSTATION",
            delegation_type=DelegationType.NONE,
            requires_mfa=False,
            allowed_roles=["ROLE_FINANCE_USER"]
        )

        self.engine.register_resource(self.res_t0_dc)
        self.engine.register_resource(self.res_t1_sql)
        self.engine.register_resource(self.res_t2_pc)

    def test_01_clean_matrix_full_audit_pass(self):
        """1. Test: Kusursuz yapılandırılmış kurumsal matrisin 100 tam puan almasını doğrular."""
        sub_t0 = SubjectContext(
            user_id="USR-T0-01",
            username="admin.seydi",
            roles=["ROLE_DOMAIN_ADMIN"],
            tier_level=TierLevel.TIER_0,
            department="BT_GUVENLIK",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.0.50",
            is_trusted_network=True
        )
        sub_t2 = SubjectContext(
            user_id="USR-T2-01",
            username="ayse.muhasebe",
            roles=["ROLE_FINANCE_USER"],
            tier_level=TierLevel.TIER_2,
            department="FINANS",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.2.10",
            is_trusted_network=True
        )
        self.engine.register_subject(sub_t0)
        self.engine.register_subject(sub_t2)

        audit = self.engine.audit_entire_matrix()
        self.assertTrue(audit.is_compliant)
        self.assertEqual(audit.overall_security_score, 100.0)
        self.assertEqual(len(audit.findings), 0)

    def test_02_tier0_access_to_tier0_permit(self):
        """2. Test: Şartları sağlayan Tier-0 yöneticisinin Tier-0 DC'ye erişebilmesini (PERMIT) doğrular."""
        sub = SubjectContext(
            user_id="USR-ADM-01",
            username="da_admin",
            roles=["ROLE_DOMAIN_ADMIN"],
            tier_level=TierLevel.TIER_0,
            department="BILGI_ISLEM",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.0.10",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-ADM-01", "RES-DC-01")
        self.assertEqual(decision.decision, DecisionType.PERMIT)
        self.assertEqual(decision.matched_rule, "RULE-ZERO-TRUST-PERMIT")

    def test_03_tier0_downward_logon_denied(self):
        """3. Test: Tier-0 yöneticisinin alt katman (Tier-2) iş istasyonunda oturum açmasının engellenmesini doğrular."""
        sub = SubjectContext(
            user_id="USR-ADM-02",
            username="da_admin2",
            roles=["ROLE_DOMAIN_ADMIN"],
            tier_level=TierLevel.TIER_0,
            department="BILGI_ISLEM",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.2.100",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-ADM-02", "RES-PC-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-TIER0-DOWNWARD-LOGON-DENIED")
        self.assertIn("Tiering İhlali", decision.reason)

    def test_04_tier2_upward_access_to_tier0_denied(self):
        """4. Test: Standart Tier-2 kullanıcısının doğrudan Tier-0 DC'ye erişiminin engellenmesini doğrular."""
        sub = SubjectContext(
            user_id="USR-USER-01",
            username="standart_kullanici",
            roles=["ROLE_FINANCE_USER"],
            tier_level=TierLevel.TIER_2,
            department="FINANS",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.2.15",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-USER-01", "RES-DC-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-TIER2-UPWARD-ACCESS-DENIED")

    def test_05_rbac_role_mismatch_denied(self):
        """5. Test: Kaynağın izin verilen rolüne sahip olmayan kullanıcının engellenmesini (RBAC) doğrular."""
        sub = SubjectContext(
            user_id="USR-DEV-01",
            username="yazilimci_ali",
            roles=["ROLE_DEVELOPER"],
            tier_level=TierLevel.TIER_1,
            department="YAZILIM",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.1.20",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        # SQL veritabanı ROLE_DBA_ADMIN veya ROLE_APP_BACKEND bekliyor
        decision = self.engine.evaluate_access("USR-DEV-01", "RES-SQL-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-RBAC-ROLE-MISMATCH")

    def test_06_abac_missing_mfa_denied(self):
        """6. Test: MFA gerektiren kaynağa MFA doğrulaması olmadan erişimin engellenmesini (ABAC) doğrular."""
        sub = SubjectContext(
            user_id="USR-DBA-01",
            username="dba_can",
            roles=["ROLE_DBA_ADMIN"],
            tier_level=TierLevel.TIER_1,
            department="VERITABANI",
            is_employee_active=True,
            mfa_authenticated=False,  # Zafiyet: MFA yok
            device_compliant=True,
            source_ip="10.0.1.25",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-DBA-01", "RES-SQL-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-ABAC-MFA-REQUIRED")

    def test_07_abac_non_compliant_device_denied(self):
        """7. Test: Uyumsuz (güvensiz / yamalanmamış) cihaz üzerinden gelen erişimin engellenmesini doğrular."""
        sub = SubjectContext(
            user_id="USR-DBA-02",
            username="dba_ahmet",
            roles=["ROLE_DBA_ADMIN"],
            tier_level=TierLevel.TIER_1,
            department="VERITABANI",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=False,  # Cihaz uyumsuz
            source_ip="10.0.1.26",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-DBA-02", "RES-SQL-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-ABAC-DEVICE-NON-COMPLIANT")

    def test_08_abac_high_risk_session_denied(self):
        """8. Test: Yüksek riskli (imkansız seyahat / risk skoru >= 0.70) oturumların engellenmesini doğrular."""
        sub = SubjectContext(
            user_id="USR-DBA-03",
            username="dba_mehmet",
            roles=["ROLE_DBA_ADMIN"],
            tier_level=TierLevel.TIER_1,
            department="VERITABANI",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="185.220.101.5",
            is_trusted_network=False,
            risk_score=0.85  # Yüksek risk skoru
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-DBA-03", "RES-SQL-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-ABAC-HIGH-RISK-SESSION")

    def test_09_sod_toxic_combination_denied(self):
        """9. Test: SoD zehirli rol kombinasyonuna sahip kullanıcının erişiminin durdurulmasını doğrular."""
        # Hem fatura oluşturan hem ödeme onaylayan zehirli rolü taşıyan kullanıcı
        sub = SubjectContext(
            user_id="USR-FRAUD-01",
            username="kotu_muhasebeci",
            roles=["ROLE_FIN_INVOICE_CREATE", "ROLE_FIN_PAYMENT_APPROVE", "ROLE_FINANCE_USER"],
            tier_level=TierLevel.TIER_2,
            department="FINANS",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.2.30",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-FRAUD-01", "RES-PC-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-SOD-TOXIC-COMBINATION")

    def test_10_leaver_orphan_account_denied(self):
        """10. Test: İK ilişiği kesilmiş personelin hesabından yapılan erişimin engellenmesini doğrular."""
        sub = SubjectContext(
            user_id="USR-LEAVER-01",
            username="eski_calisan",
            roles=["ROLE_DOMAIN_ADMIN"],
            tier_level=TierLevel.TIER_0,
            department="BILGI_ISLEM",
            is_employee_active=False,  # İşten ayrılmış
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.0.12",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        decision = self.engine.evaluate_access("USR-LEAVER-01", "RES-DC-01")
        self.assertEqual(decision.decision, DecisionType.DENY)
        self.assertEqual(decision.matched_rule, "RULE-LEAVER-ORPHAN-BLOCKED")

    def test_11_unconstrained_delegation_audit_finding(self):
        """11. Test: Kısıtlamasız yetki devri kullanan sunucunun CRITICAL zafiyet olarak yakalanmasını doğrular."""
        bad_res = ResourceTarget(
            resource_id="RES-BAD-WEB",
            name="IIS-INSECURE.kurum.local",
            target_tier=TierLevel.TIER_1,
            service_type="WEB_PORTAL",
            spn="http/iis-insecure.kurum.local",
            delegation_type=DelegationType.UNCONSTRAINED  # Tehlikeli yetki devri!
        )
        self.engine.register_resource(bad_res)
        audit = self.engine.audit_entire_matrix()
        self.assertFalse(audit.is_compliant)
        self.assertEqual(audit.unconstrained_delegation_count, 1)
        finding_rules = [f.rule_id for f in audit.findings]
        self.assertIn("MAT-KERB-01", finding_rules)

    def test_12_orphan_account_audit_finding(self):
        """12. Test: İK ilişiği kesilmiş aktif hesapların denetimde CRITICAL olarak raporlanmasını doğrular."""
        sub = SubjectContext(
            user_id="USR-ORPHAN-99",
            username="unclosed_ghost_account",
            roles=["ROLE_FINANCE_USER"],
            tier_level=TierLevel.TIER_2,
            department="FINANS",
            is_employee_active=False,  # Yetim hesap
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.2.55",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        audit = self.engine.audit_entire_matrix()
        self.assertEqual(audit.orphan_accounts_count, 1)
        finding_rules = [f.rule_id for f in audit.findings]
        self.assertIn("MAT-JML-01", finding_rules)

    def test_13_overprivileged_tier2_user_audit_finding(self):
        """13. Test: Alt katmandaki kullanıcıya Tier-0 admin yetkisi verilmesinin HIGH zafiyet olarak yakalanmasını doğrular."""
        sub = SubjectContext(
            user_id="USR-OVERPRIV-01",
            username="stajyer_superadmin",
            roles=["ROLE_TIER0_SUPERADMIN", "ROLE_FINANCE_USER"],
            tier_level=TierLevel.TIER_2,  # Tier-2 ama Tier-0 yetkisi var!
            department="FINANS",
            is_employee_active=True,
            mfa_authenticated=True,
            device_compliant=True,
            source_ip="10.0.2.99",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        audit = self.engine.audit_entire_matrix()
        self.assertEqual(audit.overprivileged_subjects_count, 1)
        finding_rules = [f.rule_id for f in audit.findings]
        self.assertIn("MAT-PRIV-01", finding_rules)

    def test_14_tier0_without_mfa_audit_finding(self):
        """14. Test: Tier-0 yöneticisinin MFA'sız olmasının CRITICAL olarak yakalanmasını doğrular."""
        sub = SubjectContext(
            user_id="USR-T0-NO-MFA",
            username="da_without_mfa",
            roles=["ROLE_DOMAIN_ADMIN"],
            tier_level=TierLevel.TIER_0,
            department="BILGI_ISLEM",
            is_employee_active=True,
            mfa_authenticated=False,  # Tier-0 MFA yok!
            device_compliant=True,
            source_ip="10.0.0.8",
            is_trusted_network=True
        )
        self.engine.register_subject(sub)
        audit = self.engine.audit_entire_matrix()
        finding_rules = [f.rule_id for f in audit.findings]
        self.assertIn("MAT-TIER-01", finding_rules)

    def test_15_remediation_powershell_and_summary_json(self):
        """15. Test: PowerShell sertleştirme betiğinin ve matris özet JSON çıktısının geçerliliğini doğrular."""
        # Unconstrained delegation kaynağı ve yetim hesap ekle
        bad_res = ResourceTarget(
            resource_id="RES-TEST-UNCON",
            name="SRV-BAD.kurum.local",
            target_tier=TierLevel.TIER_1,
            service_type="WEB_PORTAL",
            delegation_type=DelegationType.UNCONSTRAINED
        )
        self.engine.register_resource(bad_res)

        audit = self.engine.audit_entire_matrix()
        ps1 = self.engine.generate_remediation_powershell(audit)
        self.assertIn("Set-ADComputer", ps1)
        self.assertIn("SRV-BAD.kurum.local", ps1)

        summary_json = self.engine.generate_matrix_summary_json()
        self.assertIn("katmanlar", summary_json)
        self.assertIn("TIER_0", summary_json["katmanlar"])
        self.assertIn("standartlar", summary_json)


if __name__ == "__main__":
    unittest.main()
