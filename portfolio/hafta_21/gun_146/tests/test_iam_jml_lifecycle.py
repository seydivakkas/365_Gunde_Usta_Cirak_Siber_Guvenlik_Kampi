"""
Gün 146: IAM JML Yaşam Döngüsü ve Güvenlik Motoru Birim Testleri
================================================================
Bu test modülü; Joiner, Mover, Leaver yaşam döngüsü adımlarını,
yetki birikimi (Privilege Creep), yetim hesap (Orphan Account),
görevler ayrılığı (SoD) ve atıl hesap (Dormant Account) kontrollerini
15 kapsamlı senaryo ile %100 doğrular.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

import unittest
import sys
import os
from datetime import datetime, timezone, timedelta

# Uygulama modülünü arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

from iam_jml_lifecycle_engine import (
    IAMJMLEngine,
    EmployeeRecord,
    AccountRecord,
    RoleDefinition,
    SoDConflictRule,
    LifecycleStatus,
    AccountStatus,
    Severity,
    JMLAuditResult
)


class TestIAMJMLLifecycle(unittest.TestCase):
    """IAM JML güvenlik motoru birim test sınıfı."""

    def setUp(self):
        """Her testten önce temiz ve izole bir motor ortamı hazırlar."""
        self.engine = IAMJMLEngine(dormant_threshold_days=90)
        self.now_utc = datetime.now(timezone.utc)

        # Standart rolleri kaydet
        self.role_it_admin = RoleDefinition(
            role_id="ROLE_IT_ADMIN",
            name="BT Sistem Yöneticisi",
            department="BILGI_ISLEM",
            allowed_entitlements=["AD_Domain_Admins", "Server_SSH_Root"],
            is_privileged=True
        )
        self.role_fin_creator = RoleDefinition(
            role_id="ROLE_FIN_INVOICE_CREATE",
            name="Fatura Giriş Yetkilisi",
            department="FINANS",
            allowed_entitlements=["SAP_Invoice_Create", "Bank_Draft_Entry"],
            is_privileged=False
        )
        self.role_fin_approver = RoleDefinition(
            role_id="ROLE_FIN_PAYMENT_APPROVE",
            name="Ödeme Onay Yetkilisi",
            department="FINANS",
            allowed_entitlements=["SAP_Payment_Approve", "Bank_Wire_Release"],
            is_privileged=True
        )
        self.role_hr_general = RoleDefinition(
            role_id="ROLE_HR_SPECIALIST",
            name="İK Uzmanı",
            department="INSAN_KAYNAKLARI",
            allowed_entitlements=["Workday_Employee_Read", "Workday_Employee_Edit"],
            is_privileged=False
        )

        self.engine.register_role(self.role_it_admin)
        self.engine.register_role(self.role_fin_creator)
        self.engine.register_role(self.role_fin_approver)
        self.engine.register_role(self.role_hr_general)

        # Standart SoD Kuralı: Fatura giren ile ödemeyi onaylayan AYNI KİŞİ OLAMAZ
        self.sod_rule = SoDConflictRule(
            conflict_id="SOD-FIN-001",
            role_a="ROLE_FIN_INVOICE_CREATE",
            role_b="ROLE_FIN_PAYMENT_APPROVE",
            description="Fatura oluşturan personel kendi faturasının ödemesini onaylayamaz (Dolandırıcılık Önleme).",
            severity=Severity.CRITICAL
        )
        self.engine.register_sod_rule(self.sod_rule)

    def test_01_clean_directory_audit_pass(self):
        """1. Test: Temiz ve kurallara tam uyumlu bir dizinin 100 tam puan almasını doğrular."""
        # 1 aktif çalışan ve bağlı 1 güvenli hesap ekle
        emp = EmployeeRecord(
            employee_id="EMP-100",
            name="Ali Yılmaz",
            department="BILGI_ISLEM",
            job_title="Sistem Mühendisi",
            manager_id="MGR-001",
            status=LifecycleStatus.ACTIVE,
            start_date="2026-01-10",
            assigned_roles=["ROLE_IT_ADMIN"]
        )
        self.engine.employees[emp.employee_id] = emp

        acc = AccountRecord(
            account_id="ACC-001",
            username="ali.yilmaz",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-100",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_IT_ADMIN"],
            entitlements=["AD_Domain_Admins"],
            last_logon_date=self.now_utc.isoformat(),
            mfa_enabled=True,
            password_must_change=False
        )
        self.engine.accounts[acc.account_id] = acc

        result = self.engine.audit_directory()
        self.assertTrue(result.is_compliant)
        self.assertEqual(result.security_score, 100.0)
        self.assertEqual(result.orphan_accounts_count, 0)
        self.assertEqual(result.privilege_creep_count, 0)
        self.assertEqual(result.sod_violations_count, 0)
        self.assertEqual(len(result.findings), 0)

    def test_02_joiner_success_with_mfa_and_pwd_reset(self):
        """2. Test: Joiner akışının MFA aktif ve parola değişimi zorunlu hesap açtığını doğrular."""
        new_emp = EmployeeRecord(
            employee_id="EMP-200",
            name="Zeynep Kaya",
            department="INSAN_KAYNAKLARI",
            job_title="İK Uzmanı",
            manager_id="MGR-002",
            status=LifecycleStatus.PENDING_ONBOARDING,
            start_date="2026-11-03"
        )
        res = self.engine.process_joiner(
            employee=new_emp,
            target_systems=["ActiveDirectory", "EntraID"],
            birthright_roles=["ROLE_HR_SPECIALIST"],
            approver="ik_muduru@kurum.local"
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(len(res["created_accounts"]), 2)

        # Oluşturulan hesapların güvenlik niteliklerini kontrol et
        for acc_id in res["created_accounts"]:
            acc = self.engine.accounts[acc_id]
            self.assertTrue(acc.mfa_enabled)
            self.assertTrue(acc.password_must_change)
            self.assertEqual(acc.status, AccountStatus.ACTIVE)

    def test_03_joiner_missing_approver_rejected(self):
        """3. Test: Onaylayıcı bilgisi bulunmayan Joiner talebinin reddedilmesini doğrular."""
        new_emp = EmployeeRecord(
            employee_id="EMP-201",
            name="Caner Demir",
            department="BILGI_ISLEM",
            job_title="Stajyer",
            manager_id="MGR-001",
            status=LifecycleStatus.PENDING_ONBOARDING,
            start_date="2026-11-03"
        )
        with self.assertRaises(ValueError):
            self.engine.process_joiner(
                employee=new_emp,
                target_systems=["ActiveDirectory"],
                birthright_roles=[],
                approver=""  # Geçersiz boş onaylayıcı
            )

    def test_04_joiner_sod_conflict_blocked(self):
        """4. Test: Başlangıç rolleri SoD çatışması içeren Joiner işleminin engellenmesini doğrular."""
        new_emp = EmployeeRecord(
            employee_id="EMP-202",
            name="Fatih Korkmaz",
            department="FINANS",
            job_title="Mali İşler Sorumlusu",
            manager_id="MGR-003",
            status=LifecycleStatus.PENDING_ONBOARDING,
            start_date="2026-11-03"
        )
        with self.assertRaises(PermissionError):
            self.engine.process_joiner(
                employee=new_emp,
                target_systems=["SAP"],
                birthright_roles=["ROLE_FIN_INVOICE_CREATE", "ROLE_FIN_PAYMENT_APPROVE"],
                approver="cfo@kurum.local"
            )

    def test_05_mover_clean_transfer_revokes_old_roles(self):
        """5. Test: Mover sürecinde eski departman rollerinin başarıyla iptal edildiğini doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-300",
            name="Mehmet Ak",
            department="FINANS",
            job_title="Fatura Uzmanı",
            manager_id="MGR-003",
            status=LifecycleStatus.ACTIVE,
            start_date="2025-01-01",
            assigned_roles=["ROLE_FIN_INVOICE_CREATE"]
        )
        self.engine.employees[emp.employee_id] = emp

        acc = AccountRecord(
            account_id="ACC-300",
            username="mehmet.ak",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-300",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_FIN_INVOICE_CREATE"],
            entitlements=["SAP_Invoice_Create"],
            last_logon_date=self.now_utc.isoformat(),
            mfa_enabled=True
        )
        self.engine.accounts[acc.account_id] = acc

        # Mehmet Bilgi İşlem departmanına geçiş yapıyor
        res = self.engine.process_mover(
            employee_id="EMP-300",
            new_department="BILGI_ISLEM",
            new_job_title="Sistem Yöneticisi",
            new_roles=["ROLE_IT_ADMIN"],
            revoke_old_roles=True,
            approver="hr_director@kurum.local"
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("ROLE_FIN_INVOICE_CREATE", res["revoked_roles"])
        self.assertEqual(emp.assigned_roles, ["ROLE_IT_ADMIN"])
        self.assertEqual(self.engine.accounts["ACC-300"].roles, ["ROLE_IT_ADMIN"])

    def test_06_mover_privilege_creep_detection(self):
        """6. Test: Eski rolleri silinmeyen personelde Yetki Birikiminin (Privilege Creep) yakalanmasını doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-301",
            name="Burak Kurt",
            department="FINANS",
            job_title="Finans Uzmanı",
            manager_id="MGR-003",
            status=LifecycleStatus.ACTIVE,
            start_date="2025-01-01",
            assigned_roles=["ROLE_FIN_INVOICE_CREATE"]
        )
        self.engine.employees[emp.employee_id] = emp

        acc = AccountRecord(
            account_id="ACC-301",
            username="burak.kurt",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-301",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_FIN_INVOICE_CREATE"],
            last_logon_date=self.now_utc.isoformat(),
            mfa_enabled=True
        )
        self.engine.accounts[acc.account_id] = acc

        # İK Departmanına geçiyor ama eski roller silinmiyor (Privilege Creep hatası)
        self.engine.process_mover(
            employee_id="EMP-301",
            new_department="INSAN_KAYNAKLARI",
            new_job_title="İK Sorumlusu",
            new_roles=["ROLE_HR_SPECIALIST"],
            revoke_old_roles=False,
            approver="manager@kurum.local"
        )

        result = self.engine.audit_directory()
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.privilege_creep_count, 1)
        finding_rules = [f.rule_id for f in result.findings]
        self.assertIn("JML-CREEP-01", finding_rules)

    def test_07_mover_sod_conflict_blocked(self):
        """7. Test: Mover sırasında personelin çatışan ikinci rolü almasının engellenmesini doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-302",
            name="Seda Aydın",
            department="FINANS",
            job_title="Giriş Yetkilisi",
            manager_id="MGR-003",
            status=LifecycleStatus.ACTIVE,
            start_date="2025-02-01",
            assigned_roles=["ROLE_FIN_INVOICE_CREATE"]
        )
        self.engine.employees[emp.employee_id] = emp

        # Eski rolü silmeden ödeme onay yetkisi alma girişimi (SoD ihlali)
        with self.assertRaises(PermissionError):
            self.engine.process_mover(
                employee_id="EMP-302",
                new_department="FINANS",
                new_job_title="Onay Yetkilisi",
                new_roles=["ROLE_FIN_PAYMENT_APPROVE"],
                revoke_old_roles=False,
                approver="cfo@kurum.local"
            )

    def test_08_mover_missing_approver_rejected(self):
        """8. Test: Onaylayıcı girilmeyen Mover talebinin hata fırlatmasını doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-303",
            name="Gizem Er",
            department="FINANS",
            job_title="Uzman",
            manager_id="MGR-003",
            status=LifecycleStatus.ACTIVE,
            start_date="2025-02-01",
            assigned_roles=["ROLE_FIN_INVOICE_CREATE"]
        )
        self.engine.employees[emp.employee_id] = emp

        with self.assertRaises(ValueError):
            self.engine.process_mover(
                employee_id="EMP-303",
                new_department="INSAN_KAYNAKLARI",
                new_job_title="İK Uzmanı",
                new_roles=["ROLE_HR_SPECIALIST"],
                approver=""
            )

    def test_09_leaver_deprovisions_all_accounts_immediately(self):
        """9. Test: Leaver sürecinde tüm bağlı hesapların anında kapatıldığını ve rollerin silindiğini doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-400",
            name="Hakan Çelik",
            department="BILGI_ISLEM",
            job_title="Ağ Yöneticisi",
            manager_id="MGR-001",
            status=LifecycleStatus.ACTIVE,
            start_date="2024-05-01",
            assigned_roles=["ROLE_IT_ADMIN"]
        )
        self.engine.employees[emp.employee_id] = emp

        acc1 = AccountRecord(
            account_id="ACC-400-AD",
            username="hakan.celik",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-400",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_IT_ADMIN"]
        )
        acc2 = AccountRecord(
            account_id="ACC-400-AWS",
            username="hakan.celik-aws",
            target_system="AWS",
            owner_employee_id="EMP-400",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_IT_ADMIN"]
        )
        self.engine.accounts[acc1.account_id] = acc1
        self.engine.accounts[acc2.account_id] = acc2

        # Leaver işlemini çalıştır
        res = self.engine.process_leaver(
            employee_id="EMP-400",
            termination_date="2026-11-03",
            immediate=True,
            approver="ik_direktoru@kurum.local"
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(emp.status, LifecycleStatus.TERMINATED)
        self.assertEqual(emp.assigned_roles, [])
        self.assertEqual(self.engine.accounts["ACC-400-AD"].status, AccountStatus.DISABLED)
        self.assertEqual(self.engine.accounts["ACC-400-AWS"].status, AccountStatus.DISABLED)

    def test_10_leaver_orphan_account_detected_if_not_deprovisioned(self):
        """10. Test: İK'dan ayrılmış ama hedef sistemde kapatılmamış Yetim Hesabın (Orphan Account) yakalanmasını doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-401",
            name="Eski Çalışan",
            department="FINANS",
            job_title="Eski Muhasebeci",
            manager_id="MGR-003",
            status=LifecycleStatus.TERMINATED,
            start_date="2023-01-01",
            end_date="2026-01-01",
            assigned_roles=[]
        )
        self.engine.employees[emp.employee_id] = emp

        # Ancak sistemde hesabı kapatılmayı unutulmuş ve AKTİF kalmış
        acc = AccountRecord(
            account_id="ACC-ORPHAN-01",
            username="eski.calisan",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-401",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_FIN_INVOICE_CREATE"],
            last_logon_date=self.now_utc.isoformat(),
            mfa_enabled=True
        )
        self.engine.accounts[acc.account_id] = acc

        result = self.engine.audit_directory()
        self.assertFalse(result.is_compliant)
        self.assertEqual(result.orphan_accounts_count, 1)
        finding_rules = [f.rule_id for f in result.findings]
        self.assertIn("JML-ORPHAN-02", finding_rules)

    def test_11_ghost_account_without_employee_detected(self):
        """11. Test: İK veri tabanında hiç kaydı olmayan sahipsiz hayalet hesabın yakalanmasını doğrular."""
        ghost_acc = AccountRecord(
            account_id="ACC-GHOST-99",
            username="unknown_shadow_admin",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-NON-EXISTENT",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_IT_ADMIN"],
            mfa_enabled=False
        )
        self.engine.accounts[ghost_acc.account_id] = ghost_acc

        result = self.engine.audit_directory()
        self.assertFalse(result.is_compliant)
        finding_rules = [f.rule_id for f in result.findings]
        self.assertIn("JML-ORPHAN-01", finding_rules)

    def test_12_dormant_account_detected(self):
        """12. Test: 90 günden uzun süredir oturum açılmamış atıl (dormant) hesabın tespitini doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-500",
            name="Derya Deniz",
            department="INSAN_KAYNAKLARI",
            job_title="İK Uzmanı",
            manager_id="MGR-002",
            status=LifecycleStatus.ACTIVE,
            start_date="2025-01-01",
            assigned_roles=["ROLE_HR_SPECIALIST"]
        )
        self.engine.employees[emp.employee_id] = emp

        # 120 gün önce oturum açmış
        old_date = (self.now_utc - timedelta(days=120)).isoformat()
        acc = AccountRecord(
            account_id="ACC-DORMANT-01",
            username="derya.deniz",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-500",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_HR_SPECIALIST"],
            last_logon_date=old_date,
            mfa_enabled=True
        )
        self.engine.accounts[acc.account_id] = acc

        result = self.engine.audit_directory()
        self.assertEqual(result.dormant_accounts_count, 1)
        finding_rules = [f.rule_id for f in result.findings]
        self.assertIn("JML-DORMANT-01", finding_rules)

    def test_13_privileged_account_without_mfa_flagged(self):
        """13. Test: Ayrıcalıklı role sahip ancak MFA aktif olmayan hesabın yakalanmasını doğrular."""
        emp = EmployeeRecord(
            employee_id="EMP-600",
            name="Serdar Taş",
            department="BILGI_ISLEM",
            job_title="Domain Admin",
            manager_id="MGR-001",
            status=LifecycleStatus.ACTIVE,
            start_date="2025-01-01",
            assigned_roles=["ROLE_IT_ADMIN"]
        )
        self.engine.employees[emp.employee_id] = emp

        acc = AccountRecord(
            account_id="ACC-NO-MFA",
            username="serdar.tas",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-600",
            status=AccountStatus.ACTIVE,
            roles=["ROLE_IT_ADMIN"],
            last_logon_date=self.now_utc.isoformat(),
            mfa_enabled=False  # Zafiyet: Ayrıcalıklı hesapta MFA yok!
        )
        self.engine.accounts[acc.account_id] = acc

        result = self.engine.audit_directory()
        finding_rules = [f.rule_id for f in result.findings]
        self.assertIn("JML-MFA-01", finding_rules)

    def test_14_remediation_powershell_generation(self):
        """14. Test: Yetim hesaplar için üretilen PowerShell betiğinin Disable-ADAccount komutu içerdiğini doğrular."""
        acc = AccountRecord(
            account_id="ACC-BAD-01",
            username="salih.yetim",
            target_system="ActiveDirectory",
            owner_employee_id="EMP-GHOST",
            status=AccountStatus.ACTIVE,
            roles=[]
        )
        self.engine.accounts[acc.account_id] = acc

        result = self.engine.audit_directory()
        ps1_script = self.engine.generate_remediation_powershell(result)
        self.assertIn("Disable-ADAccount", ps1_script)
        self.assertIn("Revoke-MgUserAllRefreshToken", ps1_script)
        self.assertIn("salih.yetim", ps1_script)

    def test_15_hardening_matrix_integrity(self):
        """15. Test: CIS, NIST ve ISO standartlarına referans veren sertleştirme matrisinin bütünlüğünü doğrular."""
        matrix = self.engine.generate_hardening_matrix()
        self.assertIn("standartlar", matrix)
        self.assertIn("kontrol_maddeleri", matrix)
        self.assertIn("NIST_SP_800_63B", matrix["standartlar"])
        self.assertIn("CIS_Controls_v8", matrix["standartlar"])
        self.assertIn("ISO_27001_A9", matrix["standartlar"])
        self.assertGreaterEqual(len(matrix["kontrol_maddeleri"]), 5)


if __name__ == "__main__":
    unittest.main()
