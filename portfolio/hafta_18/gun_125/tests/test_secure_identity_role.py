# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 125: Mini Proje 17 — Güvenli Kimlik ve Rol Prototipi Birim Testleri.
15 birim test senaryosu: PBKDF2 parola doğrulaması, kaba kuvvet hesap kilitleme,
oturum süre aşımı (CWE-613), statik SoD çatışmaları (CWE-863), hiyerarşik RBAC kalıtımı,
Default-Deny, Step-Up MFA (CWE-308), Fail-Secure arıza kalkanı (CWE-636) ve CWE-532 log maskeleme.
"""

# Standart unittest çerçevesi içe aktarılıyor
import unittest
# Sistem yolu ve dosya manipülasyonu için sys ve os içe aktarılıyor
import sys
import os
# Süre hesaplamaları için datetime ve timedelta içe aktarılıyor
from datetime import datetime, timedelta

# Uygulama modülünü arama yoluna dahil etmek için dizin ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
sys.path.insert(0, app_dir)

# Test edilecek motor sınıfları ve istisnalar içe aktarılıyor
from secure_identity_role_engine import (
    SecureIdentityRoleManager,
    SystemFailureType,
    AuthenticationFailedError,
    StepUpMFARequiredError,
    SeparationOfDutyConflictError,
    SessionExpiredError,
    DuplicateEntityError
)


class TestSecureIdentityRoleEngine(unittest.TestCase):
    """Mini Proje 17: Güvenli Kimlik ve Rol Yönetim Motoru test sınıfı."""

    def setUp(self):
        """Her testten önce standart bir test ortamı kurar."""
        self.mgr = SecureIdentityRoleManager(system_name="Test Kimlik Platformu")

        # 1. Rol Hiyerarşisi Kurulumu
        # 'guest' -> 'employee' -> 'manager' -> 'super_admin'
        self.mgr.register_role("guest", permissions={"public:read"})
        self.mgr.register_role("employee", permissions={"profile:read", "profile:edit"}, parent_roles=["guest"])
        self.mgr.register_role("manager", permissions={"team:review", "budget:approve"}, parent_roles=["employee"])
        self.mgr.register_role("super_admin", permissions={"system:*"}, parent_roles=["manager"], requires_mfa=True)

        # 2. Finans ve Denetim Rolleri (SoD testi için)
        self.mgr.register_role("payment_maker", permissions={"ledger:create"})
        self.mgr.register_role("payment_checker", permissions={"ledger:approve"})
        self.mgr.add_toxic_role_pair("payment_maker", "payment_checker")

        # 3. Test Kullanıcıları
        self.mgr.register_user(
            user_id="U-100",
            username="alice",
            password="AliceStrongPassword2026!#",
            roles=["employee"],
            department="Engineering"
        )
        self.mgr.register_user(
            user_id="U-200",
            username="bob_admin",
            password="BobAdminPassword2026!#",
            roles=["super_admin"],
            department="Security",
            mfa_secret="123456"
        )

    def test_01_user_authentication_success_pbkdf2(self):
        """Doğru parola ile PBKDF2 doğrulaması başarılı olmalı ve geçerli bir AuthToken dönmelidir."""
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        self.assertIsNotNone(token)
        self.assertEqual(token.user_id, "U-100")
        self.assertIn("employee", token.roles)
        self.assertFalse(token.mfa_verified)
        self.assertIn(token.token_id, self.mgr.active_tokens)

    def test_02_authentication_failure_invalid_password(self):
        """Hatalı parola girildiğinde AuthenticationFailedError fırlatılmalıdır (CWE-287)."""
        with self.assertRaises(AuthenticationFailedError):
            self.mgr.authenticate("alice", "WrongPassword123!")

    def test_03_account_lockout_after_multiple_failures(self):
        """5 kez üst üste hatalı parola girildiğinde hesap güvenlik amacıyla kilitlenmelidir."""
        for _ in range(5):
            try:
                self.mgr.authenticate("alice", "WrongPassword123!")
            except AuthenticationFailedError:
                pass

        user = self.mgr.users["U-100"]
        self.assertTrue(user.is_locked)
        # Kilitlendikten sonra doğru parola girilse bile reddedilmelidir
        with self.assertRaises(AuthenticationFailedError):
            self.mgr.authenticate("alice", "AliceStrongPassword2026!#")

    def test_04_session_ttl_expiration(self):
        """Oturum süresi (TTL) dolduğunda erişim talebi DENY ile reddedilmelidir (CWE-613)."""
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        # Süresi geçmişe alınır
        token.expires_at = datetime.now() - timedelta(seconds=1)
        res = self.mgr.authorize(token.token_id, "profile", "read")
        self.assertEqual(res.decision, "DENY")
        self.assertIn("Oturum süresi (TTL) sona ermiştir", res.reason)

    def test_05_static_sod_conflict_rejected_on_registration(self):
        """Aynı kullanıcıya çatışan iki rol (maker + checker) atanmaya çalışıldığında SeparationOfDutyConflictError fırlatılmalıdır (CWE-863)."""
        with self.assertRaises(SeparationOfDutyConflictError):
            self.mgr.register_user(
                user_id="U-BAD-SOD",
                username="hacker_sod",
                password="Password123!",
                roles=["payment_maker", "payment_checker"]
            )

    def test_06_hierarchical_rbac_direct_permission(self):
        """Kullanıcının doğrudan rolündeki izin başarıyla onaylanmalıdır."""
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        res = self.mgr.authorize(token.token_id, "profile", "read")
        self.assertEqual(res.decision, "PERMIT")
        self.assertEqual(res.matched_permission, "profile:read")

    def test_07_hierarchical_rbac_inherited_permission(self):
        """Üst rollerden miras alınan izinler hiyerarşik olarak çözümlenmelidir."""
        # 'employee' rolü 'guest' rolündeki 'public:read' iznini miras alır
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        res = self.mgr.authorize(token.token_id, "public", "read")
        self.assertEqual(res.decision, "PERMIT")
        self.assertEqual(res.matched_permission, "public:read")

    def test_08_saltzer_schroeder_default_deny(self):
        """Tanımlı olmayan veya yetki dışı bir istek Saltzer-Schroeder Default-Deny ile reddedilmelidir."""
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        # Alice manager veya admin iznine sahip değildir
        res = self.mgr.authorize(token.token_id, "budget", "approve")
        self.assertEqual(res.decision, "DENY")
        self.assertIn("Fail-Safe Defaults", res.reason)

    def test_09_step_up_mfa_blocks_unverified_critical_access(self):
        """MFA zorunlu bir rolde oturum MFA ile doğrulanmamışsa erişim bloke edilmelidir (CWE-308)."""
        token = self.mgr.authenticate("bob_admin", "BobAdminPassword2026!#")
        # super_admin rolü requires_mfa=True gerektirir
        res = self.mgr.authorize(token.token_id, "system", "reboot")
        self.assertEqual(res.decision, "DENY")
        self.assertIn("MFA", res.reason)
        self.assertIn("CWE-308", res.reason)

    def test_10_step_up_mfa_success_permits_critical_access(self):
        """Step-Up MFA kodu doğrulandıktan sonra kritik erişime izin verilmelidir."""
        token = self.mgr.authenticate("bob_admin", "BobAdminPassword2026!#")
        # MFA doğrulanır
        self.mgr.verify_mfa(token.token_id, "123456")
        self.assertTrue(token.mfa_verified)
        res = self.mgr.authorize(token.token_id, "system", "reboot")
        self.assertEqual(res.decision, "PERMIT")

    def test_11_fail_secure_on_identity_store_timeout(self):
        """Kimlik servisi zaman aşımına uğradığında Fail-Secure mekanizması yetkiyi kesmelidir (CWE-636)."""
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        res = self.mgr.authorize(
            token.token_id, "profile", "read",
            simulate_failure=SystemFailureType.IDENTITY_STORE_TIMEOUT
        )
        self.assertEqual(res.decision, "DENY")
        self.assertTrue(res.is_fail_secure_intervention)
        self.assertIn("Fail-Secure ilkesi gereğince", res.reason)

    def test_12_fail_secure_on_database_unavailable(self):
        """Veritabanı çöktüğünde Fail-Secure kapıları kilitlemelidir."""
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        res = self.mgr.authorize(
            token.token_id, "profile", "read",
            simulate_failure=SystemFailureType.DATABASE_UNAVAILABLE
        )
        self.assertEqual(res.decision, "DENY")
        self.assertTrue(res.is_fail_secure_intervention)

    def test_13_fail_secure_on_mfa_provider_down(self):
        """MFA sağlayıcısı yanıt vermediğinde fail-open olmak yerine fail-secure devreye girmelidir."""
        token = self.mgr.authenticate("bob_admin", "BobAdminPassword2026!#")
        res = self.mgr.authorize(
            token.token_id, "system", "backup",
            simulate_failure=SystemFailureType.MFA_PROVIDER_DOWN
        )
        self.assertEqual(res.decision, "DENY")
        self.assertTrue(res.is_fail_secure_intervention)

    def test_14_log_masking_redacts_passwords_and_tokens(self):
        """Log maskeleyici kullanıcının düz metin parolasını ve aktif token'ını sansürlemelidir (CWE-532)."""
        token = self.mgr.authenticate("alice", "AliceStrongPassword2026!#")
        raw_log = f"Giriş yapıldı: parola=AliceStrongPassword2026!# ve token={token.token_id}"
        masked = self.mgr.mask_log_message(raw_log)
        self.assertNotIn("AliceStrongPassword2026!#", masked)
        self.assertNotIn(token.token_id, masked)
        self.assertIn("[REDACTED_SENSITIVE_DATA]", masked)

    def test_15_capstone_full_report_and_summary_export(self):
        """Mini Proje 17 bitirme raporu ve JSON özet çıktısı eksiksiz üretilmelidir."""
        report = self.mgr.generate_capstone_report()
        self.assertIn("# Test Kimlik Platformu", report)
        self.assertIn("super_admin", report)
        self.assertIn("payment_maker", report)
        self.assertIn("CWE-636", report)

        summary = self.mgr.export_summary_dict()
        self.assertEqual(summary["roles_count"], 6)
        self.assertEqual(summary["users_count"], 2)


if __name__ == "__main__":
    unittest.main()
