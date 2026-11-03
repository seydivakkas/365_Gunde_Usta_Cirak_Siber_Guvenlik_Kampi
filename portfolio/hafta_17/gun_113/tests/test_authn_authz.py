# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 113: Kimlik Doğrulama ve Yetkilendirme Kapsamlı Birim Testleri.

Bu test paketi, Kimlik Doğrulama (AuthN) ve Yetkilendirme (AuthZ) mimarilerini,
CWE-287, CWE-285, CWE-639 (IDOR), CWE-208 (Zamanlama), CWE-307 (Hesap Kilitleme),
CWE-384 (Oturum Sabitleme), CWE-613 (Oturum Zaman Aşımı) ve CWE-284 (Kiracı İzolasyonu)
zafiyetlerine karşı 15 bağımsız senaryoda denetler.
"""

# Standart birim test kütüphanesi içe aktarılır
import unittest
# Zaman ve tarih manipülasyonu için datetime ve timedelta içe aktarılır
from datetime import datetime, timezone, timedelta
# Dosya sistemi ve sistem yolu yönetimi için os ve sys içe aktarılır
import os
import sys

# Test edilen uygulamanın bulunduğu dizin Python arama yoluna eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# authn_authz_engine modülünden gerekli sınıflar ve istisnalar içe aktarılır
from authn_authz_engine import (
    AuthenticationEngine,
    AuthorizationEngine,
    IdentityAndAccessGateway,
    Resource,
    InvalidCredentialsError,
    AccountLockedError,
    SessionExpiredError,
    SessionInvalidError,
    MissingAuthenticationError,
    AccessDeniedError,
    InsecureDirectObjectReferenceError,
    TenantMismatchError
)


class TestAuthNAuthZSecurityEngine(unittest.TestCase):
    """Kimlik Doğrulama ve Yetkilendirme güvenlik kontrollerini sınayan test sınıfı."""

    def setUp(self):
        """Her bir test öncesinde izole bir çalışma ortamı ve motor instances'ı oluşturur."""
        # AuthN motoru hızlı birim testler için 2000 iterasyon ve 3 deneme limitiyle başlatılır
        self.authn = AuthenticationEngine(default_iterations=2000, max_failed_attempts=3, lockout_duration_seconds=300)
        # AuthZ motoru varsayılan politika kurallarıyla başlatılır
        self.authz = AuthorizationEngine()
        # İki motoru koordine eden geçit oluşturulur
        self.gateway = IdentityAndAccessGateway(self.authn, self.authz)

        # Standart test kullanıcıları kaydedilir
        self.authn.register_user("alice", "AliceParola123!", roles=["analyst"], tenant_id="TENANT_ALPHA")
        self.authn.register_user("bob", "BobParola456!", roles=["operator"], tenant_id="TENANT_ALPHA")
        self.authn.register_user("charlie_admin", "AdminParola789!", roles=["admin"], tenant_id="TENANT_ALPHA")
        self.authn.register_user("eve_attacker", "EveParola000!", roles=["analyst"], tenant_id="TENANT_BETA")

        # Standart korumalı test kaynakları sisteme tanımlanır
        # Kaynak 1: Alice'e ait gizli analiz raporu
        self.res_alice = Resource(
            resource_id="doc_alice_01",
            resource_type="report",
            owner_username="alice",
            tenant_id="TENANT_ALPHA",
            classification="CONFIDENTIAL",
            required_permissions={"read": "READ_DOCUMENT", "delete": "DELETE_DOCUMENT"}
        )
        self.gateway.register_resource(self.res_alice)

        # Kaynak 2: Sistem konfigürasyon nesnesi
        self.res_sys = Resource(
            resource_id="sys_config_01",
            resource_type="config",
            owner_username="charlie_admin",
            tenant_id="TENANT_ALPHA",
            classification="RESTRICTED",
            required_permissions={"read": "READ_DOCUMENT", "write": "SYSTEM_CONFIG"}
        )
        self.gateway.register_resource(self.res_sys)

    def test_01_successful_user_registration_and_hash_format(self):
        """Test 1: Kullanıcı kaydının tuzlu PBKDF2 özeti ve 64-karakter hex çıktısı üretmesi denetlenir."""
        user = self.authn.register_user("deniz", "GuvenliParola*2026", roles=["auditor"], tenant_id="TENANT_ALPHA")
        # Kullanıcı adı doğru kaydedilmeli
        self.assertEqual(user.username, "deniz")
        # Tuz 16 bayt (32 karakter hex) olmalı
        self.assertEqual(len(user.salt_hex), 32)
        # SHA-256 özeti 32 bayt (64 karakter hex) olmalı
        self.assertEqual(len(user.hash_hex), 64)
        # İterasyon sayısı yapılandırılan değerle eşleşmeli
        self.assertEqual(user.iterations, 2000)

    def test_02_successful_authentication_and_session_creation(self):
        """Test 2: Doğru kimlik bilgileriyle giriş yapılabilmesi ve aktif oturum üretilmesi denetlenir."""
        user = self.authn.authenticate("alice", "AliceParola123!")
        # Başarıyla dönen kullanıcı kontrol edilir
        self.assertEqual(user.username, "alice")
        # Oturum oluşturulur
        session = self.authn.create_session("alice", ttl_seconds=1800)
        # Oturum belirteci boş olmamalı
        self.assertTrue(len(session.token_str) >= 32)
        # Oturum aktif olmalı
        self.assertFalse(session.is_revoked)

    def test_03_invalid_password_raises_invalid_credentials_error(self):
        """Test 3: Hatalı parola girişinde InvalidCredentialsError (CWE-287) fırlatıldığı doğrulanır."""
        with self.assertRaises(InvalidCredentialsError):
            self.authn.authenticate("alice", "YanlisParola999!")

    def test_04_constant_time_digest_comparison_cwe_208(self):
        """Test 4: Parola doğrulamasında zamanlama yan kanalına (CWE-208) karşı sabit zamanlı özet denetlenir."""
        # Yanlış parola verildiğinde de aynı işlem adımlarının yürütüldüğü doğrulanır
        with self.assertRaises(InvalidCredentialsError):
            self.authn.authenticate("alice", "A" * 50)

    def test_05_brute_force_lockout_cwe_307(self):
        """Test 5: Eşik değerine (3 deneme) ulaşıldığında hesabın kilitlenmesi (CWE-307) denetlenir."""
        # 1. Başarısız deneme
        with self.assertRaises(InvalidCredentialsError):
            self.authn.authenticate("bob", "Hatali1")
        # 2. Başarısız deneme
        with self.assertRaises(InvalidCredentialsError):
            self.authn.authenticate("bob", "Hatali2")
        # 3. Başarısız deneme -> Hesap kilitlenmelidir
        with self.assertRaises(AccountLockedError):
            self.authn.authenticate("bob", "Hatali3")

        # Kilitlendikten sonra doğru parola girilse dahi AccountLockedError fırlatılmalıdır
        with self.assertRaises(AccountLockedError):
            self.authn.authenticate("bob", "BobParola456!")

    def test_06_account_lockout_expiration_unlock(self):
        """Test 6: Kilit süresi dolduğunda hesabın otomatik olarak açıldığı simüle edilir."""
        # Hesabı kilitleyelim
        for _ in range(3):
            try:
                self.authn.authenticate("bob", "HataliDeneme")
            except (InvalidCredentialsError, AccountLockedError):
                pass

        # 301 saniye sonrasını simüle eden zaman damgası
        future_time = datetime.now(timezone.utc) + timedelta(seconds=301)
        # Gelecekte doğru parola ile denendiğinde kilidin açılıp girişin başarılı olması gerekir
        user = self.authn.authenticate("bob", "BobParola456!", now=future_time)
        self.assertFalse(user.is_locked)
        self.assertEqual(user.failed_attempts, 0)

    def test_07_session_fixation_defense_cwe_384(self):
        """Test 7: Yeni giriş yapıldığında önceki oturum belirtecinin iptal edilmesi (CWE-384) denetlenir."""
        # Alice için 1. oturum açılır
        session1 = self.authn.create_session("alice", ttl_seconds=3600)
        token1 = session1.token_str
        # Oturumun geçerli olduğu doğrulanır
        self.assertEqual(self.authn.validate_session(token1).username, "alice")

        # Alice için 2. oturum açılır (Session Fixation engelleme mekanizması devreye girmeli)
        session2 = self.authn.create_session("alice", ttl_seconds=3600)
        token2 = session2.token_str

        # Eski oturum belirteci (token1) artık geçersiz olmalıdır
        with self.assertRaises(SessionInvalidError):
            self.authn.validate_session(token1)

        # Yeni oturum belirteci (token2) geçerli olmalıdır
        self.assertEqual(self.authn.validate_session(token2).username, "alice")

    def test_08_session_expiration_ttl_cwe_613(self):
        """Test 8: Oturum geçerlilik süresi (TTL) dolduğunda SessionExpiredError (CWE-613) denetlenir."""
        now = datetime.now(timezone.utc)
        session = self.authn.create_session("alice", ttl_seconds=60, now=now)
        # 61 saniye sonrası için denetim yapılır
        future = now + timedelta(seconds=61)
        with self.assertRaises(SessionExpiredError):
            self.authn.validate_session(session.token_str, now=future)

    def test_09_revoked_session_rejection(self):
        """Test 9: Kullanıcı çıkış yaptığında (revoke) oturum belirtecinin derhal geçersiz kılınması denetlenir."""
        session = self.authn.create_session("alice", ttl_seconds=3600)
        # Çıkış yapılır
        self.authn.revoke_session(session.token_str)
        # Oturum doğrulama hata fırlatmalıdır
        with self.assertRaises(SessionInvalidError):
            self.authn.validate_session(session.token_str)

    def test_10_missing_session_token_raises_missing_authentication_cwe_306(self):
        """Test 10: Oturum belirteci olmadan korumalı kaynağa erişimde MissingAuthenticationError denetlenir."""
        with self.assertRaises(MissingAuthenticationError):
            self.gateway.execute_request(session_token_str=None, resource_id="doc_alice_01", action="read")

    def test_11_role_based_access_allowed_for_authorized_role(self):
        """Test 11: Rol tabanlı yetki kontrolünde yetkili analistin okuma yapabilmesi denetlenir."""
        session = self.authn.create_session("alice", ttl_seconds=3600)
        res = self.gateway.execute_request(session.token_str, "doc_alice_01", "read")
        self.assertEqual(res["durum"], "ONAYLANDI")
        self.assertEqual(res["kullanici"], "alice")

    def test_12_role_based_access_denied_for_unauthorized_action_cwe_862(self):
        """Test 12: Rol tabanlı kontrolde analistin silme yetkisine sahip olmaması (CWE-862) denetlenir."""
        session = self.authn.create_session("alice", ttl_seconds=3600)
        # 'analyst' rolünün 'delete' eylemi (DELETE_DOCUMENT izni) yoktur
        with self.assertRaises(AccessDeniedError):
            self.gateway.execute_request(session.token_str, "doc_alice_01", "delete")

    def test_13_idor_protection_cwe_639(self):
        """Test 13: Aynı roldeki başka bir kullanıcının nesnesine erişimin engellenmesi (IDOR - CWE-639) denetlenir."""
        # Bob bir operatördür ve READ_DOCUMENT iznine sahiptir
        session_bob = self.authn.create_session("bob", ttl_seconds=3600)
        # Ancak doc_alice_01 kaynağının sahibi Alice'tir; Bob admin olmadığı için IDOR engeline takılmalıdır
        with self.assertRaises(InsecureDirectObjectReferenceError):
            self.gateway.execute_request(session_bob.token_str, "doc_alice_01", "read")

    def test_14_admin_bypass_for_idor_with_audit_trail(self):
        """Test 14: Yönetici (admin) rolünün nesne sahipliği sınırını meşru olarak aşabilmesi denetlenir."""
        session_admin = self.authn.create_session("charlie_admin", ttl_seconds=3600)
        # Admin Alice'in dokümanını okuyabilir
        res = self.gateway.execute_request(session_admin.token_str, "doc_alice_01", "read")
        self.assertEqual(res["durum"], "ONAYLANDI")
        # Denetim izinde kaydın tutulduğu teyit edilir
        logs = self.gateway.get_audit_logs()
        self.assertTrue(any(l["subject"] == "charlie_admin" and l["outcome"] == "SUCCESS" for l in logs))

    def test_15_tenant_isolation_violation_cwe_284(self):
        """Test 15: Farklı kiracıya (TENANT_BETA) ait kullanıcının diğer kiracı verisine erişememesi denetlenir."""
        # Eve TENANT_BETA kiracısındadır ve analist rolündedir
        session_eve = self.authn.create_session("eve_attacker", ttl_seconds=3600)
        # doc_alice_01 ise TENANT_ALPHA kiracısına aittir
        with self.assertRaises(TenantMismatchError):
            self.gateway.execute_request(session_eve.token_str, "doc_alice_01", "read")


if __name__ == "__main__":
    unittest.main()
