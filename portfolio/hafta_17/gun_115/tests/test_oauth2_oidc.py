# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 115: OAuth 2.0 ve OpenID Connect (OIDC) Kapsamlı Birim Testleri.

Bu test paketi, RFC 6749 Yetkilendirme Çerçevesi, RFC 7636 PKCE zorunluluğu,
CWE-601 Açık Yönlendirme (Open Redirector), CWE-352 CSRF (State Denetimi),
CWE-294 Kod/Nonce Tekrarı (Replay), CWE-287 Kimlik Doğrulama ve CWE-285 Kapsam (Scope)
denetimlerini 15 bağımsız test senaryosunda doğrular.
"""

# Birim test çatısı için unittest modülü içe aktarılır
import unittest
# Zaman ve tarih manipülasyonu için datetime, timezone ve timedelta içe aktarılır
from datetime import datetime, timezone, timedelta
# URL ayrıştırma için parse_qs ve urlparse içe aktarılır
from urllib.parse import urlparse, parse_qs
# Kriptografik güvenli rastgele dizgiler için secrets içe aktarılır
import secrets
# Dosya sistemi ve sistem yolu yönetimi için os ve sys içe aktarılır
import os
import sys

# Test edilen uygulamanın bulunduğu dizin Python arama yoluna eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# oauth2_oidc_engine modülünden gerekli sınıflar içe aktarılır
from oauth2_oidc_engine import (
    OAuth2AuthorizationServer,
    OAuth2ResourceServer,
    OIDCClientRelyingParty,
    PKCEHelper,
    JWTHelper,
    InvalidClientError,
    InvalidRedirectURIError,
    PKCEVerificationFailedError,
    AuthorizationCodeExpiredOrUsedError,
    StateMismatchCSRFError,
    OIDCNonceMismatchError,
    InsufficientScopeError,
    InvalidAccessTokenError,
    OAuthSecurityError
)


class TestOAuth2OIDCSecurityEngine(unittest.TestCase):
    """OAuth 2.0 ve OpenID Connect güvenlik kontrollerini sınayan test sınıfı."""

    def setUp(self):
        """Her testten önce izole IdP, Kaynak Sunucusu ve İstemci yapılandırır."""
        self.idp_secret = "TestGizliAnahtar2026!HS256"
        self.auth_server = OAuth2AuthorizationServer(
            issuer_url="https://idp.siber.local",
            token_secret=self.idp_secret
        )
        self.res_server = OAuth2ResourceServer(self.auth_server)
        self.client_id = "test_finans_app"
        self.client_secret = "GizliTestParolasi123!"
        self.valid_redirect_uri = "https://app.siber.local/auth/callback"

        # İstemci kaydı
        self.auth_server.register_client(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uris=[self.valid_redirect_uri],
            allowed_scopes=["openid", "profile", "read:profile", "read:reports"],
            client_type="confidential"
        )

        self.client_rp = OIDCClientRelyingParty(
            client_id=self.client_id,
            expected_issuer="https://idp.siber.local",
            idp_secret=self.idp_secret
        )

    def test_01_pkce_generation_and_verification(self):
        """Test 1: PKCE code_verifier ve S256 code_challenge üretim/doğrulama testi."""
        verifier = PKCEHelper.generate_code_verifier(64)
        self.assertEqual(len(verifier), 64)
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        self.assertTrue(len(challenge) > 20)
        # Doğru verifier ile doğrulama başarılı olmalı
        self.assertTrue(PKCEHelper.verify_pkce(verifier, challenge, "S256"))
        # Hatalı verifier ile doğrulama reddedilmeli
        self.assertFalse(PKCEHelper.verify_pkce("hatali_verifier_999", challenge, "S256"))

    def test_02_jwt_encode_and_decode_verification(self):
        """Test 2: HS256 JWT kodlama, çözme ve sahtecilik tespiti doğrulanır."""
        payload = {"sub": "user_123", "aud": self.client_id, "exp": 9999999999}
        token = JWTHelper.encode_jwt(payload, self.idp_secret)
        decoded = JWTHelper.decode_and_verify_jwt(token, self.idp_secret)
        self.assertEqual(decoded["sub"], "user_123")
        # Yanlış gizli anahtarla çözme denemesi hata fırlatmalıdır
        with self.assertRaises(OAuthSecurityError):
            JWTHelper.decode_and_verify_jwt(token, "YanlisSecretAnahtar!")

    def test_03_successful_authorization_code_issuance(self):
        """Test 3: Meşru parametrelerle /authorize uç noktasından yönlendirme ve kod alınması denetlenir."""
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        state = secrets.token_urlsafe(16)

        cb_url = self.auth_server.authorize_endpoint(
            client_id=self.client_id,
            redirect_uri=self.valid_redirect_uri,
            response_type="code",
            scope="openid profile",
            state=state,
            code_challenge=challenge,
            code_challenge_method="S256"
        )
        self.assertTrue(cb_url.startswith(self.valid_redirect_uri))
        parsed = urlparse(cb_url)
        qs = parse_qs(parsed.query)
        self.assertIn("code", qs)
        self.assertEqual(qs["state"][0], state)

    def test_04_open_redirector_prevention_cwe_601(self):
        """Test 4: Beyaz listede olmayan sahte redirect_uri sunulduğunda InvalidRedirectURIError (CWE-601) denetlenir."""
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        # Saldırganın kontrolündeki sahte yönlendirme adresi
        malicious_redirect = "https://phishing-attacker.com/steal-code"
        with self.assertRaises(InvalidRedirectURIError):
            self.auth_server.authorize_endpoint(
                client_id=self.client_id,
                redirect_uri=malicious_redirect,
                response_type="code",
                scope="openid",
                state="state123",
                code_challenge=challenge
            )

    def test_05_unknown_client_rejection_cwe_287(self):
        """Test 5: Kayıtlı olmayan bilinmeyen istemci kimliğinde InvalidClientError denetlenir."""
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        with self.assertRaises(InvalidClientError):
            self.auth_server.authorize_endpoint(
                client_id="bilinmeyen_sahte_istemci",
                redirect_uri=self.valid_redirect_uri,
                response_type="code",
                scope="openid",
                state="state123",
                code_challenge=challenge
            )

    def test_06_pkce_missing_challenge_rejection(self):
        """Test 6: PKCE code_challenge eksik veya S256 dışında bir yöntemle sunulduğunda red denetlenir."""
        with self.assertRaises(PKCEVerificationFailedError):
            self.auth_server.authorize_endpoint(
                client_id=self.client_id,
                redirect_uri=self.valid_redirect_uri,
                response_type="code",
                scope="openid",
                state="state123",
                code_challenge="",  # Eksik PKCE
                code_challenge_method="plain"
            )

    def test_07_successful_token_exchange_with_pkce(self):
        """Test 7: Geçerli kod ve doğru code_verifier ile access_token ve id_token takası denetlenir."""
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        cb_url = self.auth_server.authorize_endpoint(
            client_id=self.client_id,
            redirect_uri=self.valid_redirect_uri,
            response_type="code",
            scope="openid read:profile",
            state="state_xyz",
            code_challenge=challenge
        )
        auth_code = parse_qs(urlparse(cb_url).query)["code"][0]

        tokens = self.auth_server.token_endpoint(
            grant_type="authorization_code",
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=auth_code,
            redirect_uri=self.valid_redirect_uri,
            code_verifier=verifier
        )
        self.assertIn("access_token", tokens)
        self.assertIn("id_token", tokens)
        self.assertEqual(tokens["token_type"], "Bearer")

    def test_08_pkce_code_interception_attack_defense_cwe_287(self):
        """Test 8: Saldırgan authorization_code'u çalsa dahi code_verifier olmadan token alamaz (CWE-287)."""
        legit_verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(legit_verifier)
        cb_url = self.auth_server.authorize_endpoint(
            client_id=self.client_id,
            redirect_uri=self.valid_redirect_uri,
            response_type="code",
            scope="openid",
            state="state_xyz",
            code_challenge=challenge
        )
        stolen_code = parse_qs(urlparse(cb_url).query)["code"][0]

        # Saldırgan kendi uydurduğu sahte verifier ile takas yapmaya çalışıyor
        attacker_fake_verifier = PKCEHelper.generate_code_verifier()
        with self.assertRaises(PKCEVerificationFailedError):
            self.auth_server.token_endpoint(
                grant_type="authorization_code",
                client_id=self.client_id,
                client_secret=self.client_secret,
                code=stolen_code,
                redirect_uri=self.valid_redirect_uri,
                code_verifier=attacker_fake_verifier
            )

    def test_09_authorization_code_replay_prevention_cwe_294(self):
        """Test 9: Daha önce kullanılmış bir authorization_code'un tekrar sunulması (CWE-294) denetlenir."""
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        cb_url = self.auth_server.authorize_endpoint(
            client_id=self.client_id,
            redirect_uri=self.valid_redirect_uri,
            response_type="code",
            scope="openid",
            state="state_xyz",
            code_challenge=challenge
        )
        code = parse_qs(urlparse(cb_url).query)["code"][0]

        # 1. Takas Başarılı
        self.auth_server.token_endpoint(
            grant_type="authorization_code",
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self.valid_redirect_uri,
            code_verifier=verifier
        )

        # 2. Takas (Replay): Aynı kod tekrar denenir -> AuthorizationCodeExpiredOrUsedError fırlatılmalıdır
        with self.assertRaises(AuthorizationCodeExpiredOrUsedError):
            self.auth_server.token_endpoint(
                grant_type="authorization_code",
                client_id=self.client_id,
                client_secret=self.client_secret,
                code=code,
                redirect_uri=self.valid_redirect_uri,
                code_verifier=verifier
            )

    def test_10_authorization_code_expiration_rejection(self):
        """Test 10: 60 saniyelik geçerlilik süresi dolan kodun takasının reddedilmesi denetlenir."""
        now = datetime.now(timezone.utc)
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        cb_url = self.auth_server.authorize_endpoint(
            client_id=self.client_id,
            redirect_uri=self.valid_redirect_uri,
            response_type="code",
            scope="openid",
            state="state_xyz",
            code_challenge=challenge,
            now=now
        )
        code = parse_qs(urlparse(cb_url).query)["code"][0]

        # 65 saniye sonra takas denenir
        future = now + timedelta(seconds=65)
        with self.assertRaises(AuthorizationCodeExpiredOrUsedError):
            self.auth_server.token_endpoint(
                grant_type="authorization_code",
                client_id=self.client_id,
                client_secret=self.client_secret,
                code=code,
                redirect_uri=self.valid_redirect_uri,
                code_verifier=verifier,
                now=future
            )

    def test_11_client_secret_mismatch_rejection_cwe_287(self):
        """Test 11: Gizli istemcinin yanlış client_secret sunması durumunda InvalidClientError denetlenir."""
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        cb_url = self.auth_server.authorize_endpoint(
            client_id=self.client_id,
            redirect_uri=self.valid_redirect_uri,
            response_type="code",
            scope="openid",
            state="state_xyz",
            code_challenge=challenge
        )
        code = parse_qs(urlparse(cb_url).query)["code"][0]

        with self.assertRaises(InvalidClientError):
            self.auth_server.token_endpoint(
                grant_type="authorization_code",
                client_id=self.client_id,
                client_secret="HataliSecretParola999!",
                code=code,
                redirect_uri=self.valid_redirect_uri,
                code_verifier=verifier
            )

    def test_12_csrf_state_parameter_mismatch_defense_cwe_352(self):
        """Test 12: İstemciye dönen callback'te state uyuşmadığında StateMismatchCSRFError (CWE-352) denetlenir."""
        with self.assertRaises(StateMismatchCSRFError):
            self.client_rp.verify_callback_and_id_token(
                callback_state="saldirganin_enjekte_ettigi_sahte_state",
                original_state="istemcinin_urettigi_orijinal_state",
                id_token_jwt="jwt.placeholder.sig"
            )

    def test_13_oidc_nonce_replay_mismatch_defense_cwe_294(self):
        """Test 13: ID Token içindeki nonce istemcinin gönderdiği ile eşleşmediğinde OIDCNonceMismatchError denetlenir."""
        now = datetime.now(timezone.utc)
        payload = {
            "iss": "https://idp.siber.local",
            "sub": "seydi_user",
            "aud": self.client_id,
            "exp": int((now + timedelta(seconds=3600)).timestamp()),
            "iat": int(now.timestamp()),
            "nonce": "eski_veya_farkli_nonce"
        }
        id_jwt = JWTHelper.encode_jwt(payload, self.idp_secret)

        with self.assertRaises(OIDCNonceMismatchError):
            self.client_rp.verify_callback_and_id_token(
                callback_state="valid_state",
                original_state="valid_state",
                id_token_jwt=id_jwt,
                original_nonce="beklenen_yeni_nonce"
            )

    def test_14_scope_based_access_control_allowed_and_denied_cwe_285(self):
        """Test 14: Kapsam (Scope) tabanlı erişim kontrolünde yetkili ve yetkisiz kaynak erişimleri denetlenir."""
        verifier = PKCEHelper.generate_code_verifier()
        challenge = PKCEHelper.compute_code_challenge_s256(verifier)
        # Sadece 'read:profile' kapsamı talep ediliyor ('read:reports' yok)
        cb_url = self.auth_server.authorize_endpoint(
            client_id=self.client_id,
            redirect_uri=self.valid_redirect_uri,
            response_type="code",
            scope="openid read:profile",
            state="state123",
            code_challenge=challenge
        )
        code = parse_qs(urlparse(cb_url).query)["code"][0]
        tokens = self.auth_server.token_endpoint(
            grant_type="authorization_code",
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self.valid_redirect_uri,
            code_verifier=verifier
        )

        auth_hdr = f"Bearer {tokens['access_token']}"

        # 1. read:profile izni olan API başarılı olmalıdır
        res_profile = self.res_server.get_user_profile(auth_hdr)
        self.assertEqual(res_profile["durum"], "ONAYLANDI")

        # 2. read:reports gerektiren API InsufficientScopeError (CWE-285) ile reddedilmelidir
        with self.assertRaises(InsufficientScopeError):
            self.res_server.get_confidential_reports(auth_hdr)

    def test_15_invalid_or_expired_access_token_rejection_cwe_287(self):
        """Test 15: Sahte veya geçersiz erişim belirteci sunulduğunda InvalidAccessTokenError denetlenir."""
        with self.assertRaises(InvalidAccessTokenError):
            self.res_server.get_user_profile("Bearer sahte_ve_gecersiz_token_999")


if __name__ == "__main__":
    unittest.main()
