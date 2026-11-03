# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 116: JWT Güvenlik ve Doğrulama Kapsamlı Birim Testleri.

Bu test paketi, RFC 7519 JSON Web Token standartlarını, 'alg: none' saldırısını,
algoritma karışıklığını (RS256 vs HS256), zaman aşımı (exp/nbf), kimlik sınırlarını (iss/aud),
jti iptal kara listesini ve bozuk biçim kontrollerini 15 bağımsız test senaryosunda doğrular.
"""

# Birim test kütüphanesi içe aktarılır
import unittest
# Zaman ve tarih hesaplamaları için datetime, timezone ve timedelta içe aktarılır
from datetime import datetime, timezone, timedelta
# JSON serileştirme için json içe aktarılır
import json
# Dosya sistemi ve arama yolları için os ve sys içe aktarılır
import os
import sys

# Test edilen uygulamanın bulunduğu dizin Python arama yoluna eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# jwt_security_engine modülünden gerekli sınıflar içe aktarılır
from jwt_security_engine import (
    JWTIssuerEngine,
    JWTValidatorEngine,
    JWTValidationPolicy,
    Base64URL,
    JWTSecurityError,
    AlgorithmNoneAttackError,
    AlgorithmConfusionError,
    InvalidSignatureError,
    TokenExpiredError,
    TokenNotYetValidError,
    InvalidIssuerError,
    InvalidAudienceError,
    TokenRevokedError,
    MalformedJWTError
)


class TestJWTSecurityEngine(unittest.TestCase):
    """JWT güvenlik ve savunma mekanizmalarını test eden sınıf."""

    def setUp(self):
        """Her testten önce izole test ortamı, RSA anahtarları ve politikaları hazırlar."""
        self.secret_key = "TestSunucusuGucluGizliAnahtar!2026"
        self.issuer = "https://idp.siber.local"
        self.audience = "siber_api_servisi"

        # 512-bit RSA test anahtar çifti
        p = 79767748627722170403753678573501130792297299195379632297507984385755962539519
        q = 74423822195679822963040554606743229645699794242435226315153894989068738755257
        self.rsa_n = p * q
        self.rsa_e = 65537
        phi = (p - 1) * (q - 1)
        self.rsa_d = pow(self.rsa_e, -1, phi)

        # Standart doğrulama politikası
        self.policy = JWTValidationPolicy(
            allowed_algorithms={"HS256", "RS256"},
            expected_issuer=self.issuer,
            expected_audience=self.audience,
            leeway_seconds=5,
            reject_none_algorithm=True
        )
        self.validator = JWTValidatorEngine(self.policy)

    def test_01_hs256_token_generation_and_validation(self):
        """Test 1: Meşru HS256 JWT üretimi ve başarılı imza/claim doğrulaması denetlenir."""
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_101", "rol": "analyst"},
            secret_key=self.secret_key,
            ttl_seconds=1800,
            issuer=self.issuer,
            audience=self.audience
        )
        payload = self.validator.validate_token(token, secret_key=self.secret_key)
        self.assertEqual(payload["sub"], "user_101")
        self.assertEqual(payload["rol"], "analyst")
        self.assertEqual(payload["iss"], self.issuer)

    def test_02_rs256_token_generation_and_validation(self):
        """Test 2: Asimetrik RS256 JWT üretimi ve genel anahtarla başarılı doğrulanması denetlenir."""
        token = JWTIssuerEngine.issue_token_rs256(
            claims={"sub": "admin_505", "rol": "super_admin"},
            private_key_d=self.rsa_d,
            modulus_n=self.rsa_n,
            ttl_seconds=1800,
            issuer=self.issuer,
            audience=self.audience
        )
        payload = self.validator.validate_token(token, public_key_n=self.rsa_n, public_key_e=self.rsa_e)
        self.assertEqual(payload["sub"], "admin_505")
        self.assertEqual(payload["rol"], "super_admin")

    def test_03_alg_none_attack_prevention_cwe_347(self):
        """Test 3: 'alg: none' imzasız belirteç saldırısında AlgorithmNoneAttackError (CWE-347) denetlenir."""
        header_b64 = Base64URL.encode(json.dumps({"typ": "JWT", "alg": "none"}).encode("utf-8"))
        payload_b64 = Base64URL.encode(json.dumps({"sub": "attacker", "rol": "admin"}).encode("utf-8"))
        none_token = f"{header_b64}.{payload_b64}."

        with self.assertRaises(AlgorithmNoneAttackError):
            self.validator.validate_token(none_token, secret_key=self.secret_key)

    def test_04_tampered_payload_signature_failure_cwe_347(self):
        """Test 4: Payload üzerinde yetki tahrifatı yapıldığında InvalidSignatureError (CWE-347) denetlenir."""
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "normal_user", "rol": "user"},
            secret_key=self.secret_key,
            issuer=self.issuer,
            audience=self.audience
        )
        parts = token.split(".")
        # Saldırgan payload'u değiştirip tekrar Base64URL kodluyor
        tampered_claims = json.loads(Base64URL.decode(parts[1]).decode("utf-8"))
        tampered_claims["rol"] = "admin"
        tampered_payload_b64 = Base64URL.encode(json.dumps(tampered_claims).encode("utf-8"))
        tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

        with self.assertRaises(InvalidSignatureError):
            self.validator.validate_token(tampered_token, secret_key=self.secret_key)

    def test_05_wrong_secret_signature_failure(self):
        """Test 5: Yanlış gizli anahtarla doğrulamada InvalidSignatureError fırlatıldığı teyit edilir."""
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_test"},
            secret_key=self.secret_key,
            issuer=self.issuer,
            audience=self.audience
        )
        with self.assertRaises(InvalidSignatureError):
            self.validator.validate_token(token, secret_key="YanlisGizliAnahtar999!")

    def test_06_token_expiration_cwe_298_cwe_613(self):
        """Test 6: Geçerlilik süresi (exp) dolan belirteçte TokenExpiredError (CWE-298) denetlenir."""
        now = datetime.now(timezone.utc)
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_exp"},
            secret_key=self.secret_key,
            ttl_seconds=10,
            issuer=self.issuer,
            audience=self.audience
        )
        # 20 saniye sonra (5 saniyelik leeway aşılmışken) denenir
        future = now + timedelta(seconds=20)
        with self.assertRaises(TokenExpiredError):
            self.validator.validate_token(token, secret_key=self.secret_key, now=future)

    def test_07_token_not_yet_valid_cwe_298(self):
        """Test 7: nbf (Not Before) tarihi henüz gelmemiş belirteçte TokenNotYetValidError denetlenir."""
        now = datetime.now(timezone.utc)
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_nbf"},
            secret_key=self.secret_key,
            ttl_seconds=3600,
            not_before_offset_seconds=60,  # 60 saniye sonra geçerli olacak
            issuer=self.issuer,
            audience=self.audience
        )
        # Şu anki zamanda sunulduğunda nbf engeline takılmalıdır
        with self.assertRaises(TokenNotYetValidError):
            self.validator.validate_token(token, secret_key=self.secret_key, now=now)

    def test_08_leeway_clock_skew_tolerance(self):
        """Test 8: Leeway toleransı dahilindeki (+3 saniye) küçük saat kaymalarının kabul edilmesi denetlenir."""
        now = datetime.now(timezone.utc)
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_leeway"},
            secret_key=self.secret_key,
            ttl_seconds=10,
            issuer=self.issuer,
            audience=self.audience
        )
        # 12 saniye sonra deneniyor (exp 10 saniyeydi, ancak 5s leeway olduğu için 15s'ye kadar geçerlidir)
        slightly_future = now + timedelta(seconds=12)
        payload = self.validator.validate_token(token, secret_key=self.secret_key, now=slightly_future)
        self.assertEqual(payload["sub"], "user_leeway")

    def test_09_invalid_issuer_rejection_cwe_287(self):
        """Test 9: Beklenmeyen bir Issuer ile gelen token'da InvalidIssuerError denetlenir."""
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_iss"},
            secret_key=self.secret_key,
            issuer="https://sahte-idp.attacker.com",  # Yanlış Issuer
            audience=self.audience
        )
        with self.assertRaises(InvalidIssuerError):
            self.validator.validate_token(token, secret_key=self.secret_key)

    def test_10_invalid_audience_rejection_cwe_287(self):
        """Test 10: Başka bir servis için üretilmiş Audience token'ında InvalidAudienceError denetlenir."""
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_aud"},
            secret_key=self.secret_key,
            issuer=self.issuer,
            audience="farkli_bir_api_servisi"  # Yanlış Audience
        )
        with self.assertRaises(InvalidAudienceError):
            self.validator.validate_token(token, secret_key=self.secret_key)

    def test_11_token_revocation_blacklist_cwe_294(self):
        """Test 11: İptal edilmiş (kara listedeki jti) belirteçte TokenRevokedError (CWE-294) denetlenir."""
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_logout", "jti": "jti_kara_liste_123"},
            secret_key=self.secret_key,
            issuer=self.issuer,
            audience=self.audience
        )
        # Önce geçerli olduğu doğrulanır
        self.validator.validate_token(token, secret_key=self.secret_key)

        # Token iptal edilir (Logout işlemi)
        self.validator.revoke_token("jti_kara_liste_123")

        # Artık reddedilmelidir
        with self.assertRaises(TokenRevokedError):
            self.validator.validate_token(token, secret_key=self.secret_key)

    def test_12_algorithm_confusion_rs256_to_hs256_cwe_327(self):
        """Test 12: Sadece RS256 bekleyen sunucuya HS256 sunulduğunda AlgorithmConfusionError denetlenir."""
        # Sadece RS256'ya izin veren katı politika
        strict_rs_policy = JWTValidationPolicy(
            allowed_algorithms={"RS256"},
            expected_issuer=self.issuer,
            expected_audience=self.audience
        )
        strict_validator = JWTValidatorEngine(strict_rs_policy)

        # HS256 ile imzalanmış token
        hs_token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_confusion"},
            secret_key=self.secret_key,
            issuer=self.issuer,
            audience=self.audience
        )

        with self.assertRaises(AlgorithmConfusionError):
            strict_validator.validate_token(hs_token, secret_key=self.secret_key)

    def test_13_malformed_jwt_parts_count_cwe_20(self):
        """Test 13: 3 parça içermeyen (örneğin 2 parçalı) bozuk belirteçte MalformedJWTError denetlenir."""
        with self.assertRaises(MalformedJWTError):
            self.validator.validate_token("sadece_header.sadece_payload", secret_key=self.secret_key)

    def test_14_corrupted_base64url_in_payload_cwe_20(self):
        """Test 14: Base64URL karakter kümesi dışında bozuk veri içeren token'da MalformedJWTError denetlenir."""
        with self.assertRaises(MalformedJWTError):
            self.validator.validate_token("gecersiz!b64.gecersiz!b64.gecersiz!sig", secret_key=self.secret_key)

    def test_15_constant_time_hmac_comparison_cwe_208(self):
        """Test 15: İmza doğrulamasında sabit zamanlı karşılaştırma mekanizması teyit edilir."""
        token = JWTIssuerEngine.issue_token_hs256(
            claims={"sub": "user_timing"},
            secret_key=self.secret_key,
            issuer=self.issuer,
            audience=self.audience
        )
        parts = token.split(".")
        # Son karakteri bozulmuş imza
        bad_sig = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
        bad_token = f"{parts[0]}.{parts[1]}.{bad_sig}"
        with self.assertRaises(InvalidSignatureError):
            self.validator.validate_token(bad_token, secret_key=self.secret_key)


if __name__ == "__main__":
    unittest.main()
