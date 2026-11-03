# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 114: MFA Yöntemleri ve Oltalama (Phishing) Direnci Kapsamlı Birim Testleri.

Bu test paketi, RFC 6238 TOTP mekanizmasını, FIDO2 / WebAuthn asimetrik imza doğrulamasını,
CWE-346 Menşe Doğrulamasını (Origin Binding), CWE-294 Replay saldırılarını,
CWE-347 Klonlama tespitini ve AiTM ters vekil (Evilginx) oltalama simülasyonunu
15 bağımsız test senaryosunda doğrular.
"""

# Birim test çatısı için unittest modülü içe aktarılır
import unittest
# Zaman ve süre hesaplamaları için datetime, timedelta, timezone ve time içe aktarılır
from datetime import datetime, timezone, timedelta
import time
# Kriptografik özet ve bayt işlemleri için hashlib ve struct içe aktarılır
import hashlib
import struct
# JSON serileştirme için json içe aktarılır
import json
# Dosya sistemi ve sistem yolu yönetimi için os ve sys içe aktarılır
import os
import sys

# Test edilen uygulamanın bulunduğu dizin Python arama yoluna eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# mfa_phishing_resistant_engine modülünden gerekli sınıflar içe aktarılır
from mfa_phishing_resistant_engine import (
    TOTPEngine,
    WebAuthnFIDO2Engine,
    PhishingAttackSimulator,
    InvalidTOTPCodeError,
    TOTPReplayError,
    PhishingOriginMismatchError,
    WebAuthnChallengeMismatchError,
    WebAuthnInvalidSignatureError,
    AuthenticatorCloneDetectedError
)


class TestMFAPhishingResistance(unittest.TestCase):
    """MFA yöntemlerini ve oltalama direncini sınayan test paketi."""

    def setUp(self):
        """Her testten önce izole TOTP ve FIDO2 motorları ve test anahtarları hazırlar."""
        # Standart 30 saniyelik TOTP motoru
        self.totp = TOTPEngine(period_seconds=30, digits=6)
        self.totp_cred = self.totp.register_user("seydi_user", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")

        # FIDO2 WebAuthn motoru
        self.rp_id = "mevzuat.siber.local"
        self.rp_origin = "https://mevzuat.siber.local"
        self.fido2 = WebAuthnFIDO2Engine(relying_party_id=self.rp_id, relying_party_origin=self.rp_origin)

        # 512-bit RSA test anahtar çifti (SHA-256 imzası için en az 256-bit modulus gereklidir)
        p = 79767748627722170403753678573501130792297299195379632297507984385755962539519
        q = 74423822195679822963040554606743229645699794242435226315153894989068738755257
        self.n = p * q
        self.e = 65537
        phi = (p - 1) * (q - 1)
        self.d = pow(self.e, -1, phi)

        self.cred_id = "yubikey_test_cred_01"
        self.fido2.register_credential(
            credential_id=self.cred_id,
            username="seydi_user",
            public_key_n=self.n,
            public_key_e=self.e,
            initial_sign_count=50
        )

    def _sign_client_assertion(self, authenticator_data: bytes, client_data_json: str, override_d: int = None) -> int:
        """İstemci tarafında asimetrik dijital imza üretimini simüle eder."""
        d_val = override_d if override_d is not None else self.d
        client_data_hash = hashlib.sha256(client_data_json.encode("utf-8")).digest()
        signed_data = authenticator_data + client_data_hash
        hash_to_sign = hashlib.sha256(signed_data).digest()

        byte_len = (self.n.bit_length() + 7) // 8
        padding = b"\x00\x01" + (b"\xFF" * (byte_len - 3 - len(hash_to_sign))) + b"\x00" + hash_to_sign
        int_to_sign = int.from_bytes(padding, byteorder="big")
        return pow(int_to_sign, d_val, self.n)

    def test_01_totp_rfc6238_vector_generation(self):
        """Test 1: RFC 6238 algoritmasının 6-haneli sayısal kod üretmesi doğrulanır."""
        code, step = self.totp.generate_code(self.totp_cred.secret_base32, timestamp=1111111109)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())
        self.assertEqual(step, int(1111111109 // 30))

    def test_02_totp_verification_success_within_period(self):
        """Test 2: Üretilen geçerli TOTP kodunun aynı zaman aralığında başarıyla doğrulanması denetlenir."""
        current_time = time.time()
        code, _ = self.totp.generate_code(self.totp_cred.secret_base32, timestamp=current_time)
        is_valid = self.totp.verify_code("seydi_user", code, timestamp=current_time)
        self.assertTrue(is_valid)

    def test_03_totp_verification_failure_with_wrong_code_cwe_287(self):
        """Test 3: Hatalı TOTP kodu sunulduğunda InvalidTOTPCodeError (CWE-287) fırlatıldığı doğrulanır."""
        with self.assertRaises(InvalidTOTPCodeError):
            self.totp.verify_code("seydi_user", "000000")

    def test_04_totp_drift_window_tolerance(self):
        """Test 4: Saat kayması toleransında (+1 pencere = 30 saniye sonra) kodun kabul edilmesi denetlenir."""
        t0 = time.time()
        code, _ = self.totp.generate_code(self.totp_cred.secret_base32, timestamp=t0)
        # 25 saniye sonra (+1 zaman penceresi dahilinde) doğrulanır
        is_valid = self.totp.verify_code("seydi_user", code, timestamp=t0 + 25, window=1)
        self.assertTrue(is_valid)

    def test_05_totp_replay_prevention_cwe_294(self):
        """Test 5: Aynı TOTP kodunun ikinci kez sunulmasında TOTPReplayError (CWE-294) denetlenir."""
        t0 = time.time()
        code, _ = self.totp.generate_code(self.totp_cred.secret_base32, timestamp=t0)
        # İlk kullanım başarılı olmalı
        self.assertTrue(self.totp.verify_code("seydi_user", code, timestamp=t0))
        # İkinci kullanımda Replay engeli tetiklenmelidir
        with self.assertRaises(TOTPReplayError):
            self.totp.verify_code("seydi_user", code, timestamp=t0)

    def test_06_fido2_registration_and_credential_storage(self):
        """Test 6: FIDO2 kimlik bilgisinin doğru sayaç ve Relying Party kimliğiyle kaydedilmesi denetlenir."""
        cred = self.fido2.get_credential(self.cred_id)
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "seydi_user")
        self.assertEqual(cred.sign_count, 50)
        self.assertEqual(cred.rp_id, self.rp_id)

    def test_07_fido2_challenge_creation_and_expiration(self):
        """Test 7: WebAuthn 32-baytlık tek kullanımlık challenge üretimi ve TTL süresi denetlenir."""
        ch = self.fido2.create_authentication_challenge("seydi_user", ttl_seconds=60)
        self.assertEqual(len(ch.challenge_hex), 64)
        self.assertFalse(ch.is_used)
        self.assertTrue(ch.expires_at > datetime.now(timezone.utc))

    def test_08_fido2_assertion_success_on_legitimate_origin(self):
        """Test 8: Meşru menşede (https://mevzuat.siber.local) geçerli FIDO2 imzasının onaylanması denetlenir."""
        ch = self.fido2.create_authentication_challenge("seydi_user")
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + b"\x01" + struct.pack(">I", 51)

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": ch.challenge_hex,
            "origin": self.rp_origin
        })

        sig = self._sign_client_assertion(auth_data, client_data)
        is_ok = self.fido2.verify_assertion(self.cred_id, client_data, auth_data, sig)
        self.assertTrue(is_ok)
        self.assertEqual(self.fido2.get_credential(self.cred_id).sign_count, 51)

    def test_09_fido2_phishing_resistance_origin_mismatch_cwe_346(self):
        """Test 9: Sahte oltalama sitesinde FIDO2 menşe uyuşmazlığının (CWE-346) engellenmesi denetlenir."""
        ch = self.fido2.create_authentication_challenge("seydi_user")
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + b"\x01" + struct.pack(">I", 52)

        # Kurban sahte oltalama sitesinde (phishing-site.com) oturum açmaya çalışıyor
        phishing_origin = "https://phishing-fake-login.com"
        client_data_phishing = json.dumps({
            "type": "webauthn.get",
            "challenge": ch.challenge_hex,
            "origin": phishing_origin
        })

        sig = self._sign_client_assertion(auth_data, client_data_phishing)
        # Meşru sunucu sahte menşei derhal reddetmelidir (Phishing-Resistance)
        with self.assertRaises(PhishingOriginMismatchError):
            self.fido2.verify_assertion(self.cred_id, client_data_phishing, auth_data, sig)

    def test_10_fido2_challenge_replay_attack_prevention_cwe_294(self):
        """Test 10: Daha önce kullanılmış bir WebAuthn challenge'ının tekrar sunulması (CWE-294) denetlenir."""
        ch = self.fido2.create_authentication_challenge("seydi_user")
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + b"\x01" + struct.pack(">I", 53)

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": ch.challenge_hex,
            "origin": self.rp_origin
        })

        sig = self._sign_client_assertion(auth_data, client_data)
        # İlk kullanım başarılı
        self.assertTrue(self.fido2.verify_assertion(self.cred_id, client_data, auth_data, sig))

        # İkinci kullanımda Replay engeli fırlatılmalıdır
        auth_data2 = rp_hash + b"\x01" + struct.pack(">I", 54)
        sig2 = self._sign_client_assertion(auth_data2, client_data)
        with self.assertRaises(WebAuthnChallengeMismatchError):
            self.fido2.verify_assertion(self.cred_id, client_data, auth_data2, sig2)

    def test_11_fido2_challenge_expired_rejection(self):
        """Test 11: Süresi dolmuş WebAuthn challenge'ının reddedilmesi denetlenir."""
        now = datetime.now(timezone.utc)
        ch = self.fido2.create_authentication_challenge("seydi_user", ttl_seconds=10)
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + b"\x01" + struct.pack(">I", 55)

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": ch.challenge_hex,
            "origin": self.rp_origin
        })

        sig = self._sign_client_assertion(auth_data, client_data)
        # 15 saniye sonra deneniyor
        future = now + timedelta(seconds=15)
        with self.assertRaises(WebAuthnChallengeMismatchError):
            self.fido2.verify_assertion(self.cred_id, client_data, auth_data, sig, now=future)

    def test_12_fido2_invalid_signature_rejection_cwe_347(self):
        """Test 12: Yanlış özel anahtarla imzalanmış WebAuthn yanıtında WebAuthnInvalidSignatureError denetlenir."""
        ch = self.fido2.create_authentication_challenge("seydi_user")
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + b"\x01" + struct.pack(">I", 56)

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": ch.challenge_hex,
            "origin": self.rp_origin
        })

        # Sahte bir özel üs (d + 2) ile hatalı imza
        bad_sig = self._sign_client_assertion(auth_data, client_data, override_d=self.d + 2)
        with self.assertRaises(WebAuthnInvalidSignatureError):
            self.fido2.verify_assertion(self.cred_id, client_data, auth_data, bad_sig)

    def test_13_fido2_authenticator_clone_detection_cwe_347(self):
        """Test 13: Donanım anahtarı sayacının gerilemesi durumunda klon tespiti (CWE-347) denetlenir."""
        ch = self.fido2.create_authentication_challenge("seydi_user")
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        # Kayıtlı sayaç 50 iken gelen sayaç 49 (Geriye gitmiş -> Klon veya tekrar)
        bad_auth_data = rp_hash + b"\x01" + struct.pack(">I", 49)

        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": ch.challenge_hex,
            "origin": self.rp_origin
        })

        sig = self._sign_client_assertion(bad_auth_data, client_data)
        with self.assertRaises(AuthenticatorCloneDetectedError):
            self.fido2.verify_assertion(self.cred_id, client_data, bad_auth_data, sig)

    def test_14_aitm_simulator_totp_vulnerability_demonstration(self):
        """Test 14: AiTM simülatörünün TOTP kodunun ters vekil tarafından başarıyla çalınabildiğini kanıtlaması."""
        code, _ = self.totp.generate_code(self.totp_cred.secret_base32)
        res = PhishingAttackSimulator.simulate_totp_phishing_attack(self.totp, "seydi_user", code)
        self.assertTrue(res["saldiri_basarili_mi"])
        self.assertIn("ZAFİYET", res["aciklama"])

    def test_15_aitm_simulator_fido2_phishing_defense_demonstration(self):
        """Test 15: AiTM simülatörünün FIDO2'nin ters vekil oltalama saldırısını sıfıra indirdiğini kanıtlaması."""
        ch = self.fido2.create_authentication_challenge("seydi_user")
        rp_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        auth_data = rp_hash + b"\x01" + struct.pack(">I", 75)

        phishing_origin = "https://evil-phishing-proxy.com"
        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": ch.challenge_hex,
            "origin": phishing_origin
        })
        sig = self._sign_client_assertion(auth_data, client_data)

        res = PhishingAttackSimulator.simulate_fido2_phishing_attack(
            self.fido2, self.cred_id, phishing_origin, ch.challenge_hex, auth_data, sig
        )
        self.assertFalse(res["saldiri_basarili_mi"])
        self.assertEqual(res["yakalanan_zafiyet"], "CWE-346: Origin Validation Error")


if __name__ == "__main__":
    unittest.main()
