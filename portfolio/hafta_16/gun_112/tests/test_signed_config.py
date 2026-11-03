# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
Mini Proje 15: İmzalı Yapılandırma Konsepti Kapsamlı Birim Testleri (test_signed_config.py).

Bu test paketi; RFC 8785 kanonik serileştirme, asimetrik RSA imzalama ve doğrulama,
zarf bütünlüğü, tek baytlık tahrifat tespiti (CWE-353), sahte imza reddi (CWE-347),
monotonik epoch ile Rollback koruması (CWE-294), geçerlilik süresi (CWE-298),
Çift İmza (Dual Signing / CWE-285), güven kökü denetimi (CWE-295) ve
algoritma düşürme engellemesini (CWE-327) 15 bağımsız test senaryosuyla sınar.
"""

import os
import sys
import unittest
import datetime

# Uygulama modülünü arama yoluna dahil et
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

from signed_config_engine import (
    RSAKeyPair,
    SignedConfigSigner,
    SignedConfigVerifier,
    canonicalize_json,
    SignedConfigError,
    ConfigTamperingError,
    InvalidSignatureError,
    RollbackAttackDetectedError,
    ConfigExpiredError,
    InsufficientSignaturesError,
    UntrustedSignerError,
    MalformedConfigError,
    FutureTimestampError,
    InsecureAlgorithmError
)

class TestSignedConfigurationConcept(unittest.TestCase):
    """Mini Proje 15: İmzalı Yapılandırma Kapsamlı Birim Testleri (15 Test)."""

    def setUp(self):
        """Her test öncesi temiz anahtarlar, güven deposu ve motorlar oluştur."""
        self.key_admin1 = RSAKeyPair.generate(key_id="admin_01", bits=512)
        self.key_admin2 = RSAKeyPair.generate(key_id="admin_02", bits=512)

        self.trust_store = {
            self.key_admin1.key_id: self.key_admin1.public_key,
            self.key_admin2.key_id: self.key_admin2.public_key
        }

        self.signer1 = SignedConfigSigner(self.key_admin1)
        self.signer2 = SignedConfigSigner(self.key_admin2)
        self.verifier = SignedConfigVerifier(trust_store=self.trust_store, current_system_epoch=1, required_signatures=1)

        self.sample_payload = {
            "service": "api-gateway",
            "listen_port": 8443,
            "security_profile": "strict",
            "rate_limit_rps": 500
        }

    def test_01_canonical_json_rfc8785(self):
        """Test 01 (RFC 8785): Sırasız sözlüklerin özdeş kanonik bayt dizisine dönüşmesi."""
        dict_a = {"b": 2, "a": 1, "c": [3, 2, 1]}
        dict_b = {"a": 1, "c": [3, 2, 1], "b": 2}
        bytes_a = canonicalize_json(dict_a)
        bytes_b = canonicalize_json(dict_b)
        self.assertEqual(bytes_a, bytes_b)
        self.assertEqual(bytes_a, b'{"a":1,"b":2,"c":[3,2,1]}')

    def test_02_rsa_keypair_generation_and_sign(self):
        """Test 02: Asimetrik anahtar üretimi ve özet imzalama doğruluğu."""
        digest = b"test_ozet_32bayt_uzunlugundadir!"
        sig = self.key_admin1.sign_digest(digest)
        is_valid = RSAKeyPair.verify_digest(self.key_admin1.public_key, digest, sig)
        self.assertTrue(is_valid)

    def test_03_signed_config_envelope_structure(self):
        """Test 03: İmzalı yapılandırma zarfının format ve alan doğruluğu."""
        env = self.signer1.sign_config(self.sample_payload, epoch=1, validity_days=30)
        self.assertEqual(env["format"], "SEC-SIGNED-CONFIG-V1")
        self.assertEqual(env["epoch"], 1)
        self.assertIn("payload_sha256", env)
        self.assertEqual(len(env["signatures"]), 1)

    def test_04_successful_single_signature_verification(self):
        """Test 04: Geçerli tek imzalı yapılandırmanın başarıyla yüklenmesi."""
        env = self.signer1.sign_config(self.sample_payload, epoch=1)
        loaded = self.verifier.verify_and_load(env)
        self.assertEqual(loaded["service"], "api-gateway")

    def test_05_payload_single_byte_tampering(self):
        """Test 05 (CWE-353): Yapılandırma yükünde tek bir değer değiştirildiğinde imza reddi."""
        env = self.signer1.sign_config(self.sample_payload, epoch=1)
        # Tahrifat: Portu 8443'ten 80'e düşür
        env["payload"]["listen_port"] = 80
        with self.assertRaises(ConfigTamperingError):
            self.verifier.verify_and_load(env)

    def test_06_invalid_signature_hex_rejection(self):
        """Test 06 (CWE-347): Bozulmuş veya sahte imza hex dizesinin reddedilmesi."""
        env = self.signer1.sign_config(self.sample_payload, epoch=1)
        # İmzayı tahrif et
        env["signatures"][0]["signature_hex"] = "beef" * 16
        with self.assertRaises(InvalidSignatureError):
            self.verifier.verify_and_load(env)

    def test_07_rollback_attack_epoch_rejection(self):
        """Test 07 (CWE-294): Mevcut sistem epoch'undan daha düşük sürümle Rollback engeli."""
        self.verifier.current_system_epoch = 5
        old_env = self.signer1.sign_config(self.sample_payload, epoch=4)
        with self.assertRaises(RollbackAttackDetectedError):
            self.verifier.verify_and_load(old_env)

    def test_08_config_expired_rejection(self):
        """Test 08 (CWE-298): Geçerlilik süresi (ExpiresAt) dolmuş yapılandırma reddi."""
        env = self.signer1.sign_config(self.sample_payload, epoch=1, validity_days=10)
        future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        with self.assertRaises(ConfigExpiredError):
            self.verifier.verify_and_load(env, current_time=future_time)

    def test_09_future_timestamp_rejection(self):
        """Test 09 (CWE-298): Sistem saatinden ileride oluşturulmuş zaman damgası reddi."""
        env = self.signer1.sign_config(self.sample_payload, epoch=1)
        past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        with self.assertRaises(FutureTimestampError):
            self.verifier.verify_and_load(env, current_time=past_time)

    def test_10_dual_signing_success(self):
        """Test 10: Çift imza (2-of-2) politikasında iki geçerli imza ile başarı."""
        dual_verifier = SignedConfigVerifier(trust_store=self.trust_store, current_system_epoch=1, required_signatures=2)
        env = self.signer1.sign_config(self.sample_payload, epoch=1)
        dual_env = self.signer2.co_sign_envelope(env)
        loaded = dual_verifier.verify_and_load(dual_env)
        self.assertEqual(loaded["security_profile"], "strict")

    def test_11_insufficient_signatures_rejection(self):
        """Test 11 (CWE-285): Çift imza politikasında tek imza sunulması durumunda ret."""
        dual_verifier = SignedConfigVerifier(trust_store=self.trust_store, current_system_epoch=1, required_signatures=2)
        env = self.signer1.sign_config(self.sample_payload, epoch=1)
        with self.assertRaises(InsufficientSignaturesError):
            dual_verifier.verify_and_load(env)

    def test_12_untrusted_signer_rejection(self):
        """Test 12 (CWE-295): Güven deposunda bulunmayan yetkisiz imzalayıcı reddi."""
        untrusted_key = RSAKeyPair.generate(key_id="rogue_signer", bits=512)
        untrusted_signer = SignedConfigSigner(untrusted_key)
        env = untrusted_signer.sign_config(self.sample_payload, epoch=1)
        with self.assertRaises(UntrustedSignerError):
            self.verifier.verify_and_load(env)

    def test_13_insecure_algorithm_none_rejection(self):
        """Test 13 (CWE-327): İmzalamada 'none' veya geçersiz algoritma talebinin reddi."""
        with self.assertRaises(InsecureAlgorithmError):
            self.signer1.sign_config(self.sample_payload, epoch=1, algorithm="none")

    def test_14_malformed_config_envelope_rejection(self):
        """Test 14 (CWE-20): Bozuk zarf yapısı veya yanlış format başlığı reddi."""
        with self.assertRaises(MalformedConfigError):
            self.verifier.verify_and_load({"format": "INVALID_FORMAT", "epoch": 1})

    def test_15_epoch_advancement_and_forward_progression(self):
        """Test 15: Daha yüksek epoch başarıyla yüklendiğinde sistem sayacının ilerlemesi."""
        self.assertEqual(self.verifier.current_system_epoch, 1)
        env = self.signer1.sign_config(self.sample_payload, epoch=5)
        self.verifier.verify_and_load(env)
        self.assertEqual(self.verifier.current_system_epoch, 5)

if __name__ == "__main__":
    unittest.main()
