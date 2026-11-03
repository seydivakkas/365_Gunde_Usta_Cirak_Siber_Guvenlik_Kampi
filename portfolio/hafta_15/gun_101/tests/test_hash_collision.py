# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 101: Kriptografik Hash Fonksiyonları ve Çakışma Birim Test Paketi.
Referans test vektörleri, çığ etkisi, Doğum Günü çakışma simülasyonu,
güvensiz algoritma engellemesi ve negatif kontrol senaryolarını test eder.
"""

# Standart birim testi kütüphanesi
import unittest
# Dosya ve dizin yol işlemleri modülü
import os
# Sistem parametreleri ve yol modülü
import sys
# JSON veri okuma ve ayrıştırma modülü
import json

# Test edilecek yerel modülleri içe aktarabilmek için ana yolu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor sınıflarını ve istisnalarını içe aktar
from uygulama.hash_collision_engine import (
    HashAnalyzer,
    AvalancheResult,
    CollisionSimulationResult,
    HashSecurityError,
    BrokenHashAlgorithmError,
    HashCollisionDetectedError,
    AvalancheEffectFailureError,
    HashVerificationError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


class TestHashCollision(unittest.TestCase):
    """Kriptografik Hash ve Çakışma birim testleri sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        self.ornek_veri_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ornek_veri"))
        self.negative_json_path = os.path.join(self.ornek_veri_dir, "invalid_hash_inputs.json")
        self.samples_json_path = os.path.join(self.ornek_veri_dir, "collision_samples.json")

    def test_01_sha256_reference_vector(self):
        """NIST FIPS 180-4 standardı 'abc' girdi vektörünün beklenen SHA-256 özetini doğruladığını test eder."""
        beklenen = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        hesaplanan = HashAnalyzer.compute_digest("abc", algorithm="sha256")
        self.assertEqual(hesaplanan, beklenen)

    def test_02_sha512_and_blake2b_support(self):
        """SHA-512 ve BLAKE2b algoritmalarının beklenen çıktı uzunluklarında özet ürettiğini doğrular."""
        ozet_sha512 = HashAnalyzer.compute_digest("test_payload", algorithm="sha512")
        self.assertEqual(len(ozet_sha512), 128)  # 512 bit = 128 hex

        ozet_blake2b = HashAnalyzer.compute_digest("test_payload", algorithm="blake2b")
        self.assertEqual(len(ozet_blake2b), 128)  # 512 bit = 128 hex

    def test_03_prohibited_md5_rejection(self):
        """Varsayılan güvenli modda kırılmış MD5 algoritmasının engellendiğini doğrular (CWE-328)."""
        with self.assertRaises(BrokenHashAlgorithmError):
            HashAnalyzer.compute_digest("guvensiz_veri", algorithm="md5", allow_insecure=False)

    def test_04_prohibited_sha1_rejection(self):
        """Varsayılan güvenli modda çakışmalı SHA-1 algoritmasının engellendiğini doğrular (CWE-328)."""
        with self.assertRaises(BrokenHashAlgorithmError):
            HashAnalyzer.compute_digest("guvensiz_veri", algorithm="sha1", allow_insecure=False)

    def test_05_allow_insecure_flag_md5(self):
        """allow_insecure=True bayrağı ile deneysel amaçlı MD5 üretilebildiğini doğrular."""
        ozet_md5 = HashAnalyzer.compute_digest("deneysel", algorithm="md5", allow_insecure=True)
        self.assertEqual(len(ozet_md5), 32)  # 128 bit = 32 hex

    def test_06_avalanche_effect_ideal_range(self):
        """1 bitlik girdi farkının SHA-256 çıktısında %40 ile %60 arasında bit değişimi sağladığını doğrular."""
        t1 = "SiberGuvenlik2026_Kripto_G101_A"
        t2 = "SiberGuvenlik2026_Kripto_G101_B"
        res = HashAnalyzer.calculate_avalanche_effect(t1, t2, algorithm="sha256")
        self.assertEqual(res.toplam_bit_sayisi, 256)
        self.assertGreaterEqual(res.degisim_yuzdesi, 40.0)
        self.assertLessEqual(res.degisim_yuzdesi, 60.0)

    def test_07_avalanche_strict_failure(self):
        """Kusurlu çığ etkisi oranının sıkı modda AvalancheEffectFailureError fırlattığını doğrular."""
        # Aynı iki metin verildiğinde değişim %0 olur
        with self.assertRaises(AvalancheEffectFailureError):
            HashAnalyzer.calculate_avalanche_effect("ayni_metin", "ayni_metin", strict_mode=True)

    def test_08_birthday_collision_simulation_16bit(self):
        """16-bitlik kırpılmış hash üzerinde Doğum Günü çakışmasının başarıyla bulunduğunu doğrular."""
        sim = HashAnalyzer.birthday_collision_simulation(bit_size=16, max_attempts=50000)
        self.assertEqual(sim.kirpma_bit, 16)
        self.assertNotEqual(sim.cakisan_girdi_1, sim.cakisan_girdi_2)
        # Her iki girdinin de kırpılmış hash'lerinin eşit olduğunu doğrula
        h1 = HashAnalyzer.compute_digest(sim.cakisan_girdi_1, algorithm="sha256")[:4]
        h2 = HashAnalyzer.compute_digest(sim.cakisan_girdi_2, algorithm="sha256")[:4]
        self.assertEqual(h1, h2)

    def test_09_constant_time_verification_pass(self):
        """Doğru özet değerinin sabit zamanlı doğrulamadan başarıyla geçtiğini test eder."""
        veri = "G101_Bütünlük_Testi"
        ozet = HashAnalyzer.compute_digest(veri, algorithm="sha256")
        self.assertTrue(HashAnalyzer.verify_digest_constant_time(ozet, ozet))

    def test_10_constant_time_verification_fail_strict(self):
        """Tahrif edilmiş özetin sıkı modda HashVerificationError fırlattığını doğrular (CWE-208/CWE-345)."""
        veri = "G101_Bütünlük_Testi"
        ozet = HashAnalyzer.compute_digest(veri, algorithm="sha256")
        sahte_ozet = "0" * 64
        with self.assertRaises(HashVerificationError):
            HashAnalyzer.verify_digest_constant_time(ozet, sahte_ozet, strict_mode=True)

    def test_11_payload_limit_dos_rejection(self):
        """1 MB tavanını aşan verilerin DoS korumasıyla engellendiğini doğrular (CWE-400)."""
        huge_bytes = b"H" * 1_000_001
        with self.assertRaises(PayloadLimitExceededError):
            HashAnalyzer.compute_digest(huge_bytes)

    def test_12_null_byte_rejection(self):
        """Algoritma adında veya metinde Null-Byte zehirlemesinin engellendiğini doğrular (CWE-158)."""
        with self.assertRaises(NullByteInjectionError):
            HashAnalyzer.compute_digest("sha256\x00md5")
        with self.assertRaises(NullByteInjectionError):
            HashAnalyzer.compute_digest("metin\x00zararli")

    def test_13_invalid_truncation_bit_size(self):
        """Doğum günü simülasyonunda geçersiz bit boyutlarının TypeValidationError fırlattığını doğrular (CWE-1284)."""
        with self.assertRaises(TypeValidationError):
            HashAnalyzer.birthday_collision_simulation(bit_size=-4)
        with self.assertRaises(TypeValidationError):
            HashAnalyzer.birthday_collision_simulation(bit_size=64)

    def test_14_type_validation_rejection(self):
        """Uyumsuz tiplerin (int, liste) TypeValidationError fırlattığını doğrular (CWE-843)."""
        with self.assertRaises(TypeValidationError):
            HashAnalyzer.compute_digest(123456)  # type: ignore
        with self.assertRaises(TypeValidationError):
            HashAnalyzer.verify_digest_constant_time("", "")

    def test_15_negative_inputs_json_suite(self):
        """invalid_hash_inputs.json dosyasındaki 9 negatif senaryonun tamamını doğrular."""
        with open(self.negative_json_path, "r", encoding="utf-8") as f:
            cases = json.load(f)

        self.assertEqual(len(cases), 9)

        for case in cases:
            cid = case["id"]
            # Case 1: DEPRECATED_MD5_USAGE
            if cid == "NEG_01_DEPRECATED_MD5_USAGE":
                with self.assertRaises(BrokenHashAlgorithmError):
                    HashAnalyzer.compute_digest("test", algorithm=case["algoritma"], allow_insecure=False)
            # Case 2: DEPRECATED_SHA1_USAGE
            elif cid == "NEG_02_DEPRECATED_SHA1_USAGE":
                with self.assertRaises(BrokenHashAlgorithmError):
                    HashAnalyzer.compute_digest("test", algorithm=case["algoritma"], allow_insecure=False)
            # Case 3: INSUFFICIENT_AVALANCHE_EFFECT
            elif cid == "NEG_03_INSUFFICIENT_AVALANCHE_EFFECT":
                with self.assertRaises(AvalancheEffectFailureError):
                    HashAnalyzer.calculate_avalanche_effect("same", "same", strict_mode=True)
            # Case 4: INSECURE_HASH_COMPARISON
            elif cid == "NEG_04_INSECURE_HASH_COMPARISON":
                with self.assertRaises(HashVerificationError):
                    HashAnalyzer.verify_digest_constant_time(case["ozet_1"], case["ozet_2"], strict_mode=True)
            # Case 5: OVERSIZED_INPUT_DOS
            elif cid == "NEG_05_OVERSIZED_INPUT_DOS":
                huge_data = b"X" * 1_000_001
                with self.assertRaises(PayloadLimitExceededError):
                    HashAnalyzer.compute_digest(huge_data)
            # Case 6: NULL_BYTE_INJECTION
            elif cid == "NEG_06_NULL_BYTE_INJECTION":
                with self.assertRaises(NullByteInjectionError):
                    HashAnalyzer.compute_digest("data", algorithm=case["yol"])
            # Case 7: INVALID_TRUNCATION_BITS
            elif cid == "NEG_07_INVALID_TRUNCATION_BITS":
                with self.assertRaises(TypeValidationError):
                    HashAnalyzer.birthday_collision_simulation(bit_size=case["bit_uzunlugu"])
            # Case 8: EMPTY_DIGEST_COMPARISON
            elif cid == "NEG_08_EMPTY_DIGEST_COMPARISON":
                with self.assertRaises(TypeValidationError):
                    HashAnalyzer.verify_digest_constant_time(case["ozet"], "valid_hex")
            # Case 9: TYPE_CONFUSION
            elif cid == "NEG_09_TYPE_CONFUSION":
                with self.assertRaises(TypeValidationError):
                    HashAnalyzer.compute_digest(case["girdi"])  # type: ignore


if __name__ == "__main__":
    unittest.main(verbosity=2)
