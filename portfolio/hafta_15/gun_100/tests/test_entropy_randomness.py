# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 100: Entropi ve Kriptografik Rastgelelik Birim Test Paketi.
Shannon Entropisi, Min-Entropi, Ki-Kare, Monobit testi, CSPRNG üretimi,
zayıf PRNG tespiti ve negatif kontrol senaryolarını test eder.
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
from uygulama.entropy_randomness_engine import (
    EntropyMath,
    CSPRNGGenerator,
    EntropyAuditor,
    EntropyMetrics,
    EntropyAuditReport,
    EntropySecurityError,
    WeakPRNGDetectedError,
    InsufficientEntropyError,
    PredictableSeedError,
    SmallEntropySpaceError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


class TestEntropyRandomness(unittest.TestCase):
    """Entropi ve Kriptografik Rastgelelik birim testleri sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        self.auditor = EntropyAuditor(min_pass_shannon=7.0)
        self.ornek_veri_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ornek_veri"))
        self.negative_json_path = os.path.join(self.ornek_veri_dir, "invalid_entropy_inputs.json")
        self.samples_json_path = os.path.join(self.ornek_veri_dir, "entropy_test_samples.json")

    def test_01_shannon_entropy_calculation_math(self):
        """Shannon Entropisi: Sabit baytta 0.0, tekdüze 256 baytta tam 8.0 bit/bayt olmasını doğrular."""
        sabit_baytlar = b"A" * 100
        self.assertEqual(EntropyMath.shannon_entropy(sabit_baytlar), 0.0)

        tam_tekduze_baytlar = bytes(range(256))
        self.assertEqual(EntropyMath.shannon_entropy(tam_tekduze_baytlar), 8.0)

    def test_02_min_entropy_worst_case(self):
        """Min-Entropi: En sık tekrarlanan bayta göre en kötü durum entropisini doğrular."""
        sabit_baytlar = b"A" * 100
        self.assertEqual(EntropyMath.min_entropy(sabit_baytlar), 0.0)

        esit_iki_bayt = b"AB" * 50
        self.assertEqual(EntropyMath.min_entropy(esit_iki_bayt), 1.0)

    def test_03_chi_square_uniformity(self):
        """Ki-Kare Testi: Tam uniform dağılımda Ki-Kare değerinin sıfır olduğunu doğrular."""
        tekduze_baytlar = bytes(range(256))
        chi_sq = EntropyMath.chi_square(tekduze_baytlar)
        self.assertEqual(chi_sq, 0.0)

    def test_04_monobit_frequency_test(self):
        """Monobit Testi: Tam dengeli bit akışında 1 oranının 0.5 ve p-değerinin 1.0 olmasını doğrular."""
        # 0xAA = 10101010b, 0x55 = 01010101b (Eşit sayıda 0 ve 1)
        dengeli_baytlar = b"\xaa\x55" * 100
        oran, p_val = EntropyMath.monobit_frequency_test(dengeli_baytlar)
        self.assertEqual(oran, 0.5)
        self.assertEqual(p_val, 1.0)

    def test_05_csprng_key_generation_entropy(self):
        """CSPRNG: Üretilen 256-bit anahtarın yüksek entropiye (>= 7.0) sahip olduğunu doğrular."""
        key = CSPRNGGenerator.generate_key(bits=256)
        self.assertEqual(len(key), 32)
        # 1024 baytlık daha büyük CSPRNG akışında istatistik ölçümü
        stream = CSPRNGGenerator.generate_key(bits=8192)
        metrics = EntropyMath.calculate_all(stream)
        self.assertGreaterEqual(metrics.shannon_entropi, 7.5)
        self.assertGreaterEqual(metrics.monobit_p_degeri, 0.01)

    def test_06_csprng_token_length_and_hex(self):
        """CSPRNG: Güvenli token üretiminin uzunluğunu ve onaltılık formatını doğrular."""
        token = CSPRNGGenerator.generate_token(length_bytes=32)
        self.assertEqual(len(token), 64)  # 32 bayt = 64 hex karakteri
        self.assertTrue(all(c in "0123456789abcdef" for c in token.lower()))

    def test_07_small_entropy_space_rejection(self):
        """Small Space: 64 bitten küçük anahtarların reddedildiğini doğrular (CWE-334)."""
        with self.assertRaises(SmallEntropySpaceError):
            CSPRNGGenerator.generate_key(bits=32)
        with self.assertRaises(SmallEntropySpaceError):
            CSPRNGGenerator.generate_token(length_bytes=4)

    def test_08_weak_prng_static_detection(self):
        """Weak PRNG: Mersenne Twister veya random modülü kullanımının yakalandığını doğrular (CWE-338)."""
        with self.assertRaises(WeakPRNGDetectedError):
            CSPRNGGenerator.inspect_generator("random.MT19937")
        with self.assertRaises(WeakPRNGDetectedError):
            CSPRNGGenerator.inspect_generator("Python_random_module")

    def test_09_predictable_seed_detection(self):
        """Predictable Seed: Sistem zaman damgası gibi tohumların engellendiğini doğrular (CWE-337)."""
        with self.assertRaises(PredictableSeedError):
            CSPRNGGenerator.inspect_generator("custom_rng", seed_type="SYSTEM_TIMESTAMP")

    def test_10_low_entropy_strict_rejection(self):
        """Insufficient Entropy: Düşük entropili verilerin sıkı modda hata fırlatmasını doğrular (CWE-331)."""
        low_entropy_bytes = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        with self.assertRaises(InsufficientEntropyError):
            self.auditor.audit_bytes(low_entropy_bytes, strict_mode=True)

    def test_11_empty_payload_rejection(self):
        """Empty Payload: Boş veri dizisinin InsufficientEntropyError fırlatmasını doğrular (CWE-20)."""
        with self.assertRaises(InsufficientEntropyError):
            self.auditor.audit_bytes(b"", strict_mode=False)

    def test_12_oversized_payload_rejection(self):
        """Payload Limit: 1 MB tavanını aşan tamponların engellendiğini doğrular (CWE-400)."""
        oversized_data = b"X" * 1_000_001
        with self.assertRaises(PayloadLimitExceededError):
            self.auditor.audit_bytes(oversized_data)

    def test_13_null_byte_rejection(self):
        """Null-Byte: İsim veya yoldaki Null-Byte zehirlemesinin engellendiğini doğrular (CWE-158)."""
        with self.assertRaises(NullByteInjectionError):
            CSPRNGGenerator.inspect_generator("safe_rng\x00evil")
        with self.assertRaises(NullByteInjectionError):
            self.auditor.audit_file("safe.bin\x00malicious")

    def test_14_type_validation_rejection(self):
        """Type Validation: Uyumsuz veri tiplerinin TypeValidationError fırlatmasını doğrular (CWE-843)."""
        with self.assertRaises(TypeValidationError):
            EntropyMath.calculate_all("string_not_bytes")  # type: ignore
        with self.assertRaises(TypeValidationError):
            CSPRNGGenerator.generate_key("invalid_bits")  # type: ignore

    def test_15_negative_inputs_json_suite(self):
        """invalid_entropy_inputs.json dosyasındaki 9 negatif senaryonun tamamını doğrular."""
        with open(self.negative_json_path, "r", encoding="utf-8") as f:
            cases = json.load(f)

        self.assertEqual(len(cases), 9)

        for case in cases:
            cid = case["id"]
            # Case 1: WEAK_PRNG_KEYGEN
            if cid == "NEG_01_WEAK_PRNG_KEYGEN":
                with self.assertRaises(WeakPRNGDetectedError):
                    CSPRNGGenerator.inspect_generator(case["algoritma"])
            # Case 2: INSUFFICIENT_ENTROPY_KEY
            elif cid == "NEG_02_INSUFFICIENT_ENTROPY_KEY":
                raw_bytes = bytes.fromhex(case["veri_hex"])
                with self.assertRaises(InsufficientEntropyError):
                    self.auditor.audit_bytes(raw_bytes, strict_mode=True)
            # Case 3: PREDICTABLE_TIME_SEED
            elif cid == "NEG_03_PREDICTABLE_TIME_SEED":
                with self.assertRaises(PredictableSeedError):
                    CSPRNGGenerator.inspect_generator("rng_test", seed_type=case["tohum_tipi"])
            # Case 4: SMALL_ENTROPY_SPACE
            elif cid == "NEG_04_SMALL_ENTROPY_SPACE":
                with self.assertRaises(SmallEntropySpaceError):
                    CSPRNGGenerator.generate_key(bits=case["bit_uzunlugu"])
            # Case 5: EMPTY_PAYLOAD_EVAL
            elif cid == "NEG_05_EMPTY_PAYLOAD_EVAL":
                with self.assertRaises(InsufficientEntropyError):
                    self.auditor.audit_bytes(case["veri"].encode())
            # Case 6: OVERSIZED_BUFFER_DOS
            elif cid == "NEG_06_OVERSIZED_BUFFER_DOS":
                huge_data = b"A" * 1_000_001
                with self.assertRaises(PayloadLimitExceededError):
                    self.auditor.audit_bytes(huge_data)
            # Case 7: NULL_BYTE_INJECTION
            elif cid == "NEG_07_NULL_BYTE_INJECTION":
                with self.assertRaises(NullByteInjectionError):
                    CSPRNGGenerator.inspect_generator(case["etiket"])
            # Case 8: INVALID_TOKEN_LENGTH
            elif cid == "NEG_08_INVALID_TOKEN_LENGTH":
                with self.assertRaises(TypeValidationError):
                    CSPRNGGenerator.generate_token(length_bytes=case["uzunluk"])
            # Case 9: TYPE_CONFUSION
            elif cid == "NEG_09_TYPE_CONFUSION":
                with self.assertRaises(TypeValidationError):
                    self.auditor.audit_bytes(case["girdi"])  # type: ignore


if __name__ == "__main__":
    unittest.main(verbosity=2)
