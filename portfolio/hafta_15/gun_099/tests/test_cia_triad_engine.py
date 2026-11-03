# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 099: CIA Triad ve Güvenlik Nitelikleri Birim Test Paketi.
Gizlilik, bütünlük, erişilebilirlik, inkar edilemezlik ve negatif kontrol
senaryolarını matematiksel ve mantıksal doğrulukla test eder.
"""

# Standart birim testi kütüphanesi
import unittest
# Dosya ve dizin yol işlemleri modülü
import os
# Sistem parametreleri ve yol modülü
import sys
# JSON veri okuma ve ayrıştırma modülü
import json
# Kriptografik rastgele bayt üretimi
import secrets

# Test edilecek yerel modülleri içe aktarabilmek için ana yolu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor sınıflarını ve istisnalarını içe aktar
from uygulama.cia_triad_engine import (
    CIASecurityEngine,
    ConfidentialityGuard,
    IntegrityGuard,
    AvailabilityGuard,
    NonRepudiationAuditor,
    CIASecurityVerdict,
    CIASecurityError,
    ConfidentialityBreachError,
    IntegrityVerificationError,
    AvailabilityRateLimitExceededError,
    PayloadLimitExceededError,
    AuditChainCorruptedError,
    NullByteInjectionError,
    InsecureKeyLengthError,
    TypeValidationError
)


class TestCIATriadEngine(unittest.TestCase):
    """CIA Triad ve Güvenlik Nitelikleri test paketi sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        # 32 baytlık (256-bit) güvenli test anahtarı
        self.master_key = b"G099_TEST_SECURE_KEY_123456789012"
        # Motoru başlat
        self.engine = CIASecurityEngine(master_key=self.master_key)
        # Örnek veri dizin yolunu belirle
        self.ornek_veri_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ornek_veri"))
        # Negatif test veri kümesi yolu
        self.negative_json_path = os.path.join(self.ornek_veri_dir, "invalid_cia_inputs.json")
        # Örnek işlem verisi yolu
        self.sample_tx_path = os.path.join(self.ornek_veri_dir, "sample_transaction.json")

    def test_01_confidentiality_encryption_decryption(self):
        """Gizlilik: Simetrik akış şifreleme ve şifre çözmenin doğruluğunu test eder."""
        acik_metin = "Çok Gizli Siber Güvenlik Raporu 2026"
        sifreli_hex = ConfidentialityGuard.encrypt(acik_metin, self.master_key)
        cozulmus_metin = ConfidentialityGuard.decrypt(sifreli_hex, self.master_key)
        self.assertEqual(acik_metin, cozulmus_metin)
        self.assertNotEqual(acik_metin, sifreli_hex)

    def test_02_confidentiality_leak_detection(self):
        """Gizlilik: Açık metindeki hassas kart ve parola sızıntılarının tespitini doğrular."""
        temiz_veri = "Genel duyuru: Sistem bakımı bu gece yapılacaktır."
        sizintili_veri = "Kullanıcı kartı: 4543-1234-5678-9999 parola: GizliSifre!"
        self.assertFalse(ConfidentialityGuard.inspect_plaintext_leak(temiz_veri))
        self.assertTrue(ConfidentialityGuard.inspect_plaintext_leak(sizintili_veri))

    def test_03_confidentiality_strict_breach_error(self):
        """Gizlilik: Sıkı modda şifrelenmemiş hassas veri iletiminin hata fırlatmasını doğrular."""
        sizintili_paket = "IBAN: TR330006100511123456789001 parola=123456"
        with self.assertRaises(ConfidentialityBreachError):
            self.engine.evaluate_transaction(
                payload_data=sizintili_paket,
                is_encrypted=False,
                strict_mode=True
            )

    def test_04_integrity_seal_and_verify_pass(self):
        """Bütünlük: Kriptografik mühürleme ve doğrulamanın başarıyla çalıştığını test eder."""
        mesaj = "TRANSFER_ID=9901&TUTAR=5000&DURUM=ONAYLANDI"
        muhur = IntegrityGuard.seal_message(mesaj, self.master_key)
        self.assertTrue(IntegrityGuard.verify_seal(mesaj, muhur, self.master_key))

    def test_05_integrity_tampering_bitflip_fails(self):
        """Bütünlük: Mesajdaki 1 karakterlik tahrifatın mührü geçersiz kıldığını doğrular."""
        orijinal = "TRANSFER_ID=9901&TUTAR=5000"
        tahrif = "TRANSFER_ID=9901&TUTAR=9000"
        muhur = IntegrityGuard.seal_message(orijinal, self.master_key)
        self.assertFalse(IntegrityGuard.verify_seal(tahrif, muhur, self.master_key))

    def test_06_integrity_strict_tamper_error(self):
        """Bütünlük: Sıkı modda tahrif edilmiş mührün IntegrityVerificationError fırlatmasını doğrular."""
        mesaj = "TRANSFER=1000"
        sahte_muhur = "0" * 64
        with self.assertRaises(IntegrityVerificationError):
            self.engine.evaluate_transaction(
                payload_data=mesaj,
                provided_seal=sahte_muhur,
                strict_mode=True
            )

    def test_07_availability_rate_limiting(self):
        """Erişilebilirlik: Saniyede izin verilen limit aşıldığında DoS korumasını doğrular."""
        guard = AvailabilityGuard(max_requests_per_window=10, window_seconds=1.0)
        # İlk 10 istek başarılı olmalı
        for _ in range(10):
            self.assertTrue(guard.record_and_check_request("client_alpha"))
        # 11. istek hata fırlatmalı
        with self.assertRaises(AvailabilityRateLimitExceededError):
            guard.record_and_check_request("client_alpha")

    def test_08_availability_payload_limit_dos(self):
        """Erişilebilirlik: 1 MB tavanını aşan verilerin DoS korumasıyla engellenmesini doğrular."""
        oversized_str = "A" * 1_000_001
        with self.assertRaises(PayloadLimitExceededError):
            AvailabilityGuard.validate_payload_size(oversized_str)

    def test_09_non_repudiation_chain_verification(self):
        """İnkar Edilemezlik: Sıralı denetim zincirinin kriptografik bütünlüğünü doğrular."""
        auditor = NonRepudiationAuditor(self.master_key)
        auditor.append_log("LOGIN", "admin", "Oturum açıldı")
        auditor.append_log("CREATE_KEY", "admin", "Yeni API anahtarı üretildi")
        auditor.append_log("LOGOUT", "admin", "Güvenli çıkış yapıldı")
        self.assertEqual(len(auditor.chain), 4)  # Genesis + 3 kayıt
        is_valid, bad_idx = auditor.verify_chain_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(bad_idx)

    def test_10_non_repudiation_chain_corruption(self):
        """İnkar Edilemezlik: Aradaki bir kaydın mührü bozulduğunda zincirin ihlali yakalamasını doğrular."""
        auditor = NonRepudiationAuditor(self.master_key)
        auditor.append_log("ACTION_1", "user1", "Veri 1")
        auditor.append_log("ACTION_2", "user2", "Veri 2")
        # 1. kaydın mührünü sahteleştir
        auditor.chain[1].dijital_muhur = "deadbeef" * 8
        is_valid, bad_idx = auditor.verify_chain_integrity()
        self.assertFalse(is_valid)
        self.assertEqual(bad_idx, 1)

    def test_11_null_byte_rejection(self):
        """Zararlı Null-Byte (\x00) zehirlemelerinin tüm katmanlarda engellendiğini doğrular."""
        malicious_str = "TRANSFER\x00_ATTACK"
        with self.assertRaises(NullByteInjectionError):
            ConfidentialityGuard.encrypt(malicious_str, self.master_key)
        with self.assertRaises(NullByteInjectionError):
            IntegrityGuard.seal_message(malicious_str, self.master_key)

    def test_12_insecure_key_length_rejection(self):
        """16 bayttan kısa güvensiz anahtarların reddedildiğini doğrular (CWE-326)."""
        short_key = b"short_8b"
        with self.assertRaises(InsecureKeyLengthError):
            ConfidentialityGuard.encrypt("test", short_key)
        with self.assertRaises(InsecureKeyLengthError):
            IntegrityGuard.seal_message("test", short_key)
        with self.assertRaises(InsecureKeyLengthError):
            NonRepudiationAuditor(short_key)

    def test_13_type_validation_rejection(self):
        """Uyumsuz veri tiplerinin TypeValidationError fırlatmasını doğrular (CWE-843)."""
        with self.assertRaises(TypeValidationError):
            ConfidentialityGuard.inspect_plaintext_leak(12345)  # type: ignore
        with self.assertRaises(TypeValidationError):
            IntegrityGuard.seal_message("metin", "string_anahtar")  # type: ignore

    def test_14_full_cia_transaction_evaluation_pass(self):
        """Örnek finansal işlemin tüm CIA kriterlerinden 100 tam puanla geçmesini doğrular."""
        with open(self.sample_tx_path, "r", encoding="utf-8") as f:
            tx_data = f.read()

        seal = IntegrityGuard.seal_message(tx_data, self.master_key)
        verdict = self.engine.evaluate_transaction(
            payload_data=tx_data,
            asset_name="sample_transaction.json",
            is_encrypted=True,
            provided_seal=seal,
            client_id="trusted_payment_gateway",
            strict_mode=False
        )

        self.assertEqual(verdict.gizlilik_skoru, 25)
        self.assertEqual(verdict.butunluk_skoru, 25)
        self.assertEqual(verdict.erisilebilirlik_skoru, 25)
        self.assertEqual(verdict.inkar_edilemezlik_skoru, 25)
        self.assertEqual(verdict.toplam_skor, 100)
        self.assertEqual(verdict.durum, "PASS")
        self.assertEqual(verdict.ihlal_sayisi, 0)

    def test_15_negative_inputs_json_suite(self):
        """invalid_cia_inputs.json dosyasındaki 9 negatif senaryonun tamamını doğrular."""
        with open(self.negative_json_path, "r", encoding="utf-8") as f:
            cases = json.load(f)

        self.assertEqual(len(cases), 9)

        for case in cases:
            cid = case["id"]
            # Case 1: CONFIDENTIALITY_PLAINTEXT_LEAK
            if cid == "NEG_01_CONFIDENTIALITY_PLAINTEXT_LEAK":
                with self.assertRaises(ConfidentialityBreachError):
                    self.engine.evaluate_transaction(
                        payload_data=case["veri"],
                        is_encrypted=False,
                        strict_mode=True
                    )
            # Case 2: INTEGRITY_TAMPERED_PAYLOAD
            elif cid == "NEG_02_INTEGRITY_TAMPERED_PAYLOAD":
                muhur = IntegrityGuard.seal_message(case["orijinal_mesaj"], self.master_key)
                self.assertFalse(IntegrityGuard.verify_seal(case["tahrif_edilmis_mesaj"], muhur, self.master_key))
            # Case 3: INTEGRITY_INVALID_DIGEST
            elif cid == "NEG_03_INTEGRITY_INVALID_DIGEST":
                with self.assertRaises(IntegrityVerificationError):
                    self.engine.evaluate_transaction(
                        payload_data="valid_msg",
                        provided_seal=case["sahte_hmac"],
                        strict_mode=True
                    )
            # Case 4: AVAILABILITY_FLOOD_DOS
            elif cid == "NEG_04_AVAILABILITY_FLOOD_DOS":
                guard = AvailabilityGuard(max_requests_per_window=case["limit"], window_seconds=1.0)
                with self.assertRaises(AvailabilityRateLimitExceededError):
                    for _ in range(case["istek_adedi"]):
                        guard.record_and_check_request("attacker_ip")
            # Case 5: AVAILABILITY_OVERSIZED_BUFFER
            elif cid == "NEG_05_AVAILABILITY_OVERSIZED_BUFFER":
                oversized_text = "OVERSIZED_BUFFER_EXCEEDING_LIMIT_" + ("X" * 100)
                with self.assertRaises(PayloadLimitExceededError):
                    AvailabilityGuard.validate_payload_size(oversized_text)
            # Case 6: NON_REPUDIATION_CHAIN_BREAK
            elif cid == "NEG_06_NON_REPUDIATION_CHAIN_BREAK":
                auditor = NonRepudiationAuditor(self.master_key)
                auditor.append_log("TEST", "usr", "d1")
                auditor.chain[1].onceki_hash = case["sahte_onceki_hash"]
                ok, _ = auditor.verify_chain_integrity()
                self.assertFalse(ok)
            # Case 7: NULL_BYTE_INJECTION
            elif cid == "NEG_07_NULL_BYTE_INJECTION":
                with self.assertRaises(NullByteInjectionError):
                    ConfidentialityGuard.inspect_plaintext_leak(case["veri"])
            # Case 8: INVALID_KEY_LENGTH
            elif cid == "NEG_08_INVALID_KEY_LENGTH":
                with self.assertRaises(InsecureKeyLengthError):
                    ConfidentialityGuard.encrypt("data", case["anahtar"].encode())
            # Case 9: TYPE_CONFUSION
            elif cid == "NEG_09_TYPE_CONFUSION":
                with self.assertRaises(TypeValidationError):
                    ConfidentialityGuard.inspect_plaintext_leak(case["veri"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
