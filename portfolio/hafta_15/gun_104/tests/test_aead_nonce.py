# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 104: AEAD ve Nonce Yönetimi Kapsamlı Test Paketi.
15 birim test ile AEAD bütünlüğü, AAD bağlamı, Nonce tekrarı (CWE-323),
Two-Time Pad matematiksel iptali, SIV modu ve 9 negatif kontrol senaryosu doğrulanır.
"""

# Birim test kütüphanesi
import unittest
# JSON veri dönüştürme modülü
import json
# Sistem ve yol araçları
import sys
# Dosya sistemi araçları
import os

# Ana dizini modül arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# AEAD motoru, durum takipçisi ve güvenlik istisnalarını içe aktar
from uygulama.aead_nonce_engine import (
    AEADNonceEngine,
    StatefulNonceTracker,
    AEADResult,
    TwoTimePadAnalysis,
    AEADEngineError,
    NonceReuseDetectedError,
    InsecureNonceLengthError,
    PredictableNonceError,
    AuthenticationTagMismatchError,
    InvalidKeyLengthError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    TypeValidationError
)


class TestAEADNonceEngine(unittest.TestCase):
    """AEAD ve Nonce güvenlik motoru test sınıfı."""

    def setUp(self) -> None:
        """Ortak test değişkenlerini ve veri yollarını hazırla."""
        # 128-bit standart test anahtarı
        self.test_key = b"1234567890abcdef"
        # 96-bit (12 bayt) standart Nonce
        self.test_nonce = b"abcdef123456"
        # Test düz metni
        self.duz_metin = "Guvenli_AEAD_Mesaji_2026!"
        # İlişkili doğrulanmış açık veri (AAD)
        self.aad = "kullanici=ahmet;rol=admin;oturum=98765"
        # Bağımsız test takip önbelleği
        self.tracker = StatefulNonceTracker()
        # Negatif girdi JSON dosyası
        self.negatif_json_yolu = os.path.join(
            os.path.dirname(__file__), "..", "ornek_veri", "invalid_aead_inputs.json"
        )

    def test_01_aead_encrypt_decrypt_roundtrip(self) -> None:
        """Test 1: Standart AEAD şifreleme ve başarılı deşifre döngüsü."""
        # Rastgele Nonce ile şifrele
        res = AEADNonceEngine.encrypt_aead(self.duz_metin, self.test_key, tracker=self.tracker)
        # Şifreyi çöz
        pt_bytes, pt_str = AEADNonceEngine.decrypt_aead(
            res.ciphertext_hex, self.test_key, res.nonce_hex, res.tag_hex
        )
        self.assertEqual(pt_str, self.duz_metin)

    def test_02_aead_with_aad_authentication(self) -> None:
        """Test 2: İlişkili açık verinin (AAD) etiket mühürlemesine dahil edilmesi."""
        res = AEADNonceEngine.encrypt_aead(
            self.duz_metin, self.test_key, associated_data=self.aad, tracker=self.tracker
        )
        pt_bytes, pt_str = AEADNonceEngine.decrypt_aead(
            res.ciphertext_hex, self.test_key, res.nonce_hex, res.tag_hex, associated_data=self.aad
        )
        self.assertEqual(pt_str, self.duz_metin)

    def test_03_aad_tampering_raises_cwe345(self) -> None:
        """Test 3: Şifre çözmede AAD'nin tek bir karakter bile tahrif edilmesinin engellenmesi (CWE-345)."""
        res = AEADNonceEngine.encrypt_aead(
            self.duz_metin, self.test_key, associated_data=self.aad, tracker=self.tracker
        )
        sahte_aad = "kullanici=ahmet;rol=SUPERADMIN;oturum=98765"  # Rol değiştirildi!
        with self.assertRaises(AuthenticationTagMismatchError):
            AEADNonceEngine.decrypt_aead(
                res.ciphertext_hex, self.test_key, res.nonce_hex, res.tag_hex, associated_data=sahte_aad
            )

    def test_04_ciphertext_tampering_raises_cwe353(self) -> None:
        """Test 4: Şifreli metindeki tek bir bit değişikliğinin (Bit-Flipping) tespiti (CWE-353)."""
        res = AEADNonceEngine.encrypt_aead(self.duz_metin, self.test_key, tracker=self.tracker)
        ct_bytes = bytearray.fromhex(res.ciphertext_hex)
        ct_bytes[0] ^= 0x01  # İlk biti ters çevir
        with self.assertRaises(AuthenticationTagMismatchError):
            AEADNonceEngine.decrypt_aead(
                ct_bytes.hex(), self.test_key, res.nonce_hex, res.tag_hex
            )

    def test_05_stateful_nonce_reuse_detection_cwe323(self) -> None:
        """Test 5: Aynı anahtar ile daha önce kullanılan bir Nonce'un tekrarının engellenmesi (CWE-323)."""
        # İlk kullanım -> Başarılı
        AEADNonceEngine.encrypt_aead("Mesaj 1", self.test_key, nonce=self.test_nonce, tracker=self.tracker)
        # İkinci kullanım aynı anahtar ve aynı Nonce -> NonceReuseDetectedError fırlatılmalı
        with self.assertRaises(NonceReuseDetectedError):
            AEADNonceEngine.encrypt_aead("Mesaj 2", self.test_key, nonce=self.test_nonce, tracker=self.tracker)

    def test_06_different_key_same_nonce_allowed(self) -> None:
        """Test 6: Farklı bir anahtar ile aynı Nonce'un kullanılmasına izin verilmesi (Farklı anahtar akışı)."""
        farkli_anahtar = b"fedcba0987654321"
        # İlk anahtarla kullan
        AEADNonceEngine.encrypt_aead("Mesaj A", self.test_key, nonce=self.test_nonce, tracker=self.tracker)
        # Farklı anahtarla aynı Nonce kullanılabilmeli (hata vermez)
        res2 = AEADNonceEngine.encrypt_aead("Mesaj B", farkli_anahtar, nonce=self.test_nonce, tracker=self.tracker)
        self.assertEqual(res2.nonce_hex, self.test_nonce.hex())

    def test_07_two_time_pad_xor_cancellation(self) -> None:
        """Test 7: C1 ⊕ C2 == P1 ⊕ P2 matematiksel eşitliğinin kanıtı (Anahtar Akışı İptali)."""
        p1 = "KREDI_KARTI_1111"
        p2 = "TRANSFER_TUTAR99"
        analiz = AEADNonceEngine.simulate_two_time_pad_leakage(p1, p2, self.test_key, self.test_nonce)
        self.assertTrue(analiz.is_identical_leakage)
        self.assertEqual(analiz.c1_xor_c2_hex, analiz.p1_xor_p2_hex)

    def test_08_crib_dragging_demonstration(self) -> None:
        """Test 8: Two-Time Pad zafiyetinde bilinen kelime (crib) ile ikinci metnin açığa çıkması."""
        p1 = "KREDI_KARTI_NO=4111222233334444_CVV=999"
        p2 = "TRANSFER_TUTAR=0000500000_TL_ALICI=AHM"
        analiz = AEADNonceEngine.simulate_two_time_pad_leakage(p1, p2, self.test_key, self.test_nonce)
        self.assertTrue(analiz.crib_drag_match)

    def test_09_siv_deterministic_nonce_mode(self) -> None:
        """Test 9: SIV (Synthetic IV) modunda aynı metin için deterministik Nonce türetilmesi."""
        res1 = AEADNonceEngine.encrypt_aead(self.duz_metin, self.test_key, associated_data=self.aad, use_siv=True)
        res2 = AEADNonceEngine.encrypt_aead(self.duz_metin, self.test_key, associated_data=self.aad, use_siv=True)
        # SIV modunda aynı metin aynı Nonce'u üretir ancak farklı metin farklı Nonce üretir
        self.assertEqual(res1.nonce_hex, res2.nonce_hex)
        self.assertEqual(res1.ciphertext_hex, res2.ciphertext_hex)

        # Farklı metinle çağır
        res3 = AEADNonceEngine.encrypt_aead("BaskaMetin", self.test_key, associated_data=self.aad, use_siv=True)
        self.assertNotEqual(res1.nonce_hex, res3.nonce_hex)

    def test_10_short_nonce_raises_cwe326(self) -> None:
        """Test 10: 12 bayt (96 bit) altındaki yetersiz Nonce uzunluğunun engellenmesi (CWE-326)."""
        kisa_nonce = b"12345678"  # 8 bayt
        with self.assertRaises(InsecureNonceLengthError):
            AEADNonceEngine.encrypt_aead(self.duz_metin, self.test_key, nonce=kisa_nonce, tracker=self.tracker)

    def test_11_predictable_static_nonce_raises_cwe329(self) -> None:
        """Test 11: Tamamı sıfırlardan oluşan tahmin edilebilir Nonce'un engellenmesi (CWE-329)."""
        sifir_nonce = bytes.fromhex("000000000000000000000000")
        with self.assertRaises(PredictableNonceError):
            AEADNonceEngine.encrypt_aead(self.duz_metin, self.test_key, nonce=sifir_nonce, tracker=self.tracker)

    def test_12_invalid_key_length_raises_cwe326(self) -> None:
        """Test 12: Standart dışı (24 bayt) anahtar uzunluğunun engellenmesi (CWE-326)."""
        gecersiz_key = b"123456789012345678901234"  # 24 bayt
        with self.assertRaises(InvalidKeyLengthError):
            AEADNonceEngine.encrypt_aead(self.duz_metin, gecersiz_key, tracker=self.tracker)

    def test_13_null_byte_in_plaintext_raises_cwe158(self) -> None:
        """Test 13: Düz metinde Null-Byte (\x00) enjeksiyonunun engellenmesi (CWE-158)."""
        zararli = "ZararliMetin\x00SaldırganEkstrası"
        with self.assertRaises(NullByteInjectionError):
            AEADNonceEngine.encrypt_aead(zararli, self.test_key, tracker=self.tracker)

    def test_14_oversized_payload_raises_cwe400(self) -> None:
        """Test 14: 1 MB tavanını aşan aşırı büyük verinin DoS korumasıyla engellenmesi (CWE-400)."""
        dev_veri = "X" * 1_200_000
        with self.assertRaises(PayloadLimitExceededError):
            AEADNonceEngine.encrypt_aead(dev_veri, self.test_key, tracker=self.tracker)

    def test_15_negative_json_cases_verification(self) -> None:
        """Test 15: ornek_veri/invalid_aead_inputs.json içindeki 9 negatif senaryonun yürütülmesi."""
        with open(self.negatif_json_yolu, "r", encoding="utf-8") as f:
            negatif_vakalar = json.load(f)

        self.assertEqual(len(negatif_vakalar), 9)

        for vaka in negatif_vakalar:
            vid = vaka["id"]
            beklenen = vaka["beklenen_hata"]

            if vid == "NEG_01_NONCE_REUSE_DETECTED":
                local_tr = StatefulNonceTracker()
                AEADNonceEngine.encrypt_aead("test1", self.test_key, nonce=self.test_nonce, tracker=local_tr)
                with self.assertRaises(NonceReuseDetectedError):
                    AEADNonceEngine.encrypt_aead("test2", self.test_key, nonce=self.test_nonce, tracker=local_tr)

            elif vid == "NEG_02_INSUFFICIENT_NONCE_LENGTH":
                with self.assertRaises(InsecureNonceLengthError):
                    AEADNonceEngine.encrypt_aead("test", self.test_key, nonce=bytes(vaka["nonce_boyut"]), tracker=self.tracker)

            elif vid == "NEG_03_PREDICTABLE_STATIC_NONCE":
                with self.assertRaises(PredictableNonceError):
                    AEADNonceEngine.encrypt_aead("test", self.test_key, nonce=bytes.fromhex(vaka["nonce_hex"]), tracker=self.tracker)

            elif vid == "NEG_04_AUTH_TAG_FORGERY":
                res = AEADNonceEngine.encrypt_aead("test", self.test_key, tracker=self.tracker)
                sahte_tag = bytes.fromhex(res.tag_hex)
                sahte_tag_bytes = bytes([sahte_tag[0] ^ 0xFF]) + sahte_tag[1:]
                with self.assertRaises(AuthenticationTagMismatchError):
                    AEADNonceEngine.decrypt_aead(res.ciphertext_hex, self.test_key, res.nonce_hex, sahte_tag_bytes.hex())

            elif vid == "NEG_05_AAD_METADATA_MANIPULATION":
                res = AEADNonceEngine.encrypt_aead("test", self.test_key, associated_data="admin=false", tracker=self.tracker)
                with self.assertRaises(AuthenticationTagMismatchError):
                    AEADNonceEngine.decrypt_aead(res.ciphertext_hex, self.test_key, res.nonce_hex, res.tag_hex, associated_data=vaka["sahte_aad"])

            elif vid == "NEG_06_KEY_LENGTH_INVALID":
                with self.assertRaises(InvalidKeyLengthError):
                    AEADNonceEngine.encrypt_aead("test", bytes(vaka["key_boyut"]), tracker=self.tracker)

            elif vid == "NEG_07_NULL_BYTE_INJECTION":
                with self.assertRaises(NullByteInjectionError):
                    AEADNonceEngine.encrypt_aead(vaka["zararli_veri"], self.test_key, tracker=self.tracker)

            elif vid == "NEG_08_OVERSIZED_PAYLOAD_DOS":
                with self.assertRaises(PayloadLimitExceededError):
                    AEADNonceEngine.encrypt_aead("Y" * vaka["boyut_bayt"], self.test_key, tracker=self.tracker)

            elif vid == "NEG_09_TYPE_CONFUSION":
                with self.assertRaises(TypeValidationError):
                    AEADNonceEngine.encrypt_aead("test", vaka["hatali_girdi"], tracker=self.tracker)


if __name__ == "__main__":
    unittest.main(verbosity=2)
