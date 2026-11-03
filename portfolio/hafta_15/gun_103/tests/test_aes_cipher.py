# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 103: FIPS 197 AES ve Simetrik Şifreleme Kapsamlı Test Paketi.
15 birim test ile FIPS 197, NIST SP 800-38A, CBC, CTR, AEAD, PKCS#7 dolgusu,
desen sızıntısı ve 9 negatif kontrol senaryosu doğrulanır.
"""

# Birim test kütüphanesi
import unittest
# JSON dosya işleme kütüphanesi
import json
# Sistem ve yol araçları
import sys
# Dosya sistemi kütüphanesi
import os

# Test edilen modüllere erişim için ana dizini ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# AES motoru, blok fonksiyonları ve güvenlik istisnalarını içe aktar
from uygulama.aes_cipher_engine import (
    AESCipherEngine,
    encrypt_block,
    decrypt_block,
    key_expansion,
    pkcs7_pad,
    pkcs7_unpad,
    AESCipherError,
    InsecureCipherModeError,
    InvalidKeyLengthError,
    PredictableIVError,
    InvalidIVLengthError,
    InvalidPaddingError,
    AuthenticationTagMismatchError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


class TestAESCipherEngine(unittest.TestCase):
    """FIPS 197 AES şifreleme motoru test sınıfı."""

    def setUp(self) -> None:
        """Ortak test değişkenlerini ve vektör dosyalarını hazırla."""
        # 128-bit standart test anahtarı
        self.key_128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        # 256-bit standart test anahtarı (32 bayt)
        self.key_256 = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        # Standart IV
        self.iv_128 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        # Test metni
        self.duz_metin = "Kurumsal_Kriptografik_Guvenlik_2026!"
        # JSON dosya yolları
        self.vectors_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "aes_known_vectors.json")
        self.negatif_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "invalid_aes_inputs.json")

    def test_01_fips197_single_block_kat(self) -> None:
        """Test 1: NIST FIPS 197 resmi tek blok Known Answer Test (KAT) doğrulaması."""
        with open(self.vectors_path, "r", encoding="utf-8") as f:
            vdata = json.load(f)
        fb = vdata["aes_128_fips197_single_block"]
        k = bytes.fromhex(fb["key_hex"])
        pt = bytes.fromhex(fb["plaintext_hex"])
        expected_ct = fb["expected_ciphertext_hex"]

        w, nr = key_expansion(k)
        ct = encrypt_block(pt, w, nr)
        self.assertEqual(ct.hex(), expected_ct)

        dec = decrypt_block(ct, w, nr)
        self.assertEqual(dec.hex(), pt.hex())

    def test_02_sp800_38a_cbc_vector(self) -> None:
        """Test 2: NIST SP 800-38A resmi CBC modu test vektörü doğrulaması."""
        with open(self.vectors_path, "r", encoding="utf-8") as f:
            vdata = json.load(f)
        cb = vdata["aes_128_cbc_sp800_38a"]
        k = bytes.fromhex(cb["key_hex"])
        iv = bytes.fromhex(cb["iv_hex"])
        pt = bytes.fromhex(cb["plaintext_hex"])
        expected_ct = cb["expected_ciphertext_hex"]

        w, nr = key_expansion(k)
        xored = bytes(a ^ b for a, b in zip(pt, iv))
        ct = encrypt_block(xored, w, nr)
        self.assertEqual(ct.hex(), expected_ct)

    def test_03_sp800_38a_ctr_vector(self) -> None:
        """Test 3: NIST SP 800-38A resmi CTR modu test vektörü doğrulaması."""
        with open(self.vectors_path, "r", encoding="utf-8") as f:
            vdata = json.load(f)
        ct_v = vdata["aes_128_ctr_sp800_38a"]
        k = bytes.fromhex(ct_v["key_hex"])
        ctr_init = bytes.fromhex(ct_v["initial_counter_hex"])
        pt = bytes.fromhex(ct_v["plaintext_hex"])
        expected_ct = ct_v["expected_ciphertext_hex"]

        w, nr = key_expansion(k)
        ks = encrypt_block(ctr_init, w, nr)
        ct = bytes(a ^ b for a, b in zip(pt, ks))
        self.assertEqual(ct.hex(), expected_ct)

    def test_04_aes_256_roundtrip_cbc(self) -> None:
        """Test 4: 256-bit anahtar (14 tur) ile CBC şifreleme ve geri çözme döngüsü."""
        # AES-256 ile şifrele
        res = AESCipherEngine.encrypt_cbc(self.duz_metin, self.key_256)
        self.assertEqual(res.key_bits, 256)
        # AES-256 ile şifreyi çöz
        dec = AESCipherEngine.decrypt_cbc(res.ciphertext_hex, self.key_256, iv=res.iv_hex)
        self.assertEqual(dec.plaintext_str, self.duz_metin)

    def test_05_ecb_pattern_leakage_demonstration(self) -> None:
        """Test 5: ECB modunda özdeş blokların aynı şifreli çıktıyı ürettiğinin kanıtı (CWE-327)."""
        pattern_text = "ORTAK_BLOK_12345ORTAK_BLOK_12345"  # 2 adet 16 baytlık özdeş blok
        res_ecb = AESCipherEngine.encrypt_ecb(pattern_text, self.key_128, strict_mode=False)
        # İlk 16 bayt (32 hex) ile ikinci 16 baytın aynı olduğunu sına
        block1 = res_ecb.ciphertext_hex[:32]
        block2 = res_ecb.ciphertext_hex[32:64]
        self.assertEqual(block1, block2)

        # CBC modunda ise aynı metnin farklı çıktılar ürettiğini sına
        res_cbc = AESCipherEngine.encrypt_cbc(pattern_text, self.key_128)
        cbc_block1 = res_cbc.ciphertext_hex[:32]
        cbc_block2 = res_cbc.ciphertext_hex[32:64]
        self.assertNotEqual(cbc_block1, cbc_block2)

    def test_06_ecb_strict_mode_raises_cwe327(self) -> None:
        """Test 6: Katı güvenlik modunda güvensiz ECB modunun reddedilmesi (CWE-327)."""
        with self.assertRaises(InsecureCipherModeError):
            AESCipherEngine.encrypt_ecb(self.duz_metin, self.key_128, strict_mode=True)

    def test_07_insufficient_key_length_raises_cwe326(self) -> None:
        """Test 7: 16 bayt (128 bit) altındaki yetersiz anahtar uzunluğunun reddi (CWE-326)."""
        kisa_anahtar = b"12345678"  # 8 bayt DES seviyesi
        with self.assertRaises(InvalidKeyLengthError):
            AESCipherEngine.encrypt_cbc(self.duz_metin, kisa_anahtar)

    def test_08_invalid_key_length_raises_cwe326(self) -> None:
        """Test 8: Standart dışı (20 bayt) anahtar uzunluğunun reddi (CWE-326)."""
        gecersiz_anahtar = b"12345678901234567890"  # 20 bayt
        with self.assertRaises(InvalidKeyLengthError):
            AESCipherEngine.encrypt_cbc(self.duz_metin, gecersiz_anahtar)

    def test_09_predictable_static_iv_raises_cwe329(self) -> None:
        """Test 9: Tamamı sıfır veya statik tahmin edilebilir IV kullanımının engellenmesi (CWE-329)."""
        sifir_iv = bytes.fromhex("00000000000000000000000000000000")
        with self.assertRaises(PredictableIVError):
            AESCipherEngine.encrypt_cbc(self.duz_metin, self.key_128, iv=sifir_iv)

    def test_10_invalid_iv_length_raises_cwe329(self) -> None:
        """Test 10: 16 bayttan farklı IV uzunluğu iletiminin engellenmesi (CWE-329)."""
        hatali_iv = b"12345678"  # 8 bayt
        with self.assertRaises(InvalidIVLengthError):
            AESCipherEngine.encrypt_cbc(self.duz_metin, self.key_128, iv=hatali_iv)

    def test_11_pkcs7_corrupt_padding_raises_cwe347(self) -> None:
        """Test 11: Bozuk veya sahte PKCS#7 dolgu baytının deşifrede tespiti (CWE-347)."""
        # Normal şifreleme yap
        res = AESCipherEngine.encrypt_cbc(self.duz_metin, self.key_128)
        # Şifreli metnin son baytını tahrif et (dolgu bozulur)
        ct_bytes = bytearray.fromhex(res.ciphertext_hex)
        ct_bytes[-1] ^= 0xFF
        with self.assertRaises(InvalidPaddingError):
            AESCipherEngine.decrypt_cbc(ct_bytes.hex(), self.key_128, iv=res.iv_hex)

    def test_12_aead_encrypt_then_mac_tampering_raises_cwe353(self) -> None:
        """Test 12: AEAD şifreli metin kurcalandığında etiket uyuşmazlığı tespiti (CWE-353)."""
        mac_key = b"1234567890123456"
        res = AESCipherEngine.encrypt_aead_etm(self.duz_metin, self.key_128, mac_key)
        # Metni kurcalamadan çöz -> Başarılı
        dec_ok = AESCipherEngine.decrypt_aead_etm(
            res.ciphertext_hex, self.key_128, mac_key, iv_hex=res.iv_hex, tag_hex=res.tag_hex
        )
        self.assertEqual(dec_ok.plaintext_str, self.duz_metin)

        # Şifreli metnin ilk baytını kurcala
        ct_tampered = bytearray.fromhex(res.ciphertext_hex)
        ct_tampered[0] ^= 0x01
        with self.assertRaises(AuthenticationTagMismatchError):
            AESCipherEngine.decrypt_aead_etm(
                ct_tampered.hex(), self.key_128, mac_key, iv_hex=res.iv_hex, tag_hex=res.tag_hex
            )

    def test_13_oversized_payload_raises_cwe400(self) -> None:
        """Test 13: 1 MB tavanını aşan büyük metin girdisinin DoS korumasıyla engellenmesi (CWE-400)."""
        dev_veri = "A" * 1_200_000  # 1.2 MB
        with self.assertRaises(PayloadLimitExceededError):
            AESCipherEngine.encrypt_cbc(dev_veri, self.key_128)

    def test_14_type_confusion_raises_cwe843(self) -> None:
        """Test 14: Anahtar veya veri yerine tamsayı iletildiğinde tip hatası fırlatılması (CWE-843)."""
        with self.assertRaises(TypeValidationError):
            AESCipherEngine.encrypt_cbc(self.duz_metin, 987654321)  # type: ignore

    def test_15_negative_json_cases_verification(self) -> None:
        """Test 15: ornek_veri/invalid_aes_inputs.json dosyasındaki 9 negatif senaryonun yürütülmesi."""
        with open(self.negatif_path, "r", encoding="utf-8") as f:
            negatif_vakalar = json.load(f)

        self.assertEqual(len(negatif_vakalar), 9)

        for vaka in negatif_vakalar:
            vid = vaka["id"]
            beklenen = vaka["beklenen_hata"]

            if vid == "NEG_01_INSECURE_ECB_MODE_USAGE":
                with self.assertRaises(InsecureCipherModeError):
                    AESCipherEngine.encrypt_ecb("test", self.key_128, strict_mode=True)

            elif vid == "NEG_02_INSUFFICIENT_KEY_LENGTH":
                with self.assertRaises(InvalidKeyLengthError):
                    AESCipherEngine.encrypt_cbc("test", bytes(vaka["key_boyut"]))

            elif vid == "NEG_03_INVALID_KEY_LENGTH":
                with self.assertRaises(InvalidKeyLengthError):
                    AESCipherEngine.encrypt_cbc("test", bytes(vaka["key_boyut"]))

            elif vid == "NEG_04_PREDICTABLE_STATIC_IV":
                with self.assertRaises(PredictableIVError):
                    AESCipherEngine.encrypt_cbc("test", self.key_128, iv=bytes.fromhex(vaka["iv_hex"]))

            elif vid == "NEG_05_INVALID_IV_LENGTH":
                with self.assertRaises(InvalidIVLengthError):
                    AESCipherEngine.encrypt_cbc("test", self.key_128, iv=bytes(vaka["iv_boyut"]))

            elif vid == "NEG_06_PKCS7_CORRUPT_PADDING":
                res = AESCipherEngine.encrypt_cbc("test", self.key_128)
                ct_mod = bytearray.fromhex(res.ciphertext_hex)
                ct_mod[-1] ^= 0x55
                with self.assertRaises(InvalidPaddingError):
                    AESCipherEngine.decrypt_cbc(ct_mod.hex(), self.key_128, iv=res.iv_hex)

            elif vid == "NEG_07_CIPHERTEXT_TAMPERING_AEAD":
                mac_k = b"1234567890123456"
                res = AESCipherEngine.encrypt_aead_etm("test", self.key_128, mac_k)
                ct_mod = bytearray.fromhex(res.ciphertext_hex)
                ct_mod[0] ^= 0x01
                with self.assertRaises(AuthenticationTagMismatchError):
                    AESCipherEngine.decrypt_aead_etm(ct_mod.hex(), self.key_128, mac_k, iv_hex=res.iv_hex, tag_hex=res.tag_hex)

            elif vid == "NEG_08_OVERSIZED_PLAINTEXT_DOS":
                with self.assertRaises(PayloadLimitExceededError):
                    AESCipherEngine.encrypt_cbc("B" * vaka["boyut_bayt"], self.key_128)

            elif vid == "NEG_09_TYPE_CONFUSION":
                with self.assertRaises(TypeValidationError):
                    AESCipherEngine.encrypt_cbc("test", vaka["hatali_anahtar"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
