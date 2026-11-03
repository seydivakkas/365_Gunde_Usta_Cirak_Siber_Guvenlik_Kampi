# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 106: Asimetrik Kriptografi, RSA ve Güvenli Dolgu (OAEP) Kapsamlı Birim Testleri.
15 Birim testi (%100 PASS hedefi), negatif kontroller, matematiksel doğrulama
ve zafiyet simülasyonlarını içerir.
"""

# Standart unittest test kütüphanesi
import unittest
# Matematiksel ve sistem fonksiyonları
import math
import os
import sys

# Test edilen motor modülünün yolunu sistem yoluna ekleme
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
APP_DIR = os.path.join(PARENT_DIR, "uygulama")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

# Test edilecek sınıfları ve matematiksel fonksiyonları içe aktarma
from asymmetric_crypto_engine import (
    AsymmetricCryptoEngine,
    RSAPublicKey,
    RSAPrivateKey,
    is_probable_prime,
    generate_prime,
    extended_gcd,
    modular_inverse,
    mgf1,
    oaep_encode,
    oaep_decode,
    WeakKeySizeError,
    InvalidExponentError,
    MessageTooLargeError,
    OAEPPaddingError,
    MalformedKeyError,
    TextbookRSAMalleabilityDetected
)


class TestAsymmetricCrypto(unittest.TestCase):
    """Asimetrik kriptografi matematiksel ve yazılımsal güvenlik testleri."""

    @classmethod
    def setUpClass(cls):
        """Tüm testler için ortak deterministik 1024 bitlik test anahtarı üretir (SHA-256 OAEP için k=128)."""
        cls.pub_key, cls.priv_key = AsymmetricCryptoEngine.generate_keypair(bits=1024)

    def test_01_miller_rabin_known_primes_and_composites(self):
        """1. Miller-Rabin algoritması bilinen asal ve bileşik sayıları doğru tespit etmelidir."""
        known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 65537, 2147483647]
        for p in known_primes:
            self.assertTrue(is_probable_prime(p, k=10), f"{p} asal olarak tespit edilmeliydi.")

        known_composites = [4, 6, 8, 9, 15, 21, 561, 1105, 1729, 65535]
        for c in known_composites:
            self.assertFalse(is_probable_prime(c, k=10), f"{c} bileşik sayı olarak tespit edilmeliydi.")

    def test_02_extended_euclidean_algorithm_identity(self):
        """2. Genişletilmiş Öklid algoritması a*x + b*y = gcd(a, b) denklemini sağlamalıdır."""
        test_pairs = [(240, 46), (65537, 1000), (12345, 6789), (17, 31)]
        for a, b in test_pairs:
            gcd_val, x, y = extended_gcd(a, b)
            self.assertEqual(a * x + b * y, gcd_val)
            self.assertEqual(math.gcd(a, b), gcd_val)

    def test_03_modular_inverse_correctness(self):
        """3. Modüler ters hesaplaması e * d ≡ 1 (mod phi) eşitliğini sağlamalıdır."""
        e = 65537
        phi = (101 - 1) * (103 - 1)  # 100 * 102 = 10200
        d = modular_inverse(e, phi)
        self.assertEqual((e * d) % phi, 1)

    def test_04_prime_generation_bit_length(self):
        """4. Güvenli asal sayı üretici hedeflenen bit uzunluğunda ve asal sayılar üretmelidir."""
        for target_bits in (32, 64, 128):
            p = generate_prime(target_bits)
            self.assertEqual(p.bit_length(), target_bits)
            self.assertTrue(is_probable_prime(p))

    def test_05_rsa_keypair_generation_validity(self):
        """5. Üretilen RSA anahtar çiftinin matematiksel parametreleri tutarlı olmalıdır."""
        pub, priv = AsymmetricCryptoEngine.generate_keypair(bits=512)
        self.assertEqual(pub.n, priv.n)
        self.assertEqual(pub.e, priv.e)
        self.assertEqual(pub.bit_length, 512)
        phi = (priv.p - 1) * (priv.q - 1)
        self.assertEqual((pub.e * priv.d) % phi, 1)

    def test_06_rsa_raw_textbook_encryption_decryption(self):
        """6. Düz (Textbook) RSA şifreleme ve çözme döngüsü mesajı aslına döndürmelidir."""
        message_int = 123456789
        cipher_int = self.pub_key.encrypt_raw(message_int)
        decrypted_int = self.priv_key.decrypt_raw(cipher_int)
        self.assertEqual(decrypted_int, message_int)

    def test_07_mgf1_mask_generation(self):
        """7. MGF1 maske üretim fonksiyonu istenen uzunlukta deterministik bayt üretmelidir."""
        seed = b"test_seed_123456"
        mask1 = mgf1(seed, mask_len=64)
        mask2 = mgf1(seed, mask_len=64)
        self.assertEqual(len(mask1), 64)
        self.assertEqual(mask1, mask2)
        # Farklı tohum farklı maske üretmelidir
        diff_mask = mgf1(b"other_seed_99999", mask_len=64)
        self.assertNotEqual(mask1, diff_mask)

    def test_08_oaep_encode_decode_roundtrip(self):
        """8. RSA-OAEP dolgulama ve çözme döngüsü veriyi kayıpsız kurtarmalıdır."""
        k = 128  # 1024 bit modül için 128 bayt
        original_msg = b"Siber Guvenlik 365 Gun"
        em = oaep_encode(original_msg, k=k)
        self.assertEqual(len(em), k)
        recovered_msg = oaep_decode(em, k=k)
        self.assertEqual(recovered_msg, original_msg)

    def test_09_oaep_label_binding(self):
        """9. Farklı etiket (label) ile OAEP çözümü dolgu hatası fırlatmalıdır (CWE-780)."""
        k = 128
        msg = b"Etiketli Guvenli Mesaj"
        em = oaep_encode(msg, k=k, label=b"dogru_etiket")
        with self.assertRaises(OAEPPaddingError):
            oaep_decode(em, k=k, label=b"yanlis_etiket")

    def test_10_oaep_tamper_detection_in_ciphertext(self):
        """10. Şifreli metin baytlarında tahrifat yapıldığında OAEP çözümü başarısız olmalıdır."""
        msg = b"Tahrifat Deneyi"
        ciphertext = bytearray(self.pub_key.encrypt_oaep(msg))
        # 10. baytı tersine çevirerek manipüle ediyoruz
        ciphertext[10] ^= 0xFF
        with self.assertRaises(OAEPPaddingError):
            self.priv_key.decrypt_oaep(bytes(ciphertext))

    def test_11_key_serialization_to_dict_and_from_dict(self):
        """11. Anahtarlar sözlük (dict) formatına dönüştürülüp hatasız geri yüklenebilmelidir."""
        pub_dict = self.pub_key.to_dict()
        restored_pub = RSAPublicKey.from_dict(pub_dict)
        self.assertEqual(self.pub_key.n, restored_pub.n)
        self.assertEqual(self.pub_key.e, restored_pub.e)

        priv_dict = self.priv_key.to_dict()
        restored_priv = RSAPrivateKey.from_dict(priv_dict)
        self.assertEqual(self.priv_key.d, restored_priv.d)
        self.assertEqual(self.priv_key.n, restored_priv.n)

    def test_12_weak_key_size_rejection(self):
        """12. 512 bitin altındaki zayıf anahtar üretimi WeakKeySizeError ile reddedilmelidir (CWE-326)."""
        with self.assertRaises(WeakKeySizeError):
            AsymmetricCryptoEngine.generate_keypair(bits=256)

    def test_13_invalid_public_exponent_rejection(self):
        """13. Çift sayı veya 1'e eşit/küçük genel üsler InvalidExponentError fırlatmalıdır (CWE-327)."""
        with self.assertRaises(InvalidExponentError):
            AsymmetricCryptoEngine.generate_keypair(bits=512, public_exponent=65536)
        with self.assertRaises(InvalidExponentError):
            AsymmetricCryptoEngine.generate_keypair(bits=512, public_exponent=1)

    def test_14_textbook_rsa_malleability_detection(self):
        """14. Düz RSA'da homomorfik şifreli çarpım manipülasyonu tespit edilip hata fırlatmalıdır."""
        with self.assertRaises(TextbookRSAMalleabilityDetected):
            AsymmetricCryptoEngine.demonstrate_textbook_rsa_malleability(
                self.pub_key, self.priv_key, m1=7, m2=11
            )

    def test_15_common_modulus_attack_recovery(self):
        """15. Ortak modül kullanan iki anahtarda mesajın özel anahtarsız kurtarılması doğrulanmalıdır."""
        # Ortak n modülü kullanan iki anahtar çifti inşa edilir
        p = generate_prime(256)
        q = generate_prime(256)
        n = p * q
        phi = (p - 1) * (q - 1)
        e1 = 3
        e2 = 65537
        # e1 ve e2 phi ile aralarında asal olmalı
        while math.gcd(e1, phi) != 1 or math.gcd(e2, phi) != 1:
            p = generate_prime(256)
            q = generate_prime(256)
            n = p * q
            phi = (p - 1) * (q - 1)

        pub1 = RSAPublicKey(n=n, e=e1, bit_length=512)
        pub2 = RSAPublicKey(n=n, e=e2, bit_length=512)

        secret_message = 987654321
        c1 = pub1.encrypt_raw(secret_message)
        c2 = pub2.encrypt_raw(secret_message)

        recovered_m = AsymmetricCryptoEngine.demonstrate_common_modulus_attack(pub1, pub2, c1, c2)
        self.assertEqual(recovered_m, secret_message)


if __name__ == "__main__":
    unittest.main()
