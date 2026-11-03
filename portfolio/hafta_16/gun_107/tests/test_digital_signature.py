# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 107: Dijital İmza ve Doğrulama Kapsamlı Birim Testleri.
15 Birim testi (%100 PASS hedefi), negatif kontroller, matematiksel doğrulama
ve zafiyet simülasyonlarını (Textbook, Bleichenbacher, ECDSA nonce leak) içerir.
"""

# Standart test kütüphanesi
import unittest
# Sistem ve dizin yönetimi
import os
import sys

# Test edilen motor modülünü sistem yoluna ekleme
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
APP_DIR = os.path.join(PARENT_DIR, "uygulama")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

# Çekirdek motor sınıflarını içe aktarma
from digital_signature_engine import (
    DigitalSignatureEngine,
    RSAPublicKey,
    RSAPrivateKey,
    SignatureVerificationError,
    WeakKeySizeError,
    InvalidSignatureFormatError,
    BleichenbacherVulnerabilityDetected,
    ECDSANonceReuseDetected,
    TextbookSignatureForgeryDetected
)


class TestDigitalSignature(unittest.TestCase):
    """Dijital imza algoritmaları, PSS, PKCS#1 v1.5 ve zafiyet güvenlik testleri."""

    @classmethod
    def setUpClass(cls):
        """Tüm testler için ortak 1024 bitlik hızlı test anahtarı üretir."""
        cls.pub_key, cls.priv_key = DigitalSignatureEngine.generate_keypair(bits=1024)

    def test_01_textbook_signature_roundtrip(self):
        """1. Düz (Textbook) RSA imza ve doğrulama döngüsü matematiksel olarak çalışmalıdır."""
        m = 123456789
        sig = DigitalSignatureEngine.sign_raw_textbook(self.priv_key, m)
        valid = DigitalSignatureEngine.verify_raw_textbook(self.pub_key, m, sig)
        self.assertTrue(valid)

    def test_02_textbook_existential_forgery(self):
        """2. Düz RSA'da özel anahtar olmadan varoluşsal imza sahteciliği tespit edilmelidir (CWE-327)."""
        with self.assertRaises(TextbookSignatureForgeryDetected):
            DigitalSignatureEngine.demonstrate_textbook_existential_forgery(self.pub_key)

    def test_03_textbook_multiplicative_forgery(self):
        """3. Düz RSA'da şifreli imzaların çarpımı mesajların çarpımını imzalamalıdır (Malleability)."""
        m1, m2 = 17, 23
        s1 = DigitalSignatureEngine.sign_raw_textbook(self.priv_key, m1)
        s2 = DigitalSignatureEngine.sign_raw_textbook(self.priv_key, m2)
        res = DigitalSignatureEngine.demonstrate_textbook_multiplicative_forgery(self.pub_key, m1, s1, m2, s2)
        self.assertTrue(res["is_valid"])

    def test_04_pkcs1_v1_5_encode_format(self):
        """4. PKCS#1 v1.5 kodlaması standart 0x00 0x01 ... 0x00 T biçimine uymalıdır."""
        k = 128  # 1024 bit için 128 bayt
        dummy_hash = b"\xaa" * 32
        em = DigitalSignatureEngine.encode_pkcs1_v1_5(dummy_hash, k)
        self.assertEqual(len(em), k)
        self.assertTrue(em.startswith(b"\x00\x01"))
        self.assertTrue(em.endswith(dummy_hash))
        self.assertIn(DigitalSignatureEngine.SHA256_ASN1_PREFIX, em)

    def test_05_pkcs1_v1_5_sign_and_verify_success(self):
        """5. RSASSA-PKCS1-v1_5 şeması ile imzalama ve katı doğrulama başarılı olmalıdır."""
        belge = b"Gorev Emri: Siber Savunma Tatbikati 2026"
        sig = DigitalSignatureEngine.sign_pkcs1_v1_5(self.priv_key, belge)
        self.assertEqual(len(sig), 128)
        valid = DigitalSignatureEngine.verify_pkcs1_v1_5(self.pub_key, belge, sig, strict=True)
        self.assertTrue(valid)

    def test_06_pkcs1_v1_5_tamper_detection(self):
        """6. PKCS#1 v1.5 imzasında belge tahrif edildiğinde doğrulama başarısız olmalıdır."""
        belge = b"Orijinal Guvenli Belge"
        sig = DigitalSignatureEngine.sign_pkcs1_v1_5(self.priv_key, belge)
        sahte_belge = b"Orijinal Guvenli Belge!"
        valid = DigitalSignatureEngine.verify_pkcs1_v1_5(self.pub_key, sahte_belge, sig, strict=True)
        self.assertFalse(valid)

    def test_07_bleichenbacher_forgery_mitigation(self):
        """7. e=3 durumunda gevşek doğrulayıcı zaafı tespit edilip Bleichenbacher uyarısı verilmelidir."""
        pub_e3, priv_e3 = DigitalSignatureEngine.generate_keypair(bits=1024, public_exponent=3)
        target_msg = b"Yetkisiz Admin Yetkisi Talebi"
        with self.assertRaises(BleichenbacherVulnerabilityDetected):
            DigitalSignatureEngine.demonstrate_bleichenbacher_attack(pub_e3, target_msg)

    def test_08_pss_encode_verify_roundtrip(self):
        """8. EMSA-PSS kodlama ve doğrulama alt katmanı kayıpsız çalışmalıdır."""
        m_hash = b"\x55" * 32
        em_bits = 1024 - 1
        em = DigitalSignatureEngine.emsa_pss_encode(m_hash, em_bits, salt_len=32)
        self.assertEqual(len(em), 128)
        self.assertEqual(em[-1], 0xbc)
        valid = DigitalSignatureEngine.emsa_pss_verify(m_hash, em, em_bits, salt_len=32)
        self.assertTrue(valid)

    def test_09_pss_sign_and_verify_success(self):
        """9. RSASSA-PSS imzalama ve doğrulama uçtan uca hatasız çalışmalıdır."""
        mesaj = b"Kriptografik PSS Imza Dogrulama Protokolu"
        sig = DigitalSignatureEngine.sign_pss(self.priv_key, mesaj)
        valid = DigitalSignatureEngine.verify_pss(self.pub_key, mesaj, sig)
        self.assertTrue(valid)

    def test_10_pss_probabilistic_nature(self):
        """10. PSS şeması olasılıksal olmalı; aynı mesaja her defasında farklı imza üretmelidir."""
        mesaj = b"Ayni Mesaj"
        sig1 = DigitalSignatureEngine.sign_pss(self.priv_key, mesaj)
        sig2 = DigitalSignatureEngine.sign_pss(self.priv_key, mesaj)
        self.assertNotEqual(sig1, sig2)
        self.assertTrue(DigitalSignatureEngine.verify_pss(self.pub_key, mesaj, sig1))
        self.assertTrue(DigitalSignatureEngine.verify_pss(self.pub_key, mesaj, sig2))

    def test_11_pss_tamper_detection_in_document(self):
        """11. Belgede tek karakter değiştiğinde PSS doğrulaması SignatureVerificationError fırlatmalıdır."""
        mesaj = b"Hesaba 5000 TL transfer et"
        sig = DigitalSignatureEngine.sign_pss(self.priv_key, mesaj)
        tahrif_mesaj = b"Hesaba 50000 TL transfer et"
        with self.assertRaises(SignatureVerificationError):
            DigitalSignatureEngine.verify_pss(self.pub_key, tahrif_mesaj, sig)

    def test_12_pss_tamper_detection_in_signature(self):
        """12. İmza baytlarında tahrifat yapıldığında PSS doğrulaması başarısız olmalıdır (CWE-347)."""
        mesaj = b"Kritik Konfigurasyon Guncellemesi"
        sig = bytearray(DigitalSignatureEngine.sign_pss(self.priv_key, mesaj))
        sig[15] ^= 0xAA
        with self.assertRaises(SignatureVerificationError):
            DigitalSignatureEngine.verify_pss(self.pub_key, mesaj, bytes(sig))

    def test_13_ecdsa_nonce_reuse_private_key_recovery(self):
        """13. ECDSA nonce yeniden kullanımı durumunda özel anahtar ifşası kanıtlanmalıdır (CWE-323)."""
        q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        d = 777888999111222333
        z1 = 111111111
        z2 = 222222222
        k = 999999999
        with self.assertRaises(ECDSANonceReuseDetected):
            DigitalSignatureEngine.demonstrate_ecdsa_nonce_reuse(q, d, z1, z2, k)

    def test_14_weak_key_size_rejection(self):
        """14. 512 bitin altındaki zayıf anahtar üretimi WeakKeySizeError ile engellenmelidir (CWE-326)."""
        with self.assertRaises(WeakKeySizeError):
            DigitalSignatureEngine.generate_keypair(bits=256)

    def test_15_invalid_signature_length_rejection(self):
        """15. Modül boyutuna uymayan kırpılmış imza InvalidSignatureFormatError fırlatmalıdır (CWE-20)."""
        mesaj = b"Test Mesaji"
        sig = DigitalSignatureEngine.sign_pss(self.priv_key, mesaj)
        kirpilmis_sig = sig[:64]  # 128 bayt yerine 64 bayt
        with self.assertRaises(InvalidSignatureFormatError):
            DigitalSignatureEngine.verify_pss(self.pub_key, mesaj, kirpilmis_sig)


if __name__ == "__main__":
    unittest.main()
