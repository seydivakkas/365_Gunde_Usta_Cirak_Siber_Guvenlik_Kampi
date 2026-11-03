# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 102: Güvenli Parola Saklama ve KDF Kapsamlı Test Paketi.
15 birim test ile PBKDF2-HMAC-SHA256, tuz (salt), biber (pepper),
sabit zamanlı doğrulama ve 9 negatif kontrol senaryosu doğrulanır.
"""

# Birim test kütüphanesi
import unittest
# JSON dosya işleme modülü
import json
# Sistem ve yol araçları
import sys
# Dosya sistemi araçları
import os

# Test edilen modüllere erişim için ana dizini ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Güvenli parola saklama motoru bileşenlerini içe aktar
from uygulama.secure_password_vault import (
    PasswordHasher,
    PasswordSecurityConfig,
    PasswordHashRecord,
    PasswordVerificationResult,
    PasswordVaultError,
    UnsaltedHashError,
    InsufficientIterationsError,
    InsecureSaltLengthError,
    PredictableSaltError,
    PasswordVerificationMismatchError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


class TestSecurePasswordVault(unittest.TestCase):
    """Güvenli parola saklama motoru doğrulama testleri."""

    def setUp(self) -> None:
        """Her testten önce ortak test değişkenlerini hazırla."""
        # Standart güvenli test parolası
        self.guvenli_parola = "Kurumsal_Guvenli_Parola_2026!?"
        # Gizli sistem biberi (pepper)
        self.gizli_biber = b"HSM_KMS_IZOLE_DONANIM_BIBERI_KEY_2026"
        # Negatif girdi JSON dosyası yolu
        self.negatif_json_yolu = os.path.join(
            os.path.dirname(__file__), "..", "ornek_veri", "invalid_password_inputs.json"
        )

    def test_01_generate_salt_valid(self) -> None:
        """Test 1: Kriptografik rastgele tuzun geçerli uzunlukta ve benzersiz üretilmesi."""
        # 16 baytlık tuz üret
        salt1 = PasswordHasher.generate_salt(16)
        # Uzunluğunun 16 bayt olduğunu doğrula
        self.assertEqual(len(salt1), 16)
        # İkinci bir tuz üret
        salt2 = PasswordHasher.generate_salt(16)
        # İki bağımsız tuzun birbirinden farklı (rastgele) olduğunu doğrula
        self.assertNotEqual(salt1, salt2)

    def test_02_generate_salt_too_short_raises_cwe326(self) -> None:
        """Test 2: 16 bayt (128 bit) altındaki yetersiz tuz uzunluğunun reddedilmesi (CWE-326)."""
        # 8 baytlık yetersiz tuz denemesinde InsecureSaltLengthError fırlatılmalı
        with self.assertRaises(InsecureSaltLengthError):
            PasswordHasher.generate_salt(8)

    def test_03_generate_salt_invalid_type_raises(self) -> None:
        """Test 3: Tamsayı olmayan tuz uzunluğu argümanında tip hatası fırlatılması."""
        # String tipi iletildiğinde TypeValidationError fırlatılmalı
        with self.assertRaises(TypeValidationError):
            PasswordHasher.generate_salt("16")  # type: ignore

    def test_04_hash_password_success_and_format(self) -> None:
        """Test 4: Standart PBKDF2-HMAC-SHA256 parolasının kurumsal formatta kilitlenmesi."""
        # 100.000 iterasyonla hashle
        kayit = PasswordHasher.hash_password(self.guvenli_parola, iterations=100000)
        # Algoritmanın doğruluğunu sına
        self.assertEqual(kayit.algoritma, "pbkdf2-sha256")
        # İterasyonun doğruluğunu sına
        self.assertEqual(kayit.iterasyon, 100000)
        # Biber kullanılmadığını doğrula
        self.assertFalse(kayit.has_pepper)
        # Serileştirilmiş formatın $pbkdf2-sha256 ile başladığını doğrula
        self.assertTrue(kayit.tam_format.startswith("$pbkdf2-sha256$i=100000$"))

    def test_05_hash_password_with_pepper(self) -> None:
        """Test 5: Biber (pepper) ile kilitlenen kaydın bibersiz kayıttan ayrışması."""
        # Sabit bir tuz belirle
        sabit_tuz = b"1234567890abcdef"
        # Bibersiz hash üret
        kayit_bibersiz = PasswordHasher.hash_password(self.guvenli_parola, salt=sabit_tuz, pepper=None)
        # Biberli hash üret
        kayit_biberli = PasswordHasher.hash_password(self.guvenli_parola, salt=sabit_tuz, pepper=self.gizli_biber)
        # İki hash özetinin birbirinden tamamen farklı olduğunu doğrula
        self.assertNotEqual(kayit_bibersiz.hash_hex, kayit_biberli.hash_hex)
        # Biberli kayıtta bayrağın True olduğunu sına
        self.assertTrue(kayit_biberli.has_pepper)

    def test_06_insufficient_iterations_raises_cwe916(self) -> None:
        """Test 6: 100.000 iterasyon altındaki yetersiz iş gücünün engellenmesi (CWE-916)."""
        # 1.000 iterasyon denemesinde InsufficientIterationsError fırlatılmalı
        with self.assertRaises(InsufficientIterationsError):
            PasswordHasher.hash_password(self.guvenli_parola, iterations=1000)

    def test_07_predictable_salt_raises_cwe760(self) -> None:
        """Test 7: Tahmin edilebilir veya statik tuz kullanımının engellenmesi (CWE-760)."""
        # Statik ve bilinen bir tuz belirle
        statik_tuz = b"1234567812345678"
        # Bu tuz ile hashleme yapıldığında PredictableSaltError fırlatılmalı
        with self.assertRaises(PredictableSaltError):
            PasswordHasher.hash_password(self.guvenli_parola, salt=statik_tuz)

    def test_08_null_byte_in_password_raises_cwe158(self) -> None:
        """Test 8: Parola içinde Null-Byte zehirlemesi denemesinin engellenmesi (CWE-158)."""
        # Null byte içeren zararlı parola
        zararli_parola = "GizliParola\x00SaldırganEkstrası"
        # NullByteInjectionError fırlatılmalı
        with self.assertRaises(NullByteInjectionError):
            PasswordHasher.hash_password(zararli_parola)

    def test_09_oversized_payload_raises_cwe400(self) -> None:
        """Test 9: 1 MB tavanını aşan aşırı büyük parolanın bellek tüketimi (DoS) engeli (CWE-400)."""
        # 1 MB'ı aşan büyük parola oluştur (1.200.000 bayt)
        dev_parola = "A" * 1_200_000
        # PayloadLimitExceededError fırlatılmalı
        with self.assertRaises(PayloadLimitExceededError):
            PasswordHasher.hash_password(dev_parola)

    def test_10_invalid_password_type_raises_cwe843(self) -> None:
        """Test 10: Parola parametresi yerine int veya geçersiz tip iletilmesinin engellenmesi (CWE-843)."""
        # Tamsayı parola denemesi
        with self.assertRaises(TypeValidationError):
            PasswordHasher.hash_password(123456789)  # type: ignore

    def test_11_verify_password_success(self) -> None:
        """Test 11: Doğru parola ve doğru pepper ile sabit zamanlı doğrulamanın onaylanması."""
        # Kayıt üret
        kayit = PasswordHasher.hash_password(self.guvenli_parola, pepper=self.gizli_biber)
        # Doğrula
        sonuc = PasswordHasher.verify_password(self.guvenli_parola, kayit.tam_format, pepper=self.gizli_biber)
        # Doğrulamanın başarılı olduğunu sına
        self.assertTrue(sonuc.dogrulandi)
        # Sürenin hesaplandığını doğrula (>0 ms)
        self.assertGreater(sonuc.gecen_sure_ms, 0.0)

    def test_12_verify_password_mismatch_strict_raises_cwe208(self) -> None:
        """Test 12: Yanlış parola girişinde katı modda uyuşmazlık istisnasının fırlatılması."""
        # Kayıt üret
        kayit = PasswordHasher.hash_password(self.guvenli_parola, pepper=self.gizli_biber)
        # Katı modda yanlış parola ile PasswordVerificationMismatchError fırlatılmalı
        with self.assertRaises(PasswordVerificationMismatchError):
            PasswordHasher.verify_password("YanlisParola123!", kayit.tam_format, pepper=self.gizli_biber, strict_mode=True)

    def test_13_verify_password_wrong_pepper_strict_raises(self) -> None:
        """Test 13: Yanlış biber (pepper) kullanımında doğrulamanın reddedilmesi."""
        # Gerçek biber ile kayıt üret
        kayit = PasswordHasher.hash_password(self.guvenli_parola, pepper=self.gizli_biber)
        # Sahte biber tanımla
        sahte_biber = b"SAHTE_VE_YANLIS_BIBER_ANAHTARI"
        # Yanlış biber ile doğrulama başarısız olmalı
        sonuc = PasswordHasher.verify_password(self.guvenli_parola, kayit.tam_format, pepper=sahte_biber, strict_mode=False)
        self.assertFalse(sonuc.dogrulandi)

    def test_14_detect_legacy_unsalted_hashes_cwe759(self) -> None:
        """Test 14: Eski tuzsuz MD5, SHA-1 ve düz SHA-256 hashlerinin zafiyet olarak tespiti."""
        # 32 karakter MD5 tespiti
        md5_analiz = PasswordHasher.detect_insecure_hashing("5d41402abc4b2a76b9719d911017c592")
        self.assertIn("KRİTİK GÜVENSİZ", md5_analiz["guvenlik"])
        self.assertIn("CWE-759", md5_analiz["zafiyet"])

        # 40 karakter SHA-1 tespiti
        sha1_analiz = PasswordHasher.detect_insecure_hashing("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        self.assertIn("KRİTİK GÜVENSİZ", sha1_analiz["guvenlik"])

        # 64 karakter düz SHA-256 tespiti
        sha256_analiz = PasswordHasher.detect_insecure_hashing("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertIn("YÜKSEK RİSKLİ", sha256_analiz["guvenlik"])

    def test_15_negative_json_cases_verification(self) -> None:
        """Test 15: ornek_veri/invalid_password_inputs.json içindeki 9 negatif kontrolün yürütülmesi."""
        # JSON dosyasını aç ve oku
        with open(self.negatif_json_yolu, "r", encoding="utf-8") as f:
            negatif_vakalar = json.load(f)

        # 9 vakanın eksiksiz olduğunu doğrula
        self.assertEqual(len(negatif_vakalar), 9)

        # Her negatif vakayı senaryosuna göre sına
        for vaka in negatif_vakalar:
            vaka_id = vaka["id"]
            beklenen_hata_adi = vaka["beklenen_hata"]

            if vaka_id == "NEG_01_UNSALTED_HASH_STORAGE":
                # Tuzsuz hash kaydının ayrıştırılması UnsaltedHashError fırlatmalı
                with self.assertRaises(UnsaltedHashError):
                    PasswordHasher.parse_record(vaka["hash_formati"])

            elif vaka_id == "NEG_02_INSUFFICIENT_ITERATIONS":
                # Yetersiz iterasyon InsufficientIterationsError fırlatmalı
                with self.assertRaises(InsufficientIterationsError):
                    PasswordHasher.hash_password("parola123", iterations=vaka["iterasyon"])

            elif vaka_id == "NEG_03_SHORT_SALT_LENGTH":
                # Kısa tuz InsecureSaltLengthError fırlatmalı
                with self.assertRaises(InsecureSaltLengthError):
                    PasswordHasher.generate_salt(vaka["salt_bayt"])

            elif vaka_id == "NEG_04_PREDICTABLE_SALT_VALUE":
                # Statik tuz PredictableSaltError fırlatmalı
                with self.assertRaises(PredictableSaltError):
                    PasswordHasher.hash_password("parola123", salt=vaka["salt_degeri"].encode("utf-8"))

            elif vaka_id == "NEG_05_PEPPER_MISMATCH_VERIFY":
                # Biber uyuşmazlığı katı modda PasswordVerificationMismatchError fırlatmalı
                kayit = PasswordHasher.hash_password("parola123", pepper=self.gizli_biber)
                with self.assertRaises(PasswordVerificationMismatchError):
                    PasswordHasher.verify_password(
                        "parola123",
                        kayit.tam_format,
                        pepper=vaka["sahte_pepper"].encode("utf-8"),
                        strict_mode=True
                    )

            elif vaka_id == "NEG_06_PASSWORD_MISMATCH_VERIFY":
                # Yanlış parola katı modda PasswordVerificationMismatchError fırlatmalı
                kayit = PasswordHasher.hash_password("DogruParola2026!")
                with self.assertRaises(PasswordVerificationMismatchError):
                    PasswordHasher.verify_password(
                        vaka["yanlis_parola"],
                        kayit.tam_format,
                        strict_mode=True
                    )

            elif vaka_id == "NEG_07_NULL_BYTE_INJECTION":
                # Parolada Null-Byte tespiti NullByteInjectionError fırlatmalı
                with self.assertRaises(NullByteInjectionError):
                    PasswordHasher.hash_password(vaka["parola"])

            elif vaka_id == "NEG_08_OVERSIZED_PASSWORD_DOS":
                # Boyutu 1 MB'ı aşan parola PayloadLimitExceededError fırlatmalı
                buyuk_parola = "X" * vaka["boyut_bayt"]
                with self.assertRaises(PayloadLimitExceededError):
                    PasswordHasher.hash_password(buyuk_parola)

            elif vaka_id == "NEG_09_TYPE_CONFUSION":
                # Tip uyuşmazlığı TypeValidationError fırlatmalı
                with self.assertRaises(TypeValidationError):
                    PasswordHasher.hash_password(vaka["parola"])


# Testleri komut satırından çalıştırma bloğu
if __name__ == "__main__":
    # Testleri ayrıntılı (verbose) modda yürüt
    unittest.main(verbosity=2)
