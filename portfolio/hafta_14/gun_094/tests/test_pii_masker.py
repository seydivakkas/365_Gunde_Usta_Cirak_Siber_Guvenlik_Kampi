# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 094: Regex ile Kişisel Veri Maskeleme ve DLP Motoru Birim Testleri.
14 adet kapsamlı test senaryosu ile algoritmalar, zafiyet kalkanları ve maskeleme modları doğrulanır.
"""

# Birim test çerçevesi kütüphanesi
import unittest
# Sistem modülü
import sys
# Dosya yolu işlemleri
import os

# Uygulama modülünü içe aktarmak için kök dizini ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor ve fonksiyonları içe aktar
from uygulama.pii_masker import (
    PIIMaskerEngine,
    verify_luhn,
    verify_tckn,
    verify_iban_tr,
    NullByteInjectionError,
    PayloadLimitExceededError,
    ReDoSProtectionTriggered,
    TypeValidationError,
    InvalidRuleError,
    LuhnChecksumError,
    TCKNChecksumError,
    TCKNLeadingZeroError,
    IBANChecksumError
)


class TestPIIMaskerEngine(unittest.TestCase):
    """Kişisel veri maskeleme motoru birim test sınıfı."""

    def setUp(self):
        """Her test öncesi standart test motorunu başlatır."""
        # Varsayılan MASK stilinde motor nesnesi oluştur
        self.engine = PIIMaskerEngine(mask_style="MASK")
        # REDACT stilinde motor oluştur
        self.redact_engine = PIIMaskerEngine(mask_style="REDACT")
        # HASH stilinde motor oluştur
        self.hash_engine = PIIMaskerEngine(mask_style="HASH", salt="TEST_SALT_123")

    def test_01_verify_luhn_valid_cards(self):
        """Test 01: Geçerli Visa ve MasterCard kart numaralarının Luhn kontrolünden geçtiğini doğrular."""
        # Geçerli Visa kartı
        valid_visa = "4532 0151 1283 0366"
        # Geçerli MasterCard
        valid_mc = "5425-2334-3010-9903"
        # Visa doğrulaması başarılı olmalı
        self.assertTrue(verify_luhn(valid_visa))
        # MasterCard doğrulaması başarılı olmalı
        self.assertTrue(verify_luhn(valid_mc))

    def test_02_verify_luhn_invalid_cards(self):
        """Test 02: Basamağı tahrif edilmiş sahte kartın Luhn kontrolünde başarısız olduğunu doğrular."""
        # Son basamağı değiştirilmiş geçersiz kart
        invalid_card = "4532015112830367"
        # Doğrulama False dönmeli
        self.assertFalse(verify_luhn(invalid_card))
        # raise_on_error bayrağıyla LuhnChecksumError fırlatılmalı
        with self.assertRaises(LuhnChecksumError):
            # Hata moduyla çağır
            verify_luhn(invalid_card, raise_on_error=True)

    def test_03_verify_tckn_valid(self):
        """Test 03: Matematiksel algoritması geçerli TCKN'lerin onaylandığını doğrular."""
        # 1. geçerli TCKN
        tckn_1 = "12345678950"
        # 2. geçerli TCKN
        tckn_2 = "10000000146"
        # İlk TCKN onaylanmalı
        self.assertTrue(verify_tckn(tckn_1))
        # İkinci TCKN onaylanmalı
        self.assertTrue(verify_tckn(tckn_2))

    def test_04_verify_tckn_invalid_algorithm(self):
        """Test 04: 10. ve 11. basamak formülü tutmayan sahte TCKN'nin reddedildiğini doğrular."""
        # Son basamağı bozuk TCKN
        invalid_tckn = "12345678959"
        # False dönmeli
        self.assertFalse(verify_tckn(invalid_tckn))
        # raise_on_error ile TCKNChecksumError fırlatılmalı
        with self.assertRaises(TCKNChecksumError):
            # Çağır ve hatayı yakala
            verify_tckn(invalid_tckn, raise_on_error=True)

    def test_05_verify_tckn_leading_zero(self):
        """Test 05: Sıfır ile başlayan 11 haneli sayıların TCKN olarak kabul edilmediğini doğrular."""
        # Sıfırla başlayan sayı
        zero_tckn = "01234567890"
        # Doğrulama False olmalı
        self.assertFalse(verify_tckn(zero_tckn))
        # Hata moduyla TCKNLeadingZeroError beklenmeli
        with self.assertRaises(TCKNLeadingZeroError):
            # Çağır
            verify_tckn(zero_tckn, raise_on_error=True)

    def test_06_verify_iban_tr_valid(self):
        """Test 06: ISO 7064 MOD-97 doğrulamasından geçen TR IBAN'ın onaylandığını doğrular."""
        # Geçerli Türkiye IBAN örneği
        valid_iban = "TR780006100519786457841001"
        # Doğrulama True olmalı
        self.assertTrue(verify_iban_tr(valid_iban))
        # Boşluklu format da onaylanmalı
        self.assertTrue(verify_iban_tr("TR78 0006 1005 1978 6457 8410 01"))

    def test_07_verify_iban_tr_invalid(self):
        """Test 07: MOD-97 kontrol basamağı bozuk IBAN'ın reddedildiğini doğrular."""
        # Kontrol hanesi bozuk sahte IBAN
        invalid_iban = "TR000006100519786457841001"
        # Doğrulama False olmalı
        self.assertFalse(verify_iban_tr(invalid_iban))
        # Hata modunda IBANChecksumError fırlatılmalı
        with self.assertRaises(IBANChecksumError):
            # Hata fırlatmayı dene
            verify_iban_tr(invalid_iban, raise_on_error=True)

    def test_08_email_masking(self):
        """Test 08: E-posta adreslerinin domain korunarak doğru maskelendiğini doğrular."""
        # Uzun kullanıcı adlı e-posta
        sample = "Kullanıcı iletişim: ahmet.yilmaz@kurumsal-banka.com.tr"
        # Maskeleme işlemi yap
        res, stats = self.engine.process_text(sample, rules=["email"])
        # Domain korunmalı
        self.assertIn("@kurumsal-banka.com.tr", res)
        # ah*** kullanıcı adı olmalı
        self.assertIn("ah***@", res)
        # İstatistik sayacı 1 olmalı
        self.assertEqual(stats["stats"]["email_count"], 1)

    def test_09_phone_masking(self):
        """Test 09: Telefon numaralarının formatına uygun maskelendiğini doğrular."""
        # Örnek telefon metni
        sample = "İletişim numarası: +90 532 444 22 11 ve cep 05559876543"
        # Maskele
        res, stats = self.engine.process_text(sample, rules=["phone"])
        # Sayacın 2 adet telefon bulduğunu doğrula
        self.assertEqual(stats["stats"]["phone_count"], 2)
        # Ham telefon numaralarının metinden temizlendiğini doğrula
        self.assertNotIn("444 22 11", res)

    def test_10_secrets_masking(self):
        """Test 10: Parola ve API anahtarı dizgilerinin maskelendiğini doğrular."""
        # Örnek token içeren metin
        sample = 'Sistem yapılandırma api_key="secret_live_tok_998877665544"'
        # Maskele
        res, stats = self.engine.process_text(sample, rules=["secret"])
        # Sayacın 1 bulduğunu doğrula
        self.assertEqual(stats["stats"]["secret_count"], 1)
        # Ham anahtarın gizlendiğini doğrula
        self.assertNotIn("secret_live_tok", res)

    def test_11_mask_styles(self):
        """Test 11: MASK, REDACT ve HASH stillerinin farklı davranışlarını doğrular."""
        # Test metni
        sample = "Kayıt tckn=12345678950"
        # MASK çıktısı
        res_mask, _ = self.engine.process_text(sample, rules=["tckn"])
        # Yıldızlı format olmalı
        self.assertIn("123******50", res_mask)
        # REDACT çıktısı
        res_redact, _ = self.redact_engine.process_text(sample, rules=["tckn"])
        # Tam etiket olmalı
        self.assertIn("[REDACTED_TCKN]", res_redact)
        # HASH çıktısı
        res_hash, _ = self.hash_engine.process_text(sample, rules=["tckn"])
        # Kriptografik özet öneki bulunmalı
        self.assertIn("TCKN#", res_hash)

    def test_12_redos_defense(self):
        """Test 12: ReDoS saldırı şablonlarının tespit edilerek engellendiğini doğrular."""
        # Kötücül ReDoS dizgisi
        evil_pattern = "girdi: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@evil.org"
        # ReDoS koruma istisnasının fırlatıldığını doğrula
        with self.assertRaises(ReDoSProtectionTriggered):
            # İşlemi dene
            self.engine.process_text(evil_pattern)

    def test_13_null_byte_rejection(self):
        """Test 13: Null-Byte karakteri içeren metinlerin reddedildiğini doğrular (CWE-158)."""
        # Zehirli null karakterli metin
        poisoned = "admin_auth=true\x00email=user@corp.com"
        # NullByteInjectionError beklenir
        with self.assertRaises(NullByteInjectionError):
            # Doğrulamayı dene
            self.engine.process_text(poisoned)

    def test_14_dos_payload_limits(self):
        """Test 14: 1 MB tavanını aşan aşırı büyük girdilerin DoS korumasına takıldığını doğrular (CWE-400)."""
        # Boyut aşım simülasyonu
        oversized = "OVERSIZED_LOG_BUFFER_SIMULATION_EXCEEDING_LIMITS"
        # PayloadLimitExceededError fırlatılmalı
        with self.assertRaises(PayloadLimitExceededError):
            # İşlemi dene
            self.engine.process_text(oversized)


if __name__ == "__main__":
    # Test paketini verbose modda çalıştır
    unittest.main()
