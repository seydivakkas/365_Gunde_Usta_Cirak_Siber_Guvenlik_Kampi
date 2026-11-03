# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 076: Metin, Regex ve Karakter Kodlaması Birim Testleri
Bu test paketi, savunmacı log ayrıştırmayı, ReDoS korumasını, IDN homograf analizini,
Null-Byte ve Bidi enjeksiyon savunmasını 14 birim test ile doğrular.
"""

# Birim test çerçevesi için unittest modülü içe aktarılır
import unittest
# Yol ve sistem işlemleri için os ve sys modülleri içe aktarılır
import os
import sys

# Uygulama modülünü dinamik olarak içe aktarmak için modül yolu sys.path'e eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Doğrulanacak ana metin ve regex motoru sınıfı içe aktarılır
from secure_regex_and_encoding_engine import SecureRegexAndEncodingEngine


class TestSecureRegexAndEncodingEngine(unittest.TestCase):
    """
    Metin işleme, düzenli ifadeler ve karakter kodlaması güvenlik kontrollerini test eden sınıf.
    """

    def setUp(self) -> None:
        """
        Her test öncesinde temiz ve bağımsız bir motor örneği oluşturulur.
        """
        # Test için motor nesnesi atanır
        self.engine = SecureRegexAndEncodingEngine()
        # Standart geçerli bir erişim logu örneği tanımlanır
        self.valid_log = (
            '192.168.1.50 - - [31/Oct/2026:10:15:20 +0300] '
            '"GET /api/v1/auth/login HTTP/1.1" 200 4520 '
            '"https://portal.kurum.local" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )

    def test_01_parse_access_log_valid_entry(self) -> None:
        """
        Test 01: Savunmacı regex'in geçerli erişim logunu isimlendirilmiş gruplarla doğru ayrıştırdığını doğrular.
        """
        parsed = self.engine.parse_access_log(self.valid_log)
        self.assertEqual(parsed["ip"], "192.168.1.50")
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["uri"], "/api/v1/auth/login")
        self.assertEqual(parsed["status"], 200)
        self.assertEqual(parsed["size"], 4520)

    def test_02_parse_access_log_oversized_raises(self) -> None:
        """
        Test 02: ReDoS ve bellek tükenmesi koruması için 4096 karakter sınırını aşan logda ValueError fırlatıldığını doğrular.
        """
        oversized = "A" * (self.engine.MAX_INPUT_LENGTH + 1)
        with self.assertRaises(ValueError):
            self.engine.parse_access_log(oversized)

    def test_03_parse_access_log_null_byte_raises(self) -> None:
        """
        Test 03: Log satırında Null-Byte (\x00) tespit edildiğinde güvenlik istisnası üretildiğini doğrular.
        """
        tainted_log = self.valid_log.replace("/login", "/login\x00.admin")
        with self.assertRaises(ValueError):
            self.engine.parse_access_log(tainted_log)

    def test_04_parse_access_log_bidi_trojan_raises(self) -> None:
        """
        Test 04: Unicode Bidi yön değiştirme karakteri (\u202E / Trojan Source) enjeksiyonunun reddedildiğini doğrular.
        """
        bidi_log = self.valid_log.replace("Mozilla", "Moz\u202Eilla")
        with self.assertRaises(ValueError):
            self.engine.parse_access_log(bidi_log)

    def test_05_parse_access_log_malformed_format_raises(self) -> None:
        """
        Test 05: Malforme ve eksik alanlı log satırının regex formatına uymadığı için ValueError verdiğini test eder.
        """
        bad_format = "INVALID LOG LINE WITHOUT STANDARD FIELDS"
        with self.assertRaises(ValueError):
            self.engine.parse_access_log(bad_format)

    def test_06_detect_homoglyph_clean_ascii_domain(self) -> None:
        """
        Test 06: Temiz ASCII alan adının (portal.banka.com.tr) homograf saldırısı olmadığını doğrular.
        """
        res = self.engine.detect_homoglyph_attack("portal.banka.com.tr")
        self.assertFalse(res["is_homoglyph_attack"])
        self.assertTrue(res["is_clean_ascii"])

    def test_07_detect_homoglyph_cyrillic_spoofing(self) -> None:
        """
        Test 07: Latin 'a' yerine Kiril 'а' (\u0430) kullanılan alan adının homograf oltalama olarak yakalandığını doğrular.
        """
        spoofed = "p\u0430yp\u0430l.com"
        res = self.engine.detect_homoglyph_attack(spoofed)
        self.assertTrue(res["is_homoglyph_attack"])
        self.assertFalse(res["is_clean_ascii"])
        self.assertGreater(len(res["suspicious_characters"]), 0)

    def test_08_safe_decode_bytes_valid_utf8(self) -> None:
        """
        Test 08: Geçerli UTF-8 bayt dizisinin başarıyla çözüldüğünü test eder.
        """
        raw_b = "Güvenlik Duvarı".encode("utf-8")
        decoded = self.engine.safe_decode_bytes(raw_b, "utf-8")
        self.assertEqual(decoded, "Güvenlik Duvarı")

    def test_09_safe_decode_bytes_invalid_utf8_strict_raises(self) -> None:
        """
        Test 09: Bozuk UTF-8 bayt dizisinde strict modda ValueError fırlatıldığını doğrular.
        """
        corrupted_bytes = bytes.fromhex("c328")
        with self.assertRaises(ValueError):
            self.engine.safe_decode_bytes(corrupted_bytes, "utf-8", strict=True)

    def test_10_safe_decode_bytes_replace_mode(self) -> None:
        """
        Test 10: Bozuk UTF-8 bayt dizisinde strict=False iken güvenle kurtarma yapıldığını doğrular.
        """
        corrupted_bytes = bytes.fromhex("c328")
        recovered = self.engine.safe_decode_bytes(corrupted_bytes, "utf-8", strict=False)
        self.assertIn("\ufffd", recovered)

    def test_11_validate_strict_pattern_anchored_match(self) -> None:
        """
        Test 11: Katı bağlaçlı regex'in tam eşleşen CVE kimliğini (CVE-2026-12345) onayladığını doğrular.
        """
        pattern = r"^CVE-\d{4}-\d{4,7}$"
        self.assertTrue(self.engine.validate_strict_pattern(pattern, "CVE-2026-12345"))

    def test_12_validate_strict_pattern_partial_match_fails(self) -> None:
        """
        Test 12: Kısmi eşleşme atlatması (partial match bypass) içeren girdinin reddedildiğini test eder.
        """
        pattern = r"^CVE-\d{4}-\d{4,7}$"
        self.assertFalse(self.engine.validate_strict_pattern(pattern, "CVE-2026-12345; DROP TABLE"))

    def test_13_validate_strict_pattern_invalid_regex_raises(self) -> None:
        """
        Test 13: Geçersiz regex sözdizimi gönderildiğinde ValueError üretildiğini doğrular.
        """
        bad_pattern = r"^(?P<unclosed_group>[a-z+"
        with self.assertRaises(ValueError):
            self.engine.validate_strict_pattern(bad_pattern, "test")

    def test_14_sanitize_log_control_characters(self) -> None:
        """
        Test 14: Terminal kaçış kodları ve kontrol karakterlerinin başarıyla temizlendiğini doğrular.
        """
        tainted = "USER_LOGIN \x1b[2J\x1b[H ADMIN \x07\x08 OK\n"
        cleaned = self.engine.sanitize_log_control_characters(tainted)
        self.assertEqual(cleaned, "USER_LOGIN  ADMIN  OK\n")
        self.assertNotIn("\x1b", cleaned)


if __name__ == "__main__":
    unittest.main()
