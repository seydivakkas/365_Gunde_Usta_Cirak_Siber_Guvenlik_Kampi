# -*- coding: utf-8 -*-
"""
Girdi Doğrulama ve Çıktı Kodlama Birim Test Paketi (15 Test)
Hafta 23 / Gün 159 - Aşama 7 (Web Güvenliği)

Bu test paketi; kanonikleştirme (Unicode NFKC, recursive URL unquoting, Null byte),
pozitif izin listesi (Allowlist) doğrulaması, enjeksiyon saldırı imzaları (SQLi, XSS,
Komut Enjeksiyonu, Path Traversal) ve bağlama duyarlı çıktı kodlama (HTML Body,
HTML Attribute, JavaScript, URL Param, CSS) yeteneklerini 15 senaryoda doğrular.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.input_validator_encoder_engine import (
    InputValidatorEncoderEngine,
    ValidationType,
    EncodingContext,
    ValidationResult
)


class TestInputValidatorEncoderEngine(unittest.TestCase):
    """InputValidatorEncoderEngine sınıfının tüm fonksiyonlarını test eden sınıf."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        self.engine = InputValidatorEncoderEngine()

    def test_01_canonicalize_double_url_encoding(self):
        """Çift URL kodlama (%252e%252e%252f) hilesinin ../ haline çözüldüğünü doğrular."""
        raw = "%252e%252e%252fadmin"
        canonical = self.engine.canonicalize(raw)
        self.assertEqual(canonical, "../admin")

    def test_02_canonicalize_unicode_nfkc_homoglyph(self):
        """Unicode tam genişlikli veya benzer karakterlerin NFKC ile normalize edildiğini test eder."""
        raw = "ａｄｍｉｎ"  # Fullwidth latin a-d-m-i-n
        canonical = self.engine.canonicalize(raw)
        self.assertEqual(canonical, "admin")

    def test_03_canonicalize_strips_null_bytes(self):
        """Zararlı Null byte (\x00) karakterinin temizlendiğini doğrular."""
        raw = "dosya.pdf\x00.exe"
        canonical = self.engine.canonicalize(raw)
        self.assertEqual(canonical, "dosya.pdf.exe")

    def test_04_validate_field_valid_alphanumeric(self):
        """Geçerli Türkçe ve alfanümerik kullanıcı adının başarıyla geçtiğini doğrular."""
        res = self.engine.validate_field(
            field_name="username",
            value="Seydi_Eryilmaz123",
            val_type=ValidationType.TEXT_ALPHANUMERIC,
            min_length=3,
            max_length=30
        )
        self.assertTrue(res.is_valid)
        self.assertIsNone(res.error_message)

    def test_05_validate_field_email_format(self):
        """RFC 5322 e-posta doğrulamasının geçerli ve geçersiz adresleri ayırt ettiğini test eder."""
        valid_res = self.engine.validate_field("email", "guvenlik@kurum.gov.tr", ValidationType.EMAIL)
        self.assertTrue(valid_res.is_valid)

        invalid_res = self.engine.validate_field("email", "guvenlik@kurum", ValidationType.EMAIL)
        self.assertFalse(invalid_res.is_valid)

    def test_06_validate_field_sql_injection_detection(self):
        """SQL Enjeksiyonu imzasının (' OR 1=1 --) tespit edilerek alanın reddedildiğini test eder."""
        res = self.engine.validate_field(
            field_name="search",
            value="' UNION SELECT username, password FROM users --",
            val_type=ValidationType.TEXT_ALPHANUMERIC
        )
        self.assertFalse(res.is_valid)
        self.assertIn("SQL_INJECTION", res.detected_threats)

    def test_07_validate_field_xss_script_tag_detection(self):
        """Zararlı XSS betik etiketinin (<script>) yakalandığını test eder."""
        res = self.engine.validate_field(
            field_name="comment",
            value="<script>alert(document.cookie)</script>",
            val_type=ValidationType.SAFE_TEXT_MULTILINE
        )
        self.assertFalse(res.is_valid)
        self.assertIn("XSS_SCRIPT", res.detected_threats)

    def test_08_validate_field_command_injection_detection(self):
        """İşletim sistemi komut ayırıcılarının (; rm, | bash) yakalandığını test eder."""
        res = self.engine.validate_field(
            field_name="filename",
            value="rapor.txt; cat /etc/passwd",
            val_type=ValidationType.TEXT_ALPHANUMERIC
        )
        self.assertFalse(res.is_valid)
        self.assertIn("COMMAND_INJECTION", res.detected_threats)

    def test_09_validate_field_path_traversal_detection(self):
        """Dizin geçişi (Path Traversal ../../) saldırısının engellendiğini doğrular."""
        res = self.engine.validate_field(
            field_name="doc_path",
            value="../../etc/passwd",
            val_type=ValidationType.TEXT_ALPHANUMERIC
        )
        self.assertFalse(res.is_valid)
        self.assertIn("PATH_TRAVERSAL", res.detected_threats)

    def test_10_validate_field_length_bounds(self):
        """Asgari ve azami uzunluk sınırlarının ihlal edildiğinde hata verdiğini doğrular."""
        too_short = self.engine.validate_field("pin", "12", ValidationType.NUMERIC_INT, min_length=4)
        self.assertFalse(too_short.is_valid)

        too_long = self.engine.validate_field("kod", "ABCDEFGHIJKL", ValidationType.TEXT_ALPHA, max_length=5)
        self.assertFalse(too_long.is_valid)

    def test_11_encode_html_body_context(self):
        """HTML Gövdesi bağlamında özel karakterlerin varlık kodlamasına (Entity) dönüştüğünü doğrular."""
        raw = "<script>alert('XSS & Test');</script>"
        encoded = self.engine.encode_for_context(raw, EncodingContext.HTML_BODY)
        self.assertNotIn("<script>", encoded)
        self.assertIn("&lt;script&gt;", encoded)
        self.assertIn("&amp;", encoded)
        self.assertIn("&#x27;", encoded)

    def test_12_encode_html_attribute_context(self):
        """HTML Öznitelik bağlamında tırnak kırma saldırısının (Attribute Breakout) engellendiğini test eder."""
        raw = '" onfocus="alert(1)'
        encoded = self.engine.encode_for_context(raw, EncodingContext.HTML_ATTRIBUTE)
        self.assertNotIn('"', encoded)
        self.assertIn("&#x22;", encoded)

    def test_13_encode_javascript_variable_context(self):
        """JavaScript bağlamında metnin Unicode kaçışı (\\u00XX) ile zararsız hale geldiğini doğrular."""
        raw = "'; alert(1); //"
        encoded = self.engine.encode_for_context(raw, EncodingContext.JAVASCRIPT)
        self.assertNotIn("'", encoded)
        self.assertIn("\\u0027", encoded)
        self.assertIn("\\u003B", encoded)

    def test_14_encode_url_param_context(self):
        """URL Parametresi bağlamında percent-encoding yapıldığını doğrular."""
        raw = "siber güvenlik & test"
        encoded = self.engine.encode_for_context(raw, EncodingContext.URL_PARAM)
        self.assertIn("%26", encoded)
        self.assertNotIn(" ", encoded)

    def test_15_validate_and_sanitize_payload_batch(self):
        """JSON istek gövdesinin şema üzerinden toplu doğrulanmasını test eder."""
        schema = {
            "name": {"type": "TextAlpha", "min_length": 2, "max_length": 50},
            "age": {"type": "NumericInt"},
            "email": {"type": "Email"}
        }
        valid_payload = {"name": "Seydi", "age": "30", "email": "seydi@test.com"}
        report = self.engine.validate_and_sanitize_payload(valid_payload, schema)
        self.assertTrue(report["all_valid"])
        self.assertEqual(len(report["errors"]), 0)

        invalid_payload = {"name": "A", "age": "abc", "email": "bad_email"}
        bad_report = self.engine.validate_and_sanitize_payload(invalid_payload, schema)
        self.assertFalse(bad_report["all_valid"])
        self.assertEqual(len(bad_report["errors"]), 3)


if __name__ == "__main__":
    unittest.main()
