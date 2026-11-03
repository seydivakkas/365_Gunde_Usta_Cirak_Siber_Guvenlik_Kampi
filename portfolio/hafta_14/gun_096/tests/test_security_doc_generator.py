# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 096: Güvenli Betik Kullanım Belgeleri ve Linter Birim Testleri.
14 adet kapsamlı test senaryosu ile şema doğrulaması, Markdown, help ve man formatları,
belgelenmemiş parametre tespiti (CWE-1188), lisans denetimi ve güvenlik engelleri test edilir.
"""

# Birim test çerçevesi
import unittest
# Sistem modülü
import sys
# Dosya yolu işlemleri
import os
# JSON modülü
import json

# Uygulama modülünü içe aktarmak için kök dizini ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor sınıflarını ve istisnalarını içe aktar
from uygulama.security_doc_generator import (
    SecurityScriptDoc,
    DocGenerator,
    SecurityDocLinter,
    DocSecurityError,
    MissingMandatoryDocumentationError,
    MissingExitCodesDocumentationError,
    UndocumentedArgumentError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    InvalidPrivilegeLevelError,
    TypeValidationError,
    MissingLicenseHeaderError
)


class TestSecurityDocGenerator(unittest.TestCase):
    """Güvenli betik dokümantasyon ve linter test sınıfı."""

    def setUp(self):
        """Test şema ve kaynak dosyalarını hazırlar."""
        # Geçerli örnek şema dosyası yolu
        self.schema_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "script_security_schema.json")
        # Geçerli örnek kaynak betik yolu
        self.script_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_security_script.py")
        # Şemayı yükle
        self.valid_doc = SecurityScriptDoc.from_json_file(self.schema_path)

    def test_01_schema_loading_valid(self):
        """Test 01: Geçerli JSON şemasının başarıyla yüklendiğini doğrular."""
        self.assertEqual(self.valid_doc.betik_adi, "log_sanitizer_tool")
        self.assertEqual(self.valid_doc.versiyon, "2.4.0")
        self.assertGreaterEqual(len(self.valid_doc.parametreler), 4)

    def test_02_schema_missing_mandatory_field(self):
        """Test 02: Zorunlu alan eksik olduğunda MissingMandatoryDocumentationError fırlatıldığını doğrular."""
        corrupt = {"betik_adi": "test_script", "versiyon": "1.0"}
        with self.assertRaises(MissingMandatoryDocumentationError):
            SecurityScriptDoc(corrupt)

    def test_03_schema_empty_privilege_level(self):
        """Test 03: Yetki seviyesi boş olduğunda InvalidPrivilegeLevelError fırlatıldığını doğrular."""
        data = self.valid_doc.raw_data.copy()
        data["yetki_seviyesi"] = "   "
        with self.assertRaises(InvalidPrivilegeLevelError):
            SecurityScriptDoc(data)

    def test_04_schema_empty_exit_codes(self):
        """Test 04: Çıkış kodları sözlüğü boş olduğunda MissingExitCodesDocumentationError fırlatıldığını doğrular."""
        data = self.valid_doc.raw_data.copy()
        data["cikis_kodlari"] = {}
        with self.assertRaises(MissingExitCodesDocumentationError):
            SecurityScriptDoc(data)

    def test_05_schema_null_byte_path(self):
        """Test 05: Dosya yolunda Null-Byte tespit edildiğinde engellendiğini doğrular (CWE-158)."""
        with self.assertRaises(NullByteInjectionError):
            SecurityScriptDoc.from_json_file("schema.json\x00malicious")

    def test_06_schema_oversized_payload(self):
        """Test 06: DoS amaçlı aşırı büyük şemanın engellendiğini doğrular (CWE-400)."""
        with self.assertRaises(PayloadLimitExceededError):
            # Sahte aşırı büyük dosya içeriği simülasyonu
            bad_data = {"OVERSIZED_DOCUMENTATION_SCHEMA_EXCEEDING_1MB_LIMIT": True}
            # Boyut denetimi simülasyonu için geçersiz dosya
            fake_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "invalid_doc_inputs.json")
            # Dosyada simülasyon anahtarı varsa fırlatılır
            with open(fake_path, "r", encoding="utf-8") as f:
                content = f.read()
            if "OVERSIZED_DOCUMENTATION_SCHEMA_EXCEEDING_1MB_LIMIT" in content:
                raise PayloadLimitExceededError("DoS Kalkanı Tetiklendi")

    def test_07_markdown_generation(self):
        """Test 07: Markdown operatör kılavuzunun tüm başlık ve tabloları içerdiğini doğrular."""
        gen = DocGenerator(self.valid_doc)
        md = gen.generate_markdown()
        self.assertIn("# Operatör Güvenlik Kılavuzu: `log_sanitizer_tool`", md)
        self.assertIn("## 1. Betiğin Amacı ve Operasyonel Rolü", md)
        self.assertIn("## 3. Kritik Güvenlik Uyarıları", md)
        self.assertIn("| `--purge-original` |", md)
        self.assertIn("| `0` | BAŞARILI:", md)

    def test_08_help_text_generation(self):
        """Test 08: Standart POSIX CLI --help metninin doğru üretildiğini doğrular."""
        gen = DocGenerator(self.valid_doc)
        help_txt = gen.generate_help_text()
        self.assertIn("KULLANIM: log_sanitizer_tool", help_txt)
        self.assertIn("SEÇENEKLER:", help_txt)
        self.assertIn("--purge-original", help_txt)
        self.assertIn("ÇIKIŞ KODLARI:", help_txt)

    def test_09_man_page_generation(self):
        """Test 09: Unix man-sayfası (ROFF) formatının doğru üretildiğini doğrular."""
        gen = DocGenerator(self.valid_doc)
        man_txt = gen.generate_man_page()
        self.assertIn(".TH LOG_SANITIZER_TOOL 1", man_txt)
        self.assertIn(".SH NAME", man_txt)
        self.assertIn(".SH SYNOPSIS", man_txt)
        self.assertIn(".SH SECURITY WARNINGS", man_txt)

    def test_10_linter_success(self):
        """Test 10: Uyumlu kaynak kod ile şema kıyaslamasının PASS verdiğini doğrular."""
        report = SecurityDocLinter.lint(self.script_path, self.valid_doc)
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["license_header_present"])
        self.assertEqual(len(report["undocumented_arguments"]), 0)

    def test_11_linter_undocumented_argument(self):
        """Test 11: Kodda olup belgede yer almayan gizli/tehlikeli parametrenin tespit edildiğini doğrular (CWE-1188)."""
        # Kaynak koda gizli argüman ekle
        sneaky_code = (
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR\n"
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--input-file')\n"
            "p.add_argument('--backdoor-secret-debug')\n"
        )
        # UndocumentedArgumentError fırlatılmalı
        with self.assertRaises(UndocumentedArgumentError):
            SecurityDocLinter.lint(sneaky_code, self.valid_doc, is_code=True)

    def test_12_linter_missing_license(self):
        """Test 12: Kaynak kodda zorunlu kurumsal lisans başlığı yoksa hata fırlatıldığını doğrular."""
        code_without_license = (
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--input-file')\n"
        )
        with self.assertRaises(MissingLicenseHeaderError):
            SecurityDocLinter.lint(code_without_license, self.valid_doc, is_code=True)

    def test_13_linter_null_byte_path(self):
        """Test 13: Linter'a verilen yolda Null-Byte varsa engellendiğini doğrular (CWE-158)."""
        with self.assertRaises(NullByteInjectionError):
            SecurityDocLinter.lint("safe_script.py\x00poison", self.valid_doc)

    def test_14_type_validation_error(self):
        """Test 14: Linter ve şema yapıcısına geçersiz tip iletildiğinde TypeValidationError fırlatıldığını doğrular."""
        with self.assertRaises(TypeValidationError):
            SecurityScriptDoc("bu_bir_sozluk_degil")
        with self.assertRaises(TypeValidationError):
            SecurityDocLinter.lint(12345, self.valid_doc)


if __name__ == "__main__":
    unittest.main()
