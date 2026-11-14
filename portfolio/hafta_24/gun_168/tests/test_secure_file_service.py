# portfolio/hafta_24/gun_168/tests/test_secure_file_service.py
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

"""
Mini Proje 23: Güvenli Dosya Servisi Kapsamlı Birim Test Paketi.
15 birim testi ile depolama, dosya başlıkları, sihirli baytlar, webshell taraması,
dizin atlama ve yetkilendirme kontrollerini %100 kapsar.
"""

import os
import sys
import unittest
import tempfile
import shutil

# Gün dizini sys.path'e eklenir
gun_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if gun_dir not in sys.path:
    sys.path.insert(0, gun_dir)

from uygulama.secure_file_service_engine import (
    SecureFileService, SecurityException
)


class TestSecureFileService(unittest.TestCase):
    """Güvenli dosya servisi test sınıfı."""

    def setUp(self):
        """Her testten önce izole geçici depolama dizini ve servis motoru oluşturur."""
        # Geçici dizin açılır
        self.test_dir = tempfile.mkdtemp(prefix="test_file_service_")
        # Güvenli dosya servisi 1 MB sınırla başlatılır
        self.service = SecureFileService(base_storage_dir=self.test_dir, max_file_size=1024 * 1024)

    def tearDown(self):
        """Test bittikten sonra geçici dizin temizlenir."""
        # Geçici dizin tamamen silinir
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_valid_pdf_upload(self):
        """Geçerli bir PDF dosyasının başarıyla yüklenmesi ve UUID atanması."""
        # Geçerli PDF sihirli baytı ile başlayan veri
        pdf_data = b"%PDF-1.4\n1 0 obj << /Type /Catalog >>\nendobj\n%%EOF"
        # Dosya depoya kaydedilir
        meta = self.service.store_file("annual_report_2026.pdf", pdf_data, "user_1", "tenant_a")
        # Dosya UUID'si atanmış olmalıdır
        self.assertIsNotNone(meta.file_id)
        # Durumu ACTIVE olmalıdır
        self.assertEqual(meta.status, "ACTIVE")
        # MIME türü application/pdf olmalıdır
        self.assertEqual(meta.mime_type, "application/pdf")

    def test_02_valid_png_upload(self):
        """Geçerli bir PNG resminin sihirli baytlarıyla doğrulanıp yüklenmesi."""
        # PNG sihirli baytı
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        # Dosya yüklenir
        meta = self.service.store_file("company_logo.png", png_data, "user_1", "tenant_a")
        # Uzantı .png olmalıdır
        self.assertEqual(meta.extension, ".png")
        # MIME türü image/png olmalıdır
        self.assertEqual(meta.mime_type, "image/png")

    def test_03_path_traversal_in_filename_blocked(self):
        """Dosya adında dizin atlama (../) karakterleri bulunduğunda engellenmesi."""
        # Traversal içeren dosya adı
        evil_name = "../../../../etc/passwd.pdf"
        # SecurityException fırlatılmalıdır
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file(evil_name, b"%PDF-1.4\nTest\n%%EOF", "user_1", "tenant_a")
        # Hata kodu TRAVERSAL_DETECTED olmalıdır
        self.assertEqual(ctx.exception.code, "TRAVERSAL_DETECTED")

    def test_04_url_encoded_traversal_blocked(self):
        """URL kodlu dizin atlama (%2e%2e%2f) girişiminin çözülüp engellenmesi."""
        # URL kodlu traversal
        encoded_name = "%2e%2e%2f%2e%2e%2fsecret.pdf"
        # Güvenlik istisnası beklenir
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file(encoded_name, b"%PDF-1.4\nTest\n%%EOF", "user_1", "tenant_a")
        # Traversal tespit kodu doğrulanır
        self.assertEqual(ctx.exception.code, "TRAVERSAL_DETECTED")

    def test_05_null_byte_in_filename_blocked(self):
        """Dosya adında Null Byte (%00 veya \\x00) tespit edildiğinde engellenmesi."""
        # Null byte içeren dosya adı
        null_name = "contract.pdf%00.exe"
        # Güvenlik istisnası beklenir
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file(null_name, b"%PDF-1.4\nTest\n%%EOF", "user_1", "tenant_a")
        # Hata kodu NULL_BYTE_DETECTED olmalıdır
        self.assertEqual(ctx.exception.code, "NULL_BYTE_DETECTED")

    def test_06_double_extension_blocked(self):
        """Zararlı çoklu/çift uzantı manipülasyonunun (örn: invoice.pdf.php) engellenmesi."""
        # Çift uzantı saldırı dosyası
        double_ext_name = "invoice.pdf.php"
        # Güvenlik istisnası fırlatılmalıdır
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file(double_ext_name, b"<?php phpinfo(); ?>", "user_1", "tenant_a")
        # Hata ya çift uzantı ya da uzantı reddi olmalıdır
        self.assertIn(ctx.exception.code, ["DOUBLE_EXTENSION_DETECTED", "EXTENSION_NOT_ALLOWED"])

    def test_07_disallowed_extension_blocked(self):
        """Beyaz listede yer almayan (.exe) uzantılı dosyanın reddedilmesi."""
        # İzin verilmeyen uzantı
        bad_name = "malware.exe"
        # SecurityException fırlatılmalıdır
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file(bad_name, b"MZ\x90\x00Executable", "user_1", "tenant_a")
        # EXTENSION_NOT_ALLOWED kodu beklenir
        self.assertEqual(ctx.exception.code, "EXTENSION_NOT_ALLOWED")

    def test_08_magic_bytes_mismatch_blocked(self):
        """Beyan edilen uzantı ile dosya sihirli baytları uyuşmadığında engellenmesi."""
        # PDF uzantısı verilmiş ama içi düz rastgele veri
        fake_pdf = b"THIS IS NOT A VALID PDF FILE AT ALL"
        # Sihirli bayt uyuşmazlığı hatası beklenir
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file("fake_doc.pdf", fake_pdf, "user_1", "tenant_a")
        # MAGIC_BYTES_MISMATCH kodu doğrulanır
        self.assertEqual(ctx.exception.code, "MAGIC_BYTES_MISMATCH")

    def test_09_webshell_content_blocked(self):
        """Görünüşte geçerli PDF içerisine gömülmüş webshell betiğinin yakalanması."""
        # PDF başlığıyla başlayan ama içinde PHP kodu barındıran polyglot payload
        polyglot_payload = b"%PDF-1.4\n<?php system($_GET['c']); ?>\n%%EOF"
        # Zararlı içerik istisnası beklenir
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file("polyglot.pdf", polyglot_payload, "user_1", "tenant_a")
        # MALICIOUS_CONTENT_DETECTED kodu doğrulanır
        self.assertEqual(ctx.exception.code, "MALICIOUS_CONTENT_DETECTED")

    def test_10_file_size_limit_exceeded_blocked(self):
        """Belirlenen maksimum boyutu (1 MB) aşan dosyanın reddedilmesi."""
        # 1 MB + 10 bayt veri hazırlanır
        huge_data = b"%PDF-" + (b"A" * (1024 * 1024 + 10))
        # Boyut limiti hatası beklenir
        with self.assertRaises(SecurityException) as ctx:
            self.service.store_file("huge.pdf", huge_data, "user_1", "tenant_a")
        # FILE_TOO_LARGE kodu kontrol edilir
        self.assertEqual(ctx.exception.code, "FILE_TOO_LARGE")

    def test_11_secure_retrieve_and_headers(self):
        """Güvenli indirme sırasında Content-Disposition, nosniff ve CSP başlıklarının üretilmesi."""
        # Geçerli dosya yüklenir
        pdf_data = b"%PDF-1.4\nDocument\n%%EOF"
        meta = self.service.store_file("financial_audit.pdf", pdf_data, "user_1", "tenant_a")
        # Dosya sahibi tarafından çekilir
        ret_meta, content, headers = self.service.retrieve_file(meta.file_id, "user_1", "tenant_a", "user")
        # İçerik eşleşmelidir
        self.assertEqual(content, pdf_data)
        # Content-Disposition attachment olmalıdır
        self.assertIn("attachment", headers["Content-Disposition"])
        # nosniff başlığı bulunmalıdır
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        # CSP sandbox bulunmalıdır
        self.assertIn("sandbox", headers["Content-Security-Policy"])

    def test_12_cross_tenant_access_blocked(self):
        """Tenant A'ya ait bir dosyaya Tenant B kullanıcısının erişiminin engellenmesi (BOLA/IDOR)."""
        # Tenant A'da dosya oluşturulur
        pdf_data = b"%PDF-1.4\nTenant A Secret\n%%EOF"
        meta = self.service.store_file("secret.pdf", pdf_data, "user_1", "tenant_a")
        # Tenant B kullanıcısı erişmeye çalışır
        with self.assertRaises(SecurityException) as ctx:
            self.service.retrieve_file(meta.file_id, "user_2", "tenant_b", "user")
        # CROSS_TENANT_ACCESS_DENIED kodu beklenir
        self.assertEqual(ctx.exception.code, "CROSS_TENANT_ACCESS_DENIED")

    def test_13_unauthorized_user_in_same_tenant_blocked(self):
        """Aynı kurum içinde başkasının özel dosyasına yetkisiz erişimin engellenmesi."""
        # User 1 dosya yükler
        pdf_data = b"%PDF-1.4\nUser 1 Personal\n%%EOF"
        meta = self.service.store_file("private.pdf", pdf_data, "user_1", "tenant_a")
        # Aynı kurumdaki User 2 (standart rol) indirmeye çalışır
        with self.assertRaises(SecurityException) as ctx:
            self.service.retrieve_file(meta.file_id, "user_2", "tenant_a", "user")
        # PERMISSION_DENIED hatası beklenir
        self.assertEqual(ctx.exception.code, "PERMISSION_DENIED")

    def test_14_admin_can_retrieve_any_tenant_file(self):
        """Admin rolündeki kullanıcının kendi kurumu içerisindeki tüm dosyaları indirebilmesi."""
        # User 1 dosya yükler
        pdf_data = b"%PDF-1.4\nData\n%%EOF"
        meta = self.service.store_file("data.pdf", pdf_data, "user_1", "tenant_a")
        # Admin rolündeki yönetici dosyayı çeker
        ret_meta, content, headers = self.service.retrieve_file(meta.file_id, "admin_user", "tenant_a", "admin")
        # Başarıyla indirilmelidir
        self.assertEqual(content, pdf_data)

    def test_15_ssrf_safe_remote_fetch(self):
        """SSRF koruması: Uzak dosya getirmede Loopback ve Cloud Metadata IP'lerinin engellenmesi."""
        # Loopback URL'i denenir
        with self.assertRaises(SecurityException) as ctx1:
            self.service.fetch_remote_file_safe("http://127.0.0.1:8080/file.pdf", "user_1", "tenant_a")
        self.assertEqual(ctx1.exception.code, "LOOPBACK_BLOCKED")

        # Bulut metaveri servisi denenir
        with self.assertRaises(SecurityException) as ctx2:
            self.service.fetch_remote_file_safe("http://169.254.169.254/latest/meta-data", "user_1", "tenant_a")
        self.assertEqual(ctx2.exception.code, "METADATA_IP_BLOCKED")


if __name__ == "__main__":
    # Testler çalıştırılır
    unittest.main()
