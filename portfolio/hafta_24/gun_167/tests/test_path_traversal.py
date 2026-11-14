# -*- coding: utf-8 -*-
r"""
Gün 167: Path Traversal ve Dosya Erişimi Birim Testleri (test_path_traversal.py)

Bu test paketi; standart dizin atlama (../, ..\), mutlak yol enjeksiyonu,
URL ve Çift URL kodlamalı atlatmalar, iç içe özyinelemeli filtre aşma denemeleri (....//),
Null Byte (%00) saldırıları, uzantı ve karakter beyaz listeleri, zafiyetli okuyucudaki
os.path.join davranış kusurlarını ve kanonik hapis (Canonical Jail) korumalarını
15 kapsamlı birim test senaryosuyla doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import os  # Dosya ve dizin yolu işlemleri için
import sys  # Sistem çalışma yolu yönetimi için
import unittest  # Birim test çerçevesi için

# Uygulama dizininin eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Test dizini
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # En başa ekle

# Test edilecek motor bileşenleri
from path_traversal_engine import (
    PathTraversalDefenseEngine,  # Merkezi motor
    EnterpriseStoragePolicy,  # Depolama politikası
    TraversalRiskType  # Risk türleri
)


class TestPathTraversalDefenseEngine(unittest.TestCase):
    """Path Traversal ve dosya erişim güvenlik denetimleri için 15 fonksiyonel test sınıfı."""

    def setUp(self):
        """Her testten önce temiz kurumsal depolama politikası ve motor örneği hazırlanır."""
        self.policy = EnterpriseStoragePolicy(
            base_directory="/var/www/kurumsal_depo",
            allowed_extensions={".pdf", ".png", ".jpg", ".docx", ".txt"},
            allow_subdirectories=False,
            enforce_strict_basename=True
        )
        self.engine = PathTraversalDefenseEngine(policy=self.policy)  # Motor başlatılır

    def test_01_dot_dot_slash_unix_blocked(self):
        """1. Test: ../../../../etc/passwd göreli dizin atlama saldırısının engellendiğini doğrular."""
        res = self.engine.validate_path("../../../../etc/passwd")  # Unix dizin atlama
        self.assertFalse(res.is_safe)  # Güvensiz bulunmalı
        self.assertEqual(res.risk_type, TraversalRiskType.DOT_DOT_SLASH)  # Risk türü doğrulanır
        self.assertIn("Göreli dizin atlama", res.rejection_reason)  # Gerekçe kontrolü

    def test_02_dot_dot_backslash_windows_blocked(self):
        r"""2. Test: ..\..\Windows\win.ini ters eğik çizgi dizin atlama saldırısının engellendiğini doğrular."""
        res = self.engine.validate_path(r"..\..\Windows\win.ini")  # Windows dizin atlama
        self.assertFalse(res.is_safe)  # Güvensiz bulunmalı
        self.assertEqual(res.risk_type, TraversalRiskType.DOT_DOT_SLASH)  # Risk türü

    def test_03_absolute_path_unix_blocked(self):
        """3. Test: /etc/passwd mutlak Unix yolunun ABSOLUTE_PATH_INJECTION ile engellendiğini doğrular."""
        res = self.engine.validate_path("/etc/passwd")  # Mutlak yol
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, TraversalRiskType.ABSOLUTE_PATH_INJECTION)  # Mutlak yol riski

    def test_04_absolute_path_windows_blocked(self):
        r"""4. Test: C:\Windows\System32\drivers\etc\hosts mutlak Windows yolunun engellendiğini doğrular."""
        res = self.engine.validate_path(r"C:\Windows\System32\drivers\etc\hosts")  # Windows mutlak yol
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, TraversalRiskType.ABSOLUTE_PATH_INJECTION)  # Mutlak yol riski

    def test_05_url_encoded_traversal_blocked(self):
        """5. Test: %2e%2e%2f URL kodlanmış dizin atlamanın çözümlenip engellendiğini doğrular."""
        res = self.engine.validate_path("%2e%2e%2f%2e%2e%2ffatura.pdf")  # URL kodlu yol
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, TraversalRiskType.URL_ENCODED_TRAVERSAL)  # URL kodlama riski

    def test_06_double_url_encoded_traversal_blocked(self):
        """6. Test: %252e%252e%252f Çift URL kodlanmış dizin atlamanın çözülüp engellendiğini doğrular."""
        res = self.engine.validate_path("%252e%252e%252f%252e%252e%252fetc/passwd")  # Çift URL kodlu
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, TraversalRiskType.DOUBLE_URL_ENCODED)  # Çift URL riski

    def test_07_nested_recursive_filter_bypass_blocked(self):
        """7. Test: ....//....//etc/passwd iç içe filtre atlatma kalıbının engellendiğini doğrular."""
        res = self.engine.validate_path("....//....//etc/passwd")  # İç içe kalıp
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, TraversalRiskType.NESTED_FILTER_BYPASS)  # İç içe filtre riski

    def test_08_null_byte_injection_blocked(self):
        """8. Test: fatura_2026.pdf%00.exe Null Byte sonlandırma saldırısının engellendiğini doğrular."""
        res = self.engine.validate_path("fatura_2026.pdf%00.exe")  # Null byte URL
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, TraversalRiskType.NULL_BYTE_INJECTION)  # Null byte riski
        res_raw_null = self.engine.validate_path("dosya.txt\x00.png")  # Ham null bayt
        self.assertFalse(res_raw_null.is_safe)  # Engellenmeli
        self.assertEqual(res_raw_null.risk_type, TraversalRiskType.NULL_BYTE_INJECTION)

    def test_09_unapproved_extension_blocked(self):
        """9. Test: .env veya .sh gibi tehlikeli sistem uzantılarının UNAPPROVED_EXTENSION ile engellendiğini doğrular."""
        res_env = self.engine.validate_path("sistem_ayarlari.env")  # İzin verilmeyen uzantı
        self.assertFalse(res_env.is_safe)  # Engellenmeli
        self.assertEqual(res_env.risk_type, TraversalRiskType.UNAPPROVED_EXTENSION)
        res_sh = self.engine.validate_path("calistir.sh")  # Shell betiği
        self.assertFalse(res_sh.is_safe)  # Engellenmeli
        self.assertEqual(res_sh.risk_type, TraversalRiskType.UNAPPROVED_EXTENSION)

    def test_10_special_characters_in_filename_blocked(self):
        """10. Test: Dosya adındaki komut ayracı veya zararlı karakterlerin engellendiğini doğrular."""
        res = self.engine.validate_path("fatura;cat /etc/passwd.pdf")  # Komut enjeksiyonu karakteri
        self.assertFalse(res.is_safe)  # Engellenmeli

    def test_11_valid_file_read_success(self):
        """11. Test: Güvenli depodaki meşru dosyanın (fatura_2026.pdf) 200 OK ile okunduğunu doğrular."""
        resp = self.engine.secure_read_file("fatura_2026.pdf")  # Meşru dosya
        self.assertTrue(resp["success"])  # Başarılı olmalı
        self.assertEqual(resp["status_code"], 200)  # 200 OK
        self.assertIn("Kurumsal Mali Fatura", resp["content"])  # İçerik eşleşmeli

    def test_12_nonexistent_file_in_jail_returns_404(self):
        """12. Test: Depo sınırları içinde ancak mevcut olmayan dosyanın 404 döndürdüğünü doğrular."""
        resp = self.engine.secure_read_file("olmayan_dosya.pdf")  # Olmayan dosya
        self.assertFalse(resp["success"])  # Başarısız olmalı
        self.assertEqual(resp["status_code"], 404)  # 404 Not Found
        self.assertIsNone(resp["content"])  # İçerik boş olmalı

    def test_13_vulnerable_reader_leaks_etc_passwd(self):
        """13. Test: Zafiyetli dosya okuyucunun ../../etc/passwd ile parola dosyasını sızdırdığını doğrular."""
        resp = self.engine.vulnerable_read_file("../../../../etc/passwd")  # Zafiyetli çağrı
        self.assertTrue(resp["success"])  # Dosya okundu
        self.assertTrue(resp["is_vulnerable_leak"])  # ZAFİYET KANITI: Depo dışına taştı!
        self.assertIn("root:x:0:0:root", resp["content"])  # Parola içeriği sızdırıldı

    def test_14_vulnerable_reader_leaks_via_absolute_path(self):
        """14. Test: os.path.join fonksiyonunun mutlak yol görünce base_dir'i sildiğini ve veri sızdırdığını doğrular."""
        resp = self.engine.vulnerable_read_file("/var/www/.env")  # Mutlak yol ile join
        self.assertTrue(resp["success"])  # Okundu
        self.assertTrue(resp["is_vulnerable_leak"])  # Sızıntı doğrulandı
        self.assertIn("JWT_SECRET_KEY", resp["content"])  # Gizli ortam değişkenleri sızdı

    def test_15_secure_reader_blocks_jail_escape(self):
        """15. Test: Güvenli okuyucunun depo dışına taşan istekleri 403 Forbidden ile engellediğini doğrular."""
        resp = self.engine.secure_read_file("../../../../var/www/.env")  # Saldırı
        self.assertFalse(resp["success"])  # Engellenmeli
        self.assertEqual(resp["status_code"], 403)  # 403 Forbidden
        self.assertIsNone(resp["content"])  # İçerik verilmemeli


if __name__ == "__main__":
    unittest.main()
