# ============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
#
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
#
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
#
# YASAKLAR:
#   1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
#   2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
#   3. Alt lisanslanamaz, satılamaz veya devredilemez.
#   4. Tersine mühendislik yapılamaz.
#
# İZİN VERİLEN KULLANIM:
#   - GitHub üzerinde görüntüleme ve okuma.
#   - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).
#
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ============================================================================
"""
Gün 34: Dosya Türleri, Metadata ve MIME Birim Testleri
Bu test paketi; sihirli bayt (magic bytes) doğrulaması, uzantı-imza uyuşmazlığı,
çift uzantı saldırıları, boş dosya işleme ve negatif kontroller dahil
14 kapsamlı test senaryosu içerir.
"""

# Dosya sistemi yolları ve operasyonları için os modülü
import os
# Sistem arama yolları için sys modülü
import sys
# Birim test çerçevesi için unittest modülü
import unittest
# JSON veri doğrulama için json modülü
import json

# Test edilen modüle erişim için proje ana dizinini sys.path'e ekliyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Gün 34 analiz sınıfı ve modellerini içe aktarıyoruz
from portfolio.hafta_05.gun_034.uygulama.file_metadata_mime_analyzer import (
    FileMetadataMimeAnalyzer,
    FileSignature,
    FileInspectionResult
)


class TestFileMetadataMimeAnalyzer(unittest.TestCase):
    """Dosya türleri, metadata ve MIME analizcisinin 14 kapsamlı test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz analizci ve veri yolları hazırlar."""
        # Yeni analizci nesnesini oluşturuyoruz
        self.analyzer = FileMetadataMimeAnalyzer()
        # Temel dizini belirliyoruz
        self.base_dir = os.path.dirname(CURRENT_DIR)
        # Örnek veri dizini
        self.data_dir = os.path.join(self.base_dir, "ornek_veri")
        # Örnek dosyalar dizini
        self.sample_files_dir = os.path.join(self.data_dir, "sample_files")
        # Örnek envanter dosyası
        self.inventory_path = os.path.join(self.data_dir, "sample_file_type_inventory.json")
        # Bozuk veri seti dosyası
        self.corrupted_path = os.path.join(self.data_dir, "corrupted_metadata_test_cases.json")

    def test_01_init_state(self) -> None:
        """Analizcinin başlangıç durumunun boş ve temiz olduğunu doğrular."""
        # Başlangıçta sonuç listesi boş olmalıdır
        self.assertEqual(len(self.analyzer.results), 0)
        # Başlangıçta bozuk kayıt listesi boş olmalıdır
        self.assertEqual(len(self.analyzer.corrupted_records), 0)

    def test_02_detect_pdf_signature(self) -> None:
        """Meşru PDF dosyasının başlık baytlarından (%PDF-) tam doğrulukla tespit edildiğini test eder."""
        pdf_path = os.path.join(self.sample_files_dir, "sample_document.pdf")
        res = self.analyzer.inspect_file(pdf_path)
        # Biçim adını sınıyoruz
        self.assertEqual(res.detected_format, "PDF Document")
        # MIME türünü sınıyoruz
        self.assertEqual(res.detected_mime, "application/pdf")
        # Uyuşmazlık olmamalıdır
        self.assertFalse(res.is_mismatch)
        self.assertEqual(res.risk_level, "CLEAN")

    def test_03_detect_png_signature(self) -> None:
        """Meşru PNG dosyasının sihirli baytlarından (\x89PNG) doğru tespit edildiğini test eder."""
        png_path = os.path.join(self.sample_files_dir, "sample_image.png")
        res = self.analyzer.inspect_file(png_path)
        self.assertEqual(res.detected_format, "PNG Image")
        self.assertEqual(res.detected_mime, "image/png")
        self.assertFalse(res.is_mismatch)
        self.assertEqual(res.risk_level, "CLEAN")

    def test_04_detect_zip_signature(self) -> None:
        """Meşru ZIP arşivinin (PK\x03\x04) doğru tespit edildiğini test eder."""
        zip_path = os.path.join(self.sample_files_dir, "sample_archive.zip")
        res = self.analyzer.inspect_file(zip_path)
        self.assertEqual(res.detected_format, "ZIP Archive")
        self.assertEqual(res.detected_mime, "application/zip")
        self.assertFalse(res.is_mismatch)
        self.assertEqual(res.risk_level, "CLEAN")

    def test_05_detect_pe_mismatch_fake_pdf(self) -> None:
        """Uzantısı .pdf olan fakat MZ başlığı içeren zararlı dosyayı (CRITICAL) tespit eder."""
        fake_pdf = os.path.join(self.sample_files_dir, "fake_invoice.pdf")
        res = self.analyzer.inspect_file(fake_pdf)
        # Uyuşmazlığın yakalandığını sınıyoruz
        self.assertTrue(res.is_mismatch)
        # Gerçek biçimin PE çalıştırılabilir ikili olduğunu sınıyoruz
        self.assertEqual(res.detected_format, "Windows PE Executable")
        # Risk seviyesinin CRITICAL olduğunu teyit ediyoruz
        self.assertEqual(res.risk_level, "CRITICAL")
        # Açıklamanın Extension Spoofing uyarısını içerdiğini sınıyoruz
        self.assertIn("Extension Spoofing", res.finding_description)

    def test_06_detect_elf_mismatch_disguised_photo(self) -> None:
        """Uzantısı .jpg olan fakat Linux ELF başlığı içeren ikiliyi (CRITICAL) tespit eder."""
        fake_jpg = os.path.join(self.sample_files_dir, "disguised_photo.jpg")
        res = self.analyzer.inspect_file(fake_jpg)
        self.assertTrue(res.is_mismatch)
        self.assertEqual(res.detected_format, "Linux ELF Executable")
        self.assertEqual(res.risk_level, "CRITICAL")

    def test_07_detect_double_extension(self) -> None:
        """Çift uzantı saldırısını (.pdf.exe) ve gizli yürütme girişimini yakalar."""
        dbl_path = os.path.join(self.sample_files_dir, "urgent_bill.pdf.exe")
        res = self.analyzer.inspect_file(dbl_path)
        self.assertTrue(res.is_double_extension)
        self.assertTrue(res.is_mismatch)
        self.assertEqual(res.risk_level, "HIGH")

    def test_08_empty_file_handling(self) -> None:
        """0 baytlık boş dosyanın çökme olmaksızın 'Empty File' olarak işlendiğini test eder."""
        empty_path = os.path.join(self.sample_files_dir, "empty_zero_byte.bin")
        res = self.analyzer.inspect_file(empty_path)
        self.assertEqual(res.detected_format, "Empty File")
        self.assertEqual(res.detected_mime, "application/x-empty")
        self.assertEqual(res.size_bytes, 0)

    def test_09_plain_text_detection(self) -> None:
        """Sihirli ikili bayt içermeyen salt metin dosyasının 'Plain Text' olarak tespit edildiğini test eder."""
        txt_path = os.path.join(self.sample_files_dir, "sample_text.txt")
        res = self.analyzer.inspect_file(txt_path)
        self.assertEqual(res.detected_format, "Plain Text")
        self.assertEqual(res.detected_mime, "text/plain")

    def test_10_inventory_analysis(self) -> None:
        """Envanter dosyasının taranıp 7 dosyanın başarıyla analiz edildiğini test eder."""
        analysis_res = self.analyzer.load_inventory_and_analyze(self.inventory_path, self.data_dir)
        # Toplam analiz edilen dosya sayısı 7 olmalıdır
        self.assertEqual(analysis_res["total_analyzed"], 7)
        # Uyuşmazlık sayısı en az 3 olmalıdır (fake_invoice, disguised_photo, urgent_bill)
        self.assertGreaterEqual(analysis_res["mismatch_count"], 3)
        # Kritik tehdit sayısı en az 2 olmalıdır
        self.assertGreaterEqual(analysis_res["critical_threats"], 2)

    def test_11_negative_control_corrupted_manifest(self) -> None:
        """Negatif kontrol: Bozuk şemalı ve hatalı metadata kayıtlarının güvenle reddedildiğini test eder."""
        res = self.analyzer.load_inventory_and_analyze(self.corrupted_path, self.data_dir)
        # Hiçbir bozuk kaydın sonuç listesine alınmadığını sınıyoruz
        self.assertEqual(res["total_analyzed"], 0)
        # 6 bozuk kaydın tamamının yakalandığını sınıyoruz
        self.assertEqual(len(self.analyzer.corrupted_records), 6)
        # Hata gerekçelerini denetliyoruz
        reasons = [c["reason"] for c in self.analyzer.corrupted_records]
        self.assertTrue(any("EKSIK_ALAN" in r for r in reasons))
        self.assertTrue(any("GECERSIZ_ISIM" in r for r in reasons))
        self.assertTrue(any("GECERSIZ_YOL" in r for r in reasons))
        self.assertTrue(any("KAYIT_SOZLUK_DEGIL" in r for r in reasons))

    def test_12_negative_control_missing_file(self) -> None:
        """Negatif kontrol: Diskte var olmayan hayali bir dosyada FileNotFoundError fırlatıldığını test eder."""
        fake_path = os.path.join(self.sample_files_dir, "olmayan_hayali_dosya_9999.xyz")
        with self.assertRaises(FileNotFoundError):
            self.analyzer.inspect_file(fake_path)

    def test_13_ascii_report_generation(self) -> None:
        """ASCII denetim raporunun formatını ve kritik tehdit uyarılarını eksiksiz ürettiğini test eder."""
        self.analyzer.load_inventory_and_analyze(self.inventory_path, self.data_dir)
        report = self.analyzer.generate_ascii_report()
        self.assertIn("DOSYA TÜRLERİ, METADATA VE MIME GÜVENLİK ANALİZ RAPORU", report)
        self.assertIn("UYUSMAZLIK", report)
        self.assertIn("fake_invoice.pdf", report)

    def test_14_custom_license_presence(self) -> None:
        """Özel lisans kuralı gereğince dosyalarda 'Özel Lisans - Tüm Hakları Saklıdır' ibaresini denetler."""
        app_file = os.path.join(self.base_dir, "uygulama", "file_metadata_mime_analyzer.py")
        with open(app_file, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", content)
        self.assertIn("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)", content)
        self.assertIn("YASAKLAR:", content)
        self.assertIn("YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ", content)


if __name__ == "__main__":
    unittest.main()
