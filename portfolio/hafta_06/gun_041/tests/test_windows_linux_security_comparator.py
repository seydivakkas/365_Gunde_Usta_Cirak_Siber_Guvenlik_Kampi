# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G041: Mini Proje 5 - Windows ve Linux Karşılaştırmalı Güvenlik Raporu Birim ve Negatif Test Süiti.

Bu test süiti, 10 göstergeli sistem güvenlik envanteri karşılaştırma motorunun
doğrulama mantığını, pozitif ve negatif sınır durumlarını, tip kontrollerini ve
raporlama yeteneklerini kapsamlı şekilde sınar.
"""

# Python'un yerleşik birim test çatısı olan unittest modülünü içe aktarıyoruz.
import unittest
# Dosya sistemi yolları ve dizin kontrolleri için os modülünü dahil ediyoruz.
import os
# Test girdilerini serileştirmek veya geçici JSON dosyaları oluşturmak için json modülünü yüklüyoruz.
import json
# Geçici dosya ve dizinler üzerinde güvenli test yapmak için tempfile modülünü kullanıyoruz.
import tempfile

# Test edilecek hedef uygulama modülünü ve istisna sınıflarını içe aktarıyoruz.
from portfolio.hafta_06.gun_041.uygulama.windows_linux_security_comparator import (
    load_and_validate_matrix,
    validate_indicator_node,
    calculate_system_metrics,
    compare_operating_systems,
    generate_markdown_comparison_report,
    SecurityIndicatorError,
    MANDATORY_INDICATOR_COUNT
)


class TestWindowsLinuxSecurityComparator(unittest.TestCase):
    """Windows ve Linux karşılaştırmalı denetim motoru için birim ve negatif test senaryoları."""

    def setUp(self) -> None:
        """Her testten önce çalıştırılarak geçerli örnek veri dosyalarının yollarını hazırlar."""
        # Mevcut test dosyasının bulunduğu dizini tespit ediyoruz.
        test_dir = os.path.dirname(os.path.abspath(__file__))
        # Proje kök dizinine göre örnek veri klasörünün yolunu hesaplıyoruz.
        self.sample_dir = os.path.join(test_dir, "..", "ornek_veri")
        # 10 göstergeli geçerli referans matris dosyasının tam yolunu belirliyoruz.
        self.baseline_matrix_path = os.path.join(self.sample_dir, "baseline_windows_linux_10_indicators.json")
        # Bozuk test senaryolarının yer aldığı JSON dosyasının yolunu belirliyoruz.
        self.corrupted_cases_path = os.path.join(self.sample_dir, "corrupted_comparison_test_cases.json")

    def test_01_valid_matrix_loading(self) -> None:
        """Geçerli 10 göstergeli matris dosyasının başarıyla yüklendiğini ve doğrulandığını test eder."""
        # Matrisi dosya yolundan yüklüyoruz.
        matrix_data = load_and_validate_matrix(self.baseline_matrix_path)
        # Yüklenen verinin bir sözlük olduğunu doğruluyoruz.
        self.assertIsInstance(matrix_data, dict)
        # 'indicators' anahtarının varlığını kontrol ediyoruz.
        self.assertIn("indicators", matrix_data)
        # Tam olarak 10 gösterge bulunduğunu teyit ediyoruz.
        self.assertEqual(len(matrix_data["indicators"]), MANDATORY_INDICATOR_COUNT)

    def test_02_all_10_indicators_present(self) -> None:
        """IND-01 ile IND-10 arasındaki tüm standart göstergelerin sırayla mevcut olduğunu doğrular."""
        # Referans matrisi yüklüyoruz.
        matrix_data = load_and_validate_matrix(self.baseline_matrix_path)
        # Mevcut gösterge kimliklerini bir listeye topluyoruz.
        indicator_ids = [ind["indicator_id"] for ind in matrix_data["indicators"]]
        # 1'den 10'a kadar beklenen tüm gösterge kimliklerini kontrol ediyoruz.
        for i in range(1, 11):
            # Beklenen kimlik biçimi (Örn: IND-01, IND-10).
            expected_id = f"IND-{i:02d}"
            # Kimliğin listede yer aldığını sınıyoruz.
            self.assertIn(expected_id, indicator_ids)

    def test_03_windows_metrics_calculation(self) -> None:
        """Windows Server için toplam puan, yüzde ve risk seviyesi hesaplamalarını denetler."""
        # Matrisi yüklüyoruz.
        matrix_data = load_and_validate_matrix(self.baseline_matrix_path)
        # Windows metriklerini hesaplıyoruz.
        win_metrics = calculate_system_metrics(matrix_data["indicators"], "windows")
        # Toplam puanın pozitif ve 100'e eşit veya küçük olduğunu doğruluyoruz.
        self.assertGreaterEqual(win_metrics["total_score"], 0)
        self.assertLessEqual(win_metrics["total_score"], 100)
        # Maksimum olası puanın 100 olduğunu teyit ediyoruz.
        self.assertEqual(win_metrics["max_possible_score"], 100.0)
        # Başarı yüzdesinin 0 ile 100 aralığında olduğunu sınıyoruz.
        self.assertTrue(0 <= win_metrics["percentage"] <= 100)
        # Risk seviyesinin geçerli bir metin içerdiğini kontrol ediyoruz.
        self.assertIn("Risk", win_metrics["risk_level"])

    def test_04_linux_metrics_calculation(self) -> None:
        """Linux (Ubuntu) için toplam puan, yüzde ve risk seviyesi hesaplamalarını denetler."""
        # Matrisi yüklüyoruz.
        matrix_data = load_and_validate_matrix(self.baseline_matrix_path)
        # Linux metriklerini hesaplıyoruz.
        lin_metrics = calculate_system_metrics(matrix_data["indicators"], "linux")
        # Toplam puan sınırlarını doğruluyoruz.
        self.assertGreaterEqual(lin_metrics["total_score"], 0)
        self.assertLessEqual(lin_metrics["total_score"], 100)
        # Gösterge toplamlarının 10'a eşit olduğunu sınıyoruz.
        total_counted = lin_metrics["compliant_count"] + lin_metrics["partial_count"] + lin_metrics["non_compliant_count"]
        self.assertEqual(total_counted, MANDATORY_INDICATOR_COUNT)

    def test_05_score_differential_calculation(self) -> None:
        """Karşılaştırma motorunun iki işletim sistemi arasındaki puan farkını doğru hesapladığını test eder."""
        # Matrisi yüklüyoruz.
        matrix_data = load_and_validate_matrix(self.baseline_matrix_path)
        # Karşılaştırmayı çalıştırıyoruz.
        comparison = compare_operating_systems(matrix_data)
        # Puan farkını alıyoruz.
        diff = comparison["score_differential_linux_minus_windows"]
        # Farkın Linux puanı eksi Windows puanı olduğunu matematiksel olarak teyit ediyoruz.
        expected_diff = round(comparison["linux"]["total_score"] - comparison["windows"]["total_score"], 1)
        self.assertEqual(diff, expected_diff)

    def test_06_markdown_report_generation(self) -> None:
        """Üretilen Markdown raporunun zorunlu başlıkları, tabloları ve lisans bildirimini içerdiğini doğrular."""
        # Matrisi yüklüyoruz.
        matrix_data = load_and_validate_matrix(self.baseline_matrix_path)
        # Karşılaştırma yapıyoruz.
        comparison = compare_operating_systems(matrix_data)
        # Markdown raporu üretiyoruz.
        report = generate_markdown_comparison_report(comparison)
        # Raporun boş olmadığını sınıyoruz.
        self.assertTrue(len(report) > 0)
        # Özel lisans uyarısının raporda bulunduğunu teyit ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", report)
        # Windows ve Linux başlıklarının varlığını denetliyoruz.
        self.assertIn("Windows Server 2022", report)
        self.assertIn("Ubuntu 22.04 LTS", report)
        # Tablo başlıklarının yer aldığını kontrol ediyoruz.
        self.assertIn("Toplam Güvenlik Puanı", report)

    def test_07_negative_missing_indicator_count(self) -> None:
        """Negatif Kontrol: 10'dan az (örneğin 9) gösterge içeren matrisin reddedildiğini doğrular."""
        # Geçici bir 9 göstergeli matris oluşturuyoruz.
        matrix_data = load_and_validate_matrix(self.baseline_matrix_path)
        # Son göstergeyi çıkararak listeyi 9 elemana düşürüyoruz.
        matrix_data["indicators"] = matrix_data["indicators"][:9]
        
        # Geçici bir dosyaya yazıyoruz.
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json") as tf:
            json.dump(matrix_data, tf)
            temp_path = tf.name
            
        try:
            # 9 göstergeli dosya okunduğunda SecurityIndicatorError fırlatılmasını bekliyoruz.
            with self.assertRaises(SecurityIndicatorError) as ctx:
                load_and_validate_matrix(temp_path)
            # Hata mesajında gösterge sayısına dair uyarı bulunduğunu sınıyoruz.
            self.assertIn("en az 10 gösterge", str(ctx.exception))
        finally:
            # Geçici dosyayı temizliyoruz.
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_08_negative_score_overflow(self) -> None:
        """Negatif Kontrol: Gösterge puanının 10'u aşması durumunda SecurityIndicatorError fırlatıldığını doğrular."""
        # Geçersiz bir gösterge hazırlıyoruz (puan = 15).
        invalid_ind = {
            "indicator_id": "IND-99",
            "name": "Taşan Puan Testi",
            "windows": {"status": "COMPLIANT", "score": 15},
            "linux": {"status": "COMPLIANT", "score": 9}
        }
        # Hata fırlatıldığını denetliyoruz.
        with self.assertRaises(SecurityIndicatorError) as ctx:
            validate_indicator_node(invalid_ind, 1)
        # Hata açıklamasında puan aralığı uyarısının yer aldığını sınıyoruz.
        self.assertIn("0-10 aralığında olmalıdır", str(ctx.exception))

    def test_09_negative_score_negative(self) -> None:
        """Negatif Kontrol: Gösterge puanının negatif olması durumunda sistemin hata ürettiğini doğrular."""
        # Negatif puan içeren gösterge oluşturuyoruz (puan = -2).
        invalid_ind = {
            "indicator_id": "IND-98",
            "name": "Negatif Puan Testi",
            "windows": {"status": "COMPLIANT", "score": 8},
            "linux": {"status": "NON_COMPLIANT", "score": -2}
        }
        # İstisnanın yakalandığını sınıyoruz.
        with self.assertRaises(SecurityIndicatorError) as ctx:
            validate_indicator_node(invalid_ind, 1)
        # Hata mesajını doğruluyoruz.
        self.assertIn("0-10 aralığında olmalıdır", str(ctx.exception))

    def test_10_negative_score_non_numeric(self) -> None:
        """Negatif Kontrol: Puanın dize (string) olarak verilmesi durumunda tip hatası fırlatıldığını doğrular."""
        # String puan içeren gösterge (puan = "mukemmel").
        invalid_ind = {
            "indicator_id": "IND-97",
            "name": "Tip Hatası Testi",
            "windows": {"status": "COMPLIANT", "score": "mukemmel"},
            "linux": {"status": "COMPLIANT", "score": 9}
        }
        # Tip istisnasının fırlatıldığını sınıyoruz.
        with self.assertRaises(SecurityIndicatorError) as ctx:
            validate_indicator_node(invalid_ind, 1)
        # Hata mesajında sayı beklenmesi gerektiğinin yazdığını teyit ediyoruz.
        self.assertIn("puanı sayı olmalıdır", str(ctx.exception))

    def test_11_negative_score_boolean_rejection(self) -> None:
        """Negatif Kontrol: Python'da bool tipinin int alt sınıfı olmasından kaynaklanan sızıntıyı sınar."""
        # Puan yerine boolean True verilmiş gösterge.
        invalid_ind = {
            "indicator_id": "IND-96",
            "name": "Boolean Sızıntı Testi",
            "windows": {"status": "COMPLIANT", "score": True},
            "linux": {"status": "COMPLIANT", "score": 9}
        }
        # Boolean değerin reddedildiğini teyit ediyoruz.
        with self.assertRaises(SecurityIndicatorError) as ctx:
            validate_indicator_node(invalid_ind, 1)
        # Sayı olma şartı uyarısını sınıyoruz.
        self.assertIn("puanı sayı olmalıdır", str(ctx.exception))

    def test_12_negative_missing_os_node(self) -> None:
        """Negatif Kontrol: Zorunlu işletim sistemi düğümünün (windows veya linux) eksik olması durumunu sınar."""
        # Linux düğümü bulunmayan eksik gösterge.
        invalid_ind = {
            "indicator_id": "IND-95",
            "name": "Eksik İşletim Sistemi Düğümü Testi",
            "windows": {"status": "COMPLIANT", "score": 8}
        }
        # Hatanın yakalandığını sınıyoruz.
        with self.assertRaises(SecurityIndicatorError) as ctx:
            validate_indicator_node(invalid_ind, 1)
        # Eksik düğüm uyarısını teyit ediyoruz.
        self.assertIn("zorunlu 'linux' verisi eksik", str(ctx.exception))

    def test_13_negative_non_dict_indicator(self) -> None:
        """Negatif Kontrol: Gösterge nesnesi yerine dize veya liste geçirilmesi durumunu test eder."""
        # Sözlük yerine string gönderiyoruz.
        invalid_entry = "Bu bir gosterge degildir"
        # İstisnanın fırlatıldığını denetliyoruz.
        with self.assertRaises(SecurityIndicatorError) as ctx:
            # Tip denetimi fonksiyonunu çağırıyoruz (type ignore cast ile test ediyoruz).
            validate_indicator_node(invalid_entry, 1)  # type: ignore
        # Hata mesajında sözlük nesnesi uyarısını kontrol ediyoruz.
        self.assertIn("sözlük nesnesi olmalıdır", str(ctx.exception))

    def test_14_negative_corrupted_json_file(self) -> None:
        """Negatif Kontrol: Sentaksı bozuk bir JSON dosyası verildiğinde sistemin çökmeden hata verdiğini doğrular."""
        # Sentaksı bozuk JSON içeriğine sahip geçici dosya yazıyoruz.
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json") as tf:
            tf.write("{ 'bozuk_json': anahtar_kapali_degil, }")
            temp_path = tf.name
            
        try:
            # Bozuk JSON okumasının SecurityIndicatorError fırlattığını sınıyoruz.
            with self.assertRaises(SecurityIndicatorError) as ctx:
                load_and_validate_matrix(temp_path)
            # Bozuk JSON uyarısının varlığını teyit ediyoruz.
            self.assertIn("bozuk JSON verisi", str(ctx.exception))
        finally:
            # Geçici dosyayı temizliyoruz.
            if os.path.exists(temp_path):
                os.remove(temp_path)


# Test süiti doğrudan çalıştırıldığında testleri icra ediyoruz.
if __name__ == "__main__":
    # Testleri detaylı (verbose) kipte başlatıyoruz.
    unittest.main()
