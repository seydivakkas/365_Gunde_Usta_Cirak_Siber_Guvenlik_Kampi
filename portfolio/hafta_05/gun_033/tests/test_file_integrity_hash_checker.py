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
Gün 33: Dosya Hash ve Kriptografik Bütünlük Birim Testleri
Bu test paketi; SHA-256 ve MD5 özetleme, Çığ Etkisi (Avalanche Effect),
bütünlük ihlali tespiti, kayıp ve yetkisiz dosya saptama ile
negatif kontroller dahil 14 kapsamlı test senaryosu içerir.
"""

# Dosya ve dizin yönetimi için os standart modülü
import os
# Sistem çalışma yolları ve parametreleri için sys modülü
import sys
# Birim test çatısı için unittest modülü
import unittest
# Geçici test dosyaları ve dizinleri üretmek için tempfile modülü
import tempfile
# JSON test manipülasyonları için json modülü
import json
# Geçici dizinleri temizlemek için shutil modülü
import shutil

# Test edilecek modülü içe aktarmak için proje kök dizinini ekliyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Üst kök dizini belirliyoruz
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", ".."))
# sys.path'e dahil ediyoruz
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Gün 33 denetleyici sınıfı ve veri modellerini içe aktarıyoruz
from portfolio.hafta_05.gun_033.uygulama.file_integrity_hash_checker import (
    FileIntegrityHashChecker,
    FileMetadata,
    IntegrityFinding
)


class TestFileIntegrityHashChecker(unittest.TestCase):
    """Dosya hash ve kriptografik bütünlük denetleyicisinin 14 birim testi."""

    def setUp(self) -> None:
        """Her testten önce temiz bir denetleyici ve veri yolları hazırlar."""
        # Yeni denetleyici örneğini oluşturuyoruz
        self.checker = FileIntegrityHashChecker()
        # Temel dizini tespit ediyoruz
        self.base_dir = os.path.dirname(CURRENT_DIR)
        # Örnek veri dizinini belirliyoruz
        self.data_dir = os.path.join(self.base_dir, "ornek_veri")
        # Örnek dosyalar dizinini belirliyoruz
        self.sample_files_dir = os.path.join(self.data_dir, "sample_files")
        # Yetkili taban çizgisi dosya yolunu alıyoruz
        self.baseline_path = os.path.join(self.data_dir, "sample_baseline_manifest.json")
        # Bozuk negatif test dosya yolunu alıyoruz
        self.corrupted_path = os.path.join(self.data_dir, "corrupted_hash_test_cases.json")

    def test_01_initial_state(self) -> None:
        """Denetleyicinin başlangıç durumunun boş ve temiz olduğunu doğrular."""
        # Başlangıçta taban çizgisi eleman sayısı 0 olmalıdır
        self.assertEqual(len(self.checker.baseline_entries), 0)
        # Başlangıçta bulgu sayısı 0 olmalıdır
        self.assertEqual(len(self.checker.findings), 0)
        # Bozuk kayıt sayısı başlangıçta 0 olmalıdır
        self.assertEqual(len(self.checker.corrupted_records), 0)

    def test_02_compute_file_hash_sha256(self) -> None:
        """config.json dosyasının fiili SHA-256 özetini tam doğrulukla hesaplar."""
        # Hedef dosya yolunu alıyoruz
        target_file = os.path.join(self.sample_files_dir, "config.json")
        # SHA-256 özetini hesaplatıyoruz
        computed_hash = self.checker.compute_file_hash(target_file, "sha256")
        # Beklenen bilinen kesin hash ile sınıyoruz
        expected_hash = "2cf886ce37d1c9fdf227bd875fc638c83938da29d65c074a562c30e79136474f"
        self.assertEqual(computed_hash, expected_hash)

    def test_03_compute_file_hash_md5(self) -> None:
        """config.json dosyasının fiili MD5 özetini tam doğrulukla hesaplar."""
        # Hedef dosya yolunu alıyoruz
        target_file = os.path.join(self.sample_files_dir, "config.json")
        # MD5 özetini hesaplatıyoruz
        computed_md5 = self.checker.compute_file_hash(target_file, "md5")
        # Beklenen bilinen kesin MD5 ile sınıyoruz
        expected_md5 = "ab2d7aa56941c4b10d1eb49fcbe0a32e"
        self.assertEqual(computed_md5, expected_md5)

    def test_04_avalanche_effect_demonstration(self) -> None:
        """Tek bir bit/karakter değişiminin Çığ Etkisini (%40-%60 bit farkı) doğruladığını test eder."""
        # Orijinal ve tahrif edilmiş konfigürasyon dosyalarını okuyoruz
        path_orig = os.path.join(self.sample_files_dir, "config.json")
        path_tamp = os.path.join(self.sample_files_dir, "tampered_config.json")
        with open(path_orig, "rb") as f1, open(path_tamp, "rb") as f2:
            data_orig = f1.read()
            data_tamp = f2.read()

        # Çığ etkisi analizini koşturuyoruz
        avalanche_res = self.checker.calculate_avalanche_effect(data_orig, data_tamp)
        # Değişen bit sayısının sıfırdan büyük olduğunu sınıyoruz
        self.assertGreater(avalanche_res["different_bits"], 90)
        # Yüzdesel farkın kriptografik beklenti olan %40 - %60 bandında olduğunu teyit ediyoruz
        self.assertTrue(avalanche_res["avalanche_proven"])
        self.assertGreaterEqual(avalanche_res["change_percentage"], 40.0)
        self.assertLessEqual(avalanche_res["change_percentage"], 60.0)

    def test_05_load_valid_baseline(self) -> None:
        """Yetkili taban çizgisi dosyasının başarıyla yüklendiğini test eder."""
        # Taban çizgisini yüklüyoruz
        loaded_count = self.checker.load_baseline(self.baseline_path)
        # 3 geçerli dosyanın yüklendiğini sınıyoruz
        self.assertEqual(loaded_count, 3)
        self.assertEqual(len(self.checker.baseline_entries), 3)
        # Reddedilen bozuk kayıt olmadığını sınıyoruz
        self.assertEqual(len(self.checker.corrupted_records), 0)

    def test_06_verify_file_integrity_clean(self) -> None:
        """Yetkili taban çizgisiyle tamamen uyuşan bir ortamda hiçbir ihlal çıkmadığını test eder."""
        # Geçici temiz bir test ortamı hazırlıyoruz
        temp_dir = tempfile.mkdtemp()
        try:
            # Temiz bir dosya oluşturuyoruz
            clean_sub = os.path.join(temp_dir, "sample_files")
            os.makedirs(clean_sub, exist_ok=True)
            clean_file = os.path.join(clean_sub, "clean.txt")
            with open(clean_file, "w", encoding="utf-8") as f:
                f.write("Bu temiz bir sistem dosyasidir.")

            # Bu temiz dosyanın hash'ini hesaplayıp taban çizgisine ekliyoruz
            h = self.checker.compute_file_hash(clean_file, "sha256")
            self.checker.baseline_entries["sample_files/clean.txt"] = FileMetadata(
                file_name="clean.txt",
                relative_path="sample_files/clean.txt",
                sha256=h
            )

            # Bütünlük denetimini koşturuyoruz
            res = self.checker.verify_file_integrity(temp_dir)
            # İhlal bulunmamalıdır
            self.assertEqual(res["total_findings"], 0)
            self.assertEqual(res["integrity_status"], "VERIFIED_CLEAN")
        finally:
            # Geçici dizini kaldırıyoruz
            shutil.rmtree(temp_dir)

    def test_07_verify_tampered_file_detection(self) -> None:
        """Değiştirilmiş bir dosyanın INTEGRITY_COMPROMISED ve CRITICAL olarak saptandığını test eder."""
        # Geçici test ortamı açıyoruz
        temp_dir = tempfile.mkdtemp()
        try:
            # Taban çizgisinde beklenen dosyayı taklit ediyoruz
            sub = os.path.join(temp_dir, "sample_files")
            os.makedirs(sub, exist_ok=True)
            target = os.path.join(sub, "config.json")
            # Tahrif edilmiş dosyayı buraya kopyalıyoruz
            shutil.copyfile(os.path.join(self.sample_files_dir, "tampered_config.json"), target)

            # Taban çizgisini yüklüyoruz (orijinal hash bekleniyor)
            self.checker.load_baseline(self.baseline_path)

            # Denetimi koşturuyoruz
            res = self.checker.verify_file_integrity(temp_dir)
            # İhlaller arasında INTEGRITY_COMPROMISED bulunmalıdır
            finding_types = [f["finding_type"] for f in res["findings"]]
            self.assertIn("INTEGRITY_COMPROMISED", finding_types)
            # İlgili bulgunun ciddiyetinin CRITICAL olduğunu teyit ediyoruz
            comp_finding = next(f for f in res["findings"] if f["finding_type"] == "INTEGRITY_COMPROMISED")
            self.assertEqual(comp_finding["severity"], "CRITICAL")
        finally:
            shutil.rmtree(temp_dir)

    def test_08_verify_missing_file_detection(self) -> None:
        """Taban çizgisinde olup diskte bulunamayan dosyanın FILE_MISSING olarak yakalandığını test eder."""
        # Boş geçici dizin açıyoruz
        temp_dir = tempfile.mkdtemp()
        try:
            # Taban çizgisini yüklüyoruz
            self.checker.load_baseline(self.baseline_path)
            # Boş dizinde denetim çalıştırıyoruz
            res = self.checker.verify_file_integrity(temp_dir)
            # Bütün 3 taban çizgisi dosyasının da kayıp olduğunu sınıyoruz
            missing = [f for f in res["findings"] if f["finding_type"] == "FILE_MISSING"]
            self.assertEqual(len(missing), 3)
            for m in missing:
                self.assertEqual(m["severity"], "HIGH")
        finally:
            shutil.rmtree(temp_dir)

    def test_09_verify_new_unauthorized_file(self) -> None:
        """Taban çizgisinde olmayan yetkisiz yeni dosyanın NEW_UNAUTHORIZED_FILE olarak yakalandığını test eder."""
        # Geçici dizin açıyoruz
        temp_dir = tempfile.mkdtemp()
        try:
            # Yetkisiz yabancı bir dosya bırakıyoruz
            rogue = os.path.join(temp_dir, "rogue_backdoor.sh")
            with open(rogue, "w", encoding="utf-8") as f:
                f.write("nc -lvp 4444")

            # Taban çizgisini yüklüyoruz
            self.checker.load_baseline(self.baseline_path)
            # Denetimi koşturuyoruz
            res = self.checker.verify_file_integrity(temp_dir)
            # Yetkisiz dosya bulgusunu sınıyoruz
            new_files = [f for f in res["findings"] if f["finding_type"] == "NEW_UNAUTHORIZED_FILE"]
            self.assertGreaterEqual(len(new_files), 1)
            self.assertEqual(new_files[0]["file_path"], "rogue_backdoor.sh")
        finally:
            shutil.rmtree(temp_dir)

    def test_10_trust_limitation_didactic(self) -> None:
        """G033-SC1: 'Hash tek başına dosyanın güvenilir olduğunu söylemez' ilkesini test eder."""
        # Sahte bir dosya yolu ve geçerli bir hash veriyoruz
        sample_path = "sample_files/malicious_payload.sh"
        sample_hash = "2cf886ce37d1c9fdf227bd875fc638c83938da29d65c074a562c30e79136474f"
        # Güvenilirlik değerlendirmesini çağırıyoruz
        eval_res = self.checker.assess_trust_limitations(sample_path, sample_hash)
        # Bütünlüğün doğrulandığını fakat dosyanın doğrudan güvenilir KABUL EDİLMEDİĞİNİ sınıyoruz
        self.assertTrue(eval_res["integrity_verified"])
        self.assertFalse(eval_res["is_trusted"])
        # Açıklama metninin didaktik gerekçeyi içerdiğini teyit ediyoruz
        self.assertIn("butunluk", eval_res["trust_rationale"])
        self.assertIn("malware", eval_res["trust_rationale"])

    def test_11_negative_control_corrupted_dataset(self) -> None:
        """Negatif kontrol: Bozuk formatlı, hatalı uzunluklu ve geçersiz hex içeren hash kayıtlarını güvenle reddeder."""
        # Bozuk test dosyasını yüklüyoruz
        loaded = self.checker.load_baseline(self.corrupted_path)
        # Sıfır geçerli kayıt yüklenmelidir
        self.assertEqual(loaded, 0)
        self.assertEqual(len(self.checker.baseline_entries), 0)
        # 7 hatalı kaydın tamamının yakalandığını sınıyoruz
        self.assertEqual(len(self.checker.corrupted_records), 7)
        # Nedenleri inceliyoruz
        reasons = [r["reason"] for r in self.checker.corrupted_records]
        self.assertTrue(any("GECERSIZ_HEX" in r for r in reasons))
        self.assertTrue(any("HATALI_UZUNLUK" in r for r in reasons))
        self.assertTrue(any("EKSIK_ALAN" in r for r in reasons))
        self.assertTrue(any("GECERSIZ_YOL" in r for r in reasons))
        self.assertTrue(any("BOS_HASH" in r for r in reasons))
        self.assertTrue(any("KAYIT_SOZLUK_DEGIL" in r for r in reasons))

    def test_12_negative_control_missing_file_exception(self) -> None:
        """Negatif kontrol: Var olmayan bir dosyada FileNotFoundError fırlatıldığını test eder."""
        # Olmayan dosya yolu
        non_existent = os.path.join(self.sample_files_dir, "hayali_olmayan_dosya_12345.xyz")
        # Hash hesaplama denendiğinde FileNotFoundError beklenir
        with self.assertRaises(FileNotFoundError):
            self.checker.compute_file_hash(non_existent)

    def test_13_text_report_generation(self) -> None:
        """Metin tabanlı bütünlük raporunun format ve başlıklarını eksiksiz ürettiğini test eder."""
        # Taban çizgisini yüklüyoruz
        self.checker.load_baseline(self.baseline_path)
        # Rapor metnini üretiyoruz
        report = self.checker.generate_integrity_report()
        # Başlık ve anahtar metinlerin varlığını sınıyoruz
        self.assertIn("DOSYA HASH VE KRİPTOGRAFİK BÜTÜNLÜK DENETİM RAPORU", report)
        self.assertIn("Taban Çizgisindeki Yetkili Dosya Sayısı", report)

    def test_14_custom_license_presence(self) -> None:
        """Özel lisans kuralı gereğince dosyalarda 'Özel Lisans - Tüm Hakları Saklıdır' ibaresini denetler."""
        # Uygulama dosyasını okuyoruz
        app_file = os.path.join(self.base_dir, "uygulama", "file_integrity_hash_checker.py")
        with open(app_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Zorunlu lisans ifadelerini doğruluyoruz
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", content)
        self.assertIn("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)", content)
        self.assertIn("YASAKLAR:", content)
        self.assertIn("YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ", content)


# Doğrudan çalıştırıldığında testleri yürüt
if __name__ == "__main__":
    unittest.main()
