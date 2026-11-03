# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G037: Disk Bölümleri ve Dosya Sistemleri Denetçisi Birim Test Paketi (Unit Tests)

Bu test modülü, DiskPartitionFsAuditor sınıfının şema doğrulama, MBR/GPT tespiti,
FAT32 yetkisiz dosya sistemi uyarısı, şifresiz disk bölümleri, /tmp bağlama bayrakları
ve kapasite aşımı kontrollerini 14 bağımsız test senaryosuyla denetler.
"""

# Testleri yürütmek için standart Python unittest kütüphanesini içeri aktarıyoruz.
import unittest

# Dosya yollarını ve dizinleri yönetmek için os modülünü kullanıyoruz.
import os

# Test senaryolarındaki JSON yüklerini ayrıştırmak için json kütüphanesini içeri aktarıyoruz.
import json

# Denetlenecek ana sınıfı ve özel hata sınıfını uygulama paketinden dahil ediyoruz.
from portfolio.hafta_06.gun_037.uygulama.disk_partition_fs_auditor import (
    # Denetim motoru sınıfını alıyoruz.
    DiskPartitionFsAuditor,
    # Özel doğrulama hatasını alıyoruz.
    DiskTelemetryValidationError
)


# Test sınıfımızı unittest.TestCase miras alarak tanımlıyoruz.
class TestDiskPartitionFsAuditor(unittest.TestCase):
    """
    Disk ve dosya sistemi güvenlik denetçisi kapsamlı birim testleri.
    """

    # Her test metodundan önce çalışacak hazırlık fonksiyonu.
    def setUp(self) -> None:
        """
        Test ortamını hazırlar ve temiz denetçi nesnesi ile örnek veri yolunu ayarlar.
        """
        # Yeni ve izole bir denetçi örneği oluşturuyoruz.
        self.auditor = DiskPartitionFsAuditor()

        # Güncel dosyanın dizinini tespit ediyoruz.
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Örnek telemetri dosyasının mutlak yolunu oluşturuyoruz.
        self.sample_telemetry_path = os.path.join(current_dir, "..", "ornek_veri", "sample_disk_telemetry.json")
        # Bozuk test senaryolarının mutlak yolunu oluşturuyoruz.
        self.corrupted_telemetry_path = os.path.join(current_dir, "..", "ornek_veri", "corrupted_disk_telemetry_test_cases.json")

        # Örnek geçerli telemetri verisini yüklüyoruz.
        with open(self.sample_telemetry_path, "r", encoding="utf-8") as f:
            # JSON olarak belleğe alıyoruz.
            self.valid_telemetry = json.load(f)

    # 1. Test: Geçerli telemetri verisinin şema doğrulamasını başarıyla geçmesi.
    def test_01_telemetry_schema_validation_success(self) -> None:
        """
        Geçerli telemetri verisinin şema doğrulamasını hatasız geçtiğini doğrular.
        """
        # Doğrulama fonksiyonunu çağırıyoruz.
        result = self.auditor.validate_telemetry_schema(self.valid_telemetry)
        # Sonucun True olduğunu test ediyoruz.
        self.assertTrue(result, "Geçerli telemetri verisi şema doğrulamasından başarıyla geçmelidir.")

    # 2. Test: 'disks' anahtarı bulunmadığında DiskTelemetryValidationError fırlatılması.
    def test_02_missing_disks_key_raises_validation_error(self) -> None:
        """
        'disks' anahtarı bulunmadığında hata fırlatıldığını test eder.
        """
        # Eksik anahtarlı sahte veri oluşturuyoruz.
        bad_data = {"system_info": {"hostname": "no-disk-host"}}
        # Hata beklentisini sınıyoruz.
        with self.assertRaises(DiskTelemetryValidationError) as ctx:
            # Doğrulamayı tetikliyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında 'disks' kelimesinin geçtiğini doğruluyoruz.
        self.assertIn("disks", str(ctx.exception))

    # 3. Test: Negatif disk boyutunda DiskTelemetryValidationError fırlatılması.
    def test_03_negative_disk_size_raises_validation_error(self) -> None:
        """
        Negatif disk boyutu verildiğinde sistemin hata fırlattığını doğrular.
        """
        # Negatif boyutlu geçersiz disk verisi oluşturuyoruz.
        bad_data = {
            "disks": [
                {
                    "device": "/dev/sda",
                    "size_gb": -256.0,
                    "partition_table": "gpt",
                    "partitions": []
                }
            ]
        }
        # Hata fırlatma beklentisini sınıyoruz.
        with self.assertRaises(DiskTelemetryValidationError) as ctx:
            # Fonksiyonu çalıştırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında pozitiflik uyarısı olduğunu doğruluyoruz.
        self.assertIn("pozitif olmalıdır", str(ctx.exception))

    # 4. Test: Kullanılan alan toplam alanı aştığında doğrulama hatası fırlatılması.
    def test_04_used_space_exceeds_total_raises_validation_error(self) -> None:
        """
        Bölümde kullanılan alan toplam alandan büyük olduğunda hata fırlatıldığını denetler.
        """
        # Taşma içeren mantıksız bölüm verisi hazırlıyoruz.
        bad_data = {
            "disks": [
                {
                    "device": "/dev/sda",
                    "size_gb": 500.0,
                    "partition_table": "gpt",
                    "partitions": [
                        {
                            "partition_id": "/dev/sda1",
                            "filesystem": "ext4",
                            "total_gb": 100.0,
                            "used_gb": 150.0
                        }
                    ]
                }
            ]
        }
        # Hata beklentisini test ediyoruz.
        with self.assertRaises(DiskTelemetryValidationError) as ctx:
            # Doğrulamayı çağırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında aşamaz uyarısını kontrol ediyoruz.
        self.assertIn("aşamaz", str(ctx.exception))

    # 5. Test: Sayısal olmayan kapasite değerlerinde hata fırlatılması.
    def test_05_non_numeric_partition_capacity_raises_error(self) -> None:
        """
        Bölüm kapasite değerleri string veya None olduğunda hata fırlatıldığını doğrular.
        """
        # String kapasite değerli veri hazırlıyoruz.
        bad_data = {
            "disks": [
                {
                    "device": "/dev/sda",
                    "size_gb": 500.0,
                    "partition_table": "gpt",
                    "partitions": [
                        {
                            "partition_id": "/dev/sda1",
                            "filesystem": "ext4",
                            "total_gb": "yuz_gb",
                            "used_gb": 50.0
                        }
                    ]
                }
            ]
        }
        # Hata fırlatma kontrolü yapıyoruz.
        with self.assertRaises(DiskTelemetryValidationError) as ctx:
            # Doğrulamayı çalıştırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında sayısal ibaresini kontrol ediyoruz.
        self.assertIn("sayısal olmalıdır", str(ctx.exception))

    # 6. Test: Dosya sistemi metin olmadığında hata fırlatılması.
    def test_06_non_string_filesystem_type_raises_error(self) -> None:
        """
        Dosya sistemi alanı int veya None olduğunda hata fırlatıldığını doğrular.
        """
        # Hatalı tip içeren veri hazırlıyoruz.
        bad_data = {
            "disks": [
                {
                    "device": "/dev/sda",
                    "size_gb": 500.0,
                    "partition_table": "gpt",
                    "partitions": [
                        {
                            "partition_id": "/dev/sda1",
                            "filesystem": 12345,
                            "total_gb": 100.0,
                            "used_gb": 50.0
                        }
                    ]
                }
            ]
        }
        # Hata beklentisini sınıyoruz.
        with self.assertRaises(DiskTelemetryValidationError) as ctx:
            # Fonksiyonu tetikliyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında metin uyarısını doğruluyoruz.
        self.assertIn("metin olmalıdır", str(ctx.exception))

    # 7. Test: Eski MBR bölüm tablosunun MEDIUM önem seviyesinde bulgu üretmesi.
    def test_07_mbr_partition_table_detected_as_medium_severity(self) -> None:
        """
        MBR bölüm tablosu içeren disklerin MEDIUM önem derecesinde raporlandığını doğrular.
        """
        # MBR disk içeren örnek disk listesi oluşturuyoruz.
        disks = [
            {"device": "/dev/sdb", "partition_table": "mbr", "partitions": []}
        ]
        # Bölüm tablosu denetimini çalıştırıyoruz.
        findings = self.auditor.audit_partition_tables(disks)
        # En az bir bulgu üretildiğini test ediyoruz.
        self.assertEqual(len(findings), 1)
        # Bulgu önem seviyesinin MEDIUM olduğunu kontrol ediyoruz.
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        # Başlığında MBR kelimesinin geçtiğini doğruluyoruz.
        self.assertIn("MBR", findings[0]["title"])

    # 8. Test: GPT bölüm tablosunun temiz geçmesi (bulgu üretmemesi).
    def test_08_gpt_partition_table_passes_clean(self) -> None:
        """
        Modern GPT bölüm tablosu kullanan disklerde herhangi bir MBR uyarısı üretilmediğini doğrular.
        """
        # GPT disk içeren örnek disk listesi oluşturuyoruz.
        disks = [
            {"device": "/dev/nvme0n1", "partition_table": "gpt", "partitions": []}
        ]
        # Bölüm tablosu denetimini çağırıyoruz.
        findings = self.auditor.audit_partition_tables(disks)
        # Hiçbir bulgu üretilmediğini kontrol ediyoruz.
        self.assertEqual(len(findings), 0)

    # 9. Test: Veri bölümünde FAT32 kullanımı durumunda HIGH önem seviyesinde bulgu üretilmesi.
    def test_09_fat32_data_partition_detected_as_high_severity(self) -> None:
        """
        Sistem veya veri bölümünde izin desteği olmayan FAT32 kullanımının HIGH olarak raporlandığını doğrular.
        """
        # FAT32 veri diski içeren örnek veri oluşturuyoruz.
        disks = [
            {
                "device": "/dev/sdb",
                "partitions": [
                    {
                        "partition_id": "/dev/sdb1",
                        "filesystem": "fat32",
                        "mount_point": "/mnt/data",
                        "is_encrypted": True
                    }
                ]
            }
        ]
        # Dosya sistemi denetimini icra ediyoruz.
        findings = self.auditor.audit_filesystem_and_encryption(disks)
        # FAT32 bulgusunun olup olmadığını kontrol ediyoruz.
        fat_findings = [f for f in findings if "FAT32" in f["title"]]
        # En az 1 bulgu olmalıdır.
        self.assertGreaterEqual(len(fat_findings), 1)
        # Önem seviyesinin HIGH olduğunu doğruluyoruz.
        self.assertEqual(fat_findings[0]["severity"], "HIGH")

    # 10. Test: Şifrelenmemiş kök/var bölümünün CRITICAL bulgu üretmesi.
    def test_10_unencrypted_partition_detected_as_critical(self) -> None:
        """
        Şifresiz kök ('/') bölümünün CRITICAL olarak raporlandığını doğrular.
        """
        # Şifresiz kök bölümü içeren veri oluşturuyoruz.
        disks = [
            {
                "device": "/dev/sda",
                "partitions": [
                    {
                        "partition_id": "/dev/sda2",
                        "filesystem": "ext4",
                        "mount_point": "/",
                        "is_encrypted": False
                    }
                ]
            }
        ]
        # Denetimi çalıştırıyoruz.
        findings = self.auditor.audit_filesystem_and_encryption(disks)
        # Şifresiz disk bulgularını filtreliyoruz.
        enc_findings = [f for f in findings if f["category"] == "ENCRYPTION_AT_REST"]
        # En az bir bulgu bekliyoruz.
        self.assertEqual(len(enc_findings), 1)
        # Önem derecesinin CRITICAL olduğunu test ediyoruz.
        self.assertEqual(enc_findings[0]["severity"], "CRITICAL")

    # 11. Test: /tmp dizininde noexec bayrağı eksikliğinin HIGH bulgu üretmesi.
    def test_11_mount_options_missing_noexec_on_tmp_detected(self) -> None:
        """
        /tmp dizininde 'noexec' bayrağı eksikliğinin HIGH önem derecesinde tespit edildiğini doğrular.
        """
        # /tmp üzerinde eksik bayraklı bağlama verisi oluşturuyoruz.
        disks = [
            {
                "device": "/dev/nvme0n1",
                "partitions": [
                    {
                        "partition_id": "/dev/nvme0n1p4",
                        "mount_point": "/tmp",
                        "mount_options": ["rw", "relatime"] # noexec ve nosuid eksik!
                    }
                ]
            }
        ]
        # Bağlama bayrakları denetimini çalıştırıyoruz.
        findings = self.auditor.audit_mount_options_hardening(disks)
        # Bulgu sayısının en az 1 olduğunu sınıyoruz.
        self.assertEqual(len(findings), 1)
        # Önem seviyesinin HIGH olduğunu test ediyoruz.
        self.assertEqual(findings[0]["severity"], "HIGH")
        # Açıklamada noexec uyarısının yer aldığını kontrol ediyoruz.
        self.assertIn("noexec", findings[0]["description"])

    # 12. Test: Kapasite tükenme uyarıları (%85 warning, %95 critical).
    def test_12_capacity_exhaustion_warning_and_critical_thresholds(self) -> None:
        """
        %85 üzerinde WARNING, %95 üzerinde CRITICAL kapasite bulgusu üretildiğini doğrular.
        """
        # Doluluk sınırlarını içeren disk verisi hazırlıyoruz.
        disks = [
            {
                "device": "/dev/sda",
                "partitions": [
                    # %88 doluluk -> WARNING
                    {"partition_id": "/dev/sda1", "mount_point": "/opt", "total_gb": 100.0, "used_gb": 88.0},
                    # %96 doluluk -> CRITICAL
                    {"partition_id": "/dev/sda2", "mount_point": "/var/log", "total_gb": 100.0, "used_gb": 96.0}
                ]
            }
        ]
        # Kapasite denetimini yürütüyoruz.
        findings = self.auditor.audit_capacity_and_exhaustion(disks)
        # Toplam 2 bulgu bekliyoruz.
        self.assertEqual(len(findings), 2)
        # İlk bulgunun WARNING olduğunu kontrol ediyoruz.
        self.assertEqual(findings[0]["severity"], "WARNING")
        # İkinci bulgunun CRITICAL olduğunu kontrol ediyoruz.
        self.assertEqual(findings[1]["severity"], "CRITICAL")

    # 13. Test: Bozuk test senaryoları dosyasındaki tüm girdilerin güvenle reddedilmesi.
    def test_13_corrupted_test_cases_suite_robustness(self) -> None:
        """
        corrupted_disk_telemetry_test_cases.json dosyasındaki tüm senaryoların yakalandığını doğrular.
        """
        # Bozuk test senaryolarını okuyoruz.
        with open(self.corrupted_telemetry_path, "r", encoding="utf-8") as f:
            # JSON olarak yüklüyoruz.
            suite = json.load(f)

        # Her test senaryosunu deniyoruz.
        for case in suite.get("test_cases", []):
            # Test adını alıyoruz.
            tname = case.get("test_name")
            # Gövdeyi alıyoruz.
            payload = case.get("payload")
            # Her birinin hata fırlattığını sınıyoruz.
            with self.assertRaises(DiskTelemetryValidationError, msg=f"Test '{tname}' hata fırlatmalıdır"):
                # Denetimi başlatıyoruz.
                self.auditor.execute_full_audit(payload)

    # 14. Test: Uçtan uca tam denetim akışı ve Markdown rapor çıktısı.
    def test_14_markdown_and_full_audit_workflow(self) -> None:
        """
        Tam denetim iş akışının başarıyla tamamlandığını ve Markdown çıktısının üretildiğini doğrular.
        """
        # Örnek geçerli telemetri üzerinde tam denetimi çalıştırıyoruz.
        audit_result = self.auditor.execute_full_audit(self.valid_telemetry)
        # Sonucun sözlük olduğunu kontrol ediyoruz.
        self.assertIsInstance(audit_result, dict)
        # Güvenlik puanının 0 ile 100 arasında olduğunu test ediyoruz.
        self.assertTrue(0 <= audit_result["security_score"] <= 100)
        # Rapor metriklerinin hesaplandığını doğruluyoruz.
        self.assertIn("metrics", audit_result)

        # Markdown raporu üretiyoruz.
        md_report = self.auditor.export_markdown_report(audit_result)
        # Raporun boş olmadığını sınıyoruz.
        self.assertTrue(len(md_report) > 0)
        # Rapor içinde lisans başlığının yer aldığını kontrol ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", md_report)
        # Raporda başlık olduğunu kontrol ediyoruz.
        self.assertIn("Disk Bölümleri ve Dosya Sistemleri Güvenlik Denetim Raporu", md_report)


# Testler doğrudan çağrıldığında çalışması için unittest.main'i çalıştırıyoruz.
if __name__ == "__main__":
    # Testleri detaylı modda icra ediyoruz.
    unittest.main()
