# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G039: Yedekleme Stratejisi ve 3-2-1 Kuralı Denetçisi Birim Test Paketi (Unit Tests)

Bu modül, BackupStrategy321Auditor sınıfının şema doğrulama, 3-2-1 kuralı (kopya sayısı,
medya çeşitliliği, offsite), fidye yazılımı değiştirilemezliği (WORM), Schrödinger'in yedeği
(test edilmemiş yedek), RAID yanılgısı ve RPO sapması kontrollerini 14 bağımsız birim testle denetler.
"""

# Standart Python birim test kütüphanesini içeri aktarıyoruz.
import unittest

# Dosya ve dizin işlemleri için os modülünü kullanıyoruz.
import os

# JSON yüklerini ayrıştırmak için json kütüphanesini dahil ediyoruz.
import json

# Denetlenecek ana sınıfı ve özel hata sınıfını uygulama paketinden dahil ediyoruz.
from portfolio.hafta_06.gun_039.uygulama.backup_strategy_321_auditor import (
    # Denetim motorunu alıyoruz.
    BackupStrategy321Auditor,
    # Özel doğrulama hatasını alıyoruz.
    BackupTelemetryValidationError
)


# Test sınıfımızı tanımlıyoruz.
class TestBackupStrategy321Auditor(unittest.TestCase):
    """
    Yedekleme stratejisi ve 3-2-1 kuralı denetçisi kapsamlı birim testleri.
    """

    # Her test öncesinde çalışan hazırlık metodu.
    def setUp(self) -> None:
        """
        Test ortamını hazırlar ve örnek telemetri verilerini yükler.
        """
        # Yeni ve izole bir denetçi nesnesi oluşturuyoruz.
        self.auditor = BackupStrategy321Auditor()

        # Mevcut dosya dizinini alıyoruz.
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Geçerli örnek envanter yolunu belirliyoruz.
        self.sample_inventory_path = os.path.join(current_dir, "..", "ornek_veri", "sample_backup_inventory.json")
        # Bozuk test senaryolarının yolunu belirliyoruz.
        self.corrupted_inventory_path = os.path.join(current_dir, "..", "ornek_veri", "corrupted_backup_inventory_test_cases.json")

        # Geçerli veriyi dosyadan okuyoruz.
        with open(self.sample_inventory_path, "r", encoding="utf-8") as f:
            # JSON olarak yüklüyoruz.
            self.valid_inventory = json.load(f)

    # 1. Test: Geçerli envanter verisinin şema doğrulamasını hatasız geçmesi.
    def test_01_telemetry_schema_validation_success(self) -> None:
        """
        Geçerli yedekleme telemetrisinin şema doğrulamasından başarıyla geçtiğini doğrular.
        """
        # Doğrulamayı çağırıyoruz.
        res = self.auditor.validate_telemetry_schema(self.valid_inventory)
        # Sonucun True olduğunu test ediyoruz.
        self.assertTrue(res, "Geçerli envanter şema doğrulamasını geçmelidir.")

    # 2. Test: 'backup_policies' anahtarı bulunmadığında BackupTelemetryValidationError fırlatılması.
    def test_02_missing_policies_key_raises_validation_error(self) -> None:
        """
        'backup_policies' anahtarı eksik olduğunda hata fırlatıldığını denetler.
        """
        # Eksik anahtarlı sahte veri hazırlıyoruz.
        bad_data = {"inventory_metadata": {"org": "No Policies"}}
        # Hata beklentisini sınıyoruz.
        with self.assertRaises(BackupTelemetryValidationError) as ctx:
            # Doğrulamayı tetikliyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında 'backup_policies' geçtiğini kontrol ediyoruz.
        self.assertIn("backup_policies", str(ctx.exception))

    # 3. Test: Negatif toplam kopya sayısında hata fırlatılması.
    def test_03_negative_total_copies_raises_validation_error(self) -> None:
        """
        total_copies negatif olduğunda hata fırlatıldığını doğrular.
        """
        # Negatif kopyalı veri hazırlıyoruz.
        bad_data = {
            "backup_policies": [
                {"policy_id": "P1", "total_copies": -2, "media_types": ["Disk"], "offsite_copies": 0}
            ]
        }
        # Hata fırlatma kontrolü yapıyoruz.
        with self.assertRaises(BackupTelemetryValidationError) as ctx:
            # Fonksiyonu çalıştırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında negatif uyarısını sınıyoruz.
        self.assertIn("negatif olamaz", str(ctx.exception))

    # 4. Test: Sayısal olmayan geri yükleme gününde hata fırlatılması.
    def test_04_non_numeric_restore_days_raises_error(self) -> None:
        """
        days_since_last_restore_test string olduğunda hata fırlatıldığını denetler.
        """
        # String gün değerli veri oluşturuyoruz.
        bad_data = {
            "backup_policies": [
                {"policy_id": "P1", "total_copies": 3, "media_types": ["Disk"], "offsite_copies": 1, "days_since_last_restore_test": "dun"}
            ]
        }
        # Hata beklentisini test ediyoruz.
        with self.assertRaises(BackupTelemetryValidationError) as ctx:
            # Doğrulamayı çağırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında sayısal uyarısını sınıyoruz.
        self.assertIn("sayısal veya null olmalıdır", str(ctx.exception))

    # 5. Test: Negatif geri yükleme gününde hata fırlatılması.
    def test_05_negative_restore_days_raises_error(self) -> None:
        """
        days_since_last_restore_test negatif olduğunda hata fırlatıldığını doğrular.
        """
        # Negatif gün değerli veri oluşturuyoruz.
        bad_data = {
            "backup_policies": [
                {"policy_id": "P1", "total_copies": 3, "media_types": ["Disk"], "offsite_copies": 1, "days_since_last_restore_test": -10}
            ]
        }
        # Hata kontrolü yapıyoruz.
        with self.assertRaises(BackupTelemetryValidationError) as ctx:
            # Fonksiyonu çalıştırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında negatif uyarısını sınıyoruz.
        self.assertIn("negatif olamaz", str(ctx.exception))

    # 6. Test: Politika kimliği metin olmadığında hata fırlatılması.
    def test_06_non_string_policy_id_raises_error(self) -> None:
        """
        policy_id int veya dict olduğunda hata fırlatıldığını doğrular.
        """
        # Hatalı kimlikli veri hazırlıyoruz.
        bad_data = {
            "backup_policies": [
                {"policy_id": 9999, "total_copies": 3, "media_types": ["Disk"], "offsite_copies": 1}
            ]
        }
        # Hata beklentisini sınıyoruz.
        with self.assertRaises(BackupTelemetryValidationError) as ctx:
            # Doğrulamayı icra ediyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında metin ibaresini sınıyoruz.
        self.assertIn("metin olmalıdır", str(ctx.exception))

    # 7. Test: Yetersiz kopya sayısının (< 3) HIGH seviyesinde raporlanması.
    def test_07_insufficient_copies_detected_as_high_severity(self) -> None:
        """
        Toplam kopya sayısı 3'ten az olduğunda HIGH önem derecesinde bulgu üretildiğini doğrular.
        """
        # 1 kopyalı politika oluşturuyoruz.
        policies = [
            {"policy_id": "P-TEST", "workload_name": "TestDB", "total_copies": 1, "media_types": ["Disk"], "offsite_copies": 1, "is_immutable_or_airgapped": True}
        ]
        # 3-2-1 denetimini çağırıyoruz.
        findings = self.auditor.audit_321_rule_compliance(policies)
        # Kopya sayısı bulgusunu filtreliyoruz.
        copy_findings = [f for f in findings if f["category"] == "321_RULE_COPIES_INSUFFICIENT"]
        # En az bir bulgu olmalıdır.
        self.assertEqual(len(copy_findings), 1)
        # Önem seviyesinin HIGH olduğunu sınıyoruz.
        self.assertEqual(copy_findings[0]["severity"], "HIGH")

    # 8. Test: Medya çeşitliliği eksikliğinin (< 2) MEDIUM olarak raporlanması.
    def test_08_missing_media_diversity_detected_as_medium(self) -> None:
        """
        Farklı medya türü sayısı 2'den az olduğunda MEDIUM önem derecesinde bulgu üretildiğini doğrular.
        """
        # Tek medya türü içeren politika hazırlıyoruz.
        policies = [
            {"policy_id": "P-TEST", "workload_name": "TestFS", "total_copies": 3, "media_types": ["Local_Disk"], "offsite_copies": 1, "is_immutable_or_airgapped": True}
        ]
        # Denetimi icra ediyoruz.
        findings = self.auditor.audit_321_rule_compliance(policies)
        # Medya bulgusunu filtreliyoruz.
        media_findings = [f for f in findings if f["category"] == "321_RULE_MEDIA_DIVERSITY_MISSING"]
        # 1 bulgu bekliyoruz.
        self.assertEqual(len(media_findings), 1)
        # Önem seviyesinin MEDIUM olduğunu test ediyoruz.
        self.assertEqual(media_findings[0]["severity"], "MEDIUM")

    # 9. Test: Tesis dışı (Offsite) kopya eksikliğinin CRITICAL olarak raporlanması.
    def test_09_missing_offsite_copy_detected_as_critical(self) -> None:
        """
        Tesis dışı kopya sayısı 0 olduğunda CRITICAL bulgu üretildiğini doğrular.
        """
        # Tesis dışı kopyası olmayan politika hazırlıyoruz.
        policies = [
            {"policy_id": "P-TEST", "workload_name": "TestWorkload", "total_copies": 3, "media_types": ["Disk", "Tape"], "offsite_copies": 0, "is_immutable_or_airgapped": True}
        ]
        # Denetimi çağırıyoruz.
        findings = self.auditor.audit_321_rule_compliance(policies)
        # Offsite bulgusunu filtreliyoruz.
        offsite_findings = [f for f in findings if f["category"] == "321_RULE_OFFSITE_MISSING"]
        # 1 bulgu olmalıdır.
        self.assertEqual(len(offsite_findings), 1)
        # Önem seviyesinin CRITICAL olduğunu test ediyoruz.
        self.assertEqual(offsite_findings[0]["severity"], "CRITICAL")

    # 10. Test: Fidye yazılımına karşı değiştirilemezlik (Immutability) eksikliğinin CRITICAL raporlanması.
    def test_10_missing_immutability_ransomware_detected_as_critical(self) -> None:
        """
        is_immutable_or_airgapped=False olduğunda CRITICAL seviyesinde fidye yazılımı açığı üretildiğini doğrular.
        """
        # Değiştirilemez kopyası olmayan politika oluşturuyoruz.
        policies = [
            {"policy_id": "P-TEST", "workload_name": "TestERP", "total_copies": 3, "media_types": ["Disk", "Cloud"], "offsite_copies": 1, "is_immutable_or_airgapped": False}
        ]
        # Denetimi icra ediyoruz.
        findings = self.auditor.audit_321_rule_compliance(policies)
        # Immutability bulgusunu filtreliyoruz.
        imm_findings = [f for f in findings if f["category"] == "RANSOMWARE_IMMUTABILITY_GAP"]
        # 1 bulgu bekliyoruz.
        self.assertEqual(len(imm_findings), 1)
        # Önem derecesinin CRITICAL olduğunu test ediyoruz.
        self.assertEqual(imm_findings[0]["severity"], "CRITICAL")

    # 11. Test: Schrödinger'in yedeği (Hiç test edilmemiş geri yükleme) durumunun CRITICAL raporlanması.
    def test_11_schrodingers_backup_untested_restore_detected_as_critical(self) -> None:
        """
        days_since_last_restore_test=None olduğunda 'Schrödinger'in Yedeği' CRITICAL bulgusu üretildiğini doğrular.
        """
        # Hiç test edilmemiş politika hazırlıyoruz.
        policies = [
            {"policy_id": "P-UNTESTED", "workload_name": "UntestedApp", "days_since_last_restore_test": None, "integrity_checksum_algorithm": "SHA256"}
        ]
        # Geri yükleme test denetimini icra ediyoruz.
        findings = self.auditor.audit_restore_verification_and_testing(policies)
        # Schrödinger bulgusunu filtreliyoruz.
        schrodinger = [f for f in findings if f["category"] == "RESTORE_VERIFICATION_NEVER_TESTED"]
        # 1 bulgu olmalıdır.
        self.assertEqual(len(schrodinger), 1)
        # Önem derecesinin CRITICAL olduğunu sınıyoruz.
        self.assertEqual(schrodinger[0]["severity"], "CRITICAL")
        # Başlıkta Schrödinger geçtiğini test ediyoruz.
        self.assertIn("Schrödinger", schrodinger[0]["title"])

    # 12. Test: RAID'in yedek olarak kabul edilmesinin CRITICAL mimari hata olarak tespit edilmesi.
    def test_12_relying_on_raid_as_backup_detected_as_critical(self) -> None:
        """
        relies_on_raid_as_backup=True olduğunda 'RAID bir yedekleme değildir' CRITICAL bulgusu üretildiğini doğrular.
        """
        # RAID yanılgısı içeren politika hazırlıyoruz.
        policies = [
            {"policy_id": "P-RAID", "workload_name": "RaidStorage", "relies_on_raid_as_backup": True, "snapshot_on_same_pool_only": False}
        ]
        # Yanılgı denetimini çağırıyoruz.
        findings = self.auditor.audit_raid_and_snapshot_misconceptions(policies)
        # RAID bulgusunu filtreliyoruz.
        raid_findings = [f for f in findings if f["category"] == "ARCHITECTURAL_MISCONCEPTION_RAID"]
        # 1 bulgu bekliyoruz.
        self.assertEqual(len(raid_findings), 1)
        # Önem seviyesinin CRITICAL olduğunu sınıyoruz.
        self.assertEqual(raid_findings[0]["severity"], "CRITICAL")

    # 13. Test: Bozuk test senaryoları dosyasındaki tüm girdilerin güvenle reddedilmesi.
    def test_13_corrupted_test_cases_suite_robustness(self) -> None:
        """
        corrupted_backup_inventory_test_cases.json dosyasındaki tüm testlerin yakalandığını doğrular.
        """
        # Bozuk test dosyasını açıyoruz.
        with open(self.corrupted_inventory_path, "r", encoding="utf-8") as f:
            # JSON olarak yüklüyoruz.
            suite = json.load(f)

        # Tüm senaryoları sınıyoruz.
        for case in suite.get("test_cases", []):
            # Test adını alıyoruz.
            tname = case.get("test_name")
            # Gövdeyi alıyoruz.
            payload = case.get("payload")
            # Hata beklentisini sınıyoruz.
            with self.assertRaises(BackupTelemetryValidationError, msg=f"Test '{tname}' hata fırlatmalıdır"):
                # Denetimi başlatıyoruz.
                self.auditor.execute_full_audit(payload)

    # 14. Test: Uçtan uca tam denetim iş akışı ve Markdown rapor çıktısı.
    def test_14_markdown_and_full_audit_workflow(self) -> None:
        """
        Tam denetim iş akışının hatasız çalıştığını ve Markdown raporu ürettiğini doğrular.
        """
        # Örnek geçerli envanter üzerinde tam denetimi çalıştırıyoruz.
        result = self.auditor.execute_full_audit(self.valid_inventory)
        # Sonucun sözlük olduğunu kontrol ediyoruz.
        self.assertIsInstance(result, dict)
        # Güvenlik puanının 0 ile 100 arasında olduğunu sınıyoruz.
        self.assertTrue(0 <= result["security_score"] <= 100)
        # Metrik tablosunun varlığını sınıyoruz.
        self.assertIn("metrics", result)

        # Markdown raporu üretiyoruz.
        report_md = self.auditor.export_markdown_report(result)
        # Raporun boş olmadığını sınıyoruz.
        self.assertTrue(len(report_md) > 0)
        # Raporda lisans başlığının yer aldığını kontrol ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", report_md)
        # Raporda ana başlığı sınıyoruz.
        self.assertIn("Yedekleme Stratejisi ve 3-2-1 Kuralı Güvenlik Denetim Raporu", report_md)


# Testler doğrudan icra edildiğinde unittest.main'i çalıştırıyoruz.
if __name__ == "__main__":
    # Testleri detaylı modda icra ediyoruz.
    unittest.main()
