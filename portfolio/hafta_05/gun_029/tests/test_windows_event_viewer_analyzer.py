# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 05, Gün 029: Windows Event Viewer Analiz ve Doğrulama Birim Testleri.
Bu test paketi; olay günlüğü alan bütünlüğünü (G029-SC2), tekil olay kimliklerinin
bağlamsal korelasyonunu (G029-SC1), SHA-256 özet mühürlemesini ve bozuk verilere
karşı negatif kontrol filtrelerini 14 bağımsız test ile sınar.
"""

# Standart Python birim test modülü içe aktarılır.
import unittest
# Dosya yolları ve çevre kontrolleri için içe aktarılır.
import os
# JSON formatında sahte test verileri oluşturmak ve ayrıştırmak için içe aktarılır.
import json
# Geçici test dosyaları ve dizinleri oluşturmak için içe aktarılır.
import tempfile
# CLI üzerinden alt süreç çağrılarını test etmek için içe aktarılır.
import subprocess
# Sistem parametreleri ve python yorumlayıcı yoluna erişmek için içe aktarılır.
import sys

# Test edilecek sınıflar modülden içe aktarılır.
from portfolio.hafta_05.gun_029.uygulama.windows_event_viewer_analyzer import (
    WindowsEventValidator,
    ContextualCorrelationEngine,
    WindowsEventViewerAnalyzer
)


class TestWindowsEventViewerAnalyzer(unittest.TestCase):
    """
    Gün 029 için 14 kapsamlı birim testten oluşan test sınıfı.
    G029-SC1, G029-SC2 ve G029-SC3 isterlerini %100 kapsar.
    """

    # Her test öncesinde geçici ortam ve geçerli bir örnek olay hazırlayan kurulum metodu.
    def setUp(self):
        # Geçici dizin açılır.
        self.test_dir = tempfile.mkdtemp()
        # Standartlara uygun geçerli bir Windows olay sözlüğü tanımlanır.
        self.valid_event = {
            "record_id": 101,
            "provider_name": "Service Control Manager",
            "event_id": 7045,
            "level": "Information",
            "channel": "System",
            "time_created": "2026-10-27T08:00:00.000000Z",
            "computer": "TEST-HOST-01",
            "user_name": "SYSTEM",
            "raw_message": "Service TestService installed.",
            "event_data": {
                "ServiceName": "TestService",
                "ImagePath": "C:\\Program Files\\TestApp\\service.exe"
            }
        }

    # Her test sonrasında geçici dosyaları temizleyen metod.
    def tearDown(self):
        # Geçici dizindeki dosyalar temizlenir.
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)

    def test_01_event_validator_accepts_valid_event(self):
        """Eksiksiz ve doğru biçimlendirilmiş bir olayın geçerlilik testinden başarıyla geçmesini sınar."""
        is_valid, err_code, msg = WindowsEventValidator.validate_event_dict(self.valid_event)
        self.assertTrue(is_valid)
        self.assertIsNone(err_code)
        self.assertIsNone(msg)

    def test_02_event_validator_rejects_missing_provider(self):
        """ProviderName alanı boş olduğunda sistemin MISSING_PROVIDER_NAME hatası üretmesini test eder."""
        bad_event = dict(self.valid_event)
        bad_event["provider_name"] = ""
        is_valid, err_code, msg = WindowsEventValidator.validate_event_dict(bad_event)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "MISSING_PROVIDER_NAME")

    def test_03_event_validator_rejects_invalid_event_id(self):
        """Sayısal olmayan EventID durumunda INVALID_EVENT_ID hatası üretilmesini test eder."""
        bad_event = dict(self.valid_event)
        bad_event["event_id"] = "ABC_NOT_INTEGER"
        is_valid, err_code, msg = WindowsEventValidator.validate_event_dict(bad_event)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "INVALID_EVENT_ID")

    def test_04_event_validator_rejects_malformed_timestamp(self):
        """Geçersiz ISO 8601 tarih dizesi girildiğinde MALFORMED_TIMESTAMP hatası üretilmesini test eder."""
        bad_event = dict(self.valid_event)
        bad_event["time_created"] = "2026-99-99 88:99:00"
        is_valid, err_code, msg = WindowsEventValidator.validate_event_dict(bad_event)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "MALFORMED_TIMESTAMP")

    def test_05_contextual_eval_event_6005_boot(self):
        """Event ID 6005 (Olay günlüğü başlatıldı) kaydının SYSTEM_BOOT_AUDIT_START olarak sınıflandırılmasını test eder."""
        boot_event = {
            "event_id": 6005,
            "provider_name": "EventLog",
            "raw_message": "Event log service was started."
        }
        ctx = ContextualCorrelationEngine.evaluate_event_context(boot_event)
        self.assertEqual(ctx["verdict"], "SYSTEM_BOOT_AUDIT_START")
        self.assertEqual(ctx["risk_level"], "INFO")

    def test_06_contextual_eval_event_7045_legitimate(self):
        """Meşru Program Files dizininden kurulan servisin AUTHORIZED_SERVICE_INSTALLATION sayılmasını test eder."""
        ctx = ContextualCorrelationEngine.evaluate_event_context(self.valid_event)
        self.assertEqual(ctx["verdict"], "AUTHORIZED_SERVICE_INSTALLATION")
        self.assertEqual(ctx["risk_level"], "INFORMATIONAL")

    def test_07_contextual_eval_event_7045_suspicious_temp_path(self):
        """Geçici dizinden (Temp) kurulan servisin SUSPICIOUS_SERVICE_INSTALLATION ve HIGH risk almasını test eder."""
        suspicious_event = dict(self.valid_event)
        suspicious_event["event_data"] = {
            "ServiceName": "MaliciousDropper",
            "ImagePath": "C:\\Windows\\Temp\\malware.exe"
        }
        ctx = ContextualCorrelationEngine.evaluate_event_context(suspicious_event)
        self.assertEqual(ctx["verdict"], "SUSPICIOUS_SERVICE_INSTALLATION")
        self.assertEqual(ctx["risk_level"], "HIGH")

    def test_08_contextual_eval_event_1074_shutdown(self):
        """Event ID 1074 (Kapatma/Yeniden başlatma) olayının kapatma gerekçesi ve kullanıcısıyla eşleşmesini test eder."""
        shutdown_event = {
            "event_id": 1074,
            "provider_name": "USER32",
            "user_name": "CORP\\admin",
            "event_data": {"Reason": "Security Patch Restart"}
        }
        ctx = ContextualCorrelationEngine.evaluate_event_context(shutdown_event)
        self.assertEqual(ctx["verdict"], "SYSTEM_SHUTDOWN_PLANNED")
        self.assertIn("Security Patch Restart", ctx["rationale"])

    def test_09_contextual_eval_event_4625_single_vs_spray(self):
        """Tek bir 4625 olayının saldırı ispatı değil, SINGLE_LOGON_FAILURE sayılmasını test eder (G029-SC1)."""
        logon_fail = {
            "event_id": 4625,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "raw_message": "An account failed to log on."
        }
        ctx = ContextualCorrelationEngine.evaluate_event_context(logon_fail)
        self.assertEqual(ctx["verdict"], "SINGLE_LOGON_FAILURE")
        self.assertIn("G029-SC1", ctx["rationale"])

    def test_10_contextual_eval_event_1102_log_cleared(self):
        """Event ID 1102 (Güvenlik günlüğü silindi) olayının CRITICAL ve AUDIT_LOG_TAMPERING sayılmasını test eder."""
        clear_event = {
            "event_id": 1102,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "raw_message": "The audit log was cleared."
        }
        ctx = ContextualCorrelationEngine.evaluate_event_context(clear_event)
        self.assertEqual(ctx["verdict"], "AUDIT_LOG_TAMPERING")
        self.assertEqual(ctx["risk_level"], "CRITICAL")
        self.assertIn("T1070.001", ctx["mitre_mapping"])

    def test_11_load_sample_system_events_dataset(self):
        """Gerçek sample_system_events.json dosyasından tam 3 sistem olayının başarıyla yüklenmesini test eder (G029-SC2)."""
        real_json = "portfolio/hafta_05/gun_029/ornek_veri/sample_system_events.json"
        engine = WindowsEventViewerAnalyzer()
        events = engine.load_events_from_json(real_json)
        self.assertEqual(len(events), 3, "G029-SC2 gereğince tam 3 sistem olayı incelenmelidir.")
        self.assertEqual(len(engine.rejected_events), 0)

    def test_12_sha256_integrity_hash_computation(self):
        """Yüklenen her olayın kriptografik bütünlük için 64 karakterlik SHA-256 özeti üretmesini test eder."""
        real_json = "portfolio/hafta_05/gun_029/ornek_veri/sample_system_events.json"
        engine = WindowsEventViewerAnalyzer()
        events = engine.load_events_from_json(real_json)
        for ev in events:
            self.assertIn("integrity_sha256", ev)
            self.assertEqual(len(ev["integrity_sha256"]), 64)

    def test_13_negative_control_corrupted_dataset(self):
        """Bozuk olaylar test kümesindeki tüm kayıtların (%100) tespit edilip reddedilmesini test eder (G029-SC2)."""
        corrupted_json = "portfolio/hafta_05/gun_029/ornek_veri/corrupted_events_test.json"
        engine = WindowsEventViewerAnalyzer()
        res = engine.test_corrupted_dataset(corrupted_json)
        self.assertTrue(res["passed"])
        self.assertEqual(res["rejected_count"], res["total_tested"])
        self.assertGreaterEqual(res["total_tested"], 4)

    def test_14_cli_subprocess_execution(self):
        """CLI üzerinden --analyze argümanıyla script çağrıldığında 0 çıkış koduyla rapor üretilmesini test eder."""
        script_path = "portfolio/hafta_05/gun_029/uygulama/windows_event_viewer_analyzer.py"
        real_json = "portfolio/hafta_05/gun_029/ornek_veri/sample_system_events.json"
        p = subprocess.run(
            [sys.executable, script_path, "--events", real_json, "--analyze"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(p.returncode, 0)
        self.assertIn("WINDOWS EVENT VIEWER ADLİ VE GÜVENLİK OLAY ANALİZ RAPORU", p.stdout)
        self.assertIn("Event ID: 7045", p.stdout)


if __name__ == "__main__":
    unittest.main()
