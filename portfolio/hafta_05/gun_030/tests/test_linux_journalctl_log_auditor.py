# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 05, Gün 030: Linux journalctl ve Günlük Dizinleri Birim Testleri.
Bu test paketi; systemd-journald kalıcılık denetimini (G030-SC1), saat dilimi
korelasyonunu (UTC vs Yerel Saat), birim ve öncelik filtrelemesini (G030-SC2),
SHA-256 bütünlük mühürlemesini ve negatif kontrolleri 14 test ile doğrular.
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
from portfolio.hafta_05.gun_030.uygulama.linux_journalctl_log_auditor import (
    LinuxJournalValidator,
    LinuxJournalctlAuditor
)


class TestLinuxJournalctlAuditor(unittest.TestCase):
    """
    Gün 030 için 14 kapsamlı birim testten oluşan test sınıfı.
    G030-SC1, G030-SC2 ve G030-SC3 isterlerini %100 kapsar.
    """

    # Her test öncesinde geçici ortam ve geçerli bir örnek journal girdisi hazırlayan kurulum metodu.
    def setUp(self):
        # Geçici dizin açılır.
        self.test_dir = tempfile.mkdtemp()
        # Geçerli bir systemd journal girdisi tanımlanır.
        self.valid_entry = {
            "cursor": "s=test_cursor_101",
            "systemd_unit": "sshd.service",
            "priority": 6,
            "time_utc": "2026-10-27T08:15:30.000000Z",
            "time_local": "2026-10-27T11:15:30.000000+03:00",
            "timezone_offset": "+03:00",
            "storage_location": "/var/log/journal",
            "is_persistent": True,
            "message": "Accepted publickey for secops from 192.168.1.100 port 55120 ssh2"
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

    def test_01_journal_validator_accepts_valid_entry(self):
        """Kalıcı depolamadaki eksiksiz journal kaydının doğrulayıcıdan başarıyla geçmesini test eder."""
        is_valid, err_code, detail = LinuxJournalValidator.validate_entry(self.valid_entry)
        self.assertTrue(is_valid)
        self.assertIsNone(err_code)
        self.assertIsNone(detail)

    def test_02_journal_validator_rejects_missing_message(self):
        """Mesaj alanı boş olan journal kaydının MISSING_MESSAGE hatası üretmesini test eder."""
        bad_entry = dict(self.valid_entry)
        bad_entry["message"] = ""
        is_valid, err_code, detail = LinuxJournalValidator.validate_entry(bad_entry)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "MISSING_MESSAGE")

    def test_03_journal_validator_rejects_invalid_priority(self):
        """0-7 aralığı dışındaki öncelik değerinin INVALID_PRIORITY_LEVEL hatası vermesini test eder."""
        bad_entry = dict(self.valid_entry)
        bad_entry["priority"] = 9
        is_valid, err_code, detail = LinuxJournalValidator.validate_entry(bad_entry)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "INVALID_PRIORITY_LEVEL")

    def test_04_journal_validator_rejects_malformed_timestamp(self):
        """Geçersiz UTC zaman damgasının MALFORMED_TIMESTAMP hatası üretmesini test eder."""
        bad_entry = dict(self.valid_entry)
        bad_entry["time_utc"] = "BAD_DATE_FORMAT_2026"
        is_valid, err_code, detail = LinuxJournalValidator.validate_entry(bad_entry)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "MALFORMED_TIMESTAMP")

    def test_05_journal_validator_flags_volatile_storage_risk(self):
        """Geçici RAM günlüğü (/run/log/journal) kullanımının VOLATILE_STORAGE_RISK üretmesini test eder (G030-SC1)."""
        volatile_entry = dict(self.valid_entry)
        volatile_entry["storage_location"] = "/run/log/journal/123/system.journal"
        volatile_entry["is_persistent"] = False
        is_valid, err_code, detail = LinuxJournalValidator.validate_entry(volatile_entry)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "VOLATILE_STORAGE_RISK")

    def test_06_load_journal_logs_dataset(self):
        """sample_journal_logs.json dosyasından tüm geçerli kayıtların başarıyla yüklenmesini test eder."""
        real_json = "portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json"
        engine = LinuxJournalctlAuditor()
        entries = engine.load_journal_from_json(real_json)
        self.assertGreaterEqual(len(entries), 5)
        self.assertEqual(len(engine.rejected_entries), 0)

    def test_07_sha256_integrity_hash_computation(self):
        """Doğrulanan her journal girdisi için 64 karakterlik SHA-256 özeti oluşturulmasını test eder."""
        real_json = "portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json"
        engine = LinuxJournalctlAuditor()
        entries = engine.load_journal_from_json(real_json)
        for e in entries:
            self.assertIn("integrity_sha256", e)
            self.assertEqual(len(e["integrity_sha256"]), 64)

    def test_08_load_journald_conf_storage_persistence(self):
        """journald.conf yapılandırmasından Storage=persistent ayarının okunduğunu test eder (G030-SC1)."""
        real_conf = "portfolio/hafta_05/gun_030/ornek_veri/sample_journald_conf_baseline.ini"
        engine = LinuxJournalctlAuditor()
        conf = engine.load_journald_conf(real_conf)
        self.assertEqual(conf.get("Storage"), "persistent")
        self.assertEqual(conf.get("Compress"), "yes")

    def test_09_filter_entries_by_unit(self):
        """systemd birimine göre filtreleme yapıldığında (örn: sshd) yalnızca o birimin dönmesini test eder (G030-SC2)."""
        real_json = "portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json"
        engine = LinuxJournalctlAuditor()
        engine.load_journal_from_json(real_json)
        filtered = engine.filter_entries(unit="sshd")
        self.assertGreater(len(filtered), 0)
        for item in filtered:
            self.assertIn("sshd", item["systemd_unit"].lower())

    def test_10_filter_entries_by_priority(self):
        """Maksimum öncelik seviyesi 4 (warning ve altı) verildiğinde sadece kritik/hata kayıtlarının dönmesini test eder."""
        real_json = "portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json"
        engine = LinuxJournalctlAuditor()
        engine.load_journal_from_json(real_json)
        filtered = engine.filter_entries(max_priority=4)
        for item in filtered:
            self.assertLessEqual(item["priority"], 4)

    def test_11_filter_entries_by_text_pattern(self):
        """Mesaj içinde düzenli ifade araması ile parola hatası içeren kayıtların filtrelenmesini test eder."""
        real_json = "portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json"
        engine = LinuxJournalctlAuditor()
        engine.load_journal_from_json(real_json)
        filtered = engine.filter_entries(search_pattern=r"Failed password")
        self.assertEqual(len(filtered), 1)
        self.assertIn("Failed password", filtered[0]["message"])

    def test_12_timezone_correlation_utc_and_local(self):
        """Kayıtlarda UTC ve Yerel Saat bilgilerinin karşılaştırmalı olarak tutulduğunu test eder (G030-SC1)."""
        real_json = "portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json"
        engine = LinuxJournalctlAuditor()
        entries = engine.load_journal_from_json(real_json)
        first_entry = entries[0]
        self.assertIn("time_utc", first_entry)
        self.assertIn("time_local", first_entry)
        self.assertIn("timezone_offset", first_entry)
        self.assertNotEqual(first_entry["time_utc"], first_entry["time_local"])

    def test_13_negative_control_corrupted_dataset(self):
        """Bozuk ve geçici bellek kullanan kayıtların negatif kontrolde %100 reddedilmesini test eder (G030-SC2)."""
        corrupted_json = "portfolio/hafta_05/gun_030/ornek_veri/corrupted_journal_test.json"
        engine = LinuxJournalctlAuditor()
        res = engine.test_corrupted_dataset(corrupted_json)
        self.assertTrue(res["passed"])
        self.assertEqual(res["rejected_count"], res["total_tested"])
        self.assertGreaterEqual(res["total_tested"], 4)

    def test_14_cli_subprocess_execution(self):
        """CLI üzerinden --audit argümanıyla script çağrıldığında 0 çıkış koduyla çalışmasını test eder."""
        script_path = "portfolio/hafta_05/gun_030/uygulama/linux_journalctl_log_auditor.py"
        real_json = "portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json"
        p = subprocess.run(
            [sys.executable, script_path, "--logs", real_json, "--audit"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(p.returncode, 0)
        self.assertIn("LINUX JOURNALCTL VE GÜNLÜK DİZİNLERİ ADLİ DENETİM RAPORU", p.stdout)
        self.assertIn("sshd.service", p.stdout)


if __name__ == "__main__":
    unittest.main()
