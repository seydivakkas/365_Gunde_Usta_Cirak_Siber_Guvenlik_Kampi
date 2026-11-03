# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 05, Gün 031: Process Explorer ve Süreç Ağacı Birim Testleri.
Bu test paketi; süreç hiyerarşisi oluşturmayı (G031-SC2), döngüsel süreç tespitini,
meşru karmaşık ağaçlar ile saldırı zincirlerinin ayrımını (G031-SC1), taklit
(masquerading) tespiti ve negatif kontrolleri 14 test ile doğrular.
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
from portfolio.hafta_05.gun_031.uygulama.process_tree_explorer_analyzer import (
    ProcessValidator,
    ProcessTreeBuilder,
    ProcessAnomalyDetector,
    ProcessTreeExplorerAnalyzer
)


class TestProcessTreeExplorerAnalyzer(unittest.TestCase):
    """
    Gün 031 için 14 kapsamlı birim testten oluşan test sınıfı.
    G031-SC1, G031-SC2 ve G031-SC3 isterlerini %100 kapsar.
    """

    # Her test öncesinde geçici ortam ve geçerli bir süreç listesi hazırlayan kurulum metodu.
    def setUp(self):
        # Geçici dizin açılır.
        self.test_dir = tempfile.mkdtemp()
        # Standart meşru süreç listesi tanımlanır.
        self.valid_processes = [
            {"pid": 4, "ppid": 0, "name": "System", "path": "ntoskrnl.exe"},
            {"pid": 610, "ppid": 4, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe"},
            {"pid": 780, "ppid": 610, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "is_verified_signature": True}
        ]

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

    def test_01_process_validator_accepts_valid_process_list(self):
        """Hiyerarşik ve döngü içermeyen geçerli süreç listesinin doğrulanmasını test eder."""
        is_valid, err_code, detail = ProcessValidator.validate_process_list(self.valid_processes)
        self.assertTrue(is_valid)
        self.assertIsNone(err_code)

    def test_02_process_validator_rejects_negative_pid(self):
        """Negatif PID değerinin INVALID_PID hatası ile reddedilmesini test eder."""
        bad_list = [{"pid": -5, "ppid": 0, "name": "bad.exe"}]
        is_valid, err_code, detail = ProcessValidator.validate_process_list(bad_list)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "INVALID_PID")

    def test_03_process_validator_rejects_missing_name(self):
        """Süreç adı boş olan kaydın MISSING_PROCESS_NAME hatası vermesini test eder."""
        bad_list = [{"pid": 100, "ppid": 0, "name": ""}]
        is_valid, err_code, detail = ProcessValidator.validate_process_list(bad_list)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "MISSING_PROCESS_NAME")

    def test_04_process_validator_rejects_duplicate_pid(self):
        """Aynı PID numarasına sahip iki sürecin DUPLICATE_PID_DETECTED vermesini test eder."""
        bad_list = [
            {"pid": 200, "ppid": 0, "name": "first.exe"},
            {"pid": 200, "ppid": 0, "name": "second.exe"}
        ]
        is_valid, err_code, detail = ProcessValidator.validate_process_list(bad_list)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "DUPLICATE_PID_DETECTED")

    def test_05_process_validator_detects_circular_loop(self):
        """Döngüsel ebeveyn ilişkisinin (A -> B -> A) CIRCULAR_PROCESS_LOOP üretmesini test eder."""
        cycle_list = [
            {"pid": 10, "ppid": 20, "name": "proc_a.exe"},
            {"pid": 20, "ppid": 10, "name": "proc_b.exe"}
        ]
        is_valid, err_code, detail = ProcessValidator.validate_process_list(cycle_list)
        self.assertFalse(is_valid)
        self.assertEqual(err_code, "CIRCULAR_PROCESS_LOOP")

    def test_06_build_tree_hierarchy_roots_and_children(self):
        """Düz süreç listesinden doğru ebeveyn-çocuk ağacı inşa edildiğini test eder."""
        roots = ProcessTreeBuilder.build_tree(self.valid_processes)
        self.assertEqual(len(roots), 1)
        root = roots[0]
        self.assertEqual(root.pid, 4)
        self.assertEqual(len(root.children), 1)
        child = root.children[0]
        self.assertEqual(child.pid, 610)
        self.assertEqual(len(child.children), 1)
        grandchild = child.children[0]
        self.assertEqual(grandchild.pid, 780)

    def test_07_detect_office_spawned_shell(self):
        """Ofis uygulamasının (winword.exe) cmd.exe başlatmasının CRITICAL anomali üretmesini test eder (T1204/T1059)."""
        nodes = ProcessTreeBuilder.build_tree([
            {"pid": 3100, "ppid": 0, "name": "winword.exe", "path": "C:\\Office\\WINWORD.EXE"},
            {"pid": 3150, "ppid": 3100, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"}
        ])
        engine = ProcessTreeExplorerAnalyzer()
        engine.root_nodes = nodes
        anoms = engine.evaluate_tree_anomalies()
        types = [a["type"] for a in anoms]
        self.assertIn("OFFICE_SPAWNED_SHELL", types)

    def test_08_detect_invalid_parent_for_svchost(self):
        """svchost.exe sürecinin services.exe haricinde başlatılmasının HIGH anomali vermesini test eder (T1036.005)."""
        nodes = ProcessTreeBuilder.build_tree([
            {"pid": 1000, "ppid": 0, "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
            {"pid": 1010, "ppid": 1000, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe"}
        ])
        engine = ProcessTreeExplorerAnalyzer()
        engine.root_nodes = nodes
        anoms = engine.evaluate_tree_anomalies()
        types = [a["type"] for a in anoms]
        self.assertIn("INVALID_PARENT_FOR_SVCHOST", types)

    def test_09_detect_suspicious_system_binary_in_temp(self):
        """Sistem dosyasının (svchost.exe) Temp dizininden çalıştırılmasının CRITICAL anomali vermesini test eder."""
        nodes = ProcessTreeBuilder.build_tree([
            {"pid": 4050, "ppid": 0, "name": "svchost.exe", "path": "C:\\Users\\analyst\\AppData\\Local\\Temp\\svchost.exe"}
        ])
        engine = ProcessTreeExplorerAnalyzer()
        engine.root_nodes = nodes
        anoms = engine.evaluate_tree_anomalies()
        types = [a["type"] for a in anoms]
        self.assertIn("SUSPICIOUS_SYSTEM_BINARY_PATH", types)

    def test_10_detect_unsigned_critical_process(self):
        """Kritik sistem sürecinin dijital imzasız olmasının UNSIGNED_CRITICAL_PROCESS üretmesini test eder."""
        nodes = ProcessTreeBuilder.build_tree([
            {"pid": 4050, "ppid": 0, "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "is_verified_signature": False}
        ])
        engine = ProcessTreeExplorerAnalyzer()
        engine.root_nodes = nodes
        anoms = engine.evaluate_tree_anomalies()
        types = [a["type"] for a in anoms]
        self.assertIn("UNSIGNED_CRITICAL_PROCESS", types)

    def test_11_detect_encoded_powershell_execution(self):
        """PowerShell komut satırında -enc parametresinin ENCODED_POWERSHELL_EXECUTION üretmesini test eder."""
        nodes = ProcessTreeBuilder.build_tree([
            {"pid": 5000, "ppid": 0, "name": "powershell.exe", "path": "powershell.exe", "command_line": "powershell.exe -enc JABzAD0..."}
        ])
        engine = ProcessTreeExplorerAnalyzer()
        engine.root_nodes = nodes
        anoms = engine.evaluate_tree_anomalies()
        types = [a["type"] for a in anoms]
        self.assertIn("ENCODED_POWERSHELL_EXECUTION", types)

    def test_12_legitimate_complex_process_tree_chrome(self):
        """G031-SC1 Prensibi: Chrome çoklu süreç mimarisinin meşru karmaşık ağaç olduğunu ve false-positive vermediğini test eder."""
        chrome_tree = [
            {"pid": 2100, "ppid": 0, "name": "chrome.exe", "path": "C:\\Program Files\\Chrome\\chrome.exe", "is_verified_signature": True, "signer": "Google LLC"},
            {"pid": 2110, "ppid": 2100, "name": "chrome.exe", "path": "C:\\Program Files\\Chrome\\chrome.exe", "command_line": "--type=gpu-process", "is_verified_signature": True, "signer": "Google LLC"},
            {"pid": 2120, "ppid": 2100, "name": "chrome.exe", "path": "C:\\Program Files\\Chrome\\chrome.exe", "command_line": "--type=renderer", "is_verified_signature": True, "signer": "Google LLC"}
        ]
        nodes = ProcessTreeBuilder.build_tree(chrome_tree)
        engine = ProcessTreeExplorerAnalyzer()
        engine.root_nodes = nodes
        anoms = engine.evaluate_tree_anomalies()
        self.assertEqual(len(anoms), 0, "Meşru Google Chrome ağacı sahte anomali (false-positive) üretmemelidir.")

    def test_13_negative_control_corrupted_dataset(self):
        """Bozuk ve döngüsel süreç veri kümesinin negatif kontrolde %100 reddedilmesini test eder (G031-SC2)."""
        corrupted_json = "portfolio/hafta_05/gun_031/ornek_veri/corrupted_process_tree_test.json"
        engine = ProcessTreeExplorerAnalyzer()
        res = engine.test_corrupted_dataset(corrupted_json)
        self.assertTrue(res["passed"])
        self.assertEqual(res["rejected_count"], res["total_tested"])
        self.assertGreaterEqual(res["total_tested"], 4)

    def test_14_cli_subprocess_execution(self):
        """CLI üzerinden --tree ve --audit argümanlarıyla script çağrıldığında 0 çıkış koduyla çalışmasını test eder."""
        script_path = "portfolio/hafta_05/gun_031/uygulama/process_tree_explorer_analyzer.py"
        real_json = "portfolio/hafta_05/gun_031/ornek_veri/sample_process_inventory.json"
        p = subprocess.run(
            [sys.executable, script_path, "--inventory", real_json, "--tree", "--audit"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(p.returncode, 0)
        self.assertIn("PROCESS EXPLORER SÜREÇ AĞACI ŞEMASI", p.stdout)
        self.assertIn("OFFICE_SPAWNED_SHELL", p.stdout)


if __name__ == "__main__":
    unittest.main()
