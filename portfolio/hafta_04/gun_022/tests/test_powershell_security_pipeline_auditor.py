# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar yalnızca görüntüleme ve eğitim amaçlıdır.
# Siber Güvenlik 365 Gün Müfredatı - Gün 022 (Komut Satırı: PowerShell Temelleri)

"""PowerShell Güvenlik Boru Hattı Denetçisi Birim Test Paketi (Unit Tests).

Bu test paketi; canlı PowerShell nesne toplama, JSON yükleme ve doğrulama,
şüpheli komut satırı tespiti (MITRE T1059.001), tırnaksız servis yolu analizi (CWE-428),
aşırı kaynak anomalileri, CSV dışa aktarımı ve CLI alt süreç yürütümünü doğrular.
"""

# Birim test çerçevesi için unittest modülü içe aktarılır.
import unittest
# Dosya ve dizin işlemleri için os modülü içe aktarılır.
import os
# JSON formatlama ve doğrulama için json modülü içe aktarılır.
import json
# Geçici dosya ve dizin yönetimi için tempfile modülü içe aktarılır.
import tempfile
# Dizin ağacını temizlemek için shutil modülü içe aktarılır.
import shutil
# CLI alt süreç testleri için subprocess modülü içe aktarılır.
import subprocess
# Python yorumlayıcı yolunu almak için sys modülü içe aktarılır.
import sys

# Test edilecek denetçi sınıfı içe aktarılır.
from portfolio.hafta_04.gun_022.uygulama.powershell_security_pipeline_auditor import PowerShellSecurityPipelineAuditor


class TestPowerShellSecurityPipelineAuditor(unittest.TestCase):
    """Gün 022 PowerShell Güvenlik Boru Hattı Test Sınıfı."""

    def setUp(self) -> None:
        """Her test öncesinde bağımsız geçici test ortamı ve örnek nesneleri hazırlar."""
        # Geçici bir çalışma klasörü oluşturulur.
        self.test_dir = tempfile.mkdtemp()
        # Toplayıcı sınıfı başlatılır.
        self.auditor = PowerShellSecurityPipelineAuditor()

        # Örnek zararsız süreç nesnesi tanımlanır.
        self.clean_process = {
            "ProcessName": "notepad",
            "Id": 1200,
            "CPU": 0.1,
            "WorkingSetMB": 15.0,
            "Handles": 150,
            "CommandLine": "notepad.exe C:\\Users\\Public\\notes.txt"
        }

        # Örnek zararsız servis nesnesi tanımlanır.
        self.clean_service = {
            "Name": "wuauserv",
            "DisplayName": "Windows Update",
            "Status": "Running",
            "StartType": "Automatic",
            "BinaryPathName": "\"C:\\Windows\\system32\\svchost.exe\" -k netsvcs",
            "ServiceAccount": "LocalSystem"
        }

    def tearDown(self) -> None:
        """Her testten sonra geçici test dosyalarını güvenli biçimde temizler."""
        # Geçici dizin mevcutsa temizlenir.
        if os.path.exists(self.test_dir):
            # Klasör ve içeriği silinir.
            shutil.rmtree(self.test_dir)

    def test_01_init_ve_varsayilan_kurallar(self) -> None:
        """Test 01: Sınıf başlatma ve varsayılan kural sözlüğünün doğrulanması."""
        # Kural nesnesinin varlığı doğrulanır.
        self.assertIsNotNone(self.auditor.rules)
        # Şüpheli süreç kalıpları listesi kontrol edilir.
        patterns = self.auditor.rules.get("supheli_surec_kaliplari", [])
        # Kritik kalıpların varlığı test edilir.
        self.assertIn("mimikatz", patterns)
        # Bypass parametresinin varlığı test edilir.
        self.assertIn("-executionpolicy bypass", patterns)

    def test_02_canli_powershell_nesne_toplama(self) -> None:
        """Test 02: Canlı sistemden PowerShell süreç ve servis nesnelerinin toplanması."""
        # Canlı veri toplama metodu çağrılır.
        live_res = self.auditor.collect_live_powershell_objects()
        # Dönen sonucun sözlük olduğu doğrulanır.
        self.assertIsInstance(live_res, dict)
        # surecler anahtarının varlığı kontrol edilir.
        self.assertIn("surecler", live_res)
        # servisler anahtarının varlığı kontrol edilir.
        self.assertIn("servisler", live_res)

    def test_03_json_yukleme_gecerli_surecler(self) -> None:
        """Test 03: Proje ornek_veri altındaki süreç JSON dosyasının hatasız yüklenmesi."""
        # Dosya yolu belirlenir.
        path = os.path.join("portfolio", "hafta_04", "gun_022", "ornek_veri", "ps_process_samples.json")
        # Dosya mevcutsa test edilir.
        if os.path.exists(path):
            # Dosya yüklenir.
            data = self.auditor.load_json_file(path)
            # Liste tipi kontrol edilir.
            self.assertIsInstance(data, list)
            # Eleman sayısı sıfırdan büyük olmalıdır.
            self.assertGreater(len(data), 0)

    def test_04_json_yukleme_gecerli_servisler(self) -> None:
        """Test 04: Proje ornek_veri altındaki servis JSON dosyasının hatasız yüklenmesi."""
        # Dosya yolu belirlenir.
        path = os.path.join("portfolio", "hafta_04", "gun_022", "ornek_veri", "ps_service_samples.json")
        # Dosya mevcutsa test edilir.
        if os.path.exists(path):
            # Dosya yüklenir.
            data = self.auditor.load_json_file(path)
            # Liste tipi kontrol edilir.
            self.assertIsInstance(data, list)
            # Eleman sayısı sıfırdan büyük olmalıdır.
            self.assertGreater(len(data), 0)

    def test_05_dosya_bulunamadi_negatif_kontrol(self) -> None:
        """Test 05: Var olmayan dosya istendiğinde FileNotFoundError fırlatılması (Negatif Test)."""
        # Var olmayan dosya yolu tanımlanır.
        ghost_path = os.path.join(self.test_dir, "hayali_dosya.json")
        # İstisnanın fırlatıldığı test edilir.
        with self.assertRaises(FileNotFoundError):
            # Yükleme denenir.
            self.auditor.load_json_file(ghost_path)

    def test_06_bozuk_json_negatif_kontrol(self) -> None:
        """Test 06: Bozuk sözdizimli JSON dosyasında ValueError fırlatılması (Negatif Test)."""
        # Bozuk JSON dosyası yazılır.
        bad_json = os.path.join(self.test_dir, "bad.json")
        # Dosyaya geçersiz veri yazılır.
        with open(bad_json, "w", encoding="utf-8") as fp:
            fp.write("{ 'gecersiz': json, ")
        # ValueError fırlatıldığı kontrol edilir.
        with self.assertRaises(ValueError):
            # Yükleme denenir.
            self.auditor.load_json_file(bad_json)

    def test_07_temiz_surec_denetimi(self) -> None:
        """Test 07: Standart ve zararsız süreç nesnesinin 0 bulgu ile temiz çıkması."""
        # Temiz süreç listesi ile denetim yapılır.
        findings = self.auditor.audit_processes([self.clean_process])
        # Bulgu sayısı 0 olmalıdır.
        self.assertEqual(len(findings), 0)

    def test_08_supheli_powershell_komut_satiri_tespiti(self) -> None:
        """Test 08: Bypass ve Hidden parametreli PowerShell sürecinde KRİTİK risk tespiti (MITRE T1059.001)."""
        # Şüpheli süreç hazırlanır.
        sus_proc = {
            "ProcessName": "powershell",
            "Id": 8812,
            "Handles": 400,
            "WorkingSetMB": 50.0,
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SUVY"
        }
        # Denetim icra edilir.
        findings = self.auditor.audit_processes([sus_proc])
        # En az bir bulgu olmalıdır.
        self.assertGreaterEqual(len(findings), 1)
        # Risk seviyesinin KRİTİK olduğu doğrulanır.
        self.assertEqual(findings[0]["risk_seviyesi"], "KRITIK")
        # Gerekçede MITRE T1059.001 referansı yer almalıdır.
        self.assertIn("MITRE T1059.001", findings[0]["guvenlik_gerekcesi"])

    def test_09_mimikatz_ve_sekurlsa_tespiti(self) -> None:
        """Test 09: Mimikatz bellek dökümü aracı sürecinde KRİTİK risk tespiti (Zafiyet/Saldırı Testi)."""
        # Mimikatz süreci tanımlanır.
        mimi_proc = {
            "ProcessName": "mimikatz_test",
            "Id": 9924,
            "Handles": 150,
            "WorkingSetMB": 30.0,
            "CommandLine": "mimikatz_test.exe sekurlsa::logonpasswords"
        }
        # Denetim icra edilir.
        findings = self.auditor.audit_processes([mimi_proc])
        # Bulgu sayısı kontrol edilir.
        self.assertEqual(len(findings), 1)
        # Risk KRİTİK olmalıdır.
        self.assertEqual(findings[0]["risk_seviyesi"], "KRITIK")

    def test_10_asiri_kaynak_tuketim_anomalisi_tespiti(self) -> None:
        """Test 10: Eşik üstü handle/RAM kullanan süreçte ORTA seviye anomali tespiti."""
        # Yüksek kaynak tüketen süreç tanımlanır.
        heavy_proc = {
            "ProcessName": "explorer_heavy",
            "Id": 4010,
            "Handles": 3500,  # Eşik 2000'in üstünde
            "WorkingSetMB": 220.0,  # Eşik 150'nin üstünde
            "CommandLine": "C:\\Windows\\explorer.exe"
        }
        # Denetim icra edilir.
        findings = self.auditor.audit_processes([heavy_proc])
        # Anomali tespit edilmelidir.
        self.assertEqual(len(findings), 1)
        # Risk seviyesi ORTA olmalıdır.
        self.assertEqual(findings[0]["risk_seviyesi"], "ORTA")

    def test_11_guvensiz_servis_tespiti(self) -> None:
        """Test 11: Karalistedeki Telnet servisinin çalışması durumunda KRİTİK risk tespiti (CIS İhlali)."""
        # Telnet servisi tanımlanır.
        telnet_srv = {
            "Name": "TlntSvr",
            "DisplayName": "Telnet Server",
            "Status": "Running",
            "ServiceAccount": "LocalSystem",
            "BinaryPathName": "C:\\Windows\\System32\\tlntsvr.exe"
        }
        # Denetim icra edilir.
        findings = self.auditor.audit_services([telnet_srv])
        # Bulgu sayısı kontrol edilir.
        self.assertEqual(len(findings), 1)
        # Risk seviyesi KRİTİK olmalıdır.
        self.assertEqual(findings[0]["risk_seviyesi"], "KRITIK")

    def test_12_tirnaksiz_servis_yolu_tespiti(self) -> None:
        """Test 12: Boşluk içeren ve tırnak içine alınmamış servis yolunda YÜKSEK risk tespiti (CWE-428)."""
        # CWE-428 zafiyetli servis tanımlanır.
        unquoted_srv = {
            "Name": "VulnerableCustomService",
            "DisplayName": "Legacy Enterprise Agent",
            "Status": "Running",
            "ServiceAccount": "LocalSystem",
            "BinaryPathName": "C:\\Program Files\\Enterprise Software\\service.exe"
        }
        # Denetim icra edilir.
        findings = self.auditor.audit_services([unquoted_srv])
        # Bulgu tespit edilmelidir.
        self.assertEqual(len(findings), 1)
        # Risk seviyesi YÜKSEK olmalıdır.
        self.assertEqual(findings[0]["risk_seviyesi"], "YUKSEK")
        # Gerekçede CWE-428 yer almalıdır.
        self.assertIn("CWE-428", findings[0]["guvenlik_gerekcesi"])

    def test_13_csv_disa_aktarma_ve_kolon_dogrulamasi(self) -> None:
        """Test 13: Filtrelenmiş bulguların CSV olarak kaydedilmesi ve sütun doğrulaması (G022-SC2)."""
        # Hedef CSV dosya yolu belirlenir.
        out_csv = os.path.join(self.test_dir, "test_filtre.csv")
        # Örnek bulgular oluşturulur.
        sample_findings = [
            {
                "nesne_tipi": "Surec",
                "isim": "powershell",
                "id_veya_durum": "8812",
                "metrik_veya_hesap": "400 Handle / 50.0 MB",
                "risk_seviyesi": "KRITIK",
                "guvenlik_gerekcesi": "Bypass parametresi tespit edildi"
            },
            {
                "nesne_tipi": "Servis",
                "isim": "TlntSvr",
                "id_veya_durum": "Running",
                "metrik_veya_hesap": "LocalSystem",
                "risk_seviyesi": "KRITIK",
                "guvenlik_gerekcesi": "Telnet servisi aktif"
            }
        ]
        # CSV dışa aktarılır.
        res_path = self.auditor.export_filtered_to_csv(sample_findings, out_csv)
        # Dosyanın varlığı doğrulanır.
        self.assertTrue(os.path.exists(res_path))

        # CSV dosyası okunur ve satırlar kontrol edilir.
        with open(res_path, "r", encoding="utf-8") as fp:
            lines = [l.strip() for l in fp.readlines() if l.strip()]

        # Başlık dahil 3 satır olmalıdır.
        self.assertEqual(len(lines), 3)
        # Başlık kolonları doğrulanır.
        header = lines[0]
        # Kolonlar kontrol edilir.
        for expected_col in ["nesne_tipi", "isim", "id_veya_durum", "risk_seviyesi"]:
            self.assertIn(expected_col, header)

    def test_14_cli_alt_surec_yurutme(self) -> None:
        """Test 14: Komut satırı (CLI) aracının alt süreç (subprocess) olarak yürütülmesi."""
        # Betik yolu belirlenir.
        script = os.path.join("portfolio", "hafta_04", "gun_022", "uygulama", "powershell_security_pipeline_auditor.py")
        # Süreç ve servis girdi yolları belirlenir.
        proc_file = os.path.join("portfolio", "hafta_04", "gun_022", "ornek_veri", "ps_process_samples.json")
        srv_file = os.path.join("portfolio", "hafta_04", "gun_022", "ornek_veri", "ps_service_samples.json")
        out_csv = os.path.join(self.test_dir, "cli_output.csv")

        # Komut çalıştırılır.
        result = subprocess.run(
            [sys.executable, script, "--processes", proc_file, "--services", srv_file, "--csv", out_csv],
            capture_output=True,
            text=True
        )
        # Çıkış kodu 0 olmalıdır.
        self.assertEqual(result.returncode, 0)
        # CSV dosyasının oluştuğu doğrulanır.
        self.assertTrue(os.path.exists(out_csv))


# Testler doğrudan çağrıldığında çalıştırılır.
if __name__ == "__main__":
    unittest.main()
