# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar yalnızca görüntüleme ve eğitim amaçlıdır.
# Siber Güvenlik 365 Gün Müfredatı - Gün 021 (Mini Proje 2: İşletim Sistemi Envanteri)

"""İşletim Sistemi Güvenlik Envanteri Birim Test Paketi (Unit Tests).

Bu test paketi; canlı envanter toplama, JSON yükleme ve şema doğrulama,
güvenlik duruşu denetimi (CWE/CIS ihlalleri), karşılaştırmalı CSV dışa aktarımı
ve CLI alt süreç yürütümünü hem pozitif hem de negatif testlerle doğrular.
"""

# Birim test çerçevesi için unittest modülü içe aktarılır.
import unittest
# Dosya sistemi ve geçici dosya temizliği için os modülü içe aktarılır.
import os
# JSON verisi oluşturma ve doğrulama için json modülü içe aktarılır.
import json
# Geçici test dosyaları ve dizinleri oluşturmak için tempfile modülü içe aktarılır.
import tempfile
# Dizinleri temizlemek için shutil modülü içe aktarılır.
import shutil
# CLI alt süreç testleri için subprocess modülü içe aktarılır.
import subprocess
# Python yorumlayıcı yolunu almak için sys modülü içe aktarılır.
import sys

# Test edilecek toplayıcı sınıfı içe aktarılır.
from portfolio.hafta_03.gun_021.uygulama.os_security_inventory_collector import OsSecurityInventoryCollector


class TestOsSecurityInventoryCollector(unittest.TestCase):
    """Gün 021 İşletim Sistemi Güvenlik Envanteri Test Sınıfı."""

    def setUp(self) -> None:
        """Her bir test öncesinde bağımsız geçici test ortamı ve örnek verileri hazırlar."""
        # Geçici bir çalışma klasörü oluşturulur.
        self.test_dir = tempfile.mkdtemp()
        # Toplayıcı sınıfı varsayılan kurallarla başlatılır.
        self.collector = OsSecurityInventoryCollector()

        # Örnek geçerli Windows envanter verisi tanımlanır.
        self.valid_windows_inv = {
            "platform": "Windows",
            "os_bilgisi": {
                "isletim_sistemi": "Windows Server 2022",
                "surum": "21H2",
                "is_derleme": "20348",
                "mimari": "x86_64"
            },
            "donanim": {
                "cekirdek_sayisi": 8,
                "toplam_ram_gb": 32.0,
                "diskler": [{"dosya_sistemi": "NTFS", "sifreleme": "BitLocker Etkin"}]
            },
            "hesaplar": [
                {"kullanici_adi": "Administrator", "yonetici_mi": True, "aktif_mi": False},
                {"kullanici_adi": "seydi", "yonetici_mi": True, "aktif_mi": True}
            ],
            "servisler": [
                {"servis_adi": "wuauserv", "gorunen_ad": "Windows Update", "durum": "Running"}
            ],
            "guncellemeler": {
                "bekleyen_kritik_guncelleme_sayisi": 0
            }
        }

        # Örnek geçerli Linux envanter verisi tanımlanır.
        self.valid_linux_inv = {
            "platform": "Linux",
            "os_bilgisi": {
                "isletim_sistemi": "Ubuntu",
                "dagitim": "24.04 LTS",
                "cekirdek_surumu": "6.8.0",
                "mimari": "x86_64"
            },
            "donanim": {
                "cekirdek_sayisi": 16,
                "toplam_ram_gb": 64.0,
                "diskler": [{"dosya_sistemi": "ext4", "sifreleme": "LUKS2 Etkin"}]
            },
            "hesaplar": [
                {"kullanici_adi": "root", "yonetici_mi": True, "aktif_mi": True},
                {"kullanici_adi": "seydi", "yonetici_mi": True, "aktif_mi": True}
            ],
            "servisler": [
                {"servis_adi": "sshd.service", "gorunen_ad": "OpenSSH Daemon", "durum": "Running"}
            ],
            "guncellemeler": {
                "bekleyen_kritik_guncelleme_sayisi": 0
            }
        }

    def tearDown(self) -> None:
        """Her testten sonra geçici dosyaları güvenli biçimde temizler."""
        # Geçici dizin mevcutsa temizlenir.
        if os.path.exists(self.test_dir):
            # Klasör ve içeriği silinir.
            shutil.rmtree(self.test_dir)

    def test_01_init_ve_varsayilan_sema_dogrulamasi(self) -> None:
        """Test 01: Sınıf başlatma ve varsayılan şema kurallarının doğrulanması."""
        # Şema nesnesinin varlığı kontrol edilir.
        self.assertIsNotNone(self.collector.schema)
        # Zorunlu kategoriler listesi alınır.
        cats = self.collector.schema.get("zorunlu_kategoriler", [])
        # 5 zorunlu kategorinin tamamının şemada yer aldığı doğrulanır (G021-SC1).
        for expected in ["os_bilgisi", "donanim", "hesaplar", "servisler", "guncellemeler"]:
            # Kategorinin varlığı onaylanır.
            self.assertIn(expected, cats)

    def test_02_canli_envanter_toplama(self) -> None:
        """Test 02: Canlı sistemden çalışma ortamı güvenlik envanterinin toplanması."""
        # Canlı envanter toplayıcı metodu çalıştırılır.
        live_data = self.collector.collect_live_inventory()
        # Dönen verinin sözlük tipinde olduğu kontrol edilir.
        self.assertIsInstance(live_data, dict)
        # Platform bilgisinin tespit edildiği doğrulanır.
        self.assertIn("platform", live_data)
        # 5 temel alanın canlı envanterde eksiksiz yer aldığı onaylanır.
        self.assertTrue(self.collector.validate_schema(live_data))

    def test_03_json_yukleme_windows_gecerli(self) -> None:
        """Test 03: Proje ornek_veri altındaki Windows envanterinin hatasız yüklenmesi."""
        # Windows örnek JSON dosya yolu belirlenir.
        path = os.path.join("portfolio", "hafta_03", "gun_021", "ornek_veri", "os_inventory_windows_sample.json")
        # Dosya mevcutsa test edilir.
        if os.path.exists(path):
            # Dosya yüklenir.
            data = self.collector.load_inventory_from_json(path)
            # Platform Windows olmalıdır.
            self.assertEqual(data.get("platform"), "Windows")
            # os_bilgisi alanı doğrulanır.
            self.assertIn("Microsoft Windows", data["os_bilgisi"]["isletim_sistemi"])

    def test_04_json_yukleme_linux_gecerli(self) -> None:
        """Test 04: Proje ornek_veri altındaki Linux envanterinin hatasız yüklenmesi."""
        # Linux örnek JSON dosya yolu belirlenir.
        path = os.path.join("portfolio", "hafta_03", "gun_021", "ornek_veri", "os_inventory_linux_sample.json")
        # Dosya mevcutsa test edilir.
        if os.path.exists(path):
            # Dosya yüklenir.
            data = self.collector.load_inventory_from_json(path)
            # Platform Linux olmalıdır.
            self.assertEqual(data.get("platform"), "Linux")
            # os_bilgisi alanı doğrulanır.
            self.assertIn("Ubuntu", data["os_bilgisi"]["isletim_sistemi"])

    def test_05_dosya_bulunamadi_negatif_kontrol(self) -> None:
        """Test 05: Var olmayan dosya istendiğinde FileNotFoundError fırlatılması (Negatif Test)."""
        # Var olmayan hayali dosya yolu tanımlanır.
        ghost_file = os.path.join(self.test_dir, "olmayan_envanter_dosyasi.json")
        # İstisnanın fırlatıldığı doğrulanır.
        with self.assertRaises(FileNotFoundError):
            # Yükleme denenir.
            self.collector.load_inventory_from_json(ghost_file)

    def test_06_bozuk_json_negatif_kontrol(self) -> None:
        """Test 06: Bozuk sözdizimli JSON dosyasında ValueError fırlatılması (Negatif Test)."""
        # Bozuk JSON dosyası yazılır.
        bad_json = os.path.join(self.test_dir, "corrupt.json")
        # Dosyaya geçersiz JSON yazılır.
        with open(bad_json, "w", encoding="utf-8") as fp:
            fp.write("{ 'gecersiz': json, ")
        # ValueError fırlatıldığı doğrulanır.
        with self.assertRaises(ValueError):
            # Yükleme denenir.
            self.collector.load_inventory_from_json(bad_json)

    def test_07_sema_eksik_kategori_negatif_kontrol(self) -> None:
        """Test 07: Zorunlu 5 kategoriden biri eksik olduğunda ValueError fırlatılması (Negatif Test)."""
        # guncellemeler kategorisi eksik bir veri hazırlanır.
        broken_inv = dict(self.valid_windows_inv)
        # Kategori silinir.
        del broken_inv["guncellemeler"]
        # Doğrulama fonksiyonunun hata fırlattığı test edilir.
        with self.assertRaises(ValueError):
            # Şema doğrulaması denenir.
            self.collector.validate_schema(broken_inv)

    def test_08_guvenli_envanter_denetimi_temiz(self) -> None:
        """Test 08: Standartlara tam uyumlu envanterin GUVENLI kararı alması."""
        # Temiz Windows verisi denetlenir.
        audit_res = self.collector.audit_security_posture(self.valid_windows_inv)
        # Genel durumun GUVENLI olduğu doğrulanır.
        self.assertEqual(audit_res.get("genel_durum"), "GUVENLI")
        # Bulgu sayısının sıfır olduğu doğrulanır.
        self.assertEqual(audit_res.get("toplam_bulgu_sayisi"), 0)

    def test_09_guvensiz_calisan_servis_zafiyet_tespiti(self) -> None:
        """Test 09: Karalistedeki Telnet servisinin çalışması durumunda KRİTİK risk tespiti (Negatif/Zafiyet Testi)."""
        # Zafiyetli envanter kopyası oluşturulur.
        vuln_inv = json.loads(json.dumps(self.valid_linux_inv))
        # Çalışan telnet servisi eklenir.
        vuln_inv["servisler"].append({
            "servis_adi": "telnetd",
            "gorunen_ad": "Insecure Telnet Daemon",
            "durum": "Running"
        })
        # Denetim icra edilir.
        audit_res = self.collector.audit_security_posture(vuln_inv)
        # Durumun KRITIK_IHLAL olduğu doğrulanır.
        self.assertEqual(audit_res.get("genel_durum"), "KRITIK_IHLAL")
        # En az bir kritik bulgu olduğu kontrol edilir.
        crit_findings = [f for f in audit_res["bulgular"] if f["risk_seviyesi"] == "KRITIK"]
        # Kritik bulgu sayısı 1 olmalıdır.
        self.assertEqual(len(crit_findings), 1)

    def test_10_aktif_konuk_hesabi_zafiyet_tespiti(self) -> None:
        """Test 10: Guest hesabının aktif bırakılması durumunda YÜKSEK risk tespiti (CIS İhlali)."""
        # Zafiyetli envanter hazırlanır.
        vuln_inv = json.loads(json.dumps(self.valid_windows_inv))
        # Konuk hesabı aktif olarak eklenir.
        vuln_inv["hesaplar"].append({
            "kullanici_adi": "Guest",
            "yonetici_mi": False,
            "aktif_mi": True
        })
        # Denetim icra edilir.
        audit_res = self.collector.audit_security_posture(vuln_inv)
        # Yüksek riskli bulgu aranır.
        high_findings = [f for f in audit_res["bulgular"] if f["risk_seviyesi"] == "YUKSEK"]
        # Yüksek risk bulunduğu onaylanır.
        self.assertTrue(len(high_findings) >= 1)

    def test_11_bekleyen_kritik_yama_zafiyet_tespiti(self) -> None:
        """Test 11: Bekleyen kritik güvenlik yaması olduğunda YÜKSEK risk tespiti."""
        # Zafiyetli envanter kopyalanır.
        vuln_inv = json.loads(json.dumps(self.valid_windows_inv))
        # Bekleyen kritik yama sayısı 3 yapılır.
        vuln_inv["guncellemeler"]["bekleyen_kritik_guncelleme_sayisi"] = 3
        # Denetim icra edilir.
        audit_res = self.collector.audit_security_posture(vuln_inv)
        # Yama bulgusu aranır.
        patch_findings = [f for f in audit_res["bulgular"] if f["kategori"] == "guncellemeler"]
        # Yama bulgusunun varlığı doğrulanır.
        self.assertEqual(len(patch_findings), 1)

    def test_12_karsilastirmali_csv_olusturma(self) -> None:
        """Test 12: Windows ve Linux için karşılaştırmalı CSV envanter şablonu oluşturma (G021-SC2)."""
        # Hedef CSV dosya yolu belirlenir.
        csv_file = os.path.join(self.test_dir, "test_karsilastirmali_envanter.csv")
        # CSV oluşturma çağrılır.
        res_path = self.collector.generate_comparative_csv(self.valid_windows_inv, self.valid_linux_inv, csv_file)
        # Dosyanın oluşturulduğu doğrulanır.
        self.assertTrue(os.path.exists(res_path))
        # Dosya boyutu 0'dan büyük olmalıdır.
        self.assertGreater(os.path.getsize(res_path), 100)

    def test_13_karsilastirmali_csv_kolon_icerik_dogrulamasi(self) -> None:
        """Test 13: CSV çıktısındaki 5 zorunlu sütun ve satır içeriklerinin doğrulanması."""
        # CSV dosya yolu belirlenir.
        csv_file = os.path.join(self.test_dir, "test_kolonlar.csv")
        # CSV oluşturulur.
        self.collector.generate_comparative_csv(self.valid_windows_inv, self.valid_linux_inv, csv_file)
        # CSV dosyası okunur.
        with open(csv_file, "r", encoding="utf-8") as fp:
            lines = [line.strip() for line in fp.readlines() if line.strip()]
        # Başlık satırı kontrol edilir.
        header = lines[0]
        # 5 zorunlu kolonun varlığı onaylanır.
        for expected_col in ["kategori", "ozellik_adi", "windows_degeri", "linux_degeri", "guvenlik_onemi_ve_etkisi"]:
            self.assertIn(expected_col, header)
        # En az 5 veri satırı bulunmalıdır.
        self.assertGreaterEqual(len(lines), 6)

    def test_14_cli_alt_surec_yurutme_dogrulamasi(self) -> None:
        """Test 14: Komut satırı (CLI) aracının alt süreç (subprocess) olarak yürütülmesi."""
        # CLI betik yolu belirlenir.
        script_path = os.path.join("portfolio", "hafta_03", "gun_021", "uygulama", "os_security_inventory_collector.py")
        # Örnek Windows ve Linux dosya yolları alınır.
        win_path = os.path.join("portfolio", "hafta_03", "gun_021", "ornek_veri", "os_inventory_windows_sample.json")
        lin_path = os.path.join("portfolio", "hafta_03", "gun_021", "ornek_veri", "os_inventory_linux_sample.json")
        out_csv = os.path.join(self.test_dir, "cli_test_out.csv")

        # Komut çalıştırılır.
        result = subprocess.run(
            [sys.executable, script_path, "--windows", win_path, "--linux", lin_path, "--csv", out_csv],
            capture_output=True,
            text=True
        )
        # Çıkış kodu 0 olmalıdır.
        self.assertEqual(result.returncode, 0)
        # CSV dosyasının başarıyla oluşturulduğu doğrulanır.
        self.assertTrue(os.path.exists(out_csv))


# Test suite doğrudan çalıştırıldığında testler icra edilir.
if __name__ == "__main__":
    unittest.main()
