# -*- coding: utf-8 -*-
"""
GÜN 020: Linux Dosya Ağacı ve FHS Güvenlik Analizörü Birim Testleri
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 20)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu dosya ve testler yalnızca görüntüleme ve eğitim amaçlıdır.
"""

# Standart Python unittest test kütüphanesini içe aktarıyoruz
import unittest
# Dosya yolları ve işletim sistemi işlemleri için os modülü
import os
# Python yorumlayıcı parametreleri için sys modülü
import sys
# JSON verilerini ayrıştırmak için json modülü
import json
# Komut satırı (CLI) aracını bağımsız alt süreç olarak test etmek için subprocess modülü
import subprocess

# Gün 020 kök dizinini hesaplayıp sys.path'e dahil ediyoruz
G020_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if G020_DIR not in sys.path:
    sys.path.insert(0, G020_DIR)

# Test edilecek hedef sınıfı uygulama paketinden içe aktarıyoruz
from uygulama.linux_fhs_hierarchy_auditor import LinuxFhsHierarchyAuditor


class TestLinuxFhsHierarchyAuditor(unittest.TestCase):
    """
    Linux FHS 3.0 dosya ağacı hiyerarşisini, 6 temel dizinin doğrulanmasını,
    Sticky Bit (+t) kontrollerini ve mount sertleştirme bayraklarını
    doğrulayan 14 adet kapsamlı birim testi.
    """

    def setUp(self):
        """
        Her test öncesi analizör nesnesini ve örnek veri dosyası yollarını hazırlar.
        """
        # Her test için taze bir denetim motoru başlatıyoruz
        self.auditor = LinuxFhsHierarchyAuditor()
        # Örnek FHS dosya ağacı veri seti yolu
        self.sample_path = os.path.join(G020_DIR, "ornek_veri", "linux_fhs_sample_map.json")
        # Güvenlik taban çizgisi dosyası yolu
        self.baseline_path = os.path.join(G020_DIR, "ornek_veri", "linux_fhs_security_baseline.json")

    def test_01_init_ve_zorunlu_dizin_listesi(self):
        """
        Test 01: Sınıf başlatma ve zorunlu FHS dizin listesi doğrulaması.
        """
        # Sürüm numarasının 1.0.0 olduğunu teyit ediyoruz
        self.assertEqual(self.auditor.version, "1.0.0")
        # Zorunlu 6 temel dizinin listede olduğunu sınıyoruz (G020-SC2)
        for zorunlu in ["/etc", "/var", "/home", "/tmp", "/dev", "/proc"]:
            self.assertIn(zorunlu, self.auditor.mandatory_fhs_dirs)

    def test_02_canli_platform_baglami_sorgulama(self):
        """
        Test 02: Canlı sistemden çalışma ortamı ve kök dosya sistemi bağlamının okunması.
        """
        ctx = self.auditor.get_live_platform_context()
        # Sözlük tipi olduğunu ve işletim sistemi bilgisini içerdiğini sınıyoruz
        self.assertIsInstance(ctx, dict)
        self.assertIn("isletim_sistemi", ctx)
        self.assertIn("kok_dizin", ctx)

    def test_03_dosya_yukleme_gecerli_json(self):
        """
        Test 03: Geçerli JSON dosyasının UTF-8 ile hatasız yüklenmesi.
        """
        data = self.auditor.load_json_file(self.sample_path)
        self.assertIsInstance(data, dict)
        self.assertIn("fhs_dizinleri", data)
        self.assertIn("zafiyet_test_senaryolari", data)

    def test_04_dosya_yukleme_bulunamadi_negatif_kontrol(self):
        """
        Test 04: Var olmayan dosya istendiğinde FileNotFoundError fırlatılması (Negatif Test).
        """
        hayali = os.path.join(G020_DIR, "ornek_veri", "olmayan_fhs_dosyasi_99.json")
        with self.assertRaises(FileNotFoundError):
            self.auditor.load_json_file(hayali)

    def test_05_fhs_alti_dizin_haritasi_dogrulamasi(self):
        """
        Test 05: FHS 3.0 standardındaki en az 6 çekirdek dizinin doğrulanması (G020-SC2).
        """
        data = self.auditor.load_json_file(self.sample_path)
        dizinler = data.get("fhs_dizinleri", [])
        res = self.auditor.verify_fhs_core_directories(dizinler)
        # Zorunlu dizin sayısının 6 olduğunu ve hepsinin doğrulandığını sınıyoruz
        self.assertEqual(res["dogrulanan_sayisi"], 6)
        self.assertEqual(res["eksik_dizin_sayisi"], 0)
        self.assertTrue(res["fhs_karsilandi_mi"])

    def test_06_fhs_eksik_dizin_negatif_kontrol(self):
        """
        Test 06: Temel dizinlerden biri (/var) eksik olduğunda ihlal üretilmesi (Negatif Test).
        """
        eksik_liste = [
            {"dizin_adi": "/etc", "amac": "Yapilandirma"},
            {"dizin_adi": "/home", "amac": "Kullanici"},
            {"dizin_adi": "/tmp", "amac": "Gecici"},
            {"dizin_adi": "/dev", "amac": "Aygit"},
            {"dizin_adi": "/proc", "amac": "Surec"}
            # /var eksik!
        ]
        res = self.auditor.verify_fhs_core_directories(eksik_liste)
        # 1 adet eksik dizin olduğunu ve fhs_karsilandi_mi bayrağının False olduğunu sınıyoruz
        self.assertEqual(res["eksik_dizin_sayisi"], 1)
        self.assertIn("/var", res["eksik_dizinler"])
        self.assertFalse(res["fhs_karsilandi_mi"])

    def test_07_sticky_bit_etkin_tmp_dizini_dogrulamasi(self):
        """
        Test 07: 1777 izinli ve Sticky Bit etkin /tmp dizininin güvenli onaylanması.
        """
        guvenli_tmp = {"dizin_adi": "/tmp", "izin_oktal": "1777", "sticky_bit_etkin": True}
        res = self.auditor.audit_sticky_bit_and_permissions(guvenli_tmp)
        # Sticky bit olduğunu ve riskin DÜŞÜK olduğunu sınıyoruz
        self.assertTrue(res["sticky_bit_var_mi"])
        self.assertEqual(res["risk_seviyesi"], "DUSUK")
        self.assertEqual(res["durum"], "GUVENLI")

    def test_08_sticky_bit_eksik_tmp_zafiyet_tespiti(self):
        """
        Test 08: 0777 izinli ancak Sticky Bit eksik geçici alanda KRİTİK risk tespiti (CWE-377).
        """
        guvensiz_tmp = {"dizin_adi": "/tmp", "izin_oktal": "0777", "sticky_bit_etkin": False}
        res = self.auditor.audit_sticky_bit_and_permissions(guvensiz_tmp)
        # Sticky bit olmadığını ve KRİTİK risk üretildiğini sınıyoruz
        self.assertFalse(res["sticky_bit_var_mi"])
        self.assertEqual(res["risk_seviyesi"], "KRITIK")
        self.assertEqual(res["durum"], "ZAFIYET_STICKY_BIT_EKSIK")

    def test_09_mount_secenekleri_tam_tmp_dogrulamasi(self):
        """
        Test 09: /tmp üzerinde nodev, nosuid, noexec mount seçeneklerinin tam doğrulanması.
        """
        guvenli_mount_tmp = {
            "dizin_adi": "/tmp",
            "mount_secenekleri": ["nodev", "nosuid", "noexec", "rw"]
        }
        res = self.auditor.audit_mount_hardening_options(guvenli_mount_tmp)
        # Eksik bayrak olmadığını ve güvenli olduğunu sınıyoruz
        self.assertEqual(len(res["eksik_guvenlik_bayraklari"]), 0)
        self.assertTrue(res["guvenli_mi"])
        self.assertEqual(res["risk_seviyesi"], "DUSUK")

    def test_10_mount_secenekleri_eksik_bayrak_tespiti(self):
        """
        Test 10: /tmp üzerinde noexec eksik olduğunda YÜKSEK risk tespiti.
        """
        eksik_mount_tmp = {
            "dizin_adi": "/tmp",
            "mount_secenekleri": ["rw", "relatime"] # noexec, nosuid, nodev yok!
        }
        res = self.auditor.audit_mount_hardening_options(eksik_mount_tmp)
        # Eksik bayraklar olduğunu ve güvenli olmadığını sınıyoruz
        self.assertFalse(res["guvenli_mi"])
        self.assertEqual(res["risk_seviyesi"], "YUKSEK")
        self.assertIn("noexec", res["eksik_guvenlik_bayraklari"])

    def test_11_kritik_shadow_dosyasi_guvenli_izin_dogrulamasi(self):
        """
        Test 11: /etc/shadow dosyasının 0640 izniyle güvenli onaylanması.
        """
        dosyalar = [{"yol": "/etc/shadow", "izin_oktal": "0640", "sahip": "root:shadow"}]
        res = self.auditor.audit_critical_system_files(dosyalar)
        # İhlal sayısının 0 olduğunu teyit ediyoruz
        self.assertEqual(res["ihlal_sayisi"], 0)
        self.assertEqual(res["dosya_bulgulari"][0]["risk_seviyesi"], "DUSUK")

    def test_12_kritik_shadow_dosyasi_gevsik_izin_ihlal_tespiti(self):
        """
        Test 12: /etc/shadow dosyası 0644 (world-readable) olduğunda KRİTİK risk tespiti (CWE-732).
        """
        tehlikeli_shadow = [{"yol": "/etc/shadow", "izin_oktal": "0644", "sahip": "root:root"}]
        res = self.auditor.audit_critical_system_files(tehlikeli_shadow)
        # 1 ihlal yakalandığını ve KRİTİK risk olduğunu sınıyoruz
        self.assertEqual(res["ihlal_sayisi"], 1)
        self.assertEqual(res["dosya_bulgulari"][0]["risk_seviyesi"], "KRITIK")
        self.assertIn("okunabilir", res["dosya_bulgulari"][0]["ihlal"])

    def test_13_tam_denetim_raporu_olusturma(self):
        """
        Test 13: Bütünleştirilmiş tam denetim raporunun eksiksiz veri üretmesi.
        """
        rapor = self.auditor.generate_full_audit(self.sample_path, self.baseline_path)
        self.assertIn("canli_platform_baglami", rapor)
        self.assertIn("fhs_temel_dizin_haritasi", rapor)
        self.assertIn("sticky_bit_analizleri", rapor)
        self.assertIn("mount_sertlestirme_analizleri", rapor)
        self.assertIn("genel_sonuc", rapor)

    def test_14_cli_alt_surec_yurutme_dogrulamasi(self):
        """
        Test 14: Komut satırı (CLI) aracının harici alt süreç (subprocess) olarak yürütülmesi.
        """
        script_path = os.path.join(G020_DIR, "uygulama", "linux_fhs_hierarchy_auditor.py")
        cmd = [
            sys.executable,
            script_path,
            "--sample", self.sample_path,
            "--baseline", self.baseline_path,
            "--json"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, f"Hata: {result.stderr.decode('utf-8', errors='replace')}")
        out_text = result.stdout.decode("utf-8", errors="replace")
        cli_json = json.loads(out_text)
        self.assertIn("fhs_temel_dizin_haritasi", cli_json)
        self.assertIn("sticky_bit_analizleri", cli_json)


if __name__ == "__main__":
    unittest.main()
