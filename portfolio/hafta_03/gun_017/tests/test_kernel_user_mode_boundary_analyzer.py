# -*- coding: utf-8 -*-
"""
GÜN 017: Çekirdek ve Kullanıcı Modu Güvenlik Analizörü Birim Testleri
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 17)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu dosya ve testler yalnızca görüntüleme ve eğitim amaçlıdır.
"""

# Standart unittest kütüphanesini dahil ediyoruz
import unittest
# Dosya yolları ve işletim sistemi işlemleri için os modülü
import os
# Python yürütme yolları ve parametreleri için sys modülü
import sys
# JSON verileriyle test yapmak için json modülü
import json
# Komut satırı (CLI) aracını bağımsız alt süreç olarak test etmek için subprocess modülü
import subprocess

# Gün 017 kök dizinini hesaplayıp sys.path'e ekliyoruz
G017_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if G017_DIR not in sys.path:
    sys.path.insert(0, G017_DIR)

# Hedef denetim sınıfını uygulama modülünden içe aktarıyoruz
from uygulama.kernel_user_mode_boundary_analyzer import KernelUserModeBoundaryAnalyzer


class TestKernelUserModeBoundaryAnalyzer(unittest.TestCase):
    """
    Çekirdek (Ring 0) ve Kullanıcı (Ring 3) modu yetki sınırları,
    sistem çağrısı işaretçi doğrulaması ve BYOVD sürücü denetimlerini
    doğrulayan 14 adet kapsamlı birim testi.
    """

    def setUp(self):
        """
        Her test öncesi analizör nesnesini ve dosya yollarını hazırlar.
        """
        # Taze bir analizör nesnesi oluşturuyoruz
        self.analyzer = KernelUserModeBoundaryAnalyzer()
        # Yetki matrisi veri dosyasının tam yolunu alıyoruz
        self.matrix_path = os.path.join(G017_DIR, "ornek_veri", "kernel_user_privilege_matrix.json")
        # Çekirdek güvenlik taban çizgisi dosyasının tam yolunu alıyoruz
        self.baseline_path = os.path.join(G017_DIR, "ornek_veri", "kernel_security_baseline.json")

    def test_01_init_ve_adres_sinirlari(self):
        """
        Test 01: Sınıf başlatma ve 64-bit kanonik adres sınırları doğrulaması.
        """
        # Sürüm numarasının tanımlı olduğunu sınıyoruz
        self.assertEqual(self.analyzer.version, "1.0.0")
        # Kullanıcı alanı azami adresinin 0x00007FFFFFFFFFFF olduğunu teyit ediyoruz
        self.assertEqual(self.analyzer.canonical_user_space_max, 0x00007FFFFFFFFFFF)
        # Çekirdek alanı başlangıç adresinin 0xFFFF800000000000 olduğunu sınıyoruz
        self.assertEqual(self.analyzer.canonical_kernel_space_min, 0xFFFF800000000000)

    def test_02_canli_surec_baglami_sorgulama(self):
        """
        Test 02: Canlı sistemden mevcut sürecin yetki ve bütünlük bağlamının sorgulanması.
        """
        # Canlı süreç bağlamını çağırıyoruz
        ctx = self.analyzer.get_current_process_privilege_context()
        # PID değerinin geçerli bir tamsayı olduğunu sınıyoruz
        self.assertIsInstance(ctx["pid"], int)
        self.assertGreater(ctx["pid"], 0)
        # Çalışma halkasının Ring 3 (Kullanıcı Kipi) olduğunu doğruluyoruz
        self.assertIn("Ring 3", ctx["calisma_halkasi"])
        # Bütünlük seviyesinin belirlendiğini teyit ediyoruz
        self.assertIsInstance(ctx["butunluk_seviyesi"], str)

    def test_03_dosya_yukleme_gecerli_json(self):
        """
        Test 03: Geçerli bir JSON dosyasının hatasız yüklenmesi.
        """
        # Matris verisini yüklüyoruz
        data = self.analyzer.load_json_file(self.matrix_path)
        # Sözlük tipi olduğunu ve anahtarları içerdiğini sınıyoruz
        self.assertIsInstance(data, dict)
        self.assertIn("yetki_seviyeleri", data)
        self.assertIn("bilinen_guvenliksiz_suruculer_byovd", data)

    def test_04_dosya_yukleme_bulunamadi_negatif_kontrol(self):
        """
        Test 04: Var olmayan dosya istendiğinde FileNotFoundError fırlatılması (Negatif Test).
        """
        # Olmayan bir dosya yolu oluşturuyoruz
        hayali = os.path.join(G017_DIR, "ornek_veri", "olmayan_dosya_404.json")
        # FileNotFoundError fırlatıldığını sınıyoruz
        with self.assertRaises(FileNotFoundError):
            self.analyzer.load_json_file(hayali)

    def test_05_syscall_gecerli_kullanici_isaretcisi(self):
        """
        Test 05: Kullanıcı alanındaki meşru bir bellek göstericisinin onaylanması.
        """
        # Kullanıcı alanında geçerli bir 64-bit adres (ör: 0x00007ffd12340000)
        gecerli_adres = "0x00007ffd12340000"
        boyut = 1024
        res = self.analyzer.validate_syscall_pointer(gecerli_adres, boyut)
        # Doğrulamanın başarılı ve güvenli olduğunu sınıyoruz
        self.assertTrue(res["guvenli_mi"])
        self.assertEqual(res["durum"], "GECERLI_KULLANICI_ISARETCISI")

    def test_06_syscall_null_pointer_engeli_negatif_kontrol(self):
        """
        Test 06: NULL Pointer (0x0) enjeksiyonunun engellenmesi (CWE-476 Negatif Kontrol).
        """
        # NULL adresi veriyoruz
        null_adres = "0x0000000000000000"
        res = self.analyzer.validate_syscall_pointer(null_adres, 64)
        # Güvenli olmadığını ve engellendiğini sınıyoruz
        self.assertFalse(res["guvenli_mi"])
        self.assertEqual(res["durum"], "ENGEL_NULL_POINTER")
        self.assertIn("NULL Pointer", res["hata"])

    def test_07_syscall_cekirdek_alani_ihlali_negatif_kontrol(self):
        """
        Test 07: Çekirdek adres alanını (Kernel Space) işaret eden sahte göstericinin engellenmesi.
        """
        # Çekirdek alanı adresi (0xFFFFF800...)
        cekirdek_adresi = "0xfffff80012340000"
        res = self.analyzer.validate_syscall_pointer(cekirdek_adresi, 128)
        # Engellendiğini ve güvenlik ihlali üretildiğini sınıyoruz
        self.assertFalse(res["guvenli_mi"])
        self.assertEqual(res["durum"], "ENGEL_CEKIRDEK_ALANI_IHLALI")
        self.assertIn("SMEP/SMAP ihlali", res["hata"])

    def test_08_syscall_integer_overflow_engeli(self):
        """
        Test 08: İşaretçi ve boyut toplamında 64-bit tamsayı taşması engeli.
        """
        # Çok büyük adres ve boyut
        buyuk_adres = 0xFFFFFFFFFFFFFFFF
        buyuk_boyut = 100
        # addr + size taşması oluşursa
        res = self.analyzer.validate_syscall_pointer(hex(buyuk_adres), buyuk_boyut)
        # Engellendiğini sınıyoruz
        self.assertFalse(res["guvenli_mi"])

    def test_09_syscall_gecersiz_hex_formati(self):
        """
        Test 09: Geçersiz karakterler içeren adres formatında hata döndürülmesi.
        """
        bozuk_adres = "0xZZZ_GECERSIZ_ADRES"
        res = self.analyzer.validate_syscall_pointer(bozuk_adres, 32)
        # Geçersiz format durumunu sınıyoruz
        self.assertEqual(res["durum"], "GECERSIZ_FORMAT")

    def test_10_byovd_surucu_denetimi_tehdit_tespiti(self):
        """
        Test 10: Bilinen savunmasız sürücülerin (RTCore64, gdrv) BYOVD tehdidi olarak saptanması.
        """
        # Tehlikeli sürücü listesi
        suruculer = [
            {"surucu_adi": "RTCore64.sys", "uretici": "MSI", "zafiyet_turu": "Kernel RW", "durum": "ENGEL_LISTESINDE_OLMALI"}
        ]
        res = self.analyzer.audit_byovd_drivers(suruculer)
        # 1 adet engellenen sürücü olduğunu sınıyoruz
        self.assertEqual(res["engellenen_byovd_surucu_sayisi"], 1)
        self.assertEqual(res["surucu_detaylari"][0]["risk_seviyesi"], "KRITIK")

    def test_11_byovd_surucu_denetimi_guvenli_surucu(self):
        """
        Test 11: Meşru ve imzalı sürücünün güvenli kabul edilmesi.
        """
        temiz_suruculer = [
            {"surucu_adi": "corp_filter.sys", "uretici": "Corp Inc", "zafiyet_turu": "Yok", "durum": "GUVENLI_IMZALI"}
        ]
        res = self.analyzer.audit_byovd_drivers(temiz_suruculer)
        # Engellenen sürücünün 0 olduğunu teyit ediyoruz
        self.assertEqual(res["engellenen_byovd_surucu_sayisi"], 0)
        self.assertEqual(res["guvenli_surucu_sayisi"], 1)

    def test_12_cekirdek_taban_cizgisi_ihlal_yakalama(self):
        """
        Test 12: Çekirdek koruma taban çizgisindeki eksik ayarların ihlal olarak raporlanması.
        """
        # Taban çizgisi dosyasını yüklüyoruz
        baseline = self.analyzer.load_json_file(self.baseline_path)
        # İhlal içeren bir sistem ayar sözlüğü
        eksik_sistem = {
            "surucu_imza_zorunlulugu_dse": False, # DSE kapalı!
            "savunmasiz_surucu_engelleme_listesi_etkin": True,
            "hipervizor_korumali_kod_butunlugu_hvci": True,
            "smep_smap_donanim_izolasyonu": True
        }
        res = self.analyzer.audit_kernel_security_baseline(eksik_sistem, baseline)
        # En az 1 ihlal yakalandığını sınıyoruz
        self.assertGreaterEqual(res["ihlal_sayisi"], 1)
        ihlal_idleri = [i["kural_id"] for i in res["ihlal_edilen_kurallar"]]
        self.assertIn("RULE-KERN-001", ihlal_idleri)

    def test_13_tam_denetim_raporu_olusturma(self):
        """
        Test 13: Bütünleşik tam denetim raporunun eksiksiz veri üretmesi.
        """
        rapor = self.analyzer.generate_full_audit(self.matrix_path, self.baseline_path)
        # Temel anahtar alanları sınıyoruz
        self.assertIn("canli_surec_baglami", rapor)
        self.assertIn("surucu_byovd_denetimi", rapor)
        self.assertIn("isaretci_syscall_denetimi", rapor)
        self.assertIn("cekirdek_taban_cizgisi_denetimi", rapor)
        self.assertIn("genel_sonuc", rapor)

    def test_14_cli_alt_surec_yurutme_dogrulamasi(self):
        """
        Test 14: Komut satırı (CLI) aracının harici alt süreç (subprocess) olarak icra edilmesi.
        """
        script_path = os.path.join(G017_DIR, "uygulama", "kernel_user_mode_boundary_analyzer.py")
        cmd = [
            sys.executable,
            script_path,
            "--matrix", self.matrix_path,
            "--baseline", self.baseline_path,
            "--json"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Sıfır dönüş kodu ile sonlandığını sınıyoruz
        self.assertEqual(result.returncode, 0, f"Hata: {result.stderr.decode('utf-8', errors='replace')}")
        # JSON ayrıştırması yapıyoruz
        out_text = result.stdout.decode("utf-8", errors="replace")
        cli_json = json.loads(out_text)
        self.assertIn("surucu_byovd_denetimi", cli_json)
        self.assertIn("cekirdek_taban_cizgisi_denetimi", cli_json)


if __name__ == "__main__":
    unittest.main()
