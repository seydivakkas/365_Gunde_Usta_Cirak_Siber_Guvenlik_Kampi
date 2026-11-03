# -*- coding: utf-8 -*-
"""
GÜN 018: Süreç, İş Parçacığı ve Hizmet Güvenlik Analizörü Birim Testleri
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 18)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu dosya ve testler yalnızca görüntüleme ve eğitim amaçlıdır.
"""

# Standart Python unittest test kütüphanesini içe aktarıyoruz
import unittest
# Dosya ve dizin işlemleri için os modülü
import os
# Python yorumlayıcı parametreleri ve yol yönetimi için sys modülü
import sys
# JSON verilerini ayrıştırmak için json modülü
import json
# Komut satırı (CLI) aracını bağımsız alt süreç olarak test etmek için subprocess modülü
import subprocess

# Gün 018 kök dizinini hesaplayıp sys.path'e dahil ediyoruz
G018_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if G018_DIR not in sys.path:
    sys.path.insert(0, G018_DIR)

# Test edilecek hedef sınıfı uygulama paketinden içe aktarıyoruz
from uygulama.process_thread_service_security_auditor import ProcessThreadServiceSecurityAuditor


class TestProcessThreadServiceSecurityAuditor(unittest.TestCase):
    """
    Süreç bellek izolasyonunu, iş parçacığı senkronizasyonunu ve
    Windows hizmet zaafiyetlerini (Unquoted Service Path, Zayıf İzinler)
    doğrulayan 14 adet kapsamlı birim testi.
    """

    def setUp(self):
        """
        Her test öncesi analizör nesnesini ve örnek veri dosyası yollarını hazırlar.
        """
        # Her test için taze bir denetim motoru başlatıyoruz
        self.auditor = ProcessThreadServiceSecurityAuditor()
        # Örnek süreç ve hizmet envanteri yolu
        self.sample_path = os.path.join(G018_DIR, "ornek_veri", "process_thread_service_inventory.json")
        # Güvenlik taban çizgisi dosyası yolu
        self.baseline_path = os.path.join(G018_DIR, "ornek_veri", "service_security_baseline.json")

    def test_01_init_ve_surum_kontrolu(self):
        """
        Test 01: Sınıf başlatma ve sürüm numarası doğrulaması.
        """
        # Sürüm numarasının 1.0.0 olduğunu teyit ediyoruz
        self.assertEqual(self.auditor.version, "1.0.0")

    def test_02_canli_envanter_kullanici_surecleri_en_az_iki_surec(self):
        """
        Test 02: Canlı sistemden en az iki kullanıcı sürecinin belgelenmesi (G018-SC2).
        """
        # Canlı envanter fonksiyonunu çağırıyoruz
        inv = self.auditor.get_live_process_and_service_inventory()
        # Kullanıcı süreçleri listesini alıyoruz
        surecler = inv.get("ornek_kullanici_surecleri", [])
        # En az 2 sürecin bulunduğunu sınıyoruz (G018-SC2 gereksinimi)
        self.assertGreaterEqual(len(surecler), 2)
        # Süreçlerin PID ve ad alanlarını içerdiğini teyit ediyoruz
        for s in surecler:
            self.assertIn("pid", s)
            self.assertIn("ad", s)
            self.assertIsInstance(s["pid"], int)

    def test_03_canli_envanter_sistem_hizmeti_session_zero(self):
        """
        Test 03: Canlı sistemden en az bir sistem hizmetinin belgelenmesi (G018-SC2).
        """
        # Canlı envanteri çağırıyoruz
        inv = self.auditor.get_live_process_and_service_inventory()
        # Hizmetler listesini alıyoruz
        hizmetler = inv.get("ornek_sistem_hizmetleri", [])
        # En az 1 hizmetin listelendiğini sınıyoruz
        self.assertGreaterEqual(len(hizmetler), 1)
        # Hizmet adının ve Session 0 izolasyonunun varlığını kontrol ediyoruz
        h1 = hizmetler[0]
        self.assertIn("hizmet_adi", h1)
        self.assertEqual(h1["oturum_id"], 0)

    def test_04_dosya_yukleme_gecerli_json(self):
        """
        Test 04: Geçerli JSON dosyasının UTF-8 ile başarıyla yüklenmesi.
        """
        data = self.auditor.load_json_file(self.sample_path)
        # Yüklenen verinin sözlük olduğunu sınıyoruz
        self.assertIsInstance(data, dict)
        self.assertIn("surecler", data)
        self.assertIn("hizmetler", data)

    def test_05_dosya_yukleme_bulunamadi_negatif_kontrol(self):
        """
        Test 05: Var olmayan dosya istendiğinde FileNotFoundError fırlatılması (Negatif Test).
        """
        hayali = os.path.join(G018_DIR, "ornek_veri", "hayali_dosya_yok_99.json")
        with self.assertRaises(FileNotFoundError):
            self.auditor.load_json_file(hayali)

    def test_06_unquoted_path_tespiti_pozitif_zafiyet(self):
        """
        Test 06: Boşluklu ve tırnaksız servis yolunda zaafiyet tespiti (MITRE T1574.009).
        """
        zafiyetli_yol = "C:\\Program Files\\Kurumsal Bakim Yazilimi\\agent service\\engine.exe"
        res = self.auditor.detect_unquoted_service_path(zafiyetli_yol)
        # Zaafiyetin tespit edildiğini sınıyoruz
        self.assertTrue(res["zafiyet_var_mi"])
        self.assertEqual(res["risk_seviyesi"], "YUKSEK")
        self.assertIn("T1574.009", res["zafiyet_adi"])

    def test_07_unquoted_path_cift_tirnakli_guvenli_yol(self):
        """
        Test 07: Çift tırnak içine alınmış servis yolunun güvenli olarak sınıflandırılması.
        """
        guvenli_yol = "\"C:\\Program Files\\Kurumsal Guvenlik\\guvenli_svc.exe\""
        res = self.auditor.detect_unquoted_service_path(guvenli_yol)
        # Zaafiyet olmadığını sınıyoruz
        self.assertFalse(res["zafiyet_var_mi"])
        self.assertIn("çift tırnak", res["aciklama"])

    def test_08_unquoted_path_bosluksuz_guvenli_yol(self):
        """
        Test 08: Boşluk içermeyen servis yolunun güvenli olarak sınıflandırılması.
        """
        bosluksuz_yol = "C:\\Windows\\System32\\svchost.exe"
        res = self.auditor.detect_unquoted_service_path(bosluksuz_yol)
        # Zaafiyet olmadığını teyit ediyoruz
        self.assertFalse(res["zafiyet_var_mi"])
        self.assertIn("boşluk karakteri yok", res["aciklama"])

    def test_09_unquoted_path_olasi_tuzak_yol_uretme(self):
        """
        Test 09: Unquoted path istismarında CreateProcess ara tuzak .exe adaylarının listelenmesi.
        """
        zafiyetli_yol = "C:\\Program Files\\My App\\service.exe"
        res = self.auditor.detect_unquoted_service_path(zafiyetli_yol)
        # Aday yollar arasında C:\Program.exe ve C:\Program Files\My.exe olmalıdır
        olasi = res["olasi_istismar_yollari"]
        self.assertIn("C:\\Program.exe", olasi)
        self.assertIn("C:\\Program Files\\My.exe", olasi)

    def test_10_hizmet_denetimi_kritik_yazilabilir_klasor_tespiti(self):
        """
        Test 10: Standart kullanıcıların yazabildiği servis klasöründe KRİTİK risk tespiti.
        """
        tehlikeli_servis = {
            "hizmet_adi": "ZayifServis",
            "hesap": "LocalSystem",
            "calistirilabilir_yol": "\"C:\\Program Files\\App\\svc.exe\"",
            "dizin_yazma_izni_kullanicilar": True # Zayıf izin!
        }
        res = self.auditor.audit_service_security(tehlikeli_servis)
        # Risk seviyesinin KRİTİK olduğunu teyit ediyoruz
        self.assertEqual(res["risk_seviyesi"], "KRITIK")
        self.assertTrue(res["zafiyet_var_mi"])

    def test_11_hizmet_denetimi_guvenli_hizmet(self):
        """
        Test 11: Düzgün tırnaklanmış ve kısıtlı izinli hizmetin DÜŞÜK risk alması.
        """
        guvenli_servis = {
            "hizmet_adi": "GuvenliServis",
            "hesap": "NT AUTHORITY\\LocalService",
            "calistirilabilir_yol": "\"C:\\Program Files\\Guvenli\\svc.exe\"",
            "dizin_yazma_izni_kullanicilar": False
        }
        res = self.auditor.audit_service_security(guvenli_servis)
        # Risk seviyesinin DÜŞÜK olduğunu ve zaafiyet bulunmadığını sınıyoruz
        self.assertEqual(res["risk_seviyesi"], "DUSUK")
        self.assertFalse(res["zafiyet_var_mi"])

    def test_12_is_parcacigi_kilitli_senkronizasyon_guvenli_sonuc(self):
        """
        Test 12: Mutex (Kilit) kullanılan iş parçacıklarında yarış durumunun engellenmesi.
        """
        res = self.auditor.simulate_thread_memory_sharing(use_mutex=True)
        # Yarış durumunun oluşmadığını sınıyoruz
        self.assertFalse(res["yaris_durumu_olustu_mu"])
        # Nihai sonucun 0 olduğunu doğruluyoruz
        self.assertEqual(res["gerceklesen_deger"], 0)
        self.assertIn("GÜVENLİ", res["guvenlik_sonucu"])

    def test_13_tam_denetim_raporu_olusturma(self):
        """
        Test 13: Bütünleştirilmiş tam denetim raporunun eksiksiz üretilmesi.
        """
        rapor = self.auditor.generate_full_audit(self.sample_path, self.baseline_path)
        # Rapor alanlarını sınıyoruz
        self.assertIn("canli_envanter", rapor)
        self.assertIn("hizmet_denetim_sonuclari", rapor)
        self.assertIn("is_parcacigi_yaris_durumu_deneyleri", rapor)
        self.assertIn("genel_sonuc", rapor)

    def test_14_cli_alt_surec_yurutme_dogrulamasi(self):
        """
        Test 14: Komut satırı (CLI) aracının harici alt süreç (subprocess) olarak yürütülmesi.
        """
        script_path = os.path.join(G018_DIR, "uygulama", "process_thread_service_security_auditor.py")
        cmd = [
            sys.executable,
            script_path,
            "--sample", self.sample_path,
            "--baseline", self.baseline_path,
            "--json"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Dönüş kodunun sıfır olduğunu sınıyoruz
        self.assertEqual(result.returncode, 0, f"Hata: {result.stderr.decode('utf-8', errors='replace')}")
        # JSON ayrıştırmasını doğruluyoruz
        out_text = result.stdout.decode("utf-8", errors="replace")
        cli_json = json.loads(out_text)
        self.assertIn("canli_envanter", cli_json)
        self.assertIn("hizmet_denetim_sonuclari", cli_json)


if __name__ == "__main__":
    unittest.main()
