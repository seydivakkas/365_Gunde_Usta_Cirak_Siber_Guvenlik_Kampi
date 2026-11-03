# -*- coding: utf-8 -*-
"""
GÜN 016: CPU, RAM ve Depolama Güvenlik Analizörü Birim Testleri
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 16)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu dosya ve testler yalnızca görüntüleme ve eğitim amaçlıdır.
"""

# Standart Python unittest test kütüphanesini içe aktarıyoruz
import unittest
# Dosya yolları ve işletim sistemi işlemleri için os modülü
import os
# Sistem modül yollarını yönetmek için sys modülü
import sys
# JSON verilerini oluşturmak ve test etmek için json modülü
import json
# Geçici test dosyaları ve dizinleri oluşturmak için tempfile modülü
import tempfile
# CLI aracını bağımsız alt süreç olarak test etmek için subprocess modülü
import subprocess

# Uygulama dizinini sistem yoluna ekliyoruz ki modülü içe aktarabilelim
G016_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# sys.path listesine modül kök dizinini ekliyoruz
if G016_DIR not in sys.path:
    sys.path.insert(0, G016_DIR)

# Test edilecek hedef denetim sınıfını uygulama paketinden içe aktarıyoruz
from uygulama.system_hardware_boundary_auditor import SystemHardwareBoundaryAuditor


class TestSystemHardwareBoundaryAuditor(unittest.TestCase):
    """
    CPU, RAM ve Depolama donanım sınırları analizörünün tüm fonksiyonlarını
    ve güvenlik mekanizmalarını doğrulayan 14 adet kapsamlı birim testi.
    """

    def setUp(self):
        """
        Her test öncesinde denetim motoru nesnesini ve örnek verileri hazırlar.
        """
        # Her test metodu için taze bir denetim motoru örneği oluşturuyoruz
        self.auditor = SystemHardwareBoundaryAuditor()
        # Örnek donanım verisi yolunu belirliyoruz
        self.sample_path = os.path.join(G016_DIR, "ornek_veri", "hardware_boundary_sample.json")
        # Güvenlik taban çizgisi veri yolunu belirliyoruz
        self.baseline_path = os.path.join(G016_DIR, "ornek_veri", "hardware_security_baseline.json")

    def test_01_init_ve_katman_hiyerarsisi(self):
        """
        Test 01: Sınıf başlatma ve donanım katman hiyerarşisi doğrulaması.
        """
        # Sürüm numarasının boş olmadığını doğruluyoruz
        self.assertEqual(self.auditor.version, "1.0.0")
        # Desteklenen 3 temel katmanın (CPU, RAM, Depolama) listede olduğunu sınıyoruz
        self.assertIn("CPU", self.auditor.hardware_layers)
        self.assertIn("RAM", self.auditor.hardware_layers)
        self.assertIn("Depolama", self.auditor.hardware_layers)

    def test_02_canli_donanim_envanteri_cpu_katmani(self):
        """
        Test 02: Canlı sistemden CPU katmanı metriklerinin toplanması doğrulaması.
        """
        # Canlı envanter fonksiyonunu çağırıyoruz
        inventory = self.auditor.get_live_hardware_inventory()
        # CPU katmanı sözlüğünün varlığını kontrol ediyoruz
        self.assertIn("cpu_katmani", inventory)
        # Mimari bilginin string ve dolu olduğunu sınıyoruz
        self.assertIsInstance(inventory["cpu_katmani"]["mimari"], str)
        # Mantıksal çekirdek sayısının en az 1 olduğunu teyit ediyoruz
        self.assertGreaterEqual(inventory["cpu_katmani"]["mantiksal_cekirdek_sayisi"], 1)

    def test_03_canli_donanim_envanteri_ram_katmani(self):
        """
        Test 03: Canlı sistemden RAM katmanı bellek adres genişliğinin sorgulanması.
        """
        # Canlı envanteri alıyoruz
        inventory = self.auditor.get_live_hardware_inventory()
        # RAM katmanı sözlüğünü kontrol ediyoruz
        self.assertIn("ram_katmani", inventory)
        # Adres genişliğinin 32 veya 64 bit olduğunu sınıyoruz
        self.assertIn(inventory["ram_katmani"]["adres_genisligi_bit"], [32, 64])
        # Uçuculuk (volatility) bilgisinin açıklandığını doğruluyoruz
        self.assertIn("Volatile", inventory["ram_katmani"]["ucuculuk"])

    def test_04_canli_donanim_envanteri_depolama_katmani(self):
        """
        Test 04: Canlı sistem depolama katmanı alan boyutlarının pozitif değer kontrolü.
        """
        # Canlı envanteri çekiyoruz
        inventory = self.auditor.get_live_hardware_inventory()
        # Depolama katmanını inceliyoruz
        depolama = inventory["depolama_katmani"]
        # Toplam disk alanının sıfırdan büyük olduğunu doğruluyoruz
        self.assertGreater(depolama["toplam_alan_gb"], 0.0)
        # Boş disk alanının sıfırdan büyük veya eşit olduğunu sınıyoruz
        self.assertGreaterEqual(depolama["bos_alan_gb"], 0.0)

    def test_05_dosya_yukleme_gecerli_json(self):
        """
        Test 05: Geçerli bir JSON dosyasının UTF-8 ile hatasız yüklenmesi.
        """
        # Örnek donanım verisini yüklüyoruz
        data = self.auditor.load_json_file(self.sample_path)
        # Yüklenen verinin bir sözlük olduğunu doğruluyoruz
        self.assertIsInstance(data, dict)
        # Önemli anahtar alanların varlığını sınıyoruz
        self.assertIn("donanim_bilesenleri", data)
        self.assertIn("islem_ve_bellek_nesneleri", data)

    def test_06_dosya_yukleme_bulunamadi_negatif_kontrol(self):
        """
        Test 06: Var olmayan bir dosya istendiğinde FileNotFoundError fırlatılması (Negatif Test).
        """
        # Var olmayan hayali bir yol belirliyoruz
        olmayan_dosya = os.path.join(G016_DIR, "ornek_veri", "hayali_dosya_9999.json")
        # FileNotFoundError fırlatıldığını sınıyoruz
        with self.assertRaises(FileNotFoundError):
            self.auditor.load_json_file(olmayan_dosya)

    def test_07_ram_nesnesi_guvensiz_kalinti_degerlendirmesi(self):
        """
        Test 07: RAM'de açık metin tutulan ve sıfırlanmayan nesnede KRİTİK risk tespiti.
        """
        # Güvensiz bellek nesnesi simülasyonu
        guvensiz_nesne = {
            "nesne_id": "TEST-RAM-BAD",
            "mevcut_katman": "RAM",
            "sifrelenmis": False,
            "mlock_kullanildi": False,
            "temizleme_yontemi": "plain_free",
            "guvenli_sifirlama_yapildi": False
        }
        # Kalıntı değerlendirmesini çalıştırıyoruz
        sonuc = self.auditor.evaluate_data_remanence(guvensiz_nesne)
        # Risk seviyesinin KRİTİK olduğunu doğruluyoruz
        self.assertEqual(sonuc["risk_seviyesi"], "KRITIK")
        # Güvenli mi bayrağının False olduğunu teyit ediyoruz
        self.assertFalse(sonuc["guvenli_mi"])
        # İlgili bulguların mevcut olduğunu sınıyoruz
        self.assertTrue(any("SecureZeroMemory eksik" in b for b in sonuc["bulgular"]))

    def test_08_ram_nesnesi_guvenli_sifirlama_degerlendirmesi(self):
        """
        Test 08: Güvenli sıfırlama (SecureZeroMemory) ve mlock uygulanan nesnede DÜŞÜK risk tespiti.
        """
        # Güvenli bellek nesnesi tanımı
        guvenli_nesne = {
            "nesne_id": "TEST-RAM-GOOD",
            "mevcut_katman": "RAM",
            "sifrelenmis": True,
            "mlock_kullanildi": True,
            "temizleme_yontemi": "secure_zero_memory",
            "guvenli_sifirlama_yapildi": True
        }
        # Değerlendirmeyi yapıyoruz
        sonuc = self.auditor.evaluate_data_remanence(guvenli_nesne)
        # Risk seviyesinin DÜŞÜK olduğunu doğruluyoruz
        self.assertEqual(sonuc["risk_seviyesi"], "DUSUK")
        # Güvenli mi bayrağının True olduğunu sınıyoruz
        self.assertTrue(sonuc["guvenli_mi"])

    def test_09_depolama_nesnesi_silinmeyen_kalinti_degerlendirmesi(self):
        """
        Test 09: Depolamada güvenli silinmeyen (shred edilmeyen) dosyada kalıntı riski tespiti.
        """
        # Depolama nesnesi tanımı
        depolama_nesnesi = {
            "nesne_id": "TEST-STORAGE-REMNANT",
            "mevcut_katman": "Depolama",
            "sifrelenmis": False,
            "dosya_guvenli_silindi": False
        }
        # Değerlendiriyoruz
        sonuc = self.auditor.evaluate_data_remanence(depolama_nesnesi)
        # Risk seviyesinin KRİTİK olduğunu (şifresiz + güvenli silinmemiş) teyit ediyoruz
        self.assertEqual(sonuc["risk_seviyesi"], "KRITIK")
        # Güvenli silinmeme bulgusunu kontrol ediyoruz
        self.assertTrue(any("güvenli silinmemiş" in b for b in sonuc["bulgular"]))

    def test_10_cpu_yazmac_nesnesi_degerlendirmesi(self):
        """
        Test 10: CPU yazmacında tutulan hassas verinin kaza/çökme dökümü risk kontrolü.
        """
        # CPU yazmaç nesnesi
        cpu_nesnesi = {
            "nesne_id": "TEST-CPU-REG",
            "mevcut_katman": "CPU",
            "yazmac_adi": "RBX"
        }
        # Değerlendiriyoruz
        sonuc = self.auditor.evaluate_data_remanence(cpu_nesnesi)
        # Risk seviyesinin ORTA olduğunu doğruluyoruz
        self.assertEqual(sonuc["risk_seviyesi"], "ORTA")
        # Core dump bulgusunun varlığını sınıyoruz
        self.assertTrue(any("core dump" in b for b in sonuc["bulgular"]))

    def test_11_donanim_taban_cizgisi_denetimi_ihlal_tespiti(self):
        """
        Test 11: Donanım güvenlik taban çizgisi uyumluluk denetiminin ihlalleri yakalaması.
        """
        # Örnek veriyi ve taban çizgisini yüklüyoruz
        hw_data = self.auditor.load_json_file(self.sample_path)
        base_data = self.auditor.load_json_file(self.baseline_path)
        # Denetimi icra ediyoruz
        audit_res = self.auditor.audit_hardware_security(hw_data, base_data)
        # Toplam kural sayısının sıfırdan büyük olduğunu doğruluyoruz
        self.assertGreater(audit_res["toplam_kural_sayisi"], 0)
        # Örnek veride pagefile temizleme false olduğundan en az 1 ihlal yakalanmalıdır
        self.assertGreaterEqual(audit_res["ihlal_sayisi"], 1)
        # İhlal listesini sınıyoruz
        ihlal_idleri = [i["kural_id"] for i in audit_res["ihlal_edilen_kurallar"]]
        self.assertIn("RULE-STORAGE-002", ihlal_idleri)

    def test_12_bellek_yasam_dongusu_guvenli_sifirlama_simulasyonu(self):
        """
        Test 12: Güvenli bellek sıfırlama (SecureZeroMemory) simülasyonunda sıfır kalıntı testi.
        """
        # Gizli bir parola bayt dizisi veriyoruz
        gizli_veri = b"GizliAnahtar123"
        # Güvenli sıfırlama simülasyonunu çalıştırıyoruz
        sim = self.auditor.simulate_memory_lifecycle(gizli_veri, use_secure_zero=True)
        # Verinin tamamen silindiğini sınıyoruz
        self.assertTrue(sim["veri_tamamen_silindi_mi"])
        # Kalıntı verisinin tamamen sıfırlardan oluştuğunu doğruluyoruz
        self.assertEqual(sim["kalinti_verisi_hex"], "00" * len(gizli_veri))
        # Adli kalıntı riskinin YOK olduğunu teyit ediyoruz
        self.assertEqual(sim["adli_kalinti_riski"], "YOK")

    def test_13_bellek_yasam_dongusu_guvensiz_birakma_kalinti_simulasyonu(self):
        """
        Test 13: Güvensiz serbest bırakmada (plain free) verinin bellekte aynen kalması testi (Negatif Kontrol).
        """
        # Gizli veri baytları
        gizli_veri = b"SifirlanmayanGizliVeri"
        # Güvensiz simülasyonu çalıştırıyoruz (use_secure_zero=False)
        sim = self.auditor.simulate_memory_lifecycle(gizli_veri, use_secure_zero=False)
        # Verinin tamamen silinmediğini (hala bellekte durduğunu) sınıyoruz
        self.assertFalse(sim["veri_tamamen_silindi_mi"])
        # Kalıntı verisinin orijinal verinin hex'iyle birebir aynı olduğunu doğruluyoruz
        self.assertEqual(sim["kalinti_verisi_hex"], gizli_veri.hex())
        # Risk seviyesinin KRİTİK olduğunu teyit ediyoruz
        self.assertIn("KRITIK", sim["adli_kalinti_riski"])

    def test_14_cli_alt_surec_ve_entegrasyon_dogrulamasi(self):
        """
        Test 14: Komut satırı (CLI) aracının harici alt süreç (subprocess) olarak yürütülmesi.
        """
        # CLI yürütülebilir betik yolunu alıyoruz
        script_path = os.path.join(G016_DIR, "uygulama", "system_hardware_boundary_auditor.py")
        # Subprocess komutunu oluşturuyoruz
        cmd = [
            sys.executable,
            script_path,
            "--sample", self.sample_path,
            "--baseline", self.baseline_path,
            "--json"
        ]
        # Alt süreci çalıştırıyoruz
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Dönüş kodunun 0 (başarılı) olduğunu sınıyoruz
        self.assertEqual(result.returncode, 0, f"Hata: {result.stderr.decode('utf-8', errors='replace')}")
        # Standart çıktıyı UTF-8 olarak okuyup JSON ayrıştırması yapıyoruz
        out_text = result.stdout.decode("utf-8", errors="replace")
        cli_json = json.loads(out_text)
        # JSON alanlarının doğruluğunu teyit ediyoruz
        self.assertIn("donanim_taban_cizgisi_ozeti", cli_json)
        self.assertIn("nesne_kalinti_analizleri", cli_json)
        self.assertIn("genel_sonuc", cli_json)


if __name__ == "__main__":
    unittest.main()
