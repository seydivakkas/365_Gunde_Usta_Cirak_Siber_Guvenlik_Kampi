# -*- coding: utf-8 -*-
"""
GÜN 019: Windows Dosya Sistemi ve NTFS Güvenlik Analizörü Birim Testleri
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 19)

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

# Gün 019 kök dizinini hesaplayıp sys.path'e dahil ediyoruz
G019_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if G019_DIR not in sys.path:
    sys.path.insert(0, G019_DIR)

# Test edilecek hedef sınıfı uygulama paketinden içe aktarıyoruz
from uygulama.ntfs_security_and_acl_analyzer import NtfsSecurityAndAclAnalyzer


class TestNtfsSecurityAndAclAnalyzer(unittest.TestCase):
    """
    NTFS DACL/SACL erişim denetimlerini, Alternatif Veri Akışlarını (ADS)
    ve Dosya Uzantısı - Sihirli Bayt uyumsuzluğunu doğrulayan 14 adet kapsamlı birim testi.
    """

    def setUp(self):
        """
        Her test öncesi analizör nesnesini ve örnek veri dosyası yollarını hazırlar.
        """
        # Her test için taze bir denetim motoru başlatıyoruz
        self.analyzer = NtfsSecurityAndAclAnalyzer()
        # Örnek dosya ve ACL veri seti yolu
        self.sample_path = os.path.join(G019_DIR, "ornek_veri", "ntfs_file_samples.json")
        # Güvenlik taban çizgisi dosyası yolu
        self.baseline_path = os.path.join(G019_DIR, "ornek_veri", "ntfs_security_baseline.json")

    def test_01_init_ve_surum_kontrolu(self):
        """
        Test 01: Sınıf başlatma ve sürüm numarası doğrulaması.
        """
        # Sürüm numarasının 1.0.0 olduğunu teyit ediyoruz
        self.assertEqual(self.analyzer.version, "1.0.0")

    def test_02_canli_dizin_izinleri_icacls_sorgusu(self):
        """
        Test 02: Canlı sistemden yerel dizinin NTFS izinlerinin başarıyla okunması.
        """
        # Mevcut dizini sorguluyoruz
        res = self.analyzer.get_live_directory_acls(".")
        # Sonucun sözlük olduğunu ve ham izin kayıtlarını içerdiğini sınıyoruz
        self.assertIsInstance(res, dict)
        self.assertIn("hedef_yol", res)
        self.assertIn("ham_izin_kayitlari", res)
        self.assertGreater(len(res["ham_izin_kayitlari"]), 0)

    def test_03_dosya_yukleme_gecerli_json(self):
        """
        Test 03: Geçerli JSON dosyasının UTF-8 ile hatasız yüklenmesi.
        """
        data = self.analyzer.load_json_file(self.sample_path)
        self.assertIsInstance(data, dict)
        self.assertIn("ornek_dosyalar", data)
        self.assertIn("klasor_acl_once_sonra_senaryosu", data)

    def test_04_dosya_yukleme_bulunamadi_negatif_kontrol(self):
        """
        Test 04: Var olmayan dosya istendiğinde FileNotFoundError fırlatılması (Negatif Test).
        """
        hayali = os.path.join(G019_DIR, "ornek_veri", "olmayan_ntfs_dosyasi_99.json")
        with self.assertRaises(FileNotFoundError):
            self.analyzer.load_json_file(hayali)

    def test_05_magic_bytes_eslesmesi_gecerli_pdf(self):
        """
        Test 05: PDF uzantılı ve %PDF sihirli baytlarına sahip dosyanın geçerli bulunması.
        """
        base_data = self.analyzer.load_json_file(self.baseline_path)
        sig = base_data.get("bilinen_sihirli_baytlar", {})
        res = self.analyzer.inspect_magic_bytes_and_extension("rapor.pdf", "25504446", sig)
        # Uzantı ve içeriğin tutarlı olduğunu sınıyoruz
        self.assertTrue(res["uzanti_ve_icerik_tutarlı_mı"])
        self.assertFalse(res["kritik_maskeleme_var_mi"])
        self.assertEqual(res["guvenlik_durumu"], "GECERLI_TUTARLI")

    def test_06_magic_bytes_spoofing_pe_executable_as_pdf(self):
        """
        Test 06: PDF gibi gösterilen ancak MZ PE çalıştırılabilir başlığı taşıyan zararlı tespiti (G019-SC1).
        """
        base_data = self.analyzer.load_json_file(self.baseline_path)
        sig = base_data.get("bilinen_sihirli_baytlar", {})
        # .pdf uzantılı ancak 4d5a (MZ) baytları var!
        res = self.analyzer.inspect_magic_bytes_and_extension("fatura.pdf", "4d5a9000", sig)
        # Kritik maskelemenin tespit edildiğini teyit ediyoruz
        self.assertTrue(res["kritik_maskeleme_var_mi"])
        self.assertFalse(res["uzanti_ve_icerik_tutarlı_mı"])
        self.assertEqual(res["guvenlik_durumu"], "KRITIK_MASKELEME_PE_SPOOFING")

    def test_07_magic_bytes_jpeg_ve_png_dogrulamasi(self):
        """
        Test 07: PNG ve JPEG sihirli baytlarının başarıyla tanınması.
        """
        base_data = self.analyzer.load_json_file(self.baseline_path)
        sig = base_data.get("bilinen_sihirli_baytlar", {})
        # PNG kontrolü
        res_png = self.analyzer.inspect_magic_bytes_and_extension("resim.png", "89504e470d0a1a0a", sig)
        self.assertTrue(res_png["uzanti_ve_icerik_tutarlı_mı"])
        # JPEG kontrolü
        res_jpg = self.analyzer.inspect_magic_bytes_and_extension("fotograf.jpg", "ffd8ffe0", sig)
        self.assertTrue(res_jpg["uzanti_ve_icerik_tutarlı_mı"])

    def test_08_ads_zone_identifier_meşru_etiket_tespiti(self):
        """
        Test 08: Mark-of-the-Web (Zone.Identifier) ADS akışının meşru olarak raporlanması.
        """
        ads_list = [{"akis_adi": "Zone.Identifier", "akis_boyut_byte": 64}]
        res = self.analyzer.inspect_alternate_data_streams(ads_list)
        # 1 adet ADS olduğunu ancak tehlikeli ADS olmadığını sınıyoruz
        self.assertEqual(res["toplam_ads_sayisi"], 1)
        self.assertEqual(res["tehlikeli_ads_sayisi"], 0)
        self.assertEqual(res["ads_detaylari"][0]["risk_seviyesi"], "BILGI")

    def test_09_ads_gizli_powershell_tehlikeli_akis_tespiti(self):
        """
        Test 09: Dosya içine gizlenmiş tehlikeli PowerShell ADS akışı tespiti (MITRE T1564.004).
        """
        ads_list = [{"akis_adi": "gizli_kod.ps1", "akis_boyut_byte": 2048}]
        res = self.analyzer.inspect_alternate_data_streams(ads_list)
        # Tehlikeli ADS sayısının 1 olduğunu sınıyoruz
        self.assertEqual(res["tehlikeli_ads_sayisi"], 1)
        self.assertEqual(res["ads_detaylari"][0]["risk_seviyesi"], "KRITIK")

    def test_10_acl_once_sonra_diff_everyone_kaldirilmasi(self):
        """
        Test 10: Klasör ACL fark analizinde Everyone FullControl izninin kaldırılmasının tespiti (G019-SC2).
        """
        onceki = [{"kullanici_grup": "Everyone", "izin": "FullControl", "tip": "Allow"}]
        sonraki = [{"kullanici_grup": "BUILTIN\\Administrators", "izin": "FullControl", "tip": "Allow"}]
        diff = self.analyzer.compare_acl_diff(onceki, sonraki)
        # Güvenlik iyileştirmesinin olduğunu sınıyoruz
        self.assertTrue(diff["guvenlik_iyilestirmesi_var_mi"])
        self.assertTrue(any("Everyone" in n for n in diff["iyilestirme_notlari"]))

    def test_11_acl_once_sonra_diff_explicit_deny_eklenmesi(self):
        """
        Test 11: Klasör ACL fark analizinde Explicit Deny kuralı eklenmesinin tespiti.
        """
        onceki = [{"kullanici_grup": "BUILTIN\\Users", "izin": "Write", "tip": "Allow"}]
        sonraki = [
            {"kullanici_grup": "BUILTIN\\Users", "izin": "Read", "tip": "Allow"},
            {"kullanici_grup": "Everyone", "izin": "Write", "tip": "Deny"}
        ]
        diff = self.analyzer.compare_acl_diff(onceki, sonraki)
        # Explicit Deny notunun üretildiğini sınıyoruz
        self.assertTrue(any("Explicit Deny" in n for n in diff["iyilestirme_notlari"]))

    def test_12_dacl_everyone_full_control_kritik_risk_tespiti(self):
        """
        Test 12: Bir dosyanın DACL'inde Everyone FullControl olduğunda KRİTİK risk üretilmesi.
        """
        base_data = self.analyzer.load_json_file(self.baseline_path)
        tehlikeli_dosya = {
            "dosya_adi": "hassas_veritabani.txt",
            "sihirli_baytlar_hex": "54657374",
            "ads_akislari": [],
            "acl_izinleri": {
                "dacl": [{"kullanici_grup": "Everyone", "izin": "FullControl", "tip": "Allow"}]
            }
        }
        res = self.analyzer.audit_ntfs_file_security(tehlikeli_dosya, base_data)
        # Risk seviyesinin KRİTİK olduğunu teyit ediyoruz
        self.assertEqual(res["risk_seviyesi"], "KRITIK")
        self.assertTrue(res["zafiyet_var_mi"])

    def test_13_tam_denetim_raporu_olusturma(self):
        """
        Test 13: Bütünleştirilmiş tam denetim raporunun eksiksiz veri üretmesi.
        """
        rapor = self.analyzer.generate_full_audit(self.sample_path, self.baseline_path)
        self.assertIn("canli_dizin_izinleri", rapor)
        self.assertIn("dosya_denetim_sonuclari", rapor)
        self.assertIn("klasor_acl_once_sonra_fark_analizi", rapor)
        self.assertIn("genel_sonuc", rapor)

    def test_14_cli_alt_surec_yurutme_dogrulamasi(self):
        """
        Test 14: Komut satırı (CLI) aracının harici alt süreç (subprocess) olarak yürütülmesi.
        """
        script_path = os.path.join(G019_DIR, "uygulama", "ntfs_security_and_acl_analyzer.py")
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
        self.assertIn("dosya_denetim_sonuclari", cli_json)
        self.assertIn("klasor_acl_once_sonra_fark_analizi", cli_json)


if __name__ == "__main__":
    unittest.main()
