# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 008: Sanallaştırmanın Güvenlikteki Rolü
Birim Testleri: test_vm_security_auditor.py

Bu test modülü; Sanal Makine Güvenlik ve İzolasyon Denetleyicisinin
pozitif (sertleştirilmiş profil), negatif (izolasyon açığı, VM Escape, Evasion)
ve sınır durumlarını %100 kapsama ile doğrular.
"""

import os
import sys
import json
import tempfile
import unittest

# Üst dizindeki uygulama modülünün içe aktarılabilmesi için arama yoluna ekleme yapılıyor
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../uygulama")))

# Denetleyici sınıfı ve özel hata türü içe aktarılıyor
from vm_security_auditor import VMSecurityAuditor, VMSecurityValidationError


class TestVMSecurityAuditor(unittest.TestCase):
    """
    Sanal Makine Güvenlik Denetleyicisi Test Paketi.
    Pozitif, negatif ve güvenlik sınır durumlarını test eder.
    """

    def setUp(self):
        """
        Her test öncesinde ortak kullanılacak geçerli temel dosya yolunu ve örnek profilleri hazırla.
        """
        # Canlı örnek verinin tam yolunu tespit et
        self.ornek_veri_yolu = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../ornek_veri/vm_guvenlik_profili.json")
        )

        # İzole ve tam sertleştirilmiş altın standart VM şablonu (Pozitif kontrol için)
        self.altin_profil = {
            "vm_id": "VM-SEC-TEST",
            "vm_adi": "Test_Altin_Standart_VM",
            "hypervisor_turu": "Tip-2 Hosted",
            "guvenlik_seviyesi": "KRITIK_IZOLE",
            "donanim_yapilandirmasi": {
                "v_cpu": 2,
                "ram_mb": 4096,
                "nested_virtualization": false if hasattr(__builtins__, 'false') else False,
                "hizlandirma_3d": False
            },
            "ag_yapilandirmasi": {
                "adaptor_tipi": "Internal_Isolated",
                "mac_adresi": "52:54:00:AA:BB:CC",
                "promiscuous_mode": "Deny",
                "internet_erisim_izni": False,
                "vlan_etiketi": 100
            },
            "entegrasyon_ozellikleri": {
                "pano_paylasimi": "Disabled",
                "surukle_birak": "Disabled",
                "paylasilan_klasorler": [],
                "misafir_araclari_servisi": "Hardened_Minimal",
                "usb_filtresi_aktif": False
            },
            "dayaniklilik_ve_kurtarma": {
                "anlik_goruntu_politikasi": "Her_Analiz_Sonrasi_Sifirla",
                "disk_calisma_modu": "Non_Persistent",
                "otomatik_rollback_aktif": True,
                "bellek_dump_kaydi": True
            },
            "anti_vm_gizleme": {
                "cpuid_hypervisor_flag_gizli": True,
                "bios_seri_numarasi_ozellestirildi": True,
                "donanim_uretici_adi_maskelendi": True,
                "acpi_tablolari_temizlendi": True
            }
        }

    def _gecici_profil_olustur(self, profiller_listesi):
        """
        Yardımcı metot: Verilen profiller listesini geçici bir JSON dosyasına yazar ve dosya yolunu döner.
        """
        gecici = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"profiller": profiller_listesi}, gecici)
        gecici.close()
        return gecici.name

    def test_01_altin_standart_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: Tam sertleştirilmiş, izole bir analiz VM'i denetlendiğinde
        skor 100 olmalı, 0 güvenlik bulgusu üretilmeli ve durum 'GÜVENLİ' olmalıdır.
        """
        dosya_yolu = self._gecici_profil_olustur([self.altin_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            # 1 profil incelendiğini doğrula
            self.assertEqual(len(sonuclar), 1)
            # Güvenlik skorunun eksiksiz 100 olduğunu doğrula
            self.assertEqual(sonuclar[0]["skor"], 100)
            # Sıfır güvenlik açığı bulunduğunu doğrula
            self.assertEqual(sonuclar[0]["toplam_bulgu_sayisi"], 0)
            # Risk derecesinin GÜVENLİ olduğunu doğrula
            self.assertIn("GÜVENLİ", sonuclar[0]["risk_derecesi"])
        finally:
            os.remove(dosya_yolu)

    def test_02_bridged_ag_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Ağ adaptörü 'Bridged' olarak ayarlandığında,
        fiziksel yerel ağa yayılma riski nedeniyle KRİTİK bulgu üretilmelidir.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["ag_yapilandirmasi"]["adaptor_tipi"] = "Bridged"

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            # Skorun 100'den düştüğünü doğrula (Bridged cezası: 40)
            self.assertEqual(sonuclar[0]["skor"], 60)
            # Bulgular arasında Bridged uyarısının yer aldığını doğrula
            bulgu_basliklari = [b["baslik"] for b in sonuclar[0]["bulgular"]]
            self.assertTrue(any("Bridged" in b for b in bulgu_basliklari))
        finally:
            os.remove(dosya_yolu)

    def test_03_promiscuous_mod_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Ağ kartında Promiscuous mod 'Allow_All' yapıldığında,
        sanal ağ paket koklama (sniffing) riski nedeniyle YÜKSEK risk bulgusu üretilmelidir.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["ag_yapilandirmasi"]["promiscuous_mode"] = "Allow_All"

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 75)
            bulgular = sonuclar[0]["bulgular"]
            self.assertTrue(any("Promiscuous" in b["baslik"] for b in bulgular))
        finally:
            os.remove(dosya_yolu)

    def test_04_izole_vm_internet_erisim_negatif_kontrol(self):
        """
        NEGATİF KONTROL: KRİTİK_İZOLE seviyesindeki analiz makinesine doğrudan internet
        izni verildiğinde C2 iletişimi ve veri sızıntısı uyarısı verilmelidir.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["ag_yapilandirmasi"]["internet_erisim_izni"] = True

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 65)
            self.assertTrue(any("Açık İnternet Erişimi" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_05_pano_paylasimi_vm_escape_kontrol(self):
        """
        NEGATİF KONTROL: Pano paylaşımı 'Bidirectional' yapıldığında,
        konak işletim sistemine sızma (VM Escape) riski KRİTİK olarak raporlanmalıdır.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["entegrasyon_ozellikleri"]["pano_paylasimi"] = "Bidirectional"

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 70)
            self.assertTrue(any("Pano Paylaşımı Açık" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_06_surukle_birak_escape_kontrol(self):
        """
        NEGATİF KONTROL: Sürükle ve bırak 'Bidirectional' yapıldığında,
        konak sisteme dosya enjekte etme riski KRİTİK olarak yakalanmalıdır.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["entegrasyon_ozellikleri"]["surukle_birak"] = "Bidirectional"

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 70)
            self.assertTrue(any("Sürükle-Bırak Açık" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_07_paylasilan_klasor_felaket_kontrol(self):
        """
        NEGATİF KONTROL: Konak sistemin C:\\ kök dizini VM ile ReadWrite paylaşılırsa,
        50 puan ceza kesilmeli ve 'FELAKET' seviyesinde uyarı üretilmelidir.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["entegrasyon_ozellikleri"]["paylasilan_klasorler"] = [
            {"klasor_adi": "Host_Kok", "konak_yolu": "C:\\", "erisim_yetkisi": "ReadWrite"}
        ]

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 50)
            felaket_bulgulari = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaket_bulgulari), 1)
        finally:
            os.remove(dosya_yolu)

    def test_08_3d_hizlandirma_risk_kontrol(self):
        """
        NEGATİF KONTROL: 3D donanım hızlandırma açıkken GPU sürücü zafiyet yüzeyi
        nedeniyle ORTA seviye uyarı üretilmelidir.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["donanim_yapilandirmasi"]["hizlandirma_3d"] = True

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 85)
            self.assertTrue(any("3D Grafik" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_09_snapshot_politikasi_eksik_kontrol(self):
        """
        NEGATİF KONTROL: Anlık görüntü politikası 'Yok' yapıldığında,
        analiz sonrası temiz duruma dönülemeyeceği için YÜKSEK risk uyarısı verilmelidir.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["dayaniklilik_ve_kurtarma"]["anlik_goruntu_politikasi"] = "Yok"

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 75)
            self.assertTrue(any("Snapshot" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_10_anti_vm_mac_evasion_kontrol(self):
        """
        NEGATİF KONTROL: VirtualBox'ın varsayılan MAC adresi (08:00:27) kullanıldığında,
        zararlı yazılımın sanal ortamı fark edeceği (Evasion) uyarısı üretilmelidir.
        """
        bozuk_profil = json.loads(json.dumps(self.altin_profil))
        bozuk_profil["ag_yapilandirmasi"]["mac_adresi"] = "08:00:27:11:22:33"

        dosya_yolu = self._gecici_profil_olustur([bozuk_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            sonuclar = denetleyici.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 90)
            self.assertTrue(any("Oracle VirtualBox" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_11_gecersiz_sema_ve_alan_eksikligi(self):
        """
        HATA YÖNETİMİ: Zorunlu alanlardan biri eksik olduğunda VMSecurityValidationError fırlatılmalıdır.
        """
        eksik_profil = {"vm_id": "VM-EKSIK"}  # donanim, ag, entegrasyon alanları yok!
        dosya_yolu = self._gecici_profil_olustur([eksik_profil])
        try:
            denetleyici = VMSecurityAuditor(dosya_yolu)
            with self.assertRaises(VMSecurityValidationError):
                denetleyici.denetle_tumunu()
        finally:
            os.remove(dosya_yolu)

    def test_12_olmayan_dosya_hatasi(self):
        """
        HATA YÖNETİMİ: Disk üzerinde bulunmayan bir dosya yolu verildiğinde FileNotFoundError fırlatılmalıdır.
        """
        with self.assertRaises(FileNotFoundError):
            VMSecurityAuditor("c:/hayali_olmayan_dizin/profil.json")


if __name__ == "__main__":
    unittest.main()
