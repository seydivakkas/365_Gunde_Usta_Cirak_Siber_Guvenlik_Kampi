# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 009: Windows Üzerinde Laboratuvar Hazırlığı
Birim Testleri: test_windows_lab_provisioner.py

Bu test modülü; Windows Laboratuvar Kurulum ve Doğrulama Motorunun
pozitif (sertleştirilmiş Windows Sandbox, izole vSwitch, güvenli Defender dışlamaları),
negatif (Sandbox sızıntısı, External vSwitch, Exclusion Hijacking) ve sınır durumlarını %100 kapsama ile doğrular.
"""

import os
import sys
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET

# Uygulama modülünün içe aktarılabilmesi için arama yoluna ekleme yapılıyor
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../uygulama")))

# Motor sınıfı ve özel hata türü içe aktarılıyor
from windows_lab_provisioner import WindowsLabProvisioner, WindowsLabValidationError


class TestWindowsLabProvisioner(unittest.TestCase):
    """
    Windows Güvenlik Laboratuvarı Kurulum ve Doğrulama Test Paketi.
    """

    def setUp(self):
        """
        Her test öncesinde geçerli, izole ve sertleştirilmiş bir temel şablon hazırla.
        """
        self.altin_lab = {
            "lab_id": "WIN-LAB-TEST-SEC",
            "lab_adi": "Test_Altin_Windows_Lab",
            "hedef_rol": "Zararlı Yazılım Analizi ve İzolasyon",
            "guvenlik_derecesi": "KRITIK_KORUMALI",
            "sanallastirma_ve_vbs": {
                "hyper_v_etkin": True,
                "vbs_etkin": True,
                "hvci_etkin": True,
                "windows_sandbox_etkin": True
            },
            "windows_sandbox": {
                "profil_adi": "Test_Izole.wsb",
                "v_gpu": "Disable",
                "networking": "Disable",
                "baglanan_klasorler": [
                    {
                        "konak_yolu": "C:\\Guvenli_Lab\\Numuneler",
                        "sandbox_yolu": "C:\\Users\\WDAGUtilityAccount\\Desktop\\Numuneler",
                        "salt_okunur": True
                    }
                ],
                "oturum_acilis_komutu": "",
                "bellek_siniri_mb": 4096
            },
            "hyper_v_ag_anahtarlari": [
                {
                    "anahtar_id": "VSW-INT-01",
                    "anahtar_adi": "Lab_Internal_Switch",
                    "anahtar_tipi": "Internal",
                    "promiscuous_mode": "Deny",
                    "fiziksel_ag_kartina_bagli": False,
                    "guvenlik_duvari_kurali": "Block_Public_Inbound"
                }
            ],
            "defender_dislama_politikasi": {
                "dislama_etkin": True,
                "dislanan_klasorler": [
                    "C:\\Guvenli_Lab\\Araclar"
                ],
                "acl_guvenlik_dogrulamasi": {
                    "sadece_admin_ve_system_yazabilir": True,
                    "standart_kullanici_yazma_engeli": True
                }
            },
            "wsl2_altyapisi": {
                "wsl_surumu": 2,
                "dagitim": "Kali-Linux-Lab",
                "mnt_c_erisim_modu": "ReadOnly",
                "ag_modu": "NAT_Host_Only"
            }
        }

    def _gecici_yapilandirma_olustur(self, lab_listesi):
        """
        Testler için geçici bir JSON yapılandırma dosyası oluşturur.
        """
        gecici = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"laboratuvar_profilleri": lab_listesi}, gecici)
        gecici.close()
        return gecici.name

    def test_01_altin_standart_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: BSL-4 seviyesinde tam sertleştirilmiş Windows laboratuvarı
        denetlendiğinde 100/100 tam puan almalı, sıfır bulgu üretmeli ve durumu 'GÜVENLİ' olmalıdır.
        """
        dosya_yolu = self._gecici_yapilandirma_olustur([self.altin_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            # 1 adet profil incelendiğini teyit et
            self.assertEqual(len(sonuclar), 1)
            # Güvenlik skorunun 100 olduğunu doğrula
            self.assertEqual(sonuclar[0]["skor"], 100)
            # Sıfır güvenlik açığı bulunduğunu doğrula
            self.assertEqual(sonuclar[0]["toplam_bulgu_sayisi"], 0)
            # Risk derecesinin GÜVENLİ olduğunu doğrula
            self.assertIn("GÜVENLİ", sonuclar[0]["risk_derecesi"])
        finally:
            os.remove(dosya_yolu)

    def test_02_sandbox_networking_default_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Windows Sandbox ağ ayarı 'Default' (Açık) bırakılırsa,
        zararlı yazılımın C2 iletişimi ve veri sızdırma riski nedeniyle KRİTİK bulgu üretilmelidir.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["windows_sandbox"]["networking"] = "Default"

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 65)  # 35 ceza puanı
            bulgular = sonuclar[0]["bulgular"]
            self.assertTrue(any("Networking != Disable" in b["baslik"] for b in bulgular))
        finally:
            os.remove(dosya_yolu)

    def test_03_sandbox_mapped_folder_kok_dizin_felaket_kontrol(self):
        """
        NEGATİF KONTROL: Windows Sandbox içine konak sistemin 'C:\\' kök dizini bağlanırsa,
        50 ceza puanı kesilmeli ve FELAKET seviyesinde uyarı üretilmelidir.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["windows_sandbox"]["baglanan_klasorler"] = [
            {"konak_yolu": "C:\\", "sandbox_yolu": "C:\\Users\\WDAGUtilityAccount\\Desktop\\Host_C", "salt_okunur": False}
        ]

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            # Skor düşüşünü ve FELAKET bulgusunu doğrula
            felaket_bulgulari = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaket_bulgulari), 1)
            self.assertIn("Kritik Konak Dizini", felaket_bulgulari[0]["baslik"])
        finally:
            os.remove(dosya_yolu)

    def test_04_sandbox_mapped_folder_yazma_izni_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Sandbox içine bağlanan klasörde 'salt_okunur=False' yapıldığında,
        Sandbox içindeki zararlının konak dosyalarını bozma riski KRİTİK olarak raporlanmalıdır.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["windows_sandbox"]["baglanan_klasorler"][0]["salt_okunur"] = False

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 70)  # 30 ceza puanı
            self.assertTrue(any("Yazma İzni Açık" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_05_hyper_v_external_vswitch_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Hyper-V Sanal Anahtarı (vSwitch) 'External' olarak yapılandırıldığında,
        laboratuvardaki zararlının fiziksel yerel ağa yayılma riski KRİTİK olarak engellenmelidir.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["hyper_v_ag_anahtarlari"] = [
            {
                "anahtar_id": "VSW-EXT",
                "anahtar_adi": "Tehlikeli_External_Switch",
                "anahtar_tipi": "External",
                "promiscuous_mode": "Deny",
                "fiziksel_ag_kartina_bagli": True,
                "guvenlik_duvari_kurali": "None"
            }
        ]

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 60)  # 40 ceza puanı
            self.assertTrue(any("External vSwitch" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_06_hyper_v_promiscuous_mode_negatif_kontrol(self):
        """
        NEGATİF KONTROL: vSwitch üzerinde Promiscuous mod 'Allow_All' yapıldığında,
        sanal ağ paket koklama riski YÜKSEK seviye olarak yakalanmalıdır.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["hyper_v_ag_anahtarlari"][0]["promiscuous_mode"] = "Allow_All"

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 75)  # 25 ceza puanı
            self.assertTrue(any("Promiscuous Mod" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_07_defender_yasakli_genis_dislama_felaket_kontrol(self):
        """
        NEGATİF KONTROL: Windows Defender dışlamalarına 'C:\\Users' veya 'C:\\Windows' eklenirse,
        Exclusion Hijacking tehlikesi nedeniyle FELAKET seviyesinde 50 puan ceza kesilmelidir.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["defender_dislama_politikasi"]["dislanan_klasorler"] = ["C:\\Users"]

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            felaketler = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaketler), 1)
            self.assertIn("Ölümcül Defender Dışlaması", felaketler[0]["baslik"])
        finally:
            os.remove(dosya_yolu)

    def test_08_defender_acl_standart_kullanici_yazma_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Defender dışlama klasörüne standart kullanıcıların yazma izni varsa,
        kısıtlı kullanıcıların taranmayan dizine zararlı atabilmesi YÜKSEK risk olarak yakalanmalıdır.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["defender_dislama_politikasi"]["acl_guvenlik_dogrulamasi"]["standart_kullanici_yazma_engeli"] = False

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 75)
            self.assertTrue(any("Standart Kullanıcı Yazma İzni" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_09_vbs_ve_hvci_kapali_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Sanallaştırma Tabanlı Güvenlik (VBS) ve HVCI kapalıysa,
        çekirdek bellek zafiyetlerine karşı uyarılar üretilmelidir.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["sanallastirma_ve_vbs"]["vbs_etkin"] = False
        bozuk_lab["sanallastirma_ve_vbs"]["hvci_etkin"] = False

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            # VBS: 20 puan, HVCI: 15 puan toplam 35 ceza
            self.assertEqual(sonuclar[0]["skor"], 65)
            self.assertTrue(any("VBS" in b["baslik"] for b in sonuclar[0]["bulgular"]))
            self.assertTrue(any("HVCI" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_10_wsl1_eski_mimari_negatif_kontrol(self):
        """
        NEGATİF KONTROL: WSL1 kullanıldığında (çekirdek paylaşımı),
        WSL2 bağımsız Hyper-V mimarisine geçiş uyarısı ORTA seviyede üretilmelidir.
        """
        bozuk_lab = json.loads(json.dumps(self.altin_lab))
        bozuk_lab["wsl2_altyapisi"]["wsl_surumu"] = 1

        dosya_yolu = self._gecici_yapilandirma_olustur([bozuk_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 85)
            self.assertTrue(any("WSL1" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_11_wsb_dosya_uretim_dogrulamasi(self):
        """
        İŞLEVSELLİK KONTROLÜ: urete_guvenli_wsb_dosyasi metodu geçerli bir XML oluşturmalı
        ve Networking=Disable ile ReadOnly=true etiketlerini içermelidir.
        """
        dosya_yolu = self._gecici_yapilandirma_olustur([self.altin_lab])
        cikti_dizini = tempfile.mkdtemp()
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            wsb_yolu = motor.urete_guvenli_wsb_dosyasi("WIN-LAB-TEST-SEC", cikti_dizini)

            self.assertTrue(os.path.exists(wsb_yolu))

            # Üretilen XML dosyasını ayrıştır ve güvenli etiketleri doğrula
            agac = ET.parse(wsb_yolu)
            kok = agac.getroot()
            self.assertEqual(kok.tag, "Configuration")

            networking_elem = kok.find("Networking")
            self.assertIsNotNone(networking_elem)
            self.assertEqual(networking_elem.text, "Disable")

            mapped = kok.find("MappedFolders")
            self.assertIsNotNone(mapped)
            read_only_elem = mapped.find("MappedFolder/ReadOnly")
            self.assertEqual(read_only_elem.text, "true")
        finally:
            os.remove(dosya_yolu)
            if os.path.exists(wsb_yolu):
                os.remove(wsb_yolu)
            os.rmdir(cikti_dizini)

    def test_12_gecersiz_sema_ve_alan_eksikligi(self):
        """
        HATA YÖNETİMİ: Zorunlu alanlardan biri eksik olduğunda WindowsLabValidationError fırlatılmalıdır.
        """
        eksik_lab = {"lab_id": "LAB-EKSIK"}  # Diğer alanlar eksik
        dosya_yolu = self._gecici_yapilandirma_olustur([eksik_lab])
        try:
            motor = WindowsLabProvisioner(dosya_yolu)
            with self.assertRaises(WindowsLabValidationError):
                motor.denetle_tumunu()
        finally:
            os.remove(dosya_yolu)

    def test_13_olmayan_dosya_hatasi(self):
        """
        HATA YÖNETİMİ: Olmayan bir dosya yolu verildiğinde FileNotFoundError fırlatılmalıdır.
        """
        with self.assertRaises(FileNotFoundError):
            WindowsLabProvisioner("C:/hayali_olmayan_klasor/lab_config.json")


if __name__ == "__main__":
    unittest.main()
