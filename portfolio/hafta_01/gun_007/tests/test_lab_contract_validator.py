#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

Güvenli Laboratuvar Sözleşmesi ve İzolasyon Birim Testleri
---------------------------------------------------------
Bu test modülü; laboratuvar sözleşmesi onay mekanizmasını, internet sızıntı
engellemelerini, VM Escape (hipervizör kaçış) korumalarını ve topoloji
tutarlılığını doğrular. Tüm testler detaylı açıklamalarla donatılmıştır.
"""

# Standart test modülleri
import unittest  # Python dahili birim test motoru
import sys       # Sistem yolları modifikasyonu için
from pathlib import Path  # Dosya yolları için

# Uygulama modülünü Python arama yoluna dahil etme
uygulama_dizini = Path(__file__).resolve().parent.parent / "uygulama"
if str(uygulama_dizini) not in sys.path:
    sys.path.insert(0, str(uygulama_dizini))

# Test edilecek sınıf ve istisna türü
from lab_contract_validator import LabContractValidator, ContractViolationError


class TestLabContractValidator(unittest.TestCase):
    """Laboratuvar sözleşmesi ve izolasyon doğrulamalarını sınayan test süiti."""

    def setUp(self):
        """
        Her testten önce çalışan hazırlık fonksiyonu.
        Onaylı, tam izole ve hatasız bir referans sözleşme kurgular.
        """
        self.gecerli_sozlesme = {
            "proje_adi": "Test Siber Laboratuvar Sözleşmesi",
            "gun_kimligi": "G007",
            "sozlesme_durumu": "ONAYLANDI",
            "taraflar_ve_imzalar": {
                "ciso": "Dr. Selin Kaya",
                "arastirmaci": "Seydi Eryılmaz"
            },
            "etik_ve_hukuki_kapsam": {
                "izinli_ip_bloklari": ["192.168.100.0/24"],
                "yasakli_ip_bloklari": ["0.0.0.0/0", "8.8.8.8", "192.168.1.1"],
                "dis_internet_izni": False,
                "izolasyon_modu": "HOST_ONLY_ISOLATED"
            },
            "hypervisor_guvenlik_ayarlari": {
                "pano_paylasimi_clipboard": "DEVRE_DISI",
                "ortak_klasorler_shared_folders": "DEVRE_DISI",
                "surukle_birak_drag_drop": "DEVRE_DISI"
            },
            "laboratuvar_topolojisi": [
                {
                    "node_id": "NODE-01",
                    "ad": "Kali Linux",
                    "ip_adresi": "192.168.100.10",
                    "mac_adresi": "08:00:27:01:01:10",
                    "adaptor_tipi": "Host-Only",
                    "rol": "SALDIRGAN"
                },
                {
                    "node_id": "NODE-02",
                    "ad": "Windows Target",
                    "ip_adresi": "192.168.100.20",
                    "mac_adresi": "08:00:27:01:01:20",
                    "adaptor_tipi": "Host-Only",
                    "rol": "HEDEF"
                }
            ],
            "riskler_ve_kontroller": [
                {
                    "risk_id": "R1",
                    "risk_tanimi": "Ağ Sızıntısı",
                    "kontrol_adi": "Host-Only Kısıtlaması",
                    "durum": "UYGULANDI"
                }
            ]
        }

    def test_gecerli_sozlesme_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: Onaylı ve tam izole referans sözleşmenin sıfır bulgu
        ile doğrulandığı ve izolasyonun başarılı sayıldığı test edilir.
        """
        validator = LabContractValidator(self.gecerli_sozlesme, katilik_modu=True)
        sonuc = validator.denetle()

        self.assertEqual(sonuc["durum"], "GECERLI")
        self.assertEqual(sonuc["sozlesme_durumu"], "ONAYLANDI")
        self.assertEqual(sonuc["toplam_dugum"], 2)
        self.assertEqual(sonuc["bulgu_sayisi"], 0)
        self.assertTrue(sonuc["izolasyon_basarili_mi"])

    def test_genel_internet_kapsam_ihlali_negatif_kontrol(self):
        """
        NEGATİF KONTROL: İzinli kapsama genel internet bloğu (0.0.0.0/0) eklenirse,
        bunun doğrudan yasal ihlal sayılarak ContractViolationError fırlatması gerekir.
        """
        hatali = dict(self.gecerli_sozlesme)
        hatali_kapsam = dict(self.gecerli_sozlesme["etik_ve_hukuki_kapsam"])
        hatali_kapsam["izinli_ip_bloklari"] = ["0.0.0.0/0"]
        hatali["etik_ve_hukuki_kapsam"] = hatali_kapsam

        validator = LabContractValidator(hatali, katilik_modu=True)
        with self.assertRaises(ContractViolationError) as context:
            validator.denetle()

        self.assertIn("YASAL İHLAL", str(context.exception))

    def test_yasakli_ip_cakismasi_negatif_kontrol(self):
        """
        NEGATİF KONTROL: İzinli kapsama yasaklı listedeki genel bir DNS (8.8.8.8)
        eklendiğinde çelişki tespit edilerek hata fırlatılmalıdır.
        """
        hatali = dict(self.gecerli_sozlesme)
        hatali_kapsam = dict(self.gecerli_sozlesme["etik_ve_hukuki_kapsam"])
        hatali_kapsam["izinli_ip_bloklari"] = ["8.8.8.8/32"]
        hatali["etik_ve_hukuki_kapsam"] = hatali_kapsam

        validator = LabContractValidator(hatali, katilik_modu=True)
        with self.assertRaises(ContractViolationError) as context:
            validator.denetle()

        self.assertIn("Kapsam Çelişkisi", str(context.exception))

    def test_onaylanmamis_sozlesme_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Sözleşme durumu 'TASLAK' veya 'BEKLEMEDE' iken
        test yürütülmesine izin verilmemeli, hata üretilmelidir.
        """
        hatali = dict(self.gecerli_sozlesme)
        hatali["sozlesme_durumu"] = "TASLAK"

        validator = LabContractValidator(hatali, katilik_modu=True)
        with self.assertRaises(ContractViolationError) as context:
            validator.denetle()

        self.assertIn("Onaylanmamış Sözleşme", str(context.exception))

    def test_eksik_imza_negatif_kontrol(self):
        """
        NEGATİF KONTROL: CISO veya Baş Araştırmacı imzası eksik olduğunda
        sözleşmenin geçersiz sayılması teyit edilir.
        """
        hatali = dict(self.gecerli_sozlesme)
        hatali["taraflar_ve_imzalar"] = {"arastirmaci": "Var"}  # CISO yok

        validator = LabContractValidator(hatali, katilik_modu=True)
        with self.assertRaises(ContractViolationError) as context:
            validator.denetle()

        self.assertIn("İmza Eksikliği", str(context.exception))

    def test_pano_paylasimi_acik_negatif_kontrol(self):
        """
        MİMARİ İZOLASYON KURALI: Pano paylaşımı (Clipboard) 'ETKİN' yapılırsa,
        sistem bunu 'KRİTİK İZOLASYON KUSURU' olarak raporlamalıdır.
        """
        guvensiz = dict(self.gecerli_sozlesme)
        guvensiz_hyp = dict(self.gecerli_sozlesme["hypervisor_guvenlik_ayarlari"])
        guvensiz_hyp["pano_paylasimi_clipboard"] = "ETKIN"
        guvensiz["hypervisor_guvenlik_ayarlari"] = guvensiz_hyp

        validator = LabContractValidator(guvensiz, katilik_modu=True)
        sonuc = validator.denetle()

        self.assertGreater(sonuc["bulgu_sayisi"], 0)
        self.assertFalse(sonuc["izolasyon_basarili_mi"])
        bulgu = [b for b in sonuc["guvenlik_bulgulari"] if "Clipboard" in b["alan"]]
        self.assertGreater(len(bulgu), 0)

    def test_ortak_klasor_acik_negatif_kontrol(self):
        """
        MİMARİ İZOLASYON KURALI: Ana makine ile ortak klasör (Shared Folders)
        paylaşımı açık bırakılırsa 'KRİTİK İZOLASYON KUSURU' verilmelidir.
        """
        guvensiz = dict(self.gecerli_sozlesme)
        guvensiz_hyp = dict(self.gecerli_sozlesme["hypervisor_guvenlik_ayarlari"])
        guvensiz_hyp["ortak_klasorler_shared_folders"] = "ETKIN"
        guvensiz["hypervisor_guvenlik_ayarlari"] = guvensiz_hyp

        validator = LabContractValidator(guvensiz, katilik_modu=True)
        sonuc = validator.denetle()

        bulgu = [b for b in sonuc["guvenlik_bulgulari"] if "Shared Folders" in b["alan"]]
        self.assertGreater(len(bulgu), 0)

    def test_guvensiz_kopru_adaptor_negatif_kontrol(self):
        """
        AĞ SIZINTISI KURALI: Dış internet izni yokken bir düğüme 'Bridged' (Köprü)
        adaptör verilmesi durumunda 'GÜVENLİKSİZ AĞ ADAPTÖRÜ' uyarısı verilmelidir.
        """
        guvensiz = dict(self.gecerli_sozlesme)
        guvensiz_topoloji = [dict(n) for n in self.gecerli_sozlesme["laboratuvar_topolojisi"]]
        # Kali makinesine köprü adaptör veriliyor
        guvensiz_topoloji[0]["adaptor_tipi"] = "Bridged"
        guvensiz["laboratuvar_topolojisi"] = guvensiz_topoloji

        validator = LabContractValidator(guvensiz, katilik_modu=True)
        sonuc = validator.denetle()

        bulgu = [b for b in sonuc["guvenlik_bulgulari"] if "ADAPTÖRÜ" in b["seviye"]]
        self.assertGreater(len(bulgu), 0)

    def test_mukerrer_ip_cakismasi_negatif_kontrol(self):
        """
        TOPOLOJİ BÜTÜNLÜĞÜ: İki farklı sanal makineye aynı IP adresi atanırsa
        'IP Çakışması' hatası verilmelidir.
        """
        hatali = dict(self.gecerli_sozlesme)
        hatali_topoloji = [dict(n) for n in self.gecerli_sozlesme["laboratuvar_topolojisi"]]
        # Her iki makineye de aynı IP veriliyor
        hatali_topoloji[1]["ip_adresi"] = "192.168.100.10"
        hatali["laboratuvar_topolojisi"] = hatali_topoloji

        validator = LabContractValidator(hatali, katilik_modu=True)
        with self.assertRaises(ContractViolationError) as context:
            validator.denetle()

        self.assertIn("IP Çakışması", str(context.exception))

    def test_kapsam_disi_dugum_ip_negatif_kontrol(self):
        """
        AĞ SEGMENTASYONU: Bir düğümün IP adresi izinli alt ağ bloğunun dışında kalırsa
        'KAPSAM DIŞI IP ADRESİ' uyarısı üretilmelidir.
        """
        guvensiz = dict(self.gecerli_sozlesme)
        guvensiz_topoloji = [dict(n) for n in self.gecerli_sozlesme["laboratuvar_topolojisi"]]
        # İzinli ağ 192.168.100.0/24 iken düğüme 172.16.5.5 veriliyor
        guvensiz_topoloji[1]["ip_adresi"] = "172.16.5.5"
        guvensiz["laboratuvar_topolojisi"] = guvensiz_topoloji

        validator = LabContractValidator(guvensiz, katilik_modu=True)
        sonuc = validator.denetle()

        bulgu = [b for b in sonuc["guvenlik_bulgulari"] if "KAPSAM DIŞI IP" in b["seviye"]]
        self.assertGreater(len(bulgu), 0)

    def test_esnek_mod_hata_toplama(self):
        """
        ESNEK MOD: katilik_modu=False iken programın çökmeyip hataları döndüğü test edilir.
        """
        kirik = {"proje_adi": "Bozuk"}
        validator = LabContractValidator(kirik, katilik_modu=False)
        gecerli, hatalar = validator.dogrula()

        self.assertFalse(gecerli)
        self.assertGreater(len(hatalar), 0)


# Testler doğrudan çağrıldığında çalıştırılır
if __name__ == "__main__":
    unittest.main(verbosity=2)
