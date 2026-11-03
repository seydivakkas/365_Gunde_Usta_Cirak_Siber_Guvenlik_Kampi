#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

Varlık Sınıflandırma ve Envanter Değerlendirici Birim Testleri
--------------------------------------------------------------
Bu test modülü; varlık sahipliği (Asset Ownership), veri sınıflandırma hiyerarşisi,
gölge BT / sahipsiz varlık tespiti ve güvenlik uyumsuzluklarını sınar.
Her test senaryosu ve doğrulama adımı detaylı açıklamalarla belgelenmiştir.
"""

# Standart test kütüphaneleri
import unittest  # Python yerleşik birim test kütüphanesi
import sys       # Sistem arama yolu modifikasyonları için
from pathlib import Path  # Dosya yolları yönetimi için

# Uygulama dizinini arama yoluna ekleme işlemi
uygulama_dizini = Path(__file__).resolve().parent.parent / "uygulama"
if str(uygulama_dizini) not in sys.path:
    sys.path.insert(0, str(uygulama_dizini))

# Test edilecek sınıf ve istisnalar içe aktarılıyor
from asset_classifier import AssetClassifier, AssetValidationError


class TestAssetClassifier(unittest.TestCase):
    """Varlık envanteri ve sınıflandırma mantığını sınayan test takımı."""

    def setUp(self):
        """
        Her bir test metodundan önce çalışan hazırlık kurgusu.
        5 farklı varlık türünü içeren kusursuz bir referans envanter oluşturur.
        """
        self.gecerli_envanter = {
            "kurum": "Test Finans Kurumu A.Ş.",
            "gun_kimligi": "G005",
            "varliklar": [
                {
                    "varlik_id": "AST-001",
                    "ad": "Müşteri Kredi Kartı DB",
                    "tur": "VERI",
                    "sahip": "Dr. Selin Kaya",
                    "veri_sinifi": "COK_GIZLI_SIR",
                    "kritiklik_derecesi": "KRITIK",
                    "parasal_donanim_degeri_usd": 2500,
                    "is_etki_degeri_usd": 15000000,
                    "ag_konumu": "PROD-VLAN-10",
                    "mevcut_kontroller": ["AES-256 Şifreleme", "FIDO2 MFA"]
                },
                {
                    "varlik_id": "AST-002",
                    "ad": "Kurumsal Web Sitesi",
                    "tur": "UYGULAMA",
                    "sahip": "Kerem Yılmaz",
                    "veri_sinifi": "KAMUYA_ACIK",
                    "kritiklik_derecesi": "DUSUK",
                    "parasal_donanim_degeri_usd": 12000,
                    "is_etki_degeri_usd": 50000,
                    "ag_konumu": "DMZ",
                    "mevcut_kontroller": ["WAF", "HTTPS"]
                },
                {
                    "varlik_id": "AST-003",
                    "ad": "Active Directory Domain Controller",
                    "tur": "KIMLIK",
                    "sahip": "Burak Demir",
                    "veri_sinifi": "GIZLI",
                    "kritiklik_derecesi": "KRITIK",
                    "parasal_donanim_degeri_usd": 4000,
                    "is_etki_degeri_usd": 25000000,
                    "ag_konumu": "MGMT-VLAN",
                    "mevcut_kontroller": ["BitLocker Şifreleme", "PAM", "Sysmon"]
                },
                {
                    "varlik_id": "AST-004",
                    "ad": "GitLab Kaynak Kod Deposu",
                    "tur": "UYGULAMA",
                    "sahip": "Zeynep Can",
                    "veri_sinifi": "GIZLI",
                    "kritiklik_derecesi": "YUKSEK",
                    "parasal_donanim_degeri_usd": 6000,
                    "is_etki_degeri_usd": 8000000,
                    "ag_konumu": "DEV-VLAN",
                    "mevcut_kontroller": ["AES Depolama Şifreleme", "RBAC"]
                },
                {
                    "varlik_id": "AST-005",
                    "ad": "Omurga Güvenlik Duvarı (NGFW)",
                    "tur": "CIHAZ",
                    "sahip": "Caner Aydın",
                    "veri_sinifi": "DAHILI",
                    "kritiklik_derecesi": "KRITIK",
                    "parasal_donanim_degeri_usd": 45000,
                    "is_etki_degeri_usd": 10000000,
                    "ag_konumu": "CORE-RACK",
                    "mevcut_kontroller": ["HA", "SSHv2", "SNMPv3"]
                }
            ]
        }

    def test_gecerli_envanter_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: 5 varlığın eksiksiz doğrulandığı, toplam donanım maliyetinin
        $69,500 ve toplam iş etki değerinin $58,050,000 olduğu teyit edilir.
        """
        classifier = AssetClassifier(self.gecerli_envanter, katilik_modu=True)
        sonuc = classifier.analiz_et()

        # Doğrulama geçerli olmalıdır
        self.assertEqual(sonuc["durum"], "GECERLI")
        # Toplam varlık adedi tam 5 olmalıdır
        self.assertEqual(sonuc["toplam_varlik_sayisi"], 5)
        # Matematiksel toplam donanım bedeli
        self.assertEqual(sonuc["toplam_donanim_maliyeti_usd"], 69500.0)
        # Matematiksel toplam iş riski / etki değeri
        self.assertEqual(sonuc["toplam_is_etkisi_usd"], 58050000.0)
        # Temel referansta sıfır güvenlik uyarısı olmalıdır
        self.assertEqual(len(sonuc["guvenlik_uyarilari"]), 0)

    def test_sahipsiz_varlik_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Bir varlığın 'sahip' (Asset Owner) alanı boş bırakıldığında
        (Orphan Asset / Gölge BT tehlikesi), sistemin AssetValidationError fırlattığı doğrulanır.
        """
        hatali_envanter = dict(self.gecerli_envanter)
        hatali_varliklar = [dict(v) for v in self.gecerli_envanter["varliklar"]]
        # AST-001 varlığının sahibi kasıtlı olarak siliniyor
        hatali_varliklar[0]["sahip"] = ""
        hatali_envanter["varliklar"] = hatali_varliklar

        classifier = AssetClassifier(hatali_envanter, katilik_modu=True)
        with self.assertRaises(AssetValidationError) as context:
            classifier.analiz_et()

        self.assertIn("Sahipsiz Varlık Hatası", str(context.exception))

    def test_gecersiz_veri_sinifi_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Standart dışı bir veri sınıfı (örn: 'TOP_SECRET_UNKNOWN')
        girildiğinde doğrulayıcının hata ürettiği test edilir.
        """
        hatali_envanter = dict(self.gecerli_envanter)
        hatali_varliklar = [dict(v) for v in self.gecerli_envanter["varliklar"]]
        hatali_varliklar[1]["veri_sinifi"] = "GECERSIZ_SINIF"
        hatali_envanter["varliklar"] = hatali_varliklar

        classifier = AssetClassifier(hatali_envanter, katilik_modu=True)
        with self.assertRaises(AssetValidationError) as context:
            classifier.analiz_et()

        self.assertIn("Geçersiz Veri Sınıfı", str(context.exception))

    def test_gecersiz_varlik_turu_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Standart varlık türleri (VERI, UYGULAMA, CIHAZ, KIMLIK, AG)
        dışında tanımsız bir tür girildiğinde reddedilmesi test edilir.
        """
        hatali_envanter = dict(self.gecerli_envanter)
        hatali_varliklar = [dict(v) for v in self.gecerli_envanter["varliklar"]]
        hatali_varliklar[2]["tur"] = "ROBOTIK_KOL"
        hatali_envanter["varliklar"] = hatali_varliklar

        classifier = AssetClassifier(hatali_envanter, katilik_modu=True)
        with self.assertRaises(AssetValidationError) as context:
            classifier.analiz_et()

        self.assertIn("Geçersiz Tür", str(context.exception))

    def test_mukerrer_id_negatif_kontrol(self):
        """
        NEGATİF KONTROL: İki farklı varlığa aynı 'varlik_id' verilmesi durumunda
        envanter bütünlüğü ihlalinden dolayı hata fırlatıldığı doğrulanır.
        """
        hatali_envanter = dict(self.gecerli_envanter)
        hatali_varliklar = [dict(v) for v in self.gecerli_envanter["varliklar"]]
        # AST-002'nin kimliği AST-001 yapılıyor
        hatali_varliklar[1]["varlik_id"] = "AST-001"
        hatali_envanter["varliklar"] = hatali_varliklar

        classifier = AssetClassifier(hatali_envanter, katilik_modu=True)
        with self.assertRaises(AssetValidationError) as context:
            classifier.analiz_et()

        self.assertIn("Mükerrer Kimlik Hatası", str(context.exception))

    def test_bos_envanter_negatif_kontrol(self):
        """
        NEGATİF KONTROL: 'varliklar' listesi boş bir liste verildiğinde sistemin
        hata üreterek işlemi durdurduğu doğrulanır.
        """
        bos_envanter = {"kurum": "Test", "varliklar": []}
        classifier = AssetClassifier(bos_envanter, katilik_modu=True)
        with self.assertRaises(AssetValidationError):
            classifier.analiz_et()

    def test_guvenlik_uyumsuzlugu_sifresiz_gizli_veri(self):
        """
        MİMARİ GÜVENLİK KURALI: 'COK_GIZLI_SIR' veya 'GIZLI' sınıfında veri taşıyan
        bir varlıkta şifreleme (Encryption) yoksa, sistem bunu 'KRİTİK AÇIK' olarak raporlamalıdır.
        """
        guvensiz_envanter = dict(self.gecerli_envanter)
        guvensiz_varliklar = [dict(v) for v in self.gecerli_envanter["varliklar"]]
        # AST-001 (Kredi Kartı DB) kontrollerinden şifreleme kaldırılıyor
        guvensiz_varliklar[0]["mevcut_kontroller"] = ["Sadece Güvenlik Duvarı"]
        guvensiz_envanter["varliklar"] = guvensiz_varliklar

        classifier = AssetClassifier(guvensiz_envanter, katilik_modu=True)
        sonuc = classifier.analiz_et()

        # Envanter geçerlidir ancak güvenlik uyarısı üretilmelidir
        self.assertEqual(sonuc["durum"], "GECERLI")
        self.assertGreater(len(sonuc["guvenlik_uyarilari"]), 0)
        bulgu = sonuc["guvenlik_uyarilari"][0]
        self.assertEqual(bulgu["varlik_id"], "AST-001")
        self.assertIn("şifreleme", bulgu["mesaj"])

    def test_dmz_kritik_varlik_uyarisi(self):
        """
        AĞ SEGMENTASYONU KURALI: Kamuya açık olmayan 'KRITIK' bir iç varlık
        yanlışlıkla doğrudan internete açık DMZ bölgesine konulursa risk uyarısı verilmelidir.
        """
        dmz_envanter = dict(self.gecerli_envanter)
        dmz_varliklar = [dict(v) for v in self.gecerli_envanter["varliklar"]]
        # Active Directory sunucusu DMZ'ye konuluyor
        dmz_varliklar[2]["ag_konumu"] = "DMZ-EDGE-ROUTER"
        dmz_envanter["varliklar"] = dmz_varliklar

        classifier = AssetClassifier(dmz_envanter, katilik_modu=True)
        sonuc = classifier.analiz_et()

        uyarilar = [u for u in sonuc["guvenlik_uyarilari"] if u["varlik_id"] == "AST-003"]
        self.assertGreater(len(uyarilar), 0)
        self.assertIn("DMZ", uyarilar[0]["mesaj"])

    def test_esnek_mod_hata_toplama(self):
        """
        ESNEK DENETİM MODU: katilik_modu=False iken istisna fırlatılmadan
        tüm hataların bir liste olarak döndürüldüğü test edilir.
        """
        kirik_envanter = {"kurum": "X"}  # varliklar anahtarı yok
        classifier = AssetClassifier(kirik_envanter, katilik_modu=False)
        gecerli, hatalar = classifier.dogrula()

        self.assertFalse(gecerli)
        self.assertGreater(len(hatalar), 0)

    def test_tablo_ve_crown_jewel_orani(self):
        """
        GÖRSEL ÇIKTI VE PARADOKS TESTİ: ASCII tablosunun doğru başlıklarla
        oluşturulduğu ve $2,500'lık sunucu için 6000.0x risk çarpanının hesaplandığı doğrulanır.
        """
        classifier = AssetClassifier(self.gecerli_envanter, katilik_modu=True)
        tablo = classifier.tablo_yazdir()

        self.assertIn("KURUMSAL VARLIK ENVANTERİ", tablo)
        self.assertIn("AST-001", tablo)
        self.assertIn("6000.0x", tablo)
        self.assertIn("FINANSAL PARADOKS", tablo)


# Modül doğrudan çalıştırıldığında testler yürütülür
if __name__ == "__main__":
    unittest.main(verbosity=2)
