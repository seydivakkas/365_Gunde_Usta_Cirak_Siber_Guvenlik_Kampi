#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

Veri Akış Diyagramı (DFD) ve Tehdit Modelleme Birim Testleri
-----------------------------------------------------------
Bu test modülü; güven sınırları (Trust Boundaries), STRIDE tehdit kategorileri,
güvensiz sınır geçişleri ve karşılanmamış açık tehdit senaryolarını test eder.
Tüm testler ve kontroller zengin Türkçe açıklamalarla donatılmıştır.
"""

# Standart test kütüphaneleri
import unittest  # Python dahili birim test motoru
import sys       # Sistem yolu yönetimi için
from pathlib import Path  # Dosya yolları yönetimi için

# Uygulama modülünü arama yoluna dahil etme
uygulama_dizini = Path(__file__).resolve().parent.parent / "uygulama"
if str(uygulama_dizini) not in sys.path:
    sys.path.insert(0, str(uygulama_dizini))

# Test edilecek motor ve hata sınıfları içe aktarılıyor
from threat_modeler import ThreatModeler, ThreatModelValidationError


class TestThreatModeler(unittest.TestCase):
    """Veri akış diyagramı ve tehdit modelleme mekanizmasını sınayan test takımı."""

    def setUp(self):
        """
        Her bir test senaryosundan önce çalışan hazırlık fonksiyonu.
        Hatasız, tam korumalı referans bir yerel not defteri modeli kurgular.
        """
        self.gecerli_model = {
            "uygulama_adi": "Test KriptoNot Uygulaması",
            "gun_kimligi": "G006",
            "bilesenler": [
                {"id": "E1", "ad": "Kullanıcı", "tur": "DIS_VARLIK"},
                {"id": "P1", "ad": "Not Arayüzü", "tur": "SUREC"},
                {"id": "DS1", "ad": "Not Kasası", "tur": "VERI_DEPOSU"},
                {"id": "P2", "ad": "Bulut API", "tur": "SUREC_UZAK"}
            ],
            "guven_sinirlari": [
                {"id": "TB1", "ad": "Kullanıcı Sınırı", "risk_seviyesi": "ORTA"},
                {"id": "TB2", "ad": "Disk Sınırı", "risk_seviyesi": "YUKSEK"},
                {"id": "TB3", "ad": "Ağ Sınırı", "risk_seviyesi": "KRITIK"}
            ],
            "veri_akislari": [
                {
                    "id": "DF1",
                    "kaynak": "E1",
                    "hedef": "P1",
                    "gecilen_sinir": "TB1",
                    "kontroller": ["Girdi Doğrulama"]
                },
                {
                    "id": "DF2",
                    "kaynak": "P1",
                    "hedef": "DS1",
                    "gecilen_sinir": "TB2",
                    "kontroller": ["AES-256-GCM Şifreleme", "Auth Tag Doğrulama"]
                },
                {
                    "id": "DF3",
                    "kaynak": "DS1",
                    "hedef": "P1",
                    "gecilen_sinir": "TB2",
                    "kontroller": ["AES-GCM Şifre Çözme"]
                },
                {
                    "id": "DF4",
                    "kaynak": "P1",
                    "hedef": "P2",
                    "gecilen_sinir": "TB3",
                    "kontroller": ["TLS 1.3 Taşıma Güvenliği", "Certificate Pinning"]
                }
            ],
            "tehditler": [
                {
                    "id": "TH-01",
                    "kategori": "TAMPERING",
                    "hedef_bilesen": "DS1",
                    "kontrol_id": "C-01",
                    "kontrol_aciklama": "GCM Auth Tag ile tahrifat anında fark edilir.",
                    "durum": "ENGEL_ALTI"
                },
                {
                    "id": "TH-02",
                    "kategori": "INFORMATION_DISCLOSURE",
                    "hedef_bilesen": "DF4",
                    "kontrol_id": "C-02",
                    "kontrol_aciklama": "TLS 1.3 hat dinlemesini engeller.",
                    "durum": "ENGEL_ALTI"
                }
            ]
        }

    def test_gecerli_dfd_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: Geçerli ve tüm kontrolleri tanımlı bir modelin
        hatasız doğrulandığı ve sıfır mimari güvenlik kusuru ürettiği test edilir.
        """
        modeler = ThreatModeler(self.gecerli_model, katilik_modu=True)
        sonuc = modeler.analiz_et()

        # Doğrulama geçerli olmalıdır
        self.assertEqual(sonuc["durum"], "GECERLI")
        # Bileşen sayıları doğru sayılmalıdır
        self.assertEqual(sonuc["toplam_bilesen"], 4)
        self.assertEqual(sonuc["toplam_sinir"], 3)
        self.assertEqual(sonuc["toplam_akis"], 4)
        # Mimari açık bulunmamalıdır
        self.assertEqual(sonuc["bulgu_sayisi"], 0)

    def test_hayalet_kaynak_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Bir veri akışının kaynağı bileşenler arasında tanımlı
        olmadığında (Hayalet Kaynak), ThreatModelValidationError fırlatıldığı doğrulanır.
        """
        hatali_model = dict(self.gecerli_model)
        hatali_akislar = [dict(a) for a in self.gecerli_model["veri_akislari"]]
        # DF1'in kaynağı sistemde olmayan 'HAYALET_USER' yapılıyor
        hatali_akislar[0]["kaynak"] = "HAYALET_USER"
        hatali_model["veri_akislari"] = hatali_akislar

        modeler = ThreatModeler(hatali_model, katilik_modu=True)
        with self.assertRaises(ThreatModelValidationError) as context:
            modeler.analiz_et()

        self.assertIn("Hayalet Kaynak Hatası", str(context.exception))

    def test_hayalet_hedef_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Bir veri akışının hedefi bileşenler arasında tanımlı
        olmadığında sistemin hata ürettiği doğrulanır.
        """
        hatali_model = dict(self.gecerli_model)
        hatali_akislar = [dict(a) for a in self.gecerli_model["veri_akislari"]]
        hatali_akislar[1]["hedef"] = "HAYALET_VERITABANI"
        hatali_model["veri_akislari"] = hatali_akislar

        modeler = ThreatModeler(hatali_model, katilik_modu=True)
        with self.assertRaises(ThreatModelValidationError) as context:
            modeler.analiz_et()

        self.assertIn("Hayalet Hedef Hatası", str(context.exception))

    def test_tanimsiz_guven_siniri_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Veri akışı tanımlanmamış bir güven sınırından (örn: TB99)
        geçtiğini iddia ederse, sistemin bunu geçersiz kabul ettiği test edilir.
        """
        hatali_model = dict(self.gecerli_model)
        hatali_akislar = [dict(a) for a in self.gecerli_model["veri_akislari"]]
        hatali_akislar[2]["gecilen_sinir"] = "TB99_TANIMSIZ"
        hatali_model["veri_akislari"] = hatali_akislar

        modeler = ThreatModeler(hatali_model, katilik_modu=True)
        with self.assertRaises(ThreatModelValidationError) as context:
            modeler.analiz_et()

        self.assertIn("Tanımsız Sınır Geçişi", str(context.exception))

    def test_gecersiz_stride_kategorisi_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Standart STRIDE dışında uydurma bir kategori (örn: 'ALIEN_ATTACK')
        verildiğinde sistemin doğrulama hatası fırlattığı teyit edilir.
        """
        hatali_model = dict(self.gecerli_model)
        hatali_tehditler = [dict(t) for t in self.gecerli_model["tehditler"]]
        hatali_tehditler[0]["kategori"] = "BUYU_SALDIRISI"
        hatali_model["tehditler"] = hatali_tehditler

        modeler = ThreatModeler(hatali_model, katilik_modu=True)
        with self.assertRaises(ThreatModelValidationError) as context:
            modeler.analiz_et()

        self.assertIn("Geçersiz STRIDE Kategorisi", str(context.exception))

    def test_korumasiz_guven_siniri_gecisi_negatif_kontrol(self):
        """
        MİMARİ GÜVENLİK KURALI: İnternet veya Disk gibi yüksek riskli bir güven sınırını
        geçen veri akışında şifreleme (TLS/AES) yoksa, sistem bunu 'KRİTİK MİMARİ KUSUR'
        olarak raporlamalıdır.
        """
        guvensiz_model = dict(self.gecerli_model)
        guvensiz_akislar = [dict(a) for a in self.gecerli_model["veri_akislari"]]
        # DF4 (İnternet bulut senkronizasyonu) kontrollerinden TLS kaldırılıyor
        guvensiz_akislar[3]["kontroller"] = ["Düz Metin HTTP", "Sıkıştırma"]
        guvensiz_model["veri_akislari"] = guvensiz_akislar

        modeler = ThreatModeler(guvensiz_model, katilik_modu=True)
        sonuc = modeler.analiz_et()

        # Doğrulama geçer ancak bulgularda mimari kusur raporlanmalıdır
        self.assertEqual(sonuc["durum"], "GECERLI")
        self.assertGreater(sonuc["bulgu_sayisi"], 0)
        bulgu = sonuc["guvenlik_bulgulari"][0]
        self.assertEqual(bulgu["seviye"], "KRİTİK MİMARİ KUSUR")
        self.assertIn("DF4", bulgu["id"])

    def test_mitigasyonsuz_acik_tehdit_negatif_kontrol(self):
        """
        TEHDİT YÖNETİMİ KURALI: Bir tehdit tanımlanmış ancak kontrolü boş bırakılmışsa
        veya durumu 'ENGEL_ALTI' yapılmamışsa, 'AÇIK TEHDİT (UNMITIGATED)' uyarısı verilmelidir.
        """
        acik_model = dict(self.gecerli_model)
        acik_tehditler = [dict(t) for t in self.gecerli_model["tehditler"]]
        # TH-01 kontrolü siliniyor
        acik_tehditler[0]["kontrol_aciklama"] = ""
        acik_tehditler[0]["durum"] = "ACIKTA"
        acik_model["tehditler"] = acik_tehditler

        modeler = ThreatModeler(acik_model, katilik_modu=True)
        sonuc = modeler.analiz_et()

        self.assertGreater(sonuc["bulgu_sayisi"], 0)
        bulgu = [b for b in sonuc["guvenlik_bulgulari"] if "UNMITIGATED" in b["seviye"]]
        self.assertGreater(len(bulgu), 0)
        self.assertIn("TH-01", bulgu[0]["id"])

    def test_mukerrer_bilesen_id_negatif_kontrol(self):
        """
        NEGATİF KONTROL: İki farklı bileşene aynı 'id' verilmesi durumunda
        mükerrer kimlik hatası fırlatıldığı doğrulanır.
        """
        hatali_model = dict(self.gecerli_model)
        hatali_bilesenler = [dict(b) for b in self.gecerli_model["bilesenler"]]
        hatali_bilesenler[1]["id"] = "E1"  # P1 yerine mükerrer E1
        hatali_model["bilesenler"] = hatali_bilesenler

        modeler = ThreatModeler(hatali_model, katilik_modu=True)
        with self.assertRaises(ThreatModelValidationError) as context:
            modeler.analiz_et()

        self.assertIn("Mükerrer Bileşen ID", str(context.exception))

    def test_esnek_mod_hata_toplama(self):
        """
        ESNEK MOD: katilik_modu=False iken program çökmeksizin hataların
        bir liste olarak toplandığı doğrulanır.
        """
        kirik_model = {"uygulama_adi": "Bozuk"}
        modeler = ThreatModeler(kirik_model, katilik_modu=False)
        gecerli, hatalar = modeler.dogrula()

        self.assertFalse(gecerli)
        self.assertGreater(len(hatalar), 0)

    def test_ascii_dfd_semasi_ve_stride_dagilimi(self):
        """
        GÖRSEL ÇIKTI KONTROLÜ: ascii_dfd_ciz() metodunun akış diyagramını,
        güven sınırlarını ve STRIDE özetini eksiksiz bastığı test edilir.
        """
        modeler = ThreatModeler(self.gecerli_model, katilik_modu=True)
        sema = modeler.ascii_dfd_ciz()

        self.assertIn("VERİ AKIŞ DİYAGRAMI", sema)
        self.assertIn("GÜVEN SINIRI: TB1", sema)
        self.assertIn("GÜVEN SINIRI: TB2", sema)
        self.assertIn("STRIDE TEHDİT KAPSAMI", sema)


# Testler doğrudan çağrıldığında çalıştırılır
if __name__ == "__main__":
    unittest.main(verbosity=2)
