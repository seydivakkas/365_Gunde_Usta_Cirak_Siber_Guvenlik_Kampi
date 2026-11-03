#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

NIST CSF 2.0 Olgunluk Değerlendirici Birim Testleri
--------------------------------------------------
Bu test modülü, NIST CSF 2.0 değerlendirme motorunun pozitif kontrollerini (tam uyum),
negatif kontrollerini (eksik işlev, aşırı puan, Protect Bias yanılsaması) ve sınır değerlerini
baştan sona doğrular.
"""

# Standart kütüphaneler içe aktarılıyor
import unittest  # Birim test çerçevesi
import sys       # Sistem yolu düzenlemeleri için
from pathlib import Path  # Yol yönetimi için

# Uygulama modülünün yolu test ortamının PYTHONPATH'ine ekleniyor
# Böylece testler bağımsız dizinlerden çağrılsa bile modül sorunsuz yüklenir
uygulama_dizini = Path(__file__).resolve().parent.parent / "uygulama"
if str(uygulama_dizini) not in sys.path:
    sys.path.insert(0, str(uygulama_dizini))

# Test edilecek değerlendirici motor ve hata sınıfı içe aktarılıyor
from nist_csf_evaluator import NistCsfEvaluator, NistCsfValidationError


class TestNistCsfEvaluator(unittest.TestCase):
    """NIST CSF 2.0 Değerlendiricisi için kapsamlı test senaryoları."""

    def setUp(self):
        """
        Her testten önce çalışan hazırlık fonksiyonu.
        6 işlevi de içeren, hatasız, referans bir tam matris kurgular.
        """
        self.gecerli_matris = {
            "kurum_adi": "Test Finansal Sistemler A.Ş.",
            "degerlendirme_tarihi": "2026-10-26",
            "fonksiyonlar": {
                "GOVERN": {
                    "kategoriler": {
                        "GV.OC": {"ad": "Bağlam", "olgunluk_puani": 80},
                        "GV.RM": {"ad": "Risk Stratejisi", "olgunluk_puani": 80}
                    }
                },
                "IDENTIFY": {
                    "kategoriler": {
                        "ID.AM": {"ad": "Varlık Yönetimi", "olgunluk_puani": 70},
                        "ID.RA": {"ad": "Risk Değerlendirmesi", "olgunluk_puani": 70}
                    }
                },
                "PROTECT": {
                    "kategoriler": {
                        "PR.AA": {"ad": "Kimlik ve Erişim", "olgunluk_puani": 85},
                        "PR.DS": {"ad": "Veri Güvenliği", "olgunluk_puani": 85}
                    }
                },
                "DETECT": {
                    "kategoriler": {
                        "DE.CM": {"ad": "Sürekli İzleme", "olgunluk_puani": 75}
                    }
                },
                "RESPOND": {
                    "kategoriler": {
                        "RS.MA": {"ad": "Olay Yönetimi", "olgunluk_puani": 80}
                    }
                },
                "RECOVER": {
                    "kategoriler": {
                        "RC.RP": {"ad": "Kurtarma Planı", "olgunluk_puani": 70}
                    }
                }
            }
        }

    def test_tam_matris_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: 6 işlevi eksiksiz olan geçerli bir matrisin doğrulanması,
        hesaplanan puanların aritmetik doğruluğu ve beklenen Tier seviyesi test edilir.
        """
        evaluator = NistCsfEvaluator(self.gecerli_matris, katilik_modu=True)
        sonuc = evaluator.hesapla()

        # Doğrulama durumu 'GECERLI' olmalıdır
        self.assertEqual(sonuc["durum"], "GECERLI")
        # Genel puan: (80 + 70 + 85 + 75 + 80 + 70) / 6 = 460 / 6 = 76.67
        self.assertAlmostEqual(sonuc["genel_puan"], 76.67, places=1)
        # 70-84 puan aralığı Tier 3 - Repeatable olmalıdır
        self.assertIn("Tier 3", sonuc["olgunluk_seviyesi"])
        # Protect Bias olmamalıdır çünkü Detect/Respond/Recover puanları 70 ve üzeridir
        self.assertFalse(sonuc["protect_bias_var_mi"])

    def test_eksik_govern_negatif_kontrol(self):
        """
        NEGATİF KONTROL: NIST CSF 2.0 ile zorunlu kılınan 'GOVERN' (Yönetişim) işlevi
        matristen silindiğinde, değerlendiricinin NistCsfValidationError fırlattığı doğrulanır.
        """
        hatali_matris = dict(self.gecerli_matris)
        hatali_fonksiyonlar = dict(self.gecerli_matris["fonksiyonlar"])
        # GOVERN fonksiyonu kasıtlı olarak kaldırılıyor
        del hatali_fonksiyonlar["GOVERN"]
        hatali_matris["fonksiyonlar"] = hatali_fonksiyonlar

        evaluator = NistCsfEvaluator(hatali_matris, katilik_modu=True)
        # Hatanın kesin olarak fırlatıldığı teyit edilir
        with self.assertRaises(NistCsfValidationError) as context:
            evaluator.hesapla()

        self.assertIn("GOVERN", str(context.exception))

    def test_eksik_recover_negatif_kontrol(self):
        """
        NEGATİF KONTROL: 'RECOVER' (Kurtarma) işlevi eksik olduğunda sistemin hata vermesi
        test edilir. Kurtarma fonksiyonu olmayan bir güvenlik mimarisi kabul edilemez.
        """
        hatali_matris = dict(self.gecerli_matris)
        hatali_fonksiyonlar = dict(self.gecerli_matris["fonksiyonlar"])
        # RECOVER fonksiyonu kasıtlı olarak kaldırılıyor
        del hatali_fonksiyonlar["RECOVER"]
        hatali_matris["fonksiyonlar"] = hatali_fonksiyonlar

        evaluator = NistCsfEvaluator(hatali_matris, katilik_modu=True)
        with self.assertRaises(NistCsfValidationError) as context:
            evaluator.hesapla()

        self.assertIn("RECOVER", str(context.exception))

    def test_protect_bias_tespiti(self):
        """
        MİMARİ YANILGI TESTİ: Kurum sadece önleyici duvarlara (Protect=95) yatırım yapmış,
        ancak tespit ve izleme (Detect=25) ile kurtarmayı (Recover=20) ihmal etmişse,
        'protect_bias_var_mi' bayrağının True olması ve açıklayıcı uyarı üretmesi gerekir.
        """
        dengesiz_matris = dict(self.gecerli_matris)
        dengesiz_fonksiyonlar = dict(self.gecerli_matris["fonksiyonlar"])

        # Protect çok yüksek, Detect ve Recover çok düşük ayarlanıyor
        dengesiz_fonksiyonlar["PROTECT"] = {"kategoriler": {"PR.AA": {"olgunluk_puani": 95}}}
        dengesiz_fonksiyonlar["DETECT"] = {"kategoriler": {"DE.CM": {"olgunluk_puani": 25}}}
        dengesiz_fonksiyonlar["RECOVER"] = {"kategoriler": {"RC.RP": {"olgunluk_puani": 20}}}
        dengesiz_matris["fonksiyonlar"] = dengesiz_fonksiyonlar

        evaluator = NistCsfEvaluator(dengesiz_matris, katilik_modu=True)
        sonuc = evaluator.hesapla()

        # Savunma yanılsaması (Protect Bias) bayrağı kalkmalıdır
        self.assertTrue(sonuc["protect_bias_var_mi"])
        # Uyarı mesajları içinde 'Detect' ve 'Recover' yetersizliği açıkça belirtilmelidir
        uyarilar_metni = " ".join(sonuc["protect_bias_uyarilari"])
        self.assertIn("Detect", uyarilar_metni)
        self.assertIn("Recover", uyarilar_metni)

    def test_gecersiz_puan_araligi_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Olgunluk puanı olarak mantıksız bir değer (örn: 150 veya -10)
        girildiğinde doğrulayıcının NistCsfValidationError fırlattığı doğrulanır.
        """
        hatali_matris = dict(self.gecerli_matris)
        hatali_fonksiyonlar = dict(self.gecerli_matris["fonksiyonlar"])
        hatali_fonksiyonlar["PROTECT"] = {
            "kategoriler": {"PR.AA": {"olgunluk_puani": 150}}  # 100'den büyük geçersiz puan
        }
        hatali_matris["fonksiyonlar"] = hatali_fonksiyonlar

        evaluator = NistCsfEvaluator(hatali_matris, katilik_modu=True)
        with self.assertRaises(NistCsfValidationError):
            evaluator.hesapla()

    def test_bos_kategori_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Bir fonksiyonun altında hiç alt kategori tanımlanmadığında
        sistemin geçersiz veri hatası vermesi teyit edilir.
        """
        hatali_matris = dict(self.gecerli_matris)
        hatali_fonksiyonlar = dict(self.gecerli_matris["fonksiyonlar"])
        hatali_fonksiyonlar["IDENTIFY"] = {"kategoriler": {}}  # Boş kategori
        hatali_matris["fonksiyonlar"] = hatali_fonksiyonlar

        evaluator = NistCsfEvaluator(hatali_matris, katilik_modu=True)
        with self.assertRaises(NistCsfValidationError):
            evaluator.hesapla()

    def test_esnek_mod_hata_toplama(self):
        """
        ESNEK MOD KONTROLÜ: katilik_modu=False olduğunda istisna fırlatılmamalı,
        ancak dogrula() fonksiyonu (False, [hata_listesi]) dönmelidir.
        """
        hatali_matris = {"kurum": "Hatalı Yapı"}  # 'fonksiyonlar' kök anahtarı yok
        evaluator = NistCsfEvaluator(hatali_matris, katilik_modu=False)
        gecerli, hatalar = evaluator.dogrula()

        self.assertFalse(gecerli)
        self.assertGreater(len(hatalar), 0)

    def test_ascii_radar_ve_rapor_cikisi(self):
        """
        GÖRSEL ÇIKTI KONTROLÜ: ascii_radar_ciz() ve ozet_rapor_olustur()
        metotlarının okunabilir karakter blokları ve başlıklar ürettiği test edilir.
        """
        evaluator = NistCsfEvaluator(self.gecerli_matris, katilik_modu=True)
        radar_cikti = evaluator.ascii_radar_ciz()
        rapor_cikti = evaluator.ozet_rapor_olustur()

        # Radarda işlev kısaltmaları ve blok karakterler yer almalıdır
        self.assertIn("GOVERN", radar_cikti)
        self.assertIn("RECOVER", radar_cikti)
        self.assertIn("█", radar_cikti)
        # Raporda Gap Analysis başlığı bulunmalıdır
        self.assertIn("GAP ANALYSIS", rapor_cikti)

    def test_tier_seviye_eslemeleri(self):
        """
        SINIR DEĞER KONTROLÜ: Puanların ilgili Tier aralıklarıyla doğru eşleştiği kontrol edilir.
        Tier 1: < 50, Tier 2: 50-69, Tier 3: 70-84, Tier 4: >= 85
        """
        # Düşük puanlı matris (Tier 1)
        dusuk_matris = dict(self.gecerli_matris)
        dusuk_fonksiyonlar = {
            f: {"kategoriler": {"K1": {"olgunluk_puani": 30}}}
            for f in ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
        }
        dusuk_matris["fonksiyonlar"] = dusuk_fonksiyonlar
        sonuc_dusuk = NistCsfEvaluator(dusuk_matris).hesapla()
        self.assertIn("Tier 1", sonuc_dusuk["olgunluk_seviyesi"])

        # En üst seviye matris (Tier 4)
        ust_matris = dict(self.gecerli_matris)
        ust_fonksiyonlar = {
            f: {"kategoriler": {"K1": {"olgunluk_puani": 95}}}
            for f in ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
        }
        ust_matris["fonksiyonlar"] = ust_fonksiyonlar
        sonuc_ust = NistCsfEvaluator(ust_matris).hesapla()
        self.assertIn("Tier 4", sonuc_ust["olgunluk_seviyesi"])


# Testler doğrudan çağrıldığında çalıştırılır
if __name__ == "__main__":
    unittest.main(verbosity=2)
