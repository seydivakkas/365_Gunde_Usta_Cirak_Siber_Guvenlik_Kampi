# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 013: Güvenli Araştırma ve Kaynak Doğrulama Birim Test Paketi
Usta-Çırak Siber Güvenlik Laboratuvarı Doğrulama Testleri

Bu test paketi;
1. Pozitif Altın Akış: NVD/MSRC resmî bültenlerinin ve CIS Benchmark standartlarının doğrulanması,
2. Çapraz Teyit (Triangulation): İki farklı kaynağın karşılaştırılarak resmî olanın seçilmesi,
3. Negatif Kontroller: Truva Atı içeren sahte PoC istismarları, eskiyen (2011) forum gönderileri,
   kriptografik imza eksikliği, 'chmod 777' gibi yıkıcı tavsiyeler ve sınır ihlalleri
senaryolarını 14 bağımsız test ile %100 kapsama oranıyla doğrular.
"""

import os  # Dosya ve dizin yolu denetimleri için standart kütüphane
import sys  # Sistem yolu manipülasyonu için
import unittest  # Birim test çatısı

# Uygulama dizinini arama yoluna dahil ediyoruz
uygulama_dizini = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama"))
if uygulama_dizini not in sys.path:
    sys.path.insert(0, uygulama_dizini)

# Test edilecek yönetici motor ve özel istisnalar içe aktarılır
from security_source_validator import (
    SecuritySourceValidator,
    SourceValidatorError,
    MaliciousSourceDetectedError,
    IncompatibleTriangulationError
)


class TestSecuritySourceValidator(unittest.TestCase):
    """Güvenli araştırma, kaynak doğrulama ve CRAAP testlerini doğrulayan test sınıfı."""

    def setUp(self):
        """Her testten önce sentetik kaynak veri tabanını yükleyen hazırlık metodu."""
        self.veri_tabani_yolu = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "ornek_veri", "guvenlik_arastirma_kaynaklari.json"
        ))
        # Doğrulama motoru başlatılır
        self.validator = SecuritySourceValidator(self.veri_tabani_yolu)

    # --- POZİTİF KONTROLLER ---

    def test_01_resmi_birincil_kaynak_yuksek_puan(self):
        """POZİTİF TEST: Resmî NVD ve üretici MSRC bülteni en az 90 CRAAP puanı almalı ve GUVENILIR_ONAYLI olmalıdır."""
        vaka = self.validator.vakalar["VAKA-CVE-RCE-01"]
        resmi_kaynak = vaka["kaynaklar"][0]  # SRC-NVD-OFFICIAL
        analiz = self.validator.craap_skoru_hesapla(resmi_kaynak)
        self.assertGreaterEqual(analiz["craap_skoru"], 90)
        self.assertEqual(analiz["durum"], "GUVENILIR_ONAYLI")
        self.assertEqual(analiz["kirmizi_bayrak_sayisi"], 0)

    def test_02_cis_benchmark_kurumsal_standart_onay(self):
        """POZİTİF TEST: CIS Benchmark belgesi en az 90 puan almalı ve tam otorite onayına sahip olmalıdır."""
        vaka = self.validator.vakalar["VAKA-LINUX-HARDENING-02"]
        cis_kaynak = vaka["kaynaklar"][0]  # SRC-CIS-BENCHMARK
        analiz = self.validator.craap_skoru_hesapla(cis_kaynak)
        self.assertGreaterEqual(analiz["craap_skoru"], 90)
        self.assertEqual(analiz["durum"], "GUVENILIR_ONAYLI")

    def test_03_capraz_kaynak_karsilastirma_vaka_01_onay(self):
        """POZİTİF TEST: VAKA-01 için çapraz karşılaştırmada NVD onaylanmalı, sahte GitHub PoC reddedilmelidir."""
        karar = self.validator.capraz_kaynak_karsilastir("VAKA-CVE-RCE-01")
        self.assertEqual(karar["nihai_karar"], "KAYNAK_A_ONAYLANDI__KAYNAK_B_REDDEDILDI")
        self.assertEqual(karar["onaylanan_kaynak"]["kaynak_id"], "SRC-NVD-OFFICIAL")
        self.assertEqual(karar["reddedilen_veya_zayif_kaynak"]["kaynak_id"], "SRC-GITHUB-ANON-POC")
        self.assertGreaterEqual(karar["guvenilirlik_farki"], 40)

    def test_04_capraz_kaynak_karsilastirma_vaka_02_onay(self):
        """POZİTİF TEST: VAKA-02 için çapraz karşılaştırmada CIS Benchmark onaylanmalı, forum yazısı reddedilmelidir."""
        karar = self.validator.capraz_kaynak_karsilastir("VAKA-LINUX-HARDENING-02")
        self.assertEqual(karar["nihai_karar"], "KAYNAK_A_ONAYLANDI__KAYNAK_B_REDDEDILDI")
        self.assertEqual(karar["onaylanan_kaynak"]["kaynak_id"], "SRC-CIS-BENCHMARK")
        self.assertEqual(karar["reddedilen_veya_zayif_kaynak"]["kaynak_id"], "SRC-LEGACY-FORUM-POST")

    # --- NEGATİF VE GÜVENLİK SINIR KONTROLLERİ ---

    def test_05_zehirli_poc_truva_ati_tespiti(self):
        """NEGATİF TEST: Anonim GitHub deposundaki zararlı yük (curl | sh) FLAG-04 ile FELAKET olarak yakalanmalıdır."""
        vaka = self.validator.vakalar["VAKA-CVE-RCE-01"]
        poc_kaynak = vaka["kaynaklar"][1]  # SRC-GITHUB-ANON-POC
        analiz = self.validator.craap_skoru_hesapla(poc_kaynak)
        kodlar = [b["kod"] for b in analiz["kirmizi_bayraklar"]]
        self.assertIn("FLAG-04-ZEHIRLI-POC-TRUVA-ATI", kodlar)
        self.assertEqual(analiz["durum"], "GUVENSIZ_REDDEDILDI")

    def test_06_yikici_guvenlik_tavsiyesi_chmod777_tespiti(self):
        """NEGATİF TEST: Eski forumdaki 'chmod 777' tavsiyesi FLAG-05 ile FELAKET seviyesinde yakalanmalıdır."""
        vaka = self.validator.vakalar["VAKA-LINUX-HARDENING-02"]
        forum_kaynak = vaka["kaynaklar"][1]  # SRC-LEGACY-FORUM-POST
        analiz = self.validator.craap_skoru_hesapla(forum_kaynak)
        kodlar = [b["kod"] for b in analiz["kirmizi_bayraklar"]]
        self.assertIn("FLAG-05-YIKICI-GUVENLIK-TAVSIYESI", kodlar)
        self.assertLess(analiz["craap_skoru"], 50)

    def test_07_eski_kaynak_tarih_asimi_tespiti(self):
        """NEGATİF TEST: 5 yıldan eski (2011 tarihli) içerikte FLAG-01-ESKI-KAYNAK bayrağı açılmalıdır."""
        vaka = self.validator.vakalar["VAKA-LINUX-HARDENING-02"]
        forum_kaynak = vaka["kaynaklar"][1]
        analiz = self.validator.craap_skoru_hesapla(forum_kaynak)
        kodlar = [b["kod"] for b in analiz["kirmizi_bayraklar"]]
        self.assertIn("FLAG-01-ESKI-KAYNAK", kodlar)

    def test_08_kriptografik_butunluk_eksikligi_tespiti(self):
        """NEGATİF TEST: GPG veya SHA-256 doğrulaması olmayan kaynakta FLAG-03 bayrağı tetiklenmelidir."""
        vaka = self.validator.vakalar["VAKA-CVE-RCE-01"]
        poc_kaynak = vaka["kaynaklar"][1]
        analiz = self.validator.craap_skoru_hesapla(poc_kaynak)
        kodlar = [b["kod"] for b in analiz["kirmizi_bayraklar"]]
        self.assertIn("FLAG-03-KRIPTO-BUTUNLUK-YOK", kodlar)

    def test_09_otoritesiz_anonim_kaynak_tespiti(self):
        """NEGATİF TEST: Anonim profilli kaynakta FLAG-02-OTORITESIZ-KAYNAK bayrağı yakalanmalıdır."""
        vaka = self.validator.vakalar["VAKA-CVE-RCE-01"]
        poc_kaynak = vaka["kaynaklar"][1]
        analiz = self.validator.craap_skoru_hesapla(poc_kaynak)
        kodlar = [b["kod"] for b in analiz["kirmizi_bayraklar"]]
        self.assertIn("FLAG-02-OTORITESIZ-KAYNAK", kodlar)

    def test_10_tek_kaynak_ile_capraz_teyit_hatasi(self):
        """HATA YÖNETİMİ: Tek bir kaynağa sahip vaka ile çapraz teyit denenirse IncompatibleTriangulationError verilmelidir."""
        # Geçici tek kaynaklı vaka enjekte edilir
        self.validator.vakalar["VAKA-TEK-KAYNAK"] = {
            "vaka_id": "VAKA-TEK-KAYNAK",
            "vaka_konusu": "Yetersiz Kaynak Testi",
            "kaynaklar": [{"kaynak_id": "K1", "kaynak_adi": "Tek Kaynak", "yayin_tarihi": "2026-01-01"}]
        }
        with self.assertRaises(IncompatibleTriangulationError):
            self.validator.capraz_kaynak_karsilastir("VAKA-TEK-KAYNAK")

    def test_11_tanimsiz_vaka_hata_yonetimi(self):
        """HATA YÖNETİMİ: Tanımsız vaka kimliği sorgulandığında SourceValidatorError fırlatılmalıdır."""
        with self.assertRaises(SourceValidatorError):
            self.validator.capraz_kaynak_karsilastir("OLMAYAN-HAYALET-VAKA")

    def test_12_tarihi_belirsiz_kaynak_puan_kirilmasi(self):
        """HATA YÖNETİMİ: Yayın tarihi olmayan sentetik kaynakta FLAG-01-TARIH-YOK cezası kesilmelidir."""
        sentetik_kaynak = {
            "kaynak_id": "SRC-NO-DATE",
            "kaynak_adi": "Tarihsiz Makale",
            "alan_adi_guvenilirligi": "UST_DUZEY_DEVLET_URETICI",
            "kriptografik_dogrulama": {"sha256_saglanmis_mi": True, "gpg_imzali_mi": True}
        }
        analiz = self.validator.craap_skoru_hesapla(sentetik_kaynak)
        kodlar = [b["kod"] for b in analiz["kirmizi_bayraklar"]]
        self.assertIn("FLAG-01-TARIH-YOK", kodlar)

    def test_13_tum_vakalar_icin_karsilastirma_dongusu(self):
        """İŞLEVSELLİK: Veri tabanındaki tüm vakalar başarıyla işlenmeli ve liste dönmelidir."""
        for v_id in self.validator.vakalar:
            karar = self.validator.capraz_kaynak_karsilastir(v_id)
            self.assertIn("onaylanan_kaynak", karar)
            self.assertIn("reddedilen_veya_zayif_kaynak", karar)

    def test_14_olmayan_veri_tabani_dosya_hatasi(self):
        """İŞLEVSELLİK & HATA YÖNETİMİ: Olmayan dosya yolunda FileNotFoundError fırlatılmalıdır."""
        with self.assertRaises(FileNotFoundError):
            SecuritySourceValidator("bu_dosya_asla_var_olamaz_9999.json")


if __name__ == "__main__":
    unittest.main()
