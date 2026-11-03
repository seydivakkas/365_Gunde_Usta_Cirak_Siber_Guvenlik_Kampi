# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 014: Aşama 1 Kalite Özeti ve Güvenlik Temelleri Birim Test Paketi
Usta-Çırak Siber Güvenlik Laboratuvarı Doğrulama Testleri

Bu test paketi;
1. Pozitif Altın Akış: RoE, Varlık Envanteri, NIST CSF 2.0 (Govern, Identify, Protect, Detect,
   Respond, Recover), İzolasyon ve CRAAP standartlarına tam uyan laboratuvarın 100/100 ile kabulü,
2. Negatif Kontroller: Etik ihlal (yetkisiz dış ağ / üretim teması), eksik varlık envanteri,
   'Bir güvenlik önlemini tek başına eksiksiz savunma sanma' yanılgısı, eksik CSF işlevleri,
   doğrulanmamış kaynaklar ve sınır ihlalleri
senaryolarını 14 bağımsız test ile %100 kapsama oranıyla doğrular.
"""

import os  # Dosya ve dizin yolu denetimleri için standart kütüphane
import sys  # Sistem yolu manipülasyonu için
import unittest  # Birim test çatısı
import tempfile  # Geçici test dosyası oluşturma kütüphanesi

# Uygulama modülünü arama yoluna ekliyoruz
uygulama_dizini = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama"))
if uygulama_dizini not in sys.path:
    sys.path.insert(0, uygulama_dizini)

# Test edilecek denetçi sınıfı ve özel istisnalar içe aktarılır
from stage1_security_auditor import (
    Stage1SecurityAuditor,
    Stage1AuditError,
    EthicalBoundaryViolationError,
    SingleMeasureFallacyError,
    IncompleteChainOfEvidenceError
)


class TestStage1SecurityAuditor(unittest.TestCase):
    """Aşama 1 kalite özeti ve güvenlik temelleri kabul motorunu doğrulayan test sınıfı."""

    def setUp(self):
        """Her testten önce sentetik Aşama 1 laboratuvar dosyasını yükleyen hazırlık metodu."""
        self.dosya_yolu = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "ornek_veri", "asama_01_laboratuvar_dosyasi.json"
        ))
        # Denetim motoru başlatılır
        self.auditor = Stage1SecurityAuditor(self.dosya_yolu)

    # --- POZİTİF KONTROLLER ---

    def test_01_altin_proje_tam_kabul_pozitif_kontrol(self):
        """POZİTİF TEST: Altın laboratuvar projesi 100/100 tam puan almalı ve ASAMA_1_KABUL_PASS olmalıdır."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-GOLDEN-01")
        self.assertEqual(sonuc["denetim_puani"], 100.0)
        self.assertEqual(sonuc["durum"], "ASAMA_1_KABUL_PASS")
        self.assertTrue(sonuc["kabul_edildi_mi"])
        self.assertEqual(sonuc["bulgu_sayisi"], 0)

    def test_02_kanit_zinciri_butunlugu_pozitif_kontrol(self):
        """POZİTİF TEST: Kanıt zincirindeki tüm halkalar (RoE, Varlık, CSF, CRAAP) eksiksiz doğrulanmalıdır."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-GOLDEN-01")
        zincir = sonuc["kanit_zinciri"]
        self.assertIn("ONAYLI_KAPSAM", zincir["etik_roe"])
        self.assertIn("Varlık Kayıtlı", zincir["varlik_envanteri"])
        self.assertIn("Eksiksiz Tamamlandı", zincir["nist_csf_2_0"])
        self.assertIn("DOGRULANMIS", zincir["kaynak_dogrulama"])

    def test_03_csf_alti_islev_tam_uyumluluk_pozitif_kontrol(self):
        """POZİTİF TEST: Govern, Identify, Protect, Detect, Respond, Recover işlevlerinin tamamı aktif olmalıdır."""
        proje = self.auditor.projeler["LAB-SEC-GOLDEN-01"]
        csf = proje["nist_csf_2_0_uyumluluk"]
        for islev in ["govern_yonetisim", "identify_tanimlama", "protect_koruma", "detect_tespit", "respond_mudahale", "recover_kurtarma"]:
            self.assertTrue(all(csf[islev].values()))

    def test_04_kriptografik_sertifika_deterministik_uretim(self):
        """POZİTİF TEST: Kabul sertifikası için 64 karakterli SHA-256 kriptografik özeti üretilmelidir."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-GOLDEN-01")
        hash_val = sonuc["kriptografik_sertifika_sha256"]
        self.assertEqual(len(hash_val), 64)
        # Deterministik tekrar hesaplama
        sonuc2 = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-GOLDEN-01")
        self.assertEqual(hash_val, sonuc2["kriptografik_sertifika_sha256"])

    # --- NEGATİF VE GÜVENLİK SINIR KONTROLLERİ ---

    def test_05_kusurlu_proje_etik_ve_kapsam_ihlali_kontrol(self):
        """NEGATİF TEST: Yazılı onaysız veya dış ağa temas eden projede CRIT-01 etik ihlali yakalanmalıdır."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-DEFECTIVE-99")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("CRIT-01-ETIK-ROE-IHLALI", kodlar)

    def test_06_tek_onleme_guvenme_yanilgisi_kontrol(self):
        """NEGATİF TEST: Sadece güvenlik duvarına güvenip kurtarma veya tespit planı yapmayan projede CRIT-04 yakalanmalıdır."""
        # Sentetik kusurlu proje: Protect var, Recover yok
        kusurlu_proje = {
            "proje_id": "LAB-TEST-SINGLE-MEASURE",
            "proje_basligi": "Yalnızca Firewall Olan Kusurlu Ortam",
            "etik_roe_kapsami": {"yazili_onay_var_mi": True, "uretim_sistem_etkilesimi": False, "dis_ag_erisim_izni": False, "hedef_ip_araligi": "192.168.1.0/24"},
            "varlik_envanteri_ve_siniflandirma": {"toplam_varlik_sayisi": 0, "sahip_ve_sorumlular_belirlenmis_mi": False},
            "nist_csf_2_0_uyumluluk": {
                "govern_yonetisim": {"k1": True},
                "identify_tanimlama": {"k1": False},
                "protect_koruma": {"k1": True},  # SADECE PROTECT VAR!
                "detect_tespit": {"k1": False},   # DETECT YOK!
                "respond_mudahale": {"k1": False},
                "recover_kurtarma": {"k1": False} # RECOVER YOK!
            },
            "kaynak_dogrulama": {"craap_skor_ortalamasi": 90.0, "resmi_nvd_ve_vendor_advisory_kullanimi": True}
        }
        self.auditor.projeler["LAB-TEST-SINGLE-MEASURE"] = kusurlu_proje
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-TEST-SINGLE-MEASURE")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("CRIT-04-TEK-ONLEME-GUVENME-YANILGISI", kodlar)

    def test_07_eksik_varlik_envanteri_kontrol(self):
        """NEGATİF TEST: Varlık envanteri tutulmayan projede WARN-02 uyarısı verilmelidir."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-DEFECTIVE-99")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("WARN-02-EKSIK-VARLIK-ENVANTERI", kodlar)

    def test_08_eksik_csf_islevleri_ceza_kontrol(self):
        """NEGATİF TEST: CSF işlevleri eksik olan projede WARN-03 ile işlev başına ceza kesilmelidir."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-DEFECTIVE-99")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("WARN-03-NIST-CSF-EKSIK-ISLEVLER", kodlar)

    def test_09_dogrulanmamis_kaynak_craap_kontrol(self):
        """NEGATİF TEST: CRAAP skoru düşük ve resmî bültensiz projede WARN-05 cezası verilmelidir."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-DEFECTIVE-99")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("WARN-05-DOGRULANMAMIS-KAYNAK-KULLANIMI", kodlar)

    def test_10_kusurlu_proje_red_karari_kontrol(self):
        """NEGATİF TEST: LAB-SEC-DEFECTIVE-99 projesinin kabul edilmediği doğrulanmalıdır."""
        sonuc = self.auditor.denetle_laboratuvar_projesi("LAB-SEC-DEFECTIVE-99")
        self.assertFalse(sonuc["kabul_edildi_mi"])
        self.assertIn(sonuc["durum"], ["REDDEDILDI_TEHLIKELI", "KOSULLU_TELAFİ"])
        self.assertLess(sonuc["denetim_puani"], 50.0)

    def test_11_tanimsiz_proje_kimligi_hata_yonetimi(self):
        """HATA YÖNETİMİ: Tanımsız proje sorgulandığında Stage1AuditError fırlatılmalıdır."""
        with self.assertRaises(Stage1AuditError):
            self.auditor.denetle_laboratuvar_projesi("TANIMSIZ-HAYALET-PROJE")

    def test_12_gecersiz_sema_hata_yonetimi(self):
        """HATA YÖNETİMİ: Geçersiz şemaya sahip JSON dosyasında Stage1AuditError fırlatılmalıdır."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as f:
            f.write('{"yanlis_anahtar": []}')
            gecici_dosya = f.name

        try:
            with self.assertRaises(Stage1AuditError):
                Stage1SecurityAuditor(gecici_dosya)
        finally:
            if os.path.exists(gecici_dosya):
                os.remove(gecici_dosya)

    def test_13_tum_projeleri_toplu_denetleme(self):
        """İŞLEVSELLİK: Tüm projeler döngüde başarıyla denetlenmeli ve rapor üretilmelidir."""
        for p_id in self.auditor.projeler:
            sonuc = self.auditor.denetle_laboratuvar_projesi(p_id)
            self.assertIn("denetim_puani", sonuc)
            self.assertIn("kabul_edildi_mi", sonuc)

    def test_14_olmayan_dosya_hatasi(self):
        """İŞLEVSELLİK & HATA YÖNETİMİ: Olmayan dosya yolunda FileNotFoundError fırlatılmalıdır."""
        with self.assertRaises(FileNotFoundError):
            Stage1SecurityAuditor("bu_dosya_asla_var_olamaz_5555.json")


if __name__ == "__main__":
    unittest.main()
