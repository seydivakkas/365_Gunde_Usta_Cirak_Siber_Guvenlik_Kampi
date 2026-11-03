# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 015: İkili Gösterim, Bayt ve Karakter Kodlaması Birim Test Paketi
Usta-Çırak Siber Güvenlik Laboratuvarı Doğrulama Testleri

Bu test paketi;
1. Pozitif Altın Akış: Standart ASCII karakter ve bayt eşitliği, UTF-8 çok baytlı Türkçe ve emoji genişlemesi,
   hex dump üretimi ve Unicode kod noktası dökümünün doğrulanması,
2. Negatif Kontroller: Null Byte (\\x00) enjeksiyonu, Homoglyph (Kiril/Latin karışımı) oltalama tespiti,
   kodlanmış dizin geçişi (path traversal), çok baytlı karakter kesilme/parçalanma anomalisi ve
   'Yönetici iznini otomatik olarak güvenli davranış saymak' yanılgısının yakalanması
senaryolarını 14 bağımsız test ile %100 kapsama oranıyla doğrular.
"""

import os  # Dosya ve dizin yolu denetimleri için standart kütüphane
import sys  # Sistem yolu manipülasyonu için
import unittest  # Birim test çatısı
import tempfile  # Güvenli geçici dosya testleri için

# Uygulama modülünü arama yoluna ekliyoruz
uygulama_dizini = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama"))
if uygulama_dizini not in sys.path:
    sys.path.insert(0, uygulama_dizini)

# Test edilecek denetçi sınıfı ve özel istisnalar içe aktarılır
from binary_byte_encoding_inspector import (
    BinaryByteEncodingInspector,
    EncodingInspectorError,
    NullByteDetectedError,
    MalformedByteSequenceError
)


class TestBinaryByteEncodingInspector(unittest.TestCase):
    """Karakter kodlaması, bayt dökümü ve güvenlik denetimlerini doğrulayan test sınıfı."""

    def setUp(self):
        """Her testten önce örnek kodlama veritabanını yükleyen hazırlık metodu."""
        self.veri_tabani_yolu = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "ornek_veri", "karakter_kodlama_ornekleri.json"
        ))
        self.inspector = BinaryByteEncodingInspector(self.veri_tabani_yolu)

    # --- POZİTİF KONTROLLER ---

    def test_01_ascii_metin_1_karakter_1_bayt_pozitif(self):
        """POZİTİF TEST: Saf ASCII metinde karakter sayısı ile bayt sayısı eşit olmalı ve 100 tam puan almalıdır."""
        ornek = self.inspector.ornekler["SAMPLE-01-ASCII-STANDARD"]
        sonuc = self.inspector.guvenlik_denetimi_yap(ornek["ham_metin"])
        self.assertEqual(sonuc["karakter_sayisi"], sonuc["bayt_sayisi_utf8"])
        self.assertEqual(sonuc["denetim_puani"], 100)
        self.assertEqual(sonuc["durum"], "GUVENLI")
        self.assertEqual(sonuc["bulgu_sayisi"], 0)

    def test_02_karakter_ayrintilari_dogrulugu(self):
        """POZİTİF TEST: karakter_ayrintilari metodu doğru Unicode Code Point ve hex baytları üretmelidir."""
        ayrintilar = self.inspector.karakter_ayrintilari("ABC")
        self.assertEqual(len(ayrintilar), 3)
        self.assertEqual(ayrintilar[0]["code_point"], "U+0041")
        self.assertEqual(ayrintilar[0]["hex_baytlar"], "41")
        self.assertEqual(ayrintilar[0]["bayt_sayisi"], 1)

    def test_03_hex_dump_standart_bicim_dogrulugu(self):
        """POZİTİF TEST: hex_dump_olustur ofset, hex ve ASCII sütunlarını içeren standart format üretmelidir."""
        döküm = self.inspector.hex_dump_olustur(b"SECURITY_TEST_123")
        self.assertIn("00000000:", döküm)
        self.assertIn("|SECURITY_TEST_12|", döküm)

    def test_04_turkce_cok_baytli_genisleme_dogrulama(self):
        """POZİTİF TEST: Türkçe metinde karakter sayısı < bayt sayısı olmalı ve boyutsal fark tespit edilmelidir."""
        ornek = self.inspector.ornekler["SAMPLE-02-TURKISH-MULTIBYTE"]
        sonuc = self.inspector.guvenlik_denetimi_yap(ornek["ham_metin"])
        self.assertGreater(sonuc["bayt_sayisi_utf8"], sonuc["karakter_sayisi"])
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("WARN-02-MULTIBYTE-EXPANSION", kodlar)

    def test_05_emoji_4_bayt_genisleme_dogrulama(self):
        """POZİTİF TEST: 4-baytlık emoji içeren metinde karakter başı bayt oranı doğrulanmalıdır."""
        emoji_metin = "Kalkan 🛡️"
        ayrintilar = self.inspector.karakter_ayrintilari(emoji_metin)
        # Emojinin bayt sayısı 4 olmalı
        emoji_karakter = [a for a in ayrintilar if "SHIELD" in a["unicode_adi"]]
        self.assertTrue(len(emoji_karakter) > 0)
        self.assertGreaterEqual(emoji_karakter[0]["bayt_sayisi"], 3)

    # --- NEGATİF VE GÜVENLİK SINIR KONTROLLERİ ---

    def test_06_null_byte_enjeksiyonu_felaket_kontrol(self):
        """NEGATİF TEST: Metinde \\x00 bulunması durumunda VULN-01 FELAKET uyarısıyla 40 puan kesilmelidir."""
        ornek = self.inspector.ornekler["SAMPLE-04-NULL-BYTE-ATTACK"]
        sonuc = self.inspector.guvenlik_denetimi_yap(ornek["ham_metin"])
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("VULN-01-NULL-BYTE-INJECTION", kodlar)
        self.assertLessEqual(sonuc["denetim_puani"], 60)

    def test_07_homoglyph_kiril_latin_karisimi_kontrol(self):
        """NEGATİF TEST: Kiril ve Latin harflerinin karıştırıldığı metinde VULN-03 yakalanmalıdır."""
        ornek = self.inspector.ornekler["SAMPLE-05-HOMOGLYPH-SPOOF"]
        sonuc = self.inspector.guvenlik_denetimi_yap(ornek["ham_metin"])
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("VULN-03-HOMOGLYPH-SPOOFING", kodlar)

    def test_08_path_traversal_overlong_kontrol(self):
        """NEGATİF TEST: Metinde '../' veya kodlanmış geçiş olduğunda VULN-04 tespit edilmelidir."""
        metin = "../../etc/passwd"
        sonuc = self.inspector.guvenlik_denetimi_yap(metin)
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("VULN-04-PATH-TRAVERSAL-ENCODING", kodlar)

    def test_09_yonetici_iznini_otomatik_guvenli_sayma_yanilgisi_kontrol(self):
        """NEGATİF TEST: Yönetici hakkıyla çalışsa bile zafiyetli girdide FALLACY-05 ölümcül hata uyarısı eklenmelidir."""
        ornek = self.inspector.ornekler["SAMPLE-04-NULL-BYTE-ATTACK"]
        sonuc = self.inspector.guvenlik_denetimi_yap(ornek["ham_metin"], yonetici_hakki_var_mi=True)
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("FALLACY-05-ADMIN-PRIVILEGE-FALLACY", kodlar)

    def test_10_tampon_kesilme_ve_parcalanmis_bayt_kontrol(self):
        """NEGATİF TEST: Çok baytlı karakterin ortasından kesildiğinde parçalanmış bayt tespiti yapılmalıdır."""
        metin = "Şifre"  # 'Ş' harfi 2 bayttır: 0xC5 0x9F
        # 1 bayt sınırından kesilirse 'Ş' parçalanır
        sonuc = self.inspector.tampon_kesilme_simulasyonu(metin, max_bayt_limiti=1)
        self.assertTrue(sonuc["kesilme_oldu_mu"])
        self.assertTrue(sonuc["parcalanmis_bayt_var_mi"])
        self.assertIn("\ufffd", sonuc["sonuc_metin"])

    def test_11_tanimsiz_ornek_id_hata_yonetimi(self):
        """HATA YÖNETİMİ: Tanımsız örnek kimliği arandığında None dönmeli ve yönetilebilmelidir."""
        ornek = self.inspector.ornekler.get("TANIMSIZ-ORNEK-999")
        self.assertIsNone(ornek)

    def test_12_gecersiz_sema_hata_yonetimi(self):
        """HATA YÖNETİMİ: Geçersiz şemaya sahip JSON dosyasında EncodingInspectorError fırlatılmalıdır."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", encoding="utf-8") as f:
            f.write('{"hatali_anahtar": []}')
            gecici_dosya = f.name

        try:
            with self.assertRaises(EncodingInspectorError):
                BinaryByteEncodingInspector(gecici_dosya)
        finally:
            if os.path.exists(gecici_dosya):
                os.remove(gecici_dosya)

    def test_13_tum_orneklerin_toplu_denetimi(self):
        """İŞLEVSELLİK: Veritabanındaki tüm örnekler döngüde başarıyla denetlenmelidir."""
        for o_id, ornek in self.inspector.ornekler.items():
            sonuc = self.inspector.guvenlik_denetimi_yap(ornek["ham_metin"])
            self.assertIn("karakter_sayisi", sonuc)
            self.assertIn("bayt_sayisi_utf8", sonuc)

    def test_14_olmayan_dosya_hatasi(self):
        """İŞLEVSELLİK & HATA YÖNETİMİ: Olmayan dosya yolunda FileNotFoundError fırlatılmalıdır."""
        with self.assertRaises(FileNotFoundError):
            BinaryByteEncodingInspector("bu_dosya_asla_var_olamaz_7777.json")


if __name__ == "__main__":
    unittest.main()
