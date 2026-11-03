# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 015: İkili Gösterim, Bayt Düzeyi ve Karakter Kodlaması Denetçisi (Binary & Byte Encoding Inspector)
Usta-Çırak Siber Güvenlik Akademisi Laboratuvar Otomasyon Aracı

Bu modül; bit, bayt, onaltılık (hex) gösterim ve karakter kodlaması (ASCII, UTF-8, UTF-16) mekanizmalarını
inceler; karakter sayısı ile bayt uzunluğu arasındaki boyutsal uyumsuzlukları, Null Byte (\x00) enjeksiyonunu,
Homoglyph/IDN aldatmaca saldırılarını ve 'Yönetici iznini otomatik olarak güvenli davranış saymak' ölümcül
yanılgısını donanım ve işletim sistemi çekirdeği seviyesinde denetler.
"""

import os  # Dosya ve işletim sistemi yol operasyonları için standart kütüphane
import sys  # Sistem argümanları ve standart çıkış akışları için
import json  # Yapılandırma ve test verilerini serileştirmek için
import argparse  # Profesyonel komut satırı arayüzü (CLI) parametreleri için
import unicodedata  # Unicode karakter sınıflandırması ve homoglyph analizi için
from typing import Dict, List, Any, Optional, Tuple  # Katı tip güvenliği ve statik doğrulama için


# --- ÖZEL İSTİSNA SINIFLARI (CUSTOM EXCEPTIONS) ---

class EncodingInspectorError(Exception):
    """Karakter kodlama ve bayt denetim motorunun temel ata istisna sınıfı."""
    pass


class NullByteDetectedError(EncodingInspectorError):
    """Metin içinde C tabanlı sonlandırma zafiyeti yaratan Null Byte (\\x00) tespit edildiğinde fırlatılır."""
    pass


class MalformedByteSequenceError(EncodingInspectorError):
    """Geçersiz veya bayt sınırında parçalanmış çok baytlı UTF-8 dizilimi oluştuğunda fırlatılır."""
    pass


# --- ÇEKİRDEK KARAKTER VE BAYT ANALİZ SINIFI ---

class BinaryByteEncodingInspector:
    """
    Metinleri ve ikili bayt dizilimlerini güvenlik perspektifinden inceleyen motor.
    """

    def __init__(self, veri_tabani_yolu: Optional[str] = None):
        # Örnek veri tabanı yolu atanır
        self.veri_tabani_yolu = veri_tabani_yolu
        # Bellekte tutulacak örnekler sözlüğü başlatılır
        self.ornekler: Dict[str, Dict[str, Any]] = {}
        if veri_tabani_yolu:
            self.veri_tabani_yukle(veri_tabani_yolu)

    def veri_tabani_yukle(self, veri_tabani_yolu: str) -> None:
        """
        JSON tabanlı kodlama örnekleri veri tabanını doğrular ve belleğe yükler.
        """
        if not os.path.exists(veri_tabani_yolu):
            raise FileNotFoundError(f"Veri tabanı dosyası bulunamadı: {veri_tabani_yolu}")

        with open(veri_tabani_yolu, "r", encoding="utf-8") as f:
            veri = json.load(f)

        if "kodlama_ornekleri" not in veri:
            raise EncodingInspectorError("Geçersiz şema: 'kodlama_ornekleri' listesi eksik.")

        self.ornekler = {o["ornek_id"]: o for o in veri["kodlama_ornekleri"]}

    def karakter_ayrintilari(self, metin: str) -> List[Dict[str, Any]]:
        """
        Girdideki her karakterin Unicode Code Point, UTF-8 baytları ve ikili (binary) bit dizilimini çıkarır.
        """
        ayrintilar = []
        for ch in metin:
            # Karakterin UTF-8 bayt temsili alınır
            utf8_baytlar = ch.encode("utf-8")
            # Karakterin onaltılık (hex) dökümü hazırlanır
            hex_str = " ".join(f"{b:02X}" for b in utf8_baytlar)
            # Karakterin 8-bit ikili (binary) dökümü hazırlanır
            bin_str = " ".join(f"{b:08b}" for b in utf8_baytlar)
            # Unicode kod noktası (Örn: U+0041 veya U+015E)
            code_point = f"U+{ord(ch):04X}"
            # Unicode resmi adı (tanımsız veya kontrol karakteriyse güvenli döndürülür)
            try:
                ad = unicodedata.name(ch)
            except ValueError:
                ad = "CONTROL_OR_UNNAMED_CHARACTER"

            ayrintilar.append({
                "karakter": repr(ch) if ord(ch) < 32 or ord(ch) == 127 else ch,
                "code_point": code_point,
                "unicode_adi": ad,
                "bayt_sayisi": len(utf8_baytlar),
                "hex_baytlar": hex_str,
                "ikili_bitler": bin_str
            })
        return ayrintilar

    def hex_dump_olustur(self, baytlar: bytes, genislik: int = 16) -> str:
        """
        Girdi baytları için xxd/hexdump formatında standart profesyonel döküm üretir.
        Ofset | Hex Değerleri (16 bayt) | ASCII Karşılığı
        """
        satirlar = []
        for ofset in range(0, len(baytlar), genislik):
            parca = baytlar[ofset:ofset + genislik]
            hex_kismi = " ".join(f"{b:02x}" for b in parca)
            # 16 bayttan kısa ise hizalama boşluğu eklenir
            if len(parca) < genislik:
                hex_kismi = hex_kismi.ljust(genislik * 3 - 1)
            # Okunabilir ASCII karakterler basılır, diğerleri nokta (.) yapılır
            ascii_kismi = "".join(chr(b) if 32 <= b <= 126 else "." for b in parca)
            satirlar.append(f"{ofset:08x}: {hex_kismi}  |{ascii_kismi}|")
        return "\n".join(satirlar)

    def guvenlik_denetimi_yap(self, metin: str, yonetici_hakki_var_mi: bool = False) -> Dict[str, Any]:
        """
        Metin girdisini 5 kritik güvenlik ve kodlama kriterine göre denetler:
        1. Null Byte (\x00) Enjeksiyonu (C-String Sonlandırma Açığı) -> FELAKET (-40 Puan)
        2. Karakter Sayısı vs Bayt Uzunluğu Genişlemesi (Buffer Overflow Riski) -> ORTA/YÜKSEK (-15 Puan)
        3. Homoglyph / Karışık Alfabe Aldatmacası (Kiril/Latin Spoofing) -> YÜKSEK (-25 Puan)
        4. Overlong / Gizli Dizin Geçişi (Path Traversal: ../) -> KRİTİK (-30 Puan)
        5. 'Yönetici İznini Otomatik Olarak Güvenli Sayma' Yanılgısı -> KRİTİK UYARI
        """
        puan = 100
        bulgular = []
        karakter_sayisi = len(metin)
        utf8_baytlar = metin.encode("utf-8")
        bayt_sayisi = len(utf8_baytlar)

        # 1. KONTROL: NULL BYTE (\x00) ENJEKSİYONU
        if "\x00" in metin:
            ceza = 40
            puan -= ceza
            bulgular.append({
                "kod": "VULN-01-NULL-BYTE-INJECTION",
                "seviye": "FELAKET",
                "ceza": ceza,
                "baslik": "Null Byte (\\x00) Enjeksiyonu Tespit Edildi",
                "aciklama": "Girdi içinde C sonlandırıcı (\\x00) bulundu! C/C++ tabanlı arka uçlarda dosya uzantısı denetimlerini atlatabilir."
            })

        # 2. KONTROL: BOYUTSAL GENİŞLEME VE TAMPON TAŞMASI (BUFFER OVERFLOW) RİSKİ
        if bayt_sayisi > karakter_sayisi:
            fark = bayt_sayisi - karakter_sayisi
            ceza = 15
            puan -= ceza
            bulgular.append({
                "kod": "WARN-02-MULTIBYTE-EXPANSION",
                "seviye": "YUKSEK",
                "ceza": ceza,
                "baslik": f"Çok Baytlı Karakter Genişlemesi (+{fark} bayt fazlalık)",
                "aciklama": f"Karakter sayısı ({karakter_sayisi}) bayt boyutundan ({bayt_sayisi} bayt) küçüktür. "
                            f"Yalnızca karakter sayısına göre tahsis edilen sabit tampon belleklerde (char buffer[N]) bellek taşmasına yol açar!"
            })

        # 3. KONTROL: HOMOGLYPH / IDN ALDATMACA KONTROLÜ
        # Kiril (Cyrillic) ve Latin alfabesinin aynı kelimede karışık kullanımı
        alfabeler = set()
        for ch in metin:
            if ch.isalpha():
                ad = unicodedata.name(ch, "")
                if "LATIN" in ad:
                    alfabeler.add("LATIN")
                elif "CYRILLIC" in ad:
                    alfabeler.add("CYRILLIC")
                elif "GREEK" in ad:
                    alfabeler.add("GREEK")

        if len(alfabeler) > 1:
            ceza = 25
            puan -= ceza
            bulgular.append({
                "kod": "VULN-03-HOMOGLYPH-SPOOFING",
                "seviye": "YUKSEK",
                "ceza": ceza,
                "baslik": f"Homoglyph / Karışık Alfabe Tespiti: {', '.join(alfabeler)}",
                "aciklama": "Girdi görsel olarak standart Latin görünürken arka planda Kiril/Yunan harfleri barındırıyor (IDN Spoofing / Phishing)."
            })

        # 4. KONTROL: GİZLİ DİZİN GEÇİŞİ (PATH TRAVERSAL SİNYALLERİ)
        if ".." in metin or "%2e%2e" in metin.lower() or "%c0%af" in metin.lower():
            ceza = 30
            puan -= ceza
            bulgular.append({
                "kod": "VULN-04-PATH-TRAVERSAL-ENCODING",
                "seviye": "KRITIK",
                "ceza": ceza,
                "baslik": "Kodlanmış Dizin Geçişi (Path Traversal) Sinyali",
                "aciklama": "Metinde '../' veya kodlanmış overlong dizin geçiş göstergeleri tespit edildi."
            })

        # 5. KONTROL: YÖNETİCİ İZNİNİ OTOMATİK GÜVENLİ SAYMA YANILGISI
        # Kullanıcı admin olsa bile geçersiz bayt dizilimi veya null byte sistemi çökertebilir
        if yonetici_hakki_var_mi and len(bulgular) > 0:
            bulgular.append({
                "kod": "FALLACY-05-ADMIN-PRIVILEGE-FALLACY",
                "seviye": "YONETISIM_HATASI",
                "ceza": 0,
                "baslik": "Ölümcül Hata: Yönetici İznini Otomatik Güvenli Davranış Saymak",
                "aciklama": "İşlem 'Root / Administrator' yetkisiyle çalıştırılsa dahi, girdi düzeyindeki bayt manipülasyonu "
                            "ve bellek taşması zafiyeti yetkiden bağımsız olarak sistemi istismar edilebilir kılar!"
            })

        puan = max(0, min(100, puan))
        durum = "GUVENLI" if puan >= 80 else ("UYARI" if puan >= 50 else "TEHLIKELI")

        return {
            "metin_ozeti": metin[:40] + ("..." if len(metin) > 40 else ""),
            "karakter_sayisi": karakter_sayisi,
            "bayt_sayisi_utf8": bayt_sayisi,
            "denetim_puani": puan,
            "durum": durum,
            "bulgu_sayisi": len(bulgular),
            "bulgular": bulgular
        }

    def tampon_kesilme_simulasyonu(self, metin: str, max_bayt_limiti: int) -> Dict[str, Any]:
        """
        Metin bayt cinsinden sabit bir tampon belleğe kesildiğinde (truncation)
        çok baytlı karakterlerin ortasından parçalanıp parçalanmadığını simüle eder.
        """
        ham_baytlar = metin.encode("utf-8")
        if len(ham_baytlar) <= max_bayt_limiti:
            return {
                "kesilme_oldu_mu": False,
                "parcalanmis_bayt_var_mi": False,
                "orijinal_bayt": len(ham_baytlar),
                "kesilen_bayt": len(ham_baytlar),
                "sonuc_metin": metin
            }

        # Naif bir C programı gibi tam max_bayt_limiti noktasından kesilir
        kesilmis_baytlar = ham_baytlar[:max_bayt_limiti]
        parcalanmis = False
        try:
            # UTF-8 olarak çözülmeye çalışılır
            cozulen_metin = kesilmis_baytlar.decode("utf-8")
        except UnicodeDecodeError:
            parcalanmis = True
            # Hata veren son baytı yutarak veya replacement karakteri ile çözer
            cozulen_metin = kesilmis_baytlar.decode("utf-8", errors="replace")

        return {
            "kesilme_oldu_mu": True,
            "parcalanmis_bayt_var_mi": parcalanmis,
            "orijinal_bayt": len(ham_baytlar),
            "kesilen_bayt": len(kesilmis_baytlar),
            "sonuc_metin": cozulen_metin,
            "tehlike_aciklamasi": "Çok baytlı bir karakterin ortasından kesildiğinde bozuk bayt (\\ufffd) veya veri kaybı oluşur!" if parcalanmis else "Kesilme güvenli bayt sınırında gerçekleşti."
        }


# --- KOMUT SATIRI ARAYÜZÜ (CLI) ---

def main():
    """CLI giriş noktası ve parametre işleyicisi."""
    parser = argparse.ArgumentParser(
        description="GÜN 015: İkili Gösterim, Bayt ve Karakter Kodlaması Denetçisi",
        epilog="ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)"
    )
    parser.add_argument("--veri-tabani", type=str, default="ornek_veri/karakter_kodlama_ornekleri.json", help="Örnek veritabanı yolu")
    parser.add_argument("--ornek-id", type=str, default="SAMPLE-01-ASCII-STANDARD", help="İncelenecek örnek kimliği")
    parser.add_argument("--metin", type=str, help="Doğrudan incelenecek metin girdisi")
    parser.add_argument("--hex-dump", action="store_true", help="Metnin Hex Dump çıktısını göster")
    parser.add_argument("--denetle", action="store_true", help="Güvenlik ve kodlama denetimi çalıştır")
    parser.add_argument("--tumunu-denetle", action="store_true", help="Tüm örnekleri topluca denetle")
    parser.add_argument("--yonetici-hakki", action="store_true", help="İşlemin yönetici haklarıyla çalıştığını simüle et")
    parser.add_argument("--cikis-json", type=str, help="Sonuçları JSON dosyasına kaydet")

    args = parser.parse_args()

    inspector = BinaryByteEncodingInspector(args.veri_tabani)
    sonuc = {}

    if args.tumunu_denetle:
        print("[*] Tüm Karakter Kodlama Örnekleri Denetleniyor...")
        raporlar = []
        for o_id, ornek in inspector.ornekler.items():
            res = inspector.guvenlik_denetimi_yap(ornek["ham_metin"], args.yonetici_hakki)
            raporlar.append({"ornek_id": o_id, "analiz": res})
            print(f"    - Örnek: {o_id} -> Skor: {res['denetim_puani']} | Durum: {res['durum']} | Bulgular: {res['bulgu_sayisi']}")
        sonuc = {"tum_ornek_denetimleri": raporlar}

    elif args.metin:
        print(f"[*] Özel Metin İnceleniyor: '{args.metin}'")
        sonuc = inspector.guvenlik_denetimi_yap(args.metin, args.yonetici_hakki)
        print(f"[+] Karakter Sayısı: {sonuc['karakter_sayisi']} | UTF-8 Bayt Boyutu: {sonuc['bayt_sayisi_utf8']}")
        print(f"[+] Denetim Skoru: {sonuc['denetim_puani']} / 100 ({sonuc['durum']})")
        if args.hex_dump:
            print("\n[+] Hex Dump Çıktısı:")
            print(inspector.hex_dump_olustur(args.metin.encode("utf-8")))

    else:
        # Belirtilen ornek-id incelenir
        ornek = inspector.ornekler.get(args.ornek_id)
        if not ornek:
            print(f"[-] Hata: Tanımsız örnek kimliği: {args.ornek_id}")
            sys.exit(1)
        print(f"[*] Örnek İnceleniyor: {args.ornek_id} ({ornek['baslik']})")
        sonuc = inspector.guvenlik_denetimi_yap(ornek["ham_metin"], args.yonetici_hakki)
        print(f"[+] Karakter Sayısı: {sonuc['karakter_sayisi']} | UTF-8 Bayt Boyutu: {sonuc['bayt_sayisi_utf8']}")
        print(f"[+] Denetim Skoru: {sonuc['denetim_puani']} / 100 ({sonuc['durum']})")
        for b in sonuc["bulgular"]:
            print(f"    - [{b['seviye']}] {b['baslik']} (-{b['ceza']}p)")
        if args.hex_dump:
            print("\n[+] Hex Dump Çıktısı:")
            print(inspector.hex_dump_olustur(ornek["ham_metin"].encode("utf-8")))

    if args.cikis_json:
        with open(args.cikis_json, "w", encoding="utf-8") as f:
            json.dump(sonuc, f, indent=2, ensure_ascii=False)
        print(f"[+] Sonuçlar dosyaya kaydedildi: {args.cikis_json}")


if __name__ == "__main__":
    main()
