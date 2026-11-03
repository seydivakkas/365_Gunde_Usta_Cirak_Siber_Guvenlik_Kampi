#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

NIST Cybersecurity Framework (CSF) 2.0 Olgunluk ve Denge Değerlendiricisi
-------------------------------------------------------------------------
Bu araç, bir kurumun siber güvenlik duruşunu NIST CSF 2.0 standardında tanımlanan
6 ana işlev (Govern, Identify, Protect, Detect, Respond, Recover) üzerinden analiz eder.
Tek bir fonksiyona aşırı odaklanıp diğerlerini kör bırakan 'Savunma Yanılsaması'nı
(Protect-Bias) matematiksel ve mantıksal kurallarla tespit eder.
"""

# Standart kütüphane modülleri içe aktarılıyor (Dış bağımlılık gerektirmez)
import sys          # Sistem çıkış kodları ve akış yönlendirmesi için
import json         # JSON formatındaki matris verisini ayrıştırmak ve dışa aktarmak için
import argparse     # Komut satırı argümanlarını (CLI) profesyonelce yönetmek için
from pathlib import Path  # Dosya yollarını işletim sisteminden bağımsız güvenle işlemek için
from typing import Dict, Any, List, Tuple, Optional  # Katı tip denetimi (Type Hints) için

# NIST CSF 2.0 standardında tanımlanan zorunlu 6 ana işlev kodu ve tam isimleri
# 2.0 sürümü ile 'GOVERN' (Yönetişim) en başa eklenerek yönetim katmanı mimariye dahil edilmiştir.
ZORUNLU_ISLEVLER: Dict[str, str] = {
    "GOVERN": "Yönetişim (Strateji, Liderlik, Tedarik Zinciri ve Politika)",
    "IDENTIFY": "Tanımlama (Varlık Yönetimi, Tehdit ve Risk Analizi)",
    "PROTECT": "Koruma (Erişim Kontrolü, Veri Güvenliği, Sıkılaştırma)",
    "DETECT": "Tespit (Sürekli İzleme, Anomali ve Tehdit Keşfi)",
    "RESPOND": "Müdahale (Olay Yönetimi, İzolasyon, Triyaj ve Analiz)",
    "RECOVER": "Kurtarma (Geri Yükleme, Süreklilik ve Paydaş İletişimi)"
}

# NIST CSF Aşamaları (Tiers) - Olgunluk Puan Aralıkları
# Kurumun süreçlerinin ne kadar oturmuş ve dinamik olduğunu gösterir
TIER_TANIMLARI: List[Tuple[int, int, str, str]] = [
    (0, 49, "Tier 1 - Partial (Kısmi/Düzensiz)", "Süreçler plansız, reaktif ve kişilere bağımlıdır."),
    (50, 69, "Tier 2 - Risk Informed (Risk Bilinçli)", "Risk farkındalığı var ancak kurumsal süreçler bütünleşik değildir."),
    (70, 84, "Tier 3 - Repeatable (Tekrarlanabilir/Kurumsal)", "Kurumsal politikalar standartlaşmış ve periyodik denetlenmektedir."),
    (85, 100, "Tier 4 - Adaptive (Uyarlanabilir/Dinamik)", "Gelişmiş tehditlere karşı sürekli öğrenen, yapay zeka ve otomasyon destekli yapı.")
]


class NistCsfValidationError(Exception):
    """NIST CSF matris doğrulama hatalarını temsil eden özel istisna sınıfı."""
    pass


class NistCsfEvaluator:
    """
    NIST CSF 2.0 çerçevesine göre bir organizasyonun siber güvenlik duruşunu,
    fonksiyonel dengesini ve kritik kör noktalarını değerlendiren motor sınıfı.
    """

    def __init__(self, matris_verisi: Dict[str, Any], katilik_modu: bool = True):
        """
        Değerlendiriciyi başlatır ve girdiyi hafızaya alır.

        :param matris_verisi: Analiz edilecek JSON sözlük yapısı
        :param katilik_modu: Eksik fonksiyon veya hatalı puanlarda istisna fırlatılıp fırlatılmayacağı
        """
        # Girdi verisi özel değişkende saklanır
        self.veri: Dict[str, Any] = matris_verisi
        # Katılık modu aktifse standart ihlallerinde program hata üretir
        self.katilik_modu: bool = katilik_modu
        # Hesaplanmış sonuçların önbelleği
        self.analiz_sonucu: Optional[Dict[str, Any]] = None

    def dogrula(self) -> Tuple[bool, List[str]]:
        """
        Matrisin NIST CSF 2.0 kurallarına tam uyumluluğunu denetler.
        Negatif Kontrol Mekanizması: 6 temel işlevden biri bile eksikse veya
        puanlar 0-100 aralığı dışında ise geçersiz sayılır.

        :return: (GecerliMi: bool, HataMesajlari: List[str])
        """
        hatalar: List[str] = []

        # 1. Kontrol: 'fonksiyonlar' ana anahtarının varlığı
        if "fonksiyonlar" not in self.veri or not isinstance(self.veri["fonksiyonlar"], dict):
            hatalar.append("Kritik Hata: Matris kök dizininde 'fonksiyonlar' sözlüğü bulunamadı.")
            if self.katilik_modu:
                raise NistCsfValidationError(hatalar[-1])
            return False, hatalar

        fonksiyonlar = self.veri["fonksiyonlar"]

        # 2. Kontrol: NIST CSF 2.0'deki 6 zorunlu işlevin eksiksiz mevcudiyeti
        for islev, aciklama in ZORUNLU_ISLEVLER.items():
            if islev not in fonksiyonlar:
                # Bir işlev eksikse savunma zinciri kırıktır (Örn: RECOVER yoksa fidye yazılımında iflas kaçınılmazdır)
                hata = f"Eksik İşlev Hatası: '{islev}' ({aciklama}) fonksiyonu matriste tanımlanmamış!"
                hatalar.append(hata)

        # 3. Kontrol: Her bir işlevin kategorileri ve puanlarının geçerliliği
        for islev_adi, islev_detay in fonksiyonlar.items():
            # Fonksiyonun altındaki 'kategoriler' anahtarı kontrol ediliyor
            if not isinstance(islev_detay, dict) or "kategoriler" not in islev_detay:
                hatalar.append(f"Yapısal Hata: '{islev_adi}' işlevi altında geçerli 'kategoriler' alanı yok.")
                continue

            kategoriler = islev_detay.get("kategoriler", {})
            if not isinstance(kategoriler, dict) or len(kategoriler) == 0:
                hatalar.append(f"Kategori Eksikliği: '{islev_adi}' işlevi altında hiçbir kategori tanımlanmamış.")
                continue

            # Her bir alt kategorinin puanı matematiksel olarak 0 ile 100 arasında olmalıdır
            for kat_kodu, kat_bilgi in kategoriler.items():
                if not isinstance(kat_bilgi, dict):
                    hatalar.append(f"Tip Hatası: '{islev_adi}.{kat_kodu}' geçerli bir kategori nesnesi değil.")
                    continue

                puan = kat_bilgi.get("olgunluk_puani")
                if puan is None or not isinstance(puan, (int, float)):
                    hatalar.append(f"Puan Hatası: '{islev_adi}.{kat_kodu}' için sayısal 'olgunluk_puani' bulunamadı.")
                elif puan < 0 or puan > 100:
                    hatalar.append(f"Sınır Aşımı Hatası: '{islev_adi}.{kat_kodu}' puanı ({puan}) 0-100 aralığında olmalıdır.")

        # Katılık modu açıksa ve hata varsa ilk hatayla süreci durdur
        if hatalar and self.katilik_modu:
            raise NistCsfValidationError("\n".join(hatalar))

        # Hata listesi boşsa matris geçerlidir
        return (len(hatalar) == 0), hatalar

    def hesapla(self) -> Dict[str, Any]:
        """
        Her bir fonksiyonun ortalama olgunluk puanını, genel güvenlik duruşunu
        ve olgunluk aşamasını (Tier) hesaplar.
        """
        # Önce doğrulama çalıştırılır
        gecerli, hatalar = self.dogrula()
        if not gecerli:
            return {"durum": "GECERSIZ", "hatalar": hatalar}

        fonksiyonlar = self.veri["fonksiyonlar"]
        islev_puanlari: Dict[str, float] = {}
        kategori_ozetleri: Dict[str, List[Dict[str, Any]]] = {}

        # Her fonksiyon için alt kategorilerin aritmetik ortalaması alınır
        for islev_kodu in ZORUNLU_ISLEVLER.keys():
            islev_obj = fonksiyonlar.get(islev_kodu, {})
            kategoriler = islev_obj.get("kategoriler", {})

            toplam_puan = 0.0
            kat_listesi: List[Dict[str, Any]] = []

            for k_kodu, k_veri in kategoriler.items():
                p = float(k_veri.get("olgunluk_puani", 0))
                toplam_puan += p
                kat_listesi.append({
                    "kod": k_kodu,
                    "ad": k_veri.get("ad", "Bilinmeyen Kategori"),
                    "puan": p,
                    "kanit": k_veri.get("kanit", "Kanıt sunulmadı")
                })

            kat_sayisi = len(kategoriler)
            ort_puan = round(toplam_puan / kat_sayisi, 2) if kat_sayisi > 0 else 0.0
            islev_puanlari[islev_kodu] = ort_puan
            kategori_ozetleri[islev_kodu] = kat_listesi

        # Kurumun Genel Güvenlik Puanı: 6 işlevin eşit ağırlıklı ortalaması
        genel_puan = round(sum(islev_puanlari.values()) / len(ZORUNLU_ISLEVLER), 2)

        # Genel puana karşılık gelen NIST CSF Seviyesi (Tier) belirlenir
        tier_adi = "Bilinmeyen Tier"
        tier_aciklama = ""
        for baslangic, bitis, t_ad, t_ack in TIER_TANIMLARI:
            if baslangic <= genel_puan <= bitis:
                tier_adi = t_ad
                tier_aciklama = t_ack
                break

        # 'Savunma Yanılsaması' (Protect Bias) Kontrolü
        # Bir kurum Protect'e 90 verip Detect veya Recover'ı 30'un altında bırakırsa bu 'Yalancı Güven' tuzağıdır
        protect_puani = islev_puanlari.get("PROTECT", 0.0)
        detect_puani = islev_puanlari.get("DETECT", 0.0)
        respond_puani = islev_puanlari.get("RESPOND", 0.0)
        recover_puani = islev_puanlari.get("RECOVER", 0.0)

        yanilsama_uyarisi = False
        yanilsama_detay = []

        if protect_puani >= 70.0:
            if detect_puani < 50.0:
                yanilsama_uyarisi = True
                yanilsama_detay.append(f"Kritik Dengesizlik: Protect ({protect_puani}) yüksek iken Detect ({detect_puani}) çok zayıf! Duvar örülmüş ancak içeri sızan saldırganı izleyecek göz yok.")
            if respond_puani < 50.0:
                yanilsama_uyarisi = True
                yanilsama_detay.append(f"Kritik Dengesizlik: Protect ({protect_puani}) yüksek iken Respond ({respond_puani}) çok zayıf! Sızma olduğunda nasıl müdahale edileceği belirsiz.")
            if recover_puani < 50.0:
                yanilsama_uyarisi = True
                yanilsama_detay.append(f"Kritik Dengesizlik: Protect ({protect_puani}) yüksek iken Recover ({recover_puani}) çok zayıf! Olası bir fidye yazılımında sistemler ayağa kaldırılamaz.")

        # Zayıf alan analizi (Puanı 70'in altında kalan tüm kategoriler öncelikli iyileştirme listesine alınır)
        iyilestirme_gerekenler = []
        for islev_kodu, kat_listesi in kategori_ozetleri.items():
            for kat in kat_listesi:
                if kat["puan"] < 75.0:
                    iyilestirme_gerekenler.append({
                        "islev": islev_kodu,
                        "kod": kat["kod"],
                        "ad": kat["ad"],
                        "puan": kat["puan"]
                    })

        # Puanı en düşük olanlar en başa gelecek şekilde sıralanır
        iyilestirme_gerekenler.sort(key=lambda x: x["puan"])

        # Sonuç sözlüğü derlenir
        self.analiz_sonucu = {
            "durum": "GECERLI",
            "kurum_adi": self.veri.get("kurum_adi", "Bilinmeyen Kurum"),
            "degerlendirme_tarihi": self.veri.get("degerlendirme_tarihi", "2026-10-26"),
            "genel_puan": genel_puan,
            "olgunluk_seviyesi": tier_adi,
            "olgunluk_aciklamasi": tier_aciklama,
            "islev_puanlari": islev_puanlari,
            "protect_bias_var_mi": yanilsama_uyarisi,
            "protect_bias_uyarilari": yanilsama_detay,
            "iyilestirme_gereken_alanlar": iyilestirme_gerekenler,
            "kategori_detaylari": kategori_ozetleri
        }

        return self.analiz_sonucu

    def ascii_radar_ciz(self) -> str:
        """
        NIST CSF 2.0'nin 6 işlev puanını görselleştiren yatay bir çubuk grafik üretir.
        Görsel çıktı analistin duruş dengesini tek bakışta algılamasını sağlar.
        """
        if not self.analiz_sonucu:
            self.hesapla()

        satirlar: List[str] = []
        satirlar.append("================================================================================")
        satirlar.append(f"  NIST CSF 2.0 OLGUNLUK RADARI: {self.analiz_sonucu.get('kurum_adi', '')}")
        satirlar.append(f"  Genel Puan: {self.analiz_sonucu.get('genel_puan', 0.0)} / 100  [{self.analiz_sonucu.get('olgunluk_seviyesi', '')}]")
        satirlar.append("================================================================================")

        puanlar = self.analiz_sonucu.get("islev_puanlari", {})
        # Her bir işlev için 40 karakter genişliğinde görsel bar çizilir
        for islev, puan in puanlar.items():
            dolu_karakter_sayisi = int(puan / 2.5)  # 100 puan = 40 karakter
            bar = "█" * dolu_karakter_sayisi + "░" * (40 - dolu_karakter_sayisi)
            islev_etiketi = f"{islev:<8}"
            satirlar.append(f"  {islev_etiketi} [{bar}] {puan:>6.2f}%")

        satirlar.append("--------------------------------------------------------------------------------")
        if self.analiz_sonucu.get("protect_bias_var_mi"):
            satirlar.append("  [!] DİKKAT: 'Savunma Yanılsaması' (Protect Bias) Tespit Edildi!")
            for u in self.analiz_sonucu.get("protect_bias_uyarilari", []):
                satirlar.append(f"      * {u}")
        else:
            satirlar.append("  [+] DENGELİ SAVUNMA: Altı işlev arasında kritik bir oransızlık saptanmadı.")
        satirlar.append("================================================================================")

        return "\n".join(satirlar)

    def ozet_rapor_olustur(self) -> str:
        """Metin tabanlı ayrıntılı denetim raporu üretir."""
        if not self.analiz_sonucu:
            self.hesapla()

        radar = self.ascii_radar_ciz()
        satirlar = [radar, ""]
        satirlar.append("--- ÖNCELİKLİ İYİLEŞTİRME VE EKSİKLİK ANALİZİ (GAP ANALYSIS) ---")

        eksikler = self.analiz_sonucu.get("iyilestirme_gereken_alanlar", [])
        if not eksikler:
            satirlar.append("Tüm kategoriler hedeflenen 75 puan eşiğinin üzerindedir. Olgunluk düzeyi mükemmel.")
        else:
            satirlar.append(f"Toplam {len(eksikler)} kategoride gelişim gerekmektedir (Öncelik Sırasıyla):")
            for idx, e in enumerate(eksikler, start=1):
                satirlar.append(f"  {idx}. [{e['islev']}] {e['kod']} - {e['ad']} -> Puan: {e['puan']}/100")

        return "\n".join(satirlar)


def main() -> int:
    """CLI Giriş Noktası."""
    # Argüman ayrıştırıcı yapılandırılıyor
    parser = argparse.ArgumentParser(
        description="NIST CSF 2.0 Güvenlik Matrisi Olgunluk ve Denge Analiz Aracı",
        epilog="Örnek kullanım: python nist_csf_evaluator.py --matris ornek_veri/nist_csf_matrisi.json --format text"
    )

    # Parametre tanımları
    parser.add_argument(
        "--matris", "-m",
        required=True,
        type=str,
        help="Değerlendirilecek NIST CSF 2.0 JSON matris dosyasının yolu"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Çıktı formatı (text: insan okuyabilir görsel rapor, json: makine okuyabilir çıktı)"
    )
    parser.add_argument(
        "--cikis", "-o",
        type=str,
        default=None,
        help="Analiz sonucunun kaydedileceği dosya yolu (Belirtilmezse konsola basılır)"
    )
    parser.add_argument(
        "--esnek",
        action="store_true",
        help="Hatalarda programı durdurmak yerine hata listesini raporda raporla"
    )

    args = parser.parse_args()

    # Dosya yolu doğrulanıyor
    matris_yolu = Path(args.matris)
    if not matris_yolu.is_file():
        sys.stderr.write(f"Hata: Belirtilen matris dosyası bulunamadı: {matris_yolu}\n")
        return 1

    # JSON verisi okunuyor
    try:
        with open(matris_yolu, "r", encoding="utf-8") as f:
            veri = json.load(f)
    except Exception as e:
        sys.stderr.write(f"JSON Okuma Hatası: {e}\n")
        return 2

    # Değerlendirici nesnesi ayağa kaldırılıyor
    evaluator = NistCsfEvaluator(veri, katilik_modu=(not args.esnek))

    try:
        sonuc = evaluator.hesapla()
    except NistCsfValidationError as ve:
        sys.stderr.write(f"NIST CSF Doğrulama Hatası:\n{ve}\n")
        return 3

    # İstenen formatta çıktı hazırlanıyor
    if args.format == "json":
        cikti_metni = json.dumps(sonuc, ensure_ascii=False, indent=2)
    else:
        cikti_metni = evaluator.ozet_rapor_olustur()

    # Konsola veya dosyaya yazdırma işlemi
    if args.cikis:
        cikis_yolu = Path(args.cikis)
        cikis_yolu.parent.mkdir(parents=True, exist_ok=True)
        with open(cikis_yolu, "w", encoding="utf-8") as f:
            f.write(cikti_metni)
        print(f"Rapor başarıyla kaydedildi: {cikis_yolu}")
    else:
        # Windows konsolunda UTF-8 çıktı desteği garantiye alınıyor
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(cikti_metni)

    # Başarılı çıkış kodu
    return 0


# Betik doğrudan terminalden çağrıldığında çalışır
if __name__ == "__main__":
    sys.exit(main())
