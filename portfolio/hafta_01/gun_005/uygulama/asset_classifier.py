#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

Varlık Envanteri, Sahiplik ve Veri Sınıflandırma Değerlendiricisi
----------------------------------------------------------------
Bu araç, bir kurumun siber varlıklarını (Cihaz, Uygulama, Kimlik, Veri) envanter altına alır;
veri sınıflandırma seviyelerini (Kamuya Açık, Dahili, Gizli, Çok Gizli/Sır) denetler;
'Sahipsiz Varlık' (Orphan Asset / Shadow IT) açıklarını tespit eder ve
'Donanım Parasal Değeri ile Gerçek İş Kritikliği Arasındaki Ayrımı' matematiksel olarak ortaya koyar.
"""

# Standart kütüphane modülleri (Dış bağımlılık gerektirmez)
import sys          # Standart girdi/çıktı ve çıkış kodları için
import json         # JSON formatlı envanter verilerini işlemek için
import argparse     # Komut satırı arayüzü (CLI) parametreleri için
from pathlib import Path  # Güvenli ve işletim sisteminden bağımsız dosya yolları için
from typing import Dict, Any, List, Tuple, Optional  # Tip güvenliği ve okunabilirlik için

# İzin verilen standart varlık türleri (NIST SP 800-53 & ISO 27001 A.8.1)
GECERLI_VARLIK_TURLERI = {"VERI", "UYGULAMA", "CIHAZ", "KIMLIK", "AG"}

# 4 Katmanlı Kurumsal Veri Sınıflandırma Standardı (Düşükten Yükseğe)
VERI_SINIFLARI = {
    "KAMUYA_ACIK": {"seviye": 1, "tanim": "İfşa olması kuruma zarar vermeyen, halka açık veriler."},
    "DAHILI": {"seviye": 2, "tanim": "Yalnızca kurum çalışanlarının erişebileceği operasyonel veriler."},
    "GIZLI": {"seviye": 3, "tanim": "Yetkisiz erişimi kuruma finansal veya itibar kaybı yaşatacak hassas veriler (Ticari sır, kaynak kod)."},
    "COK_GIZLI_SIR": {"seviye": 4, "tanim": "İfşası yasal yaptırım, iflas veya ulusal güvenlik riski doğuracak veriler (Kredi kartları, PII, biyometri)."}
}

# Varlık Kritiklik Seviyeleri ve Ağırlık Katsayıları
KRITIKLIK_SEVIYELERI = {
    "DUSUK": 1,
    "ORTA": 2,
    "YUKSEK": 3,
    "KRITIK": 4
}


class AssetValidationError(Exception):
    """Varlık doğrulama ve envanter bütünlüğü hatalarını temsil eden istisna sınıfı."""
    pass


class AssetClassifier:
    """
    Kurumsal varlık envanterini denetleyen, sahipsiz sistemleri keşfeden
    ve veri sınıflandırma uyumsuzluklarını analiz eden ana motor.
    """

    def __init__(self, envanter_verisi: Dict[str, Any], katilik_modu: bool = True):
        """
        Değerlendirici motoru başlatır.

        :param envanter_verisi: Ayrıştırılmış envanter JSON sözlüğü
        :param katilik_modu: Hatalarda programın doğrudan durdurulup durdurulmayacağı
        """
        # Envanter verisi sınıf belleğinde saklanır
        self.veri: Dict[str, Any] = envanter_verisi
        # Katılık modu açıkken kurallara uymayan girdiler istisna fırlatır
        self.katilik_modu: bool = katilik_modu
        # Denetim bulgularını tutacak liste
        self.denetim_sonuclari: Optional[Dict[str, Any]] = None

    def dogrula(self) -> Tuple[bool, List[str]]:
        """
        Envanter verisinin yapısal bütünlüğünü doğrular.
        Negatif Kontrol Mekanizması:
        - 'varliklar' listesi var mı ve dolu mu?
        - Her varlığın benzersiz bir 'varlik_id'si var mı?
        - Her varlığın geçerli bir 'sahip' (Asset Owner) kaydı var mı? (Sahipsiz varlık yasaktır!)
        - 'veri_sinifi' ve 'kritiklik_derecesi' standart sözlükte tanımlı mı?
        """
        hatalar: List[str] = []

        # 1. Kontrol: 'varliklar' anahtarının ve liste yapısının kontrolü
        if "varliklar" not in self.veri or not isinstance(self.veri["varliklar"], list):
            hatalar.append("Kritik Hata: Envanter verisinde 'varliklar' listesi bulunamadı.")
            if self.katilik_modu:
                raise AssetValidationError(hatalar[-1])
            return False, hatalar

        varliklar = self.veri["varliklar"]
        if len(varliklar) == 0:
            hatalar.append("Kritik Hata: 'varliklar' listesi boş. En az bir varlık tanımlanmalıdır.")
            if self.katilik_modu:
                raise AssetValidationError(hatalar[-1])
            return False, hatalar

        gorulen_id_seti = set()

        # Her bir varlık tek tek incelenir
        for idx, varlik in enumerate(varliklar, start=1):
            if not isinstance(varlik, dict):
                hatalar.append(f"Format Hatası: #{idx} numaralı varlık geçerli bir JSON nesnesi değil.")
                continue

            v_id = varlik.get("varlik_id")
            # Varlık ID kontrolü
            if not v_id or not isinstance(v_id, str):
                hatalar.append(f"Tanımsız Kimlik: #{idx} numaralı varlığın geçerli bir 'varlik_id' değeri yok.")
            elif v_id in gorulen_id_seti:
                hatalar.append(f"Mükerrer Kimlik Hatası: '{v_id}' kimliği birden fazla varlığa atanmış!")
            else:
                gorulen_id_seti.add(v_id)

            # Varlık Türü kontrolü (VERI, UYGULAMA, CIHAZ, KIMLIK, AG)
            tur = varlik.get("tur")
            if not tur or tur not in GECERLI_VARLIK_TURLERI:
                hatalar.append(f"Geçersiz Tür: '{v_id}' varlığının türü ({tur}) geçersiz. Kabul edilenler: {list(GECERLI_VARLIK_TURLERI)}")

            # SAHİPLİK KONTROLÜ (En Kritik Güvenlik Denetimi)
            # Sahibi olmayan bir varlık 'Orphan Asset' veya 'Gölge BT'dir. Kimse yama yapmaz, kimse korumaz.
            sahip = varlik.get("sahip")
            if not sahip or not isinstance(sahip, str) or len(sahip.strip()) < 3:
                hatalar.append(f"Sahipsiz Varlık Hatası (Orphan Asset): '{v_id}' için atanmış sorumlu bir 'sahip' bulunamadı!")

            # Veri Sınıfı kontrolü
            v_sinifi = varlik.get("veri_sinifi")
            if not v_sinifi or v_sinifi not in VERI_SINIFLARI:
                hatalar.append(f"Geçersiz Veri Sınıfı: '{v_id}' için tanımlanan sınıf ({v_sinifi}) standart dışı.")

            # Kritiklik Derecesi kontrolü
            kritiklik = varlik.get("kritiklik_derecesi")
            if not kritiklik or kritiklik not in KRITIKLIK_SEVIYELERI:
                hatalar.append(f"Geçersiz Kritiklik: '{v_id}' kritiklik seviyesi ({kritiklik}) standart dışı.")

        if hatalar and self.katilik_modu:
            raise AssetValidationError("\n".join(hatalar))

        return (len(hatalar) == 0), hatalar

    def analiz_et(self) -> Dict[str, Any]:
        """
        Envanteri detaylı güvenlik ve risk analizine tabi tutar.
        - Donanım değeri vs İş Etki Değeri karşılaştırması (Crown Jewels Paradoksu)
        - Güvenlik Uyumsuzlukları (Hassas veriye sahip ama şifrelemesi/MFA'sı olmayan varlıklar)
        - Tür bazlı varlık dağılımı
        """
        gecerli, hatalar = self.dogrula()
        if not gecerli:
            return {"durum": "GECERSIZ", "hatalar": hatalar}

        varliklar = self.veri.get("varliklar", [])
        toplam_donanim_maliyeti = 0.0
        toplam_is_etkisi = 0.0

        tur_sayilari: Dict[str, int] = {t: 0 for t in GECERLI_VARLIK_TURLERI}
        sinif_sayilari: Dict[str, int] = {s: 0 for s in VERI_SINIFLARI.keys()}
        kritiklik_sayilari: Dict[str, int] = {k: 0 for k in KRITIKLIK_SEVIYELERI.keys()}

        guvenlik_uyarilari: List[Dict[str, Any]] = []
        islenmis_varliklar: List[Dict[str, Any]] = []

        for v in varliklar:
            v_id = v["varlik_id"]
            tur = v["tur"]
            tur_sayilari[tur] = tur_sayilari.get(tur, 0) + 1

            v_sinif = v["veri_sinifi"]
            sinif_sayilari[v_sinif] = sinif_sayilari.get(v_sinif, 0) + 1

            kritiklik = v["kritiklik_derecesi"]
            kritiklik_sayilari[kritiklik] = kritiklik_sayilari.get(kritiklik, 0) + 1

            donanim_usd = float(v.get("parasal_donanim_degeri_usd", 0.0))
            is_etkisi_usd = float(v.get("is_etki_degeri_usd", 0.0))
            toplam_donanim_maliyeti += donanim_usd
            toplam_is_etkisi += is_etkisi_usd

            # Küçük harfe dönüştürerek Türkçe I/İ dönüşüm hatalarını ve büyük/küçük harf duyarlılığını önlüyoruz
            mevcut_kontroller = [str(k).lower() for k in v.get("mevcut_kontroller", [])]
            ag_konumu = str(v.get("ag_konumu", "")).upper()

            # GÜVENLİK KORUMA KURALI 1: Çok Gizli veya Gizli veri içeren varlıklarda Şifreleme Zorunluluğu
            if v_sinif in {"COK_GIZLI_SIR", "GIZLI"}:
                sifreleme_var_mi = any(
                    "aes" in c or "şifre" in c or "sifre" in c or "encrypt" in c or 
                    "tls" in c or "bitlocker" in c or "luks" in c
                    for c in mevcut_kontroller
                )
                if not sifreleme_var_mi:
                    guvenlik_uyarilari.append({
                        "varlik_id": v_id,
                        "ad": v["ad"],
                        "seviye": "KRİTİK AÇIK",
                        "mesaj": f"Varlık '{v_sinif}' sınıfında hassas veri taşıyor ancak şifreleme (Encryption) kontrolü tanımlanmamış!"
                    })

            # GÜVENLİK KORUMA KURALI 2: Kritik Varlığın DMZ'de Korunmasız Bulunması Riski
            if kritiklik == "KRITIK" and "DMZ" in ag_konumu and v_sinif != "KAMUYA_ACIK":
                guvenlik_uyarilari.append({
                    "varlik_id": v_id,
                    "ad": v["ad"],
                    "seviye": "YÜKSEK RİSK",
                    "mesaj": f"Kritik varlık doğrudan internete açık DMZ bölgesinde konumlandırılmış. Segmentasyon ihlali!"
                })

            # Crown Jewels Paradoksu Hesabı:
            # Donanımı ucuz (örn: 2.500$) ama iş değeri devasa (örn: 15.000.000$) olan varlıklar
            oran = round(is_etkisi_usd / donanim_usd, 1) if donanim_usd > 0 else 0.0

            islenmis_varliklar.append({
                "varlik_id": v_id,
                "ad": v["ad"],
                "tur": tur,
                "sahip": v["sahip"],
                "veri_sinifi": v_sinif,
                "kritiklik": kritiklik,
                "donanim_usd": donanim_usd,
                "is_etkisi_usd": is_etkisi_usd,
                "crown_jewel_orani": oran,
                "kontroller": v.get("mevcut_kontroller", [])
            })

        # Sonuç nesnesi yapılandırılıyor
        self.denetim_sonuclari = {
            "durum": "GECERLI",
            "kurum": self.veri.get("kurum", "Bilinmeyen Kurum"),
            "gun_no": self.veri.get("gun_no", 5),
            "gun_kimligi": self.veri.get("gun_kimligi", "G005"),
            "toplam_varlik_sayisi": len(varliklar),
            "toplam_donanim_maliyeti_usd": toplam_donanim_maliyeti,
            "toplam_is_etkisi_usd": toplam_is_etkisi,
            "tur_dagilimi": tur_sayilari,
            "veri_sinifi_dagilimi": sinif_sayilari,
            "kritiklik_dagilimi": kritiklik_sayilari,
            "guvenlik_uyarilari": guvenlik_uyarilari,
            "varlik_listesi": islenmis_varliklar
        }

        return self.denetim_sonuclari

    def tablo_yazdir(self) -> str:
        """
        Envanteri ve analiz bulgularını görsel bir ASCII tablosuna dönüştürür.
        """
        if not self.denetim_sonuclari:
            self.analiz_et()

        satirlar: List[str] = []
        satirlar.append("========================================================================================================================")
        satirlar.append(f"  KURUMSAL VARLIK ENVANTERİ VE VERİ SINIFLANDIRMA DENETİMİ: {self.denetim_sonuclari.get('kurum', '')}")
        satirlar.append(f"  Gün Kimliği: {self.denetim_sonuclari.get('gun_kimligi', '')} | Toplam Varlık: {self.denetim_sonuclari.get('toplam_varlik_sayisi', 0)}")
        satirlar.append("========================================================================================================================")
        satirlar.append(f"{'ID':<9} | {'TÜR':<9} | {'SINIF':<14} | {'KRİTİKLİK':<10} | {'DONANIM ($)':<12} | {'İŞ ETKİSİ ($)':<14} | {'ORAN':<6} | {'VARLIK ADI'}")
        satirlar.append("------------------------------------------------------------------------------------------------------------------------")

        for v in self.denetim_sonuclari.get("varlik_listesi", []):
            d_str = f"${v['donanim_usd']:,.0f}"
            e_str = f"${v['is_etkisi_usd']:,.0f}"
            o_str = f"{v['crown_jewel_orani']}x"
            satirlar.append(f"{v['varlik_id']:<9} | {v['tur']:<9} | {v['veri_sinifi']:<14} | {v['kritiklik']:<10} | {d_str:<12} | {e_str:<14} | {o_str:<6} | {v['ad']}")

        satirlar.append("========================================================================================================================")
        satirlar.append("  FINANSAL PARADOKS VE CROWN JEWELS ANALİZİ:")
        satirlar.append(f"  * Toplam Satın Alma / Donanım Bedeli: ${self.denetim_sonuclari.get('toplam_donanim_maliyeti_usd', 0):,.2f}")
        satirlar.append(f"  * Olası İhlal Durumunda Toplam İş Etkisi: ${self.denetim_sonuclari.get('toplam_is_etkisi_usd', 0):,.2f}")
        satirlar.append("  * SONUÇ: Kritiklik donanım fiyatıyla ölçülemez! $2,500'lık eski bir DB sunucusu $15,000,000'lık risk barındırır.")
        satirlar.append("------------------------------------------------------------------------------------------------------------------------")

        uyarilar = self.denetim_sonuclari.get("guvenlik_uyarilari", [])
        if not uyarilar:
            satirlar.append("  [+] GÜVENLİK DENETİMİ BAŞARILI: Veri sınıfları ve kontroller arasında çelişki bulunamadı.")
        else:
            satirlar.append(f"  [!] DİKKAT: {len(uyarilar)} ADET GÜVENLİK VE UYUM BULGUSU TESPİT EDİLDİ:")
            for u in uyarilar:
                satirlar.append(f"      [{u['seviye']}] {u['varlik_id']} - {u['ad']}: {u['mesaj']}")

        satirlar.append("========================================================================================================================")
        return "\n".join(satirlar)


def main() -> int:
    """CLI Giriş Noktası."""
    parser = argparse.ArgumentParser(
        description="Varlık Envanteri, Sahiplik ve Veri Sınıflandırma Denetim Aracı",
        epilog="Örnek kullanım: python asset_classifier.py --envanter ornek_veri/varlik_envanteri.json"
    )

    parser.add_argument(
        "--envanter", "-e",
        required=True,
        type=str,
        help="Analiz edilecek varlık envanteri JSON dosyasının yolu"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Çıktı formatı (text: tablo, json: ham veri)"
    )
    parser.add_argument(
        "--cikis", "-o",
        type=str,
        default=None,
        help="Sonucun kaydedileceği dosya yolu"
    )
    parser.add_argument(
        "--esnek",
        action="store_true",
        help="Hata durumunda programı kırmak yerine hata listesini dön"
    )

    args = parser.parse_args()

    envanter_yolu = Path(args.envanter)
    if not envanter_yolu.is_file():
        sys.stderr.write(f"Hata: Envanter dosyası bulunamadı: {envanter_yolu}\n")
        return 1

    try:
        with open(envanter_yolu, "r", encoding="utf-8") as f:
            veri = json.load(f)
    except Exception as e:
        sys.stderr.write(f"JSON Okuma Hatası: {e}\n")
        return 2

    classifier = AssetClassifier(veri, katilik_modu=(not args.esnek))

    try:
        sonuc = classifier.analiz_et()
    except AssetValidationError as ave:
        sys.stderr.write(f"Varlık Doğrulama Hatası:\n{ave}\n")
        return 3

    if args.format == "json":
        cikti = json.dumps(sonuc, ensure_ascii=False, indent=2)
    else:
        cikti = classifier.tablo_yazdir()

    if args.cikis:
        cikis_yolu = Path(args.cikis)
        cikis_yolu.parent.mkdir(parents=True, exist_ok=True)
        with open(cikis_yolu, "w", encoding="utf-8") as f:
            f.write(cikti)
        print(f"Denetim raporu kaydedildi: {cikis_yolu}")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(cikti)

    return 0


if __name__ == "__main__":
    sys.exit(main())
