# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 013: Güvenli Araştırma ve Kaynak Doğrulama Motoru (Security Source & Intelligence Validator)
Usta-Çırak Siber Güvenlik Akademisi Laboratuvar Otomasyon Aracı

Bu modül; siber güvenlik araştırmalarında, zaafiyet (CVE) analizlerinde ve sertleştirme süreçlerinde
başvurulan bilgi kaynaklarını (resmî bültenler, RFC standartları, blog yazıları, GitHub PoC depoları,
forum cevapları) CRAAP (Currency, Relevance, Authority, Accuracy, Purpose) çerçevesinde değerlendirir;
zehirli Truva Atı istismar kodlarını (Trojanized PoC), eskiyen hatalı tavsiyeleri ve SEO zehirlemesi
tuzaklarını tespit ederek çapraz kaynak teyidi (triangulation) icra eder.
"""

import os  # Dosya ve dizin yolu denetimleri için standart kütüphane
import sys  # Sistem argümanları ve standart hata akışlarını yönetmek için
import json  # JSON formatındaki kaynak ve kural veri tabanlarını ayrıştırmak için
import argparse  # Profesyonel komut satırı arayüzü (CLI) parametrelerini işlemek için
from datetime import datetime, timezone  # Kaynakların güncelliğini hesaplamak için zaman kütüphanesi
from typing import Dict, List, Any, Optional, Tuple  # Tip güvenliği ve statik doğrulama için


# --- ÖZEL İSTİSNA SINIFLARI (CUSTOM EXCEPTIONS) ---

class SourceValidatorError(Exception):
    """Kaynak doğrulama motorunun temel ata istisna sınıfı."""
    pass


class MaliciousSourceDetectedError(SourceValidatorError):
    """Kötü niyetli, truva atı içeren veya zehirli istismar kodu tespit edildiğinde fırlatılır."""
    pass


class IncompatibleTriangulationError(SourceValidatorError):
    """Karşılaştırılan iki kaynak arasında uzlaştırılamaz çelişki veya geçersizlik olduğunda fırlatılır."""
    pass


# --- ÇEKİRDEK DOĞRULAMA SINIFI ---

class SecuritySourceValidator:
    """
    Siber güvenlik bilgi ve istihbarat kaynaklarını bilimsel kriterlerle puanlayan ve doğrulayan motor.
    """

    def __init__(self, veri_tabani_yolu: Optional[str] = None):
        # Kaynak veri tabanı yolu atanır
        self.veri_tabani_yolu = veri_tabani_yolu
        # Bellekte tutulacak vaka sözlüğü başlatılır
        self.vakalar: Dict[str, Dict[str, Any]] = {}
        # Eğer yol verilmişse hemen yüklenir
        if veri_tabani_yolu:
            self.veri_tabani_yukle(veri_tabani_yolu)

    def veri_tabani_yukle(self, veri_tabani_yolu: str) -> None:
        """
        Araştırma vakalarını içeren JSON veri tabanını doğrular ve belleğe yükler.
        """
        # Dosya diski üzerinde var mı kontrol edilir
        if not os.path.exists(veri_tabani_yolu):
            raise FileNotFoundError(f"Kaynak veri tabanı dosyası bulunamadı: {veri_tabani_yolu}")

        # Dosya güvenli okuma kipinde açılır
        with open(veri_tabani_yolu, "r", encoding="utf-8") as dosya:
            veri = json.load(dosya)

        # Şema kontrolü
        if "arastirma_vakalari" not in veri:
            raise SourceValidatorError("Geçersiz şema: 'arastirma_vakalari' listesi eksik.")

        # Vaka listesi sözlüğe dönüştürülür
        self.vakalar = {v["vaka_id"]: v for v in veri["arastirma_vakalari"]}

    def craap_skoru_hesapla(self, kaynak: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tek bir bilgi kaynağını CRAAP kriterlerine göre puanlar (Toplam 100 puan üzerinden):
        1. Currency (Güncellik - 20 Puan): Yayın tarihi 2 yıldan yeni mi, yoksa 5+ yıllık eski bilgi mi?
        2. Relevance (İlgililik - 20 Puan): Hedef zaafiyet ve varlıkla birebir eşleşiyor mu?
        3. Authority (Otorite - 25 Puan): Yazar kurumsal bir CERT/NVD/Vendor mu, yoksa anonim profil mi?
        4. Accuracy (Doğruluk & Kanıt - 25 Puan): Kriptografik imza (GPG/SHA256) ve resmî CVE referansı var mı?
        5. Purpose (Amaç & Tarafsızlık - 10 Puan): Eğitsel/savunma amaçlı mı, yoksa şüpheli/zararlı mı?
        """
        skor = 100  # Puanlama 100 üzerinden başlar, riskli bulgular puan düşürür
        kirmizi_bayraklar = []

        # 1. GÜNCELLİK DENETİMİ (Currency - 20 Puan)
        yayin_tarihi_str = kaynak.get("yayin_tarihi")
        if yayin_tarihi_str:
            try:
                # ISO formatındaki tarih ayrıştırılır
                yayin_tarihi = datetime.fromisoformat(yayin_tarihi_str.replace("Z", "+00:00"))
                su_an = datetime.now(timezone.utc)
                yas_yil = (su_an - yayin_tarihi).days / 365.25
                if yas_yil > 5.0:
                    ceza = 20
                    skor -= ceza
                    kirmizi_bayraklar.append({
                        "kod": "FLAG-01-ESKI-KAYNAK",
                        "seviye": "YUKSEK",
                        "ceza": ceza,
                        "aciklama": f"Kaynak {yas_yil:.1f} yıl önce yayınlanmış. Eski güvenlik önerileri modern sistemlerde zafiyet yaratabilir."
                    })
                elif yas_yil > 2.0:
                    ceza = 10
                    skor -= ceza
                    kirmizi_bayraklar.append({
                        "kod": "FLAG-01-ESKIYEN-BILGI",
                        "seviye": "ORTA",
                        "ceza": ceza,
                        "aciklama": f"Kaynak {yas_yil:.1f} yıllık. Güncelliğini yitirmiş olabilir."
                    })
            except Exception:
                skor -= 10
                kirmizi_bayraklar.append({
                    "kod": "FLAG-01-TARIH-BELIRSIZ",
                    "seviye": "ORTA",
                    "ceza": 10,
                    "aciklama": "Yayın tarihi okunamadı veya biçimi geçersiz."
                })
        else:
            skor -= 20
            kirmizi_bayraklar.append({
                "kod": "FLAG-01-TARIH-YOK",
                "seviye": "YUKSEK",
                "ceza": 20,
                "aciklama": "Yayın tarihi belirtilmemiş. Bilgi güncelliği teyit edilemiyor."
            })

        # 2. OTORİTE VE YAZAR GÜVENİLİRLİĞİ (Authority - 25 Puan)
        alan_guvenilirligi = kaynak.get("alan_adi_guvenilirligi", "")
        if alan_guvenilirligi in ["UST_DUZEY_DEVLET_URETICI", "ULUSLARARASI_STANDART_KURUMU"]:
            # Tam otorite puanı, kesinti yok
            pass
        elif alan_guvenilirligi == "HAKEMLI_KURUMSAL_LAB":
            skor -= 5
        elif alan_guvenilirligi in ["HALKA_ACIK_KULLANICI_ICERIGI", "DOGRULANMAMIS_BLOG_FORUM"]:
            ceza = 25
            skor -= ceza
            kirmizi_bayraklar.append({
                "kod": "FLAG-02-OTORITESIZ-KAYNAK",
                "seviye": "KRITIK",
                "ceza": ceza,
                "aciklama": "Kaynak anonim forum veya denetimsiz açık kod deposudur. Otorite sıfırdır."
            })

        # 3. DOĞRULUK VE KRİPTOGRAFİK İMZA (Accuracy - 25 Puan)
        kripto = kaynak.get("kriptografik_dogrulama", {})
        sha256_var = kripto.get("sha256_saglanmis_mi", False)
        gpg_var = kripto.get("gpg_imzali_mi", False)
        if not sha256_var and not gpg_var:
            ceza = 25
            skor -= ceza
            kirmizi_bayraklar.append({
                "kod": "FLAG-03-KRIPTO-BUTUNLUK-YOK",
                "seviye": "YUKSEK",
                "ceza": ceza,
                "aciklama": "Dosya veya içerik için hiçbir GPG imzası veya SHA-256 sağlama değeri bulunmuyor."
            })

        # 4. TEHLİKELİ TAVSİYE VEYA ZEHİRLİ KOD TESPİTİ (Purpose & Harm Detection - 30 Puan)
        icerik = kaynak.get("icerik_ozeti", "")
        onerilen_eylem = kaynak.get("onerilen_eylem", "")
        birlesik_metin = (icerik + " " + onerilen_eylem).lower()

        # Zararlı PoC sinyalleri: curl | sh, base64, evil-domain, loader
        if any(z in birlesik_metin for z in ["curl", "loader.sh", "base64", "evil-domain", "auto-pwn"]):
            ceza = 40
            skor -= ceza
            kirmizi_bayraklar.append({
                "kod": "FLAG-04-ZEHIRLI-POC-TRUVA-ATI",
                "seviye": "FELAKET",
                "ceza": ceza,
                "aciklama": "Zehirli PoC (Trojanized Exploit) sinyali tespit edildi! Kod arka planda zararlı indirici çalıştırmaktadır."
            })

        # Yıkıcı tavsiye sinyalleri: chmod 777, permitrootlogin yes, verify=false
        if any(y in birlesik_metin for y in ["chmod 777", "permitrootlogin yes", "verify=false"]):
            ceza = 35
            skor -= ceza
            kirmizi_bayraklar.append({
                "kod": "FLAG-05-YIKICI-GUVENLIK-TAVSIYESI",
                "seviye": "FELAKET",
                "ceza": ceza,
                "aciklama": "Sistemin yetki ve kimlik denetimini tamamen kaldıran yıkıcı tavsiye (chmod 777 vb.) içeriyor."
            })

        # Puanın sınırlandırılması
        skor = max(0, min(100, skor))
        durum = "GUVENILIR_ONAYLI" if skor >= 80 else ("SUPHELI_IKINCIL" if skor >= 50 else "GUVENSIZ_REDDEDILDI")

        return {
            "kaynak_id": kaynak.get("kaynak_id"),
            "kaynak_adi": kaynak.get("kaynak_adi"),
            "craap_skoru": skor,
            "durum": durum,
            "kirmizi_bayrak_sayisi": len(kirmizi_bayraklar),
            "kirmizi_bayraklar": kirmizi_bayraklar
        }

    def capraz_kaynak_karsilastir(self, vaka_id: str) -> Dict[str, Any]:
        """
        Aynı konuyu ele alan iki farklı kaynağı CRAAP kriterleriyle çapraz karşılaştırır (Triangulation).
        Birincil resmî kaynak ile şüpheli/topluluk kaynağını ayrıştırarak güvenilirlik kararı üretir.
        """
        if vaka_id not in self.vakalar:
            raise SourceValidatorError(f"Tanımsız Vaka Kimliği: {vaka_id}")

        vaka = self.vakalar[vaka_id]
        kaynaklar = vaka.get("kaynaklar", [])
        if len(kaynaklar) < 2:
            raise IncompatibleTriangulationError(f"Çapraz teyit için en az 2 kaynak gereklidir. Mevcut: {len(kaynaklar)}")

        analizler = [self.craap_skoru_hesapla(k) for k in kaynaklar]

        # En güvenilir ve en zayıf kaynak belirlenir
        sirali = sorted(analizler, key=lambda x: x["craap_skoru"], reverse=True)
        onaylanan_kaynak = sirali[0]
        reddedilen_veya_zayif = sirali[1]

        # Güvenilirlik farkı
        fark = onaylanan_kaynak["craap_skoru"] - reddedilen_veya_zayif["craap_skoru"]

        karar = {
            "vaka_id": vaka_id,
            "vaka_konusu": vaka.get("vaka_konusu"),
            "karsilastirilan_kaynak_sayisi": len(kaynaklar),
            "onaylanan_kaynak": {
                "kaynak_id": onaylanan_kaynak["kaynak_id"],
                "kaynak_adi": onaylanan_kaynak["kaynak_adi"],
                "skor": onaylanan_kaynak["craap_skoru"],
                "durum": onaylanan_kaynak["durum"]
            },
            "reddedilen_veya_zayif_kaynak": {
                "kaynak_id": reddedilen_veya_zayif["kaynak_id"],
                "kaynak_adi": reddedilen_veya_zayif["kaynak_adi"],
                "skor": reddedilen_veya_zayif["craap_skoru"],
                "durum": reddedilen_veya_zayif["durum"]
            },
            "guvenilirlik_farki": fark,
            "nihai_karar": "KAYNAK_A_ONAYLANDI__KAYNAK_B_REDDEDILDI" if onaylanan_kaynak["craap_skoru"] >= 80 and reddedilen_veya_zayif["craap_skoru"] < 50 else "TEKRAR_INCELEME_GEREKLI",
            "tavsiye": f"Yalnızca {onaylanan_kaynak['kaynak_adi']} referans alınmalı; {reddedilen_veya_zayif['kaynak_adi']} içeriği güvenlik riski nedeniyle engellenmelidir."
        }

        return karar


# --- KOMUT SATIRI ARAYÜZÜ (CLI) ---

def main():
    """CLI giriş noktası ve parametre işleyicisi."""
    parser = argparse.ArgumentParser(
        description="GÜN 013: Güvenli Araştırma ve Kaynak Doğrulama Motoru",
        epilog="ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)"
    )
    parser.add_argument("--veri-tabani", type=str, default="ornek_veri/guvenlik_arastirma_kaynaklari.json", help="Kaynak JSON veri tabanı yolu")
    parser.add_argument("--vaka-id", type=str, default="VAKA-CVE-RCE-01", help="Çapraz teyit yapılacak vaka kimliği")
    parser.add_argument("--karsilastir", action="store_true", help="Vaka içindeki kaynakları çapraz teyit et (Triangulation)")
    parser.add_argument("--tumunu-denetle", action="store_true", help="Veri tabanındaki tüm vakaları analiz et")
    parser.add_argument("--cikis-json", type=str, help="Sonuçları JSON dosyası olarak kaydet")

    args = parser.parse_args()

    validator = SecuritySourceValidator(args.veri_tabani)
    sonuc = {}

    if args.karsilastir:
        print(f"[*] Çapraz Kaynak Karşılaştırması Başlatılıyor: Vaka={args.vaka_id}")
        sonuc = validator.capraz_kaynak_karsilastir(args.vaka_id)
        print(f"[+] Vaka: {sonuc['vaka_konusu']}")
        print(f"[+] Onaylanan Kaynak: {sonuc['onaylanan_kaynak']['kaynak_adi']} (Skor: {sonuc['onaylanan_kaynak']['skor']})")
        print(f"[-] Reddedilen Kaynak: {sonuc['reddedilen_veya_zayif_kaynak']['kaynak_adi']} (Skor: {sonuc['reddedilen_veya_zayif_kaynak']['skor']})")
        print(f"[!] Güvenilirlik Farkı: {sonuc['guvenilirlik_farki']} puan")
        print(f"[+] Nihai Karar: {sonuc['nihai_karar']}")

    elif args.tumunu_denetle:
        print("[*] Tüm Araştırma Vakaları Analiz Ediliyor...")
        raporlar = []
        for v_id in validator.vakalar:
            res = validator.capraz_kaynak_karsilastir(v_id)
            raporlar.append(res)
            print(f"    - Vaka {v_id} -> Onaylı: {res['onaylanan_kaynak']['kaynak_id']} ({res['onaylanan_kaynak']['skor']}p) vs Reddedilen: {res['reddedilen_veya_zayif_kaynak']['kaynak_id']} ({res['reddedilen_veya_zayif_kaynak']['skor']}p)")
        sonuc = {"tum_vaka_analizleri": raporlar}

    else:
        # Varsayılan: İlk vakayı karşılaştır
        sonuc = validator.capraz_kaynak_karsilastir(args.vaka_id)
        print(f"[+] Otomatik Karşılaştırma Sonucu: {sonuc['nihai_karar']}")

    if args.cikis_json:
        with open(args.cikis_json, "w", encoding="utf-8") as f:
            json.dump(sonuc, f, indent=2, ensure_ascii=False)
        print(f"[+] Sonuçlar dosyaya kaydedildi: {args.cikis_json}")


if __name__ == "__main__":
    main()
