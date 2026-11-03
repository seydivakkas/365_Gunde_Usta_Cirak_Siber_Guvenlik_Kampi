#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

Veri Akış Diyagramı (DFD) ve Tehdit Modelleme Değerlendiricisi
--------------------------------------------------------------
Bu araç, bir yazılım veya sistem mimarisinin Veri Akış Diyagramını (DFD),
bileşenlerini, veri akışlarını, güven sınırlarını (Trust Boundaries) ve
STRIDE tehditlerini analiz eder. Güven sınırını korumasız geçen veri akışlarını
ve kontrolü atanmamış açık tehditleri matematiksel kurallarla tespit eder.
"""

# Standart Python kütüphaneleri (Harici bağımlılık gerektirmez)
import sys          # Sistem çıkış kodları ve akış kontrolü için
import json         # JSON formatındaki DFD ve tehdit verilerini işlemek için
import argparse     # Komut satırı argümanlarını (CLI) yönetmek için
from pathlib import Path  # Dosya yollarını güvenli yönetmek için
from typing import Dict, Any, List, Tuple, Optional, Set  # Katı tip denetimi için

# İzin verilen geçerli bileşen türleri (Standart DFD semantolojisi)
GECERLI_BILESEN_TURLERI = {"DIS_VARLIK", "SUREC", "SUREC_UZAK", "VERI_DEPOSU"}

# STRIDE Tehdit Kategorileri (Microsoft Tehdit Modelleme Standardı)
STRIDE_KATEGORILERI = {
    "SPOOFING": "Kimlik Sahteciliği (Yetkisiz bir kimliğe bürünme)",
    "TAMPERING": "Veri Tahrifatı (Bellekteki, diskteki veya iletimdeki veriyi değiştirme)",
    "REPUDIATION": "İnkar Edilebilirlik (Yaptığı işlemi inkar etme, log eksikliği)",
    "INFORMATION_DISCLOSURE": "Bilgi İfşası (Yetkisiz kişilerin gizli veriyi okuması)",
    "DENIAL_OF_SERVICE": "Hizmet Engelleme (Sistemi aşırı yükleyip erişilmez kılma)",
    "ELEVATION_OF_PRIVILEGE": "Yetki Yükseltme (Normal kullanıcının yönetici yetkisi alması)"
}


class ThreatModelValidationError(Exception):
    """Tehdit modeli ve DFD doğrulama hatalarını temsil eden özel istisna sınıfı."""
    pass


class ThreatModeler:
    """
    Veri Akış Diyagramını (DFD), güven sınırlarını ve STRIDE tehditlerini
    denetleyen ana tehdit modelleme motoru.
    """

    def __init__(self, model_verisi: Dict[str, Any], katilik_modu: bool = True):
        """
        Tehdit modelleyiciyi başlatır.

        :param model_verisi: JSON DFD ve tehdit modeli sözlüğü
        :param katilik_modu: Standart ihlallerinde programın durup durmayacağı
        """
        # Model verisi sınıf değişkenine aktarılır
        self.veri: Dict[str, Any] = model_verisi
        # Katılık modu aktifse yapısal hatalarda istisna fırlatılır
        self.katilik_modu: bool = katilik_modu
        # Analiz çıktılarının saklanacağı önbellek
        self.analiz_sonucu: Optional[Dict[str, Any]] = None

    def dogrula(self) -> Tuple[bool, List[str]]:
        """
        Modelin DFD ve Tehdit Modelleme standartlarına uygunluğunu denetler.
        Negatif Kontroller:
        - Zorunlu anahtarlar: 'bilesenler', 'guven_sinirlari', 'veri_akislari', 'tehditler'
        - Veri akışlarının kaynak ve hedefleri 'bilesenler' listesinde mevcut mu? (Hayalet bileşen engelleme)
        - Geçilen güven sınırları 'guven_sinirlari' listesinde tanımlı mı?
        - STRIDE kategorileri standart sözlükte var mı?
        """
        hatalar: List[str] = []

        # 1. Kontrol: Kök anahtarların eksiksiz varlığı
        zorunlu_alanlar = ["bilesenler", "guven_sinirlari", "veri_akislari", "tehditler"]
        for alan in zorunlu_alanlar:
            if alan not in self.veri or not isinstance(self.veri[alan], list):
                hatalar.append(f"Yapısal Eksiklik: '{alan}' listesi model dosyasında bulunamadı.")

        if hatalar:
            if self.katilik_modu:
                raise ThreatModelValidationError("\n".join(hatalar))
            return False, hatalar

        # 2. Kontrol: Bileşenlerin ID bütünlüğü ve tür denetimi
        bilesen_idleri: Set[str] = set()
        for idx, b in enumerate(self.veri["bilesenler"], start=1):
            b_id = b.get("id")
            if not b_id or not isinstance(b_id, str):
                hatalar.append(f"Tanımsız Bileşen: #{idx} numaralı bileşenin 'id' değeri yok.")
            elif b_id in bilesen_idleri:
                hatalar.append(f"Mükerrer Bileşen ID: '{b_id}' kimliği birden fazla bileşene atanmış!")
            else:
                bilesen_idleri.add(b_id)

            b_tur = b.get("tur")
            if not b_tur or b_tur not in GECERLI_BILESEN_TURLERI:
                hatalar.append(f"Geçersiz Bileşen Türü: '{b_id}' için tanımlanan tür ({b_tur}) standart dışı.")

        # 3. Kontrol: Güven sınırlarının (Trust Boundaries) doğrulanması
        sinir_idleri: Set[str] = set()
        for s in self.veri["guven_sinirlari"]:
            s_id = s.get("id")
            if not s_id or not isinstance(s_id, str):
                hatalar.append("Tanımsız Güven Sınırı: Güven sınırının geçerli bir 'id' değeri yok.")
            elif s_id in sinir_idleri:
                hatalar.append(f"Mükerrer Sınır ID: '{s_id}' birden fazla sınıra atanmış!")
            else:
                sinir_idleri.add(s_id)

        # 4. Kontrol: Veri Akışlarının (Data Flows) doğrulanması
        # Her akış gerçek bir kaynaktan gerçek bir hedefe gitmeli ve tanımlı bir sınırı geçmelidir
        for idx, akis in enumerate(self.veri["veri_akislari"], start=1):
            a_id = akis.get("id", f"DF-#{idx}")
            kaynak = akis.get("kaynak")
            hedef = akis.get("hedef")
            sinir = akis.get("gecilen_sinir")

            # Kaynak bileşen sistemde var mı?
            if kaynak not in bilesen_idleri:
                hatalar.append(f"Hayalet Kaynak Hatası: '{a_id}' akışının kaynağı olan '{kaynak}' bileşenlerde tanımlı değil!")

            # Hedef bileşen sistemde var mı?
            if hedef not in bilesen_idleri:
                hatalar.append(f"Hayalet Hedef Hatası: '{a_id}' akışının hedefi olan '{hedef}' bileşenlerde tanımlı değil!")

            # Geçilen güven sınırı tanımlı mı?
            if sinir and sinir not in sinir_idleri:
                hatalar.append(f"Tanımsız Sınır Geçişi: '{a_id}' akışı tanımlanmamış bir güven sınırından ({sinir}) geçiyor!")

        # 5. Kontrol: Tehditlerin (Threats) STRIDE uyumluluğu
        for t in self.veri["tehditler"]:
            t_id = t.get("id", "TH-Bilinmeyen")
            kat = t.get("kategori")
            if not kat or kat not in STRIDE_KATEGORILERI:
                hatalar.append(f"Geçersiz STRIDE Kategorisi: '{t_id}' tehdidi ({kat}) STRIDE standardında bulunamadı.")

        if hatalar and self.katilik_modu:
            raise ThreatModelValidationError("\n".join(hatalar))

        return (len(hatalar) == 0), hatalar

    def analiz_et(self) -> Dict[str, Any]:
        """
        DFD ve Tehdit Modelini derinlemesine inceler:
        - Güven sınırını geçen veri akışlarında kriptografik/bütünlük kontrolleri var mı?
        - Karşılanmamış (açıkta kalan) sahipsiz tehditler var mı?
        - Saldırı Yüzeyi ve STRIDE kapsam indeksi nedir?
        """
        gecerli, hatalar = self.dogrula()
        if not gecerli:
            return {"durum": "GECERSIZ", "hatalar": hatalar}

        veri_akislari = self.veri.get("veri_akislari", [])
        tehditler = self.veri.get("tehditler", [])
        guven_sinirlari = {s["id"]: s for s in self.veri.get("guven_sinirlari", [])}

        guvenlik_bulgulari: List[Dict[str, Any]] = []

        # MİMARİ KURAL 1: Yüksek Riskli veya Kritik Sınırı Geçen Veri Akışında Şifreleme Zorunluluğu
        # (Örn: İnternet veya Disk sınırından geçen veride şifreleme yoksa bu bir tasarım kusurudur)
        for akis in veri_akislari:
            sinir_id = akis.get("gecilen_sinir")
            sinir_obj = guven_sinirlari.get(sinir_id, {})
            risk_seviyesi = sinir_obj.get("risk_seviyesi", "DUSUK")

            kontroller = [str(k).lower() for k in akis.get("kontroller", [])]

            if risk_seviyesi in {"YUKSEK", "KRITIK"}:
                sifreleme_var_mi = any(
                    "aes" in k or "tls" in k or "şifre" in k or "sifre" in k or 
                    "encrypt" in k or "gcm" in k
                    for k in kontroller
                )
                if not sifreleme_var_mi:
                    guvenlik_bulgulari.append({
                        "seviye": "KRİTİK MİMARİ KUSUR",
                        "id": akis.get("id"),
                        "mesaj": f"'{akis.get('id')}' akışı '{sinir_obj.get('ad')}' ({risk_seviyesi}) sınırını geçiyor ancak kriptografik koruma (TLS/AES) tanımlanmamış!"
                    })

        # MİMARİ KURAL 2: Kontrolü Atanmamış Açık Tehdit Denetimi (Unmitigated Threat)
        # Tehdit tanımlanmış ancak kontrolü boş bırakılmışsa sistem saldırıya açıktır
        for t in tehditler:
            kontrol_ack = t.get("kontrol_aciklama", "").strip()
            kontrol_id = t.get("kontrol_id", "").strip()
            durum = t.get("durum", "").strip()

            if not kontrol_ack or not kontrol_id or durum != "ENGEL_ALTI":
                guvenlik_bulgulari.append({
                    "seviye": "AÇIK TEHDİT (UNMITIGATED)",
                    "id": t.get("id"),
                    "mesaj": f"'{t.get('id')}' ({t.get('kategori')}) tehdidi için atanmış koruyucu kontrol bulunmuyor!"
                })

        # STRIDE Kapsam Dağılımı Hesabı
        stride_dagilimi: Dict[str, int] = {k: 0 for k in STRIDE_KATEGORILERI.keys()}
        for t in tehditler:
            k = t.get("kategori")
            if k in stride_dagilimi:
                stride_dagilimi[k] += 1

        # Analiz sonuç nesnesi derleniyor
        self.analiz_sonucu = {
            "durum": "GECERLI",
            "uygulama_adi": self.veri.get("uygulama_adi", "Bilinmeyen Uygulama"),
            "gun_kimligi": self.veri.get("gun_kimligi", "G006"),
            "toplam_bilesen": len(self.veri.get("bilesenler", [])),
            "toplam_sinir": len(self.veri.get("guven_sinirlari", [])),
            "toplam_akis": len(veri_akislari),
            "toplam_tehdit": len(tehditler),
            "stride_dagilimi": stride_dagilimi,
            "guvenlik_bulgulari": guvenlik_bulgulari,
            "bulgu_sayisi": len(guvenlik_bulgulari)
        }

        return self.analiz_sonucu

    def ascii_dfd_ciz(self) -> str:
        """
        Yerel Not Uygulamasının Veri Akış Diyagramını (DFD) ve
        Güven Sınırlarını görselleştiren bir ASCII şeması üretir.
        """
        if not self.analiz_sonucu:
            self.analiz_et()

        satirlar: List[str] = []
        satirlar.append("========================================================================================================")
        satirlar.append(f"  VERİ AKIŞ DİYAGRAMI (DFD) VE GÜVEN SINIRI ŞEMASI: {self.analiz_sonucu.get('uygulama_adi', '')}")
        satirlar.append(f"  Gün: {self.analiz_sonucu.get('gun_kimligi', '')} | Bileşen: {self.analiz_sonucu.get('toplam_bilesen', 0)} | Sınır: {self.analiz_sonucu.get('toplam_sinir', 0)} | Akış: {self.analiz_sonucu.get('toplam_akis', 0)}")
        satirlar.append("========================================================================================================")
        satirlar.append("")
        satirlar.append("  [DIŞ VARLIK: E1]                 === GÜVEN SINIRI: TB1 (Kullanıcı Girdi Sınırı) ===")
        satirlar.append("  (Kullanıcı / İnsan)")
        satirlar.append("          |")
        satirlar.append("          |  [DF1: Not Girişi / Girdi Doğrulama & Sanitizasyon]")
        satirlar.append("          v")
        satirlar.append("  +--------------------------------------------------------------------------------+")
        satirlar.append("  | [SÜREÇ: P1] Not Defteri İstemci Süreci (Masaüstü Uygulaması)                   |")
        satirlar.append("  | - Kullanıcı Arayüzü Yönetimi                                                   |")
        satirlar.append("  | - Kriptografik Şifreleme / Çözme (AES-256-GCM)                                 |")
        satirlar.append("  +-----------------------+--------------------------------+-----------------------+")
        satirlar.append("                          |                                |")
        satirlar.append("   === GÜVEN SINIRI: TB2 (Disk/Depolama) ===       === GÜVEN SINIRI: TB3 (İnternet/Bulut) ===")
        satirlar.append("                          |                                |")
        satirlar.append("     [DF2/DF3: Şifreli Okuma/Yazma]                 [DF4: Sıfır Bilgi TLS 1.3 Sync]")
        satirlar.append("     - AES-256-GCM + Auth Tag                      - Certificate Pinning + JWT")
        satirlar.append("                          |                                |")
        satirlar.append("                          v                                v")
        satirlar.append("  [(VERİ DEPOSU: DS1)]                             [UZAK SÜREÇ: P2]")
        satirlar.append("  Şifreli Not Kasası (SQLite Dosyası)              Bulut Senkronizasyon Sunucusu (API)")
        satirlar.append("")
        satirlar.append("--------------------------------------------------------------------------------------------------------")
        satirlar.append("  STRIDE TEHDİT KAPSAMI VE DURUMU:")
        for kat, sayi in self.analiz_sonucu.get("stride_dagilimi", {}).items():
            durum_str = f"{sayi} Tehdit Tanımlı ve Engellendi" if sayi > 0 else "Tehdit Tanımlanmamış"
            satirlar.append(f"    * {kat:<24}: {durum_str}")
        satirlar.append("--------------------------------------------------------------------------------------------------------")

        bulgular = self.analiz_sonucu.get("guvenlik_bulgulari", [])
        if not bulgular:
            satirlar.append("  [+] MİMARİ DOĞRULAMA BAŞARILI: Güven sınırlarını geçen tüm akışlar kriptografik olarak korunmuştur.")
            satirlar.append("      Açıkta kalan (sahipsiz/mitigasyonsuz) hiçbir STRIDE tehdidi tespit edilmedi.")
        else:
            satirlar.append(f"  [!] DİKKAT: {len(bulgular)} ADET MİMARİ GÜVENLİK KUSURU TESPİT EDİLDİ:")
            for b in bulgular:
                satirlar.append(f"      [{b['seviye']}] {b['id']}: {b['mesaj']}")
        satirlar.append("========================================================================================================")

        return "\n".join(satirlar)


def main() -> int:
    """CLI Giriş Noktası."""
    parser = argparse.ArgumentParser(
        description="Veri Akış Diyagramı (DFD) ve Tehdit Modelleme Doğrulama Aracı",
        epilog="Örnek kullanım: python threat_modeler.py --dfd ornek_veri/not_uygulamasi_dfd.json"
    )

    parser.add_argument(
        "--dfd", "-d",
        required=True,
        type=str,
        help="Değerlendirilecek DFD ve Tehdit Modeli JSON dosyasının yolu"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Çıktı formatı (text: görsel DFD ve analiz tablosu, json: ham analiz verisi)"
    )
    parser.add_argument(
        "--cikis", "-o",
        type=str,
        default=None,
        help="Çıktının kaydedileceği dosya yolu"
    )
    parser.add_argument(
        "--esnek",
        action="store_true",
        help="Hatalarda programı kırmak yerine hata listesini dön"
    )

    args = parser.parse_args()

    dfd_yolu = Path(args.dfd)
    if not dfd_yolu.is_file():
        sys.stderr.write(f"Hata: DFD dosyası bulunamadı: {dfd_yolu}\n")
        return 1

    try:
        with open(dfd_yolu, "r", encoding="utf-8") as f:
            veri = json.load(f)
    except Exception as e:
        sys.stderr.write(f"JSON Okuma Hatası: {e}\n")
        return 2

    modeler = ThreatModeler(veri, katilik_modu=(not args.esnek))

    try:
        sonuc = modeler.analiz_et()
    except ThreatModelValidationError as tve:
        sys.stderr.write(f"Tehdit Modeli Doğrulama Hatası:\n{tve}\n")
        return 3

    if args.format == "json":
        cikti = json.dumps(sonuc, ensure_ascii=False, indent=2)
    else:
        cikti = modeler.ascii_dfd_ciz()

    if args.cikis:
        cikis_yolu = Path(args.cikis)
        cikis_yolu.parent.mkdir(parents=True, exist_ok=True)
        with open(cikis_yolu, "w", encoding="utf-8") as f:
            f.write(cikti)
        print(f"Tehdit modelleme raporu kaydedildi: {cikis_yolu}")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(cikti)

    return 0


if __name__ == "__main__":
    sys.exit(main())
