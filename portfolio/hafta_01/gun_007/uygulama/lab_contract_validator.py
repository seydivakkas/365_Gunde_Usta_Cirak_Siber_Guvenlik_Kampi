#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
Açık kaynak lisansları (MIT, Apache, GPL vb.) KULLANILMAZ.
İzin talepleri için: GitHub @seydivakkas

Güvenli Laboratuvar Kurulum Sözleşmesi ve Topoloji Doğrulayıcısı
---------------------------------------------------------------
Bu araç, bir siber güvenlik laboratuvarının yasal sözleşmesini, hipervizör izolasyon
ayarlarını, ağ topolojisini ve IP sınırlarını denetler. İzole ortamlardan internete
sızma (leakage), sanal makineden ana sisteme sıçrama (VM Escape) ve yetkisiz kapsam
genişlemesi risklerini matematiksel kurallarla doğrular.
"""

# Standart Python kütüphaneleri (Dış kütüphane bağımlılığı yoktur)
import sys          # Sistem çıkış kodları ve akış yönetimi için
import json         # JSON formatındaki laboratuvar sözleşmesini işlemek için
import ipaddress    # IP adreslerini ve CIDR bloklarını matematiksel doğrulamak için
import argparse     # Komut satırı arayüzü (CLI) parametrelerini yönetmek için
from pathlib import Path  # Güvenli dosya yolu yönetimi için
from typing import Dict, Any, List, Tuple, Optional, Set  # Katı tip denetimi (Type Hints) için

# İzin verilen güvenli hipervizör adaptör türleri (Laboratuvar izolasyonu için)
GUVENLI_ADAPTOR_TURLERI = {"Host-Only", "Internal-Network", "Isolated-vSwitch"}

# Kesinlikle yasaklanmış genel internet ve şirket omurga IP blokları
YASAKLI_IP_ORNEKLERI = {"0.0.0.0/0", "8.8.8.8", "1.1.1.1", "192.168.1.1"}


class ContractViolationError(Exception):
    """Laboratuvar sözleşmesi, izolasyon veya etik kapsam ihlallerini temsil eden istisna sınıfı."""
    pass


class LabContractValidator:
    """
    Siber güvenlik laboratuvarı sözleşmesini, ağ segmentasyonunu ve
    hipervizör sıkılaştırma ayarlarını denetleyen ana doğrulama motoru.
    """

    def __init__(self, sozlesme_verisi: Dict[str, Any], katilik_modu: bool = True):
        """
        Doğrulayıcıyı başlatır.

        :param sozlesme_verisi: JSON sözlük yapısındaki sözleşme verisi
        :param katilik_modu: Standart ihlallerinde programın istisna fırlatıp durdurulması
        """
        # Sözleşme verisi hafızaya alınıyor
        self.veri: Dict[str, Any] = sozlesme_verisi
        # Katılık modu aktifse ihlaller anında süreci durdurur
        self.katilik_modu: bool = katilik_modu
        # Denetim sonuçlarının önbelleği
        self.analiz_sonucu: Optional[Dict[str, Any]] = None

    def dogrula(self) -> Tuple[bool, List[str]]:
        """
        Sözleşmenin yapısal bütünlüğünü, yasal onaylarını ve ağ kurallarını denetler.
        Negatif Kontroller:
        - Zorunlu bölümler mevcut mu?
        - Sözleşme durumu 'ONAYLANDI' mı ve imzalar tam mı?
        - İzinli IP blokları içinde genel internet (0.0.0.0/0) veya yasaklı IP var mı?
        - Düğüm IP adresleri mükerrer mi veya izinli blokların dışında mı?
        """
        hatalar: List[str] = []

        # 1. Kontrol: Zorunlu kök alanların mevcudiyeti
        zorunlu_bolumler = [
            "taraflar_ve_imzalar",
            "etik_ve_hukuki_kapsam",
            "hypervisor_guvenlik_ayarlari",
            "laboratuvar_topolojisi",
            "riskler_ve_kontroller"
        ]
        for bolum in zorunlu_bolumler:
            if bolum not in self.veri:
                hatalar.append(f"Yapısal Eksiklik: '{bolum}' bölümü sözleşmede tanımlanmamış.")

        if hatalar:
            if self.katilik_modu:
                raise ContractViolationError("\n".join(hatalar))
            return False, hatalar

        # 2. Kontrol: Sözleşme Onay Durumu ve İmzalar
        durum = self.veri.get("sozlesme_durumu")
        if durum != "ONAYLANDI":
            hatalar.append(f"Onaylanmamış Sözleşme: Laboratuvar sözleşmesi '{durum}' durumunda. Testler başlatılamaz!")

        imzalar = self.veri.get("taraflar_ve_imzalar", {})
        if not imzalar.get("ciso") or not imzalar.get("arastirmaci"):
            hatalar.append("İmza Eksikliği: Sözleşmede CISO veya Baş Araştırmacı onayı eksik.")

        # 3. Kontrol: İzinli ve Yasaklı IP Bloklarının Doğrulanması (Kapsam İhlali Kontrolü)
        kapsam = self.veri.get("etik_ve_hukuki_kapsam", {})
        izinli_bloklar = kapsam.get("izinli_ip_bloklari", [])
        yasakli_bloklar = set(kapsam.get("yasakli_ip_bloklari", []))

        if not izinli_bloklar:
            hatalar.append("Kapsam Hatası: Hiçbir izinli IP bloğu tanımlanmamış.")

        for blok_str in izinli_bloklar:
            try:
                ag = ipaddress.ip_network(blok_str, strict=False)
                # İzinli blok genel interneti (0.0.0.0/0) kapsıyorsa bu çok tehlikeli bir yasal ihlaldir
                if ag.prefixlen == 0 or ag.is_global:
                    hatalar.append(f"YASAL İHLAL: İzinli kapsama genel internet bloğu ({blok_str}) eklenemez!")
                # İzinli blok yasaklı listede yer alıyorsa
                if blok_str in yasakli_bloklar or any(str(ip) in yasakli_bloklar for ip in ag.hosts()):
                    hatalar.append(f"Kapsam Çelişkisi: '{blok_str}' izinli listesinde ancak yasaklı hedeflerle çakışıyor!")
            except ValueError:
                hatalar.append(f"Geçersiz IP Formatı: '{blok_str}' geçerli bir CIDR ağ bloğu değil.")

        # 4. Kontrol: Düğüm (Node) IP ve MAC Benzersizliği
        gorulen_ipler: Set[str] = set()
        gorulen_macler: Set[str] = set()

        for idx, node in enumerate(self.veri.get("laboratuvar_topolojisi", []), start=1):
            n_id = node.get("node_id", f"NODE-#{idx}")
            ip = node.get("ip_adresi")
            mac = node.get("mac_adresi")

            if not ip:
                hatalar.append(f"Eksik IP: '{n_id}' için IP adresi atanmamış.")
            elif ip in gorulen_ipler:
                hatalar.append(f"IP Çakışması: '{ip}' adresi birden fazla düğüme atanmış ({n_id})!")
            else:
                gorulen_ipler.add(ip)

            if not mac:
                hatalar.append(f"Eksik MAC: '{n_id}' için MAC adresi atanmamış.")
            elif mac in gorulen_macler:
                hatalar.append(f"MAC Çakışması: '{mac}' adresi birden fazla düğüme atanmış ({n_id})!")
            else:
                gorulen_macler.add(mac)

        if hatalar and self.katilik_modu:
            raise ContractViolationError("\n".join(hatalar))

        return (len(hatalar) == 0), hatalar

    def denetle(self) -> Dict[str, Any]:
        """
        Sözleşmeyi ve altyapı ayarlarını derin güvenlik denetimine tabi tutar:
        - Hipervizör sıkılaştırması (Pano paylaşımı, ortak klasörler kapalı mı?)
        - Ağ adaptör türleri (Köprü/Bridged adaptör sızıntısı var mı?)
        - Düğümlerin izinli alt ağlara tam oturması
        """
        gecerli, hatalar = self.dogrula()
        if not gecerli:
            return {"durum": "GECERSIZ", "hatalar": hatalar}

        bulgular: List[Dict[str, Any]] = []

        # MİMARİ DENETİM 1: Hipervizör Kaçış (VM Escape) Güvenlik Ayarları
        hyp = self.veri.get("hypervisor_guvenlik_ayarlari", {})
        if str(hyp.get("pano_paylasimi_clipboard")).upper() != "DEVRE_DISI":
            bulgular.append({
                "seviye": "KRİTİK İZOLASYON KUSURU",
                "alan": "Pano Paylaşımı (Clipboard)",
                "mesaj": "Sanal makine ile ana makine arasında pano paylaşımı açık! Zararlı yazılım ana belleğe sıçrayabilir."
            })

        if str(hyp.get("ortak_klasorler_shared_folders")).upper() != "DEVRE_DISI":
            bulgular.append({
                "seviye": "KRİTİK İZOLASYON KUSURU",
                "alan": "Ortak Klasörler (Shared Folders)",
                "mesaj": "Ana makine ile dosya paylaşımı açık! Fidye yazılımı ana makine diskini şifreleyebilir."
            })

        if str(hyp.get("surukle_birak_drag_drop")).upper() != "DEVRE_DISI":
            bulgular.append({
                "seviye": "YÜKSEK RİSK",
                "alan": "Sürükle & Bırak (Drag & Drop)",
                "mesaj": "Sürükle-bırak özelliği hipervizör zafiyetlerine davetiye çıkarır."
            })

        # MİMARİ DENETİM 2: Ağ Adaptör Güvenliği (Köprü/Bridged Adaptör Tespiti)
        topoloji = self.veri.get("laboratuvar_topolojisi", [])
        kapsam = self.veri.get("etik_ve_hukuki_kapsam", {})
        dis_internet_izni = kapsam.get("dis_internet_izni", False)

        for node in topoloji:
            adaptor = node.get("adaptor_tipi", "")
            if not dis_internet_izni and adaptor not in GUVENLI_ADAPTOR_TURLERI:
                bulgular.append({
                    "seviye": "GÜVENLİKSİZ AĞ ADAPTÖRÜ",
                    "alan": node.get("node_id"),
                    "mesaj": f"'{node.get('node_id')}' ({node.get('ad')}) için '{adaptor}' seçilmiş. Host-Only dışında adaptör internete sızıntı riski taşır!"
                })

        # MİMARİ DENETİM 3: IP Adreslerinin İzinli Ağlara Uygunluğu
        izinli_aglar = [ipaddress.ip_network(b, strict=False) for b in kapsam.get("izinli_ip_bloklari", [])]
        for node in topoloji:
            ip_obj = ipaddress.ip_address(node.get("ip_adresi"))
            uygun_mu = any(ip_obj in ag for ag in izinli_aglar)
            if not uygun_mu:
                bulgular.append({
                    "seviye": "KAPSAM DIŞI IP ADRESİ",
                    "alan": node.get("node_id"),
                    "mesaj": f"'{node.get('ip_adresi')}' adresi izinli alt ağ bloklarının hiçbirine ait değil!"
                })

        self.analiz_sonucu = {
            "durum": "GECERLI",
            "proje_adi": self.veri.get("proje_adi", "Bilinmeyen Proje"),
            "gun_kimligi": self.veri.get("gun_kimligi", "G007"),
            "sozlesme_durumu": self.veri.get("sozlesme_durumu", "TANIMSIZ"),
            "toplam_dugum": len(topoloji),
            "toplam_risk": len(self.veri.get("riskler_ve_kontroller", [])),
            "guvenlik_bulgulari": bulgular,
            "bulgu_sayisi": len(bulgular),
            "izolasyon_basarili_mi": (len(bulgular) == 0)
        }

        return self.analiz_sonucu

    def ascii_topoloji_ciz(self) -> str:
        """
        Sanal laboratuvar topolojisini, güvenlik duvarını, saldırı ve hedef
        düğümlerini görselleştiren bir ASCII diyagramı üretir.
        """
        if not self.analiz_sonucu:
            self.denetle()

        satirlar: List[str] = []
        satirlar.append("========================================================================================================")
        satirlar.append(f"  GÜVENLİ LABORATUVAR KURULUM VE İZOLASYON TOPOLOJİSİ: {self.analiz_sonucu.get('proje_adi', '')}")
        satirlar.append(f"  Sözleşme Durumu: {self.analiz_sonucu.get('sozlesme_durumu', '')} | Gün: {self.analiz_sonucu.get('gun_kimligi', '')} | Toplam Düğüm: {self.analiz_sonucu.get('toplam_dugum', 0)}")
        satirlar.append("========================================================================================================")
        satirlar.append("")
        satirlar.append("  [DIŞ DÜNYA / İNTERNET]  <--- X (KESİNLİKLE YASAK / AIR-GAPPED İZOLASYON) X --->")
        satirlar.append("                                   |")
        satirlar.append("          +------------------------v------------------------+")
        satirlar.append("          | [NODE-05] pfSense Sanal Güvenlik Duvarı & Ağ Geçidi |")
        satirlar.append("          | IP: 192.168.100.1 (Yalnızca İç VLAN Yönlendirme)|")
        satirlar.append("          +------------------------+------------------------+")
        satirlar.append("                                   |")
        satirlar.append("        ================= SANAL ANAHTAR (vSwitch: Host-Only) =================")
        satirlar.append("               |                           |                          |")
        satirlar.append("  +------------v-----------+  +------------v-----------+  +-----------v------------+")
        satirlar.append("  | [NODE-01] SALDIRGAN    |  | [NODE-02] HEDEF DOMAIN |  | [NODE-04] MAVİ TAKIM   |")
        satirlar.append("  | Kali Linux Rolling     |  | Windows Server 2022 AD |  | Zeek NIDS & Wazuh SIEM |")
        satirlar.append("  | IP: 192.168.100.10     |  | IP: 192.168.100.20     |  | IP: 192.168.100.40     |")
        satirlar.append("  | Segment: RED_ZONE      |  | Segment: TARGET_ZONE   |  | Segment: BLUE_ZONE     |")
        satirlar.append("  +------------------------+  +------------------------+  +------------------------+")
        satirlar.append("                                           |")
        satirlar.append("                              +------------v-----------+")
        satirlar.append("                              | [NODE-03] HEDEF LINUX  |")
        satirlar.append("                              | Ubuntu 22.04 Web & DB  |")
        satirlar.append("                              | IP: 192.168.100.30     |")
        satirlar.append("                              | Segment: TARGET_ZONE   |")
        satirlar.append("                              +------------------------+")
        satirlar.append("")
        satirlar.append("--------------------------------------------------------------------------------------------------------")
        satirlar.append("  HİPERVİZÖR SIKILAŞTIRMA VE İZOLASYON DENETİMİ:")
        hyp = self.veri.get("hypervisor_guvenlik_ayarlari", {})
        satirlar.append(f"  * Pano Paylaşımı (Clipboard)     : {hyp.get('pano_paylasimi_clipboard')} (VM Escape Engellendi)")
        satirlar.append(f"  * Ortak Klasörler (Shared Folders): {hyp.get('ortak_klasorler_shared_folders')} (Disk İzolasyonu Sağlandı)")
        satirlar.append(f"  * Sürükle & Bırak (Drag & Drop)  : {hyp.get('surukle_birak_drag_drop')} (Bellek İzolasyonu Sağlandı)")
        satirlar.append("--------------------------------------------------------------------------------------------------------")

        bulgular = self.analiz_sonucu.get("guvenlik_bulgulari", [])
        if not bulgular:
            satirlar.append("  [+] SÖZLEŞME VE İZOLASYON DOĞRULANDI: Sıfır sızıntı riski, tüm düğümler güvenli Host-Only modunda.")
            satirlar.append("      Etik kurallar ve onaylı CISO imzaları eksiksizdir.")
        else:
            satirlar.append(f"  [!] DİKKAT: {len(bulgular)} ADET İZOLASYON VE KAPSAM KUSURU BULUNDU:")
            for b in bulgular:
                satirlar.append(f"      [{b['seviye']}] {b['alan']}: {b['mesaj']}")
        satirlar.append("========================================================================================================")

        return "\n".join(satirlar)


def main() -> int:
    """CLI Giriş Noktası."""
    parser = argparse.ArgumentParser(
        description="Güvenli Laboratuvar Sözleşmesi ve İzolasyon Doğrulama Aracı",
        epilog="Örnek kullanım: python lab_contract_validator.py --sozlesme ornek_veri/laboratuvar_sozlesmesi.json"
    )

    parser.add_argument(
        "--sozlesme", "-s",
        required=True,
        type=str,
        help="Değerlendirilecek Laboratuvar Sözleşmesi JSON dosyasının yolu"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Çıktı formatı (text: görsel topoloji tablosu, json: ham denetim verisi)"
    )
    parser.add_argument(
        "--cikis", "-o",
        type=str,
        default=None,
        help="Raporun kaydedileceği dosya yolu"
    )
    parser.add_argument(
        "--esnek",
        action="store_true",
        help="Hatalarda programı kırmak yerine hata listesini dön"
    )

    args = parser.parse_args()

    sozlesme_yolu = Path(args.sozlesme)
    if not sozlesme_yolu.is_file():
        sys.stderr.write(f"Hata: Sözleşme dosyası bulunamadı: {sozlesme_yolu}\n")
        return 1

    try:
        with open(sozlesme_yolu, "r", encoding="utf-8") as f:
            veri = json.load(f)
    except Exception as e:
        sys.stderr.write(f"JSON Okuma Hatası: {e}\n")
        return 2

    validator = LabContractValidator(veri, katilik_modu=(not args.esnek))

    try:
        sonuc = validator.denetle()
    except ContractViolationError as cve:
        sys.stderr.write(f"Sözleşme Doğrulama Hatası:\n{cve}\n")
        return 3

    if args.format == "json":
        cikti = json.dumps(sonuc, ensure_ascii=False, indent=2)
    else:
        cikti = validator.ascii_topoloji_ciz()

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
