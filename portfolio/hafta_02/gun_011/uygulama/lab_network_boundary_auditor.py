# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 011: Laboratuvar Ağ Sınırları
Uygulama: Laboratuvar Ağ Sınırları ve Bölümleme Denetleyicisi (Lab Network Boundary Auditor)

Bu araç; siber güvenlik analiz, kırmızı takım ve mavi takım laboratuvarlarında:
1. Mikro-segmentasyon ve VLAN izolasyonunu (Karantina, Kırmızı Takım, SOC/SIEM, Yönetim),
2. Karantina bölgesinden (Detonation Zone) dış internete sızıntıyı (Data Exfiltration / C2 Leak),
3. Durum takipli (Statefull Conntrack) güvenlik duvarı ve tersine kabuk (Reverse Shell) engellerini,
4. DNS Sinkhole ve sahte ağ yönlendirme mekanizmalarını
NIST SP 800-115 ve CIS Network Segmentation standartlarında denetler ve güvenli iptables kuralları üretir.
"""

# Standart kütüphaneler içe aktarılıyor
import os
import sys
import json
import argparse
from typing import Dict, List, Any, Tuple


class NetworkBoundaryValidationError(Exception):
    """
    Laboratuvar ağ topolojisi ve güvenlik duvarı kural seti
    şematik veya mantıksal bir kural dışılık içerdiğinde fırlatılan özel hata sınıfı.
    """
    pass


class LabNetworkBoundaryAuditor:
    """
    Laboratuvar Ağ Sınırları ve İzolasyon Denetim Motoru.
    """

    def __init__(self, topoloji_dosya_yolu: str):
        """
        Denetleyici sınıf başlatıcısı.
        
        Args:
            topoloji_dosya_yolu: İncelenecek laboratuvar ağ topolojisi JSON dosyasının yolu.
        """
        # Dosya yolunu sınıf değişkenine kaydet
        self.topoloji_dosya_yolu = topoloji_dosya_yolu
        # Bellekte tutulacak topoloji verisi için başlangıç sözlüğü
        self.topoloji_verisi: Dict[str, Any] = {}
        # Dosyayı oku ve JSON sözdizimini doğrula
        self.topolojiyi_yukle()

    def topolojiyi_yukle(self) -> None:
        """
        Topoloji dosyasını diskten okur ve temel şema geçerliliğini doğrular.
        """
        # 1. Dosyanın disk üzerinde var olduğunu kontrol et
        if not os.path.exists(self.topoloji_dosya_yolu):
            raise FileNotFoundError(f"Topoloji dosyası bulunamadı: {self.topoloji_dosya_yolu}")

        # 2. Dosyayı UTF-8 karakter kodlamasıyla oku ve JSON olarak ayrıştır
        try:
            with open(self.topoloji_dosya_yolu, "r", encoding="utf-8") as dosya:
                self.topoloji_verisi = json.load(dosya)
        except json.JSONDecodeError as json_hatasi:
            raise NetworkBoundaryValidationError(f"Geçersiz JSON sözdizimi: {str(json_hatasi)}")

        # 3. Kök nesnenin sözlük olduğunu ve 'ag_topolojileri' listesini içerdiğini doğrula
        if not isinstance(self.topoloji_verisi, dict) or "ag_topolojileri" not in self.topoloji_verisi:
            raise NetworkBoundaryValidationError("Topoloji dosyası geçerli bir 'ag_topolojileri' listesi içermelidir.")

        # 4. 'ag_topolojileri' alanının liste olduğunu doğrula
        if not isinstance(self.topoloji_verisi["ag_topolojileri"], list):
            raise NetworkBoundaryValidationError("'ag_topolojileri' alanı bir dizi (list) olmalıdır.")

    def denetle_topoloji(self, topoloji: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tek bir laboratuvar ağ topolojisini derinlemesine inceler ve güvenlik risklerini puanlar.
        
        Args:
            topoloji: İncelenecek ağ topolojisi yapılandırma sözlüğü.
            
        Returns:
            Denetim sonuçları, bulunan sızıntı vektörleri, güvenlik skoru ve nihai durum.
        """
        # Şema geçerliliğini kontrol et
        self._dogrula_topoloji_semasi(topoloji)

        # Bulguları saklamak için dinamik liste
        bulgular: List[Dict[str, Any]] = []

        # 1. Ağ Segmentasyonu ve Bölge Ayrıştırması (VLAN & Subnets)
        bulgular.extend(self._denetle_ag_segmentasyonu(topoloji))

        # 2. Karantina / Patlatma Bölgesi Sızıntı Denetimi (Internet & DNS)
        bulgular.extend(self._denetle_karantina_sizintisi(topoloji))

        # 3. Güvenlik Duvarı Yönlendirme Politikası (Forwarding & Conntrack)
        bulgular.extend(self._denetle_guvenlik_duvari_politikasi(topoloji))

        # 4. Bölgeler Arası Çift Yönlü Trafik ve Tersine Kabuk (Reverse Shell) Kuralları
        bulgular.extend(self._denetle_bolgeler_arasi_kurallar(topoloji))

        # Güvenlik skorunu ve risk derecesini hesapla
        skor, risk_derecesi = self._hesapla_guvenlik_skoru(bulgular)

        return {
            "topoloji_id": topoloji.get("topoloji_id"),
            "topoloji_adi": topoloji.get("topoloji_adi"),
            "mimari_tipi": topoloji.get("mimari_tipi"),
            "guvenlik_seviyesi": topoloji.get("guvenlik_seviyesi"),
            "skor": skor,
            "risk_derecesi": risk_derecesi,
            "toplam_bulgu_sayisi": len(bulgular),
            "bulgular": bulgular
        }

    def _dogrula_topoloji_semasi(self, topoloji: Dict[str, Any]) -> None:
        """
        Topoloji sözlüğünde bulunması gereken zorunlu alanları doğrular.
        """
        zorunlu_alanlar = [
            "topoloji_id", "topoloji_adi", "mimari_tipi",
            "guvenlik_seviyesi", "ag_bolgeleri", "guvenlik_duvari_politikasi"
        ]
        for alan in zorunlu_alanlar:
            if alan not in topoloji:
                raise NetworkBoundaryValidationError(f"Ağ topolojisinde zorunlu '{alan}' alanı eksik!")

    def _denetle_ag_segmentasyonu(self, topoloji: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Ağın düz (flat) olup olmadığını ve mikro-segmentasyon kurallarını inceler.
        """
        bulgular = []
        bolgeler = topoloji.get("ag_bolgeleri", [])

        # KONTROL 1: Düz Ağ (Flat Network) Felaketi
        # Tüm kurbanlar, saldırganlar ve izleme sunucuları aynı alt ağdaysa ARP zehirlenmesi ve yayılma kaçınılmazdır!
        if len(bolgeler) < 3:
            bulgular.append({
                "kategori": "AG_SEGMENTASYONU",
                "seviye": "YUKSEK",
                "ceza_puani": 25,
                "baslik": "Yetersiz Ağ Segmentasyonu (Düz Ağ Riski)",
                "detay": f"Topolojide yalnızca {len(bolgeler)} adet bölge tanımlı. Güvenli bir lab en az Karantina, Saldırgan ve SOC/SIEM bölgelerini ayrı VLAN'larda tutmalıdır.",
                "cozum": "Ağı mikro-segmentlere ayırın (VLAN 10: Saldırgan, VLAN 66: Karantina, VLAN 20: SOC/SIEM)."
            })

        # KONTROL 2: Çakışan Alt Ağlar veya Geçersiz CIDR
        cidrs = set()
        for b in bolgeler:
            c = b.get("alt_ag_cidr")
            if c in cidrs:
                bulgular.append({
                    "kategori": "AG_SEGMENTASYONU",
                    "seviye": "KRITIK",
                    "ceza_puani": 30,
                    "baslik": f"Çakışan Alt Ağ CIDR Tanımı: {c}",
                    "detay": "Farklı güvenlik bölgelerine aynı alt ağ CIDR bloğu atanmış, yönlendirme sınırları çöker.",
                    "cozum": "Her güvenlik bölgesi için benzersiz bir IP alt ağı tahsis edin."
                })
            cidrs.add(c)

        return bulgular

    def _denetle_karantina_sizintisi(self, topoloji: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Karantina / Patlatma (Detonation) bölgesinin dış internete sızıntı ve DNS açıklarını denetler.
        """
        bulgular = []
        bolgeler = topoloji.get("ag_bolgeleri", [])

        for b in bolgeler:
            rol = b.get("rol", "").lower()
            bolge_id = b.get("bolge_id", "")
            internet = b.get("internet_cikis_izni", False)
            dns_sinkhole = b.get("dns_sinkhole_etkin", False)
            genel_dns_engel = b.get("harici_genel_dns_engelli", True)

            # KONTROL 1: Karantina Bölgesinde Doğrudan İnternet Çıkışı
            # Zararlı yazılım analizi yapılan bir ağdan internete doğrudan paket çıkması BSL-4 ihlalidir!
            if ("karantina" in rol or "detonation" in bolge_id.lower() or "kurban" in rol) and internet is True:
                bulgular.append({
                    "kategori": "KARANTINA_SIZINTISI",
                    "seviye": "FELAKET",
                    "ceza_puani": 50,
                    "baslik": f"Ölümcül Sızıntı: Karantina Bölgesinde Açık İnternet Erişimi ({bolge_id})",
                    "detay": "Karantina altındaki zararlı yazılım dış C2 sunucularına veri sızdırabilir veya internetteki sistemlere saldırabilir.",
                    "cozum": "Karantina bölgesinin varsayılan ağ geçidinden internete (0.0.0.0/0) çıkış rotasını tamamen kaldırın."
                })

            # KONTROL 2: Harici Genel DNS'e Erişim İzni (DNS Tünelleme / Bilgi Sızıntısı)
            if ("karantina" in rol or "detonation" in bolge_id.lower()) and not genel_dns_engel:
                bulgular.append({
                    "kategori": "KARANTINA_SIZINTISI",
                    "seviye": "YUKSEK",
                    "ceza_puani": 20,
                    "baslik": f"Karantina Bölgesinde Harici DNS Sorguları İzinli ({bolge_id})",
                    "detay": "Zararlı yazılım 8.8.8.8 veya 1.1.1.1 üzerinden DNS Tünelleme (DNSCat2) yaparak veri kaçırabilir.",
                    "cozum": "Dış DNS sunucularına giden 53 portunu engelleyin ve DNS Sinkhole kurun."
                })

            # KONTROL 3: DNS Sinkhole Eksikliği
            if ("karantina" in rol or "detonation" in bolge_id.lower()) and not dns_sinkhole:
                bulgular.append({
                    "kategori": "KARANTINA_SIZINTISI",
                    "seviye": "ORTA",
                    "ceza_puani": 15,
                    "baslik": f"DNS Sinkhole / Sahte Yanıtlayıcı Tanımsız ({bolge_id})",
                    "detay": "Zararlı yazılım alan adı çözümleyemediği için çalışmayı durdurabilir ve analiz yarıda kalabilir.",
                    "cozum": "İç ağda sahte DNS yanıtı veren INetSim veya FakeNet gibi bir sinkhole servisi konumlandırın."
                })

        return bulgular

    def _denetle_guvenlik_duvari_politikasi(self, topoloji: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Güvenlik duvarının varsayılan yönlendirme ve durum takip (conntrack) politikalarını denetler.
        """
        bulgular = []
        fw = topoloji.get("guvenlik_duvari_politikasi", {})

        forward = str(fw.get("varsayilan_forward_eylemi", "ACCEPT")).upper()
        conntrack = fw.get("statefull_conntrack_aktif", False)
        yeni_baglanti_engeli = fw.get("kurbandan_disariya_yeni_baglanti_engeli", False)

        # KONTROL 1: Varsayılan Forward Politikası
        # Güvenlik duvarının temel ilkesi: 'FORWARD DROP'. Eğer ACCEPT ise tüm bölgeler birbirine akar!
        if forward != "DROP":
            bulgular.append({
                "kategori": "GUVENLIK_DUVARI",
                "seviye": "KRITIK",
                "ceza_puani": 35,
                "baslik": "Varsayılan FORWARD Eylemi 'DROP' Değil (Açık Geçiş)",
                "detay": f"Güvenlik duvarı bölgeler arası geçişi varsayılan olarak engellememektedir ({forward}).",
                "cozum": "'iptables -P FORWARD DROP' politikasını uygulayın."
            })

        # KONTROL 2: Durum Takibi (Statefull Conntrack) Eksikliği
        if not conntrack:
            bulgular.append({
                "kategori": "GUVENLIK_DUVARI",
                "seviye": "KRITIK",
                "ceza_puani": 30,
                "baslik": "Durum Takipli Güvenlik Duvarı (Statefull Conntrack) Devre Dışı",
                "detay": "Bağlantı durumları (NEW, ESTABLISHED, RELATED) izlenmemektedir. Tersine kabuk (reverse shell) paketleri filtrelenemez.",
                "cozum": "iptables state / conntrack modülünü etkinleştirin."
            })

        # KONTROL 3: Kurbandan Dışarıya Yeni Bağlantı Başlatma İzni
        if not yeni_baglanti_engeli:
            bulgular.append({
                "kategori": "GUVENLIK_DUVARI",
                "seviye": "KRITIK",
                "ceza_puani": 30,
                "baslik": "Kurban Bölgesinden Başlatılan Yeni (NEW) Bağlantılar Engellenmemiş",
                "detay": "Kurban makine ele geçirildiğinde saldırgan veya konak makineye doğru tersine kabuk (Reverse Shell) başlatabilir.",
                "cozum": "Kurban bölgesinden çıkan paketlerde yalnızca 'ESTABLISHED,RELATED' durumlarına izin verin; 'NEW' paketleri düşürün."
            })

        return bulgular

    def _denetle_bolgeler_arasi_kurallar(self, topoloji: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Bölgeler arası tanımlanmış spesifik güvenlik duvarı kurallarını ve tersine bağlantı açıklarını denetler.
        """
        bulgular = []
        fw = topoloji.get("guvenlik_duvari_politikasi", {})
        kurallar = fw.get("bolgeler_arasi_kurallar", [])

        for k in kurallar:
            kaynak = k.get("kaynak_bolge", "")
            hedef = k.get("hedef_bolge", "")
            eylem = str(k.get("eylem", "DROP")).upper()
            durum = str(k.get("durum_takibi", "")).upper()

            # KONTROL 1: Karantinadan İnternete veya Her Yere (ANY) İzin Kuralı
            if ("detonation" in kaynak.lower() or "flat" in kaynak.lower()) and hedef.upper() in ["INTERNET", "ANY", "0.0.0.0/0"] and eylem == "ACCEPT":
                bulgular.append({
                    "kategori": "KURAL_MATRISI",
                    "seviye": "FELAKET",
                    "ceza_puani": 50,
                    "baslik": f"Güvensiz Geniş İzin Kuralı: {k.get('kural_id')}",
                    "detay": f"Karantina bölgesinden dış internete ({hedef}) doğrudan trafik geçişine izin verilmiş.",
                    "cozum": "Bu kuralı derhal silin; karantina asla genel internete erişemez."
                })

            # KONTROL 2: Kurbandan Saldırgana Yeni (NEW) Bağlantı İzni (Tersine Kabuk Açığı)
            if "detonation" in kaynak.lower() and "attacker" in hedef.lower() and eylem == "ACCEPT" and "NEW" in durum:
                bulgular.append({
                    "kategori": "KURAL_MATRISI",
                    "seviye": "KRITIK",
                    "ceza_puani": 30,
                    "baslik": f"Kurbandan Saldırgana Tersine Bağlantı İzni: {k.get('kural_id')}",
                    "detay": "Kurban makinenin saldırgan düğümüne yeni bağlantı açmasına izin verilmiş. Saldırgan reverse shell yakalayabilir.",
                    "cozum": "Durum takibini yalnızca 'ESTABLISHED,RELATED' ile sınırlandırın."
                })

        return bulgular

    def _hesapla_guvenlik_skoru(self, bulgular: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Ceza puanlarını düşerek 100 üzerinden nihai skoru üretir.
        """
        toplam_ceza = sum(b.get("ceza_puani", 0) for b in bulgular)
        skor = max(0, 100 - toplam_ceza)

        if skor >= 90:
            risk = "GÜVENLİ (MİKRO-SEGMENTE İZOLE LAB)"
        elif skor >= 70:
            risk = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        elif skor >= 40:
            risk = "YÜKSEK RİSK (SIZINTI TEHLİKESİ)"
        else:
            risk = "KRİTİK FELAKET (ACİL MÜDAHALE GEREKLİ)"

        return skor, risk

    def denetle_tumunu(self) -> List[Dict[str, Any]]:
        """
        Dosyadaki tüm topolojileri sırayla denetler.
        """
        sonuclar = []
        for t in self.topoloji_verisi.get("ag_topolojileri", []):
            sonuc = self.denetle_topoloji(t)
            sonuclar.append(sonuc)
        return sonuclar

    def urete_iptables_kurallari(self, topoloji_id: str, cikis_dosya_yolu: str) -> str:
        """
        Hedef topoloji için kurumsal standartlarda sertleştirilmiş iptables bash betiği üretir.
        """
        script = """#!/bin/bash
# ==============================================================================
# KURUMSAL LABORATUVAR AĞ SINIRLARI VE GÜVENLİK DUVARI KURAL SETİ (IPTABLES)
# Üretici: Lab Network Boundary Auditor | (c) 2026 Seydi Eryılmaz (@seydivakkas)
# ==============================================================================

# 1. Mevcut tüm kuralları ve zincirleri temizle
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# 2. Varsayılan Güvenlik Politikaları (Açıkça izin verilmeyen her şey YASAKTIR)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Yerel döngü (Loopback) trafiğine izin ver
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 4. Karantina Bölgesi (VLAN 66 - 192.168.66.0/24) DNS Sinkhole Yönlendirmesi
# Tüm DNS sorgularını yerel INetSim sahte sunucusuna yönlendir (Dış DNS sızıntısını önle)
iptables -t nat -A PREROUTING -s 192.168.66.0/24 -p udp --dport 53 -j DNAT --to-destination 192.168.66.2:53
iptables -t nat -A PREROUTING -s 192.168.66.0/24 -p tcp --dport 53 -j DNAT --to-destination 192.168.66.2:53

# 5. Kırmızı Takım (VLAN 10) -> Karantina (VLAN 66) İzinli Test Trafiği
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.66.0/24 -p tcp -m multiport --dports 80,443,445,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

# 6. Karantina (VLAN 66) -> Kırmızı Takım (VLAN 10) Geri Dönüş Trafiği
# Kurban yalnızca başlatılan oturumlara yanıt verebilir; YENİ (NEW) tersine kabuk başlatamaz!
iptables -A FORWARD -s 192.168.66.0/24 -d 192.168.10.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# 7. Karantina (VLAN 66) -> Mavi Takım / SIEM (VLAN 20) Telemetri ve Log Gönderimi
iptables -A FORWARD -s 192.168.66.0/24 -d 192.168.20.0/24 -p udp -m multiport --dports 514,1514 -m state --state NEW,ESTABLISHED -j ACCEPT

# 8. Karantinadan Dış İnternete Çıkışı KESİNLİKLE ENGELLE (Logla ve Düşür)
iptables -A FORWARD -s 192.168.66.0/24 -o eth0 -j LOG --log-prefix "[LAB-SIZINTI-ENGELI]: "
iptables -A FORWARD -s 192.168.66.0/24 -o eth0 -j DROP

echo "[+] Laboratuvar ağ sınırları ve güvenlik duvarı kuralları başarıyla devreye alındı."
"""
        with open(cikis_dosya_yolu, "w", encoding="utf-8") as dosya:
            dosya.write(script)
        return cikis_dosya_yolu

    def rapor_olustur_metin(self, sonuclar: List[Dict[str, Any]]) -> str:
        """
        Denetim sonuçlarını terminalde insan tarafından okunabilir zengin rapor formatında biçimlendirir.
        """
        satirlar = []
        satirlar.append("=" * 80)
        satirlar.append("   LABORATUVAR AĞ SINIRLARI VE BÖLÜMLEME DENETİM RAPORU")
        satirlar.append("=" * 80)
        satirlar.append(f"İncelenen Dosya: {self.topoloji_dosya_yolu}")
        satirlar.append(f"Toplam Topoloji Sayısı: {len(sonuclar)}")
        satirlar.append("-" * 80)

        for sonuc in sonuclar:
            satirlar.append(f"\n[+] TOPOLOJİ ID: {sonuc['topoloji_id']} | Adı: {sonuc['topoloji_adi']}")
            satirlar.append(f"    Mimari Tipi       : {sonuc['mimari_tipi']}")
            satirlar.append(f"    Güvenlik Seviyesi : {sonuc['guvenlik_seviyesi']}")
            satirlar.append(f"    Güvenlik Skoru    : {sonuc['skor']}/100")
            satirlar.append(f"    Risk Durumu       : {sonuc['risk_derecesi']}")
            satirlar.append(f"    Toplam Bulgu      : {sonuc['toplam_bulgu_sayisi']}")

            if sonuc["toplam_bulgu_sayisi"] == 0:
                satirlar.append("    -> TEBRİKLER: Sıfır güvenlik açığı! Tam mikro-segmente ve sızıntısız laboratuvar ağı.")
            else:
                satirlar.append("    -> TESPİT EDİLEN RİSK VE ZAFİYETLER:")
                for b in sonuc["bulgular"]:
                    satirlar.append(f"       * [{b['seviye']}] {b['baslik']} (-{b['ceza_puani']} Puan)")
                    satirlar.append(f"         Kategori: {b['kategori']}")
                    satirlar.append(f"         Risk    : {b['detay']}")
                    satirlar.append(f"         Çözüm   : {b['cozum']}")

        satirlar.append("\n" + "=" * 80)
        satirlar.append("Denetim Bitti. Tüm hakları saklıdır (c) 2026 Seydi Eryılmaz.")
        satirlar.append("=" * 80)
        return "\n".join(satirlar)


def main():
    """
    Komut satırı arayüzü (CLI) giriş noktası.
    """
    ayristirici = argparse.ArgumentParser(
        description="Laboratuvar Ağ Sınırları ve Bölümleme Denetleyicisi (Lab Network Boundary Auditor)"
    )
    ayristirici.add_argument(
        "--topology",
        required=True,
        help="İncelenecek laboratuvar ağ topolojisi JSON dosyasının yolu"
    )
    ayristirici.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Çıktı formatı: 'table' (varsayılan) veya 'json'"
    )
    ayristirici.add_argument(
        "--topology-id",
        required=False,
        default=None,
        help="Yalnızca belirli bir Topoloji ID'sini denetlemek için filtre"
    )
    ayristirici.add_argument(
        "--generate-iptables",
        help="Belirtilen dosya yoluna sertleştirilmiş iptables kural betiği üret"
    )

    argumanlar = ayristirici.parse_args()

    try:
        motor = LabNetworkBoundaryAuditor(argumanlar.topology)
        sonuclar = motor.denetle_tumunu()

        # Filtre varsa uygula
        if argumanlar.topology_id:
            sonuclar = [s for s in sonuclar if s["topoloji_id"] == argumanlar.topology_id]
            if not sonuclar:
                print(f"[!] Belirtilen Topoloji ID bulunamadı: {argumanlar.topology_id}", file=sys.stderr)
                sys.exit(1)

        # iptables kuralı üretme talebi varsa işlet
        if argumanlar.generate_iptables:
            hedef_id = argumanlar.topology_id or sonuclar[0]["topoloji_id"]
            yol = motor.urete_iptables_kurallari(hedef_id, argumanlar.generate_iptables)
            print(f"[+] Sertleştirilmiş iptables kural betiği başarıyla üretildi: {yol}")

        # Çıktıyı yazdır
        if argumanlar.format == "json":
            print(json.dumps(sonuclar, indent=2, ensure_ascii=False))
        else:
            print(motor.rapor_olustur_metin(sonuclar))

        # Kritik veya felaket riski varsa çıkış kodu 2 olsun
        herhangi_bir_felaket = any(
            any(b["seviye"] in ["KRITIK", "FELAKET"] for b in s["bulgular"])
            for s in sonuclar
        )
        if herhangi_bir_felaket:
            sys.exit(2)
        else:
            sys.exit(0)

    except Exception as hata:
        print(f"[HATA] Ağ sınırları denetimi başarısız oldu: {str(hata)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
