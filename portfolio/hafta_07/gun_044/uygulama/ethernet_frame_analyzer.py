# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G044: Ethernet, MAC ve Çerçeve Yapısı Analiz ve Doğrulama Motoru.

Bu modül, Katman 2 (Veri Bağlantısı Katmanı) seviyesinde taşınan Ethernet II ve IEEE 802.1Q
çerçevelerini ayrıştırır; MAC adreslerinin tekil/çoklu yayın (I/G) ve evrensel/yerel (U/L)
bitlerini, EtherType protokol kodlarını, asgari çerçeve boyutu dolgulamalarını ve
güvenlik anomalilerini (örn: kaynak MAC'in multicast olması) denetler.
"""

# Dosya yolu ve işletim sistemi ortamı işlemleri için os modülünü yüklüyoruz.
import os
# Komut satırı argümanlarını (CLI) yönetmek amacıyla argparse kütüphanesini dahil ediyoruz.
import argparse
# JSON verilerini okuma ve serileştirme işlemleri için json modülünü kullanıyoruz.
import json
# Çıktı yönlendirmesi ve hata kodları için sys modülünü çağırıyoruz.
import sys
# Tip güvenliği ve statik analiz için typing kütüphanesinden tipleri alıyoruz.
from typing import Dict, Any, List, Tuple, Optional
# Zaman damgalı denetim raporları oluşturmak için datetime ve timezone sınıflarını dahil ediyoruz.
from datetime import datetime, timezone
# Adres ve hex format doğrulamalarında regex kullanımı için re modülünü yüklüyoruz.
import re

# Standart Ethernet Çerçevesi Asgari Boyutu (14 bayt başlık + 46 bayt veri/dolgu + 4 bayt FCS = 64 bayt)
MIN_ETHERNET_FRAME_SIZE = 64

# Standart Ethernet Çerçevesi Azami Boyutu (VLAN etiketsiz standart MTU 1500 + 18 bayt başlık/FCS = 1518 bayt)
MAX_STANDARD_FRAME_SIZE = 1518

# 802.1Q VLAN Etiketli Azami Çerçeve Boyutu (1522 bayt)
MAX_VLAN_FRAME_SIZE = 1522

# MAC Adresi Regex Deseni (6 bayt onaltılık, iki nokta veya tire ayrılmış)
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

# EtherType 16-bit Onaltılık Biçim Deseni (örn: 0x0800, 0x0806, 0x86dd)
ETHERTYPE_REGEX = re.compile(r"^0x[0-9A-Fa-f]{4}$")

# Yaygın Bilinen EtherType Protokol Tanımları Sözlüğü
KNOWN_ETHERTYPES: Dict[str, str] = {
    "0x0800": "IPv4 (Internet Protocol Version 4)",
    "0x0806": "ARP (Address Resolution Protocol)",
    "0x86dd": "IPv6 (Internet Protocol Version 6)",
    "0x8100": "IEEE 802.1Q (VLAN Tagged Frame)",
    "0x88cc": "LLDP (Link Layer Discovery Protocol)",
    "0x888e": "EAP over LAN (IEEE 802.1X Port Authentication)"
}

# Yaygın Sanallaştırma ve Donanım Üreticisi OUI (Organizationally Unique Identifier) Örnekleri
KNOWN_OUIS: Dict[str, str] = {
    "00:50:56": "VMware Inc. (Virtual NIC / Gateway)",
    "00:0C:29": "VMware Inc. (Auto-generated Virtual Machine)",
    "00:15:5D": "Microsoft Corporation (Hyper-V)",
    "08:00:27": "PCS Systemtechnik GmbH (VirtualBox)",
    "52:54:00": "QEMU / KVM Virtual Machine",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd"
}


class EthernetFrameError(ValueError):
    """Ethernet çerçeve şeması, MAC biçimi veya protokol kural ihlallerinde fırlatılan özel istisna sınıfı."""
    # ValueError'dan türeyen özel çerçeve analiz hatası.
    pass


def validate_mac_address_format(mac_str: str) -> bool:
    """
    Bir MAC adresinin 6 baytlık geçerli onaltılık biçimde olduğunu doğrular.
    
    Argümanlar:
        mac_str: Kontrol edilecek MAC metni.
        
    Döndürür:
        Geçerli ise True, aksi halde False.
    """
    # Tip ve boşluk kontrolü.
    if not isinstance(mac_str, str) or not mac_str.strip():
        # Geçersiz.
        return False
    # Regex şablonuna uyumu sınıyoruz.
    return bool(MAC_REGEX.match(mac_str.strip()))


def validate_ethertype_format(ethertype_str: str) -> bool:
    """
    EtherType alanının geçerli bir 16-bit '0xXXXX' onaltılık formatında olduğunu doğrular.
    
    Argümanlar:
        ethertype_str: Kontrol edilecek EtherType dizisi.
        
    Döndürür:
        Geçerli ise True, aksi halde False.
    """
    # Tip ve boşluk kontrolü.
    if not isinstance(ethertype_str, str) or not ethertype_str.strip():
        # Geçersiz.
        return False
    # Regex kontrolünü icra ediyoruz.
    return bool(ETHERTYPE_REGEX.match(ethertype_str.strip()))


def analyze_mac_address(mac_str: str, is_source: bool = False) -> Dict[str, Any]:
    """
    Bir MAC adresini bit seviyesinde ayrıştırarak I/G, U/L, yayın türü ve OUI bilgilerini çıkarır.
    
    Argümanlar:
        mac_str: Doğrulanmış MAC adresi.
        is_source: Bu adresin çerçevede 'kaynak' olarak kullanılıp kullanılmadığı bayrağı.
        
    Döndürür:
        Ayrıntılı MAC analiz sözlüğü.
    """
    # İki nokta ve tireleri standart iki noktaya dönüştürüp büyük harfe alıyoruz.
    normalized = mac_str.strip().replace("-", ":").upper()
    # Oktetleri ayırıyoruz.
    octets = normalized.split(":")
    
    # İlk okteti tam sayıya çeviriyoruz (Bit kontrolleri için).
    first_byte = int(octets[0], 16)
    
    # Bit 0: Individual / Group (I/G) biti (0 = Unicast, 1 = Multicast/Broadcast).
    is_group = bool(first_byte & 0x01)
    
    # Bit 1: Universal / Local (U/L) biti (0 = Globally Unique / OUI, 1 = Locally Administered).
    is_local = bool(first_byte & 0x02)
    
    # Broadcast kontrolü (Tüm oktetler FF mi?).
    is_broadcast = (normalized == "FF:FF:FF:FF:FF:FF")
    
    # İletim türünü belirliyoruz.
    if is_broadcast:
        # Genel yayın (Broadcast).
        cast_type = "BROADCAST (Genel Yayın - Tüm Düğümler)"
    elif is_group:
        # Çok noktaya yayın (Multicast).
        cast_type = "MULTICAST (Çok Noktaya Yayın)"
    else:
        # Tek noktaya yayın (Unicast).
        cast_type = "UNICAST (Tek Noktaya Yayın)"
        
    # Yönetim türü (Evrensel vs Yerel).
    admin_type = "Locally Administered (Yerel Tanımlı)" if is_local else "Universally Administered (IEEE OUI Tescilli)"
    
    # Kaynak MAC adresinde Multicast/Broadcast bulunması kural ihlalidir (IEEE 802.3 Standardı).
    if is_source and is_group:
        # Güvenlik ve protokol ihlali istisnası üretiyoruz.
        raise EthernetFrameError(
            f"Protokol İhlali: Kaynak MAC adresi ({normalized}) Multicast veya Broadcast olamaz! (I/G biti = 1)"
        )
        
    # İlk 3 oktetten OUI önekini alıyoruz (Örn: '00:50:56').
    oui_prefix = f"{octets[0]}:{octets[1]}:{octets[2]}"
    # Bilinen üreticiyi arıyoruz.
    vendor = KNOWN_OUIS.get(oui_prefix, "Bilinmeyen / Özel Üretici")
    
    # Analiz sonuçlarını derliyoruz.
    return {
        "mac_address": normalized,
        "first_octet_hex": f"0x{octets[0]}",
        "ig_bit_group": is_group,
        "ul_bit_local": is_local,
        "cast_type": cast_type,
        "admin_type": admin_type,
        "oui_prefix": oui_prefix,
        "vendor": vendor
    }


def dissect_single_ethernet_frame(frame: Dict[str, Any], index: int) -> Dict[str, Any]:
    """
    Tekil bir Ethernet çerçevesini doğrular ve tüm başlık alanlarını detaylı olarak etiketler.
    
    Argümanlar:
        frame: Çerçeve sözlüğü.
        index: Listedeki sıra numarası.
        
    Döndürür:
        Etiketlenmiş çerçeve analiz sözlüğü.
    """
    # Çerçevenin sözlük olduğunu teyit ediyoruz.
    if not isinstance(frame, dict):
        # Sözlük değilse hata fırlatıyoruz.
        raise EthernetFrameError(f"Çerçeve #{index} bir JSON sözlüğü olmalıdır, alınan: {type(frame).__name__}")
        
    # Zorunlu alanların mevcudiyetini kontrol ediyoruz.
    for required_key in ["destination_mac", "source_mac", "ethertype"]:
        # Alan kontrolü yapıyoruz.
        if required_key not in frame:
            # Eksik alan hatası.
            raise EthernetFrameError(f"Çerçeve #{index} içinde zorunlu '{required_key}' alanı eksik.")
            
    # Hedef MAC adresi biçimini denetliyoruz.
    dst_mac = str(frame["destination_mac"])
    # Format geçerlilik kontrolü.
    if not validate_mac_address_format(dst_mac):
        # Hata üretiyoruz.
        raise EthernetFrameError(f"Çerçeve #{index} hedef MAC adresi geçersiz: '{dst_mac}'")
        
    # Kaynak MAC adresi biçimini denetliyoruz.
    src_mac = str(frame["source_mac"])
    # Format kontrolü.
    if not validate_mac_address_format(src_mac):
        # Hata fırlatıyoruz.
        raise EthernetFrameError(f"Çerçeve #{index} kaynak MAC adresi geçersiz: '{src_mac}'")
        
    # Hedef MAC adresini analiz ediyoruz (Kaynak değildir).
    dst_analysis = analyze_mac_address(dst_mac, is_source=False)
    # Kaynak MAC adresini analiz ediyoruz (Kaynak kuralı devrededir).
    src_analysis = analyze_mac_address(src_mac, is_source=True)
    
    # EtherType formatını sınıyoruz.
    eth_type = str(frame["ethertype"]).lower()
    # Format doğrulaması.
    if not validate_ethertype_format(eth_type):
        # Hata veriyoruz.
        raise EthernetFrameError(f"Çerçeve #{index} geçersiz EtherType formatı: '{eth_type}'. Beklenen: 0xXXXX")
        
    # EtherType protokol adını sözlükten alıyoruz.
    protocol_desc = KNOWN_ETHERTYPES.get(eth_type, "Bilinmeyen / Özel Protokol")
    
    # Çerçeve boyutu alanlarını alıyoruz.
    payload_size = frame.get("payload_size_bytes", 0)
    # Dolgu baytları.
    padding_size = frame.get("padding_bytes", 0)
    # Toplam boyut.
    total_size = frame.get("total_frame_size", 0)
    
    # Asgari boyut kontrolü (64 bayt).
    if total_size < MIN_ETHERNET_FRAME_SIZE:
        # 64 baytın altındaki çerçeveler Runt Frame olarak adlandırılır ve ağda hatalıdır.
        raise EthernetFrameError(
            f"Çerçeve #{index} boyutu ({total_size} bayt) Ethernet asgari sınırı olan {MIN_ETHERNET_FRAME_SIZE} baytın altındadır (Runt Frame)!"
        )
        
    # VLAN etiketi kontrolü.
    is_vlan = frame.get("vlan_tagged", False)
    # VLAN ID değeri.
    vlan_id = frame.get("vlan_id", None)
    
    # Etiketlenmiş çerçeve yapısını derliyoruz.
    return {
        "frame_id": frame.get("frame_id", f"ETH-{index:03d}"),
        "frame_type": frame.get("frame_type", "Ethernet II"),
        "description": frame.get("description", "Ağ Trafik Çerçevesi"),
        "destination": dst_analysis,
        "source": src_analysis,
        "ethertype": eth_type,
        "protocol_name": protocol_desc,
        "vlan_tagged": is_vlan,
        "vlan_id": vlan_id,
        "payload_size_bytes": payload_size,
        "padding_bytes": padding_size,
        "total_frame_size": total_size,
        "fcs_crc32": frame.get("fcs_crc32", "0x00000000")
    }


def analyze_ethernet_dataset(dataset: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Bir veri setindeki tüm Ethernet çerçevelerini ayrıştırır ve doğruluk denetiminden geçirir.
    
    Argümanlar:
        dataset: Kök JSON veri seti.
        
    Döndürür:
        Ayrıştırılmış çerçeveler listesi.
    """
    # Kök sözlük denetimi.
    if not isinstance(dataset, dict):
        # Hata fırlatıyoruz.
        raise EthernetFrameError("Veri seti kök elemanı bir JSON sözlüğü olmalıdır.")
        
    # 'frames' anahtarının varlığını kontrol ediyoruz.
    if "frames" not in dataset or not isinstance(dataset["frames"], list):
        # Hata üretiyoruz.
        raise EthernetFrameError("Veri setinde 'frames' listesi bulunamadı.")
        
    # Sonuç listesini başlatıyoruz.
    results: List[Dict[str, Any]] = []
    
    # Çerçeveleri döngü ile geziyoruz.
    for idx, f_item in enumerate(dataset["frames"], start=1):
        # Ayrıştırma fonksiyonunu çağırıyoruz.
        parsed = dissect_single_ethernet_frame(f_item, idx)
        # Listeye ekliyoruz.
        results.append(parsed)
        
    # Tamamlanan listeyi döndürüyoruz.
    return results


def generate_ethernet_markdown_report(dataset: Dict[str, Any], analyzed_frames: List[Dict[str, Any]]) -> str:
    """
    Ayrıştırılan Ethernet çerçevelerinden detaylı bir Markdown analiz raporu üretir.
    
    Argümanlar:
        dataset: Ham veri seti (meta bilgisi için).
        analyzed_frames: Ayrıştırılmış çerçeveler listesi.
        
    Döndürür:
        Markdown formatında biçimlendirilmiş rapor metni.
    """
    # Meta bilgilerini alıyoruz.
    meta = dataset.get("meta", {})
    
    # Rapor satırları listesini başlatıyoruz.
    lines: List[str] = []
    
    # Başlık ve özel lisans uyarısı
    lines.append("# G044: Ethernet, MAC ve Çerçeve Yapısı Analiz Raporu")
    lines.append("")
    lines.append("> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  ")
    lines.append("> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  ")
    lines.append("> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Bölüm 1: Yönetici Özeti ve Analiz Kapsamı
    lines.append("## 1. Yönetici Özeti ve Analiz Kapsamı")
    lines.append(f"- **Proje Başlığı:** {meta.get('project', 'Ethernet ve MAC Analizi')}")
    lines.append(f"- **Açıklama:** {meta.get('description', 'N/A')}")
    lines.append(f"- **Yakalama Arayüzü:** {meta.get('capture_interface', 'eth0')}")
    lines.append(f"- **Analiz Edilen Çerçeve Sayısı:** {len(analyzed_frames)} Adet Ethernet Çerçevesi")
    lines.append(f"- **Tarih:** {meta.get('analysis_date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))}")
    lines.append("")
    
    # Bölüm 2: Çerçeve Başlığı Alanları ve Etiketleme Tablosu
    lines.append("## 2. Ethernet Çerçeveleri Alan Etiketleme ve Ayrıştırma Tablosu")
    lines.append("")
    lines.append("| Çerçeve ID | Tip / Protokol | Hedef MAC & İletim Türü | Kaynak MAC & OUI | EtherType | Boyut (Bayt) | FCS (CRC32) |")
    lines.append("|---|---|---|---|---|---|---|")
    
    # Çerçeveleri tabloya ekliyoruz.
    for fr in analyzed_frames:
        # Hedef detayı.
        dst_str = f"`{fr['destination']['mac_address']}` ({fr['destination']['cast_type']})"
        # Kaynak detayı.
        src_str = f"`{fr['source']['mac_address']}` ({fr['source']['vendor']})"
        # EtherType detayı.
        et_str = f"`{fr['ethertype']}` ({fr['protocol_name']})"
        # Boyut detayı.
        sz_str = f"{fr['total_frame_size']} B (Veri: {fr['payload_size_bytes']}, Dolgu: {fr['padding_bytes']})"
        # Satırı ekliyoruz.
        lines.append(f"| **{fr['frame_id']}** | {fr['frame_type']} | {dst_str} | {src_str} | {et_str} | {sz_str} | `{fr['fcs_crc32']}` |")
        
    lines.append("")
    
    # Bölüm 3: MAC Adresi Bit Seviyesi ve Çerçeve Anatomisi
    lines.append("## 3. MAC Adresi Bit Seviyesi Analizi ve Çerçeve Anatomisi")
    lines.append("### I/G (Individual / Group) Biti:")
    lines.append("- MAC adresinin ilk baytının en önemsiz biti (LSB - Least Significant Bit) **I/G biti** olarak adlandırılır.")
    lines.append("- Eğer bu bit **0** ise adres bir **Unicast** (tekil cihaz) adresidir.")
    lines.append("- Eğer bu bit **1** ise adres bir **Multicast** veya **Broadcast** adresidir.")
    lines.append("- **Kritik Güvenlik Kuralı:** IEEE 802.3 standardına göre bir çerçevenin **Kaynak MAC (Source MAC)** adresinde I/G biti kesinlikle 1 olamaz. Kaynak MAC multicast ise paket doğrudan ağ donanımları veya güvenlik duvarları tarafından saldırı/spoofing kabul edilerek düşürülmelidir.")
    lines.append("")
    lines.append("### U/L (Universal / Local) Biti:")
    lines.append("- İlk baytın sondan ikinci biti **U/L biti**dir.")
    lines.append("- **0** ise adres IEEE tarafından üreticiye tescillenmiş küresel benzersiz bir adrestir (OUI).")
    lines.append("- **1** ise adres yerel ağ yöneticisi veya yazılım tarafından dinamik olarak tanımlanmıştır (Locally Administered / MAC Spoofing göstergesi olabilir).")
    lines.append("")
    lines.append("### Asgari Çerçeve Boyutu ve Dolgulama (Padding):")
    lines.append("- Ethernet CSMA/CD çarpışma algılama mekanizması gereği kablo üzerindeki asgari çerçeve boyutu **64 bayttır**.")
    lines.append("- Eğer üst katmandan gelen veri 46 baytın altında kalırsa (örneğin 28 baytlık standart bir ARP paketi), çerçeveye otomatik olarak **dolgu baytları (padding)** eklenerek toplam boyut 64 bayta tamamlanır.")
    lines.append("")
    
    # Bölüm 4: Savunma ve Güvenlik Tavsiyeleri
    lines.append("## 4. Savunma ve Tespit Kılavuzu")
    lines.append("1. **Port Security (Bağlantı Noktası Güvenliği):** Ağ anahtarı portlarında MAC adresi sınırlaması (örneğin port başına azami 1 veya 2 MAC) yapılarak MAC Flooding (CAM tablosu taşırma) saldırıları engellenmelidir.")
    lines.append("2. **Dynamic ARP Inspection (DAI):** Anahtar üzerinde DHCP Snooping veritabanı ile gelen ARP isteklerinin IP-MAC eşleşmesi doğrulanmalı; sahte ARP yanıtları (ARP Spoofing) engellenmelidir.")
    lines.append("3. **Runt ve Giant Çerçeve Filtreleme:** Ağ kartı ve switch seviyesinde 64 bayt altı (Runt) veya 1518 bayt üstü standart dışı (Giant) çerçeveler elektriksel gürültü veya saldırı girişimi sayılarak otomatik filtrelenmelidir.")
    lines.append("")
    lines.append("---")
    lines.append("*Rapor Antigravity Didaktik Ethernet Analiz Motoru tarafından otomatik üretilmiştir.*")
    
    # Rapor metnini birleştirip geri döndürüyoruz.
    return "\n".join(lines)


def main() -> int:
    """CLI giriş noktası ve yürütücü fonksiyon."""
    # Windows konsolunda UTF-8 akışını sağlıyoruz.
    if sys.platform == "win32":
        # Çıktı akışı.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        # Hata akışı.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        
    # Argüman ayrıştırıcıyı tanımlıyoruz.
    parser = argparse.ArgumentParser(
        description="G044: Ethernet, MAC ve Çerçeve Yapısı Analiz ve Doğrulama Motoru"
    )
    # Girdi dosyası.
    parser.add_argument(
        "--frames-input",
        type=str,
        required=True,
        help="Ayrıştırılacak Ethernet çerçevelerini içeren JSON dosyasının yolu."
    )
    # Rapor çıktısı.
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Markdown analiz raporunun kaydedileceği dosya yolu."
    )
    # JSON özeti.
    parser.add_argument(
        "--json-summary",
        type=str,
        default=None,
        help="Makine tarafından okunabilir JSON analizinin kaydedileceği dosya yolu."
    )
    
    # Argümanları alıyoruz.
    args = parser.parse_args()
    
    try:
        # Girdi dosyasının varlığını teyit ediyoruz.
        if not os.path.isfile(args.frames_input):
            # Dosya bulunamadı hatası.
            raise FileNotFoundError(f"Çerçeve veri dosyası bulunamadı: {args.frames_input}")
            
        # JSON dosyasını okuyoruz.
        with open(args.frames_input, "r", encoding="utf-8") as f:
            # Ayrıştırma işlemi.
            raw_dataset = json.load(f)
            
        # Çerçeveleri ayrıştırıyoruz.
        analyzed = analyze_ethernet_dataset(raw_dataset)
        # Markdown raporunu üretiyoruz.
        report = generate_ethernet_markdown_report(raw_dataset, analyzed)
        
        # Konsola basıyoruz.
        print(report)
        
        # Dosyaya çıktı istenmişse yazıyoruz.
        if args.output:
            # Üst dizin kontrolü.
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            # Raporu kaydediyoruz.
            with open(args.output, "w", encoding="utf-8") as outf:
                # Yazma işlemi.
                outf.write(report)
            # Bilgi mesajı.
            print(f"\n[+] Ethernet analiz raporu kaydedildi: {args.output}")
            
        # JSON özeti istenmişse kaydediyoruz.
        if args.json_summary:
            # Üst dizin kontrolü.
            os.makedirs(os.path.dirname(os.path.abspath(args.json_summary)), exist_ok=True)
            # JSON dosyasını yazıyoruz.
            with open(args.json_summary, "w", encoding="utf-8") as jf:
                # Serileştirme.
                json.dump({"analyzed_frames": analyzed}, jf, indent=2, ensure_ascii=False)
            # Bilgi mesajı.
            print(f"[+] JSON özeti kaydedildi: {args.json_summary}")
            
        # Başarılı çıkış kodu 0.
        return 0
        
    # Çerçeve doğrulama ve protokol ihlallerini yakalıyoruz.
    except EthernetFrameError as efe:
        # Standart hataya yazıyoruz.
        sys.stderr.write(f"[-] Ethernet Çerçeve Hatası: {efe}\n")
        # Hata kodu 1.
        return 1
    # Dosya hatasını yakalıyoruz.
    except FileNotFoundError as fnfe:
        # Standart hataya basıyoruz.
        sys.stderr.write(f"[-] Dosya Hatası: {fnfe}\n")
        # Hata kodu 2.
        return 2
    # Beklenmeyen genel hatalar.
    except Exception as ex:
        # Hatayı basıyoruz.
        sys.stderr.write(f"[-] Beklenmeyen Hata: {ex}\n")
        # Hata kodu 3.
        return 3


# Modül doğrudan çağrıldığında main() yürütülür.
if __name__ == "__main__":
    # Sistem çıkışı.
    sys.exit(main())
