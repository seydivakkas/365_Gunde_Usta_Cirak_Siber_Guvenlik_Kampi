# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G043: OSI ve TCP/IP Katmanları Paket Denetim ve Kapsülleme Motoru.

Bu modül, bir HTTPS isteğinin ağ üzerindeki iletimini 7 katmanlı OSI ve 4 katmanlı TCP/IP
modelleri çerçevesinde ayrıştırır; başlık (header) alanlarını, adresleri, portları,
şifreleme durumunu ve kapsülleme (encapsulation) sırasını doğrular.
"""

# Dosya yolu ve sistem kontrolleri için os modülünü yüklüyoruz.
import os
# Komut satırı argümanlarını ayrıştırmak amacıyla argparse modülünü dahil ediyoruz.
import argparse
# JSON verilerini okuma ve serileştirme işlemleri için json kütüphanesini kullanıyoruz.
import json
# Çıktı yönlendirmesi, UTF-8 konsol akışı ve çıkış kodları için sys modülünü çağırıyoruz.
import sys
# Tip güvenliği ve statik kod analizi için typing tiplerini alıyoruz.
from typing import Dict, Any, List, Tuple, Optional, Set
# Zaman damgalı analiz raporları için datetime ve timezone sınıflarını dahil ediyoruz.
from datetime import datetime, timezone
# Adres ve format doğrulamalarında regex kullanımı için re modülünü yüklüyoruz.
import re

# Zorunlu OSI Katman Anahtarları Listesi (En üstten en alta kapsülleme sırası)
MANDATORY_OSI_LAYERS = [
    "layer_7_application",
    "layer_6_presentation",
    "layer_5_session",
    "layer_4_transport",
    "layer_3_network",
    "layer_2_data_link",
    "layer_1_physical"
]

# Geçerli Standart TCP Bayrakları Kümesi
VALID_TCP_FLAGS: Set[str] = {"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"}

# MAC Adresi Doğrulama Deseni (Standart iki nokta veya tire ayrılmış 6 bayt hex)
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


class PacketEncapsulationError(ValueError):
    """Paket kapsülleme, katman sırası veya protokol başlık ihlallerinde fırlatılan özel istisna sınıfı."""
    # ValueError'dan türeyen özel denetim hatası.
    pass


def validate_mac_address(mac_str: str) -> bool:
    """
    Bir fiziksel MAC adresinin 6 baytlık geçerli onaltılık biçimde olduğunu doğrular.
    
    Argümanlar:
        mac_str: Doğrulanacak MAC adresi metni (örn: '00:1A:2B:3C:4D:5E').
        
    Döndürür:
        Geçerli ise True, aksi halde False.
    """
    # Girdinin string olduğunu ve boş olmadığını sınıyoruz.
    if not isinstance(mac_str, str) or not mac_str.strip():
        # Geçersiz tipte False dönüyoruz.
        return False
    # Regex şablonuna uyup uymadığını kontrol ediyoruz.
    return bool(MAC_REGEX.match(mac_str.strip()))


def validate_ipv4_address(ip_str: str) -> bool:
    """
    Bir IP adresinin noktalı ondalık (dotted-decimal) geçerli IPv4 formatında olduğunu doğrular.
    
    Argümanlar:
        ip_str: Kontrol edilecek IP adresi dizisi (örn: '192.168.1.1').
        
    Döndürür:
        Geçerli ise True, aksi halde False.
    """
    # Girdi tipini sınıyoruz.
    if not isinstance(ip_str, str) or not ip_str.strip():
        # String değilse False dönüyoruz.
        return False
    # Noktalara göre 4 parçaya bölüyoruz.
    parts = ip_str.strip().split(".")
    # Tam olarak 4 oktet olduğunu sınıyoruz.
    if len(parts) != 4:
        # 4 oktet yoksa geçersizdir.
        return False
    # Her bir okteti sayısal değer ve aralık açısından denetliyoruz.
    for p in parts:
        # Oktetin sadece rakamlardan oluştuğunu sınıyoruz.
        if not p.isdigit():
            # Rakam harici karakter varsa geçersizdir.
            return False
        # Sayısal değere dönüştürüyoruz.
        val = int(p)
        # 0 ile 255 aralığında olup olmadığına bakıyoruz.
        if val < 0 or val > 255:
            # 255'i aşarsa geçersizdir.
            return False
        # Baştaki sıfır kontrolü (01 gibi durumlara engel olmak için; tek başına '0' hariç).
        if len(p) > 1 and p.startswith("0"):
            # Geçersiz format.
            return False
    # Tüm oktetler geçerliyse True döndürüyoruz.
    return True


def validate_port_number(port: Any, port_name: str) -> int:
    """
    Bir TCP/UDP port numarasının 1-65535 aralığında geçerli bir tam sayı olduğunu doğrular.
    
    Argümanlar:
        port: Denetlenecek port değeri.
        port_name: Hata mesajında kullanılacak etiket ('kaynak port' veya 'hedef port').
        
    Döndürür:
        Doğrulanmış tam sayı port değeri.
    """
    # Boolean değerlerin (True/False) int olarak sızmasını engelliyoruz.
    if isinstance(port, bool) or not isinstance(port, int):
        # Tip hatası fırlatıyoruz.
        raise PacketEncapsulationError(f"{port_name} geçerli bir tam sayı olmalıdır, alınan: {type(port).__name__}")
    # 1 ile 65535 sınır aralığını sınıyoruz.
    if port < 1 or port > 65535:
        # Sınır dışı port hatası üretiyoruz.
        raise PacketEncapsulationError(f"{port_name} 1-65535 aralığında olmalıdır, alınan: {port}")
    # Geçerli portu geri veriyoruz.
    return port


def validate_packet_structure(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Paket kapsülleme JSON yapısını şema, katman sırası ve alan doğrulamalarından geçirir.
    
    Argümanlar:
        data: Ham paket sözlüğü.
        
    Döndürür:
        Doğrulanmış kapsülleme sözlüğü.
    """
    # Kök nesnenin sözlük olduğunu teyit ediyoruz.
    if not isinstance(data, dict):
        # Sözlük değilse hata fırlatıyoruz.
        raise PacketEncapsulationError("Paket verisi bir JSON sözlüğü olmalıdır.")
    
    # 'encapsulation' anahtarının varlığını sınıyoruz.
    if "encapsulation" not in data or not isinstance(data["encapsulation"], dict):
        # Kapsülleme düğümü eksikse hata üretiyoruz.
        raise PacketEncapsulationError("Paket verisinde zorunlu 'encapsulation' sözlüğü bulunamadı.")
    
    # Kapsülleme sözlüğünü alıyoruz.
    encap = data["encapsulation"]
    
    # Tüm 7 OSI katmanının varlığını sırayla denetliyoruz.
    for layer_key in MANDATORY_OSI_LAYERS:
        # Katman anahtarının sözlükte olup olmadığını sınıyoruz.
        if layer_key not in encap:
            # Eksik katman tespit edilirse hata fırlatıyoruz.
            raise PacketEncapsulationError(f"Zorunlu katman verisi eksik: '{layer_key}'")
        # Katman içeriğinin sözlük olmasını şart koşuyoruz.
        if not isinstance(encap[layer_key], dict):
            # Sözlük değilse hata fırlatıyoruz.
            raise PacketEncapsulationError(f"Katman '{layer_key}' bir sözlük olmalıdır.")
            
    # Katman 4: Taşıma (Transport) Başlıklarını Doğruluyoruz.
    l4 = encap["layer_4_transport"]
    # Kaynak port doğrulaması.
    validate_port_number(l4.get("source_port"), "Kaynak port (source_port)")
    # Hedef port doğrulaması.
    validate_port_number(l4.get("destination_port"), "Hedef port (destination_port)")
    # TCP bayrakları denetimi.
    flags = l4.get("flags", [])
    # Bayrakların liste olduğunu kontrol ediyoruz.
    if not isinstance(flags, list):
        # Liste değilse hata veriyoruz.
        raise PacketEncapsulationError("Taşıma katmanı 'flags' bir liste olmalıdır.")
    # Her bir bayrağı standart kümede sınıyoruz.
    for flag in flags:
        # Büyük harfe çeviriyoruz.
        f_upper = str(flag).upper()
        # İzin verilen bayraklar arasında olup olmadığına bakıyoruz.
        if f_upper not in VALID_TCP_FLAGS:
            # Geçersiz bayrak tespitinde hata fırlatıyoruz.
            raise PacketEncapsulationError(f"Geçersiz TCP bayrağı: '{flag}'. Beklenen küme: {VALID_TCP_FLAGS}")
            
    # Katman 3: Ağ (Network) Başlıklarını Doğruluyoruz.
    l3 = encap["layer_3_network"]
    # Kaynak IP kontrolü.
    src_ip = l3.get("source_ip", "")
    # IPv4 doğrulaması.
    if not validate_ipv4_address(src_ip):
        # Geçersiz IP hatası üretiyoruz.
        raise PacketEncapsulationError(f"Geçersiz kaynak IPv4 adresi: '{src_ip}'")
    # Hedef IP kontrolü.
    dst_ip = l3.get("destination_ip", "")
    # Hedef IPv4 doğrulaması.
    if not validate_ipv4_address(dst_ip):
        # Hata üretiyoruz.
        raise PacketEncapsulationError(f"Geçersiz hedef IPv4 adresi: '{dst_ip}'")
        
    # Katman 2: Veri Bağlantısı (Data Link) Başlıklarını Doğruluyoruz.
    l2 = encap["layer_2_data_link"]
    # Kaynak MAC adresi kontrolü.
    src_mac = l2.get("source_mac", "")
    # MAC biçim doğrulaması.
    if not validate_mac_address(src_mac):
        # Geçersiz MAC hatası.
        raise PacketEncapsulationError(f"Geçersiz kaynak MAC adresi: '{src_mac}'")
    # Hedef MAC adresi kontrolü.
    dst_mac = l2.get("destination_mac", "")
    # Hedef MAC doğrulaması.
    if not validate_mac_address(dst_mac):
        # Hata fırlatıyoruz.
        raise PacketEncapsulationError(f"Geçersiz hedef MAC adresi: '{dst_mac}'")
        
    # Katman 6: Sunum (Presentation) Şifreleme Durumu Doğrulaması.
    l6 = encap["layer_6_presentation"]
    # Şifreleme statüsünü alıyoruz.
    enc_status = str(l6.get("encryption_status", "")).upper()
    # HTTPS senaryosunda şifrelenmiş olmasını şart koşuyoruz.
    if enc_status != "ENCRYPTED":
        # Güvenlik uyarısı hatası veriyoruz.
        raise PacketEncapsulationError("Sunum katmanı HTTPS protokolü için 'ENCRYPTED' durumunda olmalıdır.")
        
    # Tüm doğrulama testlerini geçen veriyi döndürüyoruz.
    return data


def map_layers_to_models(encap: Dict[str, Any]) -> Dict[str, Any]:
    """
    7 Katmanlı OSI ve 4 Katmanlı TCP/IP modelleri arasındaki karşılıkları haritalandırır.
    
    Argümanlar:
        encap: Kapsülleme sözlüğü.
        
    Döndürür:
        Her iki modelin eşlemesini içeren yapılandırılmış analiz sözlüğü.
    """
    # 7 Katmanlı OSI Dizilimi Haritası
    osi_mapping = [
        {
            "osi_number": 7,
            "osi_name": "Application (Uygulama)",
            "pdu": "Data (Veri)",
            "protocol": encap["layer_7_application"].get("protocol", "HTTP/2"),
            "key_details": f"Metot: {encap['layer_7_application'].get('method', 'N/A')} URI: {encap['layer_7_application'].get('uri', 'N/A')}",
            "tcp_ip_equivalent": "Application"
        },
        {
            "osi_number": 6,
            "osi_name": "Presentation (Sunum)",
            "pdu": "Data (Veri / Şifreli Kayıt)",
            "protocol": encap["layer_6_presentation"].get("protocol", "TLSv1.3"),
            "key_details": f"Şifre Paketi: {encap['layer_6_presentation'].get('cipher_suite', 'N/A')} ({encap['layer_6_presentation'].get('encryption_status', 'N/A')})",
            "tcp_ip_equivalent": "Application"
        },
        {
            "osi_number": 5,
            "osi_name": "Session (Oturum)",
            "pdu": "Data (Oturum Yönetimi)",
            "protocol": encap["layer_5_session"].get("protocol", "TLS Session"),
            "key_details": f"Oturum ID: {encap['layer_5_session'].get('session_id', 'N/A')[:16]}... Durum: {encap['layer_5_session'].get('state', 'N/A')}",
            "tcp_ip_equivalent": "Application"
        },
        {
            "osi_number": 4,
            "osi_name": "Transport (Taşıma)",
            "pdu": "Segment (Bölüm)",
            "protocol": encap["layer_4_transport"].get("protocol", "TCP"),
            "key_details": f"Portlar: {encap['layer_4_transport'].get('source_port')} -> {encap['layer_4_transport'].get('destination_port')} Bayraklar: {encap['layer_4_transport'].get('flags')}",
            "tcp_ip_equivalent": "Transport"
        },
        {
            "osi_number": 3,
            "osi_name": "Network (Ağ)",
            "pdu": "Packet (Paket)",
            "protocol": encap["layer_3_network"].get("protocol", "IPv4"),
            "key_details": f"IP: {encap['layer_3_network'].get('source_ip')} -> {encap['layer_3_network'].get('destination_ip')} TTL: {encap['layer_3_network'].get('ttl')}",
            "tcp_ip_equivalent": "Internet"
        },
        {
            "osi_number": 2,
            "osi_name": "Data Link (Veri Bağlantısı)",
            "pdu": "Frame (Çerçeve)",
            "protocol": encap["layer_2_data_link"].get("protocol", "Ethernet II"),
            "key_details": f"MAC: {encap['layer_2_data_link'].get('source_mac')} -> {encap['layer_2_data_link'].get('destination_mac')} EtherType: {encap['layer_2_data_link'].get('ethertype')}",
            "tcp_ip_equivalent": "Network Access (Link)"
        },
        {
            "osi_number": 1,
            "osi_name": "Physical (Fiziksel)",
            "pdu": "Bit (Sinyal / Bit Akışı)",
            "protocol": encap["layer_1_physical"].get("medium", "1000BASE-T"),
            "key_details": f"Fiziksel Ortam: {encap['layer_1_physical'].get('medium')} Hız: {encap['layer_1_physical'].get('bitrate_mbps')} Mbps",
            "tcp_ip_equivalent": "Network Access (Link)"
        }
    ]
    
    # 4 Katmanlı TCP/IP Konsolide Özeti
    tcpip_summary = {
        "Application": ["Layer 7 (Application)", "Layer 6 (Presentation)", "Layer 5 (Session)"],
        "Transport": ["Layer 4 (Transport: TCP Port 443)"],
        "Internet": ["Layer 3 (Network: IPv4)"],
        "Network_Access": ["Layer 2 (Data Link: Ethernet II)", "Layer 1 (Physical)"]
    }
    
    # Haritalandırmayı döndürüyoruz.
    return {
        "osi_layers": osi_mapping,
        "tcpip_summary": tcpip_summary
    }


def generate_packet_dissection_report(data: Dict[str, Any], mapping: Dict[str, Any]) -> str:
    """
    Ayrıştırılan paketten kapsamlı, didaktik bir Markdown analiz raporu üretir.
    
    Argümanlar:
        data: Doğrulanmış paket sözlüğü.
        mapping: Katman eşleme sözlüğü.
        
    Döndürür:
        Markdown biçimli denetim raporu metni.
    """
    # Meta bilgilerini alıyoruz.
    meta = data.get("meta", {})
    # Kapsülleme verisini alıyoruz.
    encap = data["encapsulation"]
    # OSI katmanlarını alıyoruz.
    osi_list = mapping["osi_layers"]
    
    # Rapor satırları listesini başlatıyoruz.
    lines: List[str] = []
    
    # Başlık ve özel lisans uyarısı
    lines.append("# G043: OSI ve TCP/IP Katmanları Paket Denetim ve Kapsülleme Raporu")
    lines.append("")
    lines.append("> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  ")
    lines.append("> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  ")
    lines.append("> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Bölüm 1: Paket Bilgileri ve Kapsam
    lines.append("## 1. Paket Özeti ve Analiz Kapsamı")
    lines.append(f"- **Örnek Adı:** {meta.get('sample_name', 'Standart HTTPS İsteği')}")
    lines.append(f"- **Açıklama:** {meta.get('description', 'N/A')}")
    lines.append(f"- **İletişim Bağlamı:** {meta.get('capture_context', 'N/A')}")
    lines.append(f"- **Analiz Tarihi:** {meta.get('timestamp', datetime.now(timezone.utc).isoformat())}")
    lines.append("")
    
    # Bölüm 2: 7 Katmanlı OSI ve 4 Katmanlı TCP/IP Eşleme Tablosu
    lines.append("## 2. 7 Katmanlı OSI ve TCP/IP Kapsülleme (Encapsulation) Eşleme Tablosu")
    lines.append("")
    lines.append("| OSI No | OSI Katman Adı | PDU (Protokol Veri Birimi) | Protokol / Alan | Anahtar Güvenlik Detayları | TCP/IP Katmanı |")
    lines.append("|---|---|---|---|---|---|")
    
    # Her bir katmanı tabloya işliyoruz.
    for lyr in osi_list:
        # Satır verilerini biçimlendirip ekliyoruz.
        lines.append(f"| {lyr['osi_number']} | **{lyr['osi_name']}** | {lyr['pdu']} | {lyr['protocol']} | {lyr['key_details']} | **{lyr['tcp_ip_equivalent']}** |")
        
    lines.append("")
    
    # Bölüm 3: Kapsülleme ve Güvenlik Mekanizması Analizi
    lines.append("## 3. Katman Katman Güvenlik Mekanizması ve Kapsülleme Analizi")
    lines.append("### Katman 7-5 (OSI Üst Katmanları / TCP/IP Uygulama Katmanı):")
    lines.append("- **HTTP/2 & TLS 1.3:** İstemci kimlik doğrulama isteği (`GET /api/v1/auth/session`) uygulama katmanında oluşturulur. Ancak ağ kablosuna doğrudan metin olarak çıkmaz. Sunum katmanında `TLS_AES_256_GCM_SHA384` simetrik şifreleme algoritması ile `ApplicationData` tipinde şifrelenir. Böylece ortadaki adam (MitM) ve paket dinleme (sniffing) saldırılarına karşı gizlilik (confidentiality) sağlanır.")
    lines.append("")
    lines.append("### Katman 4 (Taşıma Katmanı - TCP):")
    lines.append(f"- **Port ve Durum Yönetimi:** İstemci geçici (ephemeral) port `{encap['layer_4_transport']['source_port']}` üzerinden hedef web sunucusunun standart `{encap['layer_4_transport']['destination_port']}` (HTTPS) portuna yönlenir. TCP başlığındaki `{encap['layer_4_transport']['flags']}` bayrakları ile bağlantının kurulmuş (established) olduğu ve verinin hemen uygulamaya iletilmesi gerektiği (PSH - Push) belirtilir.")
    lines.append("")
    lines.append("### Katman 3 (Ağ Katmanı - IPv4):")
    lines.append(f"- **Mantıksal Adresleme ve Yönlendirme:** Paket `{encap['layer_3_network']['source_ip']}` kaynak IP adresinden `{encap['layer_3_network']['destination_ip']}` hedef IP adresine yönlendirilir. TTL değeri ({encap['layer_3_network']['ttl']}) yönlendirme döngülerini (routing loops) engeller; Protokol Numarası 6, paketin bir üst katmanda TCP'ye teslim edileceğini tanımlar.")
    lines.append("")
    lines.append("### Katman 2-1 (Veri Bağlantısı ve Fiziksel Katman - Ethernet & Sinyal):")
    lines.append(f"- **Fiziksel Teslimat:** Çerçeve, yerel ağ anahtarı (switch) ve varsayılan ağ geçidi (gateway) üzerinden taşınmak için `{encap['layer_2_data_link']['source_mac']}` -> `{encap['layer_2_data_link']['destination_mac']}` adresleri ile çerçevelenir (Ethernet II). FCS (Frame Check Sequence - CRC32: {encap['layer_2_data_link']['fcs_crc32']}) ile aktarım sırasında bit bozulması yaşanıp yaşanmadığı donanımsal olarak kontrol edilir.")
    lines.append("")
    
    # Bölüm 4: Savunma ve Risk Değerlendirmesi
    lines.append("## 4. Savunma ve Tespit Kılavuzu")
    lines.append("1. **Protokol Doğrulaması:** Ağ güvenlik duvarları (Next-Gen Firewall) yalnızca port numarasına (TCP 443) değil, katman 6/7 içeriğinin gerçekten geçerli bir TLS el sıkışması içerip içermediğine bakmalıdır (Deep Packet Inspection - DPI). Kötü niyetli yazılımlar 443 portunu tünelleme amacıyla suistimal edebilir.")
    lines.append("2. **Ağ Segmentasyonu:** Katman 3 seviyesinde VLAN ve IP erişim listeleri (ACL) kurularak, kritik sunuculara doğrudan erişim engellenmeli; trafik Bastion veya Web Application Firewall (WAF) üzerinden geçirilmelidir.")
    lines.append("3. **Şifreleme Standartları:** Zayıf şifre paketleri (RC4, DES, 3DES, CBC modlu AES) ve eski protokol sürümleri (SSLv3, TLS 1.0, TLS 1.1) sunucu tarafında tamamen devre dışı bırakılmalıdır.")
    lines.append("")
    lines.append("---")
    lines.append("*Rapor Antigravity Didaktik Paket Denetim Motoru tarafından otomatik üretilmiştir.*")
    
    # Birleştirip döndürüyoruz.
    return "\n".join(lines)


def main() -> int:
    """CLI giriş noktası ve yürütücüsü."""
    # Windows konsolunda UTF-8 karakter desteğini sağlıyoruz.
    if sys.platform == "win32":
        # Çıktı akışını UTF-8 yapıyoruz.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        # Hata akışını UTF-8 yapıyoruz.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        
    # Argüman ayrıştırıcıyı kuruyoruz.
    parser = argparse.ArgumentParser(
        description="G043: OSI ve TCP/IP Katmanları Paket Denetim ve Kapsülleme Motoru"
    )
    # Girdi JSON dosyası yolu.
    parser.add_argument(
        "--packet-input",
        type=str,
        required=True,
        help="Ayrıştırılacak paket kapsülleme JSON dosyasının dosya yolu."
    )
    # Rapor çıktısı yolu.
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Markdown analiz raporunun kaydedileceği dosya yolu."
    )
    # JSON özeti yolu.
    parser.add_argument(
        "--json-summary",
        type=str,
        default=None,
        help="Makine tarafından okunabilir JSON özetinin kaydedileceği dosya yolu."
    )
    
    # Argümanları alıyoruz.
    args = parser.parse_args()
    
    try:
        # Dosyanın varlığını teyit ediyoruz.
        if not os.path.isfile(args.packet_input):
            # Bulunamadı hatası.
            raise FileNotFoundError(f"Paket kapsülleme dosyası bulunamadı: {args.packet_input}")
            
        # JSON dosyasını okuyoruz.
        with open(args.packet_input, "r", encoding="utf-8") as pf:
            # Ayrıştırma işlemi.
            raw_data = json.load(pf)
            
        # Şemayı ve katman başlıklarını doğruluyoruz.
        valid_data = validate_packet_structure(raw_data)
        # Katman eşlemelerini çıkarıyoruz.
        mapping = map_layers_to_models(valid_data["encapsulation"])
        # Markdown raporunu derliyoruz.
        report = generate_packet_dissection_report(valid_data, mapping)
        
        # Konsola raporu yazdırıyoruz.
        print(report)
        
        # Dosyaya çıktı istenmişse kaydediyoruz.
        if args.output:
            # Üst dizini hazırlıyoruz.
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            # Rapor dosyasını yazıyoruz.
            with open(args.output, "w", encoding="utf-8") as outf:
                # İçeriği kaydediyoruz.
                outf.write(report)
            # Konsol mesajı veriyoruz.
            print(f"\n[+] Paket ayrıştırma raporu kaydedildi: {args.output}")
            
        # JSON özeti istenmişse kaydediyoruz.
        if args.json_summary:
            # Üst dizin kontrolü.
            os.makedirs(os.path.dirname(os.path.abspath(args.json_summary)), exist_ok=True)
            # JSON dosyasını yazıyoruz.
            with open(args.json_summary, "w", encoding="utf-8") as jf:
                # Yapılandırılmış analizi kaydediyoruz.
                json.dump({"validated_packet": valid_data, "layer_mapping": mapping}, jf, indent=2, ensure_ascii=False)
            # Bilgi mesajı veriyoruz.
            print(f"[+] JSON analizi kaydedildi: {args.json_summary}")
            
        # Başarılı çıkış kodu 0 döndürüyoruz.
        return 0
        
    # Paket kapsülleme ve protokol ihlallerini yakalıyoruz.
    except PacketEncapsulationError as pee:
        # Hata mesajını standart hataya basıyoruz.
        sys.stderr.write(f"[-] Paket Doğrulama Hatası: {pee}\n")
        # Hata kodu 1.
        return 1
    # Dosya bulunamadı hatası.
    except FileNotFoundError as fnfe:
        # Hata mesajı basıyoruz.
        sys.stderr.write(f"[-] Dosya Hatası: {fnfe}\n")
        # Hata kodu 2.
        return 2
    # Beklenmeyen genel hatalar.
    except Exception as ex:
        # Hatayı basıyoruz.
        sys.stderr.write(f"[-] Beklenmeyen Hata: {ex}\n")
        # Hata kodu 3.
        return 3


# Modül doğrudan çalıştırıldığında main() fonksiyonuna dallanıyoruz.
if __name__ == "__main__":
    # Programdan ayrılıyoruz.
    sys.exit(main())
