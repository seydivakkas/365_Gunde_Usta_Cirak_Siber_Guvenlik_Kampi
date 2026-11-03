# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G046: IPv6 Temel Kavramlar, Sıkıştırma (RFC 5952), Adres Türleri ve EUI-64 Analiz Modülü.
Bu modül, IPv6'nın 128-bitlik adres mimarisini, RFC 5952 kanonik sıkıştırma algoritmasını,
EUI-64 arayüz kimliği türetimini ve gizlilik risklerini (RFC 4941), komşu keşfi (NDP) için
Solicited-Node çok noktaya yayın (multicast) adreslerini ve güvenlik sınıflandırmalarını modeller.
"""

import sys  # Standart sistem modülü, konsol UTF-8 çıktı kodlamasını yapılandırmak için dahil edilir
import json  # JSON biçimindeki test verilerini ve yapılandırmaları işlemek için kullanılır
from dataclasses import dataclass  # Yapılandırılmış IPv6 adres verilerini nesneleştirmek için kullanılır
from typing import List, Tuple, Optional  # Statik tip güvenliği için tip ipuçları dahil edilir

# Windows platformunda standart çıktı akışını UTF-8 karakter kümesine zorlayarak Türkçe karakter hatalarını önler
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Standart çıktı akışını UTF-8 yapar
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # Standart hata akışını UTF-8 yapar


class IPv6ValidationError(ValueError):
    """IPv6 adresi, hextet yapısı veya CIDR önek doğrulaması başarısız olduğunda fırlatılan özel istisna sınıfı."""
    pass  # Temel ValueError davranışını miras alarak özel hata türü oluşturur


@dataclass
class IPv6AddressResult:
    """Tek bir IPv6 adresinin analiz, genişletilmiş ve sıkıştırılmış halini saklayan veri sınıfı."""
    input_cidr: str  # Kullanıcı veya sistem tarafından girilen ham CIDR girdisi (Örn: 2001:db8::1/64)
    expanded_address: str  # 39 karakterlik tam açılmış (uncompressed) 8 hextetlik adres
    canonical_compressed: str  # RFC 5952 standardına tam uyumlu kanonik sıkıştırılmış adres
    int_value: int  # 128-bitlik işaretsiz tamsayı değeri (0 ile 2^128 - 1 arasında)
    binary_str: str  # Nokta veya iki nokta ayrımlı 128 bitlik ikili (binary) gösterim
    prefix_length: int  # CIDR önek uzunluğu (/0 ile /128 arasında)
    network_prefix: str  # Yalnızca ağ kısmını temsil eden CIDR önek gösterimi
    interface_id_hex: str  # Son 64-bitlik Arayüz Kimliği (Interface Identifier - IID)
    address_type: str  # GUA, Link-Local, ULA, Multicast, Loopback vb. adres türü
    scope: str  # Adresin etki alanı ve geçerlilik kapsamı (Global, Link-Local, Node-Local)
    solicited_node_multicast: str  # Komşu keşfi (NDP) için üretilen Solicited-Node Multicast adresi
    is_multicast: bool  # ff00::/8 çok noktaya yayın bayrağı
    is_link_local: bool  # fe80::/10 bağlantı yerel bayrağı
    is_unique_local: bool  # fc00::/7 benzersiz yerel adres (ULA) bayrağı
    is_global_unicast: bool  # 2000::/3 genel tekil yayın (GUA) bayrağı
    is_loopback: bool  # ::1/128 geri döngü bayrağı
    is_unspecified: bool  # ::/128 belirtilmemiş adres bayrağı
    is_ipv4_mapped: bool  # ::ffff:0:0/96 IPv4 eşlemeli IPv6 adresi bayrağı


def parse_and_validate_hextet(hextet_str: str) -> int:
    """Tek bir 16-bitlik onaltılık (hex) bloğu doğrular ve tamsayıya çevirir."""
    # Hextet uzunluğunun 1 ile 4 karakter arasında olduğunu denetler
    if len(hextet_str) < 1 or len(hextet_str) > 4:
        raise IPv6ValidationError(
            f"Hextet 1 ila 4 onaltılık karakterden oluşmalıdır: '{hextet_str}' ({len(hextet_str)} karakter)"
        )
    # Karakterlerin geçerli onaltılık (0-9, a-f, A-F) olduğunu sınar
    for char in hextet_str:
        if char not in "0123456789abcdefABCDEF":
            raise IPv6ValidationError(f"Geçersiz onaltılık (hex) karakter içeriyor: '{hextet_str}'")
    # Onaltılık karakter dizgesini tamsayıya dönüştürür
    return int(hextet_str, 16)


def expand_ipv6_address(ip_str: str) -> Tuple[List[int], str]:
    """
    IPv6 adres metnini doğrular, '::' kısaltmasını açar ve 8 adet 16-bit tamsayı hextet listesi döner.
    Döndürür: (hextet_tamsayi_listesi, 39_karakterlik_tam_acik_metin)
    """
    clean_ip = ip_str.strip()  # Baş ve sondaki gereksiz boşlukları ayıklar
    
    # Boş adres kontrolü
    if not clean_ip:
        raise IPv6ValidationError("IPv6 adres metni boş olamaz")
    
    # Çift iki nokta '::' sayısını denetler (en fazla bir adet bulunabilir)
    double_colon_count = clean_ip.count("::")
    if double_colon_count > 1:
        raise IPv6ValidationError("Bir IPv6 adresinde en fazla bir adet '::' çift iki nokta bulunabilir")
    
    hextets: List[int] = []  # 8 adet hexteti saklayacak dinamik liste
    
    if double_colon_count == 1:
        # Adres '::' ile iki parçaya ayrılır (sol ve sağ taraf)
        left_part, right_part = clean_ip.split("::")
        
        # Sol kısımdaki hextetleri ayıklar (varsa)
        left_hextets = [parse_and_validate_hextet(h) for h in left_part.split(":") if h != ""]
        
        # Sağ kısımdaki hextetleri ayıklar (varsa)
        right_hextets = [parse_and_validate_hextet(h) for h in right_part.split(":") if h != ""]
        
        # Toplam hextet sayısının 8'i aşmadığını doğrular
        if len(left_hextets) + len(right_hextets) >= 8:
            raise IPv6ValidationError("IPv6 adresindeki hextet sayısı '::' ile birlikte 8'i aşamaz")
        
        # Aradaki eksik sıfır hextetlerinin adedini hesaplar
        missing_zeros = 8 - (len(left_hextets) + len(right_hextets))
        hextets = left_hextets + ([0] * missing_zeros) + right_hextets
    else:
        # '::' içermeyen adreslerde tam olarak 8 adet hextet bulunmalıdır
        raw_hextets = clean_ip.split(":")
        if len(raw_hextets) != 8:
            if len(raw_hextets) > 8:
                raise IPv6ValidationError(f"'::' içermeyen adres tam olarak 8 hextet içermelidir, bulunan: {len(raw_hextets)}")
            else:
                raise IPv6ValidationError(f"'::' içermeyen adres tam olarak 8 hextet içermelidir, bulunan: {len(raw_hextets)}")
        hextets = [parse_and_validate_hextet(h) for h in raw_hextets]
        
    # Her hexteti tam 4 basamaklı küçük harf onaltılık formata getirir
    expanded_parts = [f"{val:04x}" for val in hextets]
    expanded_str = ":".join(expanded_parts)
    return hextets, expanded_str


def compress_ipv6_rfc5952(hextets: List[int]) -> str:
    """
    RFC 5952 standardına tam uyumlu kanonik IPv6 sıkıştırması gerçekleştirir:
    1. Her hextette baştaki sıfırlar atılır (Örn: '002a' -> '2a', '0000' -> '0').
    2. Ardışık sıfır içeren en uzun hextet dizisi tek bir '::' ile değiştirilir.
    3. Uzunluğu eşit ardışık sıfır dizileri varsa İLK dizi '::' ile değiştirilir.
    4. Tek bir sıfır hexteti '::' ile kısaltılamaz (en az 2 ardışık sıfır şarttır).
    5. Onaltılık harfler küçük harf olmalıdır.
    """
    # Her hexteti baştaki sıfırlar olmaksızın küçük harf onaltılık metne dönüştürür
    hex_strs = [f"{val:x}" for val in hextets]
    
    # Ardışık sıfır bloklarını tarar
    longest_start = -1  # En uzun sıfır dizisinin başlangıç indeksi
    longest_len = 0  # En uzun sıfır dizisinin boyutu
    current_start = -1  # Mevcut sıfır bloğunun başlangıcı
    current_len = 0  # Mevcut sıfır bloğunun boyutu
    
    for i in range(8):
        if hextets[i] == 0:
            if current_start == -1:
                current_start = i
                current_len = 1
            else:
                current_len += 1
            # Eğer mevcut dizi en uzundan kesinlikle büyükse en uzun olarak günceller
            if current_len > longest_len:
                longest_len = current_len
                longest_start = current_start
        else:
            current_start = -1
            current_len = 0
            
    # RFC 5952 Kural 4.2.2: Yalnızca uzunluğu 2 veya daha fazla olan sıfır dizileri '::' ile kısaltılır
    if longest_len >= 2:
        # Sol taraf parçalarını birleştirir
        left = ":".join(hex_strs[:longest_start])
        # Sağ taraf parçalarını birleştirir
        right = ":".join(hex_strs[longest_start + longest_len:])
        # Adres tamamen sıfırlardan oluşuyorsa (::) doğrudan döndürür
        if longest_len == 8:
            return "::"
        # Başta veya sonda olma durumlarına göre iki noktaları ayarlar
        if longest_start == 0:
            return f"::{right}"
        if longest_start + longest_len == 8:
            return f"{left}::"
        return f"{left}::{right}"
    else:
        # 2'den az ardışık sıfır varsa hiçbir sıkıştırma yapılmaz, normal birleştirilir
        return ":".join(hex_strs)


def classify_ipv6(hextets: List[int], int_val: int) -> Tuple[str, str, bool, bool, bool, bool, bool, bool, bool]:
    """
    IPv6 adresinin IETF RFC standartları kapsamındaki tür ve etki alanını (scope) belirler.
    Döndürür: (adres_turu, kapsam, is_multicast, is_link_local, is_ula, is_gua, is_loopback, is_unspecified, is_mapped)
    """
    # 0000:...:0001 -> ::1/128 Geri Döngü (Loopback - RFC 4291)
    if int_val == 1:
        return "Loopback", "Node-Local", False, False, False, False, True, False, False
    
    # 0000:...:0000 -> ::/128 Belirtilmemiş Adres (Unspecified - RFC 4291)
    if int_val == 0:
        return "Unspecified Address", "Reserved", False, False, False, False, False, True, False
    
    # ff00::/8 Çok Noktaya Yayın (Multicast - RFC 4291)
    if (hextets[0] & 0xFF00) == 0xFF00:
        # Multicast bayrak ve kapsam (scope) alanını ayrıştırır: ff[flags][scope]
        scope_nibble = hextets[0] & 0x000F
        scope_map = {1: "Interface-Local", 2: "Link-Local Multicast", 5: "Site-Local Multicast", 8: "Organization-Local", 14: "Global"}
        scope_name = scope_map.get(scope_nibble, "Multicast")
        multicast_type = "Multicast"
        if hextets[0] == 0xFF02 and hextets[1] == 0 and hextets[2] == 0 and hextets[3] == 0 and hextets[4] == 0 and hextets[5] == 0 and hextets[6] == 0 and hextets[7] == 1:
            multicast_type = "Multicast (All Nodes)"
        elif hextets[0] == 0xFF02 and hextets[1] == 0 and hextets[2] == 0 and hextets[3] == 0 and hextets[4] == 0 and hextets[5] == 0 and hextets[6] == 0 and hextets[7] == 2:
            multicast_type = "Multicast (All Routers)"
        return multicast_type, scope_name, True, False, False, False, False, False, False

    # fe80::/10 Bağlantı Yerel Adresi (Link-Local Unicast - RFC 4291)
    if (hextets[0] & 0xFFC0) == 0xFE80:
        return "Link-Local Unicast", "Link-Local", False, True, False, False, False, False, False

    # fc00::/7 Benzersiz Yerel Adres (Unique Local Address - ULA / RFC 4193)
    if (hextets[0] & 0xFE00) == 0xFC00:
        return "Unique Local Address (ULA)", "Unique Local", False, False, True, False, False, False, False

    # ::ffff:0:0/96 IPv4 Eşlemeli IPv6 (IPv4-Mapped IPv6 - RFC 4291)
    if (hextets[0] == 0 and hextets[1] == 0 and hextets[2] == 0 and hextets[3] == 0 and hextets[4] == 0 and hextets[5] == 0xFFFF):
        return "IPv4-Mapped IPv6", "Transition/Dual-Stack", False, False, False, False, False, False, True

    # 2000::/3 Genel Tekil Yayın (Global Unicast - GUA / RFC 4291)
    if (hextets[0] & 0xE000) == 0x2000:
        return "Global Unicast (GUA)", "Global", False, False, False, True, False, False, False

    # Yukarıdaki standart dışındaki diğer ayrılmış adresler
    return "Reserved/Special Unicast", "Special", False, False, False, False, False, False, False


def calculate_solicited_node_multicast(hextets: List[int]) -> str:
    """
    Tekil bir IPv6 adresinden RFC 4291 uyumlu Solicited-Node Multicast adresi üretir.
    Kural: 'ff02::1:ff00:0/104' bloğunun son 24 bitine unicast adresin son 24 biti eklenir.
    """
    # Son 24 bit, hextets[6]'nın son 8 biti ile hextets[7]'nin 16 bitinden oluşur
    low24_high8 = hextets[6] & 0x00FF
    low24_low16 = hextets[7] & 0xFFFF
    
    # 7. hextet için '1:ff' formatını oluşturur
    hextet6_val = f"1:ff{low24_high8:02x}"
    # 8. hextet için 4 basamaklı hex değerini oluşturur
    hextet7_val = f"{low24_low16:04x}"
    
    # Birleştirerek kanonik Solicited-Node Multicast adresini döndürür
    return f"ff02::{hextet6_val}:{hextet7_val}"


def generate_eui64_from_mac(mac_str: str, prefix_str: str = "fe80::") -> str:
    """
    48-bitlik IEEE MAC adresinden 64-bitlik EUI-64 arayüz kimliği ve IPv6 Link-Local adresi türetir.
    Adımlar:
    1. Ortaya 'ff:fe' baytları yerleştirilir (48 bit -> 64 bit genişleme).
    2. İlk baytın 7. biti (Universal/Local - U/L biti) ters çevrilir (XOR 0x02).
    """
    # MAC adresini noktalama işaretlerinden temizler
    clean_mac = mac_str.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(clean_mac) != 12:
        raise IPv6ValidationError(f"Geçersiz MAC adresi uzunluğu, 12 onaltılık hane beklenir: {mac_str}")
    
    # 6 bayta böler
    bytes_list: List[int] = []
    for i in range(0, 12, 2):
        byte_hex = clean_mac[i:i+2]
        bytes_list.append(int(byte_hex, 16))
        
    # İlk baytın 7. bitini (U/L biti) tersine çevirir (XOR 0x02)
    bytes_list[0] = bytes_list[0] ^ 0x02
    
    # Ortaya 0xFF ve 0xFE baytlarını ekleyerek 8 bayta (64 bit) tamamlar
    eui64_bytes = bytes_list[0:3] + [0xFF, 0xFE] + bytes_list[3:6]
    
    # 4 adet 16-bit hextet oluşturur
    h1 = (eui64_bytes[0] << 8) | eui64_bytes[1]
    h2 = (eui64_bytes[2] << 8) | eui64_bytes[3]
    h3 = (eui64_bytes[4] << 8) | eui64_bytes[5]
    h4 = (eui64_bytes[6] << 8) | eui64_bytes[7]
    
    iid_str = f"{h1:04x}:{h2:04x}:{h3:04x}:{h4:04x}"
    
    # 64-bitlik Link-Local veya özel önek ile 64-bit IID'yi 8 hextetlik tam adreste birleştirir
    if prefix_str.startswith("fe80"):
        full_hextets = [0xFE80, 0, 0, 0, h1, h2, h3, h4]
    else:
        prefix_hextets, _ = expand_ipv6_address(prefix_str.rstrip(":") + "::")
        full_hextets = prefix_hextets[:4] + [h1, h2, h3, h4]
    # RFC 5952 kanonik sıkıştırmasını uygulayarak döndürür
    canonical_ip = compress_ipv6_rfc5952(full_hextets)
    return f"{canonical_ip}/64"


def analyze_ipv6(cidr_input: str) -> IPv6AddressResult:
    """Bir IPv6 veya IPv6/Prefix girdisini ayrıştırır, doğrular, sıkıştırır ve analiz eder."""
    clean_input = cidr_input.strip()
    
    # CIDR önek uzunluğu kontrolü
    if "/" in clean_input:
        parts = clean_input.split("/")
        if len(parts) != 2:
            raise IPv6ValidationError(f"Geçersiz CIDR formatı, birden fazla '/' içeriyor: {clean_input}")
        ip_part, prefix_part = parts[0], parts[1]
        try:
            prefix_len = int(prefix_part)
        except ValueError:
            raise IPv6ValidationError(f"IPv6 önek uzunluğu sayısal bir tam sayı olmalıdır: {prefix_part}")
        if prefix_len < 0 or prefix_len > 128:
            raise IPv6ValidationError(f"IPv6 önek uzunluğu 0 ile 128 arasında olmalıdır: {prefix_len}")
    else:
        ip_part = clean_input
        prefix_len = 128  # Önek belirtilmemişse tekil cihaz (/128) kabul edilir
        
    # Adresi genişletir ve hextet listesini alır
    hextets, expanded_str = expand_ipv6_address(ip_part)
    
    # 128-bit tamsayı değerini hesaplar
    int_val = 0
    for h in hextets:
        int_val = (int_val << 16) | h
        
    # 128-bit ikili metin gösterimini oluşturur
    bin128 = f"{int_val:0128b}"
    binary_str = ":".join([bin128[i:i+16] for i in range(0, 128, 16)])
    
    # RFC 5952 kanonik sıkıştırmasını uygular
    canonical_compressed = compress_ipv6_rfc5952(hextets)
    
    # Adres türü ve etki alanını tespit eder
    (addr_type, scope, is_multi, is_link, is_ula, is_gua,
     is_loop, is_unspec, is_mapped) = classify_ipv6(hextets, int_val)
     
    # Solicited-Node Multicast adresini üretir
    solicited_multi = calculate_solicited_node_multicast(hextets)
    
    # Ağ önekini hesaplar
    prefix_mask_int = ((0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF << (128 - prefix_len)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) if prefix_len > 0 else 0
    network_int = int_val & prefix_mask_int
    net_hextets = [(network_int >> (16 * (7 - i))) & 0xFFFF for i in range(8)]
    net_compressed = compress_ipv6_rfc5952(net_hextets)
    network_prefix_str = f"{net_compressed}/{prefix_len}"
    
    # Son 64-bitlik arayüz kimliğini (IID) hextet dizisi olarak kaydeder
    iid_hex = f"{hextets[4]:04x}:{hextets[5]:04x}:{hextets[6]:04x}:{hextets[7]:04x}"

    return IPv6AddressResult(
        input_cidr=clean_input,
        expanded_address=expanded_str,
        canonical_compressed=canonical_compressed,
        int_value=int_val,
        binary_str=binary_str,
        prefix_length=prefix_len,
        network_prefix=network_prefix_str,
        interface_id_hex=iid_hex,
        address_type=addr_type,
        scope=scope,
        solicited_node_multicast=solicited_multi,
        is_multicast=is_multi,
        is_link_local=is_link,
        is_unique_local=is_ula,
        is_global_unicast=is_gua,
        is_loopback=is_loop,
        is_unspecified=is_unspec,
        is_ipv4_mapped=is_mapped
    )


def generate_markdown_report(results: List[IPv6AddressResult]) -> str:
    """IPv6 analiz sonuçlarını kurumsal güvenlik raporu formatında Markdown olarak derler."""
    lines: List[str] = [
        "# IPv6 Temel Kavramlar, Sıkıştırma ve Adres Güvenliği Analiz Raporu",
        "",
        "Bu rapor, analiz edilen IPv6 adreslerinin 128-bit açılımını, RFC 5952 kanonik sıkıştırma",
        "durumunu, IETF standartları çerçevesindeki etki alanlarını ve komşu keşfi (NDP) adreslerini listeler.",
        "",
        "| ID / Girdi | Kanonik Sıkıştırılmış | Tür | Kapsam (Scope) | Solicited Multicast | Önek |",
        "|---|---|---|---|---|---|"
    ]
    
    for r in results:
        lines.append(
            f"| `{r.input_cidr}` | `{r.canonical_compressed}` | {r.address_type} | {r.scope} | `{r.solicited_node_multicast}` | `/{r.prefix_length}` |"
        )
        
    lines.append("")
    lines.append("## IPv6 Güvenlik ve Savunma Tavsiyeleri")
    lines.append("- **Rogue RA ve RA Guard (RFC 6105):** Anahtarlar (Switch) üzerinde RA Guard aktifleştirilerek yetkisiz yönlendirici duyuruları engellenmeli, MitM atakları durdurulmalıdır.")
    lines.append("- **Gizlilik Eklentileri (RFC 4941):** İstemcilerde donanım MAC adresini sızdıran EUI-64 yerine rastgele geçici adresler (Privacy Extensions) zorunlu tutulmalıdır.")
    lines.append("- **Gölge Ağ (Dual-Stack Shadow Network) Tehlikesi:** Ağda IPv4 için güvenlik duvarı ve IPS varken IPv6 trafiği denetimsiz bırakılmamalı; tüm güvenlik kuralları IPv6 için de eşit sıkılıkta uygulanmalıdır.")
    lines.append("- **ICMPv6 Filtreleme Hassasiyeti:** ICMPv6 körlemesine engellenmemelidir. Komşu Keşfi (NDP - Type 133-136) engellenirse IPv6 iletişimi tamamen çöker; yalnızca sınır arayüzlerinde gerekli filtreler konmalıdır.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Komut satırından çalıştırıldığında örnek veri setini işler ve konsola yazdırır."""
    import os  # Dosya yolu yönetimi için os kütüphanesi kullanılır
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_file = os.path.join(base_dir, "ornek_veri", "sample_ipv6_addresses.json")
    
    if not os.path.exists(sample_file):
        print(f"Hata: Örnek veri dosyası bulunamadı: {sample_file}")
        sys.exit(1)
        
    with open(sample_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    results: List[IPv6AddressResult] = []
    print("=" * 80)
    print("G046: IPv6 Temel Kavramlar, Sıkıştırma ve Adres Güvenliği Laboratuvarı")
    print("=" * 80)
    
    for item in data.get("ornekler", []):
        cidr = item["girdi"]
        res = analyze_ipv6(cidr)
        results.append(res)
        print(f"[*] Analiz Edilen: {cidr} ({item['aciklama']})")
        print(f"    - Tam Açık Adres (Expanded)  : {res.expanded_address}")
        print(f"    - Kanonik Sıkıştırma (RFC5952): {res.canonical_compressed}")
        print(f"    - Adres Türü ve Kapsam       : {res.address_type} ({res.scope})")
        print(f"    - Ağ Öneki (Network Prefix)   : {res.network_prefix}")
        print(f"    - Arayüz Kimliği (IID)        : {res.interface_id_hex}")
        print(f"    - Solicited-Node Multicast   : {res.solicited_node_multicast}")
        print("-" * 80)
        
    # EUI-64 türetim gösterimi
    sample_mac = "00:1A:2B:3C:4D:5E"
    eui64_ip = generate_eui64_from_mac(sample_mac)
    print(f"\n[+] EUI-64 Örnek Türetimi (MAC: {sample_mac}) -> {eui64_ip}")
    print("[+] Özet IPv6 Analiz Raporu Başarıyla Oluşturuldu.\n")


if __name__ == "__main__":
    main()  # Betik doğrudan çağrıldığında ana fonksiyonu tetikler
