# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G045: IPv4 Adresleme, Alt Ağlar (Subnetting) ve CIDR Analiz Modülü.
Bu modül, IPv4 adres yapısını, CIDR gösterimini, bit düzeyinde ağ maskesi
ve wildcard hesaplamalarını, RFC 1918 ve Bogon IP sınıflandırmasını,
noktadan noktaya (/31 RFC 3021) ve tekil konak (/32) istisnalarını
kapsamlı bir şekilde matematiksel ve güvenlik odaklı olarak modeller.
"""

import sys  # Standart sistem modülü, konsol çıktı kodlamasını ayarlamak için dahil edilir
import json  # JSON veri setlerini okumak ve ayrıştırmak için standart kütüphane kullanılır
from dataclasses import dataclass  # Yapılandırılmış alt ağ veri modellerini tutmak için dataclass kullanılır
from typing import Optional, List, Tuple  # Tip ipuçları ve statik doğrulama için tip tanımları dahil edilir

# Windows platformunda standart çıktı akışını UTF-8 karakter kümesine zorlayarak Türkçe karakter hatalarını önler
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Konsol standart çıktı akışını UTF-8 yapar
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # Konsol hata çıktı akışını UTF-8 yapar


class IPv4ValidationError(ValueError):
    """IPv4 adresi, maskesi veya CIDR önek doğrulaması başarısız olduğunda fırlatılan özel istisna sınıfı."""
    pass  # Özel hata sınıfı için ek metot tanımlanmadan miras alınan yapı korunur


@dataclass
class IPv4SubnetResult:
    """Tek bir alt ağ (subnet) analiz sonucunu temsil eden yapılandırılmış veri sınıfı."""
    input_cidr: str  # Kullanıcı veya sistem tarafından girilen ham CIDR ifadesi (Örn: 192.168.1.10/24)
    ip_address: str  # Ayrıştırılan tekil IPv4 adresi metinsel gösterimi
    prefix_length: int  # CIDR önek bit uzunluğu (/0 ile /32 arasında)
    ip_integer: int  # 32-bitlik işaretsiz tamsayı formatındaki IP değeri
    ip_binary: str  # 8-bitlik gruplara ayrılmış noktalı ikili (binary) gösterim
    netmask_str: str  # Noktalı ondalık alt ağ maskesi (Örn: 255.255.255.0)
    netmask_binary: str  # Alt ağ maskesinin noktalı ikili bit gösterimi
    wildcard_str: str  # Güvenlik duvarı ve ACL filtrelerinde kullanılan ters maske (Örn: 0.0.0.255)
    network_address: str  # Alt ağın başlangıç (ağ kimliği) adresi
    broadcast_address: str  # Alt ağın son (yayın) adresi (RFC 3021 ve /32 durumunda özel belirtilir)
    first_usable_host: str  # Konaklara atanabilecek ilk geçerli IP adresi
    last_usable_host: str  # Konaklara atanabilecek son geçerli IP adresi
    total_addresses: int  # Alt ağdaki kuramsal toplam IP adresi sayısı (2^(32-prefix))
    usable_hosts: int  # Cihazlara atanabilir gerçek konak sayısı
    category: str  # IP adresinin RFC kapsamındaki kurumsal/kamusal sınıflandırması
    is_bogon: bool  # Genel İnternet omurgasında yönlendirilmemesi gereken sahte/bogon IP bayrağı
    is_private: bool  # RFC 1918 kapsamında yerel ağlara ayrılmış özel IP alanı bayrağı


def validate_and_parse_ip(ip_str: str) -> Tuple[int, List[int]]:
    """
    Noktalı ondalık formattaki IPv4 adresini doğrular ve 32-bit tamsayıya çevirir.
    
    Kontroller:
    - 4 oktet varlığı
    - Her oktetin 0-255 aralığında sayısal olması
    - Başında anlamsız sıfır (leading zero) bulunmaması (Örn: '01' octal yanılsamasını önlemek için)
    """
    # Girdi metninin boşluklarını temizler
    clean_ip = ip_str.strip()
    
    # Nokta karakterine göre oktetlere böler
    parts = clean_ip.split(".")
    
    # Tam olarak 4 oktet bulunup bulunmadığını kontrol eder
    if len(parts) != 4:
        raise IPv4ValidationError(f"IPv4 adresi tam olarak 4 oktetten oluşmalıdır, bulunan: {len(parts)}")
    
    octets: List[int] = []  # Sayısal oktetleri saklamak için boş liste başlatılır
    for part in parts:
        # Oktetin sadece rakamlardan oluşup oluşmadığını denetler
        if not part.isdigit():
            raise IPv4ValidationError(f"Oktet sayısal bir değer olmalıdır: '{part}'")
        
        # '01' gibi başta gereksiz sıfır kontrolü yapar (0 hariç tek başına '0' geçerlidir)
        if len(part) > 1 and part.startswith("0"):
            raise IPv4ValidationError(f"Oktet başında sıfır (leading zero) bulunamaz: {part}")
        
        # Metinsel değeri tamsayıya dönüştürür
        val = int(part)
        
        # 8-bit sınırları (0-255) denetimini gerçekleştirir
        if val < 0 or val > 255:
            raise IPv4ValidationError(f"Oktet değeri 0 ile 255 arasında olmalıdır: {val}")
        
        octets.append(val)  # Doğrulanan okteti listeye ekler
    
    # 4 okteti bit kaydırma yöntemiyle tek bir 32-bitlik işaretsiz tamsayıya birleştirir
    ip_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    return ip_int, octets


def int_to_dotted_decimal(val: int) -> str:
    """32-bit işaretsiz tamsayıyı noktalı ondalık (X.X.X.X) IPv4 formatına dönüştürür."""
    # 24 bit sağa kaydırıp ilk okteti elde eder
    o1 = (val >> 24) & 0xFF
    # 16 bit sağa kaydırıp ikinci okteti elde eder
    o2 = (val >> 16) & 0xFF
    # 8 bit sağa kaydırıp üçüncü okteti elde eder
    o3 = (val >> 8) & 0xFF
    # Son 8 biti maskeleyerek dördüncü okteti elde eder
    o4 = val & 0xFF
    return f"{o1}.{o2}.{o3}.{o4}"


def int_to_binary_str(val: int) -> str:
    """32-bit işaretsiz tamsayıyı 8 bitlik nokta ayrımlı ikili (binary) metne dönüştürür."""
    # 32 bitlik ikili dizgeyi 0 ile doldurarak üretir
    bin32 = f"{val:032b}"
    # 8'er bitlik parçalara bölerek noktayla birleştirir
    return f"{bin32[0:8]}.{bin32[8:16]}.{bin32[16:24]}.{bin32[24:32]}"


def prefix_to_mask_int(prefix: int) -> int:
    """CIDR önek uzunluğunu (/0-/32) 32-bit alt ağ maskesi tamsayısına dönüştürür."""
    # Önek sınırlarını 0 ile 32 arasında kesin olarak sınar
    if prefix < 0 or prefix > 32:
        raise IPv4ValidationError(f"CIDR önek uzunluğu 0 ile 32 arasında olmalıdır: {prefix}")
    
    # Prefix 0 ise maske tamamen 0'dır (0.0.0.0)
    if prefix == 0:
        return 0
    
    # Prefix uzunluğu kadar soldan 1 biti yerleştirir
    return ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)


def mask_str_to_prefix(mask_str: str) -> int:
    """
    Noktalı ondalık alt ağ maskesini doğrular ve CIDR önek uzunluğuna dönüştürür.
    Maskenin bitişik (contiguous) 1'lerden oluştuğunu garanti eder.
    """
    mask_int, _ = validate_and_parse_ip(mask_str)  # Maskeyi 32-bit tamsayıya çevirir
    
    # İkili formatta bit dizisini inceler
    bin_str = f"{mask_int:032b}"
    
    # 1'lerin bitip 0'ların başladığı noktadan sonra tekrar 1 gelip gelmediğini kontrol eder
    zero_started = False
    prefix_count = 0
    for bit in bin_str:
        if bit == "1":
            if zero_started:
                raise IPv4ValidationError(f"Geçersiz alt ağ maskesi, 1'ler bitişik olmalıdır: {mask_str}")
            prefix_count += 1
        else:
            zero_started = True
            
    return prefix_count


def classify_ipv4(ip_int: int) -> Tuple[str, bool, bool]:
    """
    32-bit IPv4 tamsayı değerini IETF RFC standartlarına göre sınıflandırır.
    Döndürür: (kategori_adi, bogon_mu, ozel_ip_mi)
    """
    # 0.0.0.0/8 - Bu ağdaki konaklar (RFC 1122)
    if (ip_int & 0xFF000000) == 0x00000000:
        return "RFC 1122 'This host on this network'", True, False
    
    # 10.0.0.0/8 - RFC 1918 Özel Ağ (Class A)
    if (ip_int & 0xFF000000) == 0x0A000000:
        return "RFC 1918 Private (Class A)", True, True
    
    # 100.64.0.0/10 - RFC 6598 Operatör Seviyesi NAT (CGNAT)
    if (ip_int & 0xFFC00000) == 0x64400000:
        return "RFC 6598 Shared Address Space (CGNAT)", True, False
    
    # 127.0.0.0/8 - RFC 1122 Geri Döngü (Loopback)
    if (ip_int & 0xFF000000) == 0x7F000000:
        return "RFC 1122 Loopback", True, False
    
    # 169.254.0.0/16 - RFC 3927 Bağlantı Yerel (Link-Local / APIPA)
    if (ip_int & 0xFFFF0000) == 0xA9FE0000:
        return "RFC 3927 Link-Local (APIPA)", True, False
    
    # 172.16.0.0/12 - RFC 1918 Özel Ağ (Class B) (172.16.0.0 - 172.31.255.255)
    if (ip_int & 0xFFF00000) == 0xAC100000:
        return "RFC 1918 Private (Class B)", True, True
    
    # 192.0.0.0/24 - RFC 6890 IETF Protokol Atamaları
    if (ip_int & 0xFFFFFF00) == 0xC0000000:
        return "RFC 6890 IETF Protocol Assignments", True, False
    
    # 192.0.2.0/24 - RFC 5737 Test Ağı 1 (TEST-NET-1)
    if (ip_int & 0xFFFFFF00) == 0xC0000200:
        return "RFC 5737 Documentation (TEST-NET-1)", True, False
    
    # 192.168.0.0/16 - RFC 1918 Özel Ağ (Class C)
    if (ip_int & 0xFFFF0000) == 0xC0A80000:
        return "RFC 1918 Private (Class C)", True, True
    
    # 198.18.0.0/15 - RFC 2544 Ağ Performans Karşılaştırma Testleri
    if (ip_int & 0xFFFE0000) == 0xC6120000:
        return "RFC 2544 Benchmarking", True, False
    
    # 198.51.100.0/24 - RFC 5737 Test Ağı 2 (TEST-NET-2)
    if (ip_int & 0xFFFFFF00) == 0xC6336400:
        return "RFC 5737 Documentation (TEST-NET-2)", True, False
    
    # 203.0.113.0/24 - RFC 5737 Test Ağı 3 (TEST-NET-3)
    if (ip_int & 0xFFFFFF00) == 0xCB007100:
        return "RFC 5737 Documentation (TEST-NET-3)", True, False
    
    # 224.0.0.0/4 - RFC 5771 Çok Noktaya Yayın (Multicast - D Sınıfı)
    if (ip_int & 0xF0000000) == 0xE0000000:
        return "RFC 5771 Multicast (Class D)", True, False
    
    # 240.0.0.0/4 - RFC 1112 Gelecekte Kullanım İçin Ayrılmış (E Sınıfı)
    if (ip_int & 0xF0000000) == 0xF0000000:
        if ip_int == 0xFFFFFFFF:
            return "RFC 919 Limited Broadcast", True, False
        return "RFC 1112 Reserved for Future Use (Class E)", True, False
    
    # Yukarıdaki özel bloklar haricindeki tüm adresler genel internette yönlendirilebilir IP'dir
    return "Public Routable IP", False, False


def calculate_subnet(cidr_input: str) -> IPv4SubnetResult:
    """
    Bir CIDR dizgesini (Örn: 192.168.1.10/24) ayrıştırır ve tüm alt ağ bileşenlerini hesaplar.
    RFC 3021 (/31) ve RFC 1122 (/32) istisnai durumlarını tam uyumlulukla işler.
    """
    clean_input = cidr_input.strip()
    
    # Bölü çizgisi kontrolü ile CIDR formatını sınar
    if "/" not in clean_input:
        raise IPv4ValidationError(f"CIDR biçimi eksik, '/' ayracı bulunamadı: {clean_input}")
    
    parts = clean_input.split("/")
    if len(parts) != 2:
        raise IPv4ValidationError(f"Geçersiz CIDR formatı, birden fazla '/' içeriyor: {clean_input}")
    
    ip_part, prefix_part = parts[0], parts[1]
    
    # Önekin sayısal tam sayı olup olmadığını sınar
    try:
        prefix_len = int(prefix_part)
    except ValueError:
        raise IPv4ValidationError(f"CIDR önek uzunluğu sayısal bir tam sayı olmalıdır: {prefix_part}")
    
    # Önek sınırlarını kontrol eder
    if prefix_len < 0 or prefix_len > 32:
        raise IPv4ValidationError(f"CIDR önek uzunluğu 0 ile 32 arasında olmalıdır: {prefix_len}")
    
    # IP adresini doğrular ve tamsayıya çevirir
    ip_int, _ = validate_and_parse_ip(ip_part)
    ip_normalized_str = int_to_dotted_decimal(ip_int)
    ip_binary_str = int_to_binary_str(ip_int)
    
    # Maske ve ters maske (wildcard) hesaplamalarını yürütür
    mask_int = prefix_to_mask_int(prefix_len)
    mask_str = int_to_dotted_decimal(mask_int)
    mask_binary_str = int_to_binary_str(mask_int)
    
    wildcard_int = (~mask_int) & 0xFFFFFFFF
    wildcard_str = int_to_dotted_decimal(wildcard_int)
    
    # Ağ adresi hesaplama: IP & Netmask
    network_int = ip_int & mask_int
    network_str = int_to_dotted_decimal(network_int)
    
    # Yayın adresi hesaplama: IP | Wildcard
    broadcast_int = ip_int | wildcard_int
    broadcast_str_calc = int_to_dotted_decimal(broadcast_int)
    
    # Toplam adres sayısı: 2^(32 - prefix)
    host_bits = 32 - prefix_len
    total_addresses = 2 ** host_bits
    
    # Sınıflandırma ve güvenlik bayraklarını belirler
    category, is_bogon, is_private = classify_ipv4(ip_int)
    
    # RFC 3021 (/31) ve /32 uç durum mantığı
    if prefix_len == 32:
        # /32 Tekil cihaz/host rotasıdır; yayın ve alt ağ adresi kavramı yoktur
        broadcast_str = "Yok (/32 Tekil Host)"
        first_host_str = ip_normalized_str
        last_host_str = ip_normalized_str
        usable_hosts = 1
    elif prefix_len == 31:
        # RFC 3021: Yönlendiriciler arası noktadan noktaya bağlantılarda iki IP de konak olarak kullanılır
        broadcast_str = "Yok (RFC 3021)"
        first_host_str = int_to_dotted_decimal(network_int)
        last_host_str = int_to_dotted_decimal(broadcast_int)
        usable_hosts = 2
    else:
        # Standart /0 - /30 aralığındaki alt ağlar
        broadcast_str = broadcast_str_calc
        first_host_str = int_to_dotted_decimal(network_int + 1)
        last_host_str = int_to_dotted_decimal(broadcast_int - 1)
        # Kullanılabilir konak sayısı: Toplam - 2 (Ağ ve Yayın adresleri rezerve)
        usable_hosts = total_addresses - 2 if total_addresses >= 2 else 0

    return IPv4SubnetResult(
        input_cidr=clean_input,
        ip_address=ip_normalized_str,
        prefix_length=prefix_len,
        ip_integer=ip_int,
        ip_binary=ip_binary_str,
        netmask_str=mask_str,
        netmask_binary=mask_binary_str,
        wildcard_str=wildcard_str,
        network_address=network_str,
        broadcast_address=broadcast_str,
        first_usable_host=first_host_str,
        last_usable_host=last_host_str,
        total_addresses=total_addresses,
        usable_hosts=usable_hosts,
        category=category,
        is_bogon=is_bogon,
        is_private=is_private
    )


def is_ip_in_subnet(target_ip: str, cidr_str: str) -> bool:
    """Belirli bir IP adresinin hedef CIDR bloğuna ait olup olmadığını bit düzeyinde test eder."""
    # Hedef IP adresini tamsayıya çevirir
    target_int, _ = validate_and_parse_ip(target_ip)
    
    # Alt ağın ağ adresini ve maskesini hesaplar
    sub = calculate_subnet(cidr_str)
    sub_net_int = sub.ip_integer & prefix_to_mask_int(sub.prefix_length)
    
    # Hedef IP adresini aynı alt ağ maskesi ile maskeler
    target_net_int = target_int & prefix_to_mask_int(sub.prefix_length)
    
    # İki ağ kimliğinin eşitliğini karşılaştırır
    return target_net_int == sub_net_int


def split_subnet(cidr_str: str, new_prefix: int) -> List[IPv4SubnetResult]:
    """
    Değişken Uzunluklu Alt Ağ Maskeleme (VLSM) prensibiyle bir ana CIDR bloğunu
    daha küçük alt ağlara böler.
    """
    parent = calculate_subnet(cidr_str)  # Ana ağı hesaplar
    
    if new_prefix <= parent.prefix_length:
        raise IPv4ValidationError(
            f"Yeni önek ({new_prefix}) ana önekten ({parent.prefix_length}) daha büyük olmalıdır."
        )
    if new_prefix > 32:
        raise IPv4ValidationError(f"Yeni önek 32'den büyük olamaz: {new_prefix}")
    
    # Alt ağ adedini hesaplar: 2^(yeni_prefix - ana_prefix)
    subnet_count = 2 ** (new_prefix - parent.prefix_length)
    # Her bir yeni alt ağın adım büyüklüğünü belirler: 2^(32 - yeni_prefix)
    step = 2 ** (32 - new_prefix)
    
    # Ana ağın başlangıç tamsayı değerini temel alır
    base_network_int = parent.ip_integer & prefix_to_mask_int(parent.prefix_length)
    
    results: List[IPv4SubnetResult] = []  # Bölünen alt ağları depolamak için liste
    for i in range(subnet_count):
        sub_ip_int = base_network_int + (i * step)
        sub_cidr = f"{int_to_dotted_decimal(sub_ip_int)}/{new_prefix}"
        results.append(calculate_subnet(sub_cidr))
        
    return results


def generate_markdown_report(subnets: List[IPv4SubnetResult]) -> str:
    """Ayrıştırılan alt ağların güvenlik ve yapılandırma raporunu Markdown formatında üretir."""
    lines: List[str] = [
        "# IPv4 Adresleme, Alt Ağ (Subnetting) ve CIDR Analiz Raporu",
        "",
        "Bu rapor, analiz edilen alt ağların bit düzeyindeki maske, ağ, yayın, konak aralıklarını",
        "ve IETF standartları çerçevesindeki güvenlik/bogon durumlarını belgeler.",
        "",
        "| ID / CIDR | Ağ Adresi | Alt Ağ Maskesi | Kullanılabilir Aralık | Toplam / Konak | Kategori | Bogon |",
        "|---|---|---|---|---|---|---|"
    ]
    
    for sub in subnets:
        host_range = f"{sub.first_usable_host} - {sub.last_usable_host}" if sub.usable_hosts > 0 else "Yok"
        bogon_status = "⚠️ EVET (Filtrele)" if sub.is_bogon else "✅ HAYIR (Genel)"
        lines.append(
            f"| `{sub.input_cidr}` | `{sub.network_address}` | `{sub.netmask_str}` | `{host_range}` | {sub.total_addresses} / {sub.usable_hosts} | {sub.category} | {bogon_status} |"
        )
        
    lines.append("")
    lines.append("## Güvenlik Denetim Notları ve Savunma Tavsiyeleri")
    lines.append("- **BCP 38 / RFC 2827:** Dış WAN arayüzlerinden içeri giren ve kaynak adresi Bogon/RFC 1918 olan paketler derhal atılmalıdır (Ingress Filtering).")
    lines.append("- **Mikro-Segmentasyon:** DMZ ve hassas veritabanı ağlarında /28 veya /29 gibi daraltılmış alt ağlar kullanarak yanal hareketi (lateral movement) kısıtlayın.")
    lines.append("- **Noktadan Noktaya Bağlantılar:** Yönlendirici arası linklerde RFC 3021 (/31) kullanarak IP israfını ve yayın trafiği riskini engelleyin.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Komut satırından çalıştırıldığında örnek veri setini işler ve konsola yazdırır."""
    import os  # Dosya yollarını yönetmek için os modülü dahil edilir
    
    # Örnek veri dosyasının konumunu dinamik olarak tespit eder
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_file = os.path.join(base_dir, "ornek_veri", "sample_subnets.json")
    
    if not os.path.exists(sample_file):
        print(f"Hata: Örnek veri dosyası bulunamadı: {sample_file}")
        sys.exit(1)
        
    with open(sample_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    results: List[IPv4SubnetResult] = []
    print("=" * 80)
    print("G045: IPv4 Adresleme, Alt Ağ (Subnetting) ve CIDR Analiz Laboratuvarı")
    print("=" * 80)
    
    for item in data.get("ornekler", []):
        cidr = item["girdi"]
        sub = calculate_subnet(cidr)
        results.append(sub)
        print(f"[*] Analiz Edilen: {cidr} ({item['aciklama']})")
        print(f"    - Ağ Adresi      : {sub.network_address}")
        print(f"    - Alt Ağ Maskesi : {sub.netmask_str} ({sub.netmask_binary})")
        print(f"    - Ters Maske     : {sub.wildcard_str}")
        print(f"    - Yayın Adresi   : {sub.broadcast_address}")
        print(f"    - Konak Aralığı  : {sub.first_usable_host} - {sub.last_usable_host}")
        print(f"    - Konak Kapasite : {sub.usable_hosts} kullanılabilir / {sub.total_addresses} toplam")
        print(f"    - Kategori       : {sub.category}")
        print(f"    - Bogon / Filtre : {'EVET (Engelle)' if sub.is_bogon else 'HAYIR (Genel)'}")
        print("-" * 80)
        
    report = generate_markdown_report(results)
    print("\n[+] Özet Analiz Raporu Başarıyla Oluşturuldu.\n")


if __name__ == "__main__":
    main()  # Betik doğrudan çağrıldığında ana yürütme fonksiyonunu tetikler
