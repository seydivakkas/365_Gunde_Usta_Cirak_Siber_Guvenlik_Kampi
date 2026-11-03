# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G048: İnternet Denetim Mesajı Protokolü (ICMP), Ağ Teşhisi ve Tünelleme (Covert Channel) Analiz Motoru.
Bu modül, RFC 792 ICMPv4 başlık mimarisini, 1's complement internet sağlama toplamı (checksum)
hesaplama ve doğrulamasını, Ping (Echo Request/Reply) döngüsünü, Traceroute TTL tükenme mekanizmasını,
PMTUD parçalanma kontrollerini ve ICMP veri alanı üzerinden yapılan gizli tünelleme (covert channel)
saldırılarının tespitini modeller.
"""

import sys  # Standart sistem modülü, konsol UTF-8 çıktı kodlamasını yapılandırmak için dahil edilir
import json  # JSON veri setlerini okumak ve ayrıştırmak için standart modül dahil edilir
import struct  # İkili (binary) ağ başlıklarını paketlemek ve çözmek için struct modülü dahil edilir
from dataclasses import dataclass, field  # Yapılandırılmış veri modelleri için dataclass dahil edilir
from typing import List, Dict, Tuple, Optional  # Statik tip güvenliği için tip ipuçları dahil edilir

# Windows platformunda standart çıktı akışını UTF-8 karakter kümesine zorlayarak Türkçe karakter hatalarını önler
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Standart çıktı akışını UTF-8 yapar
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # Standart hata akışını UTF-8 yapar


class ICMPValidationError(ValueError):
    """ICMP paket başlığı, geçersiz tip/kod, sağlama toplamı (checksum) veya IP doğrulaması başarısız olduğunda fırlatılır."""
    pass  # Temel ValueError davranışını devralarak özel hata türü oluşturur


# RFC 792 Standart ICMP Tipleri ve İlgili Kod Tanımları Haritası
ICMP_TYPE_CODE_MAP = {
    0: {0: "Echo Reply"},  # Ping yanıtı
    3: {  # Hedef Ulaşılamaz (Destination Unreachable)
        0: "Net Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation Needed and DF set",
        5: "Source Route Failed"
    },
    5: {  # Yönlendirme (Redirect)
        0: "Redirect Datagram for the Network",
        1: "Redirect Datagram for the Host",
        2: "Redirect Datagram for the TOS & Network",
        3: "Redirect Datagram for the TOS & Host"
    },
    8: {0: "Echo Request"},  # Ping isteği
    11: {  # Zaman Aşımı (Time Exceeded)
        0: "Time to Live exceeded in Transit",  # Traceroute mekanizması
        1: "Fragment Reassembly Time Exceeded"
    },
    12: {  # Parametre Problemi
        0: "Pointer indicates the error",
        1: "Missing a Required Option",
        2: "Bad Length"
    }
}


def calculate_internet_checksum(data: bytes) -> int:
    """
    RFC 1071 standardına göre 16-bitlik Bir'in Tümleyeni (1's complement)
    İnternet Sağlama Toplamı (Internet Checksum) hesaplar.
    """
    # Eğer veri tek sayıda bayttan oluşuyorsa sonuna 0x00 dolgusu ekler
    if len(data) % 2 != 0:
        data += b"\x00"
        
    total_sum = 0  # Toplamı saklayacak değişken
    
    # 2 baytlık (16 bit) bloklar halinde toplar
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total_sum += word
        
    # 32 bitlik taşmaları (carry bits) 16 bitlik tabana geri katlar
    while (total_sum >> 16) > 0:
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)
        
    # Bütün bitleri ters çevirerek (bitwise NOT) tümleyeni alır
    checksum = (~total_sum) & 0xFFFF
    return checksum


def validate_ipv4_address(ip_str: str) -> str:
    """IPv4 adresinin 4 oktet ve 0-255 sınırlarında olduğunu denetler."""
    if not ip_str or not isinstance(ip_str, str):
        raise ICMPValidationError("IP adresi alanı boş olamaz")
    parts = ip_str.strip().split(".")
    if len(parts) != 4:
        raise ICMPValidationError(f"Geçersiz IPv4 adres formatı: {ip_str}")
    for p in parts:
        if not p.isdigit() or int(p) < 0 or int(p) > 255:
            raise ICMPValidationError(f"Geçersiz IPv4 kaynak/hedef adresi: {ip_str}")
    return ip_str.strip()


@dataclass
class ICMPPacketInfo:
    """Ayrıştırılan ve denetlenen tekil bir ICMP paketinin ayrıntılarını temsil eden veri sınıfı."""
    packet_id: str  # Test veya paket kimliği
    icmp_type: int  # ICMP Tip numarası (Örn: 8 = Echo Request, 0 = Echo Reply)
    icmp_code: int  # ICMP Kod numarası (Örn: 0, 1, 3, 4)
    type_name: str  # Tipin metinsel tanımı
    code_name: str  # Kodun metinsel açıklaması
    checksum: int  # Pakette taşınan 16-bitlik sağlama toplamı
    is_checksum_valid: bool  # Sağlama toplamının matematiksel olarak geçerli olup olmadığı
    identifier: int  # İstek/yanıt eşleme kimliği (Identifier / PID)
    sequence: int  # Sıra numarası (Sequence Number)
    source_ip: str  # Gönderici IPv4 adresi
    dest_ip: str  # Hedef IPv4 adresi
    ttl: int  # IP başlığındaki Yaşam Süresi (Time to Live)
    payload_size: int  # Veri alanının (Payload) bayt cinsinden boyutu
    payload_text: str  # Veri alanının metinsel veya hex gösterimi
    is_anomalous: bool  # Güvenlik anomalisi bayrağı
    anomaly_reasons: List[str]  # Tespit edilen güvenlik ihlallerinin listesi


def build_icmp_packet(
    icmp_type: int,
    icmp_code: int,
    identifier: int,
    sequence: int,
    payload: bytes
) -> bytes:
    """
    Verilen alanlarla RFC 792 uyumlu 8 baytlık başlık ve payload içeren ikili (binary) paket üretir.
    Sağlama toplamını (checksum) otomatik olarak hesaplar ve başlığa yerleştirir.
    """
    # Tip ve kod geçerliliğini denetler
    if icmp_type not in ICMP_TYPE_CODE_MAP:
        raise ICMPValidationError(f"Tanımsız veya desteklenmeyen ICMP tipi: {icmp_type}")
    if icmp_code not in ICMP_TYPE_CODE_MAP[icmp_type]:
        raise ICMPValidationError(
            f"{ICMP_TYPE_CODE_MAP[icmp_type].get(0, 'ICMP')} için geçersiz kod: {icmp_code}"
        )
    # Kimlik ve sıra numarası sınır kontrolü
    if identifier < 0 or identifier > 65535:
        raise ICMPValidationError(f"Identifier değeri 0 ile 65535 arasında olmalıdır: {identifier}")
    if sequence < 0 or sequence > 65535:
        raise ICMPValidationError(f"Sequence numarası 0 ile 65535 arasında olmalıdır: {sequence}")
        
    # Checksum alanı başlangıçta 0x0000 olarak 8 baytlık başlığı paketler
    header_without_checksum = struct.pack("!BBHHH", icmp_type, icmp_code, 0, identifier, sequence)
    
    # Başlık ve veri alanını birleştirerek sağlama toplamını hesaplar
    raw_packet = header_without_checksum + payload
    calculated_checksum = calculate_internet_checksum(raw_packet)
    
    # Gerçek sağlama toplamını başlığın 2-4. baytlarına gömer
    final_header = struct.pack("!BBHHH", icmp_type, icmp_code, calculated_checksum, identifier, sequence)
    return final_header + payload


def parse_and_analyze_icmp(
    packet_bytes: bytes,
    source_ip: str,
    dest_ip: str,
    ttl: int,
    packet_id: str = "PKT-001"
) -> ICMPPacketInfo:
    """
    İkili ICMP paketini ayrıştırır, sağlama toplamını doğrular,
    RFC kodlarını eşleştirir ve tünelleme/anomali denetimini gerçekleştirir.
    """
    # IP adreslerini doğrular
    valid_src = validate_ipv4_address(source_ip)
    valid_dst = validate_ipv4_address(dest_ip)
    
    # Asgari ICMP başlık uzunluğu 8 bayttır
    if len(packet_bytes) < 8:
        raise ICMPValidationError(f"Eksik ICMP paketi, en az 8 bayt beklenir: {len(packet_bytes)} bayt")
        
    # Başlığı ayrıştırır: Type (1B), Code (1B), Checksum (2B), ID (2B), Seq (2B)
    icmp_type, icmp_code, carried_checksum, identifier, sequence = struct.unpack("!BBHHH", packet_bytes[:8])
    payload = packet_bytes[8:]
    
    # Tip geçerliliğini denetler
    if icmp_type not in ICMP_TYPE_CODE_MAP:
        raise ICMPValidationError(f"Tanımsız veya desteklenmeyen ICMP tipi: {icmp_type}")
        
    # Kod geçerliliğini denetler
    valid_codes = ICMP_TYPE_CODE_MAP[icmp_type]
    if icmp_code not in valid_codes:
        if icmp_type == 0:
            raise ICMPValidationError(f"Echo Reply (Type 0) için yalnızca Code 0 geçerlidir, bulunan: {icmp_code}")
        elif icmp_type == 8:
            raise ICMPValidationError(f"Echo Request (Type 8) için yalnızca Code 0 geçerlidir, bulunan: {icmp_code}")
        elif icmp_type == 11:
            raise ICMPValidationError(f"Time Exceeded (Type 11) için yalnızca Code 0 (transit) veya 1 (reassembly) geçerlidir, bulunan: {icmp_code}")
        else:
            raise ICMPValidationError(f"ICMP Type {icmp_type} için geçersiz kod: {icmp_code}")
            
    # Sağlama Toplamı (Checksum) Doğrulaması:
    # Verinin tamamının (başlıkta mevcut checksum varken) sağlama toplamı 0x0000 olmalıdır
    verification_sum = calculate_internet_checksum(packet_bytes)
    is_valid_checksum = (verification_sum == 0)
    
    if not is_valid_checksum:
        raise ICMPValidationError("ICMP Checksum doğrulama hatası (Sahte veya bozulmuş paket)")

    type_str = list(valid_codes.values())[0] if icmp_code not in valid_codes else valid_codes[icmp_code]
    code_str = valid_codes.get(icmp_code, f"Code {icmp_code}")

    # Payload metin çözümleme
    try:
        payload_text = payload.decode("utf-8", errors="replace")
    except Exception:
        payload_text = payload.hex()

    # Siber Güvenlik Anomali ve Tünelleme (Covert Channel) Tespiti
    anomalies: List[str] = []
    
    # 1. ICMP Redirect (Type 5) Tehlikesi
    if icmp_type == 5:
        anomalies.append("ICMP Redirect (Type 5): Rotalama manipülasyonu ve MitM saldırı vektörü olabilir!")
        
    # 2. Standart dışı aşırı büyük payload (>64 bayt)
    if (icmp_type in (0, 8)) and len(payload) > 64:
        anomalies.append(f"Aşırı büyük ICMP Payload ({len(payload)} bayt > 64 bayt): Olası veri sızıntısı veya tampon!")
        
    # 3. Payload içinde şüpheli metin / C2 anahtar kelimeleri
    covert_keywords = ["EXFILTRATED", "SECRET", "PASSWORD", "PASS=", "API_KEY", "USER=", "TOKEN="]
    upper_payload = payload_text.upper()
    for kw in covert_keywords:
        if kw in upper_payload:
            anomalies.append(f"ICMP Tünelleme / Veri Sızıntısı Şüphesi: Payload içinde kritik anahtar kelime '{kw}' bulundu!")
            break

    return ICMPPacketInfo(
        packet_id=packet_id,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        type_name=type_str,
        code_name=code_str,
        checksum=carried_checksum,
        is_checksum_valid=is_valid_checksum,
        identifier=identifier,
        sequence=sequence,
        source_ip=valid_src,
        dest_ip=valid_dst,
        ttl=ttl,
        payload_size=len(payload),
        payload_text=payload_text,
        is_anomalous=(len(anomalies) > 0),
        anomaly_reasons=anomalies
    )


def simulate_traceroute(target_ip: str, max_hops: int = 4) -> List[Dict[str, str]]:
    """Traceroute çalışma mantığını simüle eder (Artan TTL değerleri ve Type 11 geri bildirimleri)."""
    hops: List[Dict[str, str]] = []
    hop_ips = ["192.168.1.1", "10.0.0.1", "172.16.1.1", target_ip]
    
    for ttl in range(1, min(max_hops + 1, len(hop_ips) + 1)):
        current_ip = hop_ips[ttl - 1]
        if current_ip == target_ip:
            hops.append({
                "hop": str(ttl),
                "ip": current_ip,
                "type": "0 (Echo Reply)",
                "durum": "Hedefe Ulaşıldı (Success)"
            })
            break
        else:
            hops.append({
                "hop": str(ttl),
                "ip": current_ip,
                "type": "11 (Time Exceeded)",
                "durum": f"TTL={ttl} Süresi Doldu (Transit)"
            })
    return hops


def generate_markdown_report(packets: List[ICMPPacketInfo], trace_results: List[Dict[str, str]]) -> str:
    """ICMP analiz sonuçlarını kurumsal denetim formatında Markdown olarak raporlar."""
    lines: List[str] = [
        "# ICMP Protokolü, Ağ Teşhisi ve Tünelleme Güvenlik Raporu",
        "",
        "Bu rapor, analiz edilen ICMP paketlerinin tip/kod doğrulamalarını, sağlama toplamı (checksum)",
        "bütünlüğünü, Traceroute TTL akışını ve ICMP Covert Channel / Tünelleme anomali alarmlarını belgeler.",
        "",
        "## 1. Analiz Edilen ICMP Paketleri",
        "",
        "| Paket ID | Kaynak IP -> Hedef IP | Tip / Kod | Tanım | Boyut | Güvenlik Durumu |",
        "|---|---|---|---|---|---|"
    ]
    
    for p in packets:
        sec_status = "⚠️ ANOMALİ / ALARM" if p.is_anomalous else "✅ Meşru / Normal"
        lines.append(
            f"| `{p.packet_id}` | `{p.source_ip}` -> `{p.dest_ip}` | Type {p.icmp_type} / Code {p.icmp_code} | {p.code_name} | {p.payload_size} B | {sec_status} |"
        )
        
    lines.append("")
    lines.append("## 2. Tespit Edilen Güvenlik Anomalileri ve Tünelleme Alarmları")
    lines.append("")
    
    anomalous_pkts = [p for p in packets if p.is_anomalous]
    if anomalous_pkts:
        for ap in anomalous_pkts:
            lines.append(f"### [ALARM: {ap.packet_id}] {ap.source_ip} -> {ap.dest_ip} ({ap.type_name})")
            for r in ap.anomaly_reasons:
                lines.append(f"- 🚨 **Tehdit:** {r}")
            lines.append(f"- **Payload İçeriği:** `{ap.payload_text[:80]}...`")
            lines.append("")
    else:
        lines.append("✅ Herhangi bir ICMP tünelleme veya yönlendirme anomalisi tespit edilmedi.")
        
    lines.append("## 3. Traceroute TTL Tükenme Mekanizması Simülasyonu")
    lines.append("")
    lines.append("| Sekme (Hop) | Yanıt Veren IP | Dönen ICMP Tipi | Durum |")
    lines.append("|---|---|---|---|")
    for tr in trace_results:
        lines.append(f"| {tr['hop']} | `{tr['ip']}` | {tr['type']} | {tr['durum']} |")
        
    lines.append("")
    lines.append("## 4. ICMP Sertleştirme ve Güvenlik Tavsiyeleri")
    lines.append("- **Körlemesine Drop Hatası:** ICMP'yi tamamen engellemek Path MTU Discovery (Type 3 Code 4) mekanizmasını kırar ve TCP performansını düşürür; MTU hata mesajlarına izin verilmelidir.")
    lines.append("- **ICMP Redirect Engelleme (Type 5):** Ağ yönlendirme tablolarının manipüle edilmesini önlemek için Type 5 paketleri sınırda ve iç anahtarlarda engellenmelidir.")
    lines.append("- **Covert Channel Önleme (DPI):** Güvenlik duvarlarında ICMP yükü (payload) boyutu sınırlandırılmalı (>64 bayt atılmalı) ve veri alanı derinlemesine taranmalıdır.")
    lines.append("- **Hız Sınırlaması (Rate Limiting):** ICMP Flood ve Ping of Death DoS saldırılarına karşı arayüz seviyesinde hız sınırlaması uygulanmalıdır.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Komut satırından çalıştırıldığında örnek veri setini işler ve konsola yazdırır."""
    import os  # Dosya yolu yönetimi için os modülü kullanılır
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_file = os.path.join(base_dir, "ornek_veri", "sample_icmp_packets.json")
    
    if not os.path.exists(sample_file):
        print(f"Hata: Örnek veri dosyası bulunamadı: {sample_file}")
        sys.exit(1)
        
    with open(sample_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    parsed_packets: List[ICMPPacketInfo] = []
    print("=" * 80)
    print("G048: ICMP Ağ Teşhisi, Hata Kodları ve Tünelleme Güvenlik Laboratuvarı")
    print("=" * 80)
    
    for item in data.get("paketler", []):
        payload_bytes = item["payload_metin"].encode("utf-8")
        raw_pkt = build_icmp_packet(
            icmp_type=item["type"],
            icmp_code=item["code"],
            identifier=item["identifier"],
            sequence=item["sequence"],
            payload=payload_bytes
        )
        info = parse_and_analyze_icmp(
            packet_bytes=raw_pkt,
            source_ip=item["kaynak_ip"],
            dest_ip=item["hedef_ip"],
            ttl=item["ttl"],
            packet_id=item["id"]
        )
        parsed_packets.append(info)
        print(f"[*] Paket: {info.packet_id:<8} | Type {info.icmp_type}:{info.icmp_code} ({info.code_name})")
        print(f"    - Yön    : {info.source_ip} -> {info.dest_ip} (TTL: {info.ttl})")
        print(f"    - Bütünlük: Checksum: 0x{info.checksum:04X} {'[DOĞRULANDI]' if info.is_checksum_valid else '[BOZUK]'}")
        print(f"    - Veri   : Boyut: {info.payload_size} bayt | İçerik: {info.payload_text[:40]}...")
        if info.is_anomalous:
            print(f"    [!] GÜVENLİK ALARMI: {info.anomaly_reasons[0]}")
        print("-" * 80)
        
    trace_results = simulate_traceroute("8.8.8.8", max_hops=4)
    print("\n[+] Traceroute TTL Simülasyonu:")
    for tr in trace_results:
        print(f"    - Hop {tr['hop']}: {tr['ip']:<15} -> {tr['type']} [{tr['durum']}]")
        
    print(f"\n[+] Toplam Analiz Edilen Paket: {len(parsed_packets)}")
    print("[+] Özet ICMP Teşhis Raporu Başarıyla Oluşturuldu.\n")


if __name__ == "__main__":
    main()  # Betik doğrudan çağrıldığında ana yürütme fonksiyonunu çalıştırır
