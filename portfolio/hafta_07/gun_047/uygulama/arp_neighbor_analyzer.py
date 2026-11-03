# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G047: Adres Çözümleme Protokolü (ARP), Yerel Ağ Komşuluğu ve ARP Zehirleme (Spoofing) Analiz Motoru.
Bu modül, IPv4 ve Katman 2 MAC adresi eşlemelerini, ARP istek/yanıt yaşam döngüsünü,
Gratuitous ARP (GARP) mekanizmasını, dinamik vs statik önbellek ayrımını,
ve ağ güvenliği tehdidi olan ARP Zehirleme (Cache Poisoning / MitM) ataklarının
tespit ve önleme (Dynamic ARP Inspection - DAI) mantığını modeller.
"""

import sys  # Standart sistem modülü, konsol UTF-8 çıktı kodlamasını yapılandırmak için dahil edilir
import json  # JSON veri setlerini okumak ve ayrıştırmak için standart modül dahil edilir
from dataclasses import dataclass, field  # Yapılandırılmış veri sınıfları oluşturmak için dataclass dahil edilir
from typing import List, Dict, Optional, Tuple, Set  # Statik tip güvenliği için tip ipuçları dahil edilir

# Windows platformunda standart çıktı akışını UTF-8 karakter kümesine zorlayarak Türkçe karakter hatalarını önler
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Standart çıktı akışını UTF-8 yapar
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # Standart hata akışını UTF-8 yapar


class ARPValidationError(ValueError):
    """ARP girdileri, IP/MAC adres biçimleri veya paket işlem kodları geçersiz olduğunda fırlatılan özel istisna sınıfı."""
    pass  # Temel ValueError sınıfının özelliklerini devralarak özel hata türü tanımlar


@dataclass
class ARPEntry:
    """ARP önbelleğindeki (ARP Cache/Table) tekil bir IP-MAC eşlemesini temsil eden veri sınıfı."""
    ip_address: str  # Eşlenen IPv4 adresi (Örn: 192.168.1.1)
    mac_address: str  # Eşlenen 48-bitlik fiziksel MAC adresi (Örn: 00:1A:2B:3C:4D:01)
    interface: str  # İletişimin gerçekleştiği yerel ağ arayüzü (Örn: eth0)
    entry_type: str  # Girişin türü: 'Dinamik' (öğrenilen) veya 'Statik' (kalıcı)
    role: str  # IP adresinin ağdaki işlevi (Ağ Geçidi, Sunucu, Yayın vb.)
    is_static: bool = False  # Girişin statik olarak kilitlenip kilitlenmediği bayrağı
    is_broadcast: bool = False  # FF:FF:FF:FF:FF:FF yayın adresi bayrağı
    is_multicast: bool = False  # 01:00:5E:... çok noktaya yayın bayrağı


@dataclass
class ARPSpoofingAlert:
    """Tespit edilen bir ARP zehirleme veya anomali olayını temsil eden güvenlik uyarı sınıfı."""
    alert_id: str  # Benzersiz güvenlik alarmı kimliği
    timestamp: str  # Olayın gerçekleştiği zaman damgası
    target_ip: str  # Saldırıya uğrayan / kimliği taklit edilen hedef IP
    original_mac: str  # Önceden bilinen meşru MAC adresi
    spoofed_mac: str  # Sahte anonsla enjekte edilmeye çalışılan saldırgan MAC adresi
    alert_type: str  # Tehdit türü (Örn: MAC_FLIP, MULTI_IP_SINGLE_MAC, GRATUITOUS_POISON)
    severity: str  # Tehdit seviyesi ('CRITICAL', 'HIGH', 'MEDIUM')
    details: str  # Olayın detaylı analitik açıklaması
    mitigation: str  # Tavsiye edilen savunma ve sıkılaştırma adımı (DAI, Statik ARP vb.)


def validate_ipv4(ip_str: str) -> str:
    """IPv4 adres biçimini ve oktet aralıklarını (0-255) denetler."""
    if not ip_str or not isinstance(ip_str, str):
        raise ARPValidationError("IP adresi alanı boş olamaz")
    
    clean_ip = ip_str.strip()
    parts = clean_ip.split(".")
    if len(parts) != 4:
        raise ARPValidationError(f"IPv4 adresi 4 oktetten oluşmalıdır: '{clean_ip}'")
        
    for p in parts:
        if not p.isdigit():
            raise ARPValidationError(f"IPv4 okteti sayısal olmalıdır: '{p}'")
        val = int(p)
        if val < 0 or val > 255:
            raise ARPValidationError(f"Geçersiz IPv4 adresi oktet değeri: {val}")
        if len(p) > 1 and p.startswith("0"):
            raise ARPValidationError(f"Oktet başında gereksiz sıfır bulunamaz: '{p}'")
            
    return clean_ip


def validate_and_normalize_mac(mac_str: str) -> str:
    """MAC adresini doğrular, ayrıştırır ve standart iki nokta ('XX:XX:XX:XX:XX:XX') biçimine dönüştürür."""
    if not mac_str or not isinstance(mac_str, str):
        raise ARPValidationError("MAC adresi alanı boş olamaz")
        
    clean = mac_str.replace("-", ":").replace(".", "").strip()
    
    # Cisco formatı (001a.2b3c.4d01) veya düz format desteği
    if ":" not in clean and len(clean) == 12:
        clean = ":".join([clean[i:i+2] for i in range(0, 12, 2)])
        
    parts = clean.split(":")
    if len(parts) != 6:
        raise ARPValidationError(f"MAC adresi 6 oktetten (12 onaltılık hane) oluşmalıdır, bulunan: {len(parts)} oktet")
        
    for p in parts:
        if len(p) != 2:
            raise ARPValidationError(f"Her MAC okteti 2 onaltılık hane olmalıdır: '{p}'")
        for char in p:
            if char not in "0123456789abcdefABCDEF":
                raise ARPValidationError(f"MAC adresinde geçersiz onaltılık (hex) karakter: '{p}'")
                
    normalized = ":".join([p.upper() for p in parts])
    
    # Tamamen sıfırlardan oluşan tekil MAC adresini geçersiz kabul eder (Unicast için)
    if normalized == "00:00:00:00:00:00":
        raise ARPValidationError("Tekil IP için geçersiz (tamamen sıfır) MAC adresi eşlemesi")
        
    return normalized


def validate_arp_opcode(op_str: str) -> str:
    """ARP işlem kodunun geçerliliğini denetler."""
    valid_ops = {"REQUEST", "REPLY", "GRATUITOUS_REPLY", "RARP_REQUEST", "RARP_REPLY"}
    clean_op = op_str.strip().upper()
    if clean_op not in valid_ops:
        raise ARPValidationError(f"Desteklenmeyen ARP işlem kodu (Opcode): {op_str}")
    return clean_op


class ARPCacheManager:
    """
    Yerel ağ ARP önbelleğini yöneten, dinamik öğrenmeyi simüle eden
    ve ARP Spoofing / Zehirleme saldırılarını tespit eden güvenlik denetim motoru.
    """
    def __init__(self) -> None:
        self.cache: Dict[str, ARPEntry] = {}  # IP -> ARPEntry tablosu
        self.mac_to_ips: Dict[str, Set[str]] = {}  # MAC -> Set[IP] ters eşleme tablosu
        self.alerts: List[ARPSpoofingAlert] = []  # Üretilen güvenlik alarmları listesi
        self.dhcp_snooping_bindings: Dict[str, str] = {}  # Güvenilir DHCP Snooping tablosu (IP -> MAC)
        self.alert_counter: int = 1  # Alarm sayaç numarası

    def set_trusted_dhcp_binding(self, ip_str: str, mac_str: str) -> None:
        """Dynamic ARP Inspection (DAI) doğrulaması için yetkili DHCP Snooping girdisi ekler."""
        valid_ip = validate_ipv4(ip_str)  # IP adresini doğrular
        valid_mac = validate_and_normalize_mac(mac_str)  # MAC adresini doğrular
        self.dhcp_snooping_bindings[valid_ip] = valid_mac  # Yetkili eşleşmeyi kaydeder

    def add_or_update_entry(
        self,
        ip_str: str,
        mac_str: str,
        interface: str,
        entry_type: str = "Dinamik",
        role: str = "Genel Düğüm"
    ) -> ARPEntry:
        """
        Önbelleğe yeni bir giriş ekler veya mevcut girişi günceller.
        Arayüz boşluğu, adres formatları ve statik kilitlenme denetimlerini yürütür.
        """
        if not interface or not interface.strip():
            raise ARPValidationError("Ağ arayüzü (interface) alanı boş olamaz")
            
        valid_ip = validate_ipv4(ip_str)  # IP formatını doğrular
        valid_mac = validate_and_normalize_mac(mac_str)  # MAC formatını doğrular
        
        is_broadcast = (valid_mac == "FF:FF:FF:FF:FF:FF")  # Yayın adresi kontrolü
        is_multicast = valid_mac.startswith("01:00:5E")  # Multicast MAC kontrolü
        is_static = (entry_type.strip().lower() == "statik")  # Statik giriş kontrolü
        
        entry = ARPEntry(
            ip_address=valid_ip,
            mac_address=valid_mac,
            interface=interface.strip(),
            entry_type="Statik" if is_static else "Dinamik",
            role=role,
            is_static=is_static,
            is_broadcast=is_broadcast,
            is_multicast=is_multicast
        )
        
        # Eğer mevcut bir giriş varsa ve statik ise, dinamik güncellemeyi reddeder
        if valid_ip in self.cache and self.cache[valid_ip].is_static and not is_static:
            return self.cache[valid_ip]
            
        # Eski MAC eşleşmesini ters tablodan temizler
        if valid_ip in self.cache:
            old_mac = self.cache[valid_ip].mac_address
            if old_mac in self.mac_to_ips and valid_ip in self.mac_to_ips[old_mac]:
                self.mac_to_ips[old_mac].remove(valid_ip)
                
        # Yeni girişi tablolara kaydeder
        self.cache[valid_ip] = entry
        if valid_mac not in self.mac_to_ips:
            self.mac_to_ips[valid_mac] = set()
        self.mac_to_ips[valid_mac].add(valid_ip)
        
        return entry

    def process_arp_packet(
        self,
        event_id: str,
        timestamp: str,
        operation: str,
        sender_ip: str,
        sender_mac: str,
        target_ip: str,
        target_mac: str
    ) -> Optional[ARPSpoofingAlert]:
        """
        Gelen ham bir ARP paketini inceler, önbelleği günceller ve
        güvenlik anomalisini (MAC Flip, Sahte Ağ Geçidi, Çelişkili Eşleme) tespit eder.
        """
        valid_op = validate_arp_opcode(operation)  # İşlem kodunu doğrular
        valid_s_ip = validate_ipv4(sender_ip)  # Gönderici IP doğrulaması
        valid_s_mac = validate_and_normalize_mac(sender_mac)  # Gönderici MAC doğrulaması
        
        # Dynamic ARP Inspection (DAI) Kontrolü: DHCP Snooping tablosuyla teyit eder
        if valid_s_ip in self.dhcp_snooping_bindings:
            trusted_mac = self.dhcp_snooping_bindings[valid_s_ip]
            if trusted_mac != valid_s_mac:
                alert = ARPSpoofingAlert(
                    alert_id=f"ALT-{self.alert_counter:03d}",
                    timestamp=timestamp,
                    target_ip=valid_s_ip,
                    original_mac=trusted_mac,
                    spoofed_mac=valid_s_mac,
                    alert_type="DAI_DHCP_SNOOPING_VIOLATION",
                    severity="CRITICAL",
                    details=f"DAI İHLALİ: {valid_s_ip} için beklenen MAC {trusted_mac}, ancak paket {valid_s_mac} taşıyor!",
                    mitigation="Paket switch seviyesinde derhal DROP edilmeli ve port güvenlik ihlali oluşturulmalıdır."
                )
                self.alert_counter += 1
                self.alerts.append(alert)
                return alert

        # Önbellek çakışma ve MAC Flip Tespiti
        if valid_s_ip in self.cache:
            existing_entry = self.cache[valid_s_ip]
            if existing_entry.mac_address != valid_s_mac:
                # IP adresi aniden farklı bir MAC adresine bağlanmaya çalışılıyor!
                alert = ARPSpoofingAlert(
                    alert_id=f"ALT-{self.alert_counter:03d}",
                    timestamp=timestamp,
                    target_ip=valid_s_ip,
                    original_mac=existing_entry.mac_address,
                    spoofed_mac=valid_s_mac,
                    alert_type="ARP_CACHE_POISONING_MAC_FLIP",
                    severity="CRITICAL",
                    details=f"ARP ZEHİRLEME TESPİTİ: {valid_s_ip} ({existing_entry.role}) adresi meşru {existing_entry.mac_address} yerine {valid_s_mac} adresine bağlanmaya çalışıldı!",
                    mitigation="Statik ARP girişi tanımlayın, anahtarda Dynamic ARP Inspection (DAI) aktifleştirin."
                )
                self.alert_counter += 1
                self.alerts.append(alert)
                return alert
                
        # Tek bir MAC adresinin birden fazla kritik IP'yi sahiplenmesi kontrolü (MitM İndikatörü)
        if valid_s_mac in self.mac_to_ips and len(self.mac_to_ips[valid_s_mac]) >= 1:
            claimed_ips = self.mac_to_ips[valid_s_mac]
            if valid_s_ip not in claimed_ips:
                alert = ARPSpoofingAlert(
                    alert_id=f"ALT-{self.alert_counter:03d}",
                    timestamp=timestamp,
                    target_ip=valid_s_ip,
                    original_mac="Çoklu IP Eşlemesi",
                    spoofed_mac=valid_s_mac,
                    alert_type="SINGLE_MAC_MULTIPLE_IP_ABUSE",
                    severity="HIGH",
                    details=f"ŞÜPHELİ MİTM İZİ: {valid_s_mac} MAC adresi birden fazla farklı IP'yi sahipleniyor: {list(claimed_ips)} + [{valid_s_ip}]",
                    mitigation="Port Security ve 802.1X ile port başına MAC sınırlandırması uygulayın."
                )
                self.alert_counter += 1
                self.alerts.append(alert)
                # Yine de önbelleği günceller
                self.add_or_update_entry(valid_s_ip, valid_s_mac, "eth0", "Dinamik", "Şüpheli Düğüm")
                return alert

        # Anomali yoksa önbelleği normal şekilde günceller
        self.add_or_update_entry(valid_s_ip, valid_s_mac, "eth0", "Dinamik", "Normal Düğüm")
        return None


def generate_markdown_report(manager: ARPCacheManager) -> str:
    """ARP önbellek tablosunu ve tespit edilen güvenlik alarmlarını Markdown formatında raporlar."""
    lines: List[str] = [
        "# ARP Tablosu, Yerel Ağ Komşuluğu ve Güvenlik Denetim Raporu",
        "",
        "Bu rapor, yerel ağ arayüzündeki IP-MAC eşlemelerini, statik/dinamik girişleri ve",
        "simüle edilen ARP Zehirleme (Cache Poisoning) saldırılarına ait alarmları belgeler.",
        "",
        "## 1. Yerel Ağ ARP Önbellek Tablosu",
        "",
        "| IP Adresi | Fiziksel MAC Adresi | Arayüz | Tür | Ağ Rolü | Güvenlik Durumu |",
        "|---|---|---|---|---|---|"
    ]
    
    for ip, entry in manager.cache.items():
        status = "🔒 Statik (Korumalı)" if entry.is_static else "⚡ Dinamik (Değişebilir)"
        if entry.is_broadcast:
            status = "📢 Yayın (Broadcast)"
        elif entry.is_multicast:
            status = "👥 Çok Noktaya Yayın (Multicast)"
            
        lines.append(
            f"| `{entry.ip_address}` | `{entry.mac_address}` | `{entry.interface}` | {entry.entry_type} | {entry.role} | {status} |"
        )
        
    lines.append("")
    lines.append("## 2. Tespit Edilen ARP Güvenlik Alarmları (Anomali Analizi)")
    lines.append("")
    
    if manager.alerts:
        lines.append("| Alarm ID | Zaman | Hedef IP | Meşru MAC | Saldırgan MAC | Tehdit Türü | Seviye |")
        lines.append("|---|---|---|---|---|---|---|")
        for a in manager.alerts:
            lines.append(
                f"| `{a.alert_id}` | {a.timestamp} | `{a.target_ip}` | `{a.original_mac}` | `{a.spoofed_mac}` | {a.alert_type} | **{a.severity}** |"
            )
        lines.append("")
        lines.append("### Ayrıntılı Müdahale ve Savunma Tavsiyeleri")
        for a in manager.alerts:
            lines.append(f"- **[{a.alert_id}] {a.details}**")
            lines.append(f"  - *Savunma Adımı:* {a.mitigation}")
    else:
        lines.append("✅ Herhangi bir ARP zehirleme veya anomali tespit edilmedi. Ağ komşuluğu kararlı.")
        
    lines.append("")
    lines.append("## 3. Kurumsal Ağlar İçin Sertleştirme Prensipleri")
    lines.append("- **Dynamic ARP Inspection (DAI):** Anahtarlar üzerinde DHCP Snooping veri tabanına dayanarak sahte ARP paketleri donanım seviyesinde düşürülmelidir.")
    lines.append("- **Statik Ağ Geçidi Eşlemesi:** Kritik sunucularda varsayılan ağ geçidi (Default Gateway) MAC adresi statik olarak (`arp -s`) sabitlenmelidir.")
    lines.append("- **Port Güvenliği (Port Security):** Anahtar portlarında MAC adresi sınırlaması yapılarak tek bir fiziksel porttan sahte MAC yayımı engellenmelidir.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Komut satırından çalıştırıldığında örnek veri setini işler ve konsola yazdırır."""
    import os  # Dosya yolu yönetimi için os modülü kullanılır
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sample_file = os.path.join(base_dir, "ornek_veri", "sample_arp_tables.json")
    
    if not os.path.exists(sample_file):
        print(f"Hata: Örnek veri dosyası bulunamadı: {sample_file}")
        sys.exit(1)
        
    with open(sample_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    manager = ARPCacheManager()
    
    # Güvenilir DHCP Snooping bağlarını kurar
    manager.set_trusted_dhcp_binding("192.168.1.1", "00:1A:2B:3C:4D:01")
    manager.set_trusted_dhcp_binding("192.168.1.10", "00:1A:2B:3C:4D:0A")
    manager.set_trusted_dhcp_binding("192.168.1.50", "52:54:00:12:34:56")
    
    print("=" * 80)
    print("G047: ARP ve Yerel Ağ Komşuluğu Güvenlik Analiz Laboratuvarı")
    print("=" * 80)
    
    # 1. Başlangıç önbelleğini yükler
    print("[*] Başlangıç ARP Önbelleği Yükleniyor...")
    for item in data.get("arp_onbellegi", []):
        manager.add_or_update_entry(
            ip_str=item["ip"],
            mac_str=item["mac"],
            interface=item["arayuz"],
            entry_type=item["tur"],
            role=item["rol"]
        )
        print(f"    - {item['ip']:<15} -> {item['mac']} [{item['tur']}] ({item['rol']})")
        
    # 2. Trafik olaylarını ve saldırı simülasyonunu işletir
    print("\n[*] Ağ Trafiği ve ARP Olayları İşleniyor...")
    for evt in data.get("arp_trafik_olaylari", []):
        alert = manager.process_arp_packet(
            event_id=evt["olay_id"],
            timestamp=evt["zaman"],
            operation=evt["islem"],
            sender_ip=evt["kaynak_ip"],
            sender_mac=evt["kaynak_mac"],
            target_ip=evt["hedef_ip"],
            target_mac=evt["hedef_mac"]
        )
        if alert:
            print(f"    [!] GÜVENLİK ALARMI: {alert.alert_id} | {alert.alert_type} | {alert.severity}")
            print(f"        Hedef IP : {alert.target_ip}")
            print(f"        Meşru MAC: {alert.original_mac} -> Sahte MAC: {alert.spoofed_mac}")
            print(f"        Detay    : {alert.details}")
        else:
            print(f"    [✓] Meşru Paket : {evt['olay_id']} ({evt['aciklama']})")
            
    print(f"\n[+] Toplam Üretilen Alarm Sayısı: {len(manager.alerts)}")
    print("[+] Özet ARP Analiz Raporu Başarıyla Oluşturuldu.\n")


if __name__ == "__main__":
    main()  # Betik doğrudan çağrıldığında ana fonksiyonu yürütür
