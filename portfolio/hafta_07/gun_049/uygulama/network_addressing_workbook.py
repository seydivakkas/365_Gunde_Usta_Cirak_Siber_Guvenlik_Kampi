# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
Mini Proje 6: Ağ Adresleme Çalışma Kitabı ve Güvenlik Denetim Motoru
Bu modül Katman-2 (MAC/VLAN) ve Katman-3 (IPv4/IPv6/CIDR/Alt Ağ) planlamasını,
adresleme hesaplamalarını, ağ çakışmalarını ve yapılandırma denetimlerini yürütür.
"""

# Ağ adresi ve alt ağ hesaplamaları için Python standart ipaddress kütüphanesi
import ipaddress
# Yapılandırılmış JSON veri alışverişi için json kütüphanesi
import json
# Dosya sistemi ve yol işlemleri için os kütüphanesi
import os
# Düzenli ifadeler ile biçim doğrulaması için re kütüphanesi
import re
# Tip ipuçları ve veri yapıları için typing modülü
from typing import Dict, List, Any, Optional, Tuple


class WorkbookValidationError(ValueError):
    """Ağ adresleme ve topoloji doğrulama hataları için özel istisna sınıfı."""
    # Özel istisna gövdesi standart türetme mekanizmasını kullanır
    pass


class IPv4SubnetCalculator:
    """IPv4 CIDR blokları için matematiksel alt ağ hesaplayıcı ve denetleyici."""

    def __init__(self, cidr_str: str) -> None:
        # Girdi tipinin karakter dizisi olup olmadığını denetler
        if not isinstance(cidr_str, str):
            # Tip uyuşmazlığında açıklayıcı doğrulama hatası fırlatır
            raise WorkbookValidationError("CIDR girdisi karakter dizisi (str) olmalıdır.")
        # Girdinin boş veya yalnızca boşluklardan oluşmadığını kontrol eder
        if not cidr_str.strip():
            # Boş CIDR dizisinde istisna fırlatır
            raise WorkbookValidationError("CIDR girdisi boş olamaz.")
        # Eğik çizgi karakterinin varlığını kontrol eder
        if "/" not in cidr_str:
            # Önek uzunluğu bulunmadığında hata fırlatır
            raise WorkbookValidationError(f"Geçersiz CIDR biçimi (önek eksik): {cidr_str}")
        
        # Eğik çizgiye göre IP ve önek parçalarını ayırır
        ip_part, prefix_part = cidr_str.split("/", 1)
        # Önek kısmının rakamlardan oluştuğunu teyit eder
        if not prefix_part.isdigit():
            # Sayısal olmayan önekte hata fırlatır
            raise WorkbookValidationError(f"CIDR önek değeri sayısal olmalıdır: {prefix_part}")
        # Önek uzunluğunu tamsayıya çevirir
        prefix_len = int(prefix_part)
        # Önek uzunluğunun 0 ile 32 arasında olduğunu denetler
        if prefix_len < 0 or prefix_len > 32:
            # Aralık dışı önekte doğrulama hatası üretir
            raise WorkbookValidationError(f"IPv4 CIDR öneki 0-32 arasında olmalıdır: {prefix_len}")

        # IPv4 adresi oktetlerini parçalar
        octets = ip_part.split(".")
        # Tam 4 oktet olduğunu doğrular
        if len(octets) != 4:
            # Eksik veya fazla oktette hata fırlatır
            raise WorkbookValidationError(f"IPv4 adresi tam 4 oktetten oluşmalıdır: {ip_part}")
        # Her oktetin geçerliliğini denetler
        for octet in octets:
            # Oktetin sayısal olup olmadığını kontrol eder
            if not octet.isdigit():
                # Rakam dışı karakterde hata üretir
                raise WorkbookValidationError(f"Geçersiz sayısal oktet: {octet}")
            # Oktet değerini tamsayıya dönüştürür
            val = int(octet)
            # Oktetin 0-255 aralığında olduğunu doğrular
            if val < 0 or val > 255:
                # 255'ten büyük veya negatif oktette hata fırlatır
                raise WorkbookValidationError(f"Oktet 0-255 aralığında olmalıdır: {val}")

        # Standard IP ağı nesnesini strict=False ile oluşturur (host bitlerini sıfırlayarak ağ adresini bulur)
        try:
            # ipaddress modülü ile ağ nesnesini başlatır
            self.network = ipaddress.IPv4Network(cidr_str, strict=False)
        # Oluşabilecek ayrıştırma hatalarını yakalar
        except Exception as err:
            # Hata durumunda özel istisna yükseltir
            raise WorkbookValidationError(f"Geçersiz IPv4 CIDR adresi: {cidr_str} - Hata: {str(err)}")

        # Ağ kimlik adresini metin olarak saklar
        self.network_address: str = str(self.network.network_address)
        # Alt ağ maskesini saklar (örn. 255.255.255.0)
        self.netmask: str = str(self.network.netmask)
        # Joker (wildcard) maskesini saklar (örn. 0.0.0.255)
        self.wildcard_mask: str = str(self.network.hostmask)
        # Yayın (broadcast) adresini saklar (örn. 192.168.1.255)
        self.broadcast_address: str = str(self.network.broadcast_address)
        # CIDR önek uzunluğunu saklar (örn. 24)
        self.prefix_len: int = self.network.prefixlen
        # Toplam teorik IP adres sayısını hesaplar (2^(32-prefix))
        self.total_addresses: int = self.network.num_addresses
        
        # Kullanılabilir host sayısı hesabını yapar (/31 ve /32 özel durumları hariç -2 kuralı)
        if self.prefix_len >= 31:
            # /31 ve /32 ağlarda kullanılabilir adres sayısı toplam adrese eşittir
            self.usable_hosts: int = self.total_addresses
            # İlk kullanılabilir IP ağ adresine eşittir
            self.first_usable: str = str(self.network.network_address)
            # Son kullanılabilir IP yayın adresine eşittir
            self.last_usable: str = str(self.network.broadcast_address)
        # Standart /30 ve daha geniş alt ağlar için
        else:
            # Ağ ve yayın adresleri düşüldüğünde kalan host sayısı
            self.usable_hosts = self.total_addresses - 2
            # İlk kullanılabilir host IP'si (Ağ adresi + 1)
            self.first_usable = str(self.network.network_address + 1)
            # Son kullanılabilir host IP'si (Yayın adresi - 1)
            self.last_usable = str(self.network.broadcast_address - 1)

    def contains_ip(self, ip_str: str) -> bool:
        """Verilen IP adresinin bu alt ağ sınırları içinde olup olmadığını doğrular."""
        # Girdinin geçerliliğini dize kontrolü ile teyit eder
        if not isinstance(ip_str, str) or not ip_str.strip():
            # Geçersiz format durumunda false döner
            return False
        # IP dönüşümünü güvenli blok içinde yürütür
        try:
            # ipaddress nesnesine çevirir
            ip_obj = ipaddress.IPv4Address(ip_str.strip())
            # Adresin ağ sınırları içinde olup olmadığını boolean döner
            return ip_obj in self.network
        # Hatalı IP formatında False döndürür
        except Exception:
            # Geçersiz IP adresleri ağ içinde kabul edilmez
            return False

    def is_usable_host_ip(self, ip_str: str) -> bool:
        """Bir IP'nin atanabilir bir konak (host) IP'si olup olmadığını denetler."""
        # Ağ içinde değilse doğrudan False döner
        if not self.contains_ip(ip_str):
            # Alt ağ sınırları dışındaki IP geçerli host olamaz
            return False
        # /31 ve /32 ağlarda ağ ve broadcast kuralı aranmaz
        if self.prefix_len >= 31:
            # Özel nokta-nokta ağlarda tüm IP'ler kullanılabilir
            return True
        # Ağ kimlik IP'si hostlara atanamaz kuralı
        if ip_str == self.network_address:
            # Ağ adresi atandığı için False döner
            return False
        # Yayın IP'si hostlara atanamaz kuralı
        if ip_str == self.broadcast_address:
            # Broadcast adresi atandığı için False döner
            return False
        # Kuralları geçen IP adresi geçerli bir hosttur
        return True

    def overlaps_with(self, other: "IPv4SubnetCalculator") -> bool:
        """İki alt ağın IP adres uzayında birbiriyle çakışıp çakışmadığını tespit eder."""
        # Alt ağ nesnesi kontrolü yapar
        if not isinstance(other, IPv4SubnetCalculator):
            # Yanlış tip durumunda hata fırlatır
            raise WorkbookValidationError("Karşılaştırılacak nesne IPv4SubnetCalculator olmalıdır.")
        # İki ağ nesnesinin çakışma durumunu hesaplar
        return self.network.overlaps(other.network)


class IPv6SubnetCalculator:
    """IPv6 CIDR blokları ve EUI-64 MAC sızıntısı analiz motoru."""

    def __init__(self, cidr_str: str) -> None:
        # Girdi tipinin karakter dizisi olup olmadığını denetler
        if not isinstance(cidr_str, str) or not cidr_str.strip():
            # Boş veya geçersiz girdide hata fırlatır
            raise WorkbookValidationError("IPv6 CIDR girdisi geçerli bir karakter dizisi olmalıdır.")
        # Biçim kontrolü: birden fazla çift iki nokta yasaktır
        if cidr_str.count("::") > 1:
            # Geçersiz RFC formatında istisna fırlatır
            raise WorkbookValidationError(f"IPv6 adresinde birden fazla '::' bulunamaz: {cidr_str}")
        # IPv6 ağ nesnesini oluşturmayı dener
        try:
            # ipaddress modülü ile IPv6 ağını ayrıştırır
            self.network = ipaddress.IPv6Network(cidr_str, strict=False)
        # Hata durumunda doğrulama hatası üretir
        except Exception as err:
            # Ayrıştırma hatasını detaylı açıklar
            raise WorkbookValidationError(f"Geçersiz IPv6 CIDR adresi: {cidr_str} - Hata: {str(err)}")

        # Ağ adresini saklar
        self.network_address: str = str(self.network.network_address)
        # Önek uzunluğunu saklar
        self.prefix_len: int = self.network.prefixlen
        # Sıkıştırılmış gösterimi saklar
        self.compressed: str = self.network.compressed
        # Tam açılmış (exploded) gösterimi saklar
        self.exploded: str = self.network.exploded

    def contains_ip(self, ip_str: str) -> bool:
        """Verilen IPv6 adresinin bu alt ağ sınırları içinde olup olmadığını doğrular."""
        # Güvenli ayrıştırma bloğu
        try:
            # IPv6 adres nesnesi oluşturur
            ip_obj = ipaddress.IPv6Address(ip_str.strip())
            # Adresin alt ağ içinde olup olmadığını döner
            return ip_obj in self.network
        # Hata durumunda False döner
        except Exception:
            # Ayrıştırılamayan adres ağda bulunamaz
            return False

    @staticmethod
    def is_eui64_mac_leakage(ipv6_str: str, mac_str: str) -> bool:
        """Global Unicast IPv6 adresinde MAC adresinin EUI-64 ile sızdırıldığını denetler."""
        # Girdilerin doğruluğunu teyit eder
        try:
            # IPv6 adres nesnesi oluşturur
            ip_obj = ipaddress.IPv6Address(ipv6_str.strip())
            # MAC adresini temizler ve iki nokta ayracına göre böler
            mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac_str.strip().lower())
            # MAC adresinin tam 12 hex karakter olduğunu doğrular
            if len(mac_clean) != 12:
                # Geçersiz MAC adresinde sızıntı tespit edilemez
                return False
            
            # EUI-64 kuralı: MAC 24-bit OUI ve 24-bit NIC parçalarına ayrılır
            oui_part = mac_clean[:6]
            # İkinci parça olan NIC tanımlayıcısı
            nic_part = mac_clean[6:]
            
            # OUI ilk baytındaki Universal/Local biti (7. bit) ters çevrilir (XOR 0x02)
            first_byte = int(oui_part[:2], 16) ^ 0x02
            # Yeni ilk bayt hex olarak biçimlendirilir
            eui_first_byte = f"{first_byte:02x}"
            # Araya 'fffe' gömülerek 64-bitlik arayüz tanımlayıcısı üretilir
            eui64_iid = f"{eui_first_byte}{oui_part[2:]}fffe{nic_part}"
            
            # IPv6 adresinin son 64 bitini (son 16 hex karakter) alır
            ip_hex = ip_obj.exploded.replace(":", "").lower()
            # Son 16 karakter arayüz kimliğidir (Interface Identifier)
            actual_iid = ip_hex[-16:]
            
            # Hesaplanan EUI-64 kimliği ile gerçek arayüz kimliğini kıyaslar
            return actual_iid == eui64_iid
        # Hata durumlarında sızıntı yok döner
        except Exception:
            # Ayrıştırma hatasında güvenli varsayım olarak False döner
            return False


class NetworkAddressingWorkbook:
    """Katman-2 ve Katman-3 adresleme çalışma kitabı ve güvenlik denetim motoru."""

    def __init__(self, proje_adi: str = "Ağ Adresleme Çalışma Kitabı") -> None:
        # Çalışma kitabının proje başlığını saklar
        self.proje_adi: str = proje_adi
        # Tanımlı alt ağları tutan sözlük (Anahtar: alt_ag_id)
        self.alt_aglar: Dict[str, Dict[str, Any]] = {}
        # Alt ağ hesaplayıcı nesnelerini tutan sözlük
        self.hesaplayicilar_v4: Dict[str, IPv4SubnetCalculator] = {}
        # IPv6 hesaplayıcı nesnelerini tutan sözlük
        self.hesaplayicilar_v6: Dict[str, IPv6SubnetCalculator] = {}
        # Tanımlı cihaz envanterini tutan liste (boş liste olarak başlatılır)
        self.cihazlar: List[Dict[str, Any]] = []
        # Denetim bulgularını ve alarmlarını toplayan liste
        self.denetim_bulgulari: List[Dict[str, Any]] = []

    def load_from_json(self, json_path: str) -> None:
        """Çalışma kitabı topoloji verisini harici bir JSON dosyasından yükler."""
        # Dosyanın fiziksel varlığını kontrol eder
        if not os.path.exists(json_path):
            # Dosya bulunamadığında hata üretir
            raise WorkbookValidationError(f"Topoloji dosyası bulunamadı: {json_path}")
        # Dosyayı UTF-8 kodlamasıyla okuma modunda açar
        with open(json_path, "r", encoding="utf-8") as f:
            # JSON içeriğini sözlük olarak ayrıştırır
            data = json.load(f)
        
        # Verinin sözlük tipinde olduğunu doğrular
        if not isinstance(data, dict):
            # Geçersiz formatta hata fırlatır
            raise WorkbookValidationError("Topoloji verisi bir JSON nesnesi (dict) olmalıdır.")
        # Boş veri kümesi kontrolü yapar
        if not data:
            # Boş veride hata yükseltir
            raise WorkbookValidationError("Topoloji verisi boş olamaz.")

        # Proje adını günceller
        self.proje_adi = data.get("proje_adi", self.proje_adi)
        
        # Alt ağlar listesini döngüyle ekler
        for subnet_data in data.get("alt_aglar", []):
            # Her bir alt ağı kayıt motoruna iletir
            self.add_subnet(subnet_data)
            
        # Cihazlar listesini döngüyle ekler
        for device_data in data.get("cihazlar", []):
            # Her bir cihazı envanter motoruna iletir
            self.add_device(device_data)

    def add_subnet(self, subnet_dict: Dict[str, Any]) -> None:
        """Çalışma kitabına doğrulanmış bir alt ağ (subnet) tanımı ekler."""
        # Girdinin sözlük olduğunu kontrol eder
        if not isinstance(subnet_dict, dict):
            # Tip uyuşmazlığında hata fırlatır
            raise WorkbookValidationError("Alt ağ tanımı sözlük (dict) olmalıdır.")
        
        # Zorunlu alanların mevcudiyetini denetler
        zorunlu_alanlar = ["alt_ag_id", "vlan_id", "ipv4_cidr"]
        # Her bir zorunlu alanı inceler
        for alan in zorunlu_alanlar:
            # Alan eksikse hata üretir
            if alan not in subnet_dict:
                # Açıklayıcı eksik alan istisnası fırlatır
                raise WorkbookValidationError(f"Alt ağ tanımında zorunlu alan eksik: '{alan}'")

        # Alt ağ kimliğini alır
        sub_id = str(subnet_dict["alt_ag_id"]).strip()
        # Boş kimlik kontrolü yapar
        if not sub_id:
            # Boş alt ağ kimliğinde hata verir
            raise WorkbookValidationError("Alt ağ kimliği (alt_ag_id) boş olamaz.")

        # VLAN kimliğini doğrular
        vlan_id = subnet_dict["vlan_id"]
        # VLAN kimliğinin tam sayı olduğunu denetler
        if not isinstance(vlan_id, int):
            # Tam sayı olmayan VLAN'da hata verir
            raise WorkbookValidationError(f"VLAN kimliği tam sayı olmalıdır: {vlan_id}")
        # IEEE 802.1Q standardına göre VLAN aralığını (1-4094) denetler
        if vlan_id < 1 or vlan_id > 4094:
            # Geçersiz VLAN aralığında hata fırlatır
            raise WorkbookValidationError(f"VLAN kimliği 1-4094 aralığında olmalıdır: {vlan_id}")

        # IPv4 CIDR hesaplayıcı nesnesini oluşturur
        v4_calc = IPv4SubnetCalculator(subnet_dict["ipv4_cidr"])
        # Hesaplayıcıyı sözlükte saklar
        self.hesaplayicilar_v4[sub_id] = v4_calc

        # İsteğe bağlı IPv6 CIDR tanımı varsa doğrular
        if "ipv6_cidr" in subnet_dict and subnet_dict["ipv6_cidr"]:
            # IPv6 hesaplayıcısını başlatır
            v6_calc = IPv6SubnetCalculator(subnet_dict["ipv6_cidr"])
            # IPv6 hesaplayıcı sözlüğüne ekler
            self.hesaplayicilar_v6[sub_id] = v6_calc

        # Alt ağı iç kayıt sözlüğüne ekler
        self.alt_aglar[sub_id] = subnet_dict

    def add_device(self, device_dict: Dict[str, Any]) -> None:
        """Çalışma kitabına doğrulanmış bir cihaz/konak tanımı ekler."""
        # Girdinin sözlük olduğunu kontrol eder
        if not isinstance(device_dict, dict):
            # Tip uyuşmazlığında hata üretir
            raise WorkbookValidationError("Cihaz tanımı sözlük (dict) olmalıdır.")

        # Zorunlu alan kontrolü
        zorunlu_alanlar = ["cihaz_id", "konak_adi", "alt_ag_id", "ipv4", "mac"]
        # Her bir alanı kontrol eder
        for alan in zorunlu_alanlar:
            # Alan eksikse hata verir
            if alan not in device_dict:
                # Eksik alan istisnası
                raise WorkbookValidationError(f"Cihaz tanımında zorunlu alan eksik: '{alan}'")

        # IP formatı doğrulama (string olmalı)
        if not isinstance(device_dict["ipv4"], str):
            # Sayısal veya farklı tiplerde hata fırlatır
            raise WorkbookValidationError(f"Cihaz IPv4 adresi metin (str) olmalıdır: {device_dict['ipv4']}")

        # MAC adresi formatını doğrular (12 hex hanesi ve standart ayraçlar)
        mac_raw = device_dict["mac"]
        # MAC adresinin dize olduğunu denetler
        if not isinstance(mac_raw, str):
            # Geçersiz tipte hata fırlatır
            raise WorkbookValidationError(f"MAC adresi dize olmalıdır: {mac_raw}")
        # Temiz hex karakterlerini çıkarır
        mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac_raw)
        # Uzunluğun 12 olduğunu ve geçersiz karakter kalmadığını doğrular
        if len(mac_clean) != 12:
            # Hatalı MAC adresinde hata fırlatır
            raise WorkbookValidationError(f"Geçersiz MAC adresi biçimi: {mac_raw}")

        # Cihazı listeye ekler
        self.cihazlar.append(device_dict)

    def run_audits(self) -> List[Dict[str, Any]]:
        """Ağ planı, alt ağlar ve cihazlar üzerinde kapsamlı güvenlik ve çakışma denetimleri yürütür."""
        # Denetim bulguları listesini sıfırlar
        self.denetim_bulgulari = []

        # 1. DENETİM: Çakışan Alt Ağlar (Overlapping Subnets) Kontrolü
        sub_ids = list(self.alt_aglar.keys())
        # Tüm alt ağ ikililerini birbiriyle karşılaştırır
        for i in range(len(sub_ids)):
            # İlk alt ağ kimliği
            id1 = sub_ids[i]
            # İlk alt ağ hesaplayıcısı
            calc1 = self.hesaplayicilar_v4[id1]
            # İkinci alt ağları gezen iç döngü
            for j in range(i + 1, len(sub_ids)):
                # İkinci alt ağ kimliği
                id2 = sub_ids[j]
                # İkinci alt ağ hesaplayıcısı
                calc2 = self.hesaplayicilar_v4[id2]
                # İki alt ağın IP uzayı çakışıyor mu kontrolü
                if calc1.overlaps_with(calc2):
                    # Çakışma tespit edildiğinde kritik bulgu kaydeder
                    self.denetim_bulgulari.append({
                        "kategori": "CAKISAN_ALT_AG",
                        "seviye": "KRITIK",
                        "kaynak": f"{id1} ({calc1.network})",
                        "hedef": f"{id2} ({calc2.network})",
                        "mesaj": f"Alt ağlar arasında IP uzayı çakışması tespit edildi! Rota belirsizliği oluşur."
                    })

        # 2. DENETİM: Varsayılan Ağ Geçidi (Default Gateway) Doğrulaması
        for sub_id, sub_info in self.alt_aglar.items():
            # Tanımlı varsayılan ağ geçidi IP'si
            gw_ip = sub_info.get("varsayilan_ag_gecidi")
            # Ağ geçidi tanımlıysa kontrol eder
            if gw_ip:
                # Hesaplayıcı üzerinden IP'nin alt ağda olduğunu doğrular
                calc = self.hesaplayicilar_v4[sub_id]
                # Ağ geçidi alt ağ içinde değilse
                if not calc.contains_ip(gw_ip):
                    # Yüksek seviyeli yapılandırma hatası kaydeder
                    self.denetim_bulgulari.append({
                        "kategori": "GECERSIZ_AG_GECIDI",
                        "seviye": "KRITIK",
                        "kaynak": sub_id,
                        "hedef": gw_ip,
                        "mesaj": f"Varsayılan ağ geçidi {gw_ip}, {sub_id} alt ağı ({calc.network}) sınırları dışındadır!"
                    })

        # 3. DENETİM: Cihaz Seviyesinde IP ve MAC Kontrolleri
        gorulen_ipv4: Dict[str, str] = {}
        # Görülen MAC adreslerini cihaz ID ile eşleyen sözlük
        gorulen_mac: Dict[str, str] = {}

        # Tüm cihazları tek tek denetler
        for dev in self.cihazlar:
            # Cihaz ID'si
            dev_id = dev["cihaz_id"]
            # Cihaz IP'si
            ip_val = dev["ipv4"]
            # Cihaz MAC adresi
            mac_val = dev["mac"].upper()
            # Cihazın bağlı olduğu alt ağ ID'si
            sub_id = dev.get("alt_ag_id")

            # 3a. IP Çakışması (Duplicate IP) Tespiti
            if ip_val in gorulen_ipv4:
                # Aynı IP başka bir cihazda görüldüğünde kritik alarm üretir
                self.denetim_bulgulari.append({
                    "kategori": "IP_CAKISMASI",
                    "seviye": "KRITIK",
                    "kaynak": dev_id,
                    "hedef": gorulen_ipv4[ip_val],
                    "mesaj": f"IP adresi {ip_val} hem {gorulen_ipv4[ip_val]} hem de {dev_id} üzerinde tanımlıdır!"
                })
            # İlk kez görülen IP'yi kaydeder
            else:
                # IP tablosuna ekler
                gorulen_ipv4[ip_val] = dev_id

            # 3b. MAC Çakışması (Duplicate MAC / Spoofing Şüphesi) Tespiti
            if mac_val in gorulen_mac:
                # Aynı MAC başka bir cihazda görüldüğünde alarm üretir
                self.denetim_bulgulari.append({
                    "kategori": "MAC_CAKISMASI",
                    "seviye": "YUKSEK",
                    "kaynak": dev_id,
                    "hedef": gorulen_mac[mac_val],
                    "mesaj": f"MAC adresi {mac_val} hem {gorulen_mac[mac_val]} hem de {dev_id} üzerinde mevcuttur!"
                })
            # İlk kez görülen MAC adresini kaydeder
            else:
                # MAC tablosuna ekler
                gorulen_mac[mac_val] = dev_id

            # 3c. Cihaz IP'sinin Bağlı Olduğu Alt Ağda Olup Olmadığı ve Kullanılabilirlik Kontrolü
            if sub_id in self.hesaplayicilar_v4:
                # Alt ağ hesaplayıcısını alır
                calc = self.hesaplayicilar_v4[sub_id]
                # IP alt ağ sınırları içinde mi?
                if not calc.contains_ip(ip_val):
                    # Alt ağ dışı IP atamasında alarm üretir
                    self.denetim_bulgulari.append({
                        "kategori": "ALT_AG_DISI_IP",
                        "seviye": "KRITIK",
                        "kaynak": dev_id,
                        "hedef": ip_val,
                        "mesaj": f"Cihaz IP'si {ip_val}, bağlı olduğu {sub_id} ({calc.network}) ağında değildir!"
                    })
                # IP ağ adresi veya yayın adresi olarak mı atanmış?
                elif not calc.is_usable_host_ip(ip_val):
                    # Kullanılamaz IP atama hatası kaydeder
                    self.denetim_bulgulari.append({
                        "kategori": "KULLANILAMAZ_IP_ATAMASI",
                        "seviye": "KRITIK",
                        "kaynak": dev_id,
                        "hedef": ip_val,
                        "mesaj": f"Cihaza ağ adresi veya yayın adresi atanmış ({ip_val})! Konaklar bu IP'yi kullanamaz."
                    })

            # 3d. Cihazın Özel Bir Ağ Geçidi Tanımı Varsa ve Bu Geçit Alt Ağ Dışındaysa
            if "ozel_ag_gecidi" in dev and dev["ozel_ag_gecidi"]:
                # Özel ağ geçidi adresini alır
                custom_gw = dev["ozel_ag_gecidi"]
                # Alt ağ hesaplayıcısını alır
                if sub_id in self.hesaplayicilar_v4:
                    # Hesaplayıcı nesnesi
                    calc = self.hesaplayicilar_v4[sub_id]
                    # Ağ geçidinin alt ağda olup olmadığını kontrol eder
                    if not calc.contains_ip(custom_gw):
                        # Alt ağ dışı özel ağ geçidi uyarısı
                        self.denetim_bulgulari.append({
                            "kategori": "GECERSIZ_OZEL_AG_GECIDI",
                            "seviye": "KRITIK",
                            "kaynak": dev_id,
                            "hedef": custom_gw,
                            "mesaj": f"Cihaz özel ağ geçidi {custom_gw}, alt ağ ({calc.network}) dışındadır!"
                        })

            # 3e. IPv6 EUI-64 MAC Gizlilik Sızıntısı Kontrolü
            if "ipv6" in dev and dev["ipv6"]:
                # IPv6 adresi
                v6_addr = dev["ipv6"]
                # EUI-64 sızıntısı var mı inceler
                if IPv6SubnetCalculator.is_eui64_mac_leakage(v6_addr, mac_val):
                    # Gizlilik ihlali ve cihaz parmak izi uyarısı
                    self.denetim_bulgulari.append({
                        "kategori": "IPV6_EUI64_GIZLILIK_SIZINTISI",
                        "seviye": "ORTA",
                        "kaynak": dev_id,
                        "hedef": v6_addr,
                        "mesaj": f"IPv6 adresinde EUI-64 mekanizmasıyla fiziksel MAC ({mac_val}) sızdırılmıştır!"
                    })

        # Tespit edilen denetim bulguları listesini döner
        return self.denetim_bulgulari

    def generate_markdown_report(self) -> str:
        """Ağ çalışma kitabı ve denetim sonuçlarını profesyonel Markdown raporu olarak derler."""
        # Rapor satırlarını toplayacak liste başlatılır
        lines: List[str] = []
        # Başlık ve proje ismi eklenir
        lines.append(f"# 📊 {self.proje_adi} — Kapsamlı Ağ ve Güvenlik Denetim Raporu\n")
        # Lisans satırı
        lines.append("**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  ")
        # Telif hakkı bildirimi
        lines.append("*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*\n")
        # Ayırıcı çizgi
        lines.append("---\n")

        # 1. BÖLÜM: Alt Ağ (Subnet) ve VLSM Planı
        lines.append("## 1. Alt Ağ ve VLSM Adresleme Planı\n")
        # Tablo başlığı
        lines.append("| Alt Ağ ID | VLAN | Ad | IPv4 CIDR | Ağ Maskesi | Ağ IP | Yayın IP | Kullanılabilir Aralık | Toplam / Kullanılabilir Host |")
        # Tablo ayırıcı çizgisi
        lines.append("|---|---|---|---|---|---|---|---|---|")
        
        # Tüm alt ağları tabloya döker
        for sub_id, sub_info in self.alt_aglar.items():
            # Hesaplayıcı nesnesi
            calc = self.hesaplayicilar_v4[sub_id]
            # Tablo satırını biçimlendirir
            satir = (
                f"| `{sub_id}` | `{sub_info['vlan_id']}` | {sub_info.get('ad', '-')} | "
                f"`{sub_info['ipv4_cidr']}` | `{calc.netmask}` | `{calc.network_address}` | "
                f"`{calc.broadcast_address}` | `{calc.first_usable}` - `{calc.last_usable}` | "
                f"{calc.total_addresses} / **{calc.usable_hosts}** |"
            )
            # Satırı rapora ekler
            lines.append(satir)
        # Boşluk bırakır
        lines.append("")

        # 2. BÖLÜM: Cihaz ve Uç Nokta Adres Envanteri
        lines.append("## 2. Cihaz ve Uç Nokta Envanteri (Katman-2 & Katman-3)\n")
        # Tablo başlığı
        lines.append("| Cihaz ID | Konak Adı | Rol | Alt Ağ ID | IPv4 Adresi | MAC Adresi | IPv6 Adresi |")
        # Tablo ayırıcı çizgisi
        lines.append("|---|---|---|---|---|---|---|")
        
        # Cihazları tabloya ekler
        for dev in self.cihazlar:
            # Satır içeriğini derler
            satir = (
                f"| `{dev['cihaz_id']}` | `{dev['konak_adi']}` | {dev.get('rol', '-')} | "
                f"`{dev.get('alt_ag_id', '-')}` | `{dev['ipv4']}` | `{dev['mac']}` | "
                f"`{dev.get('ipv6', '-')}` |"
            )
            # Satırı listeye ekler
            lines.append(satir)
        # Boşluk bırakır
        lines.append("")

        # 3. BÖLÜM: Güvenlik ve Yapılandırma Denetim Bulguları
        lines.append("## 3. Güvenlik ve Yapılandırma Denetim Bulguları\n")
        # Bulgular boşsa tebrik mesajı ekler
        if not self.denetim_bulgulari:
            # Temiz ağ bildirimi
            lines.append("✅ **Denetim Başarılı:** Topolojide hiçbir çakışma, geçersiz ağ geçidi veya güvenlik anomalisi saptanmadı.\n")
        # Bulgular varsa tablo halinde sunar
        else:
            # Bulgu tablosu başlığı
            lines.append("| No | Kategori | Seviye | Kaynak | Hedef / İlgili IP | Açıklama ve Güvenlik Riski |")
            # Tablo ayırıcı
            lines.append("|---|---|---|---|---|---|")
            # Bulguları numaralandırarak listeler
            for idx, b in enumerate(self.denetim_bulgulari, 1):
                # Seviye ikonunu belirler
                ikon = "🚨" if b["seviye"] == "KRITIK" else "⚠️"
                # Tablo satırını oluşturur
                satir = f"| {idx} | `{b['kategori']}` | {ikon} **{b['seviye']}** | `{b['kaynak']}` | `{b['hedef']}` | {b['mesaj']} |"
                # Satırı rapora ekler
                lines.append(satir)
            # Boşluk ekler
            lines.append("")

        # 4. BÖLÜM: Ağ Sıkılaştırma ve İyileştirme Önerileri
        lines.append("## 4. Ağ Sıkılaştırma ve Mimari İyileştirme İlkeleri\n")
        # Birinci ilke
        lines.append("1. **VLAN ve VRF Tabanlı İzolasyon:** Her güvenlik bölgesi (Internal, DMZ, Guest) bağımsız bir VLAN kimliğine sahip olmalı ve yönlendirici erişim kontrol listeleri (ACL) ile sınırlandırılmalıdır.")
        # İkinci ilke
        lines.append("2. **DHCP Snooping & Dynamic ARP Inspection (DAI):** Uç anahtarlarda IP ve MAC çakışmalarını, ARP zehirleme saldırılarını önlemek için güvenilir bağlama veritabanları zorunlu kılınmalıdır.")
        # Üçüncü ilke
        lines.append("3. **IPv6 Gizlilik Uzantıları (RFC 4941):** Donanım MAC adresinin IPv6 içinde ifşa edilerek cihaz hareketlerinin takip edilmesini önlemek adına EUI-64 yerine rastgele geçici adresler (Privacy Extensions) etkinleştirilmelidir.\n")

        # Birleştirilmiş metni döner
        return "\n".join(lines)


if __name__ == "__main__":
    # Konsol başlangıç mesajı
    print("================================================================================")
    # Başlık bildirimi
    print("[+] Mini Proje 6: Ağ Adresleme Çalışma Kitabı ve Güvenlik Denetim Motoru Başlatılıyor...")
    # Çizgi
    print("================================================================================")
    
    # Örnek topoloji JSON dosya yolu
    sample_json = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_topology_workbook.json")
    # Dosya yolunu normalize eder
    sample_json = os.path.abspath(sample_json)
    
    # Çalışma kitabı nesnesini oluşturur
    workbook = NetworkAddressingWorkbook("Kurumsal Ağ Adresleme ve Segmentasyon Çalışma Kitabı")
    # JSON verisini yükler
    workbook.load_from_json(sample_json)
    
    # Başlangıç denetimlerini yürütür
    print("[*] 1. Temel Ağ Topolojisi Yüklendi. Alt Ağlar ve Cihazlar Denetleniyor...")
    # Denetim motorunu çalıştırır
    bulgular_temel = workbook.run_audits()
    # Temel denetim sonucunu ekrana yazar
    print(f"    -> Temel topolojide bulunan anomali sayısı: {len(bulgular_temel)}")

    # Test senaryolarındaki anomalileri çalışma kitabına enjekte ederek denetim gücünü kanıtlar
    with open(sample_json, "r", encoding="utf-8") as f:
        # JSON verisini okur
        raw_data = json.load(f)
    
    # Hata senaryolarını tek tek dener
    print("\n[*] 2. Güvenlik Denetim Test Senaryoları (Anomali Enjeksiyonu) Yürütülüyor...")
    # Denetim senaryoları listesini alır
    for scn in raw_data.get("denetim_test_senaryolari", []):
        # Senaryo kimliği ve açıklamasını ekrana basar
        print(f"    -> Enjekte Ediliyor: [{scn['senaryo_id']}] {scn['aciklama']}")
        # Cihaz hatası senaryosu ise
        if "cihaz" in scn:
            # Hatalı cihazı ekler
            workbook.add_device(scn["cihaz"])
        # Çakışan alt ağ senaryosu ise
        elif "cakisan_alt_ag" in scn:
            # Çakışan alt ağı ekler
            workbook.add_subnet(scn["cakisan_alt_ag"])

    # Anomaliler eklendikten sonra yeniden denetim koşar
    print("\n[*] 3. Kapsamlı Güvenlik Denetimi Koşuluyor...")
    # Denetimi yineler
    tum_bulgular = workbook.run_audits()
    # Bulunan toplam anomali sayısını basar
    print(f"    -> Toplam Tespit Edilen Güvenlik ve Yapılandırma Anomalisi: {len(tum_bulgular)}")
    
    # Her bir anomaliyi konsola raporlar
    for idx, b in enumerate(tum_bulgular, 1):
        # Ayrıntıyı ekrana yazar
        print(f"       [{idx}] {b['seviye']} | {b['kategori']} | Kaynak: {b['kaynak']} -> {b['mesaj']}")

    # Markdown raporunu üretir
    rapor_md = workbook.generate_markdown_report()
    
    # Rapor dosyasının kaydedileceği konumu belirler
    kanit_rapor_yolu = os.path.join(os.path.dirname(__file__), "..", "kanit", "gercek", "ag_adresleme_calisma_kitabi_raporu.txt")
    # Dosya yolunu normalize eder
    kanit_rapor_yolu = os.path.abspath(kanit_rapor_yolu)
    # Dizin oluşturur
    os.makedirs(os.path.dirname(kanit_rapor_yolu), exist_ok=True)
    # Raporu dosyaya yazar
    with open(kanit_rapor_yolu, "w", encoding="utf-8") as f:
        # Metni yazar
        f.write(rapor_md)
    # Kayıt bildirimini ekrana basar
    print(f"\n[+] Ağ Çalışma Kitabı Raporu Başarıyla Kaydedildi: {kanit_rapor_yolu}")
    print("================================================================================")
