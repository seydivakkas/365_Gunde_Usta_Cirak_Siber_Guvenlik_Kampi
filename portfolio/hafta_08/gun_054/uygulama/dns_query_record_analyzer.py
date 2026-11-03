# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G054: DNS (Domain Name System) Sorguları ve Kayıt Türleri Analizörü.
Bu modül RFC 1034 / RFC 1035 standartlarına uygun ikili DNS başlığı ve soru kodlama,
A, AAAA, CNAME, MX ve TXT gibi temel kaynak kayıtlarının (Resource Records) modellenmesi,
ve 'DNS Yanıtı Doğrulanmış Kimlik Değildir' ilkesi doğrultusunda SPF/DMARC e-posta güvenliği,
Sahipsiz CNAME (Subdomain Takeover) ve DNS Tünelleme (Data Exfiltration) analizlerini yürütür.
"""

import ipaddress  # IPv4 ve IPv6 adres formatı ve geçerlilik doğrulaması için standart modül
import math  # Shannon entropi hesaplamalarında logaritma işlemleri için matematik kütüphanesi
import struct  # İkili (binary) ağ bayt dizisi paketleme ve ayrıştırma modülü
from typing import Any, Dict, List, Optional, Set, Tuple  # Statik tip denetimi ve açıklama türleri


class DNSError(Exception):  # Temel DNS özel istisna sınıfı
    """DNS işlemleri için kök istisna sınıfı."""

    pass  # Temel gövde


class DNSValidationError(DNSError):  # Sözdizimi ve sınır doğrulama istisna sınıfı
    """Geçersiz alan adı, TTL, QTYPE veya format hatalarında fırlatılan istisna."""

    pass  # Doğrulama gövdesi


class DNSSpoofingRiskError(DNSError):  # DNS sahteciliği ve yanıt zehirleme istisnası
    """Doğrulanmamış veya sahte DNS yanıtı şüphesi durumunda fırlatılan hata."""

    pass  # Sahtecilik gövdesi


class DNSTunnelingRiskError(DNSError):  # DNS tünelleme ve veri sızdırma istisnası
    """DNS sorguları üzerinden tünelleme veya veri sızıntısı tespit edildiğinde uyarır."""

    pass  # Tünelleme gövdesi


class DNSType:  # DNS Kayıt Türleri Sabitleri ve Yardımcı Sınıfı
    """RFC 1035 ve RFC 3596 standartlarına uygun DNS Kayıt Türü (QTYPE) tanımları."""

    A: int = 1  # IPv4 Ana Bilgisayar Adresi (32-bit)
    NS: int = 2  # Yetkili Ad Sunucusu (Authoritative Name Server)
    CNAME: int = 5  # Standart Ad / Takma Ad (Canonical Name)
    SOA: int = 6  # Bölge Başlangıç Kaydı (Start of Authority)
    PTR: int = 12  # İşaretçi / Ters DNS Kaydı (Pointer Record)
    MX: int = 15  # Posta Sunucusu Değişimi (Mail Exchange)
    TXT: int = 16  # Metin Kaydı (SPF, DMARC, Domain Doğrulama)
    AAAA: int = 28  # IPv6 Ana Bilgisayar Adresi (128-bit)
    ANY: int = 255  # Tüm Kayıtları İsteme Joker Sorgusu

    _CODE_TO_NAME: Dict[int, str] = {  # Koddan metin adına dönüşüm tablosu
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"  # Kod eşlemeleri
    }  # Dönüşüm haritası sonu

    _NAME_TO_CODE: Dict[str, int] = {  # Metin adından koda dönüşüm tablosu
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "ANY": 255  # İsim eşlemeleri
    }  # Dönüşüm haritası sonu

    @classmethod  # Sınıf referansıyla çalışan kod adı çözücü
    def get_name(cls, code: int) -> str:  # Sayısal koddan isim döndüren metot
        """Sayısal QTYPE kodundan metin adını döndürür."""
        return cls._CODE_TO_NAME.get(code, f"TYPE_{code}")  # Bulunamazsa TYPE_x formatında döner

    @classmethod  # Metin adından kod döndüren sınıf metodu
    def get_code(cls, name: str) -> int:  # İsimden kod döndüren metot
        """Kayıt türü metin adından sayısal kodu döndürür."""
        upper_name = name.upper()  # Büyük harfe çevir
        if upper_name not in cls._NAME_TO_CODE:  # Bilinmeyen tür kontrolü
            raise DNSValidationError(f"Bilinmeyen DNS kayıt türü: '{name}'")  # Hata fırlat
        return cls._NAME_TO_CODE[upper_name]  # Sayısal kodu döndür


def encode_domain_name(domain: str) -> bytes:  # RFC 1035 etiket kodlama fonksiyonu
    """
    Alan adını RFC 1035 etiket (label) formatına dönüştürür.
    Örnek: 'example.com' -> b'\\x07example\\x03com\\x00'
    """
    if not domain or domain.strip() == "":  # Boş alan adı kontrolü
        raise DNSValidationError("Alan adı boş olamaz.")  # Hata bildir

    clean_domain = domain.rstrip(".")  # Sondaki noktayı temizle
    if len(clean_domain) > 253:  # RFC 1035 maksimum alan adı uzunluğu kontrolü
        raise DNSValidationError(f"Toplam alan adı uzunluğu 253 karakteri aşamaz: {len(clean_domain)}")  # Sınır ihlali

    labels = clean_domain.split(".")  # Noktalarından etiketlere ayır
    encoded = b""  # İkili bayt tamponu başlat
    for label in labels:  # Her etiket üzerinde döngü
        label_bytes = label.encode("ascii", errors="replace")  # ASCII baytlarına çevir
        if len(label_bytes) == 0:  # Boş etiket kontrolü (çift nokta)
            raise DNSValidationError("Alan adı boş etiket (ardışık nokta) içeremez.")  # Hata
        if len(label_bytes) > 63:  # RFC 1035 63 bayt etiket sınırı kontrolü
            raise DNSValidationError(f"DNS etiket uzunluğu 63 karakteri aşamaz: {len(label_bytes)} bayt ('{label[:15]}...')")  # Etiket hatası
        encoded += bytes([len(label_bytes)]) + label_bytes  # Uzunluk öneki + etiket verisi
    encoded += b"\x00"  # Kök etiketini belirten sonlandırıcı sıfır baytı
    return encoded  # Kodlanmış ikili bayt dizisini döndür


def decode_domain_name(data: bytes, offset: int = 0) -> Tuple[str, int]:  # İkili etiketi metne çeviren fonksiyon
    """RFC 1035 etiket baytlarını metinsel alan adına çözümler."""
    labels: List[str] = []  # Etiket listesi
    current = offset  # İlerleme imleci
    while current < len(data):  # Veri sonuna kadar tara
        length = data[current]  # Etiket uzunluk baytı
        if length == 0:  # Sıfır baytı kök etiketidir (sonlandırıcı)
            current += 1  # İmleci bir adım ilerlet
            break  # Döngüden çık
        current += 1  # Uzunluk baytını atla
        label = data[current:current + length].decode("ascii", errors="replace")  # Etiketi çöz
        labels.append(label)  # Listeye ekle
        current += length  # İmleci etiket boyu kadar ilerlet
    return ".".join(labels), current  # Noktayla birleştirilmiş alan adı ve yeni imleç


class DNSHeader:  # 12 baytlık ikili DNS Başlığı sınıfı
    """
    RFC 1035 12 Baytlık DNS Başlık Modeli.
    Alanlar:
    - ID (16 bit): Sorgu/yanıt eşleme kimliği
    - Flags (16 bit): QR, Opcode, AA, TC, RD, RA, Z, RCODE
    - QDCOUNT (16 bit): Soru sayısı
    - ANCOUNT (16 bit): Cevap kaynak kayıt sayısı
    - NSCOUNT (16 bit): Yetkili sunucu kayıt sayısı
    - ARCOUNT (16 bit): Ek kayıt sayısı
    """

    FORMAT: str = "!HHHHHH"  # 6 adet 16-bit işaretsiz tamsayı
    SIZE: int = 12  # Sabit başlık boyutu (12 bayt)

    def __init__(  # Başlatıcı metot
        self,  # Parametre / ifade: self,
        tx_id: int,  # İşlem kimliği
        qr: int = 0,  # 0: Query, 1: Response
        opcode: int = 0,  # 0: Standard Query
        aa: int = 0,  # Authoritative Answer
        tc: int = 0,  # Truncated
        rd: int = 1,  # Recursion Desired
        ra: int = 0,  # Recursion Available
        rcode: int = 0,  # Response Code (0: NoError, 3: NXDomain)
        qd_count: int = 1,  # Soru sayısı
        an_count: int = 0,  # Yanıt sayısı
        ns_count: int = 0,  # Yetkili kayıt sayısı
        ar_count: int = 0,  # Ek kayıt sayısı
    ) -> None:  # Dönüş tipi
        """DNS başlık alanlarını doğrular ve başlatır."""
        if not isinstance(tx_id, int) or tx_id < 0 or tx_id > 65535:  # ID aralık kontrolü
            raise DNSValidationError(f"Transaction ID 0 ile 65535 arasında olmalıdır: {tx_id}")  # Hata bildir
        self.tx_id: int = tx_id  # 16-bit ID
        self.qr: int = qr & 0x01  # 1 bit QR
        self.opcode: int = opcode & 0x0F  # 4 bit Opcode
        self.aa: int = aa & 0x01  # 1 bit AA
        self.tc: int = tc & 0x01  # 1 bit TC
        self.rd: int = rd & 0x01  # 1 bit RD
        self.ra: int = ra & 0x01  # 1 bit RA
        self.rcode: int = rcode & 0x0F  # 4 bit RCODE
        self.qd_count: int = qd_count  # Soru sayısı
        self.an_count: int = an_count  # Cevap sayısı
        self.ns_count: int = ns_count  # Yetkili sayısı
        self.ar_count: int = ar_count  # Ek kayıt sayısı

    @property  # Bayrakları 16-bit tamsayıya birleştiren özellik
    def flags(self) -> int:  # 16 bit bayraklar
        """16-bit birleşik DNS bayrak tamsayısını hesaplar."""
        return (  # Bitwise kaydırma ve maskeleme
            (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) |  # Parametre / ifade: (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) |
            (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | (self.rcode)  # Parametre / ifade: (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | (self.rcode)
        )  # Bayrak tamsayısı

    def pack(self) -> bytes:  # Başlığı ikili baytlara paketleme metodu
        """Başlığı 12 baytlık ikili ağ formatına dönüştürür."""
        return struct.pack(self.FORMAT, self.tx_id, self.flags, self.qd_count, self.an_count, self.ns_count, self.ar_count)  # Paketle

    @classmethod  # İkili baytlardan başlık nesnesi çıkaran metot
    def unpack(cls, data: bytes) -> "DNSHeader":  # Başlık nesnesi döndürür
        """12 baytlık ikili veriden DNSHeader nesnesi oluşturur."""
        if len(data) < cls.SIZE:  # Veri boyutu kontrolü
            raise DNSValidationError(f"DNS başlığı için en az 12 bayt gerekir, alınan: {len(data)}")  # Hata
        tx_id, flags_raw, qd, an, ns, ar = struct.unpack(cls.FORMAT, data[:cls.SIZE])  # Ayrıştır
        qr = (flags_raw >> 15) & 0x01  # QR çıkar
        opcode = (flags_raw >> 11) & 0x0F  # Opcode çıkar
        aa = (flags_raw >> 10) & 0x01  # AA çıkar
        tc = (flags_raw >> 9) & 0x01  # TC çıkar
        rd = (flags_raw >> 8) & 0x01  # RD çıkar
        ra = (flags_raw >> 7) & 0x01  # RA çıkar
        rcode = flags_raw & 0x0F  # RCODE çıkar
        return cls(tx_id, qr, opcode, aa, tc, rd, ra, rcode, qd, an, ns, ar)  # Nesne döndür


class DNSQuestion:  # DNS Soru Bölümü Modeli
    """RFC 1035 Soru Bölümü (QNAME, QTYPE, QCLASS)."""

    def __init__(self, name: str, qtype: int, qclass: int = 1) -> None:  # Başlatıcı
        """Soru nesnesini doğrular ve başlatır."""
        self.name: str = name  # Sorgulanan alan adı
        self.qtype: int = qtype  # Sorgu tür kodu (A, MX vb.)
        self.qclass: int = qclass  # Sınıf (varsayılan IN = 1)

    def pack(self) -> bytes:  # Soruyu ikili formata çevir
        """Soruyu ikili bayt dizisine dönüştürür."""
        encoded_name = encode_domain_name(self.name)  # Alan adını etiketle
        return encoded_name + struct.pack("!HH", self.qtype, self.qclass)  # QTYPE ve QCLASS ekle


class DNSRecord:  # DNS Kaynak Kaydı (Resource Record) Sınıfı
    """Tek bir DNS Kaynak Kaydını (RR) temsil eden nesne."""

    def __init__(  # Başlatıcı metot
        self,  # Parametre / ifade: self,
        name: str,  # Alan adı
        rtype: str,  # Kayıt türü adı ('A', 'AAAA', 'CNAME', 'MX', 'TXT')
        ttl: int = 3600,  # Yaşam süresi (saniye)
        rdata: str = "",  # Kayıt verisi (IP, hedef alan adı veya metin)
        preference: Optional[int] = None,  # MX için öncelik değeri
    ) -> None:  # Dönüş tipi
        """Kaynak kaydı alanlarını doğrular ve başlatır."""
        self._validate_fields(name, rtype, ttl, rdata, preference)  # Doğrulama çağrısı
        self.name: str = name.lower()  # Alan adı küçük harfe çevrilir
        self.rtype: str = rtype.upper()  # Tür adı büyük harfe çevrilir
        self.type_code: int = DNSType.get_code(self.rtype)  # Sayısal tür kodu
        self.ttl: int = ttl  # TTL değeri atanır
        self.rdata: str = rdata  # RDATA atanır
        self.preference: Optional[int] = preference  # MX önceliği atanır

    def _validate_fields(  # Doğrulama özel metodu
        self, name: str, rtype: str, ttl: int, rdata: str, pref: Optional[int]  # Parametre / ifade: self, name: str, rtype: str, ttl: int, rdata: str, pref: Optional[int]
    ) -> None:  # Doğrulama dönüşü
        """Kayıt parametrelerinin sözdizimi ve mantıksal geçerliliğini denetler."""
        if not name or name.strip() == "":  # Boş ad kontrolü
            raise DNSValidationError("Alan adı boş olamaz.")  # Hata
        if not isinstance(ttl, int) or ttl < 0:  # Negatif TTL kontrolü
            raise DNSValidationError(f"DNS TTL değeri negatif olamaz: {ttl}")  # Hata
        type_code = DNSType.get_code(rtype)  # Tür adını doğrula

        if type_code == DNSType.A:  # A kaydı için IPv4 doğrulaması
            try:  # IP denetimi
                ipaddress.IPv4Address(rdata)  # IPv4 geçerliliği
            except Exception as err:  # Hatalı IPv4
                raise DNSValidationError(f"A kaydı için geçersiz IPv4 adresi biçimi: '{rdata}'. Hata: {err}")  # Hata bildir
        elif type_code == DNSType.AAAA:  # AAAA kaydı için IPv6 doğrulaması
            try:  # IPv6 denetimi
                ipaddress.IPv6Address(rdata)  # IPv6 geçerliliği
            except Exception as err:  # Hatalı IPv6
                raise DNSValidationError(f"AAAA kaydı için geçersiz IPv6 adresi biçimi: '{rdata}'. Hata: {err}")  # Hata bildir
        elif type_code == DNSType.MX:  # MX kaydı öncelik kontrolü
            if pref is None or not isinstance(pref, int) or pref < 0 or pref > 65535:  # MX öncelik kontrolü
                raise DNSValidationError(f"MX kaydı 0-65535 arasında geçerli bir öncelik değeri gerektirir: {pref}")  # Hata

    def to_dict(self) -> Dict[str, Any]:  # Sözlük temsili metodu
        """Kaydı raporlanabilir sözlük yapısına çevirir."""
        res: Dict[str, Any] = {  # Sonuç sözlüğü
            "ad": self.name,  # Alan adı
            "tur": self.rtype,  # Tür adı
            "tur_kodu": self.type_code,  # Sayısal kod
            "ttl": self.ttl,  # TTL
            "rdata": self.rdata,  # Veri
        }  # Temel sözlük
        if self.preference is not None:  # MX önceliği varsa ekle
            res["oncelik"] = self.preference  # Öncelik değeri
        return res  # Sözlüğü döndür


class DNSSecurityAuditor:  # DNS Güvenlik ve Tehdit Denetim Motoru
    """
    DNS Bölge ve Sorgu Güvenlik Analizörü.
    Özellikler:
    - SPF ve DMARC e-posta güvenliği politikası denetimi
    - Sahipsiz CNAME (Dangling CNAME / Subdomain Takeover) tespiti
    - Shannon Entropisi ve etiket uzunluğu ile DNS Tünelleme (Veri Sızıntısı) tespiti
    """

    KNOWN_TAKEOVER_PATTERNS: List[str] = [  # Alt alan adı ele geçirmeye açık üçüncü taraf bulut adres kalıpları
        "s3-website",  # AWS S3 Statik Web Deposu
        "github.io",  # GitHub Pages
        "azurewebsites.net",  # Microsoft Azure Web App
        "herokuapp.com",  # Heroku Uygulama Platformu
        "trafficmanager.net",  # Azure Traffic Manager
        "ghost.io",  # Ghost Blog Barındırma
        "surge.sh",  # Surge Statik Barındırma
    ]  # Kalıp listesi sonu

    @staticmethod  # Entropi hesaplayıcı statik metot
    def calculate_shannon_entropy(data_str: str) -> float:  # Shannon entropi fonksiyonu
        """Bir metin dizgisinin Shannon Entropisini (rastgelelik/bilgi yoğunluğu) hesaplar."""
        if not data_str:  # Boş veri kontrolü
            return 0.0  # Sıfır entropi
        freq: Dict[str, int] = {}  # Karakter frekans tablosu
        for char in data_str:  # Karakterler üzerinde döngü
            freq[char] = freq.get(char, 0) + 1  # Frekansı artır
        total = len(data_str)  # Toplam karakter
        return -sum((c / total) * math.log2(c / total) for c in freq.values())  # Shannon formülü

    def audit_email_security_txt(self, records: List[DNSRecord]) -> Dict[str, Any]:  # E-posta güvenlik denetimi
        """Bölgedeki TXT kayıtlarını SPF ve DMARC e-posta sahteciliği koruması açısından denetler."""
        spf_records = [r for r in records if r.rtype == "TXT" and "v=spf1" in r.rdata.lower()]  # SPF kayıtları
        dmarc_records = [r for r in records if r.rtype == "TXT" and "v=dmarc1" in r.rdata.lower()]  # DMARC kayıtları
        findings: List[Dict[str, Any]] = []  # Bulgular listesi

        # 1. SPF Değerlendirmesi
        if not spf_records:  # SPF kaydı yoksa
            findings.append({  # Bulgu ekle
                "seviye": "HIGH",  # Seviye
                "kategori": "SPF_MISSING",  # Kategori
                "aciklama": "Alan adında SPF (Sender Policy Framework) kaydı bulunamadı. Saldırganlar bu alan adı adına sahte e-posta gönderebilir (Spoofing).",  # Açıklama
                "onerilen_onlem": "v=spf1 ip4:<izinli_ip> -all şeklinde katı bir SPF TXT kaydı ekleyin.",  # Önlem
            })  # Bulgu sonu
        else:  # SPF kaydı varsa
            spf_val = spf_records[0].rdata.lower()  # SPF değeri
            if "+all" in spf_val or "?all" in spf_val:  # Zayıf politika kontrolü
                findings.append({  # Bulgu ekle
                    "seviye": "MEDIUM",  # Seviye
                    "kategori": "WEAK_SPF_POLICY",  # Kategori
                    "aciklama": f"SPF kaydında zayıf mekanizma bulundu ('{spf_records[0].rdata}'). Tüm IP'lere izin veriliyor (+all) veya tarafsız (?all) bırakılmış.",  # Açıklama
                    "onerilen_onlem": "Politikayı katı engelleme için '-all' (HardFail) veya geçici test için '~all' (SoftFail) yapın.",  # Önlem
                })  # Bulgu sonu

        # 2. DMARC Değerlendirmesi
        if not dmarc_records:  # DMARC kaydı yoksa
            findings.append({  # Bulgu ekle
                "seviye": "HIGH",  # Seviye
                "kategori": "DMARC_MISSING",  # Kategori
                "aciklama": "_dmarc alt alan adında DMARC politikası bulunamadı. E-posta sağlayıcıları sahte mailleri nasıl ele alacağını bilemez.",  # Açıklama
                "onerilen_onlem": "v=DMARC1; p=reject; rua=mailto:<rapor_adresi> kaydı oluşturun.",  # Önlem
            })  # Bulgu sonu
        else:  # DMARC kaydı varsa
            dmarc_val = dmarc_records[0].rdata.lower()  # Değer
            if "p=none" in dmarc_val:  # Yalnızca izleme modu
                findings.append({  # Bulgu ekle
                    "seviye": "LOW",  # Seviye
                    "kategori": "DMARC_MONITORING_ONLY",  # Kategori
                    "aciklama": "DMARC politikası 'p=none' modunda; sahte e-postalar reddedilmiyor, yalnızca raporlanıyor.",  # Açıklama
                    "onerilen_onlem": "Politikayı aşamalı olarak 'p=quarantine' ve nihayetinde 'p=reject' seviyesine yükseltin.",  # Önlem
                })  # Bulgu sonu

        return {  # Rapor döndür
            "spf_mevcut": len(spf_records) > 0,  # SPF var mı
            "dmarc_mevcut": len(dmarc_records) > 0,  # DMARC var mı
            "bulgular": findings,  # Bulgular
        }  # Rapor sonu

    def audit_subdomain_takeover(self, records: List[DNSRecord]) -> Dict[str, Any]:  # Subdomain Takeover denetimi
        """Bölgedeki CNAME kayıtlarını sahipsiz üçüncü taraf bulut işaretçileri açısından inceler."""
        findings: List[Dict[str, Any]] = []  # Risk listesi
        cname_records = [r for r in records if r.rtype == "CNAME"]  # CNAME kayıtları

        for cr in cname_records:  # Her CNAME üzerinde döngü
            target = cr.rdata.lower()  # Hedef alan adı
            for pattern in self.KNOWN_TAKEOVER_PATTERNS:  # Şüpheli bulut sağlayıcıları listesinde ara
                if pattern in target:  # Eğer hedef eşleşiyorsa
                    findings.append({  # Kritik bulgu ekle
                        "seviye": "CRITICAL",  # Seviye
                        "kategori": "SUBDOMAIN_TAKEOVER_RISK",  # Kategori
                        "kaynak_cname": cr.name,  # Kurban alt alan adı
                        "hedef_bulut": cr.rdata,  # Hedef bulut deposu
                        "aciklama": f"'{cr.name}' alt alan adı '{pattern}' bulut servisine işaret ediyor. Eğer bu bulut kaynağı silinmiş veya sahipsiz bırakılmışsa (Dangling CNAME), saldırgan aynı isimle depo açarak alan adını tamamen ele geçirebilir!",  # Açıklama
                        "onerilen_onlem": "Hedef bulut kaynağının aktif sahipliğini doğrulayın; kullanılmıyorsa CNAME kaydını derhal silin.",  # Önlem
                    })  # Bulgu sonu

        return {  # Sonuç sözlüğü
            "toplam_cname_incelendi": len(cname_records),  # CNAME sayısı
            "risk_bulundu_mu": len(findings) > 0,  # Risk var mı
            "bulgular": findings,  # Risk detayları
        }  # Sözlük sonu

    def audit_dns_tunneling(self, query_domain: str) -> Dict[str, Any]:  # DNS Tünelleme tespit metodu
        """Sorgulanan alan adını yüksek entropi ve uzunluk kriterleriyle DNS Tünelleme / Veri Sızıntısı için inceler."""
        clean = query_domain.rstrip(".")  # Noktayı temizle
        labels = clean.split(".")  # Etiketlere böl
        first_label = labels[0] if labels else ""  # En alt etiket (genelde verinin kodlandığı kısım)
        entropy = self.calculate_shannon_entropy(first_label)  # Entropi hesapla
        length = len(first_label)  # Uzunluk

        is_tunneling = (entropy >= 2.8 and length >= 25) or (length >= 35)  # Tünelleme tespit mantığı (hex kodlama ve uzunluk eşiği)

        return {  # Rapor sözlüğü
            "sorgulanan_alan_adi": query_domain,  # Sorgulanan alan adı
            "incelenen_etiket": first_label,  # İncelenen etiket
            "etiket_uzunlugu": length,  # Uzunluk
            "shannon_entropisi": round(entropy, 3),  # Yuvarlanmış entropi
            "tunelleme_suphesi": is_tunneling,  # Tünelleme şüphesi bayrağı
            "aciklama": (  # Açıklama
                f"Yüksek entropi ({entropy:.2f}) ve olağandışı etiket uzunluğu ({length}) tespit edildi. Olası DNS Tünelleme (dnscat2/iodine) veya veri sızıntısı!"  # Tehdit uyarısı
                if is_tunneling else "Sorgu standart bir alan adı yapısına sahiptir."  # Normal durum
            ),  # Açıklama sonu
        }  # Rapor sonu
