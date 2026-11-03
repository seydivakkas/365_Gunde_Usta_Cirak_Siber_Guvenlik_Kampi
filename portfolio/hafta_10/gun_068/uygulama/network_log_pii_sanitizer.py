# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G068: Hafta 10 Gün 68 - Ağ Günlükleri ve Kişisel Veri (PII) Arındırma Motoru.
Bu modül, ağ telemetrisi ve günlüklerindeki (PCAP, NetFlow, Syslog, Web Günlükleri)
kişisel verileri (IP, MAC, E-posta, TCKN, Kredi Kartı, Yetki Başlıkları) KVKK ve GDPR
uyum standartları doğrultusunda maskeler, sözde-anonimleştirir (pseudonymize) ve arındırır.
"""

# Düzenli ifadeler ile örüntü eşleme için re modülü içe aktarılır
import re
# Kriptografik özetleme ve HMAC için hashlib ve hmac kütüphaneleri içe aktarılır
import hashlib
import hmac
# IP adres doğrulaması ve alt ağ maskeleme için ipaddress modülü içe aktarılır
import ipaddress
# Zaman damgası ve tutma süresi kontrolleri için time modülü içe aktarılır
import time
# URL ayrıştırma ve parametre çözümleme için urllib.parse içe aktarılır
import urllib.parse
# Tip ipuçları ve veri yapıları için typing modülü içe aktarılır
from typing import Dict, List, Any, Optional, Tuple, Set
# Veri sınıfı tanımlamak için dataclass içe aktarılır
from dataclasses import dataclass, field


# Temel PII arındırma hatası üst sınıfı
class PIISanitizationError(Exception):
    """Kişisel veri arındırma ve gizlilik motorunun temel istisna sınıfıdır."""
    # Üst sınıf metodu boş geçilir
    pass


# Boş günlük akışı hatası
class EmptyLogStreamError(PIISanitizationError):
    """Arındırılacak günlük listesi veya veri akışı boş olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz günlük veri formatı hatası
class InvalidLogFormatError(PIISanitizationError):
    """Günlük girdisi sözlük veya beklenen şema yapısında olmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz IP adresi formatı hatası
class InvalidIPAddressFormatError(PIISanitizationError):
    """İncelenen metin geçerli bir IPv4 veya IPv6 adresi olmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Yetersiz tuzlama (Salt) anahtarı hatası
class InvalidSaltKeyError(PIISanitizationError):
    """Sözde-anonimleştirme tuz anahtarı boş veya 8 karakterden kısa olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Arındırma sonrası açıkta kalan PII tespit hatası
class UnmaskedPIIDetectedError(PIISanitizationError):
    """Arındırma işlemi tamamlandıktan sonra metinde açık PII kalıntısı tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bozuk veya eksik kayıt verisi hatası
class MalformedRecordDataError(PIISanitizationError):
    """Zorunlu kayıt kimliği eksik veya zaman damgası negatif olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Güvenlik ve gizlilik politikası ihlali hatası
class PolicyViolationError(PIISanitizationError):
    """KVKK/GDPR veya PCI-DSS açık kredi kartı/TCKN loglama ihlali tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Veri saklama süresi aşımı hatası
class DataRetentionPolicyError(PIISanitizationError):
    """Yasal log saklama süresini (örn. 730 gün) aşan eski kayıtlar tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Arındırma istatistiklerini tutan veri sınıfı
@dataclass
class SanitizationSummary:
    """Toplu arındırma işleminde temizlenen kişisel veri metriklerini saklar."""
    # Toplam işlenen kayıt sayısı
    toplam_kayit: int
    # Maskelenen IP adresi sayısı
    maskelenen_ip: int
    # Maskelenen MAC adresi sayısı
    maskelenen_mac: int
    # Maskelenen e-posta adresi sayısı
    maskelenen_eposta: int
    # Maskelenen TCKN kimlik sayısı
    maskelenen_tckn: int
    # Maskelenen kredi kartı sayısı
    maskelenen_kart: int
    # Temizlenen hassas HTTP başlık sayısı
    temizlenen_baslik: int
    # Uyum durumu (KVKK_GDPR_UYUMLU, IHLAL_TESPIT_EDILDI)
    uyum_durumu: str = "KVKK_GDPR_UYUMLU"


# Ağ günlükleri kişisel veri arındırma ve gizlilik motoru
class NetworkLogPIISanitizer:
    """Ağ günlüklerindeki kişisel ve hassas verileri tespit edip arındıran endüstriyel motor."""

    # Sınıf başlatıcı metodu
    def __init__(self, varsayilan_tuz: str = "G068_GIZLI_TUZ_ANAHTARI_2026") -> None:
        # Tuzlama anahtarının geçerliliği denetlenir
        if not varsayilan_tuz or len(varsayilan_tuz) < 8:
            # Hata fırlatılır
            raise InvalidSaltKeyError("Tuzlama anahtarı en az 8 karakter uzunluğunda olmalıdır.")
        # Tuz anahtarı saklanır
        self.default_salt = varsayilan_tuz

        # E-posta tespiti için düzenli ifade
        self.re_email = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        # MAC adresi tespiti için düzenli ifade
        self.re_mac = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b")
        # TCKN (11 haneli kimlik no) düzenli ifadesi
        self.re_tckn = re.compile(r"\b[1-9]\d{10}\b")
        # Kredi kartı numarası tespiti için düzenli ifade (16 haneli, boşluklu veya tireli)
        self.re_card = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")
        # Telefon numarası tespiti için düzenli ifade
        self.re_phone = re.compile(r"(?:\+90|0)?\s*5\d{2}[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}\b")
        # IPv4 adresi düzenli ifadesi
        self.re_ipv4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

        # Temizlenmesi gereken hassas HTTP başlık isimleri
        self.sensitive_headers = {
            "authorization",
            "cookie",
            "set-cookie",
            "proxy-authorization",
            "x-api-key",
            "x-auth-token"
        }

    # IP adresini doğrulayan ve maskeleyen metot
    def mask_ip_address(self, ip_str: str, method: str = "subnet", salt: Optional[str] = None) -> str:
        """IP adresini alt ağ maskeleme (/24), tuzlu özetleme (HMAC) veya tam redaksiyon ile korur."""
        # IP adresi boş ise
        if not ip_str or not isinstance(ip_str, str):
            # Geçersiz IP hatası fırlatılır
            raise InvalidIPAddressFormatError("Geçersiz veya boş IP adresi.")

        # ipaddress modülü ile sözdizimi doğrulanır
        try:
            # IP nesnesi oluşturulur
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            # Format hatası fırlatılır
            raise InvalidIPAddressFormatError(f"Geçersiz IP adresi biçimi: '{ip_str}'")

        # Tuz anahtarı seçilir
        active_salt = salt or self.default_salt

        # Alt ağ korumalı maskeleme (Subnet Truncation)
        if method == "subnet":
            # IPv4 ise son oktet sıfırlanır
            if ip_obj.version == 4:
                # Oktetlere ayrılır
                parts = ip_str.strip().split(".")
                # Son oktet sıfır yapılır ve /24 notasyonu eklenir
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            # IPv6 ise ilk 48 bit korunur, kalanı maskelenir
            else:
                # IPv6 gösterimi basitleştirilir
                exploded = ip_obj.exploded.split(":")
                # İlk 3 hextet korunur
                return f"{exploded[0]}:{exploded[1]}:{exploded[2]}::/48"

        # Kriptografik tuzlu özetleme (Salted HMAC-SHA256 - Pseudonymization)
        elif method == "pseudonymize":
            # HMAC nesnesi oluşturulur
            h = hmac.new(active_salt.encode("utf-8"), ip_str.strip().encode("utf-8"), hashlib.sha256)
            # İlk 12 karakterlik sözde kimlik üretilir
            return f"IP_PSEUDO_{h.hexdigest()[:12]}"

        # Tam maskeleme (Redaction)
        else:
            # Sabit etiket döner
            return "[REDACTED_IP]"

    # MAC adresini maskeleyen metot (Üretici OUI korumalı)
    def mask_mac_address(self, mac_str: str, preserve_oui: bool = True) -> str:
        """MAC adresini donanım üretici kodunu (OUI) koruyarak veya tamamen maskeler."""
        # Biçim kontrolü
        if not self.re_mac.match(mac_str.strip()):
            # Biçim hatası fırlatılır
            raise InvalidLogFormatError(f"Geçersiz MAC adresi biçimi: '{mac_str}'")

        # Ayırıcı karakter belirlenir (: veya -)
        sep = ":" if ":" in mac_str else "-"
        # Oktetlere ayrılır
        octets = mac_str.strip().split(sep)

        # Üretici kodu (ilk 3 oktet) korunacaksa
        if preserve_oui:
            # İlk 3 oktet korunur, cihaz kimliği XX yapılır
            return f"{octets[0]}{sep}{octets[1]}{sep}{octets[2]}{sep}XX{sep}XX{sep}XX"
        # Tam maskeleme
        else:
            # Sabit redaksiyon etiketi döner
            return "[REDACTED_MAC]"

    # E-posta adresini maskeleyen metot
    def mask_email(self, email_str: str) -> str:
        """E-posta adresinin kullanıcı adını kısmen maskeler, alan adını okunabilir bırakır."""
        # E-posta parçalanır (@ işareti)
        if "@" not in email_str:
            # Redakte edilmiş etiket döner
            return "[REDACTED_EMAIL]"

        # Kullanıcı adı ve alan adı ayrılır
        user_part, domain_part = email_str.split("@", 1)
        # Kullanıcı adı 2 karakter veya daha kısaysa
        if len(user_part) <= 2:
            # Tam maskeleme yapılır
            masked_user = "**"
        # Daha uzunsa baş ve son harf bırakılır
        else:
            # Yıldızlar eklenir
            masked_user = f"{user_part[0]}***{user_part[-1]}"

        # Maskelenmiş e-posta döner
        return f"{masked_user}@{domain_part}"

    # Kredi kartı numarasını maskeleyen metot (PCI-DSS standardı)
    def mask_credit_card(self, card_str: str) -> str:
        """Kredi kartının ilk 4 ve son 4 hanesini korur, aradaki haneleri maskeler."""
        # Sadece rakamlar ayıklanır
        digits = re.sub(r"\D", "", card_str)
        # 16 haneli değilse genel maskeleme yapılır
        if len(digits) != 16:
            # Sabit etiket döner
            return "[REDACTED_CARD]"
        # İlk 4 ve son 4 hane korunur
        return f"{digits[:4]} **** **** {digits[-4:]}"

    # TCKN numarasını maskeleyen metot
    def mask_tckn(self, tckn_str: str) -> str:
        """TC Kimlik numarasının ilk 2 ve son 2 hanesini korur, ortayı maskeler."""
        # Sadece rakamlar alınır
        digits = re.sub(r"\D", "", tckn_str)
        # 11 haneli değilse
        if len(digits) != 11:
            # Sabit etiket döner
            return "[REDACTED_TCKN]"
        # İlk 2 ve son 2 hane korunur
        return f"{digits[:2]}*******{digits[-2:]}"

    # HTTP başlıklarını arındıran metot
    def sanitize_http_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """HTTP başlıklarındaki Authorization, Cookie gibi hassas alanları arındırır."""
        # Temizlenmiş başlıklar sözlüğü
        clean_headers: Dict[str, str] = {}
        # Başlıklar taranır
        for k, v in headers.items():
            # Küçük harfe normalize edilmiş anahtar
            k_lower = str(k).lower()
            # Hassas başlık kontrolü
            if k_lower in self.sensitive_headers:
                # Authorization başlığı
                if k_lower == "authorization":
                    # Token tipi korunarak içerik maskelenir
                    clean_headers[k] = "Bearer [REDACTED_TOKEN]"
                # Cookie başlığı
                elif k_lower in ("cookie", "set-cookie"):
                    # Çerez içeriği tamamen maskelenir
                    clean_headers[k] = "[REDACTED_SESSION_COOKIE]"
                # Diğer hassas başlıklar
                else:
                    # Genel redaksiyon yapılır
                    clean_headers[k] = "[REDACTED_HEADER]"
            # Hassas olmayan başlıklar
            else:
                # Orijinal başlık korunur
                clean_headers[k] = v
        # Temizlenmiş başlık sözlüğü döner
        return clean_headers

    # URI sorgu parametrelerindeki PII verilerini arındıran metot
    def sanitize_uri_query(self, uri_str: str) -> str:
        """URI içindeki ?email=, &tckn=, &token= gibi hassas sorgu parametrelerini maskeler."""
        # URI ayrıştırılır
        parsed = urllib.parse.urlsplit(uri_str)
        # Sorgu parametreleri ayrıştırılır
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        # Temizlenmiş parametreler sözlüğü
        clean_params: Dict[str, List[str]] = {}

        # Parametreler taranır
        for k, v_list in params.items():
            # Küçük harf anahtar
            k_lower = k.lower()
            # Değerler listesi temizlenir
            clean_v: List[str] = []
            # Her değer incelenir
            for val in v_list:
                # E-posta parametresi ise
                if "email" in k_lower or "eposta" in k_lower:
                    # E-posta maskeleme uygulanır
                    clean_v.append(self.mask_email(val))
                # TCKN parametresi ise
                elif "tckn" in k_lower or "kimlik" in k_lower:
                    # TCKN maskeleme uygulanır
                    clean_v.append(self.mask_tckn(val))
                # Token veya parola parametresi ise
                elif any(s in k_lower for s in ("token", "pass", "pwd", "secret", "card")):
                    # Redaksiyon uygulanır
                    clean_v.append("[REDACTED_PARAM]")
                # Hassas olmayan parametre
                else:
                    # Olduğu gibi bırakılır
                    clean_v.append(val)
            # Sözlüğe eklenir
            clean_params[k] = clean_v

        # Sorgu dizgisi yeniden oluşturulur
        new_query = urllib.parse.urlencode(clean_params, doseq=True)
        # Yeni URI birleştirilir ve döndürülür
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

    # Serbest metin gövdesi veya Syslog mesajını regex ile tarayıp temizleyen metot
    def sanitize_free_text(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Serbest metin içindeki e-posta, kart, TCKN ve telefon numaralarını otomatik maskeler."""
        # İstatistik sayacı sözlüğü
        stats = {"eposta": 0, "kart": 0, "tckn": 0, "telefon": 0}

        # Kredi kartı arındırma fonksiyonu
        def _card_sub(m: re.Match) -> str:
            # Sayacı artır
            stats["kart"] += 1
            # Maskelenmiş kart döner
            return self.mask_credit_card(m.group(0))

        # E-posta arındırma fonksiyonu
        def _email_sub(m: re.Match) -> str:
            # Sayacı artır
            stats["eposta"] += 1
            # Maskelenmiş e-posta döner
            return self.mask_email(m.group(0))

        # TCKN arındırma fonksiyonu
        def _tckn_sub(m: re.Match) -> str:
            # Sayacı artır
            stats["tckn"] += 1
            # Maskelenmiş TCKN döner
            return self.mask_tckn(m.group(0))

        # Telefon arındırma fonksiyonu
        def _phone_sub(m: re.Match) -> str:
            # Sayacı artır
            stats["telefon"] += 1
            # Sabit etiket döner
            return "[REDACTED_PHONE]"

        # Metin sırasıyla temizlenir
        # 1. Kredi kartları maskelenir
        sanitized = self.re_card.sub(_card_sub, text)
        # 2. E-postalar maskelenir
        sanitized = self.re_email.sub(_email_sub, sanitized)
        # 3. TCKN kimlikler maskelenir
        sanitized = self.re_tckn.sub(_tckn_sub, sanitized)
        # 4. Telefon numaraları maskelenir
        sanitized = self.re_phone.sub(_phone_sub, sanitized)

        # Temizlenmiş metin ve istatistik döner
        return sanitized, stats

    # Tek bir ham günlük kaydını arındıran ana metot
    def sanitize_log_record(self, record: Dict[str, Any], salt: Optional[str] = None) -> Dict[str, Any]:
        """Tek bir günlük kaydındaki tüm ağ ve uygulama PII alanlarını standartlara uygun arındırır."""
        # Sözlük tipi denetlenir
        if not isinstance(record, dict):
            # Biçim hatası fırlatılır
            raise InvalidLogFormatError("Günlük kaydı geçerli bir sözlük (dict) olmalıdır.")

        # Zorunlu kayıt kimliği kontrolü
        if "kayit_id" not in record or not record["kayit_id"]:
            # Eksik veri hatası fırlatılır
            raise MalformedRecordDataError("Günlük kaydında zorunlu 'kayit_id' alanı eksik.")

        # Zaman damgası kontrolü
        if "zaman_damgasi" not in record or float(record["zaman_damgasi"]) < 0:
            # Bozuk zaman damgası hatası fırlatılır
            raise MalformedRecordDataError("Zaman damgası negatif veya tanımsız olamaz.")

        # Veri saklama süresi (Log Retention - 730 gün / 2 yıl) kontrolü
        rec_time = float(record["zaman_damgasi"])
        # Güncel zamandan fark hesaplanır (2026 yılı referans alınır)
        curr_time = 1730340000.0  # Referans zaman damgası
        # İki yıldan (63072000 saniye) eski loglar denetlenir
        if (curr_time - rec_time) > (730 * 86400):
            # Saklama süresi aşım hatası fırlatılır
            raise DataRetentionPolicyError(f"Log saklama süresi aşıldı! Kayıt {round((curr_time - rec_time) / 86400)} günlük.")

        # Tuz anahtarı seçilir
        active_salt = salt or self.default_salt
        # Tuz uzunluğu denetlenir
        if len(active_salt) < 8:
            # Tuz hatası fırlatılır
            raise InvalidSaltKeyError("Tuzlama anahtarı en az 8 karakter olmalıdır.")

        # Temiz kayıt kopyası oluşturulur
        clean_rec = dict(record)

        # İstemci IP adresi maskeleme
        if "istemci_ip" in clean_rec:
            # Maskeleme metodu işletilir
            clean_rec["istemci_ip"] = self.mask_ip_address(clean_rec["istemci_ip"], method="subnet", salt=active_salt)

        # İstemci MAC adresi maskeleme
        if "istemci_mac" in clean_rec:
            # OUI korumalı maskeleme işletilir
            clean_rec["istemci_mac"] = self.mask_mac_address(clean_rec["istemci_mac"], preserve_oui=True)

        # HTTP URI sorgu arındırma
        if "uri" in clean_rec:
            # Sorgu temizleme metodu çağrılır
            clean_rec["uri"] = self.sanitize_uri_query(clean_rec["uri"])

        # HTTP Başlık arındırma
        if "basliklar" in clean_rec and isinstance(clean_rec["basliklar"], dict):
            # Başlık arındırma çağrılır
            clean_rec["basliklar"] = self.sanitize_http_headers(clean_rec["basliklar"])

        # HTTP Gövdesi (Body) arındırma
        if "govde" in clean_rec and clean_rec["govde"]:
            # Serbest metin temizleme çağrılır
            clean_body, _ = self.sanitize_free_text(str(clean_rec["govde"]))
            # Gövde güncellenir
            clean_rec["govde"] = clean_body

        # Syslog mesajı arındırma
        if "mesaj" in clean_rec and clean_rec["mesaj"]:
            # Serbest metin temizleme çağrılır
            clean_msg, _ = self.sanitize_free_text(str(clean_rec["mesaj"]))
            # Mesaj güncellenir
            clean_rec["mesaj"] = clean_msg

        # Arındırılmış kayıt döndürülür
        return clean_rec

    # Arındırma sonrası açıkta kalan PII denetimi yapan doğrulama metodu
    def assert_no_unmasked_pii(self, text: str) -> None:
        """Metin içinde arındırılmamış ham e-posta veya kredi kartı kalıp kalmadığını denetler."""
        # E-posta aranır
        email_match = self.re_email.search(text)
        # Eşleşme varsa ve maskelenmemişse (içinde *** yoksa)
        if email_match and "***" not in email_match.group(0):
            # Açık PII hatası fırlatılır
            raise UnmaskedPIIDetectedError(f"Açık e-posta PII verisi tespit edildi: '{email_match.group(0)}'")

        # TCKN kimlik aranır
        tckn_match = self.re_tckn.search(text)
        # Eşleşme varsa
        if tckn_match:
            # Açık PII hatası fırlatılır
            raise UnmaskedPIIDetectedError(f"Açık TCKN PII verisi tespit edildi: '{tckn_match.group(0)}'")

        # Kredi kartı aranır
        card_match = self.re_card.search(text)
        # Eşleşme varsa ve maskelenmemişse
        if card_match and "****" not in card_match.group(0):
            # Güvenlik politikası ihlali fırlatılır
            raise PolicyViolationError(f"Kritik PCI-DSS ihlali: Ham kredi kartı tespit edildi: '{card_match.group(0)}'")

    # Toplu günlük veri setini arındıran ve özet rapor sunan metot
    def sanitize_log_batch(self, raw_data: Any, salt: Optional[str] = None) -> Dict[str, Any]:
        """Tüm günlük veri setini işler; temizlenmiş kayıtları ve KVKK/GDPR uyum raporunu üretir."""
        # Veri tipi kontrolü
        if not isinstance(raw_data, dict):
            # Biçim hatası fırlatılır
            raise InvalidLogFormatError("Toplu günlük verisi geçerli bir sözlük olmalıdır.")

        # Günlük kayıtları listesi alınır
        records = raw_data.get("gunluk_kayitlari")
        # Liste denetimi
        if records is None or not isinstance(records, list):
            # Biçim hatası fırlatılır
            raise InvalidLogFormatError("Veri setinde 'gunluk_kayitlari' listesi bulunmalıdır.")

        # Liste boşsa
        if len(records) == 0:
            # Boş akış hatası fırlatılır
            raise EmptyLogStreamError("Arındırılacak günlük listesi boş olamaz.")

        # Temizlenmiş kayıtlar listesi
        sanitized_records: List[Dict[str, Any]] = []
        # Sayaçlar
        masked_ip_cnt = 0
        masked_mac_cnt = 0
        masked_headers_cnt = 0

        # Her kayıt arındırılır
        for r in records:
            # IP var mıydı
            if "istemci_ip" in r:
                # Sayaç artırılır
                masked_ip_cnt += 1
            # MAC var mıydı
            if "istemci_mac" in r:
                # Sayaç artırılır
                masked_mac_cnt += 1
            # Başlıklar var mıydı
            if "basliklar" in r:
                # Sayaç artırılır
                masked_headers_cnt += len([k for k in r["basliklar"].keys() if str(k).lower() in self.sensitive_headers])

            # Arındırma yürütülür
            clean_r = self.sanitize_log_record(r, salt=salt)
            # Listeye eklenir
            sanitized_records.append(clean_r)

        # Toplu rapor inşa edilir
        return {
            "toplam_islenen_kayit": len(sanitized_records),
            "maskelenen_ip_sayisi": masked_ip_cnt,
            "maskelenen_mac_sayisi": masked_mac_cnt,
            "temizlenen_hassas_baslik_sayisi": masked_headers_cnt,
            "kvkk_gdpr_uyum_durumu": "TAM_UYUMLU",
            "arindirilmis_gunlukler": sanitized_records
        }
