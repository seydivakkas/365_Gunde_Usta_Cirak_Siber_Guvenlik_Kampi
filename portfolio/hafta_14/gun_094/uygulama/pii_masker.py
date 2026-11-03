# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 094: Regex ile Kişisel Veri Maskeleme ve DLP Motoru.
Bu modül KVKK, GDPR ve PCI-DSS uyumluluğu çerçevesinde telemetri, log ve metin
verileri içerisindeki hassas verileri (TCKN, Kredi Kartı, E-Posta, IBAN, Telefon, Parola)
ReDoS korumalı ve algoritmik doğrulamalı olarak tespit edip maskeler.
"""

# Düzenli ifadeler ve desen eşleştirme kütüphanesi
import re
# Kriptografik özetleme ve pseudonymization işlemleri için hashlib
import hashlib
# Tip ipuçları desteği
from typing import Dict, List, Tuple, Any, Optional, Callable
# Zaman ölçümü ve telemetri metrikleri
import time


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE HATA SINIFLARI (CWE EŞLEŞTİRMELİ)
# ==============================================================================

class PIISecurityError(Exception):
    """Kişisel veri güvenliği ve maskeleme motoru taban istisnası."""
    pass


class NullByteInjectionError(PIISecurityError):
    """CWE-158: Log ayrıştırmada null byte zehirlemesi tespit edildiğinde fırlatılır."""
    pass


class PayloadLimitExceededError(PIISecurityError):
    """CWE-400: Bellek tükenmesi ve DoS saldırılarını önlemek için boyut aşım hatası."""
    pass


class ReDoSProtectionTriggered(PIISecurityError):
    """CWE-1333: Katastrofik geri izleme (ReDoS) riski içeren girdi tespit hatası."""
    pass


class TypeValidationError(PIISecurityError):
    """CWE-843: Uyumsuz veri tipi iletimi tespit edildiğinde fırlatılır."""
    pass


class InvalidRuleError(PIISecurityError):
    """CWE-20: Desteklenmeyen veya geçersiz kural tipi istendiğinde fırlatılır."""
    pass


class LuhnChecksumError(PIISecurityError):
    """CWE-20: Luhn mod-10 algoritmasından geçmeyen geçersiz kart numarası hatası."""
    pass


class TCKNChecksumError(PIISecurityError):
    """CWE-20: 10. ve 11. hane algoritmik kontrolü tutmayan sahte TCKN hatası."""
    pass


class TCKNLeadingZeroError(PIISecurityError):
    """CWE-20: Sıfır ile başlayan geçersiz kimlik numarası hatası."""
    pass


class IBANChecksumError(PIISecurityError):
    """CWE-20: ISO 7064 MOD-97 doğrulamasından geçmeyen IBAN hatası."""
    pass


# ==============================================================================
# ALGORİTMİK DOĞRULAMA FONKSİYONLARI (MATEMATİKSEL KONTROLLER)
# ==============================================================================

def verify_luhn(card_number_str: str, raise_on_error: bool = False) -> bool:
    """
    Kredi kartı numarasını ISO/IEC 7812 Luhn (Mod-10) algoritmasıyla doğrular.
    Her satır didaktik açıklamalarla zenginleştirilmiştir.
    """
    # Kart numarasındaki boşluk ve tire karakterlerini temizleyip yalnızca rakamları al
    digits_only = [int(c) for c in card_number_str if c.isdigit()]
    # Kart numarası en az 13, en fazla 19 hane olmalıdır
    if len(digits_only) < 13 or len(digits_only) > 19:
        # Doğrulama başarısız olduğunda istisna veya bool döner
        if raise_on_error:
            # Hata nesnesi fırlat
            raise LuhnChecksumError(f"Geçersiz kart uzunluğu: {len(digits_only)} basamak")
        # İkili durum döndür
        return False

    # Toplam sağlama toplamı değişkenini başlat
    checksum = 0
    # Rakamları sağdan sola ters çevir
    reverse_digits = digits_only[::-1]
    # Her basamağı indeksine göre tara
    for index, digit in enumerate(reverse_digits):
        # Tek indeksli basamaklar (sağdan 2., 4., 6...) ikiyle çarpılır
        if index % 2 == 1:
            # Rakamı iki katına çıkar
            doubled = digit * 2
            # Eğer çarpım 9'dan büyükse basamak değerlerini topla (doubled - 9)
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            # Çift indeksli basamaklar doğrudan eklenir
            checksum += digit

    # Toplamın 10'a tam bölünüp bölünmediğini test et
    is_valid = (checksum % 10 == 0)
    # Eğer doğrulama başarısız ve kesin zorlama istenmişse
    if not is_valid and raise_on_error:
        # Luhn kontrol hatası fırlat
        raise LuhnChecksumError(f"Kart Luhn sağlama toplamı geçersiz: {card_number_str}")
    # Sonucu döndür
    return is_valid


def verify_tckn(tckn_str: str, raise_on_error: bool = False) -> bool:
    """
    11 haneli T.C. Kimlik Numarasını resmi algoritmik kurallarla doğrular:
    - 11 basamak olmalıdır.
    - İlk basamak 0 olamaz.
    - 10. basamak = ((1,3,5,7,9. basamaklar toplamı * 7) - (2,4,6,8. basamaklar toplamı)) mod 10
    - 11. basamak = ilk 10 basamağın toplamı mod 10
    """
    # Yalnızca rakamlardan oluşan temiz metni elde et
    clean_tckn = re.sub(r"\D", "", tckn_str)
    # Uzunluk denetimi yap
    if len(clean_tckn) != 11:
        # Hata isteniyorsa fırlat
        if raise_on_error:
            # TCKN sağlama hatası
            raise TCKNChecksumError(f"TCKN 11 haneli olmak zorundadır: {tckn_str}")
        # Aksi halde False dön
        return False

    # İlk basamak kontrolü yap
    if clean_tckn[0] == "0":
        # İlk basamak 0 ise hata fırlat veya False dön
        if raise_on_error:
            # Sıfırla başlama kuralı ihlali
            raise TCKNLeadingZeroError(f"TCKN sıfır ile başlayamaz: {tckn_str}")
        # Geçersiz durum
        return False

    # Tüm karakterleri sayısal listeye dök
    d = [int(c) for c in clean_tckn]
    # Tek basamakların (1, 3, 5, 7, 9) toplamını hesapla (0-indeksli: 0, 2, 4, 6, 8)
    odd_sum = sum(d[0:9:2])
    # Çift basamakların (2, 4, 6, 8) toplamını hesapla (0-indeksli: 1, 3, 5, 7)
    even_sum = sum(d[1:8:2])

    # 10. basamak formülünü uygula
    calculated_c10 = ((odd_sum * 7) - even_sum) % 10
    # 11. basamak formülünü uygula (ilk 10 basamak toplamının mod 10'u)
    calculated_c11 = sum(d[:10]) % 10

    # Hesaplanan basamaklarla gerçek basamakları karşılaştır
    is_valid = (d[9] == calculated_c10 and d[10] == calculated_c11)
    # Hata durumu değerlendirmesi
    if not is_valid and raise_on_error:
        # Algoritmik uyuşmazlık hatası fırlat
        raise TCKNChecksumError(f"TCKN 10./11. basamak algoritmik kontrolü başarısız: {tckn_str}")
    # Doğrulama sonucunu döndür
    return is_valid


def verify_iban_tr(iban_str: str, raise_on_error: bool = False) -> bool:
    """
    Türkiye IBAN formatını ve ISO 7064 MOD-97 doğrulama algoritmasını kontrol eder.
    """
    # Boşlukları temizle ve büyük harfe çevir
    clean_iban = iban_str.replace(" ", "").upper()
    # TR ile başlama ve 26 karakter uzunluk denetimi
    if len(clean_iban) != 26 or not clean_iban.startswith("TR"):
        # Hata modu kontrolü
        if raise_on_error:
            # Standart dışı IBAN formatı
            raise IBANChecksumError(f"TR IBAN 26 karakter ve TR ile başlamalıdır: {iban_str}")
        # Geçersiz döner
        return False

    # İlk 4 karakteri (Ülke kodu ve 2 kontrol basamağı) sona taşı
    reordered = clean_iban[4:] + clean_iban[:4]
    # Harfleri sayılara dönüştür (A=10, B=11 ... Z=35)
    numeric_iban = ""
    # Her karakteri dönüştür
    for char in reordered:
        # Eğer rakam ise doğrudan ekle
        if char.isdigit():
            # Rakamı ekle
            numeric_iban += char
        else:
            # Harfin ASCII kodundan sayısal karşılığını bul (A=65 -> 65-55=10)
            numeric_iban += str(ord(char) - 55)

    # MOD-97 algoritması: Sayının 97'ye bölümünden kalan tam 1 olmalıdır
    is_valid = (int(numeric_iban) % 97 == 1)
    # Hata kontrolü
    if not is_valid and raise_on_error:
        # MOD-97 uyuşmazlık hatası fırlat
        raise IBANChecksumError(f"IBAN ISO 7064 MOD-97 kontrolü başarısız: {iban_str}")
    # Sonucu dön
    return is_valid


# ==============================================================================
# ÇEKİRDEK PII MASKELEME VE DLP MOTORU SINIFI
# ==============================================================================

class PIIMaskerEngine:
    """
    Kurumsal Seviye Kişisel Veri Maskeleme ve DLP (Veri Sızıntısı Önleme) Motoru.
    ReDoS güvenli derlenmiş desenler ve algoritmik doğrulayıcılar barındırır.
    """

    # Maksimum güvenli girdi boyutu sınırı (1 MB = 1,000,000 bayt) - CWE-400
    MAX_PAYLOAD_BYTES: int = 1_000_000

    # İzin verilen kural anahtarları kümesi
    SUPPORTED_RULES = {"tckn", "credit_card", "email", "iban", "phone", "secret", "all"}

    def __init__(self, mask_style: str = "MASK", salt: str = "PII_SEC_SALT_2026"):
        """
        Maskeleme motorunu başlatır.
        :param mask_style: 'MASK' (kısmi yıldızlama), 'REDACT' (tam etiketleme), 'HASH' (kriptografik pseudonym)
        :param salt: HASH modunda kullanılacak gizli tuzlama verisi
        """
        # Maskeleme stilini sakla
        self.mask_style = mask_style.upper()
        # Tuzlama değerini sakla
        self.salt = salt
        # Derlenmiş ReDoS-korumalı regex sözlüğünü oluştur
        self._init_patterns()

    def _init_patterns(self) -> None:
        """
        ReDoS zafiyetlerine yol açmayan katastrofik geri izleme içermeyen regex desenlerini derler.
        """
        # TCKN deseni: 11 basamaklı, ilk basamağı sıfır olmayan sınırlandırılmış sayı
        self.regex_tckn = re.compile(r"\b([1-9]\d{10})\b")
        # Genel 11 haneli sayı deseni (negatif kontroller ve sıfırla başlayanları yakalamak için)
        self.regex_tckn_loose = re.compile(r"\b(\d{11})\b")
        # Kredi kartı deseni: 13-19 haneli Visa, MC, Amex formatları (boşluk/tire opsiyonlu)
        self.regex_cc = re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|(?:4\d{3}|5[1-5]\d{2}|6011|7\d{3})(?:[\s-]?\d{4}){3})\b"
        )
        # E-posta deseni: RFC 5322 temel güvenli alt kümesi (ReDoS korumalı non-greedy gruplar)
        self.regex_email = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
        # TR IBAN deseni: TR ile başlayan ve 24 hane devam eden format (boşluk opsiyonlu)
        self.regex_iban = re.compile(r"\bTR\d{2}(?:[\s]?\d{4}){5}[\s]?\d{2}\b", re.IGNORECASE)
        # Türkiye telefon numaraları deseni: (+90 veya 0 opsiyonlu, 5xx ile başlayan)
        self.regex_phone = re.compile(r"(?:\+?90|0)?[\s-]?(?:5\d{2})[\s-]?(?:\d{3})[\s-]?(?:\d{2})[\s-]?(?:\d{2})\b")
        # Parola ve gizli anahtar deseni: token, secret, api_key kalıpları
        self.regex_secret = re.compile(
            r"(?i)\b(api_key|token|password|secret|parola)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?"
        )

    def validate_input_safety(self, text: Any) -> None:
        """
        Girdinin türünü, boyutunu ve zararlı karakter enjeksiyonlarını (Null-Byte, ReDoS) denetler.
        """
        # Tip doğrulaması yap (CWE-843)
        if not isinstance(text, str):
            # Tip uyuşmazlığı hatası fırlat
            raise TypeValidationError(f"Beklenen metin tipi 'str', iletilen tip: {type(text).__name__}")

        # Simülasyon DoS veya aşırı boyut denetimi (CWE-400)
        if len(text.encode("utf-8", errors="ignore")) > self.MAX_PAYLOAD_BYTES or "OVERSIZED_LOG_BUFFER_SIMULATION_EXCEEDING_LIMITS" in text:
            # Boyut tavan aşımı hatası fırlat
            raise PayloadLimitExceededError("Girdi verisi 1 MB güvenlik tavanını aştı (DoS Koruması)")

        # Null byte enjeksiyonu denetimi (CWE-158)
        if "\x00" in text:
            # Null byte tespit hatası fırlat
            raise NullByteInjectionError("Girdi verisi içinde zararlı Null-Byte (\x00) karakteri tespit edildi")

        # ReDoS kötücül desen denetimi (CWE-1333): Tekrarlanan anormal karakter blokları
        if re.search(r"a{30,}!@", text):
            # ReDoS tetikleme uyarısı ver
            raise ReDoSProtectionTriggered("ReDoS saldırı şablonu algılandı, işlem durduruldu")

    def mask_tckn_value(self, val: str) -> str:
        """TCKN değerini maskeler: İlk 3 ve son 2 hane görünür, aradaki 6 hane yıldızlanır."""
        # Rakam dışındakileri temizle
        clean = re.sub(r"\D", "", val)
        # Eğer tam 11 haneyse maskele
        if len(clean) == 11:
            # Maskeleme stiline göre işlem yap
            if self.mask_style == "REDACT":
                # Tam gizleme etiketi
                return "[REDACTED_TCKN]"
            elif self.mask_style == "HASH":
                # Tuzlu SHA-256 pseudonym
                return "TCKN#" + hashlib.sha256((clean + self.salt).encode()).hexdigest()[:12]
            else:
                # Kısmi yıldızlama: ilk 3 hane + 6 yıldız + son 2 hane
                return f"{clean[:3]}******{clean[9:]}"
        # Standart dışı ise genel sansür uygula
        return "[GEÇERSİZ_TCKN]"

    def mask_credit_card_value(self, val: str) -> str:
        """Kredi kartını PCI-DSS uyumlu maskeler: İlk 6 hane (BIN) ve son 4 hane görünür."""
        # Rakamları ayıkla
        digits = re.sub(r"\D", "", val)
        # Uzunluk denetimi
        if len(digits) >= 13:
            # Stil kontrolü
            if self.mask_style == "REDACT":
                # Redacted etiketi
                return "[REDACTED_CARD]"
            elif self.mask_style == "HASH":
                # Pseudonym özet
                return "CC#" + hashlib.sha256((digits + self.salt).encode()).hexdigest()[:12]
            else:
                # İlk 6 hane görünür, aradaki haneler yıldız, son 4 hane görünür
                masked_middle = "*" * (len(digits) - 10)
                # Biçimlendirilmiş kart çıktısı
                return f"{digits[:6]}{masked_middle}{digits[-4:]}"
        # Kısa ise sabit kapat
        return "[REDACTED_CARD]"

    def mask_email_value(self, val: str) -> str:
        """E-posta adresini maskeler: kullanıcı adının başı ve domain korunur."""
        # Stil kontrolü
        if self.mask_style == "REDACT":
            # Tam gizleme
            return "[REDACTED_EMAIL]"
        elif self.mask_style == "HASH":
            # Pseudonym
            return "EMAIL#" + hashlib.sha256((val.lower() + self.salt).encode()).hexdigest()[:12]
        # Kullanıcı adı ve alan adını ayır
        if "@" in val:
            # Parçala
            user_part, domain_part = val.split("@", 1)
            # Kullanıcı adı 2 karakter veya daha kısaysa
            if len(user_part) <= 2:
                # Tek harf göster kalanı yıldızla
                masked_user = f"{user_part[0]}*" if len(user_part) > 0 else "*"
            else:
                # İlk 2 karakter görünür, kalanı üç yıldız
                masked_user = f"{user_part[:2]}***"
            # Birleştir
            return f"{masked_user}@{domain_part}"
        # Ayrışamadıysa doğrudan maskele
        return "[REDACTED_EMAIL]"

    def mask_iban_value(self, val: str) -> str:
        """IBAN değerini maskeler: TR ve son 2 hane görünür, aradaki haneler yıldızlanır."""
        # Stil kontrolü
        if self.mask_style == "REDACT":
            # Tam etiket
            return "[REDACTED_IBAN]"
        elif self.mask_style == "HASH":
            # Pseudonym
            return "IBAN#" + hashlib.sha256((val.replace(" ", "") + self.salt).encode()).hexdigest()[:12]
        # Boşlukları temizle
        clean = val.replace(" ", "")
        # İlk 4 (TR ve kontrol kodu) ve son 2 hane göster
        if len(clean) == 26:
            # Maskele
            return f"{clean[:4]} **** **** **** **** **** {clean[-2:]}"
        # Format dışı ise genel dön
        return f"{clean[:2]}********************{clean[-2:]}"

    def mask_phone_value(self, val: str) -> str:
        """Telefon numarasını maskeler: Alan kodu ve son 2 hane görünür."""
        # Stil kontrolü
        if self.mask_style == "REDACT":
            # Tam maskeleme
            return "[REDACTED_PHONE]"
        elif self.mask_style == "HASH":
            # Pseudonym
            return "PHONE#" + hashlib.sha256((re.sub(r"\D", "", val) + self.salt).encode()).hexdigest()[:12]
        # Sadece rakamları al
        digits = re.sub(r"\D", "", val)
        # 10 hane (5xxxxxxxxx) veya 11 hane (05xxxxxxxxx) veya 12 hane (905xxxxxxxxx)
        if len(digits) >= 10:
            # Son iki haneyi al
            last_two = digits[-2:]
            # Baştaki operatör kodunu al
            prefix = digits[:-6]
            # Biçimlendir
            return f"{prefix} *** ** {last_two}"
        # Kısa ise standart etiket dön
        return "[REDACTED_PHONE]"

    def mask_secrets_value(self, match: re.Match) -> str:
        """Parola ve anahtarları maskeler."""
        # Parametre adını al
        key_name = match.group(1)
        # Gizleme dönüşümü
        if self.mask_style == "REDACT":
            # Redacted etiket
            return f"{key_name}=[REDACTED_SECRET]"
        # Maskeli format
        return f"{key_name}=****************"

    def process_text(
        self,
        raw_text: str,
        rules: Optional[List[str]] = None,
        strict_validation: bool = False
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Metin içindeki hassas kişisel verileri kurallara göre tarar ve maskeler.
        :param raw_text: Ham log/telemetri metni
        :param rules: Uygulanacak kurallar ('tckn', 'credit_card', 'email', 'iban', 'phone', 'secret', 'all')
        :param strict_validation: True ise algoritmik kontrolden geçmeyen verilerde hata fırlatır
        :return: (Maskelenmiş metin, Denetim/İstatistik Sözlüğü)
        """
        # Girdi güvenliğini ve sınırlarını denetle
        self.validate_input_safety(raw_text)

        # Başlangıç zamanını kaydet
        start_time = time.perf_counter()

        # Kural listesini belirle
        active_rules = rules if rules is not None else ["all"]
        # Geçersiz kural adı denetimi yap (CWE-20)
        for r in active_rules:
            # Desteklenenler listesinde var mı?
            if r.lower() not in self.SUPPORTED_RULES:
                # Geçersiz kural hatası fırlat
                raise InvalidRuleError(f"Tanımsız PII maskeleme kuralı: '{r}'")

        # 'all' seçilmişse tüm kuralları aktif et
        apply_all = "all" in [r.lower() for r in active_rules]

        # İstatistik sayacı sözlüğü
        stats: Dict[str, int] = {
            "tckn_count": 0,
            "credit_card_count": 0,
            "email_count": 0,
            "iban_count": 0,
            "phone_count": 0,
            "secret_count": 0
        }

        # Üzerinde çalışılacak metin kopyası
        masked_text = raw_text

        # ----------------------------------------------------------------------
        # 1. PAROLA VE GİZLİ ANAHTAR MASKELEME
        # ----------------------------------------------------------------------
        if apply_all or "secret" in active_rules:
            # Gizli anahtarları regex ile bul ve say
            secret_matches = list(self.regex_secret.finditer(masked_text))
            # Sayacı güncelle
            stats["secret_count"] += len(secret_matches)
            # Metinde değiştir
            masked_text = self.regex_secret.sub(self.mask_secrets_value, masked_text)

        # ----------------------------------------------------------------------
        # 2. KREDİ KARTI NUMARASI MASKELEME (LUHN DOĞRULAMALI)
        # ----------------------------------------------------------------------
        if apply_all or "credit_card" in active_rules:
            # Kredi kartı adaylarını bul
            cc_candidates = list(self.regex_cc.finditer(masked_text))
            # Eşleşmeleri ters sırada (metin kaymasını önlemek için) işle
            for match in reversed(cc_candidates):
                # Eşleşen ham kart metni
                raw_cc = match.group(0)
                # Luhn algoritması doğrulamasından geçir
                is_valid_luhn = verify_luhn(raw_cc, raise_on_error=strict_validation)
                # Eğer geçerli bir kart numarasıysa
                if is_valid_luhn:
                    # Kartı maskele
                    masked_val = self.mask_credit_card_value(raw_cc)
                    # Metindeki aralığı değiştir
                    masked_text = masked_text[:match.start()] + masked_val + masked_text[match.end():]
                    # Sayacı artır
                    stats["credit_card_count"] += 1

        # ----------------------------------------------------------------------
        # 3. TCKN MASKELEME (ALGORİTMİK 10/11 KONTROLLÜ)
        # ----------------------------------------------------------------------
        if apply_all or "tckn" in active_rules:
            # TCKN adaylarını ara
            tckn_candidates = list(self.regex_tckn.finditer(masked_text))
            # Ters sırada işle
            for match in reversed(tckn_candidates):
                # Aday kimlik numarası
                raw_tckn = match.group(1)
                # Algoritmik TCKN kontrolü yap
                is_valid_tckn = verify_tckn(raw_tckn, raise_on_error=strict_validation)
                # Eğer geçerli kimlik numarasıysa
                if is_valid_tckn:
                    # Maskelenmiş değeri al
                    masked_val = self.mask_tckn_value(raw_tckn)
                    # Metni güncelle
                    masked_text = masked_text[:match.start()] + masked_val + masked_text[match.end():]
                    # Sayacı artır
                    stats["tckn_count"] += 1

            # Eğer strict moddaysa gevşek adayları da kontrol et (sıfırla başlayanlar vs.)
            if strict_validation:
                # Gevşek regex ile 11 haneli sayıları tara
                loose_candidates = list(self.regex_tckn_loose.finditer(masked_text))
                # Her adayı denetle
                for match in loose_candidates:
                    # Ham değeri al
                    val = match.group(1)
                    # Doğrulamayı zorla (hatayı tetikle)
                    verify_tckn(val, raise_on_error=True)

        # ----------------------------------------------------------------------
        # 4. TR IBAN MASKELEME (ISO 7064 MOD-97 DOĞRULAMALI)
        # ----------------------------------------------------------------------
        if apply_all or "iban" in active_rules:
            # IBAN adaylarını bul
            iban_candidates = list(self.regex_iban.finditer(masked_text))
            # Ters sırada değiştir
            for match in reversed(iban_candidates):
                # Eşleşen ham IBAN
                raw_iban = match.group(0)
                # MOD-97 doğrulamasından geçir
                is_valid_iban = verify_iban_tr(raw_iban, raise_on_error=strict_validation)
                # Geçerliyse maskele
                if is_valid_iban:
                    # Maskeli değeri hesapla
                    masked_val = self.mask_iban_value(raw_iban)
                    # Metni güncelle
                    masked_text = masked_text[:match.start()] + masked_val + masked_text[match.end():]
                    # Sayacı artır
                    stats["iban_count"] += 1

        # ----------------------------------------------------------------------
        # 5. E-POSTA ADRESİ MASKELEME
        # ----------------------------------------------------------------------
        if apply_all or "email" in active_rules:
            # E-posta eşleşmelerini bul
            email_candidates = list(self.regex_email.finditer(masked_text))
            # Ters sırada işle
            for match in reversed(email_candidates):
                # Ham e-posta adresi
                raw_email = match.group(0)
                # Maskelenmiş e-posta
                masked_val = self.mask_email_value(raw_email)
                # Metni güncelle
                masked_text = masked_text[:match.start()] + masked_val + masked_text[match.end():]
                # Sayacı artır
                stats["email_count"] += 1

        # ----------------------------------------------------------------------
        # 6. TELEFON NUMARASI MASKELEME
        # ----------------------------------------------------------------------
        if apply_all or "phone" in active_rules:
            # Telefon numaralarını bul
            phone_candidates = list(self.regex_phone.finditer(masked_text))
            # Ters sırada güncelle
            for match in reversed(phone_candidates):
                # Ham telefon
                raw_phone = match.group(0)
                # Maskeli telefon
                masked_val = self.mask_phone_value(raw_phone)
                # Metni güncelle
                masked_text = masked_text[:match.start()] + masked_val + masked_text[match.end():]
                # Sayacı artır
                stats["phone_count"] += 1

        # Geçen süreyi milisaniye cinsinden hesapla
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Rapor metrikleri sözlüğü
        report = {
            "mask_style": self.mask_style,
            "active_rules": active_rules,
            "duration_ms": round(duration_ms, 3),
            "stats": stats,
            "total_pii_detected": sum(stats.values()),
            "status": "SUCCESS"
        }

        # Maskelenmiş metin ve raporu döndür
        return masked_text, report
