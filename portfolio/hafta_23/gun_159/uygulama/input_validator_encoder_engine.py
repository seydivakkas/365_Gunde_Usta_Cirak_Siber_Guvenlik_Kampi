# -*- coding: utf-8 -*-
"""
Girdi Doğrulama ve Bağlama Duyarlı Çıktı Kodlama Güvenlik Motoru
Hafta 23 / Gün 159 - Aşama 7 (Web Güvenliği)

Bu motor; web uygulamalarında istemciden gelen verileri sınırda kanonikleştirir
(Canonicalization), pozitif izin listesi (Allowlist) prensibiyle sözdizimsel ve
anlamsal olarak doğrular, enjeksiyon (SQLi, XSS, Komut Enjeksiyonu, Path Traversal)
imzalarını tespit eder ve veriyi hedef yorumlayıcıya (HTML Gövdesi, HTML Özniteliği,
JavaScript Değişkeni, URL Parametresi) göre bağlama duyarlı olarak kodlar (Context-Aware Output Encoding).
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import unicodedata
import urllib.parse
import html
import re
import json


class ValidationType(str, Enum):
    """Desteklenen girdi doğrulama veri türleri ve kuralları."""
    # Yalnızca harfler (Unicode harfler ve Türkçe karakterler dahil)
    TEXT_ALPHA = "TextAlpha"
    # Harfler ve rakamlar
    TEXT_ALPHANUMERIC = "TextAlphanumeric"
    # Standart e-posta adresi formatı (RFC 5322)
    EMAIL = "Email"
    # Tam sayı (Integer)
    NUMERIC_INT = "NumericInt"
    # Standart UUIDv4 formatı (36 karakter)
    UUID_V4 = "UuidV4"
    # Güvenli HTTP / HTTPS web adresi
    URL_HTTP_HTTPS = "UrlHttpHttps"
    # ISO 8601 Tarih formatı (YYYY-MM-DD)
    DATE_ISO8601 = "DateIso8601"
    # Güvenli çok satırlı metin (yorum, açıklama - kısıtlı noktalama)
    SAFE_TEXT_MULTILINE = "SafeTextMultiline"


class EncodingContext(str, Enum):
    """Bağlama duyarlı çıktı kodlama hedef yorumlayıcı bağlamları (OWASP C-03)."""
    # 1. HTML Gövdesi Bağlamı: <div>, <p>, <span> içindeki metinler
    HTML_BODY = "HtmlBody"
    # 2. HTML Öznitelik Bağlamı: <input value="...">, <a title="...">
    HTML_ATTRIBUTE = "HtmlAttribute"
    # 3. JavaScript Değişken Bağlamı: <script>var user = '...';</script>
    JAVASCRIPT = "JavaScript"
    # 4. URL Parametresi Bağlamı: /search?q=...
    URL_PARAM = "UrlParam"
    # 5. CSS / Stil Bağlamı: <style>color: ...;</style>
    CSS_STRING = "CssString"


@dataclass
class ValidationResult:
    """Tek bir alanın girdi doğrulama sonucu."""
    # Alan adı
    field_name: str
    # Orijinal ham girdi
    raw_value: str
    # Kanonikleştirilmiş (normalize edilmiş) temiz girdi
    canonical_value: str
    # Doğrulama başarılı mı?
    is_valid: bool
    # Hata mesajı (başarısızsa)
    error_message: Optional[str] = None
    # Tespit edilen güvenlik tehditleri listesi
    detected_threats: List[str] = field(default_factory=list)


@dataclass
class EncodingResult:
    """Çıktı kodlama operasyonunun sonucu."""
    # Kodlanmamış ham veri
    raw_input: str
    # Hedef bağlama göre güvenli kodlanmış çıktı
    encoded_output: str
    # Kullanılan kodlama bağlamı
    context: EncodingContext


class InputValidatorEncoderEngine:
    """Kurumsal Girdi Doğrulama ve Bağlama Duyarlı Çıktı Kodlama Motoru."""

    # Doğrulama regex şablonları
    PATTERNS: Dict[ValidationType, re.Pattern] = {
        ValidationType.TEXT_ALPHA: re.compile(r"^[a-zA-ZçÇğĞıİöÖşŞüÜ\s]+$"),
        ValidationType.TEXT_ALPHANUMERIC: re.compile(r"^[a-zA-Z0-9çÇğĞıİöÖşŞüÜ\s_-]+$"),
        ValidationType.EMAIL: re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
        ValidationType.NUMERIC_INT: re.compile(r"^-?\d+$"),
        ValidationType.UUID_V4: re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"),
        ValidationType.URL_HTTP_HTTPS: re.compile(r"^https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]*)?$"),
        ValidationType.DATE_ISO8601: re.compile(r"^\d{4}-\d{2}-\d{2}$"),
        ValidationType.SAFE_TEXT_MULTILINE: re.compile(r"^[a-zA-Z0-9çÇğĞıİöÖşŞüÜ\s.,!?:;()_#\-\n\r]+$")
    }

    # Bilinen kritik enjeksiyon saldırı imzaları
    THREAT_SIGNATURES: Dict[str, re.Pattern] = {
        "SQL_INJECTION": re.compile(r"(?i)(?:union\s+select|'\s*or\s+.*=|\bdrop\s+table\b|;\s*--|/\*.*\*/|\bexec\s*\(|\bselect\s+.*\s+from\b)"),
        "XSS_SCRIPT": re.compile(r"(?i)(?:<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|alert\(|<iframe|<svg|<img\s+.*src)"),
        "PATH_TRAVERSAL": re.compile(r"(?i)(?:\.\./|\.\.\\|/etc/passwd|c:\\windows|\bboot\.ini\b)"),
        "COMMAND_INJECTION": re.compile(r"(?:;\s*(?:rm|cat|ls|whoami|curl|wget|powershell|cmd)|\|\s*(?:bash|sh)|&&\s*(?:whoami|dir))"),
        "NULL_BYTE_INJECTION": re.compile(r"(?:\x00|%00)")
    }

    def canonicalize(self, raw_input: str) -> str:
        """Girdiyi kanonikleştirir (Unicode NFKC normalizasyonu, recursive URL decode, Null byte temizliği)."""
        if not raw_input:
            return ""
        
        # 1. Adım: Çift URL kodlama (Double Encoding - örn: %252e%252e%252f -> ../) çözme (Maks 3 tur)
        val = raw_input
        for _ in range(3):
            decoded = urllib.parse.unquote(val)
            if decoded == val:
                break
            val = decoded
            
        # 2. Adım: Unicode Uyumluluk Normalizasyonu (NFKC - homoglyph ve görsel gizlemeleri çözer)
        normalized = unicodedata.normalize("NFKC", val)
        
        # 3. Adım: Null byte (\x00) ve tehlikeli ASCII kontrol karakterlerini kaldırma
        cleaned = normalized.replace("\x00", "")
        
        return cleaned.strip()

    def detect_threat_signatures(self, value: str) -> List[str]:
        """Girdi üzerinde bilinen siber saldırı kalıplarını (İmzalarını) tarar."""
        threats: List[str] = []
        for threat_name, pattern in self.THREAT_SIGNATURES.items():
            if pattern.search(value):
                threats.append(threat_name)
        return threats

    def validate_field(
        self,
        field_name: str,
        value: str,
        val_type: ValidationType,
        min_length: int = 0,
        max_length: int = 255,
        custom_pattern: Optional[str] = None
    ) -> ValidationResult:
        """Tek bir alan girdisini kanonikleştirir, tipine ve kısıtlarına göre doğrular."""
        # 1. Kanonikleştirme
        canonical = self.canonicalize(value)

        # 2. Tehdit imzası taraması
        detected_threats = self.detect_threat_signatures(canonical)

        # 3. Uzunluk kontrolleri
        if len(canonical) < min_length:
            return ValidationResult(
                field_name=field_name,
                raw_value=value,
                canonical_value=canonical,
                is_valid=False,
                error_message=f"'{field_name}' alanı en az {min_length} karakter olmalıdır (Mevcut: {len(canonical)}).",
                detected_threats=detected_threats
            )

        if len(canonical) > max_length:
            return ValidationResult(
                field_name=field_name,
                raw_value=value,
                canonical_value=canonical,
                is_valid=False,
                error_message=f"'{field_name}' alanı en fazla {max_length} karakter olmalıdır (Mevcut: {len(canonical)}).",
                detected_threats=detected_threats
            )

        # 4. Tehdit tespiti durumunda derhal reddetme
        if detected_threats:
            return ValidationResult(
                field_name=field_name,
                raw_value=value,
                canonical_value=canonical,
                is_valid=False,
                error_message=f"Güvenlik İhlali: '{field_name}' alanında zararlı enjeksiyon imzası tespit edildi: {', '.join(detected_threats)}",
                detected_threats=detected_threats
            )

        # 5. Tip ve Desen Kontrolü (Allowlist)
        pattern = self.PATTERNS.get(val_type)
        if custom_pattern:
            pattern = re.compile(custom_pattern)

        if pattern and not pattern.match(canonical):
            return ValidationResult(
                field_name=field_name,
                raw_value=value,
                canonical_value=canonical,
                is_valid=False,
                error_message=f"'{field_name}' alanı beklenen format kurallarına uymuyor ({val_type.value}).",
                detected_threats=detected_threats
            )

        # Tüm doğrulamalar başarılı
        return ValidationResult(
            field_name=field_name,
            raw_value=value,
            canonical_value=canonical,
            is_valid=True,
            error_message=None,
            detected_threats=[]
        )

    def encode_for_context(self, value: str, context: EncodingContext) -> str:
        """Veriyi hedef yorumlayıcı bağlamına göre (Context-Aware) güvenli şekilde kodlar."""
        if not value:
            return ""

        # 1. HTML Gövdesi Bağlamı (HTML Body): <div>, <p>, <span> içi
        # Özel HTML meta karakterleri varlık kodlamasına (Entity Encoding) dönüştürülür
        if context == EncodingContext.HTML_BODY:
            # html.escape; &, <, >, ", ' karakterlerini kodlar
            return html.escape(value, quote=True).replace("'", "&#x27;")

        # 2. HTML Öznitelik Bağlamı (HTML Attribute): <input value="...">, <a href="...">
        # Tırnak kaçışını kırmak için alfanümerik olmayan karakterler hex entity kodlanır
        elif context == EncodingContext.HTML_ATTRIBUTE:
            encoded_chars = []
            for ch in value:
                # Güvenli alfanümerik ve temel karakterler
                if ch.isalnum() or ch in ("-", "_", ".", " "):
                    encoded_chars.append(ch)
                else:
                    # &#xHH; hex biçiminde kodlama
                    encoded_chars.append(f"&#x{ord(ch):02X};")
            return "".join(encoded_chars)

        # 3. JavaScript Değişken Bağlamı (JavaScript Context): var user = '...';
        # Betik sınırından çıkışı engellemek için Unicode kaçışı (\uXXXX) uygulanır
        elif context == EncodingContext.JAVASCRIPT:
            encoded_chars = []
            for ch in value:
                if ch.isalnum() or ch in (" ", "_", "-"):
                    encoded_chars.append(ch)
                else:
                    # \u00XX biçiminde 16-bit unicode kaçışı
                    encoded_chars.append(f"\\u{ord(ch):04X}")
            return "".join(encoded_chars)

        # 4. URL Parametresi Bağlamı (URL Parameter Context): ?search=...
        # RFC 3986 standartlarında percent-encoding uygulanır
        elif context == EncodingContext.URL_PARAM:
            return urllib.parse.quote_plus(value)

        # 5. CSS / Stil Bağlamı (CSS String Context)
        elif context == EncodingContext.CSS_STRING:
            encoded_chars = []
            for ch in value:
                if ch.isalnum() or ch in ("-", "_"):
                    encoded_chars.append(ch)
                else:
                    # \HH boşluklu CSS kaçış sözdizimi
                    encoded_chars.append(f"\\{ord(ch):02X} ")
            return "".join(encoded_chars)

        # Tanımsız bağlam durumunda varsayılan güvenli HTML kaçışı
        return html.escape(value, quote=True)

    def validate_and_sanitize_payload(
        self,
        payload: Dict[str, Any],
        schema: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Tüm JSON istek gövdesini şemaya göre denetler ve sonuç karnesi üretir."""
        results: Dict[str, Any] = {}
        all_valid = True
        sanitized_data: Dict[str, Any] = {}
        errors: Dict[str, str] = {}
        all_threats: List[str] = []

        for field_name, rule in schema.items():
            raw_val = payload.get(field_name, "")
            val_type = ValidationType(rule.get("type", "TextAlphanumeric"))
            min_len = rule.get("min_length", 0)
            max_len = rule.get("max_length", 255)
            pattern = rule.get("pattern")

            res = self.validate_field(
                field_name=field_name,
                value=str(raw_val),
                val_type=val_type,
                min_length=min_len,
                max_length=max_len,
                custom_pattern=pattern
            )

            results[field_name] = asdict(res)
            if res.is_valid:
                sanitized_data[field_name] = res.canonical_value
            else:
                all_valid = False
                errors[field_name] = res.error_message or "Doğrulama hatası."
                all_threats.extend(res.detected_threats)

        return {
            "all_valid": all_valid,
            "sanitized_data": sanitized_data,
            "errors": errors,
            "detected_threats": list(set(all_threats)),
            "field_results": results
        }

    def generate_ascii_pipeline(self) -> str:
        """Girdi doğrulama ve çıktı kodlama güvenlik boru hattı ASCII diyagramını üretir."""
        lines = [
            "=" * 86,
            " GİRDİ DOĞRULAMA VE BAĞLAMA DUYARLI ÇIKTI KODLAMA BORU HATTI (GÜN 159)",
            "=" * 86,
            " [ DIŞ DÜNYA / GÜVENİLMEYEN GİRDİ ] (HTTP İstek Parametreleri, JSON Gövdesi, Başlıklar)",
            "                     |",
            "                     v",
            "  +----------------------------------------------------------------------------------+",
            "  | 1. KANONİKLEŞTİRME (Canonicalization)                                            |",
            "  |    - Çift URL Kodlamalarını Çözme (%252e%252e%252f -> ../)                      |",
            "  |    - Unicode NFKC Normalizasyonu (Homoglyph & Görsel Karakter Çözümü)            |",
            "  |    - Null Byte (\\x00, %00) Temizliği                                            |",
            "  +----------------------------------------------------------------------------------+",
            "                     |",
            "                     v",
            "  +----------------------------------------------------------------------------------+",
            "  | 2. GİRDİ DOĞRULAMA (Input Validation - Pozitif İzin Listesi / Allowlist)         |",
            "  |    - Veri Tipi Kontrolü (TextAlpha, Email, NumericInt, UuidV4 vb.)               |",
            "  |    - Uzunluk ve Aralık Sınırlandırması (Min / Max Length)                        |",
            "  |    - Enjeksiyon İmzası Taraması (SQLi, XSS, Path Traversal, Command Injection)   |",
            "  +----------------------------------------------------------------------------------+",
            "                     |",
            "                     v",
            "  +----------------------------------------------------------------------------------+",
            "  | 3. GÜVENLİ İÇ İŞLEME & PARAMETRELİ DEPOLAMA (Prepared Statements / ORM)          |",
            "  +----------------------------------------------------------------------------------+",
            "                     |",
            "                     v",
            "  +----------------------------------------------------------------------------------+",
            "  | 4. BAĞLAMA DUYARLI ÇIKTI KODLAMA (Context-Aware Output Encoding - OWASP C-03)     |",
            "  |    - HTML Body Bağlamı        --> &amp;, &lt;, &gt;, &quot;, &#x27;              |",
            "  |    - HTML Attribute Bağlamı   --> &#xHH; Hex Kodlama                             |",
            "  |    - JavaScript Değişkeni     --> \\u00XX Unicode Kaçışı                         |",
            "  |    - URL Parametresi          --> RFC 3986 Percent-Encoding                      |",
            "  |    - CSS Stili                --> \\HH CSS Kaçışı                                |",
            "  +----------------------------------------------------------------------------------+",
            "                     |",
            "                     v",
            " [ HEDEF YORUMLAYICI / TARAYICI ] (Kod Olarak Çalıştırılamaz, Yalnızca Veri Görünür)",
            "=" * 86
        ]
        return "\n".join(lines)
