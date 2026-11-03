# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G057 - HTTP İstek ve Yanıt Yapısı Protokol Analiz ve Güvenlik Denetim Motoru.

Bu modül, RFC 7230 ve RFC 7231 standartlarına tam uyumlu HTTP/1.1 mesajlarının
(İstek Satırı, Durum Satırı, Başlıklar, CRLF sınırlayıcıları ve Gövde) ayrıştırılmasını,
serileştirilmesini, OWASP Güvenlik Başlıkları denetimini, CRLF Enjeksiyonu ve
HTTP Request Smuggling (CL.TE / TE.CL) zafiyet analizlerini gerçekleştirir.
"""

# Düzenli ifadeler ile başlık ve enjeksiyon kalıplarını taramak için re modülü
import re
# URL kod çözme işlemleri (%0d, %0a tespiti) için urllib.parse
import urllib.parse
# Zengin veri modelleri ve tip güvenliği için dataclass ve typing
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any


class HTTPParsingError(Exception):
    """HTTP mesaj yapısı veya sözdizimi ayrıştırma hatalarında fırlatılan özel istisna sınıfı."""
    pass


class HTTPSecurityViolation(Exception):
    """CRLF enjeksiyonu veya Request Smuggling gibi güvenlik ihlallerinde fırlatılan istisna sınıfı."""
    pass


# RFC 7231 Standart HTTP Metotları
HTTP_METHODS_STANDARD: Set[str] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PATCH"
}

# RFC 7231 §4.2.1 Güvenli (Safe) Metotlar (Sunucu durumunu değiştirmeyenler)
HTTP_METHODS_SAFE: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"}

# RFC 7231 §4.2.2 Eşgüçlü (Idempotent) Metotlar (Aynı isteğin tekrarlanması aynı sonucu üretir)
HTTP_METHODS_IDEMPOTENT: Set[str] = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}

# Desteklenen HTTP Sürümleri
SUPPORTED_HTTP_VERSIONS: Set[str] = {"HTTP/1.0", "HTTP/1.1"}

# Standart Durum Kodları ve Gerekçe İfadeleri (Reason Phrases)
STANDARD_STATUS_CODES: Dict[int, str] = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable"
}

# OWASP Tavsiye Edilen Kritik Güvenlik Başlıkları
RECOMMENDED_SECURITY_HEADERS: List[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


@dataclass
class HTTPRequest:
    """RFC 7230 uyumlu HTTP İstek Mesajı Modeli."""
    method: str                                       # İstek Metodu (GET, POST vb.)
    path: str                                         # İstek Yolu / URI (/index.html vb.)
    version: str = "HTTP/1.1"                         # HTTP Sürümü (HTTP/1.1)
    headers: Dict[str, str] = field(default_factory=dict)  # Başlıklar sözlüğü
    body: str = ""                                    # İstek gövdesi

    def __post_init__(self) -> None:
        """Alanların standartlara uygunluğunu sıkı biçimde doğrular."""
        # Metot büyük harfe çevrilir
        self.method = self.method.upper()
        # Metodun standart HTTP metotları arasında olup olmadığı denetlenir
        if self.method not in HTTP_METHODS_STANDARD:
            raise HTTPParsingError(f"Desteklenmeyen veya gecersiz HTTP metodu: '{self.method}'.")
        # Sürüm denetimi yapılır
        if self.version not in SUPPORTED_HTTP_VERSIONS:
            raise HTTPParsingError(
                f"Desteklenmeyen HTTP versiyonu: '{self.version}'. Yalnizca HTTP/1.0 ve HTTP/1.1 desteklenir."
            )
        # RFC 7230 §5.4 gereği HTTP/1.1 isteklerinde Host başlığı zorunludur
        if self.version == "HTTP/1.1":
            # Küçük-büyük harf duyarsız arama yapılır
            has_host = any(k.lower() == "host" for k in self.headers)
            if not has_host:
                raise HTTPParsingError(
                    "RFC 7230 geregi HTTP/1.1 isteklerinde zorunlu 'Host' basligi bulunamadi (400 Bad Request)."
                )

    @property
    def is_safe(self) -> bool:
        """Metodun sunucu durumunu değiştirmeyen 'safe' metot olup olmadığını döner."""
        return self.method in HTTP_METHODS_SAFE

    @property
    def is_idempotent(self) -> bool:
        """Metodun yan etkisiz tekrarlanabilir 'idempotent' metot olup olmadığını döner."""
        return self.method in HTTP_METHODS_IDEMPOTENT

    @property
    def content_length(self) -> int:
        """Content-Length başlığının tamsayı değerini döner."""
        for k, v in self.headers.items():
            if k.lower() == "content-length":
                try:
                    val = int(v)
                    if val < 0:
                        raise HTTPParsingError(f"Gecersiz Content-Length degeri: '{v}'. Sifir veya pozitif bir tamsayi olmalidir.")
                    return val
                except ValueError:
                    raise HTTPParsingError(f"Gecersiz Content-Length formati: '{v}'.")
        return len(self.body.encode("utf-8")) if self.body else 0

    def serialize(self) -> str:
        """HTTP istek nesnesini standart RFC 7230 kablo formatına (wire format) dönüştürür."""
        lines = [f"{self.method} {self.path} {self.version}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        header_block = "\r\n".join(lines) + "\r\n"
        return header_block + self.body

    @classmethod
    def parse(cls, raw_text: str) -> "HTTPRequest":
        """Ham HTTP istek metnini satır satır ayrıştırarak HTTPRequest nesnesi üretir."""
        if not raw_text or not raw_text.strip():
            raise HTTPParsingError("HTTP mesaji bos olamaz.")

        # Başlık ve gövde bloğu çift satır sonu (CRLF CRLF veya LF LF) ile ayrılır
        parts = re.split(r"\r?\n\r?\n", raw_text, maxsplit=1)
        header_text = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        # Satırlar bölünür
        lines = [l for l in re.split(r"\r?\n", header_text) if l]
        if not lines:
            raise HTTPParsingError("HTTP istek baslik satirlari bulunamadi.")

        # İlk satır: İstek Satırı (Request-Line: METHOD PATH VERSION)
        req_line = lines[0].strip()
        req_parts = req_line.split(" ")
        if len(req_parts) != 3:
            raise HTTPParsingError(
                f"Gecersiz HTTP istek satiri: '{req_line}'. Metot, yol ve versiyon 3 parca olmalidir."
            )

        method, path, version = req_parts
        headers: Dict[str, str] = {}

        # 2. satırdan itibaren başlıklar ayrıştırılır (Header: Value)
        for h_line in lines[1:]:
            if ":" not in h_line:
                raise HTTPParsingError(f"Gecersiz baslik satiri (iki nokta ':' eksik): '{h_line}'.")
            name, val = h_line.split(":", 1)
            # Başlık adı ve değeri temizlenir
            clean_name = name.strip()
            clean_val = val.strip()
            # Content-Length negatiflik denetimi yapılır
            if clean_name.lower() == "content-length":
                try:
                    c_val = int(clean_val)
                    if c_val < 0:
                        raise HTTPParsingError(
                            f"Gecersiz Content-Length degeri: '{clean_val}'. Sifir veya pozitif bir tamsayi olmalidir."
                        )
                except ValueError:
                    raise HTTPParsingError(f"Gecersiz Content-Length degeri: '{clean_val}'.")
            headers[clean_name] = clean_val

        return cls(method=method, path=path, version=version, headers=headers, body=body)


@dataclass
class HTTPResponse:
    """RFC 7230 uyumlu HTTP Yanıt Mesajı Modeli."""
    version: str = "HTTP/1.1"                         # HTTP Sürümü
    status_code: int = 200                            # Durum Kodu (200, 404 vb.)
    reason_phrase: str = "OK"                         # Durum Gerekçe İfadesi
    headers: Dict[str, str] = field(default_factory=dict)  # Yanıt başlıkları
    body: str = ""                                    # Yanıt gövdesi

    def __post_init__(self) -> None:
        """Yanıt alanlarını kurallara göre doğrular."""
        if not isinstance(self.status_code, int) or not (100 <= self.status_code <= 599):
            raise HTTPParsingError(
                f"Gecersiz HTTP durum kodu: {self.status_code}. Durum kodu 100-599 araliginda bir tamsayi olmalidir."
            )
        if self.version not in SUPPORTED_HTTP_VERSIONS:
            raise HTTPParsingError(f"Desteklenmeyen HTTP versiyonu: '{self.version}'.")

    def serialize(self) -> str:
        """HTTP yanıt nesnesini standart kablo formatına serileştirir."""
        lines = [f"{self.version} {self.status_code} {self.reason_phrase}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        header_block = "\r\n".join(lines) + "\r\n"
        return header_block + self.body

    @classmethod
    def parse(cls, raw_text: str) -> "HTTPResponse":
        """Ham yanıt metnini ayrıştırarak HTTPResponse nesnesi üretir."""
        if not raw_text or not raw_text.strip():
            raise HTTPParsingError("HTTP mesaji bos olamaz.")

        parts = re.split(r"\r?\n\r?\n", raw_text, maxsplit=1)
        header_text = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = [l for l in re.split(r"\r?\n", header_text) if l]
        if not lines:
            raise HTTPParsingError("HTTP yanit satirlari bulunamadi.")

        # Durum Satırı (Status-Line: VERSION STATUS REASON)
        status_line = lines[0].strip()
        s_parts = status_line.split(" ", 2)
        if len(s_parts) < 2:
            raise HTTPParsingError(
                f"Gecersiz HTTP durum satiri: '{status_line}'. Versiyon ve durum kodu icermelidir."
            )

        version = s_parts[0]
        try:
            status_code = int(s_parts[1])
        except ValueError:
            raise HTTPParsingError(f"Durum kodu tamsayi olmalidir: '{s_parts[1]}'.")

        reason_phrase = s_parts[2] if len(s_parts) > 2 else STANDARD_STATUS_CODES.get(status_code, "")
        headers: Dict[str, str] = {}

        for h_line in lines[1:]:
            if ":" not in h_line:
                raise HTTPParsingError(f"Gecersiz baslik satiri (iki nokta ':' eksik): '{h_line}'.")
            name, val = h_line.split(":", 1)
            headers[name.strip()] = val.strip()

        return cls(version=version, status_code=status_code, reason_phrase=reason_phrase, headers=headers, body=body)


class HTTPSecurityAuditor:
    """
    HTTP İstek ve Yanıt Mesajlarında Güvenlik Açığı ve Sıkılaştırma Denetçisi.
    """
    @classmethod
    def inspect_crlf_injection(cls, request: HTTPRequest) -> None:
        """
        İstek yolunda ve başlıklarında CRLF enjeksiyonu (\r\n veya %0d%0a) taraması yapar.
        """
        # URL kod çözümü yapılarak kontrol edilir
        decoded_path = urllib.parse.unquote(request.path)
        if "\r" in decoded_path or "\n" in decoded_path:
            raise HTTPSecurityViolation(
                f"CRLF Enjeksiyonu Algilandi! Istek yolunda yetkisiz satir sonu tespit edildi: '{request.path}'"
            )

        # Başlık değerleri denetlenir
        for name, val in request.headers.items():
            dec_val = urllib.parse.unquote(val)
            if "\r" in dec_val or "\n" in dec_val or "\r" in name or "\n" in name:
                raise HTTPSecurityViolation(
                    f"CRLF Enjeksiyonu Algilandi! '{name}' basliginda satir sonu baytlari bulundu."
                )

    @classmethod
    def inspect_request_smuggling(cls, request: HTTPRequest) -> None:
        """
        Content-Length ve Transfer-Encoding çatışmasını (CL.TE / TE.CL) denetler.
        """
        has_cl = any(k.lower() == "content-length" for k in request.headers)
        has_te = any(k.lower() == "transfer-encoding" for k in request.headers)

        # RFC 7230 §3.3.3: Her iki başlığın aynı anda bulunması Smuggling riski oluşturur!
        if has_cl and has_te:
            raise HTTPSecurityViolation(
                "HTTP Request Smuggling Tehlikesi: Mesajda hem 'Content-Length' hem de 'Transfer-Encoding' basliklari mevcut!"
            )

    @classmethod
    def audit_response_security_headers(cls, response: HTTPResponse) -> Dict[str, Any]:
        """
        Yanıt başlıklarını OWASP Güvenli Başlıklar standardına göre puanlar ve eksikleri raporlar.
        """
        lower_headers = {k.lower(): (k, v) for k, v in response.headers.items()}
        missing = []
        present = []

        for req_h in RECOMMENDED_SECURITY_HEADERS:
            if req_h.lower() in lower_headers:
                present.append(req_h)
            else:
                missing.append(req_h)

        # Güvenlik puanı hesaplaması (100 üzerinden)
        score = int((len(present) / len(RECOMMENDED_SECURITY_HEADERS)) * 100)

        # Sunucu teknolojisi ifşası (Information Disclosure) denetimi
        banner_leaks = []
        for leak_name in ("server", "x-powered-by", "x-aspnet-version"):
            if leak_name in lower_headers:
                orig_name, val = lower_headers[leak_name]
                banner_leaks.append(f"{orig_name}: {val}")
                # Bilgi ifşası varsa skordan 10 puan düşürülür
                score = max(0, score - 10)

        return {
            "guvenlik_skoru": score,
            "mevcut_guvenlik_basliklari": present,
            "eksik_guvenlik_basliklari": missing,
            "afis_bilgi_sizintisi": banner_leaks,
            "durum": "GUVENLI" if score >= 80 else ("ORTA" if score >= 50 else "ZAYIF")
        }

    @classmethod
    def inspect_risky_methods(cls, request: HTTPRequest) -> List[str]:
        """Güvensiz veya saldırı yüzeyini genişleten metotları listeler."""
        risks = []
        if request.method == "TRACE":
            risks.append("TRACE metodu etkin! XST (Cross-Site Tracing) ile HTTPOnly cerezleri calinabilir.")
        elif request.method in ("PUT", "DELETE"):
            risks.append(f"{request.method} metodu sunucuda dosya olusturma veya silme yetkisine sahiptir.")
        return risks
