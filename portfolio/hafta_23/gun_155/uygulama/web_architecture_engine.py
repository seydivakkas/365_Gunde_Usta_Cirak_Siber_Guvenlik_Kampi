# -*- coding: utf-8 -*-
"""
Web Uygulama Mimarisi ve Güven Sınırı Analiz Motoru
Hafta 23 / Gün 155 - Aşama 7 (Web Güvenliği) Başlangıcı

Bu motor; çok katmanlı web mimarilerinde (İstemci, Reverse Proxy, Uygulama, Veri)
istemci-sunucu güven sınırını (Trust Boundary) modeller. HTTP/HTTPS istek ve
yanıtlarını denetler, güvenlik başlıklarını (HSTS, CSP, X-Frame-Options vb.),
çerez ve oturum güvenlik bayraklarını (Secure, HttpOnly, SameSite) analiz eder,
istemci tarafı varsayım hatalarını (Client-side trust assumptions) saptar ve
otomatik sertleştirme (Hardening) gerçekleştirir.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import re
import math


class ViolationSeverity(str, Enum):
    """Güven sınırı ihlalinin ciddiyet derecesi."""
    # Bilgilendirme ve hafif sertleştirme tavsiyesi
    LOW = "DUSUK"
    # Orta dereceli risk, iyi uygulama ihlali
    MEDIUM = "ORTA"
    # Yüksek risk, doğrudan istismar edilebilir zafiyet
    HIGH = "YUKSEK"
    # Kritik risk, sistem veya oturum güvenliğini doğrudan kıran açık
    CRITICAL = "KRITIK"


@dataclass
class CookieSpec:
    """Tek bir HTTP çerezinin yapılandırma modeli."""
    # Çerez adı
    name: str
    # Çerez değeri
    value: str
    # Çerezin geçerli olduğu alan adı
    domain: Optional[str] = None
    # Çerezin geçerli olduğu dizin yolu
    path: str = "/"
    # Yalnızca HTTPS üzerinden iletilme zorunluluğu bayrağı
    secure: bool = False
    # JavaScript tarafından erişilmesini engelleyen bayrak (XSS önlemi)
    httponly: bool = False
    # Siteler arası isteklerde çerez gönderim kısıtlaması (CSRF önlemi)
    samesite: str = "None"  # "Strict", "Lax", "None"
    # Çerez yaşam süresi (saniye)
    max_age: Optional[int] = None


@dataclass
class HttpRequest:
    """İstemciden gelen HTTP istek modeli."""
    # HTTP istek yöntemi (GET, POST, PUT, DELETE vb.)
    method: str
    # İstek yapılan URI yolu (/api/v1/checkout vb.)
    path: str
    # İstek başlıkları sözlüğü
    headers: Dict[str, str] = field(default_factory=dict)
    # URL sorgu parametreleri sözlüğü
    query_params: Dict[str, str] = field(default_factory=dict)
    # İstek gövdesi (JSON veya form verisi)
    body: Dict[str, Any] = field(default_factory=dict)
    # İstek yapan istemcinin IP adresi
    client_ip: str = "127.0.0.1"
    # İsteğin TLS/HTTPS üzerinden gelip gelmediği
    is_https: bool = True
    # İstekle birlikte taşınan çerezler sözlüğü
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class HttpResponse:
    """Sunucudan dönen HTTP yanıt modeli."""
    # HTTP yanıt durum kodu (200, 302, 403 vb.)
    status_code: int = 200
    # Yanıt başlıkları sözlüğü
    headers: Dict[str, str] = field(default_factory=dict)
    # Yanıt gövdesi
    body: Any = ""
    # Sunucunun ayarladığı Set-Cookie listesi
    cookies: List[CookieSpec] = field(default_factory=list)


@dataclass
class TrustBoundaryViolation:
    """İstemci-sunucu güven sınırında tespit edilen kural ihlali."""
    # İhlalin gerçekleştiği mimari sınır (örn. "Client-to-Server", "API-Gateway")
    boundary: str
    # İhlal kategorisi (örn. "InsecureTransport", "ClientSideTrust", "MissingHeader")
    violation_type: str
    # İhlal ciddiyet derecesi
    severity: ViolationSeverity
    # İhlalin detaylı teknik açıklaması
    description: str
    # Güvenlik açığını gidermek için uygulanacak tavsiye
    remediation: str


@dataclass
class SecurityHeaderAudit:
    """HTTP yanıt başlıklarının güvenlik denetim karnesi."""
    # HSTS başlığı durumu
    hsts_present: bool = False
    hsts_valid: bool = False
    # CSP başlığı durumu
    csp_present: bool = False
    csp_has_unsafe_inline: bool = False
    # X-Frame-Options durumu
    x_frame_options_present: bool = False
    # X-Content-Type-Options durumu
    x_content_type_options_present: bool = False
    # Referrer-Policy durumu
    referrer_policy_present: bool = False
    # Permissions-Policy durumu
    permissions_policy_present: bool = False
    # Bilgi ifşası yapan başlıklar (Server, X-Powered-By vb.)
    disclosed_server_tokens: List[str] = field(default_factory=list)
    # Başlık güvenlik skoru (0.0 - 100.0)
    score: float = 0.0


@dataclass
class CookieSecurityAudit:
    """Tek bir çerezin güvenlik denetim çıktısı."""
    # Çerez adı
    cookie_name: str
    # Oturum çerezi mi
    is_session_cookie: bool
    # Secure bayrağı geçerli mi
    secure_valid: bool
    # HttpOnly bayrağı geçerli mi
    httponly_valid: bool
    # SameSite bayrağı güvenli mi (Lax veya Strict)
    samesite_valid: bool
    # Token entropi seviyesi (bit cinsinden tahmin)
    entropy_bits: float
    # Çerez güvenlik puanı (0.0 - 100.0)
    cookie_score: float
    # Çerez bulguları listesi
    findings: List[str] = field(default_factory=list)


@dataclass
class WebAuditReport:
    """Kapsamlı Web Mimarisi ve Güven Sınırı Denetim Raporu."""
    # İstek tarafında tespit edilen güven sınırı ihlalleri
    request_violations: List[TrustBoundaryViolation]
    # Yanıt başlıkları denetim sonucu
    header_audit: SecurityHeaderAudit
    # Çerezler denetim sonuçları listesi
    cookie_audits: List[CookieSecurityAudit]
    # Genel mimari güvenlik puanı (0.0 - 100.0)
    overall_score: float
    # Sistem güvenli mi (Skor >= 85 ve kritik ihlal yoksa True)
    is_secure: bool
    # Yönetici özeti metni
    summary: str


class WebTrustBoundaryEngine:
    """Web uygulama mimarisi ve güven sınırı analiz ve sertleştirme motoru."""

    # Hassas parametre isimleri listesi (URL'de taşınması yasak olanlar)
    SENSITIVE_PARAM_NAMES: Set[str] = {
        "password", "pass", "pwd", "token", "api_key", "apikey",
        "secret", "auth", "session_id", "access_token"
    }

    # İstemciden asla güvenilmemesi gereken yetki/fiyat alanları
    CLIENT_UNTRUSTED_FIELDS: Set[str] = {
        "role", "is_admin", "admin", "privilege", "permissions",
        "price", "unit_price", "discount", "total_amount", "balance"
    }

    # Bilgi ifşa eden tehlikeli sunucu başlıkları
    DISCLOSURE_HEADERS: Set[str] = {
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-runtime"
    }

    def audit_request(self, request: HttpRequest) -> List[TrustBoundaryViolation]:
        """İstemciden gelen HTTP isteğini güven sınırları açısından denetler."""
        # Tespit edilen ihlaller listesi başlatılır
        violations: List[TrustBoundaryViolation] = []

        # 1. Taşıma Katmanı Güvenliği Kontrolü (TLS / HTTPS)
        if not request.is_https:
            # Düz metin HTTP iletimi kritik ihlaldir
            violations.append(TrustBoundaryViolation(
                boundary="Client-to-Proxy",
                violation_type="InsecureTransport",
                severity=ViolationSeverity.CRITICAL,
                description="İstek şifresiz HTTP protokolü üzerinden iletilmiş; ortadaki adam (MitM) saldırılarına açıktır.",
                remediation="Tüm HTTP trafiğini 301 yönlendirmesi ile derhal HTTPS'e (TLS 1.3) zorlayın."
            ))

        # 2. HTTP Yöntemi (Method) Manipülasyon Kontrolü
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        # Yöntem büyük harfe çevrilmeden kontrol edilir (Method Tampering tespiti)
        if request.method not in allowed_methods:
            # Standart dışı veya tehlikeli yöntem tespiti
            violations.append(TrustBoundaryViolation(
                boundary="ReverseProxy-to-Application",
                violation_type="InvalidHttpMethod",
                severity=ViolationSeverity.HIGH,
                description=f"İzin verilmeyen veya şüpheli HTTP yöntemi tespit edildi: '{request.method}'.",
                remediation="WAF ve Reverse Proxy seviyesinde yalnızca RFC uyumlu izin verilen yöntemleri beyaz listeye alın."
            ))

        # 3. URL Yolu Üzerinde Dizin Geçişi (Path Traversal) Kontrolü
        decoded_path = request.path.lower()
        if "../" in decoded_path or "..\\" in decoded_path or "%2e%2e%2f" in decoded_path:
            # Dizin geçişi girişimi
            violations.append(TrustBoundaryViolation(
                boundary="Client-to-Application",
                violation_type="PathTraversalAttempt",
                severity=ViolationSeverity.CRITICAL,
                description=f"İstek yolunda potansiyel dizin atlama (Path Traversal) kalıbı saptandı: '{request.path}'.",
                remediation="URI kanonikleştirme (canonicalization) uygulayın ve dosya sistemi yollarını kullanıcı girdisinden izole edin."
            ))

        # 4. URL Sorgu Parametrelerinde Hassas Veri İfşası Kontrolü
        for param in request.query_params.keys():
            # Parametre adı küçük harfe çevrilerek kontrol edilir
            if param.lower() in self.SENSITIVE_PARAM_NAMES:
                # URL'de parola veya token taşınması
                violations.append(TrustBoundaryViolation(
                    boundary="Client-to-Server",
                    violation_type="SensitiveDataInQueryString",
                    severity=ViolationSeverity.HIGH,
                    description=f"URL sorgu parametrelerinde hassas kimlik bilgisi tespit edildi: '{param}' (Erişim günlüklerine ve Referrer başlıklarına sızar).",
                    remediation="Hassas kimlik doğrulama verilerini asla GET URL parametrelerinde taşımayın; POST gövdesinde veya Authorization başlığında iletin."
                ))

        # 5. İstemci Tarafı Güven Varsayımı (Client-Side Trust Assumption) Kontrolü
        # Kullanıcının gövde veya parametrelerde rol/fiyat manipüle etmeye çalışması
        all_inputs = {}
        all_inputs.update(request.query_params)
        if isinstance(request.body, dict):
            all_inputs.update(request.body)

        for field_name, value in all_inputs.items():
            clean_field = field_name.lower().strip()
            if clean_field in self.CLIENT_UNTRUSTED_FIELDS:
                # İstemci rol veya fiyat belirlemeye çalışıyor
                violations.append(TrustBoundaryViolation(
                    boundary="Client-to-Database",
                    violation_type="ClientSideTrustAssumption",
                    severity=ViolationSeverity.CRITICAL,
                    description=f"İstemcinin sunucuya doğrudan güvenilmeyen yetki/fiyat verisi gönderdiği tespit edildi: '{field_name}={value}'.",
                    remediation="Fiyat, rol ve yetkilendirme kararlarını daima sunucu tarafındaki güvenli veritabanından sorgulayın; istemci girdisine asla güvenmeyin."
                ))

        # İhlaller listesi döndürülür
        return violations

    def audit_response(self, response: HttpResponse) -> SecurityHeaderAudit:
        """Sunucunun döndürdüğü HTTP yanıtını güvenlik başlıkları açısından denetler."""
        # Başlıklar küçük harfe dönüştürülerek sözlüğe alınır
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        audit = SecurityHeaderAudit()
        score = 100.0

        # 1. HSTS (Strict-Transport-Security) Denetimi
        if "strict-transport-security" in headers_lower:
            audit.hsts_present = True
            hsts_val = headers_lower["strict-transport-security"].lower()
            # En az 1 yıl (31536000 sn) ve includeSubDomains var mı
            if "max-age=" in hsts_val and "includesubdomains" in hsts_val:
                # Süre ayrıştırılır
                match = re.search(r"max-age=(\d+)", hsts_val)
                if match and int(match.group(1)) >= 31536000:
                    audit.hsts_valid = True
                else:
                    score -= 10.0
            else:
                score -= 10.0
        else:
            score -= 25.0

        # 2. CSP (Content-Security-Policy) Denetimi
        if "content-security-policy" in headers_lower:
            audit.csp_present = True
            csp_val = headers_lower["content-security-policy"].lower()
            # Güvensiz inline komut dosyası izni var mı
            if "'unsafe-inline'" in csp_val and "nonce-" not in csp_val:
                audit.csp_has_unsafe_inline = True
                score -= 15.0
        else:
            score -= 25.0

        # 3. X-Frame-Options Denetimi (Clickjacking Koruması)
        if "x-frame-options" in headers_lower:
            xfo_val = headers_lower["x-frame-options"].upper()
            if xfo_val in ("DENY", "SAMEORIGIN"):
                audit.x_frame_options_present = True
            else:
                score -= 10.0
        else:
            score -= 15.0

        # 4. X-Content-Type-Options Denetimi (MIME-Sniffing Koruması)
        if "x-content-type-options" in headers_lower:
            if headers_lower["x-content-type-options"].lower() == "nosniff":
                audit.x_content_type_options_present = True
            else:
                score -= 5.0
        else:
            score -= 10.0

        # 5. Referrer-Policy Denetimi
        if "referrer-policy" in headers_lower:
            audit.referrer_policy_present = True
        else:
            score -= 10.0

        # 6. Permissions-Policy Denetimi
        if "permissions-policy" in headers_lower:
            audit.permissions_policy_present = True
        else:
            score -= 5.0

        # 7. Bilgi İfşası Yapan Sunucu Başlıkları Denetimi
        for h_name, h_val in headers_lower.items():
            if h_name in self.DISCLOSURE_HEADERS:
                audit.disclosed_server_tokens.append(f"{h_name}: {h_val}")
                score -= 10.0

        # Skor sınırlandırılır ve kaydedilir
        audit.score = round(max(0.0, min(100.0, score)), 1)
        return audit

    def audit_cookies(self, cookies: List[CookieSpec], is_https: bool) -> List[CookieSecurityAudit]:
        """Çerezlerin güvenlik bayraklarını ve entropisini denetler."""
        audits: List[CookieSecurityAudit] = []

        for cookie in cookies:
            findings: List[str] = []
            score = 100.0
            
            # Oturum çerezi mi (session, auth, token, jwt içerenler)
            is_sess = any(sub in cookie.name.lower() for sub in ("session", "auth", "token", "jwt", "id", "sid"))

            # 1. Secure Bayrağı Denetimi
            sec_valid = cookie.secure
            if not cookie.secure:
                score -= 35.0
                findings.append("Secure bayrağı eksik; çerez düz metin HTTP üzerinden çalınabilir.")
            elif not is_https:
                score -= 20.0
                findings.append("Secure bayrağı set edilmiş ancak bağlantı HTTPS değil.")

            # 2. HttpOnly Bayrağı Denetimi
            http_valid = cookie.httponly
            if is_sess and not cookie.httponly:
                score -= 35.0
                findings.append("HttpOnly bayrağı eksik; XSS durumunda JavaScript çerezi çalabilir (document.cookie).")
            elif not cookie.httponly:
                score -= 10.0

            # 3. SameSite Bayrağı Denetimi
            same_valid = cookie.samesite in ("Strict", "Lax")
            if cookie.samesite == "None":
                score -= 20.0
                findings.append("SameSite=None olarak ayarlanmış; siteler arası istek sahteciliğine (CSRF) açıktır.")
            elif cookie.samesite not in ("Strict", "Lax"):
                score -= 20.0
                findings.append(f"Geçersiz veya eksik SameSite değeri: '{cookie.samesite}'.")

            # 4. Entropi Analizi (Oturum token uzunluğu ve rastgeleliği)
            entropy = len(cookie.value) * 4.0  # Hex veya Base64 varsayımıyla yaklaşık bit hesabı
            if is_sess and len(cookie.value) < 16:
                score -= 20.0
                findings.append(f"Oturum belirteci çok kısa ({len(cookie.value)} karakter); tahmin edilebilir kaba kuvvet açığı.")

            final_cookie_score = round(max(0.0, min(100.0, score)), 1)
            audits.append(CookieSecurityAudit(
                cookie_name=cookie.name,
                is_session_cookie=is_sess,
                secure_valid=sec_valid,
                httponly_valid=http_valid,
                samesite_valid=same_valid,
                entropy_bits=entropy,
                cookie_score=final_cookie_score,
                findings=findings,
            ))

        return audits

    def full_audit(self, request: HttpRequest, response: HttpResponse) -> WebAuditReport:
        """İstek ve yanıtı bütüncül olarak analiz edip genel denetim raporu üretir."""
        req_violations = self.audit_request(request)
        header_audit = self.audit_response(response)
        cookie_audits = self.audit_cookies(response.cookies, request.is_https)

        # Genel puan hesabı (Başlık skoru %40, İstek ihlalleri cezası %40, Çerezler %20)
        # İstek ihlallerinden ceza hesaplanır
        req_penalty = 0.0
        for v in req_violations:
            if v.severity == ViolationSeverity.CRITICAL:
                req_penalty += 30.0
            elif v.severity == ViolationSeverity.HIGH:
                req_penalty += 15.0
            elif v.severity == ViolationSeverity.MEDIUM:
                req_penalty += 10.0
            else:
                req_penalty += 5.0
        req_score = max(0.0, 100.0 - req_penalty)

        # Çerez ortalama puanı
        if cookie_audits:
            cookie_score_avg = sum(c.cookie_score for c in cookie_audits) / len(cookie_audits)
        else:
            cookie_score_avg = 100.0

        # Ağırlıklı genel puan
        overall_score = round(
            (header_audit.score * 0.40) +
            (req_score * 0.40) +
            (cookie_score_avg * 0.20),
            1
        )

        has_critical = any(v.severity == ViolationSeverity.CRITICAL for v in req_violations)
        is_secure = (overall_score >= 85.0) and not has_critical

        if is_secure:
            summary = "Web mimarisi ve güven sınırları kurumsal güvenlik standartlarına uygundur (PASS)."
        else:
            summary = (
                f"Web mimarisinde güvenlik açıkları saptandı (Skor: {overall_score}/100). "
                f"{len(req_violations)} adet istek ihlali ve eksik güvenlik başlıkları tespit edildi."
            )

        return WebAuditReport(
            request_violations=req_violations,
            header_audit=header_audit,
            cookie_audits=cookie_audits,
            overall_score=overall_score,
            is_secure=is_secure,
            summary=summary,
        )

    def harden_response(self, response: HttpResponse) -> HttpResponse:
        """Güvensiz bir HTTP yanıtını en iyi pratiklerle otomatik olarak sertleştirir."""
        # Yanıt başlıkları klonlanır
        hardened_headers = dict(response.headers)

        # 1. Bilgi ifşa eden başlıklar temizlenir
        for h in list(hardened_headers.keys()):
            if h.lower() in self.DISCLOSURE_HEADERS:
                del hardened_headers[h]

        # 2. Güvenlik başlıkları enjekte edilir
        hardened_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        hardened_headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
        hardened_headers["X-Frame-Options"] = "DENY"
        hardened_headers["X-Content-Type-Options"] = "nosniff"
        hardened_headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        hardened_headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        # 3. Çerezler sertleştirilir
        hardened_cookies: List[CookieSpec] = []
        for c in response.cookies:
            hardened_cookies.append(CookieSpec(
                name=c.name,
                value=c.value,
                domain=c.domain,
                path=c.path,
                secure=True,          # Daima HTTPS zorunlu
                httponly=True,        # JavaScript erişimi yasak
                samesite="Lax",       # CSRF koruması
                max_age=c.max_age,
            ))

        return HttpResponse(
            status_code=response.status_code,
            headers=hardened_headers,
            body=response.body,
            cookies=hardened_cookies,
        )

    def generate_nginx_security_config(self) -> str:
        """Tüm bu kuralları uygulayan örnek kurumsal Nginx güvenlik yapılandırması üretir."""
        lines = [
            "# ==============================================================================",
            "# KURUMSAL GÜVENLİ NGINX YAPILANDIRMASI (HAFTA 23 - GÜN 155)",
            "# ==============================================================================",
            "",
            "# 1. Bilgi İfşasını Engelle",
            "server_tokens off;",
            "more_clear_headers 'Server' 'X-Powered-By';",
            "",
            "# 2. Zorunlu Güvenlik Başlıkları",
            "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\" always;",
            "add_header X-Frame-Options 'DENY' always;",
            "add_header X-Content-Type-Options 'nosniff' always;",
            "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
            "add_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;",
            "",
            "# 3. İzin Verilmeyen HTTP Yöntemlerini Engelle",
            "if ($request_method !~ ^(GET|POST|PUT|DELETE|HEAD|OPTIONS)$ ) {",
            "    return 405;",
            "}",
            "",
            "# 4. Hassas Dizin ve Dosyalara Erişimi Kapat",
            "location ~ /\\.(?!well-known).* {",
            "    deny all;",
            "    access_log off;",
            "    log_not_found off;",
            "}",
            "",
            "# ==============================================================================",
        ]
        return "\n".join(lines)
