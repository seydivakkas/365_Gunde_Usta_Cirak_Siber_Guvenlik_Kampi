# -*- coding: utf-8 -*-
"""
HTTP Cookies ve Güvenlik Bayrakları Denetim ve Sertleştirme Motoru
Hafta 23 / Gün 157 - Aşama 7 (Web Güvenliği)

Bu motor; kurumsal web uygulamaları ve API servislerinin Set-Cookie başlıklarını,
oturum çerezlerini ve durum belirteçlerini RFC 6265bis, OWASP ASVS ve modern
tarayıcı güvenlik standartlarına (Secure, HttpOnly, SameSite, __Host-, __Secure-)
göre denetler, güvenlik puanı hesaplar ve zafiyetli çerezleri otomatik sertleştirir.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import re
import json


class SameSitePolicy(str, Enum):
    """SameSite çerez politikası seviyeleri (RFC 6265bis)."""
    # Strict: Çerez sadece kaynak sitenin kendi isteklerinde gönderilir; CSRF'e karşı en katı koruma
    STRICT = "Strict"
    # Lax: Güvenli üst düzey gezinmelerde (GET linkleri) çerez taşınır; kullanıcı deneyimi ve güvenlik dengesi
    LAX = "Lax"
    # None: Çerez üçüncü taraf isteklerinde taşınır; kesinlikle Secure bayrağıyla birlikte kullanılmalıdır
    NONE = "None"
    # Eksik veya tanımsız SameSite bayrağı
    MISSING = "Missing"


class CookieType(str, Enum):
    """Çerezin taşındığı amaç ve hassasiyet sınıflandırması."""
    # Kimlik doğrulama ve oturum çerezi (en yüksek hassasiyet)
    SESSION_AUTH = "SessionAuth"
    # CSRF koruma belirteci çerezi
    CSRF_TOKEN = "CsrfToken"
    # Kullanıcı tercihleri ve tema ayarları (düşük hassasiyet)
    PREFERENCE = "Preference"
    # Analitik ve telemetri takip çerezi
    TRACKING = "Tracking"


class CookiePrefix(str, Enum):
    """RFC 6265bis güvenlik önekleri standardı."""
    # __Host-: Secure olmalı, Path=/ olmalı ve Domain özniteliği İÇERMEMELİDİR
    HOST = "__Host-"
    # __Secure-: Yalnızca HTTPS üzerinden ve Secure bayrağı ile gönderilebilir
    SECURE = "__Secure-"
    # Herhangi bir standart önek kullanılmamış
    NONE = "None"


@dataclass
class HttpCookie:
    """HTTP çerez nesnesi ve tüm güvenlik öznitelikleri."""
    # Çerez adı
    name: str
    # Çerez değeri (token, session id vb.)
    value: str
    # Secure bayrağı: Çerezin yalnızca TLS/HTTPS üzerinden iletilmesini zorunlu kılar
    secure: bool = False
    # HttpOnly bayrağı: JavaScript (document.cookie) erişimini engelleyerek XSS hırsızlığını önler
    http_only: bool = False
    # SameSite bayrağı: Siteler arası istek sahteciliği (CSRF) koruması sağlar
    same_site: SameSitePolicy = SameSitePolicy.MISSING
    # Domain alanı: Çerezin geçerli olduğu etki alanı (boş ise yalnızca mevcut host)
    domain: Optional[str] = None
    # Path alanı: Çerezin geçerli olduğu URL alt yolu
    path: str = "/"
    # Max-Age (saniye cinsinden ömür)
    max_age: Optional[int] = None
    # Oturum çerezi mi? (Tarayıcı kapanınca silinen geçici çerez)
    is_session_cookie: bool = False
    # Çerezin işlevsel türü
    cookie_type: CookieType = CookieType.SESSION_AUTH
    # Çerez değerinin opak veya şifrelenmiş olup olmadığı
    is_encrypted_or_opaque: bool = True

    def detect_prefix(self) -> CookiePrefix:
        """Çerez adındaki RFC 6265bis önekini tespit eder."""
        # __Host- öneki kontrolü
        if self.name.startswith("__Host-"):
            return CookiePrefix.HOST
        # __Secure- öneki kontrolü
        elif self.name.startswith("__Secure-"):
            return CookiePrefix.SECURE
        # Önek bulunamadı
        return CookiePrefix.NONE

    def to_set_cookie_header(self) -> str:
        """Çerezi geçerli bir HTTP 'Set-Cookie' yanıt başlığı metnine dönüştürür."""
        # İsim ve değer ikilisi
        parts = [f"{self.name}={self.value}"]
        # Path özniteliği
        if self.path:
            parts.append(f"Path={self.path}")
        # Domain özniteliği (belirtilmişse)
        if self.domain:
            parts.append(f"Domain={self.domain}")
        # Max-Age özniteliği
        if self.max_age is not None and not self.is_session_cookie:
            parts.append(f"Max-Age={self.max_age}")
        # Secure bayrağı
        if self.secure:
            parts.append("Secure")
        # HttpOnly bayrağı
        if self.http_only:
            parts.append("HttpOnly")
        # SameSite bayrağı
        if self.same_site != SameSitePolicy.MISSING:
            parts.append(f"SameSite={self.same_site.value}")
        # Parçaları noktalı virgül ile birleştirme
        return "; ".join(parts)

    @classmethod
    def parse_set_cookie_header(cls, header_value: str, cookie_type: CookieType = CookieType.SESSION_AUTH) -> "HttpCookie":
        """Set-Cookie başlık metnini ayrıştırarak HttpCookie nesnesine dönüştürür."""
        # Parçaları noktalı virgülle ayırma
        tokens = [t.strip() for t in header_value.split(";") if t.strip()]
        if not tokens:
            raise ValueError("Boş veya geçersiz Set-Cookie başlığı.")

        # İlk token isim=değer ikilisidir
        first_token = tokens[0]
        if "=" not in first_token:
            raise ValueError(f"Geçersiz çerez isim/değer yapısı: {first_token}")
        name, value = first_token.split("=", 1)

        # Varsayılan değerler
        secure = False
        http_only = False
        same_site = SameSitePolicy.MISSING
        domain = None
        path = "/"
        max_age = None

        # Kalan öznitelikleri ayrıştırma
        for token in tokens[1:]:
            lower_token = token.lower()
            if lower_token == "secure":
                secure = True
            elif lower_token == "httponly":
                http_only = True
            elif lower_token.startswith("samesite="):
                s_val = token.split("=", 1)[1].strip()
                if s_val.lower() == "strict":
                    same_site = SameSitePolicy.STRICT
                elif s_val.lower() == "lax":
                    same_site = SameSitePolicy.LAX
                elif s_val.lower() == "none":
                    same_site = SameSitePolicy.NONE
            elif lower_token.startswith("domain="):
                domain = token.split("=", 1)[1].strip()
            elif lower_token.startswith("path="):
                path = token.split("=", 1)[1].strip()
            elif lower_token.startswith("max-age="):
                try:
                    max_age = int(token.split("=", 1)[1].strip())
                except ValueError:
                    max_age = None

        return cls(
            name=name.strip(),
            value=value.strip(),
            secure=secure,
            http_only=http_only,
            same_site=same_site,
            domain=domain,
            path=path,
            max_age=max_age,
            cookie_type=cookie_type
        )


@dataclass
class CookieSecurityIssue:
    """Tek bir çerez güvenlik açığı veya yanlış yapılandırma bulgusu."""
    # Zafiyet kodu (örn: MISSING_SECURE)
    code: str
    # Zafiyet başlığı
    title: str
    # Risk ciddiyet seviyesi (CRITICAL, HIGH, MEDIUM, LOW)
    severity: str
    # Detaylı teknik açıklama
    description: str
    # Düzeltme / sertleştirme önerisi
    remediation: str
    # Ceza puanı
    penalty: float


@dataclass
class CookieAuditReport:
    """Tek bir çerezin güvenlik denetim karnesi."""
    # Çerez adı
    cookie_name: str
    # Çerezin işlev türü
    cookie_type: str
    # Güvenlik skoru (0.0 - 100.0)
    security_score: float
    # Geçme durumu ("GECTI" veya "KALDI")
    status: str
    # Tespit edilen güvenlik açıkları
    issues: List[CookieSecurityIssue] = field(default_factory=list)
    # Sertleştirilmiş Set-Cookie öneri başlığı
    hardened_header: str = ""
    # Somut öneriler listesi
    recommendations: List[str] = field(default_factory=list)


@dataclass
class FleetCookieReport:
    """Tüm kurumsal çerez envanterinin genel denetim raporu."""
    # Denetlenen toplam çerez sayısı
    total_cookies: int
    # Güvenlik standardını geçen çerez sayısı
    compliant_cookies_count: int
    # Riskli/başarısız çerez sayısı
    vulnerable_cookies_count: int
    # Ortalama güvenlik skoru (0.0 - 100.0)
    average_security_score: float
    # Genel kabul durumu ("GECTI" veya "KALDI")
    overall_status: str
    # Çerez bazlı karne sözlüğü
    cookie_reports: Dict[str, CookieAuditReport] = field(default_factory=dict)


class CookieSecurityEngine:
    """HTTP Cookies ve Güvenlik Bayrakları Denetim ve Sertleştirme Motoru."""

    # Tek çerez için asgari kabul skoru
    COOKIE_PASS_THRESHOLD = 80.0
    # Kurumsal filo için asgari genel skor
    FLEET_PASS_THRESHOLD = 85.0
    # Maksimum makul oturum çerezi ömrü (14 gün = 1,209,600 saniye)
    MAX_REASONABLE_SESSION_LIFESPAN = 1209600

    def audit_cookie(self, cookie: HttpCookie) -> CookieAuditReport:
        """Tek bir HTTP çerezini tüm bayrak ve standartlar üzerinden denetler."""
        # Başlangıç puanı tam puandır
        score = 100.0
        issues: List[CookieSecurityIssue] = []
        recommendations: List[str] = []

        # -------------------------------------------------------------
        # 1. Kural: Secure Bayrağı Denetimi
        # -------------------------------------------------------------
        # Oturum veya CSRF çerezlerinde Secure bayrağının eksikliği kritik açıktır
        if not cookie.secure:
            if cookie.cookie_type in (CookieType.SESSION_AUTH, CookieType.CSRF_TOKEN):
                score -= 40.0
                issues.append(CookieSecurityIssue(
                    code="MISSING_SECURE_FLAG",
                    title="Eksik Secure Bayrağı (Kritik)",
                    severity="CRITICAL",
                    description="Oturum veya CSRF çerezinde Secure bayrağı yok. Çerez düz metin HTTP üzerinden iletilebilir ve dinlenebilir (MITM).",
                    remediation="Set-Cookie başlığına 'Secure' bayrağını ekleyerek çerezin yalnızca HTTPS üzerinden taşınmasını zorunlu kılın.",
                    penalty=40.0
                ))
                recommendations.append("Çerezi Secure olarak işaretleyin.")
            else:
                score -= 15.0
                issues.append(CookieSecurityIssue(
                    code="NON_SECURE_COOKIE",
                    title="Güvensiz Taşıma Riski",
                    severity="MEDIUM",
                    description="Çerezde Secure bayrağı bulunmuyor.",
                    remediation="Tüm çerezleri varsayılan olarak Secure bayrağı ile yayınlayın.",
                    penalty=15.0
                ))

        # -------------------------------------------------------------
        # 2. Kural: HttpOnly Bayrağı Denetimi
        # -------------------------------------------------------------
        # Oturum çerezinde HttpOnly eksikliği XSS ile oturum çalınmasına (Session Hijacking) yol açar
        if cookie.cookie_type == CookieType.SESSION_AUTH and not cookie.http_only:
            score -= 35.0
            issues.append(CookieSecurityIssue(
                code="MISSING_HTTPONLY_FLAG",
                title="Eksik HttpOnly Bayrağı (Yüksek Risk)",
                severity="HIGH",
                description="Oturum çerezi JavaScript (document.cookie) tarafından okunabilir durumdadır. Olası bir XSS zafiyetinde saldırgan oturumu doğrudan çalabilir.",
                remediation="Oturum çerezine 'HttpOnly' bayrağı ekleyerek tarayıcı betiklerinin çereze erişimini tamamen engelleyin.",
                penalty=35.0
            ))
            recommendations.append("XSS koruması için HttpOnly bayrağını ekleyin.")

        # -------------------------------------------------------------
        # 3. Kural: SameSite Politikası Denetimi
        # -------------------------------------------------------------
        if cookie.same_site == SameSitePolicy.MISSING:
            score -= 25.0
            issues.append(CookieSecurityIssue(
                code="MISSING_SAMESITE_FLAG",
                title="Eksik SameSite Politikası (CSRF Riski)",
                severity="HIGH",
                description="Çerezde SameSite özniteliği tanımlanmamış. Siteler arası istek sahteciliği (CSRF) ve üçüncü taraf sızıntılarına açıktır.",
                remediation="Çereze 'SameSite=Lax' veya hassas işlemler için 'SameSite=Strict' politikasını uygulayın.",
                penalty=25.0
            ))
            recommendations.append("SameSite=Lax veya SameSite=Strict bayrağını zorunlu kılın.")
        elif cookie.same_site == SameSitePolicy.NONE:
            # SameSite=None durumunda Secure kesinlikle zorunludur
            if not cookie.secure:
                score -= 40.0
                issues.append(CookieSecurityIssue(
                    code="SAMESITE_NONE_WITHOUT_SECURE",
                    title="Güvensiz SameSite=None Yapılandırması",
                    severity="CRITICAL",
                    description="SameSite=None politikasında Secure bayrağı eksik. Modern tarayıcılar (Chrome, Firefox, Safari) bu çerezi derhal reddeder.",
                    remediation="SameSite=None kullanılıyorsa mutlaka 'Secure' bayrağını da ekleyin.",
                    penalty=40.0
                ))
                recommendations.append("SameSite=None ile birlikte Secure bayrağını kullanın.")

        # -------------------------------------------------------------
        # 4. Kural: RFC 6265bis Çerez Önekleri Denetimi
        # -------------------------------------------------------------
        prefix = cookie.detect_prefix()
        if prefix == CookiePrefix.HOST:
            # __Host- kuralları: Secure olmalı, Path=/ olmalı, Domain belirtilmemelidir
            if not cookie.secure or cookie.path != "/" or cookie.domain is not None:
                score -= 30.0
                issues.append(CookieSecurityIssue(
                    code="INVALID_HOST_PREFIX_USAGE",
                    title="Hatalı __Host- Öneki Kullanımı",
                    severity="HIGH",
                    description="__Host- önekli çerezler; Secure=True, Path=/ olmalı ve kesinlikle Domain özniteliği İÇERMEMELİDİR. Alt alan adı manipülasyonu riski.",
                    remediation="__Host- çerezinde Domain özniteliğini kaldırın, Path=/ yapın ve Secure bayrağını açın.",
                    penalty=30.0
                ))
                recommendations.append("__Host- kurallarını sağlayın (Secure, Path=/, Domain yok).")
        elif prefix == CookiePrefix.SECURE:
            # __Secure- kuralları: Secure olmalıdır
            if not cookie.secure:
                score -= 25.0
                issues.append(CookieSecurityIssue(
                    code="INVALID_SECURE_PREFIX_USAGE",
                    title="Hatalı __Secure- Öneki Kullanımı",
                    severity="HIGH",
                    description="__Secure- önekli çerez mutlaka Secure bayrağı içermelidir; aksi takdirde tarayıcı tarafından reddedilir.",
                    remediation="Çereze Secure bayrağını ekleyin.",
                    penalty=25.0
                ))
                recommendations.append("__Secure- çerezi için Secure bayrağını açın.")
        else:
            # Hassas oturum çerezlerinde modern önek kullanılmaması tavsiye edilir
            if cookie.cookie_type == CookieType.SESSION_AUTH:
                recommendations.append("Maksimum izolasyon için çerez adını '__Host-session' olarak adlandırın.")

        # -------------------------------------------------------------
        # 5. Kural: Geniş Domain (Broad Domain Scope) Denetimi
        # -------------------------------------------------------------
        if cookie.domain:
            if cookie.domain.startswith(".") or cookie.domain.count(".") < 2:
                score -= 25.0
                issues.append(CookieSecurityIssue(
                    code="BROAD_DOMAIN_SCOPE",
                    title="Geniş Kapsamlı Domain Yapılandırması",
                    severity="HIGH",
                    description=f"Çerez domaini '{cookie.domain}' olarak geniş tanımlanmış. Tüm alt alan adları (subdomains) bu çereze erişebilir; alt alan ele geçirilirse oturum çalınabilir.",
                    remediation="Domain özniteliğini kaldırarak çerezi yalnızca tanımlandığı host ile sınırlandırın.",
                    penalty=25.0
                ))
                recommendations.append("Domain özniteliğini kaldırarak host izolasyonu sağlayın.")

        # -------------------------------------------------------------
        # 6. Kural: Aşırı Çerez Ömrü (Excessive Lifespan) Denetimi
        # -------------------------------------------------------------
        if cookie.max_age is not None and cookie.max_age > self.MAX_REASONABLE_SESSION_LIFESPAN:
            if cookie.cookie_type == CookieType.SESSION_AUTH:
                score -= 15.0
                issues.append(CookieSecurityIssue(
                    code="EXCESSIVE_COOKIE_LIFESPAN",
                    title="Aşırı Uzun Oturum Çerezi Ömrü",
                    severity="MEDIUM",
                    description=f"Oturum çerezinin Max-Age değeri ({cookie.max_age} saniye / {round(cookie.max_age / 86400)} gün) kabul edilebilir sınırın (14 gün) üzerindedir.",
                    remediation="Oturum çerezlerinin ömrünü en fazla 14 gün (1209600 saniye) veya oturum sonuna kadar sınırlandırın.",
                    penalty=15.0
                ))
                recommendations.append("Oturum çerez ömrünü makul bir süreye düşürün.")

        # -------------------------------------------------------------
        # 7. Kural: Düz Metin Hassas Veri Sızıntısı Denetimi
        # -------------------------------------------------------------
        val_lower = cookie.value.lower()
        sensitive_patterns = ["password=", "role=admin", "tckn=", "creditcard=", "tc_kimlik="]
        if any(pat in val_lower for pat in sensitive_patterns) or not cookie.is_encrypted_or_opaque:
            score -= 30.0
            issues.append(CookieSecurityIssue(
                code="PLAINTEXT_SENSITIVE_DATA",
                title="Çerez İçinde Düz Metin Hassas Veri",
                severity="HIGH",
                description="Çerez değeri içerisinde şifrelenmemiş hassas bilgi (parola, rol, kimlik no) tespit edildi. İstemci tarafında veri ifşası riski.",
                remediation="Çerez değerinde asla düz metin veri tutmayın; rastgele yüksek entropili opak oturum belirteci (UUIDv4) veya JWE kullanın.",
                penalty=30.0
            ))
            recommendations.append("Çerez değerini şifreleyin veya rastgele bir opaque token kullanın.")

        # Puanı [0.0, 100.0] aralığında tutma
        final_score = max(0.0, min(100.0, score))
        status = "GECTI" if final_score >= self.COOKIE_PASS_THRESHOLD else "KALDI"

        # Sertleştirilmiş başlık üretimi
        hardened = self.harden_cookie(cookie)
        hardened_header = hardened.to_set_cookie_header()

        return CookieAuditReport(
            cookie_name=cookie.name,
            cookie_type=cookie.cookie_type.value,
            security_score=final_score,
            status=status,
            issues=issues,
            hardened_header=hardened_header,
            recommendations=recommendations
        )

    def harden_cookie(self, cookie: HttpCookie) -> HttpCookie:
        """Verilen çerezi en yüksek güvenlik standartlarına göre otomatik sertleştirir."""
        # Yeni bir çerez nesnesi oluşturma
        new_name = cookie.name
        new_secure = True
        new_http_only = True if cookie.cookie_type == CookieType.SESSION_AUTH else cookie.http_only
        new_same_site = SameSitePolicy.STRICT if cookie.cookie_type in (CookieType.SESSION_AUTH, CookieType.CSRF_TOKEN) else SameSitePolicy.LAX
        new_domain = None  # Host-only izolasyonu için domain kaldırılır
        new_path = "/"
        
        # Aşırı ömür varsa sınırlandırma
        new_max_age = cookie.max_age
        if new_max_age is not None and new_max_age > self.MAX_REASONABLE_SESSION_LIFESPAN:
            new_max_age = 86400  # 1 gün

        # İsimlendirmede __Host- öneki tercihi
        if cookie.cookie_type == CookieType.SESSION_AUTH and not new_name.startswith("__Host-") and not new_name.startswith("__Secure-"):
            new_name = f"__Host-{new_name}"

        return HttpCookie(
            name=new_name,
            value=cookie.value,
            secure=new_secure,
            http_only=new_http_only,
            same_site=new_same_site,
            domain=new_domain,
            path=new_path,
            max_age=new_max_age,
            is_session_cookie=cookie.is_session_cookie,
            cookie_type=cookie.cookie_type,
            is_encrypted_or_opaque=True
        )

    def audit_fleet(self, cookies: List[HttpCookie]) -> FleetCookieReport:
        """Birden fazla çerezi denetleyerek kurumsal filo raporu üretir."""
        if not cookies:
            return FleetCookieReport(
                total_cookies=0,
                compliant_cookies_count=0,
                vulnerable_cookies_count=0,
                average_security_score=0.0,
                overall_status="KALDI",
                cookie_reports={}
            )

        reports: Dict[str, CookieAuditReport] = {}
        total_score = 0.0
        passed_count = 0

        for c in cookies:
            rep = self.audit_cookie(c)
            reports[c.name] = rep
            total_score += rep.security_score
            if rep.status == "GECTI":
                passed_count += 1

        avg_score = round(total_score / len(cookies), 1)
        vuln_count = len(cookies) - passed_count
        overall_status = "GECTI" if (avg_score >= self.FLEET_PASS_THRESHOLD and vuln_count == 0) else "KALDI"

        return FleetCookieReport(
            total_cookies=len(cookies),
            compliant_cookies_count=passed_count,
            vulnerable_cookies_count=vuln_count,
            average_security_score=avg_score,
            overall_status=overall_status,
            cookie_reports=reports
        )

    def export_fleet_report_to_dict(self, fleet_rep: FleetCookieReport) -> Dict[str, Any]:
        """Filo raporunu JSON uyumlu sözlük formatına dönüştürür."""
        data = asdict(fleet_rep)
        return data

    def generate_ascii_audit(self, fleet_rep: FleetCookieReport) -> str:
        """Konsol için görsel ASCII çerez denetim panosu üretir."""
        lines: List[str] = []
        lines.append("=" * 86)
        lines.append(" HTTP ÇEREZLERİ VE GÜVENLİK BAYRAKLARI DENETİM RAPORU (GÜN 157)")
        lines.append("=" * 86)
        lines.append(f" Toplam Çerez Sayısı   : {fleet_rep.total_cookies}")
        lines.append(f" Uyumlu Çerez Sayısı   : {fleet_rep.compliant_cookies_count} / {fleet_rep.total_cookies}")
        lines.append(f" Riskli Çerez Sayısı   : {fleet_rep.vulnerable_cookies_count}")
        lines.append(f" Ortalama Güvenlik Puanı: %{fleet_rep.average_security_score} / 100")
        lines.append(f" Kurumsal Kabul Durumu : [{fleet_rep.overall_status}]")
        lines.append("-" * 86)
        lines.append(f" {'ÇEREZ ADI':<24} {'TÜR':<14} {'PUAN':<8} {'DURUM':<8} {'BULGU SAYISI':<12}")
        lines.append("-" * 86)
        for name, rep in fleet_rep.cookie_reports.items():
            lines.append(f" {name:<24} {rep.cookie_type:<14} {rep.security_score:>5.1f}   [{rep.status}]   {len(rep.issues):<12}")
        lines.append("=" * 86)
        return "\n".join(lines)
