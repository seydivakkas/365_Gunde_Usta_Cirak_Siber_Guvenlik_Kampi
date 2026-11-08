# -*- coding: utf-8 -*-
"""
OWASP Top 10 Haritası ve Web Uygulama Güvenlik Değerlendirme Motoru
Hafta 23 / Gün 156 - Aşama 7 (Web Güvenliği)

Bu motor; kurumsal web uygulamalarını, API servislerini ve mimari yapılandırmaları
OWASP Top 10 standartlarına (A01: Kırık Erişim Denetimi'nden A10: SSRF'e kadar)
ve ilgili CWE zafiyet taksonomilerine göre haritalandırır, uyumluluk puanı hesaplar
ve önceliklendirilmiş iyileştirme yol haritaları (Remediation Roadmap) üretir.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Set
import json


class OwaspCategory(str, Enum):
    """OWASP Top 10 ana risk kategorileri taksonomisi."""
    # A01: Kırık Erişim Denetimi (IDOR, yetkisiz fonksiyon erişimi, CORS açıkları)
    A01_BROKEN_ACCESS_CONTROL = "A01:2025-Broken Access Control"
    # A02: Kriptografik Hatalar (Zayıf şifreleme, düz metin veri iletimi, zayıf anahtarlar)
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2025-Cryptographic Failures"
    # A03: Enjeksiyon Zafiyetleri (SQLi, Komut Enjeksiyonu, NoSQLi, XSS)
    A03_INJECTION = "A03:2025-Injection"
    # A04: Güvensiz Tasarım (Tehdit modelleme eksikliği, eksik hız sınırlama, tasarım açıkları)
    A04_INSECURE_DESIGN = "A04:2025-Insecure Design"
    # A05: Güvenlik Yanlış Yapılandırması (Varsayılan şifreler, açık debug modu, eksik başlıklar)
    A05_SECURITY_MISCONFIGURATION = "A05:2025-Security Misconfiguration"
    # A06: Savunmasız ve Güncel Olmayan Bileşenler (Log4Shell, eski kütüphaneler, yamalanmamış bağımlılıklar)
    A06_VULNERABLE_COMPONENTS = "A06:2025-Vulnerable and Outdated Components"
    # A07: Kimlik Tanımlama ve Doğrulama Hataları (Zayıf parola politikası, MFA eksikliği, oturum sabitleme)
    A07_AUTH_FAILURES = "A07:2025-Identification and Authentication Failures"
    # A08: Yazılım ve Veri Bütünlüğü Hataları (Güvensiz deserialization, manipüle edilebilir CI/CD boru hattı)
    A08_INTEGRITY_FAILURES = "A08:2025-Software and Data Integrity Failures"
    # A09: Güvenlik Günlüğü ve İzleme Hataları (Log tutmama, SIEM entegrasyonu yokluğu, geç alarm üretme)
    A09_LOGGING_FAILURES = "A09:2025-Security Logging and Monitoring Failures"
    # A10: Sunucu Taraflı İstek Sahteciliği (SSRF - İç ağ tarama, bulut metadata sızıntısı)
    A10_SSRF = "A10:2025-Server-Side Request Forgery"


class OwaspRiskLevel(str, Enum):
    """Zafiyet risk seviyesi derecelendirmesi."""
    LOW = "DUSUK"
    MEDIUM = "ORTA"
    HIGH = "YUKSEK"
    CRITICAL = "KRITIK"


@dataclass
class VulnerabilityMapping:
    """Tek bir zafiyet bulgusunun OWASP ve CWE eşleştirmesi."""
    # CWE (Common Weakness Enumeration) ID numarası
    cwe_id: int
    # CWE standart adı
    cwe_name: str
    # İlgili OWASP kategorisi
    category: OwaspCategory
    # Risk ciddiyet seviyesi
    severity: OwaspRiskLevel
    # Etkilenen bileşen / uç nokta
    affected_component: str
    # Zafiyetin detaylı teknik açıklaması
    description: str
    # Standart hafifletme (mitigation) adımı
    mitigation: str


@dataclass
class AppSecurityProfile:
    """Değerlendirilen web uygulamasının mimari ve güvenlik profili."""
    # Uygulama adı
    app_name: str
    # Uygulama sürümü
    version: str
    # Çalıştığı ortam (Production, Staging vb.)
    environment: str

    # A01: Erişim denetimi kontrolleri
    has_rbac_authz_middleware: bool
    idor_prevention_active: bool
    
    # A02: Kriptografi kontrolleri
    tls_minimum_version: str  # "TLSv1.3", "TLSv1.2", "TLSv1.0"
    passwords_hashed_with_argon2_or_bcrypt: bool
    sensitive_data_encrypted_at_rest: bool
    
    # A03: Enjeksiyon kontrolleri
    uses_parameterized_queries: bool
    output_encoding_for_xss: bool
    
    # A04: Güvensiz tasarım kontrolleri
    has_threat_model: bool
    has_rate_limiting: bool
    
    # A05: Yanlış yapılandırma kontrolleri
    debug_mode_disabled: bool
    default_credentials_changed: bool
    security_headers_enforced: bool
    
    # A06: Bağımlılık kontrolleri
    outdated_dependencies_count: int
    has_automated_sca_scanning: bool
    
    # A07: Kimlik doğrulama kontrolleri
    mfa_enforced_for_admin: bool
    brute_force_lockout_active: bool
    
    # A08: Bütünlük kontrolleri
    insecure_deserialization_prevented: bool
    ci_cd_pipeline_signed: bool
    
    # A09: Loglama kontrolleri
    centralized_audit_logging_active: bool
    security_event_alerting_latency_minutes: int  # <= 15 olmalı
    
    # A10: SSRF kontrolleri
    ssrf_url_validation_allowlist_active: bool
    cloud_metadata_blocked: bool


@dataclass
class OwaspCategoryScore:
    """Tek bir OWASP kategorisinin puan ve bulgu karnesi."""
    # Kategori adı ve kodu
    category: OwaspCategory
    # Kategori puanı (0.0 - 100.0)
    score: float
    # Durum (GECTI / KALDI)
    status: str
    # Tespit edilen bulgular listesi
    findings: List[str] = field(default_factory=list)


@dataclass
class OwaspComplianceReport:
    """Uygulamanın OWASP Top 10 genel uyumluluk raporu."""
    # Uygulama adı
    app_name: str
    # Genel uyumluluk puanı (0.0 - 100.0)
    overall_compliance_score: float
    # Kabul kararı
    is_compliant: bool
    # Kategori bazlı skor karnesi
    category_scores: Dict[str, OwaspCategoryScore]
    # Acil öncelikli iyileştirme adımları
    high_priority_remediations: List[str]
    # Yönetici özeti metni
    executive_summary: str


class OwaspMapperEngine:
    """OWASP Top 10 haritalama ve uyumluluk denetim motoru."""

    # Standart kategori geçme eşiği
    CATEGORY_PASS_THRESHOLD = 80.0
    # Genel kabul eşiği
    OVERALL_PASS_THRESHOLD = 85.0

    # Bilinen kritik CWE eşleştirme veritabanı
    CWE_DATABASE: Dict[int, Dict[str, Any]] = {
        89: {
            "name": "SQL Injection",
            "category": OwaspCategory.A03_INJECTION,
            "severity": OwaspRiskLevel.CRITICAL,
            "mitigation": "Daima parametreli sorgular (Prepared Statements) veya ORM soyutlaması kullanın."
        },
        79: {
            "name": "Cross-Site Scripting (XSS)",
            "category": OwaspCategory.A03_INJECTION,
            "severity": OwaspRiskLevel.HIGH,
            "mitigation": "Bağlama duyarlı bağlamsal çıktı kodlama (Contextual Output Encoding) ve katı CSP uygulayın."
        },
        639: {
            "name": "Insecure Direct Object Reference (IDOR)",
            "category": OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
            "severity": OwaspRiskLevel.HIGH,
            "mitigation": "Her nesne erişiminde kullanıcının o kayda sahip olduğunu sunucuda doğrulayın."
        },
        327: {
            "name": "Use of a Broken or Risky Cryptographic Algorithm",
            "category": OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
            "severity": OwaspRiskLevel.HIGH,
            "mitigation": "Kullanımdan kalkmış algoritmaları (MD5, SHA1, DES) terk edip AES-GCM ve Argon2id kullanın."
        },
        918: {
            "name": "Server-Side Request Forgery (SSRF)",
            "category": OwaspCategory.A10_SSRF,
            "severity": OwaspRiskLevel.HIGH,
            "mitigation": "Dışarıya yapılan HTTP isteklerinde katı alan adı beyaz listesi uygulayın ve 169.254.169.254 IP'sini engelleyin."
        },
        287: {
            "name": "Improper Authentication",
            "category": OwaspCategory.A07_AUTH_FAILURES,
            "severity": OwaspRiskLevel.HIGH,
            "mitigation": "Çok faktörlü kimlik doğrulama (MFA) ve hesap kilitleme mekanizması zorunlu kılın."
        },
        502: {
            "name": "Deserialization of Untrusted Data",
            "category": OwaspCategory.A08_INTEGRITY_FAILURES,
            "severity": OwaspRiskLevel.CRITICAL,
            "mitigation": "Güvenilmeyen kaynaktan gelen verileri doğrudan binary deserialization ile nesneye çevirmeyin; JSON kullanın."
        },
        16: {
            "name": "Configuration Error / Default Credentials",
            "category": OwaspCategory.A05_SECURITY_MISCONFIGURATION,
            "severity": OwaspRiskLevel.MEDIUM,
            "mitigation": "Tüm varsayılan şifreleri kurulum anında zorla değiştirin ve hata ayıklama modunu kapatın."
        },
        778: {
            "name": "Insufficient Logging",
            "category": OwaspCategory.A09_LOGGING_FAILURES,
            "severity": OwaspRiskLevel.MEDIUM,
            "mitigation": "Kritik güvenlik olaylarını (başarısız oturum, yetki aşımı) merkezi SIEM'e anlık aktarın."
        },
        1104: {
            "name": "Use of Unmaintained Third-Party Components",
            "category": OwaspCategory.A06_VULNERABLE_COMPONENTS,
            "severity": OwaspRiskLevel.HIGH,
            "mitigation": "Otomatik SCA (Yazılım Bileşen Analizi) araçlarını CI/CD boru hattına entegre edin."
        }
    }

    def evaluate_profile(self, profile: AppSecurityProfile) -> OwaspComplianceReport:
        """Uygulama güvenlik profilini 10 OWASP kategorisi üzerinden değerlendirir."""
        category_scores: Dict[str, OwaspCategoryScore] = {}
        high_remediations: List[str] = []

        # -------------------------------------------------------------
        # A01: Broken Access Control (Kırık Erişim Denetimi)
        # -------------------------------------------------------------
        a01_score = 100.0
        a01_findings: List[str] = []
        if not profile.has_rbac_authz_middleware:
            a01_score -= 50.0
            a01_findings.append("Merkezi yetkilendirme (RBAC/ABAC) ara katmanı eksik; yetkisiz URL erişimi riski.")
            high_remediations.append("Tüm korumalı API rotalarına merkezi yetkilendirme middleware'i ekleyin.")
        if not profile.idor_prevention_active:
            a01_score -= 40.0
            a01_findings.append("IDOR koruması kapalı; kullanıcılar parametre değiştirerek başkalarının verisine erişebilir.")
            high_remediations.append("Kayıt ID'lerini doğrulamak için nesne seviyesinde yetkilendirme (ACL) uygulayın.")

        category_scores["A01"] = OwaspCategoryScore(
            category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
            score=max(0.0, a01_score),
            status="GECTI" if a01_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a01_findings,
        )

        # -------------------------------------------------------------
        # A02: Cryptographic Failures (Kriptografik Başarısızlıklar)
        # -------------------------------------------------------------
        a02_score = 100.0
        a02_findings: List[str] = []
        if profile.tls_minimum_version in ("TLSv1.0", "TLSv1.1", "None"):
            a02_score -= 40.0
            a02_findings.append(f"Zayıf TLS sürümü destekleniyor: {profile.tls_minimum_version} (TLS 1.2 ve 1.3 zorunludur).")
            high_remediations.append("Web sunucusunda TLS 1.0 ve 1.1'i devre dışı bırakıp en az TLS 1.2 zorlayın.")
        if not profile.passwords_hashed_with_argon2_or_bcrypt:
            a02_score -= 40.0
            a02_findings.append("Parolalar zayıf algoritma ile saklanıyor (Argon2id veya bcrypt kullanılmalıdır).")
            high_remediations.append("Kullanıcı parola hashleme motorunu Argon2id standardına yükseltin.")
        if not profile.sensitive_data_encrypted_at_rest:
            a02_score -= 20.0
            a02_findings.append("Durağan hassas veriler (At-Rest) veritabanında şifrelenmemiş.")

        category_scores["A02"] = OwaspCategoryScore(
            category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
            score=max(0.0, a02_score),
            status="GECTI" if a02_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a02_findings,
        )

        # -------------------------------------------------------------
        # A03: Injection (Enjeksiyon Zafiyetleri)
        # -------------------------------------------------------------
        a03_score = 100.0
        a03_findings: List[str] = []
        if not profile.uses_parameterized_queries:
            a03_score -= 60.0
            a03_findings.append("Dinamik SQL sorgu birleştirmesi tespit edildi; SQL Enjeksiyonuna (SQLi) açıktır.")
            high_remediations.append("Tüm veritabanı çağrılarında parametreli sorgular (Prepared Statements) kullanın.")
        if not profile.output_encoding_for_xss:
            a03_score -= 40.0
            a03_findings.append("HTML çıktı kodlaması (Output Encoding) kapalı; XSS saldırılarına açık.")
            high_remediations.append("Kullanıcı girdisini render ederken bağlamsal HTML/JavaScript çıktı kodlaması uygulayın.")

        category_scores["A03"] = OwaspCategoryScore(
            category=OwaspCategory.A03_INJECTION,
            score=max(0.0, a03_score),
            status="GECTI" if a03_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a03_findings,
        )

        # -------------------------------------------------------------
        # A04: Insecure Design (Güvensiz Tasarım)
        # -------------------------------------------------------------
        a04_score = 100.0
        a04_findings: List[str] = []
        if not profile.has_threat_model:
            a04_score -= 30.0
            a04_findings.append("Mimari tasarımda STRIDE tehdit modellemesi yapılmamış.")
        if not profile.has_rate_limiting:
            a04_score -= 40.0
            a04_findings.append("Hız sınırlama (Rate Limiting) eksik; API kaba kuvvet ve DoS saldırılarına açık.")
            high_remediations.append("Tüm kimlik ve ödeme API'lerine IP ve kullanıcı bazlı Rate Limiter ekleyin.")

        category_scores["A04"] = OwaspCategoryScore(
            category=OwaspCategory.A04_INSECURE_DESIGN,
            score=max(0.0, a04_score),
            status="GECTI" if a04_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a04_findings,
        )

        # -------------------------------------------------------------
        # A05: Security Misconfiguration (Güvenlik Yanlış Yapılandırması)
        # -------------------------------------------------------------
        a05_score = 100.0
        a05_findings: List[str] = []
        if not profile.debug_mode_disabled:
            a05_score -= 50.0
            a05_findings.append("Üretim ortamında hata ayıklama modu (Debug Mode) açık; yığın izi ve gizli veriler ifşa olabilir.")
            high_remediations.append("Üretim ortamında DEBUG=False ayarlayın ve genel hata sayfalarını etkinleştirin.")
        if not profile.default_credentials_changed:
            a05_score -= 40.0
            a05_findings.append("Veritabanı veya yönetim panelinde varsayılan şifreler değiştirilmemiş.")
            high_remediations.append("Tüm varsayılan şifreleri (admin/admin, root/toor) derhal değiştirin.")
        if not profile.security_headers_enforced:
            a05_score -= 20.0
            a05_findings.append("Zorunlu HTTP güvenlik başlıkları (HSTS, CSP, XFO) yapılandırılmamış.")

        category_scores["A05"] = OwaspCategoryScore(
            category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
            score=max(0.0, a05_score),
            status="GECTI" if a05_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a05_findings,
        )

        # -------------------------------------------------------------
        # A06: Vulnerable and Outdated Components (Savunmasız Bileşenler)
        # -------------------------------------------------------------
        a06_score = 100.0
        a06_findings: List[str] = []
        if profile.outdated_dependencies_count > 0:
            penalty = min(60.0, profile.outdated_dependencies_count * 15.0)
            a06_score -= penalty
            a06_findings.append(f"{profile.outdated_dependencies_count} adet bilinen güvenlik açığı olan eski paket/kütüphane tespit edildi.")
            high_remediations.append("Eski üçüncü taraf kütüphaneleri güvenli yamalı sürümlerine güncelleyin.")
        if not profile.has_automated_sca_scanning:
            a06_score -= 25.0
            a06_findings.append("CI/CD sürecinde otomatik Yazılım Bileşen Analizi (SCA) taraması yok.")

        category_scores["A06"] = OwaspCategoryScore(
            category=OwaspCategory.A06_VULNERABLE_COMPONENTS,
            score=max(0.0, a06_score),
            status="GECTI" if a06_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a06_findings,
        )

        # -------------------------------------------------------------
        # A07: Identification and Authentication Failures (Kimlik Doğrulama Hataları)
        # -------------------------------------------------------------
        a07_score = 100.0
        a07_findings: List[str] = []
        if not profile.mfa_enforced_for_admin:
            a07_score -= 45.0
            a07_findings.append("Yönetici hesaplarında çok faktörlü kimlik doğrulama (MFA) zorunlu değil.")
            high_remediations.append("Tüm yönetim paneli erişimlerinde FIDO2 veya TOTP MFA'yı zorunlu kılın.")
        if not profile.brute_force_lockout_active:
            a07_score -= 30.0
            a07_findings.append("Kaba kuvvet saldırılarına karşı hesap kilitleme veya CAPTCHA koruması yok.")

        category_scores["A07"] = OwaspCategoryScore(
            category=OwaspCategory.A07_AUTH_FAILURES,
            score=max(0.0, a07_score),
            status="GECTI" if a07_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a07_findings,
        )

        # -------------------------------------------------------------
        # A08: Software and Data Integrity Failures (Yazılım Bütünlüğü Hataları)
        # -------------------------------------------------------------
        a08_score = 100.0
        a08_findings: List[str] = []
        if not profile.insecure_deserialization_prevented:
            a08_score -= 50.0
            a08_findings.append("Güvensiz nesne serileştirme (Pickle/Java Deserialization) uzaktan kod çalıştırmaya açıktır.")
            high_remediations.append("Güvenilmeyen verileri deserialize etmeyin; saf JSON doğrulayıcılar kullanın.")
        if not profile.ci_cd_pipeline_signed:
            a08_score -= 25.0
            a08_findings.append("CI/CD yapı artefaktları kriptografik olarak imzalanmıyor (Tedarik zinciri riski).")

        category_scores["A08"] = OwaspCategoryScore(
            category=OwaspCategory.A08_INTEGRITY_FAILURES,
            score=max(0.0, a08_score),
            status="GECTI" if a08_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a08_findings,
        )

        # -------------------------------------------------------------
        # A09: Security Logging and Monitoring Failures (Loglama ve İzleme Hataları)
        # -------------------------------------------------------------
        a09_score = 100.0
        a09_findings: List[str] = []
        if not profile.centralized_audit_logging_active:
            a09_score -= 50.0
            a09_findings.append("Merkezi denetim günlüğü (SIEM Loglama) aktif değil; saldırılar sessizce gerçekleşebilir.")
            high_remediations.append("Tüm oturum ve veri tabanı işlemlerini merkezi güvenli log sunucusuna iletin.")
        if profile.security_event_alerting_latency_minutes > 15:
            a09_score -= 25.0
            a09_findings.append(f"Güvenlik alarmları gecikmeli iletiliyor: {profile.security_event_alerting_latency_minutes} dk (>15 dk).")

        category_scores["A09"] = OwaspCategoryScore(
            category=OwaspCategory.A09_LOGGING_FAILURES,
            score=max(0.0, a09_score),
            status="GECTI" if a09_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a09_findings,
        )

        # -------------------------------------------------------------
        # A10: Server-Side Request Forgery (SSRF)
        # -------------------------------------------------------------
        a10_score = 100.0
        a10_findings: List[str] = []
        if not profile.ssrf_url_validation_allowlist_active:
            a10_score -= 50.0
            a10_findings.append("Sunucu tarafı URL doğrulamasında beyaz liste (Allowlist) yok; iç ağ tarama riski.")
            high_remediations.append("Giden webhook ve URL isteklerini katı bir alan adı beyaz listesiyle sınırlandırın.")
        if not profile.cloud_metadata_blocked:
            a10_score -= 40.0
            a10_findings.append("Bulut meta veri IP adresi (169.254.169.254) engellenmemiş; IAM rol anahtarları çalınabilir.")
            high_remediations.append("WAF ve ağ seviyesinde 169.254.169.254 metadata adresine erişimi yasaklayın.")

        category_scores["A10"] = OwaspCategoryScore(
            category=OwaspCategory.A10_SSRF,
            score=max(0.0, a10_score),
            status="GECTI" if a10_score >= self.CATEGORY_PASS_THRESHOLD else "KALDI",
            findings=a10_findings,
        )

        # -------------------------------------------------------------
        # Genel Uyumluluk Puanı Hesabı
        # -------------------------------------------------------------
        total_score = sum(s.score for s in category_scores.values())
        overall_score = round(total_score / len(category_scores), 1)

        failed_categories = [k for k, v in category_scores.items() if v.status == "KALDI"]
        is_compliant = (overall_score >= self.OVERALL_PASS_THRESHOLD) and (len(failed_categories) == 0)

        if is_compliant:
            summary = (
                f"'{profile.app_name}' uygulaması OWASP Top 10:2025 standartlarına %{overall_score} puan ile "
                "tam uyumludur. 10 kategorinin tamamı başarıyla geçilmiştir."
            )
        else:
            summary = (
                f"'{profile.app_name}' uygulaması OWASP Top 10 denetiminden KALMIŞTIR (Skor: %{overall_score}). "
                f"{len(failed_categories)} adet kategoride ({', '.join(failed_categories)}) kritik açıklar tespit edilmiştir."
            )

        return OwaspComplianceReport(
            app_name=profile.app_name,
            overall_compliance_score=overall_score,
            is_compliant=is_compliant,
            category_scores=category_scores,
            high_priority_remediations=high_remediations,
            executive_summary=summary,
        )

    def map_cwe(self, cwe_id: int, affected_comp: str = "Backend API") -> Optional[VulnerabilityMapping]:
        """CWE numarasını OWASP kategorisine dönüştürür."""
        if cwe_id not in self.CWE_DATABASE:
            return None
        data = self.CWE_DATABASE[cwe_id]
        return VulnerabilityMapping(
            cwe_id=cwe_id,
            cwe_name=data["name"],
            category=data["category"],
            severity=data["severity"],
            affected_component=affected_comp,
            description=f"CWE-{cwe_id} zafiyeti: {data['name']}",
            mitigation=data["mitigation"],
        )

    def export_report_to_dict(self, report: OwaspComplianceReport) -> Dict[str, Any]:
        """Rapor nesnesini JSON sözlüğüne dönüştürür."""
        data = asdict(report)
        for cat_k, cat_v in data["category_scores"].items():
            if isinstance(cat_v["category"], OwaspCategory):
                cat_v["category"] = cat_v["category"].value
        return data

    def generate_ascii_dashboard(self, report: OwaspComplianceReport) -> str:
        """Konsol çıktısı için görsel ASCII OWASP karnesi üretir."""
        lines: List[str] = []
        lines.append("=" * 82)
        lines.append(" OWASP TOP 10:2025 WEB GÜVENLİK HARİTASI VE UYUMLULUK RAPORU (GÜN 156)")
        lines.append("=" * 82)
        lines.append(f" Uygulama Adı          : {report.app_name}")
        lines.append(f" Genel Uyumluluk Skoru : %{report.overall_compliance_score} / 100 (Eşik: %{self.OVERALL_PASS_THRESHOLD})")
        lines.append(f" Nihai Değerlendirme   : {'[UYUMLU - GECTI]' if report.is_compliant else '[UYGUNSUZ - KALDI]'}")
        lines.append("-" * 82)
        lines.append(f" {'KOD':<5} {'KATEGORİ TANIMI':<48} {'PUAN':<8} {'DURUM':<8}")
        lines.append("-" * 82)
        for code, sc in sorted(report.category_scores.items()):
            cat_name = sc.category.value if isinstance(sc.category, OwaspCategory) else sc.category
            lines.append(f" {code:<5} {cat_name:<48} {sc.score:>5.1f}   [{sc.status}]")
        lines.append("=" * 82)
        if report.high_priority_remediations:
            lines.append(" ÖNCELİKLİ İYİLEŞTİRME EYLEM LİSTESİ:")
            for idx, rem in enumerate(report.high_priority_remediations[:5], 1):
                lines.append(f"   {idx}. {rem}")
            lines.append("=" * 82)
        return "\n".join(lines)
