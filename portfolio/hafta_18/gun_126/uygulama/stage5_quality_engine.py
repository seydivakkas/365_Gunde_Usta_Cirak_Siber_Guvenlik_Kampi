# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 126: AŞAMA 5 KALİTE ÖZETİ VE KABUL DENETÇİSİ MOTORU
------------------------------------------------------
Bu motor, Aşama 5 (Kriptografi ve Güvenlik Mimarisi) boyunca işlenen tüm
temel prensipleri (Simetrik/Asimetrik Kriptografi, Özet Fonksiyonları,
Zarf Şifreleme, STRIDE, Risk Analizi, Savunma Derinliği, Fail-Safe Defaults,
Fail-Secure ve Secrets Yönetimi) kurumsal bir denetim şartnamesi üzerinden
otomatik olarak değerlendirir, skorlar ve Aşama 5 Kabul Kararı üretir.
"""

# İşletim sistemi fonksiyonları için os kütüphanesi
import os
# Sistem çıkışları ve modül kontrolü için sys kütüphanesi
import sys
# JSON verisi çözümleme ve serileştirme için json kütüphanesi
import json
# Zaman damgaları ve denetim kayıtları için datetime kütüphanesi
from datetime import datetime
# Düzenli ifade işlemleri için re kütüphanesi
import re
# Kriptografik özetleme ve doğrulama işlemleri için hashlib kütüphanesi
import hashlib
# Sabit zamanlı karşılaştırma için hmac kütüphanesi
import hmac
# Kriptografik güvenli rastgelelik için secrets kütüphanesi
import secrets
# Veri sınıfları oluşturmak için dataclass ve field yapıları
from dataclasses import dataclass, field
# Tip belirteçleri için typing modülünden gerekli sınıflar
from typing import Dict, List, Set, Any, Optional, Tuple
# Numaralandırma sınıfları için Enum modülü
from enum import Enum


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class Stage5QualityEngineError(Exception):
    """Aşama 5 Kalite Motoru temel istisna sınıfı."""
    pass


class InsecureCryptographicAlgorithmError(Stage5QualityEngineError):
    """Kullanımdan kalkmış veya zayıf kriptografik algoritma tespit edildiğinde fırlatılır (CWE-327 / CWE-328)."""
    pass


class WeakKeyLengthError(Stage5QualityEngineError):
    """NIST standartlarına göre yetersiz anahtar veya özet uzunluğu tespit edildiğinde fırlatılır (CWE-326)."""
    pass


class WeakRandomnessError(Stage5QualityEngineError):
    """Kriptografik olmayan sözde rastgele sayı üreteci (PRNG) kullanıldığında fırlatılır (CWE-338)."""
    pass


class InsecureArchitectureError(Stage5QualityEngineError):
    """Saltzer-Schroeder ilkelerine uymayan güvensiz mimari tespit edildiğinde fırlatılır (CWE-1188)."""
    pass


class SinglePointOfFailureArchitectureError(Stage5QualityEngineError):
    """Savunma derinliğinde tek nokta arızası (SPoF) tespit edildiğinde fırlatılır (CWE-1008)."""
    pass


class SeparationOfDutiesViolationError(Stage5QualityEngineError):
    """Statik Görevler Ayrılığı (SoD) çatışması tespit edildiğinde fırlatılır (CWE-863)."""
    pass


class ExcessivePrivilegeError(Stage5QualityEngineError):
    """En Az Yetki İlkesine (PoLP) aykırı aşırı yetki veya joker karakter tespit edildiğinde fırlatılır (CWE-250 / CWE-285)."""
    pass


class FailOpenVulnerabilityError(Stage5QualityEngineError):
    """Sistem kesintisinde Fail-Closed yerine Fail-Open davranışı tespit edildiğinde fırlatılır (CWE-636)."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class StageAcceptanceDecision(Enum):
    """Aşama 5 Kalite Değerlendirmesi Nihai Kararı."""
    ACCEPTED_PASS = "STAGE_5_ACCEPTED (PASS)"
    HOLD_REMEDIATION_REQUIRED = "STAGE_5_HOLD (DÜZELTME GEREKLİ)"


@dataclass
class CryptographicComponentSpec:
    """Kriptografik bileşen şartname modeli."""
    component_name: str                      # Bileşen adı (örn: 'DataAtRestEncryption')
    cipher_or_hash_algorithm: str           # Algoritma (örn: 'AES-256-GCM', 'MD5')
    key_or_digest_bits: int                 # Anahtar/Özet bit boyutu (örn: 256, 128)
    mode_of_operation: Optional[str] = None # Çalışma modu (örn: 'GCM', 'CBC', 'ECB')
    pbkdf2_iterations: Optional[int] = None # Varsa KDF iterasyon sayısı
    random_source: str = "CSPRNG"           # Rastgelelik kaynağı ('CSPRNG' veya 'PRNG')
    uses_constant_time_compare: bool = True # Sabit zamanlı karşılaştırma kullanıyor mu?


@dataclass
class ArchitecturalControlSpec:
    """Mimari güvenlik kontrolleri şartname modeli."""
    control_name: str                        # Kontrol adı
    defense_layers_covered: List[str]        # Kapsanan katmanlar (Fiziksel, Ağ, Uygulama, Veri...)
    control_types: List[str]                 # Kontrol türleri (Önleyici, Tespit Edici, Telafi Edici...)
    default_deny_enforced: bool              # Varsayılan ret (Default-Deny) devrede mi?
    fail_secure_on_outage: bool              # Kesinti anında Fail-Secure / Fail-Closed mı?
    static_sod_enforced: bool                # Statik Görevler Ayrılığı (SoD) zorunlu mu?
    wildcard_permissions_allowed: bool       # Normal kullanıcılara joker (*) izin verilmiş mi?
    log_masking_enabled: bool                # CWE-532 log maskelemesi aktif mi?


@dataclass
class Stage5AuditResult:
    """Denetim sonucunu tutan yapısal veri modeli."""
    audit_id: str                            # Benzersiz denetim kimliği
    timestamp: str                           # Denetim zamanı
    target_system_name: str                  # Hedef sistem adı
    crypto_score: float                      # Kriptografi alt skoru (0-100)
    architecture_score: float                # Mimari alt skoru (0-100)
    governance_score: float                  # Yönetişim ve denetim skoru (0-100)
    overall_quality_score: float             # Ağırlıklı genel skor (0-100)
    decision: StageAcceptanceDecision        # Nihai kabul kararı
    critical_findings: List[str]             # Kritik seviye bulgular listesi
    warnings: List[str]                      # Uyarılar listesi
    cwe_violations: List[str]                # İhlal edilen CWE kodları


# ============================================================================
# ÇEKİRDEK KALİTE VE KABUL MOTORU
# ============================================================================

class Stage5QualityAuditor:
    """
    Aşama 5 Kalite Özeti ve Kabul Değerlendiricisi.
    Kriptografik algoritmaları, mimari prensipleri ve güvenlik kontrollerini
    NIST SP 800-131A, NIST SP 800-57, NIST SP 800-160 ve Saltzer-Schroeder
    ilkelerine göre bağımsız olarak teftiş eder.
    """

    # Kullanımdan kaldırılmış ve kırık kriptografik algoritmalar kara listesi
    BANNED_CRYPTO_ALGORITHMS: Set[str] = {
        "MD5", "MD4", "SHA1", "SHA-1", "DES", "3DES", "TRIPLEDES",
        "RC4", "BLOWFISH", "ECB", "AES-ECB"
    }

    # NIST tarafından onaylı modern ve güvenli algoritmalar
    APPROVED_CRYPTO_ALGORITHMS: Set[str] = {
        "AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305",
        "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512",
        "HMAC-SHA256", "HMAC-SHA512", "ED25519", "RSA-2048",
        "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384"
    }

    # Savunma derinliğinde beklenen 7 temel katman
    EXPECTED_DEFENSE_LAYERS: Set[str] = {
        "Fiziksel", "Çevre", "Ağ", "Host", "Uygulama", "Veri", "İnsan"
    }

    def __init__(self, auditor_name: str = "Aşama 5 Kalite ve Kabul Komitesi"):
        """Denetçi motorunu başlatır."""
        # Denetçi unvanını atıyoruz
        self.auditor_name = auditor_name
        # Gerçekleştirilen denetim geçmişi listesi
        self.audit_history: List[Stage5AuditResult] = []

    def evaluate_crypto_suite(
        self,
        components: List[CryptographicComponentSpec]
    ) -> Tuple[float, List[str], List[str]]:
        """
        Kriptografik bileşenleri NIST standartlarına göre denetler (Ağırlık: %40).
        Dönüş: (skor, bulgular, cwe_listesi)
        """
        # Başlangıç puanı 100 üzerinden hesaplanır
        score = 100.0
        # Kritik bulgular listesi
        findings: List[str] = []
        # İlgili CWE ihlalleri listesi
        cwes: List[str] = []

        # Eğer bileşen tanımlanmamışsa doğrudan sıfır puan verilir
        if not components:
            # Kritik bulgu ekliyoruz
            findings.append("Sistemde hiçbir kriptografik bileşen tanımlanmamış!")
            # CWE-311 (Eksik Şifreleme) ekliyoruz
            cwes.append("CWE-311")
            # Skoru sıfır döndürüyoruz
            return 0.0, findings, cwes

        # Her bir bileşeni sırayla inceliyoruz
        for comp in components:
            # Algoritma adını büyük harfe çevirip boşlukları temizliyoruz
            algo_upper = comp.cipher_or_hash_algorithm.strip().upper()

            # 1. Yasaklı Algoritma Denetimi (CWE-327 / CWE-328)
            if algo_upper in self.BANNED_CRYPTO_ALGORITHMS or "MD5" in algo_upper or "SHA1" in algo_upper or "DES" in algo_upper:
                # Skordan 30 puan kırıyoruz
                score -= 30.0
                # Bulgu açıklamasını ekliyoruz
                findings.append(f"Yasaklı/Zayıf Kriptografik Algoritma ({comp.component_name}): '{algo_upper}' tespit edildi (CWE-327).")
                # CWE kodunu ekliyoruz
                cwes.append("CWE-327")

            # 2. Çalışma Modu Denetimi (ECB modu asla kabul edilemez)
            if comp.mode_of_operation and comp.mode_of_operation.strip().upper() == "ECB":
                # Skordan 25 puan kırıyoruz
                score -= 25.0
                # Güvensiz ECB bulgusunu ekliyoruz
                findings.append(f"Güvensiz Blok Şifreleme Modu ({comp.component_name}): ECB modu tespit edildi (CWE-327).")
                # CWE kodunu ekliyoruz
                cwes.append("CWE-327")

            # 3. Yetersiz Anahtar / Özet Uzunluğu Denetimi (CWE-326)
            if "RSA" in algo_upper and comp.key_or_digest_bits < 2048:
                # Skordan 20 puan kırıyoruz
                score -= 20.0
                # Yetersiz anahtar bulgusunu ekliyoruz
                findings.append(f"Yetersiz RSA Anahtar Boyutu ({comp.component_name}): {comp.key_or_digest_bits} bit < 2048 bit (CWE-326).")
                # CWE kodunu ekliyoruz
                cwes.append("CWE-326")

            # AES için 128 bit altı kabul edilemez
            if "AES" in algo_upper and comp.key_or_digest_bits < 128:
                # Skordan 25 puan kırıyoruz
                score -= 25.0
                # Yetersiz AES anahtarı bulgusu
                findings.append(f"Yetersiz Simetrik Anahtar ({comp.component_name}): {comp.key_or_digest_bits} bit < 128 bit (CWE-326).")
                # CWE kodunu ekliyoruz
                cwes.append("CWE-326")

            # 4. Kriptografik Rastgelelik Kaynağı Denetimi (CWE-338)
            if comp.random_source.strip().upper() != "CSPRNG":
                # Skordan 20 puan kırıyoruz
                score -= 20.0
                # Zayıf rastgelelik bulgusu ekliyoruz
                findings.append(f"Zayıf Rastgelelik Kaynağı ({comp.component_name}): '{comp.random_source}' CSPRNG değildir (CWE-338).")
                # CWE kodunu ekliyoruz
                cwes.append("CWE-338")

            # 5. KDF İterasyon Sayısı Denetimi (PBKDF2)
            if comp.pbkdf2_iterations is not None and comp.pbkdf2_iterations < 100000:
                # Skordan 15 puan kırıyoruz
                score -= 15.0
                # Düşük iterasyon bulgusu ekliyoruz
                findings.append(f"Yetersiz PBKDF2 İterasyonu ({comp.component_name}): {comp.pbkdf2_iterations} < 100.000 döngü (CWE-916).")
                # CWE kodunu ekliyoruz
                cwes.append("CWE-916")

            # 6. Sabit Zamanlı Doğrulama Denetimi (CWE-208)
            if not comp.uses_constant_time_compare:
                # Skordan 15 puan kırıyoruz
                score -= 15.0
                # Zamanlama açığı bulgusu ekliyoruz
                findings.append(f"Zamanlama Saldırısı Riski ({comp.component_name}): Sabit zamanlı karşılaştırma eksik (CWE-208).")
                # CWE kodunu ekliyoruz
                cwes.append("CWE-208")

        # Puanın 0 ile 100 arasında kalmasını sağlıyoruz
        final_score = max(0.0, min(100.0, score))
        # Skoru, bulguları ve CWE listesini döndürüyoruz
        return final_score, findings, cwes

    def evaluate_architectural_controls(
        self,
        controls: ArchitecturalControlSpec
    ) -> Tuple[float, List[str], List[str]]:
        """
        Mimari güvenlik ilkelerini Saltzer-Schroeder ilkelerine göre denetler (Ağırlık: %40).
        Dönüş: (skor, bulgular, cwe_listesi)
        """
        # Başlangıç mimari skoru
        score = 100.0
        # Bulgular listesi
        findings: List[str] = []
        # CWE listesi
        cwes: List[str] = []

        # 1. Saltzer-Schroeder Fail-Safe Defaults / Default-Deny (CWE-1188)
        if not controls.default_deny_enforced:
            # En kritik kural çiğnenmişse 35 puan kırıyoruz
            score -= 35.0
            # Kritik bulguyu ekliyoruz
            findings.append("Mimari Kural İhlali: Varsayılan Ret (Default-Deny) devrede değil; sistem Default-Allow çalışıyor (CWE-1188)!")
            # CWE kodunu ekliyoruz
            cwes.append("CWE-1188")

        # 2. Fail-Secure / Fail-Closed Koruması (CWE-636)
        if not controls.fail_secure_on_outage:
            # Arıza anında açık kapı bırakılıyorsa 30 puan kırıyoruz
            score -= 30.0
            # Kritik bulguyu ekliyoruz
            findings.append("Kritik Arıza Güvenliği İhlali: Sistem kesintide Fail-Open çalışıyor; kapılar kilitlenmiyor (CWE-636)!")
            # CWE kodunu ekliyoruz
            cwes.append("CWE-636")

        # 3. Statik Görevler Ayrılığı (Static SoD - CWE-863)
        if not controls.static_sod_enforced:
            # SoD kısıtı yoksa 20 puan kırıyoruz
            score -= 20.0
            # Bulgu ekliyoruz
            findings.append("Görevler Ayrılığı (SoD) Eksikliği: Çatışan rol çiftleri (Maker-Checker) engellenmiyor (CWE-863).")
            # CWE kodunu ekliyoruz
            cwes.append("CWE-863")

        # 4. En Az Yetki İlkesi ve Joker Karakter Denetimi (CWE-250 / CWE-285)
        if controls.wildcard_permissions_allowed:
            # Joker yetki verilmişse 15 puan kırıyoruz
            score -= 15.0
            # Bulgu ekliyoruz
            findings.append("Aşırı Yetkilendirme (PoLP İhlali): Normal rollere joker (*) izni tanımlanmış (CWE-250).")
            # CWE kodunu ekliyoruz
            cwes.append("CWE-250")

        # 5. Savunma Derinliği Katman Kapsama Denetimi (CWE-653 / CWE-1008)
        covered_layers = set(controls.defense_layers_covered)
        # Eksik katmanları tespit ediyoruz
        missing_layers = self.EXPECTED_DEFENSE_LAYERS - covered_layers
        # Eğer katman sayısı 3'ten azsa SPoF riski vardır
        if len(covered_layers) < 4:
            # 20 puan kırıyoruz
            score -= 20.0
            # SPoF bulgusu ekliyoruz
            findings.append(f"Yetersiz Savunma Derinliği: Sadece {len(covered_layers)} katman kapsanıyor. Eksik katmanlar: {', '.join(missing_layers)} (CWE-653 / CWE-1008).")
            # CWE kodunu ekliyoruz
            cwes.append("CWE-1008")
        elif missing_layers:
            # Kısmi eksiklik için 10 puan kırıyoruz
            score -= 10.0
            # Uyarı niteliğinde bulgu ekliyoruz
            findings.append(f"Eksik Savunma Katmanları: {', '.join(missing_layers)} katmanlarında kontrol tanımlı değil.")

        # Puanın 0 ile 100 arasında kalmasını sağlıyoruz
        final_score = max(0.0, min(100.0, score))
        # Skoru ve bulguları döndürüyoruz
        return final_score, findings, cwes

    def evaluate_governance_and_evidence(
        self,
        controls: ArchitecturalControlSpec,
        has_executable_tests: bool,
        has_negative_controls: bool
    ) -> Tuple[float, List[str], List[str]]:
        """
        Yönetişim, denetim kaydı maskelemesi ve doğrulanabilir kanıt kalitesini değerlendirir (Ağırlık: %20).
        Dönüş: (skor, bulgular, cwe_listesi)
        """
        # Başlangıç yönetişim skoru
        score = 100.0
        # Bulgular listesi
        findings: List[str] = []
        # CWE listesi
        cwes: List[str] = []

        # 1. Denetim Günlüğü Maskelemesi Denetimi (CWE-532)
        if not controls.log_masking_enabled:
            # Loglarda sır sızması riski için 30 puan kırıyoruz
            score -= 30.0
            # Bulgu ekliyoruz
            findings.append("Denetim Kütüğü Güvenliği İhlali: Parolalar ve token'lar loglarda açık metin yazılıyor (CWE-532)!")
            # CWE kodunu ekliyoruz
            cwes.append("CWE-532")

        # 2. Çalıştırılabilir Yerel Birim Testleri Denetimi
        if not has_executable_tests:
            # Testler yoksa 40 puan kırıyoruz
            score -= 40.0
            # Bulgu ekliyoruz
            findings.append("Doğrulanabilirlik Eksikliği: Yerel çalıştırılabilir birim testleri mevcut değil.")

        # 3. Negatif Sınır Kontrolleri ve Hata Enjeksiyonu Denetimi
        if not has_negative_controls:
            # Negatif kontroller yoksa 30 puan kırıyoruz
            score -= 30.0
            # Bulgu ekliyoruz
            findings.append("Sınır Durum Güvencesi Eksikliği: Negatif hata enjeksiyon senaryoları eksik.")

        # Puan sınırlandırması
        final_score = max(0.0, min(100.0, score))
        # Skoru döndürüyoruz
        return final_score, findings, cwes

    def perform_full_stage5_audit(
        self,
        target_system_name: str,
        crypto_specs: List[CryptographicComponentSpec],
        arch_spec: ArchitecturalControlSpec,
        has_executable_tests: bool = True,
        has_negative_controls: bool = True
    ) -> Stage5AuditResult:
        """
        Aşama 5 kapsamındaki tüm bileşenleri denetler ve nihai kabul kararını üretir.
        Ağırlıklar: %40 Kriptografi, %40 Mimari, %20 Yönetişim & Kanıt.
        """
        # Benzersiz denetim kimliği üretiyoruz
        audit_id = f"AUD-STAGE5-{secrets.token_hex(4).upper()}"
        # Zaman damgasını alıyoruz
        now_iso = datetime.now().isoformat()

        # 1. Kriptografi değerlendirmesi
        c_score, c_findings, c_cwes = self.evaluate_crypto_suite(crypto_specs)
        # 2. Mimari kontroller değerlendirmesi
        a_score, a_findings, a_cwes = self.evaluate_architectural_controls(arch_spec)
        # 3. Yönetişim ve kanıt kalitesi değerlendirmesi
        g_score, g_findings, g_cwes = self.evaluate_governance_and_evidence(
            arch_spec, has_executable_tests, has_negative_controls
        )

        # Ağırlıklı genel skor hesaplaması: %40 Kriptografi + %40 Mimari + %20 Yönetişim
        overall = (0.40 * c_score) + (0.40 * a_score) + (0.20 * g_score)
        # Yuvarlama yapıyoruz
        overall_rounded = round(overall, 2)

        # Tüm bulguları ve CWE'leri birleştiriyoruz
        all_findings = c_findings + a_findings + g_findings
        # Benzersiz CWE kümesi oluşturuyoruz
        all_cwes = sorted(list(set(c_cwes + a_cwes + g_cwes)))

        # Kabul Kararı Kriteri:
        # 1. Genel skor en az 85.0 olmalıdır.
        # 2. Yasaklı algoritma (CWE-327), Default-Allow (CWE-1188) veya Fail-Open (CWE-636) bulunmamalıdır.
        critical_cwe_blockers = {"CWE-327", "CWE-1188", "CWE-636"}
        has_critical_blocker = any(cwe in critical_cwe_blockers for cwe in all_cwes)

        # Karar mantığı
        if overall_rounded >= 85.0 and not has_critical_blocker:
            # Aşama 5 Başarıyla Kabul Edildi
            decision = StageAcceptanceDecision.ACCEPTED_PASS
        else:
            # Düzeltme gerekli, beklemede
            decision = StageAcceptanceDecision.HOLD_REMEDIATION_REQUIRED

        # Denetim sonuç nesnesi oluşturuluyor
        result = Stage5AuditResult(
            audit_id=audit_id,
            timestamp=now_iso,
            target_system_name=target_system_name,
            crypto_score=c_score,
            architecture_score=a_score,
            governance_score=g_score,
            overall_quality_score=overall_rounded,
            decision=decision,
            critical_findings=all_findings,
            warnings=[] if overall_rounded >= 95.0 else ["Bazı ikincil iyileştirme alanları mevcuttur."],
            cwe_violations=all_cwes
        )

        # Geçmişe ekliyoruz
        self.audit_history.append(result)
        # Sonucu döndürüyoruz
        return result

    def generate_markdown_certificate(self, audit_result: Stage5AuditResult) -> str:
        """Aşama 5 Kalite ve Kabul Sertifikasını Markdown formatında üretir."""
        # Karar rozeti metni
        decision_badge = (
            "✅ **AŞAMA 5 KABUL EDİLDİ (PASS)**"
            if audit_result.decision == StageAcceptanceDecision.ACCEPTED_PASS
            else "❌ **AŞAMA 5 BEKLEMEDE (HOLD / REMEDIATION)**"
        )

        # Markdown satırları
        lines: List[str] = [
            "# AŞAMA 5: KRİPTOGRAFİ VE GÜVENLİK MİMARİSİ KALİTE SERTİFİKASI",
            f"**Denetim Kimliği:** `{audit_result.audit_id}`  ",
            f"**Tarih / Saat:** `{audit_result.timestamp}`  ",
            f"**Hedef Sistem:** `{audit_result.target_system_name}`  ",
            f"**Denetçi Otoritesi:** `{self.auditor_name}`  ",
            "",
            "---",
            "",
            "## 1. Yönetici Kararı ve Skor Özeti",
            "",
            f"### Nihai Karar: {decision_badge}",
            "",
            "| Değerlendirme Boyutu | Ağırlık | Alınan Puan | Durum |",
            "|---|---|---|---|",
            f"| **1. Kriptografik Güvenlik (NIST SP 800-131A/57)** | %40 | {audit_result.crypto_score} / 100 | {'✅ Başarılı' if audit_result.crypto_score >= 85 else '❌ Yetersiz'} |",
            f"| **2. Mimari İlkeler (Saltzer-Schroeder/NIST SP 800-160)** | %40 | {audit_result.architecture_score} / 100 | {'✅ Başarılı' if audit_result.architecture_score >= 85 else '❌ Yetersiz'} |",
            f"| **3. Yönetişim ve Doğrulanabilir Kanıt** | %20 | {audit_result.governance_score} / 100 | {'✅ Başarılı' if audit_result.governance_score >= 85 else '❌ Yetersiz'} |",
            f"| **GENEL AŞAMA 5 KALİTE SKORU** | **%100** | **{audit_result.overall_quality_score} / 100** | **{audit_result.decision.value}** |",
            "",
            "---",
            "",
            "## 2. Standartlar ve Tasarım Güvencesi Uyumluluğu",
            "",
            "> [!IMPORTANT]",
            "> **AŞAMA 5 MİMARİ İLKELER VE KRİPTOGRAFİ ONAY BEYANI:**",
            "> 1. **Kriptografik Algoritmalar:** Kırık/eski algoritmalar (MD5, SHA-1, DES, ECB) sıfır toleransla reddedilmiştir.",
            "> 2. **Saltzer-Schroeder İlkeleri:** Fail-Safe Defaults (Default-Deny) ve En Az Yetki (PoLP) işletilmektedir.",
            "> 3. **Fail-Secure Arıza İzolasyonu:** Altyapı çöküşlerinde sistem asla açık kapı (Fail-Open) bırakmamaktadır (CWE-636).",
            "> 4. **Görevler Ayrılığı (SoD):** Çıkar çatışmasına yol açabilecek zehirli rol çiftleri engellenmiştir (CWE-863).",
            "> 5. **Secrets ve Log Maskeleme:** Kütüklerdeki tüm parolalar ve tokenlar maskelenmiştir (CWE-532).",
            "",
            "## 3. Bulgular ve Tespit Edilen Zafiyetler",
            ""
        ]

        # Eğer kritik bulgu varsa listeliyoruz
        if audit_result.critical_findings:
            # Bulguları listeye ekliyoruz
            for f in audit_result.critical_findings:
                # Liste elemanı olarak ekliyoruz
                lines.append(f"- ⚠️ {f}")
        else:
            # Sıfır zafiyet bildirimi
            lines.append("✅ **Hiçbir kritik bulgu veya zafiyet tespit edilmemiştir. Sistem üretim düzeyinde güvenlidir.**")

        # CWE listesi
        lines.append("")
        # CWE başlığı
        lines.append(f"**İlişkili CWE Referansları:** {', '.join(audit_result.cwe_violations) if audit_result.cwe_violations else 'Yok (Tam Uyum)'}")
        lines.append("")
        # Metni birleştirip döndürüyoruz
        return "\n".join(lines)
