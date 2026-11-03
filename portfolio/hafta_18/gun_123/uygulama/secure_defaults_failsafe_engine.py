# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 123: Güvenli Varsayılanlar (Secure by Default) ve Fail-Safe / Fail-Secure Motoru.
Bu modül; Saltzer-Schroeder Güvenli Varsayılanlar prensibini, Default-Deny erişim modelini,
CWE-1188 Güvenli Olmayan Varsayılan Yapılandırma denetimini ve
CWE-636 Fail-Closed (Hata Halinde Güvenli Kapanma) mekanizmasını icra eder.
"""

# Standart enum modülü içe aktarılıyor
from enum import Enum
# Veri yapılarını oluşturmak için dataclass ve field içe aktarılıyor
from dataclasses import dataclass, field
# Tip ipuçları için tipler içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any
# Denetim zaman damgaları üretmek için datetime içe aktarılıyor
from datetime import datetime
# JSON serileştirme işlemleri için json modülü içe aktarılıyor
import json


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class FailSafeEngineError(Exception):
    """Fail-Safe motoru temel istisna sınıfı."""
    pass


class InsecureFailOpenForbiddenError(FailSafeEngineError):
    """Güvenlik sistemlerinde yetkisiz fail-open davranışı tespit edildiğinde fırlatılır (CWE-636)."""
    pass


class InsecureDefaultDetectedError(FailSafeEngineError):
    """Sistemde güvenli olmayan bir varsayılan konfigürasyon tespit edildiğinde fırlatılır (CWE-1188)."""
    pass


class FailSecureInterventionError(FailSafeEngineError):
    """Fail-Secure mekanizması devreye girip erişimi zorunlu kestiğinde fırlatılır."""
    pass


class InvalidResourceConfigurationError(FailSafeEngineError):
    """Kaynak yapılandırma parametreleri geçersiz veya eksik olduğunda fırlatılır."""
    pass


class DuplicateResourceError(FailSafeEngineError):
    """Aynı kimliğe sahip mükerrer kaynak kaydedilmeye çalışıldığında fırlatılır."""
    pass


class DuplicatePolicyRuleError(FailSafeEngineError):
    """Aynı kural kimliğine sahip mükerrer kural eklendiğinde fırlatılır."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class DecisionOutcome(Enum):
    """Erişim karar sonuçları."""
    PERMIT = "İZİN_VERİLDİ"      # Açıkça izin verilen durum
    DENY = "REDDEDİLDİ"          # Güvenli varsayılan veya kural gereği engellenen durum


class FailureHandlingMode(Enum):
    """Sistem arızası anında benimsenecek temel güvenlik stratejisi."""
    FAIL_SECURE = "FAIL_SECURE"  # Arıza anında kapıları kilitle (Default Deny - Güvenli)
    FAIL_OPEN = "FAIL_OPEN"      # Arıza anında erişimi serbest bırak (Kritik Tehlike - CWE-636)


class FailureType(Enum):
    """Simüle edilebilir harici bağımlılık veya sistem arızası tipleri."""
    DATABASE_DOWN = "Veritabanı Bağlantısı Kesildi"
    AUTH_SERVICE_TIMEOUT = "Kimlik Doğrulama Servisi Zaman Aşımı"
    CORRUPTED_POLICY = "Bozuk veya Okunamayan Politika Dosyası"
    UNHANDLED_EXCEPTION = "Beklenmeyen Kod İstisnası"
    NETWORK_PARTITION = "Ağ Bölünmesi / İletişim Kopması"


class SecurityDefaultIssue(Enum):
    """CWE-1188 Güvenli Olmayan Varsayılan Zaafiyet Sınıfları."""
    DEBUG_MODE_ENABLED = "Geliştirme / Debug Modu Varsayılan Olarak Açık"
    DEFAULT_CREDENTIALS_ACTIVE = "Varsayılan Parola / Kimlik Değiştirilmemiş"
    PERMISSIVE_CORS = "CORS Herkese Açık (*) Bırakılmış"
    CLEARTEXT_COMMUNICATION = "Şifresiz İletişim (HTTP/Telnet) Varsayılan Olarak İzinli"
    DEFAULT_PERMIT_ACCESS = "Erişim Kuralı Varsayılanı İZİN (Allow) Yapılmış"
    UNENCRYPTED_STORAGE = "Durağan Depolama Varsayılan Olarak Şifresiz"


@dataclass
class ResourceConfig:
    """Sistemde korunan bir bileşenin güvenlik yapılandırma modeli."""
    resource_id: str                     # Kaynak benzersiz kimliği (örn: 'RES-API-01')
    name: str                            # Kaynak adı
    default_access: str = "DENY"         # Varsayılan erişim politikası ('DENY' olmalıdır)
    debug_mode: bool = False             # Debug modu (Varsayılan: False)
    enforce_tls: bool = True             # TLS zorunluluğu (Varsayılan: True)
    is_default_credential_changed: bool = True # Varsayılan parola değiştirildi mi?
    cors_allow_all: bool = False         # CORS * açık mı? (Varsayılan: False)
    storage_encrypted: bool = True       # Depolama şifreli mi? (Varsayılan: True)

    def validate_defaults(self) -> List[SecurityDefaultIssue]:
        """Yapılandırmadaki CWE-1188 güvenli olmayan varsayılanları tarar ve listeler."""
        # Tespit edilen sorunlar listesi başlatılır
        issues: List[SecurityDefaultIssue] = []
        # 1. Kontrol: Varsayılan erişim DENY değilse
        if self.default_access.upper() != "DENY":
            issues.append(SecurityDefaultIssue.DEFAULT_PERMIT_ACCESS)
        # 2. Kontrol: Debug modu açık bırakılmışsa
        if self.debug_mode:
            issues.append(SecurityDefaultIssue.DEBUG_MODE_ENABLED)
        # 3. Kontrol: TLS zorunlu kılınmamışsa
        if not self.enforce_tls:
            issues.append(SecurityDefaultIssue.CLEARTEXT_COMMUNICATION)
        # 4. Kontrol: Varsayılan şifre değiştirilmemişse (admin/admin vb.)
        if not self.is_default_credential_changed:
            issues.append(SecurityDefaultIssue.DEFAULT_CREDENTIALS_ACTIVE)
        # 5. Kontrol: CORS herkese açıksa
        if self.cors_allow_all:
            issues.append(SecurityDefaultIssue.PERMISSIVE_CORS)
        # 6. Kontrol: Depolama şifresizse
        if not self.storage_encrypted:
            issues.append(SecurityDefaultIssue.UNENCRYPTED_STORAGE)
        # Bulunan sorunlar döndürülür
        return issues


@dataclass
class PolicyRule:
    """Erişim kontrol kuralı modeli."""
    rule_id: str                         # Kural kimliği
    subject_role: str                    # İzin verilen rol (örn: 'admin', 'analyst')
    resource_id: str                     # Hedef kaynak
    action: str                          # İzin verilen eylem (örn: 'read', 'write')
    effect: DecisionOutcome = DecisionOutcome.PERMIT # Kural etkisi


@dataclass
class AccessRequest:
    """Erişim kontrol talep nesnesi."""
    request_id: str                      # Talep kimliği
    subject_id: str                      # Kullanıcı kimliği
    subject_role: str                    # Kullanıcı rolü
    resource_id: str                     # İstenen kaynak
    action: str                          # Yapılmak istenen işlem
    context: Dict[str, Any] = field(default_factory=dict) # Ek bağlam bilgisi


@dataclass
class DecisionResult:
    """PDP karar neticesi modeli."""
    request_id: str                      # Talep kimliği
    decision: DecisionOutcome            # Nihai karar (PERMIT / DENY)
    reason: str                          # Karar gerekçesi
    matched_rule_id: Optional[str] = None # Eşleşen kural kimliği
    is_fail_secure_intervention: bool = False # Fail-Secure müdahalesi oldu mu?
    failure_encountered: Optional[FailureType] = None # Karşılaşılan arıza tipi


# ============================================================================
# GÜVENLİ VARSAYILANLAR VE FAIL-SAFE YÖNETİCİSİ
# ============================================================================

class FailSafeSecurityManager:
    """
    Güvenli varsayılanları (Secure by Default) denetleyen,
    arıza anlarında Fail-Secure (Fail-Closed) kuralını işleten ve
    CWE-636 / CWE-1188 ihlallerini engelleyen ana karar motoru (PDP).
    """

    def __init__(
        self,
        system_name: str,
        failure_mode: FailureHandlingMode = FailureHandlingMode.FAIL_SECURE,
        safety_override_token: Optional[str] = None
    ):
        """
        Güvenli varsayılan yöneticisini başlatır.
        
        Args:
            system_name: Korunan sistemin adı.
            failure_mode: Arıza anındaki davranış (Varsayılan: FAIL_SECURE).
            safety_override_token: İnsan can güvenliği acil durum token'ı (yalnızca özel durumlarda).
        """
        # Sistem adı saklanır
        self.system_name = system_name
        # Arıza modu saklanır
        self.failure_mode = failure_mode
        # Acil durum istisna anahtarı saklanır
        self.safety_override_token = safety_override_token
        # Kayıtlı kaynak yapılandırmaları sözlüğü
        self.resources: Dict[str, ResourceConfig] = {}
        # Kayıtlı politika kuralları sözlüğü
        self.rules: Dict[str, PolicyRule] = {}
        # Denetim günlüğü listesi
        self.audit_log: List[Dict[str, Any]] = []

    def _log_event(self, action: str, details: Dict[str, Any]) -> None:
        """Denetim günlüğüne yapısal kayıt ekler."""
        # Zaman damgalı olay kaydı oluşturulur
        event = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        # Listeye eklenir
        self.audit_log.append(event)

    def register_resource(self, resource: ResourceConfig) -> None:
        """Sisteme yeni bir kaynak yapılandırması kaydeder."""
        # Kaynak kimliği mükerrer mi denetlenir
        if resource.resource_id in self.resources:
            # Mükerrer kaynak hatası fırlatılır
            raise DuplicateResourceError(f"Bu ID ile kaynak zaten mevcut: {resource.resource_id}")
        # Kaynak adı doğrulanır
        if not resource.name or not resource.name.strip():
            # Geçersiz kaynak yapılandırma hatası fırlatılır
            raise InvalidResourceConfigurationError("Kaynak adı boş bırakılamaz.")
        # Kaynak sözlüğe kaydedilir
        self.resources[resource.resource_id] = resource
        # Olay günlüğüne yazılır
        self._log_event("RESOURCE_REGISTERED", {"resource_id": resource.resource_id, "name": resource.name})

    def add_policy_rule(self, rule: PolicyRule) -> None:
        """Erişim kararlarında değerlendirilecek açık bir kural ekler."""
        # Kural kimliği mükerrer mi denetlenir
        if rule.rule_id in self.rules:
            # Mükerrer kural hatası fırlatılır
            raise DuplicatePolicyRuleError(f"Bu ID ile kural zaten mevcut: {rule.rule_id}")
        # Hedef kaynak sistemde kayıtlı mı denetlenir
        if rule.resource_id not in self.resources:
            # Geçersiz kaynak hatası fırlatılır
            raise InvalidResourceConfigurationError(f"Kuralın hedeflediği kaynak sistemde kayıtlı değil: {rule.resource_id}")
        # Kural sözlüğe eklenir
        self.rules[rule.rule_id] = rule
        # Olay günlüğüne yazılır
        self._log_event("POLICY_RULE_ADDED", {"rule_id": rule.rule_id, "resource": rule.resource_id})

    def audit_secure_defaults(self) -> Tuple[bool, List[str]]:
        """
        Tüm kaynakları CWE-1188 (Güvenli Olmayan Varsayılanlar) zaafiyetine karşı denetler.
        
        Returns:
            Tuple[bool, List[str]]: Uyum durumu ve bulunan güvenlik ihlallerinin listesi.
        """
        # İhlaller listesi başlatılır
        violations: List[str] = []
        # Hiç kaynak tanımlanmamışsa uyarı eklenir
        if not self.resources:
            violations.append("Sistemde denetlenecek hiçbir kaynak yapılandırması bulunmuyor.")
            return False, violations

        # Her bir kaynak üzerinde döngü kurulur
        for r_id, res in self.resources.items():
            # Kaynağın varsayılanları taranır
            issues = res.validate_defaults()
            # Her bir tespit edilen zaafiyet ihlallere eklenir
            for issue in issues:
                violations.append(f"CWE-1188 İHLALİ [{r_id} - {res.name}]: {issue.value}")

        # Eğer arıza modu FAIL_OPEN olarak yapılandırılmışsa ve geçerli can güvenliği token'ı yoksa
        if self.failure_mode == FailureHandlingMode.FAIL_OPEN:
            if self.safety_override_token != "EMERGENCY_LIFE_SAFETY_OVERRIDE":
                violations.append(
                    "CWE-636 İHLALİ: Sistem seviyesinde 'FAIL_OPEN' yapılandırılmış! "
                    "Yetkili acil can güvenliği (Life-Safety) gerekçesi olmaksızın fail-open kabul edilemez."
                )

        # İhlal yoksa denetim başarılıdır
        is_compliant = len(violations) == 0
        # Sonuç döndürülür
        return is_compliant, violations

    def enforce_secure_defaults(self) -> None:
        """
        Güvenli varsayılanlar denetimini icra eder; herhangi bir zaafiyet varsa istisna fırlatır.
        """
        # Denetim koşturulur
        passed, violations = self.audit_secure_defaults()
        # Eğer zaafiyet tespit edildiyse
        if not passed:
            # CWE-636 ihlali varsa InsecureFailOpenForbiddenError fırlatılır
            if any("CWE-636" in v for v in violations):
                raise InsecureFailOpenForbiddenError("Güvenli Kapanma İhlali (CWE-636):\n" + "\n".join(violations))
            # CWE-1188 ihlali varsa InsecureDefaultDetectedError fırlatılır
            raise InsecureDefaultDetectedError("Güvenli Olmayan Varsayılan İhlali (CWE-1188):\n" + "\n".join(violations))

    def evaluate_access(
        self,
        request: AccessRequest,
        simulate_failure: Optional[FailureType] = None
    ) -> DecisionResult:
        """
        Erişim talebini Saltzer-Schroeder Default-Deny ve Fail-Secure ilkeleriyle değerlendirir.
        
        Args:
            request: Erişim talep nesnesi.
            simulate_failure: Simüle edilecek arıza tipi (None ise normal çalışma).
            
        Returns:
            DecisionResult: Erişim kararı, gerekçesi ve hata müdahalesi durumu.
        """
        # Hedef kaynak kayıtlı mı kontrol edilir
        if request.resource_id not in self.resources:
            # Kayıtlı olmayan kaynak için Default-Deny devreye girer
            res = DecisionResult(
                request_id=request.request_id,
                decision=DecisionOutcome.DENY,
                reason=f"Kaynak '{request.resource_id}' sistemde tanımlı değil. Güvenli varsayılan RED uygulandı."
            )
            self._log_event("ACCESS_DENIED_UNKNOWN_RESOURCE", {"request_id": request.request_id})
            return res

        # ====================================================================
        # ADIM 1: SİSTEM ARIZASI VE FAIL-SECURE DENETİMİ (CWE-636)
        # ====================================================================
        if simulate_failure is not None:
            # Eğer arıza modu FAIL_SECURE ise erişim anında bloke edilir
            if self.failure_mode == FailureHandlingMode.FAIL_SECURE:
                res = DecisionResult(
                    request_id=request.request_id,
                    decision=DecisionOutcome.DENY,
                    reason=f"Sistem arızası tespit edildi ({simulate_failure.value}). "
                           f"Fail-Secure ilkesi gereğince tüm erişimler derhal BLOKE EDİLDİ (CWE-636 Koruması).",
                    is_fail_secure_intervention=True,
                    failure_encountered=simulate_failure
                )
                self._log_event(
                    "FAIL_SECURE_TRIGGERED",
                    {"request_id": request.request_id, "failure": simulate_failure.value}
                )
                return res
            # Eğer arıza modu FAIL_OPEN ise ve geçerli güvenlik token'ı yoksa
            elif self.failure_mode == FailureHandlingMode.FAIL_OPEN:
                if self.safety_override_token != "EMERGENCY_LIFE_SAFETY_OVERRIDE":
                    # Güvensiz fail-open yasaklama hatası fırlatılır (CWE-636)
                    raise InsecureFailOpenForbiddenError(
                        f"Kritik Güvenlik İhlali (CWE-636): '{simulate_failure.value}' arızasında "
                        f"yetkisiz fail-open izin verilemez!"
                    )
                else:
                    # Acil durum istisnası ile geçici açık geçiş
                    res = DecisionResult(
                        request_id=request.request_id,
                        decision=DecisionOutcome.PERMIT,
                        reason="DİKKAT: Acil durum can güvenliği istisnası ile Fail-Open uygulandı.",
                        is_fail_secure_intervention=False,
                        failure_encountered=simulate_failure
                    )
                    self._log_event("FAIL_OPEN_EMERGENCY_PERMIT", {"request_id": request.request_id})
                    return res

        # ====================================================================
        # ADIM 2: AÇIK KURAL EŞLEŞTİRMESİ
        # ====================================================================
        for r_id, rule in self.rules.items():
            # Rol, kaynak ve eylem tam eşleşiyor mu?
            if (rule.subject_role == request.subject_role and
                rule.resource_id == request.resource_id and
                rule.action == request.action):
                # Açık kural eşleşti, izin verilir
                res = DecisionResult(
                    request_id=request.request_id,
                    decision=rule.effect,
                    reason=f"Açık kural eşleşti: [{r_id}]. Rol: '{rule.subject_role}', Eylem: '{rule.action}'.",
                    matched_rule_id=r_id
                )
                self._log_event("ACCESS_PERMITTED_RULE", {"request_id": request.request_id, "rule_id": r_id})
                return res

        # ====================================================================
        # ADIM 3: SALTZER-SCHROEDER GÜVENLİ VARSAYILAN: DEFAULT-DENY
        # Hiçbir açık izin kuralı eşleşmediğinde varsayılan olarak REDDEDİLİR!
        # ====================================================================
        res = DecisionResult(
            request_id=request.request_id,
            decision=DecisionOutcome.DENY,
            reason="Açıkça tanımlanmış bir izin kuralı bulunamadı. "
                   "Saltzer-Schroeder 'Fail-Safe Defaults' prensibi gereği talep REDDEDİLDİ."
        )
        self._log_event("ACCESS_DENIED_DEFAULT_DENY", {"request_id": request.request_id})
        return res

    def generate_failsafe_report(self) -> str:
        """Markdown formatında kapsamlı Güvenli Varsayılanlar ve Fail-Safe Raporu üretir."""
        # Rapor satırları listesi başlatılır
        lines: List[str] = []
        lines.append(f"# {self.system_name} — Güvenli Varsayılanlar ve Fail-Safe Raporu")
        lines.append(f"**Rapor Tarihi:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Sistem Arıza Davranış Modu:** `{self.failure_mode.value}`")
        lines.append("")

        # 1. Kaynak Envanteri ve Varsayılan Yapılandırma Durumu
        lines.append("## 1. Kaynak Güvenlik Yapılandırması ve Varsayılanlar")
        lines.append("| Kaynak ID | Kaynak Adı | Varsayılan Erişim | Debug Modu | TLS Zorunlu | Varsayılan Parola | CORS Durumu | Depolama |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for r_id, res in self.resources.items():
            debug_str = "❌ AÇIK (Tehlikeli)" if res.debug_mode else "✅ Kapalı"
            tls_str = "✅ Zorunlu" if res.enforce_tls else "❌ Şifresiz"
            cred_str = "✅ Değiştirildi" if res.is_default_credential_changed else "❌ Varsayılan Aktif"
            cors_str = "❌ Herkese Açık (*)" if res.cors_allow_all else "✅ Kısıtlı"
            stor_str = "✅ Şifreli" if res.storage_encrypted else "❌ Şifresiz"
            lines.append(
                f"| {r_id} | {res.name} | {res.default_access} | {debug_str} | {tls_str} | {cred_str} | {cors_str} | {stor_str} |"
            )
        lines.append("")

        # 2. Kurumsal Güvenlik Denetim Özeti
        lines.append("## 2. Kurumsal Standartlara Uyum ve Zaafiyet Analizi")
        passed, violations = self.audit_secure_defaults()
        if passed:
            lines.append("> [!NOTE]\n> **TAM UYUMLU:** Tüm sistem bileşenleri 'Secure by Default' prensiplerine uygundur. "
                         "Hiçbir CWE-1188 veya CWE-636 zaafiyeti tespit edilmemiştir.")
        else:
            lines.append(f"> [!WARNING]\n> **GÜVENLİK İHLALLERİ TESPİT EDİLDİ ({len(violations)} Adet):**")
            for v in violations:
                lines.append(f"> - {v}")
        lines.append("")

        # 3. Tanımlı Açık İzin Kuralları
        lines.append("## 3. Açık Yetki Kuralları (Saltzer-Schroeder Kural İstisnaları)")
        lines.append("| Kural ID | Rol | Hedef Kaynak | Eylem | Karar |")
        lines.append("|---|---|---|---|---|")
        for r_id, rule in self.rules.items():
            lines.append(f"| {r_id} | {rule.subject_role} | {rule.resource_id} | {rule.action} | {rule.effect.value} |")
        lines.append("")

        # Metin birleştirilip döndürülür
        return "\n".join(lines)

    def export_summary_dict(self) -> Dict[str, Any]:
        """Tüm mimariyi JSON sözlük formatında döndürür."""
        return {
            "system_name": self.system_name,
            "failure_mode": self.failure_mode.name,
            "resources_count": len(self.resources),
            "rules_count": len(self.rules),
            "resources": [
                {
                    "resource_id": r.resource_id,
                    "name": r.name,
                    "default_access": r.default_access,
                    "debug_mode": r.debug_mode,
                    "enforce_tls": r.enforce_tls,
                    "is_default_credential_changed": r.is_default_credential_changed,
                    "cors_allow_all": r.cors_allow_all,
                    "storage_encrypted": r.storage_encrypted
                }
                for r in self.resources.values()
            ],
            "rules": [
                {
                    "rule_id": rl.rule_id,
                    "subject_role": rl.subject_role,
                    "resource_id": rl.resource_id,
                    "action": rl.action,
                    "effect": rl.effect.name
                }
                for rl in self.rules.values()
            ]
        }
