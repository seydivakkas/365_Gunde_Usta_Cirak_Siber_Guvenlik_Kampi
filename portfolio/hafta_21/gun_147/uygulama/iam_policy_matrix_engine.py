"""
Gün 147: Mini Proje 20 — Kurumsal IAM Politika Matrisi ve Güvenlik Motoru
=========================================================================
Bu modül; Hafta 21'in tüm konularını (Active Directory, Kerberos v5,
Group Policy, JML ve SoD) tek bir bütünleşik kurumsal mimaride birleştiren,
Microsoft Enterprise Access Model (Tier 0 / Tier 1 / Tier 2) izolasyonunu,
RBAC/ABAC politikalarını, Kerberos kısıtlamalarını ve Sıfır Güven (Zero Trust)
koşullu erişim kurallarını denetleyen endüstriyel sınıf bir güvenlik motorudur.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
import json
import re
import uuid


class TierLevel(str, Enum):
    """Microsoft Enterprise Access Model Katman Seviyeleri."""
    TIER_0 = "TIER_0"  # Kimlik Düzlemi: Domain Controllers, PKI, AAD Connect, Tier-0 PAW
    TIER_1 = "TIER_1"  # Kurumsal Sunucular: Veritabanları, Uygulama ve Depolama Sunucuları
    TIER_2 = "TIER_2"  # Kullanıcı Uç Noktaları: İş İstasyonları, Taşınabilir Cihazlar, Yazıcılar


class DecisionType(str, Enum):
    """Erişim değerlendirme karar sonuçları."""
    PERMIT = "PERMIT"  # Erişime izin verildi
    DENY = "DENY"      # Erişim güvenlik politikası gereği engellendi


class Severity(str, Enum):
    """Denetim zafiyet önem dereceleri."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DelegationType(str, Enum):
    """Kerberos Yetki Devri (Delegation) Güvenlik Türleri."""
    NONE = "NONE"                          # Yetki devri kapalı (En güvenli)
    UNCONSTRAINED = "UNCONSTRAINED"        # Kısıtlamasız yetki devri (Kritik zafiyet / TGT çalınabilir)
    CONSTRAINED_S4U = "CONSTRAINED_S4U"    # Kısıtlı yetki devri (Belirli SPN'lere izinli)
    RBCD = "RBCD"                          # Kaynak Tabanlı Kısıtlı Yetki Devri (En modern ve güvenli)


@dataclass
class SubjectContext:
    """Erişim talebinde bulunan özne (kullanıcı/servis) ve bağlam nitelikleri (ABAC)."""
    user_id: str
    username: str
    roles: List[str]
    tier_level: TierLevel
    department: str
    is_employee_active: bool
    mfa_authenticated: bool
    device_compliant: bool
    source_ip: str
    is_trusted_network: bool
    risk_score: float = 0.0  # 0.0 (Düşük risk) ile 1.0 (Yüksek/İmkansız Seyahat)
    last_logon_date: Optional[str] = None


@dataclass
class ResourceTarget:
    """Erişilmek istenen hedef kaynak, sunucu veya uygulama."""
    resource_id: str
    name: str
    target_tier: TierLevel
    service_type: str  # AD_DC, SQL_DATABASE, WEB_PORTAL, FILE_SHARE, WORKSTATION
    spn: Optional[str] = None
    delegation_type: DelegationType = DelegationType.NONE
    requires_mfa: bool = True
    allowed_roles: List[str] = field(default_factory=list)


@dataclass
class AccessDecision:
    """Erişim denetim motorunun ürettiği karar ve ayrıntılı gerekçe."""
    decision: DecisionType
    reason: str
    matched_rule: str
    subject_user: str
    target_resource: str
    timestamp: str
    audit_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SoDRule:
    """Görevler Ayrılığı (Separation of Duties) kuralı."""
    rule_id: str
    role_a: str
    role_b: str
    description: str
    severity: Severity = Severity.CRITICAL


@dataclass
class MatrixAuditFinding:
    """Politika matrisi denetiminde bulunan zafiyet veya uyumsuzluk."""
    rule_id: str
    title: str
    severity: Severity
    affected_entity: str
    details: str
    remediation: str


@dataclass
class MatrixAuditSummary:
    """IAM Politika Matrisi Genel Denetim Rapor Özeti."""
    total_subjects: int
    total_resources: int
    tier_violations_count: int
    sod_violations_count: int
    unconstrained_delegation_count: int
    orphan_accounts_count: int
    overprivileged_subjects_count: int
    overall_security_score: float
    is_compliant: bool
    findings: List[MatrixAuditFinding]


class IAMPolicyMatrixEngine:
    """
    Mini Proje 20: Bütünleşik Kurumsal IAM Politika Matrisi Motoru.
    
    Bu motor;
    1. Katman İzolasyonunu (Tier 0 / Tier 1 / Tier 2) denetler. Üst katman
       kimliklerinin alt katman makinelerinde oturum açmasını (Pass-the-Hash /
       Credential Theft koruması) ve alt katmanların üst katmana doğrudan
       erişmesini engeller.
    2. RBAC (Rol Tabanlı) ve ABAC (Öznitelik Tabanlı: MFA, Cihaz Uyumluluğu,
       Risk Puanı, Ağ Güvenilirliği) birleşimli Zero Trust karar mekanizması işletir.
    3. Kerberos Delegation açıklarını (Unconstrained Delegation) yakalar.
    4. Görevler Ayrılığı (SoD) zehirli kombinasyonlarını tespit eder.
    5. İK kaynağıyla eşleşmeyen Yetim Hesapları (Orphan Accounts) dondurur.
    """

    def __init__(self):
        # Kayıtlı kullanıcı/özne bağlamları sözlüğü
        self.subjects: Dict[str, SubjectContext] = {}
        # Kayıtlı hedef kaynaklar sözlüğü
        self.resources: Dict[str, ResourceTarget] = {}
        # Tanımlanmış SoD kuralları listesi
        self.sod_rules: List[SoDRule] = []
        # Katman seviyesi öncelik sıralaması
        self.tier_hierarchy = {
            TierLevel.TIER_0: 0,
            TierLevel.TIER_1: 1,
            TierLevel.TIER_2: 2
        }

    def register_subject(self, subject: SubjectContext) -> None:
        """Sisteme kullanıcı veya servis hesabı bağlamı kaydeder."""
        self.subjects[subject.user_id] = subject

    def register_resource(self, resource: ResourceTarget) -> None:
        """Sisteme hedef sunucu veya kaynak kaydeder."""
        self.resources[resource.resource_id] = resource

    def register_sod_rule(self, rule: SoDRule) -> None:
        """Sisteme Görevler Ayrılığı (SoD) kuralı ekler."""
        self.sod_rules.append(rule)

    def load_matrix_spec(self, spec: Dict[str, Any]) -> None:
        """JSON spesifikasyonundan kurumsal politika matrisini yükler."""
        # SoD kurallarını yükle
        for s in spec.get("sod_rules", []):
            self.register_sod_rule(SoDRule(
                rule_id=s["rule_id"],
                role_a=s["role_a"],
                role_b=s["role_b"],
                description=s["description"],
                severity=Severity(s.get("severity", "CRITICAL"))
            ))

        # Hedef kaynakları yükle
        for res in spec.get("resources", []):
            self.register_resource(ResourceTarget(
                resource_id=res["resource_id"],
                name=res["name"],
                target_tier=TierLevel(res["target_tier"]),
                service_type=res["service_type"],
                spn=res.get("spn"),
                delegation_type=DelegationType(res.get("delegation_type", "NONE")),
                requires_mfa=res.get("requires_mfa", True),
                allowed_roles=res.get("allowed_roles", [])
            ))

        # Kullanıcı / Özne kayıtlarını yükle
        for sub in spec.get("subjects", []):
            self.register_subject(SubjectContext(
                user_id=sub["user_id"],
                username=sub["username"],
                roles=sub.get("roles", []),
                tier_level=TierLevel(sub["tier_level"]),
                department=sub["department"],
                is_employee_active=sub.get("is_employee_active", True),
                mfa_authenticated=sub.get("mfa_authenticated", False),
                device_compliant=sub.get("device_compliant", True),
                source_ip=sub.get("source_ip", "10.0.0.1"),
                is_trusted_network=sub.get("is_trusted_network", True),
                risk_score=float(sub.get("risk_score", 0.0)),
                last_logon_date=sub.get("last_logon_date")
            ))

    def evaluate_access(
        self,
        user_id: str,
        resource_id: str,
        action: str = "ACCESS"
    ) -> AccessDecision:
        """
        Sıfır Güven (Zero Trust) ve Katman İzolasyonlu Dinamik Erişim Değerlendirmesi.
        
        Kontrol Adımları:
        1. Varlık varlığı ve İK çalışan aktiflik kontrolü (Yetim hesap engeli).
        2. Tier İzolasyonu (Katman Kuralı):
           - Tier-0 hesabı Tier-2 makinesinde veya kaynağında oturum açamaz.
           - Tier-2 hesabı doğrudan Tier-0 DC'ye erişemez (PAW zorunluluğu).
        3. RBAC Yetki Kontrolü: Kullanıcının rolleri kaynağın izinli rolleriyle eşleşiyor mu?
        4. ABAC Koşullu Erişim Kontrolü:
           - MFA zorunluluğu (Tier-0 ve Tier-1 için tavizsiz).
           - Cihaz Uyumluluğu (Compliant Device).
           - Kimlik Risk Puanı (< 0.70 olmalı, aksi halde engelle).
        5. SoD Çatışma Denetimi: Kullanıcının üzerindeki zehirli rol kombinasyonları.
        """
        now_ts = datetime.now(timezone.utc).isoformat()

        # 1. Özne ve kaynak varlık denetimi
        if user_id not in self.subjects:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason="Erişim reddedildi: Özne (kullanıcı) kimliği sistemde kayıtlı değil.",
                matched_rule="RULE-SUBJECT-NOT-FOUND",
                subject_user=user_id,
                target_resource=resource_id,
                timestamp=now_ts
            )

        if resource_id not in self.resources:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason="Erişim reddedildi: Hedef kaynak kimliği sistemde kayıtlı değil.",
                matched_rule="RULE-RESOURCE-NOT-FOUND",
                subject_user=user_id,
                target_resource=resource_id,
                timestamp=now_ts
            )

        sub = self.subjects[user_id]
        res = self.resources[resource_id]

        # 2. İK Yaşam Döngüsü (Leaver / Yetim Hesap) Kontrolü
        if not sub.is_employee_active:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason=f"Erişim engellendi: '{sub.username}' kullanıcısının İK ilişiği kesilmiştir (Yetim Hesap Engeli).",
                matched_rule="RULE-LEAVER-ORPHAN-BLOCKED",
                subject_user=sub.username,
                target_resource=res.name,
                timestamp=now_ts,
                audit_data={"employee_active": False}
            )

        # 3. Microsoft Enterprise Access Katman İzolasyonu (Tiering Enforcement)
        # Kural A: Tier-0 ayrıcalıklı hesabı asla alt katman (Tier-1 veya Tier-2) iş istasyonu/servisine bağlanamaz!
        if sub.tier_level == TierLevel.TIER_0 and res.target_tier != TierLevel.TIER_0:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason=f"Tiering İhlali Engellendi: Tier-0 yöneticisi '{sub.username}', alt katmandaki '{res.name}' ({res.target_tier.value}) kaynağında oturum açamaz (Credential Dumping Koruması).",
                matched_rule="RULE-TIER0-DOWNWARD-LOGON-DENIED",
                subject_user=sub.username,
                target_resource=res.name,
                timestamp=now_ts,
                audit_data={"subject_tier": sub.tier_level.value, "target_tier": res.target_tier.value}
            )

        # Kural B: Tier-2 standart kullanıcısı doğrudan Tier-0 Kimlik Kaynağına (DC vb.) bağlanamaz!
        if sub.tier_level == TierLevel.TIER_2 and res.target_tier == TierLevel.TIER_0:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason=f"Tiering İhlali Engellendi: Standart Tier-2 kullanıcısı '{sub.username}', kritik Tier-0 kaynağına '{res.name}' doğrudan erişemez (Yalnızca PAW ve Tier-0 hesapları erişebilir).",
                matched_rule="RULE-TIER2-UPWARD-ACCESS-DENIED",
                subject_user=sub.username,
                target_resource=res.name,
                timestamp=now_ts,
                audit_data={"subject_tier": sub.tier_level.value, "target_tier": res.target_tier.value}
            )

        # 4. RBAC Rol Kontrolü (Role-Based Access Control)
        # Kaynak üzerinde tanımlı roller varsa, kullanıcının en az birine sahip olması gerekir
        if res.allowed_roles:
            has_role = any(r in res.allowed_roles for r in sub.roles)
            if not has_role:
                return AccessDecision(
                    decision=DecisionType.DENY,
                    reason=f"Yetki Yetersiz: '{sub.username}' kullanıcısının rolleri ({sub.roles}) '{res.name}' kaynağının izin verilen rollerini ({res.allowed_roles}) karşılamıyor.",
                    matched_rule="RULE-RBAC-ROLE-MISMATCH",
                    subject_user=sub.username,
                    target_resource=res.name,
                    timestamp=now_ts,
                    audit_data={"user_roles": sub.roles, "allowed_roles": res.allowed_roles}
                )

        # 5. ABAC ve Sıfır Güven (Zero Trust) Koşullu Erişim Kontrolleri
        # 5a. Çok Faktörlü Kimlik Doğrulama (MFA) Zorunluluğu
        if res.requires_mfa and not sub.mfa_authenticated:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason=f"Koşullu Erişim Engeli: '{res.name}' kaynağı Çok Faktörlü Kimlik Doğrulama (MFA) zorunlu tutmaktadır.",
                matched_rule="RULE-ABAC-MFA-REQUIRED",
                subject_user=sub.username,
                target_resource=res.name,
                timestamp=now_ts,
                audit_data={"mfa_authenticated": False}
            )

        # 5b. Cihaz Güvenliği ve Uyumluluk (Device Compliance)
        if not sub.device_compliant:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason=f"Cihaz Güvenliği Engeli: '{sub.username}' kullanıcısının bağlandığı cihaz kurumsal güvenlik uyumluluk şartlarını sağlamıyor (Non-compliant Device).",
                matched_rule="RULE-ABAC-DEVICE-NON-COMPLIANT",
                subject_user=sub.username,
                target_resource=res.name,
                timestamp=now_ts,
                audit_data={"device_compliant": False}
            )

        # 5c. Kullanıcı / Oturum Risk Skoru (Risk-based Access)
        if sub.risk_score >= 0.70:
            return AccessDecision(
                decision=DecisionType.DENY,
                reason=f"Risk Tabanlı Erişim Engeli: Kullanıcının oturum risk puanı ({sub.risk_score:.2f}) kabul edilebilir eşik değerin (0.70) üzerindedir (Olası Ele Geçirilmiş Hesap / İmkansız Seyahat).",
                matched_rule="RULE-ABAC-HIGH-RISK-SESSION",
                subject_user=sub.username,
                target_resource=res.name,
                timestamp=now_ts,
                audit_data={"risk_score": sub.risk_score}
            )

        # 6. Görevler Ayrılığı (SoD) Zehirli Kombinasyon Denetimi
        user_role_set = set(sub.roles)
        for sod in self.sod_rules:
            if sod.role_a in user_role_set and sod.role_b in user_role_set:
                return AccessDecision(
                    decision=DecisionType.DENY,
                    reason=f"Görevler Ayrılığı (SoD) İhlali: Kullanıcı birbiriyle çatışan rollere ({sod.role_a} & {sod.role_b}) sahip olduğu için işlem durduruldu ({sod.rule_id}).",
                    matched_rule="RULE-SOD-TOXIC-COMBINATION",
                    subject_user=sub.username,
                    target_resource=res.name,
                    timestamp=now_ts,
                    audit_data={"sod_rule_id": sod.rule_id}
                )

        # Tüm güvenlik kontrolleri başarıyla geçildi: ERİŞİM ONAYLANDI (PERMIT)
        return AccessDecision(
            decision=DecisionType.PERMIT,
            reason=f"Erişim İzin Verildi: Tiering ({sub.tier_level.value}), RBAC rolleri ve Sıfır Güven ABAC koşulları tam olarak sağlandı.",
            matched_rule="RULE-ZERO-TRUST-PERMIT",
            subject_user=sub.username,
            target_resource=res.name,
            timestamp=now_ts,
            audit_data={"tier": sub.tier_level.value, "mfa": True, "device_ok": True}
        )

    def audit_entire_matrix(self) -> MatrixAuditSummary:
        """Kurumsal IAM Politika Matrisini baştan sona denetler ve zafiyet raporu üretir."""
        findings: List[MatrixAuditFinding] = []
        tier_violations = 0
        sod_violations = 0
        unconstrained_count = 0
        orphan_count = 0
        overprivileged_count = 0

        now_utc = datetime.now(timezone.utc)

        # 1. DENETİM: Hedef Sistemlerde Kısıtlamasız Yetki Devri (Unconstrained Delegation)
        for res in self.resources.values():
            if res.delegation_type == DelegationType.UNCONSTRAINED:
                unconstrained_count += 1
                findings.append(MatrixAuditFinding(
                    rule_id="MAT-KERB-01",
                    title="Kısıtlamasız Kerberos Yetki Devri (Unconstrained Delegation) Tespit Edildi",
                    severity=Severity.CRITICAL,
                    affected_entity=res.name,
                    details=f"Kaynak '{res.name}' ({res.spn}) unconstrained delegation kullanıyor. Sunucu ele geçirilirse gelen tüm yöneticilerin TGT biletleri belleğe düşer.",
                    remediation=f"Yetki devrini Kaynak Tabanlı Kısıtlı Yetki Devrine (RBCD) dönüştürün: Set-ADComputer -Identity '{res.name}' -TrustedForDelegation $false"
                ))

        # 2. DENETİM: Yetim Hesaplar (Orphan Accounts)
        for sub in self.subjects.values():
            if not sub.is_employee_active:
                orphan_count += 1
                findings.append(MatrixAuditFinding(
                    rule_id="MAT-JML-01",
                    title="İlişiği Kesilmiş Personele Ait Kapatılmamış Hesap (Orphan Account)",
                    severity=Severity.CRITICAL,
                    affected_entity=sub.username,
                    details=f"Kullanıcı '{sub.username}' İK sisteminde aktif görünmüyor ancak IAM matrisinde hesap kaydı açık.",
                    remediation=f"Hesabı derhal kapatın ve oturum jetonlarını sonlandırın: Disable-ADAccount -Identity '{sub.username}'"
                ))

        # 3. DENETİM: Görevler Ayrılığı (SoD) Çatışmaları
        for sub in self.subjects.values():
            role_set = set(sub.roles)
            for sod in self.sod_rules:
                if sod.role_a in role_set and sod.role_b in role_set:
                    sod_violations += 1
                    findings.append(MatrixAuditFinding(
                        rule_id="MAT-SOD-01",
                        title=f"Görevler Ayrılığı (SoD) Zehirli Kombinasyonu: {sod.rule_id}",
                        severity=sod.severity,
                        affected_entity=sub.username,
                        details=f"'{sub.username}' kullanıcısı birbiriyle çatışan rollere sahip: '{sod.role_a}' ve '{sod.role_b}'. {sod.description}",
                        remediation=f"Kullanıcının görev tanımını inceleyin ve çatışan rollerden birini derhal geri alın (Revoke)."
                    ))

        # 4. DENETİM: Tier-0 Hesaplarında Güvensiz Yapılandırma (MFA Yokluğu)
        for sub in self.subjects.values():
            if sub.tier_level == TierLevel.TIER_0 and not sub.mfa_authenticated:
                findings.append(MatrixAuditFinding(
                    rule_id="MAT-TIER-01",
                    title="Tier-0 Ayrıcalıklı Yönetici Hesabında MFA Eksikliği",
                    severity=Severity.CRITICAL,
                    affected_entity=sub.username,
                    details=f"Tier-0 yöneticisi '{sub.username}' Çok Faktörlü Kimlik Doğrulama (MFA) olmaksızın yetkilendirilmiş.",
                    remediation="Tier-0 kimlikleri için donanım tabanlı FIDO2 anahtarı veya PAM çözümü zorunlu kılınmalıdır."
                ))

        # 5. DENETİM: Aşırı Yetki (Over-Privileged) ve Yetki Birikimi
        for sub in self.subjects.values():
            # Kullanıcının 3'ten fazla farklı hassas role sahip olması veya alt katman kullanıcısının Tier-0 rolü taşıması
            if sub.tier_level != TierLevel.TIER_0 and any("ADMIN" in r.upper() or "TIER0" in r.upper() for r in sub.roles):
                overprivileged_count += 1
                findings.append(MatrixAuditFinding(
                    rule_id="MAT-PRIV-01",
                    title="Aşırı Yetkilendirme (Over-Privileged / Katman Atlama)",
                    severity=Severity.HIGH,
                    affected_entity=sub.username,
                    details=f"Alt katmandaki '{sub.username}' ({sub.tier_level.value}) kullanıcısına Tier-0 yönetici rolleri atanmış.",
                    remediation="Ayrıcalıklı rolleri kaldırın, Tiering hiyerarşisine uygun PAW (Privileged Access Workstation) modeli uygulayın."
                ))

        # Puanlama hesabı
        penalty = (
            unconstrained_count * 25.0 +
            orphan_count * 25.0 +
            sod_violations * 20.0 +
            overprivileged_count * 15.0
        )
        # Ek kritik bulguları da cezalandır
        for f in findings:
            if f.rule_id == "MAT-TIER-01":
                penalty += 20.0

        calculated_score = max(0.0, min(100.0, 100.0 - penalty))

        return MatrixAuditSummary(
            total_subjects=len(self.subjects),
            total_resources=len(self.resources),
            tier_violations_count=tier_violations,
            sod_violations_count=sod_violations,
            unconstrained_delegation_count=unconstrained_count,
            orphan_accounts_count=orphan_count,
            overprivileged_subjects_count=overprivileged_count,
            overall_security_score=calculated_score,
            is_compliant=(len(findings) == 0),
            findings=findings
        )

    def generate_remediation_powershell(self, audit: MatrixAuditSummary) -> str:
        """Denetimde tespit edilen zafiyetler için otomatik PowerShell sertleştirme betiği üretir."""
        lines = [
            "# =====================================================================",
            "# GÜN 147: MİNİ PROJE 20 — IAM POLİTİKA MATRİSİ SERTLEŞTİRME BETİĞİ (PS1)",
            "# Katman İzolasyonu, Kerberos Kısıtlaması, Yetim Hesap ve SoD Düzeltmesi",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.",
            "# =====================================================================",
            "$ErrorActionPreference = 'Stop'",
            "Write-Host '[+] Kurumsal IAM Politika Matrisi Sertleştirmesi Başlatılıyor...' -ForegroundColor Cyan",
            ""
        ]

        if not audit.findings:
            lines.append("Write-Host '[*] Harika! Politika matrisi kusursuz. Uygulanacak düzeltme işlemi bulunamadı.' -ForegroundColor Green")
            return "\n".join(lines)

        for f in audit.findings:
            if f.rule_id == "MAT-KERB-01":
                lines.append(f"# {f.title}: {f.affected_entity}")
                lines.append(f"Write-Host '[!] Kısıtlamasız Kerberos Yetki Devri Kapatılıyor: {f.affected_entity}' -ForegroundColor Yellow")
                lines.append(f"try {{")
                lines.append(f"    Set-ADComputer -Identity '{f.affected_entity}' -TrustedForDelegation $false")
                lines.append(f"    Write-Host '  [OK] Unconstrained delegation başarıyla kapatıldı.' -ForegroundColor Green")
                lines.append(f"}} catch {{")
                lines.append(f"    Write-Warning '  [HATA] Yetki devri kapatılamadı: $_'")
                lines.append(f"}}")
                lines.append("")
            elif f.rule_id == "MAT-JML-01":
                lines.append(f"# {f.title}: {f.affected_entity}")
                lines.append(f"Write-Host '[!] Yetim Hesap Donduruluyor: {f.affected_entity}' -ForegroundColor Yellow")
                lines.append(f"try {{")
                lines.append(f"    Disable-ADAccount -Identity '{f.affected_entity}' -Confirm:$false")
                lines.append(f"    Revoke-MgUserAllRefreshToken -UserId '{f.affected_entity}@kurum.local'")
                lines.append(f"    Write-Host '  [OK] {f.affected_entity} hesabı kapatıldı ve oturum jetonları iptal edildi.' -ForegroundColor Green")
                lines.append(f"}} catch {{")
                lines.append(f"    Write-Warning '  [HATA] Hesap kapatılamadı: $_'")
                lines.append(f"}}")
                lines.append("")
            elif f.rule_id == "MAT-TIER-01":
                lines.append(f"# {f.title}: {f.affected_entity}")
                lines.append(f"Write-Host '[!] Tier-0 yöneticisinde MFA zorlanıyor: {f.affected_entity}' -ForegroundColor Yellow")
                lines.append(f"# Conditional Access politikasıyla Tier-0 PAW ve FIDO2 MFA zorunlu kılınmalı")
                lines.append("")

        lines.append("Write-Host '[+] IAM Politika Matrisi sertleştirme adımları tamamlandı.' -ForegroundColor Cyan")
        return "\n".join(lines)

    def generate_matrix_summary_json(self) -> Dict[str, Any]:
        """Tüm politika ve uyumluluk mimarisini gösteren özet matris sözlüğü üretir."""
        return {
            "proje": "Mini Proje 20: Kurumsal IAM Politika Matrisi",
            "mimari": "Microsoft Enterprise Access Model & Zero Trust ABAC",
            "katmanlar": {
                "TIER_0": {
                    "tanim": "Kimlik Düzlemi ve Kritik Güvenlik Çekirdeği",
                    "varliklar": ["Domain Controllers", "AD FS", "PKI/CA", "AAD Connect", "Tier-0 PAW"],
                    "guvenlik_kurali": "Asla alt katmanlarda oturum açamaz. FIDO2 MFA ve PAW zorunludur."
                },
                "TIER_1": {
                    "tanim": "Kurumsal Uygulama ve Sunucu Düzlemi",
                    "varliklar": ["Uygulama Sunucuları", "SQL Veritabanları", "Bulut İş Yükleri"],
                    "guvenlik_kurali": "Yalnızca LAPS ve PAM ile yönetilir. Tier-2 doğrudan erişemez."
                },
                "TIER_2": {
                    "tanim": "Kullanıcı ve Uç Nokta Düzlemi",
                    "varliklar": ["İş İstasyonları", "Yazıcılar", "Mobil Cihazlar"],
                    "guvenlik_kurali": "Yatay geçiş (Pass-the-Hash) engellenmeli, LAPS aktif olmalıdır."
                }
            },
            "standartlar": [
                "NIST SP 800-207 Zero Trust Architecture",
                "Microsoft Enterprise Access Model (Privileged Access Tiering)",
                "CIS Microsoft Windows Server Benchmark (Tiering & Kerberos)",
                "SOX 404 Separation of Duties (SoD) Framework",
                "RFC 4120 Kerberos V5 & RFC 7644 SCIM 2.0"
            ]
        }
