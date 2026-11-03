# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 117: RBAC (Role-Based Access Control) ve ABAC (Attribute-Based Access Control)
Referans Güvenlik Motoru (NIST ANSI/INCITS 359-2004 & NIST SP 800-162 Standartları).

Bu modül, kaba taneli (coarse-grained) rol tabanlı yetkilendirme (RBAC) ile
bağlamsal, ince taneli (fine-grained) öznitelik tabanlı yetkilendirmeyi (ABAC)
hibrit bir yapıda birleştiren kurumsal erişim kontrol motorunu sunar.
"""

# JSON veri serileştirme ve yapılandırma işlemleri için standart kütüphane
import json
# Zaman damgaları ve denetim kayıtları için datetime modülü
import datetime
# Güvenli IP adresi ve CIDR blok doğrulamaları için ipaddress modülü
import ipaddress
# Benzersiz denetim ve istek takip kimlikleri (UUID) üretimi için uuid modülü
import uuid
# Veri yapılarını tip güvenli ve okunaklı tanımlamak için dataclass
from dataclasses import dataclass, field
# Tip ipuçları ve statik analiz desteği için typing modülü
from typing import Dict, List, Set, Optional, Any, Tuple


# ==============================================================================
# 1. GÜVENLİK İSTİSNALARI HİYERARŞİSİ (CWE MAPPING)
# ==============================================================================

class AccessControlSecurityError(Exception):
    """Erişim kontrolü ve yetkilendirme altyapısı temel güvenlik istisnası."""
    pass


class RBACPermissionDeniedError(AccessControlSecurityError):
    """CWE-862: Rol tabanlı yetki eksikliği durumunda fırlatılır."""
    pass


class RBACSoDRuleConflictError(AccessControlSecurityError):
    """CWE-863: Görevler Ayrılığı (Separation of Duties - SoD) ihlalinde fırlatılır."""
    pass


class ABACPolicyDeniedError(AccessControlSecurityError):
    """CWE-862 / CWE-863: Öznitelik tabanlı ilke değerlendirmesi reddedildiğinde fırlatılır."""
    pass


class EnvironmentalConstraintError(ABACPolicyDeniedError):
    """CWE-284: Zaman, coğrafi konum veya ağ kısıtlaması ihlalinde fırlatılır."""
    pass


class MultiTenantIsolationBreachError(AccessControlSecurityError):
    """CWE-284 / CWE-639: Farklı kiracı (tenant) kaynağına yetkisiz erişim girişiminde fırlatılır."""
    pass


class ClassificationClearanceInsufficientError(ABACPolicyDeniedError):
    """CWE-285: Kullanıcının güvenlik yetki seviyesi belgenin gizliliğini karşılamadığında fırlatılır."""
    pass


class MissingContextAttributeError(AccessControlSecurityError):
    """CWE-20: Karar için zorunlu olan özniteliğin eksik olması durumunda fırlatılır."""
    pass


# ==============================================================================
# 2. VERİ MODELLERİ VE BAĞLAM (CONTEXT) TANIMLARI
# ==============================================================================

@dataclass
class SubjectContext:
    """İsteği yapan özneye (kullanıcı/servis) ait statik ve dinamik öznitelikler."""
    # Kullanıcının tekil sistem kimliği
    user_id: str
    # Kullanıcıya atanmış roller kümesi
    roles: Set[str] = field(default_factory=set)
    # Kullanıcının bağlı olduğu departman (örn: 'finance', 'it', 'hr')
    department: str = "general"
    # Güvenlik izin seviyesi (1: Kamu/Açık, 2: Dahili, 3: Gizli, 4: Çok Gizli)
    clearance_level: int = 1
    # Kurumsal çok kiracılı mimari için kiracı kimliği
    tenant_id: str = "tenant_default"
    # Çok faktörlü kimlik doğrulama (MFA) oturum teyit durumu
    mfa_authenticated: bool = False
    # İsteğin geldiği istemci IP adresi
    ip_address: str = "127.0.0.1"


@dataclass
class ResourceContext:
    """Erişilmek istenen kaynağa (dosya, veri, kayıt) ait öznitelikler."""
    # Kaynağın tekil kimliği
    resource_id: str
    # Kaynağın türü (örn: 'financial_report', 'source_code', 'audit_log')
    resource_type: str
    # Kaynağın ait olduğu departman
    department_owner: str
    # Kaynağın gizlilik sınıflandırma seviyesi (1-4)
    classification: int = 1
    # Kaynağın ait olduğu kiracı kimliği
    tenant_id: str = "tenant_default"
    # Kaynağın arşiv veya kilit durumu (değişikliğe kapalı mı?)
    is_locked: bool = False


@dataclass
class ActionContext:
    """Kaynak üzerinde icra edilmek istenen işlem/eylem."""
    # Eylem adı (örn: 'read', 'write', 'delete', 'export')
    name: str


@dataclass
class EnvironmentContext:
    """Erişim anındaki çevresel ve durumsal öznitelikler."""
    # İsteğin yapıldığı güncel tarih ve saat
    timestamp: datetime.datetime
    # Mesai saati içi olup olmadığı (Hafta içi 08:00 - 18:00)
    is_business_hours: bool
    # İstek kaynağının güvenilir iç ağda olup olmadığı
    is_corporate_network: bool
    # Dinamik risk puanı (0-100 arası; 70 üzeri yüksek risk)
    risk_score: int = 10


@dataclass
class AccessDecision:
    """Erişim kontrol motorunun ürettiği nihai karar ve denetim izi."""
    # Erişime izin verildi mi?
    is_allowed: bool
    # Kararı veren model türü ('RBAC', 'ABAC', 'HYBRID')
    model_used: str
    # Karara bağlayan kural veya ilke açıklaması
    decision_rule: str
    # Ret veya izin gerekçeleri listesi
    reasons: List[str]
    # Denetim (Audit) logları için tekil takip kimliği
    audit_id: str


# ==============================================================================
# 3. RBAC MOTORU (ROLE-BASED ACCESS CONTROL - NIST ANSI 359)
# ==============================================================================

class RBACEngine:
    """
    NIST Seviye 2 Hiyerarşik Rol Tabanlı Erişim Kontrolü ve
    Statik Görevler Ayrılığı (Static Separation of Duties - SSD) Motoru.
    """

    def __init__(self):
        # Rol hiyerarşisi haritası: Üst Rol -> Miras Alınan Alt Roller Kümesi
        self.role_hierarchy: Dict[str, Set[str]] = {}
        # Rol - İzin haritası: Rol Adı -> Sahip Olunan İzinler Kümesi ('resource:action')
        self.role_permissions: Dict[str, Set[str]] = {}
        # Görevler Ayrılığı (SoD) çakışma kuralları: Birbirini dışlayan rol çiftleri
        self.sod_conflicts: List[Tuple[str, str]] = []

    def add_role_hierarchy(self, parent_role: str, child_roles: Set[str]) -> None:
        """Üst rolün alt rollerin yetkilerini miras almasını sağlayan ilişkiyi ekler."""
        # Sözlükte üst rol kaydı yoksa yeni bir küme oluşturulur
        if parent_role not in self.role_hierarchy:
            # Boş küme atanır
            self.role_hierarchy[parent_role] = set()
        # Verilen alt roller miras kümesine dahil edilir
        self.role_hierarchy[parent_role].update(child_roles)

    def assign_permissions_to_role(self, role: str, permissions: Set[str]) -> None:
        """Belirtilen role doğrudan izin kümesi atar."""
        # Role ait izin kümesi tanımlı değilse başlatılır
        if role not in self.role_permissions:
            # Boş küme oluşturulur
            self.role_permissions[role] = set()
        # İzinler role eklenir
        self.role_permissions[role].update(permissions)

    def add_sod_conflict(self, role_a: str, role_b: str) -> None:
        """CWE-863: Birlikte tutulması yasak olan iki rolü (SoD çatışması) kaydeder."""
        # Çift yönlü çatışma kuralı listeye eklenir
        self.sod_conflicts.append((role_a, role_b))

    def validate_sod_compliance(self, user_roles: Set[str]) -> None:
        """Kullanıcının sahip olduğu rollerin SoD kurallarını ihlal edip etmediğini denetler."""
        # Tanımlı tüm çatışan çiftler tek tek taranır
        for role_a, role_b in self.sod_conflicts:
            # Eğer kullanıcı her iki çatışan role de aynı anda sahipse
            if role_a in user_roles and role_b in user_roles:
                # Güvenlik istisnası fırlatılarak yetkilendirme engellenir (CWE-863)
                raise RBACSoDRuleConflictError(
                    f"Görevler Ayrılığı (SoD) İhlali! '{role_a}' ve '{role_b}' rolleri aynı anda tutulamaz."
                )

    def get_effective_roles(self, assigned_roles: Set[str]) -> Set[str]:
        """Rol hiyerarşisi üzerinden miras alınan tüm etkin rolleri özyineli hesaplar."""
        # Başlangıçta kullanıcının doğrudan rolleri kümeye alınır
        effective: Set[str] = set(assigned_roles)
        # Ziyaret edilecek roller yığını oluşturulur
        to_process: List[str] = list(assigned_roles)

        # Yığında işlenecek rol kaldığı sürece döngü devam eder
        while to_process:
            # Yığından bir rol çekilir
            current_role = to_process.pop(0)
            # Eğer bu rolün miras verdiği alt roller varsa
            if current_role in self.role_hierarchy:
                # Alt roller üzerinde gezilir
                for child in self.role_hierarchy[current_role]:
                    # Eğer alt rol henüz etkin rollerde yoksa
                    if child not in effective:
                        # Etkin roller kümesine eklenir
                        effective.add(child)
                        # Alt rolün de kendi alt rolleri olabileceğinden yığına eklenir
                        to_process.append(child)

        # Hesaplanan tüm miraslı roller döndürülür
        return effective

    def get_effective_permissions(self, assigned_roles: Set[str]) -> Set[str]:
        """Kullanıcının etkin tüm rollerinden gelen birleşik izinler kümesini döner."""
        # Önce tüm miras alınan roller hesaplanır
        all_roles = self.get_effective_roles(assigned_roles)
        # İzinlerin toplanacağı küme oluşturulur
        permissions: Set[str] = set()

        # Her etkin rol için izinler taranır
        for role in all_roles:
            # Rolün doğrudan izinleri varsa kümeye birleştirilir
            if role in self.role_permissions:
                # İzinler eklenir
                permissions.update(self.role_permissions[role])

        # Toplam birleşik izin kümesi döndürülür
        return permissions

    def evaluate(self, subject: SubjectContext, resource_type: str, action: str) -> Tuple[bool, str]:
        """RBAC kuralı üzerinden erişim kararı üretir."""
        # 1. SoD kuralları doğrulanır (CWE-863)
        self.validate_sod_compliance(subject.roles)

        # 2. Aranacak zorunlu izin anahtarı formatlanır
        required_perm = f"{resource_type}:{action}"
        # Joker (wildcard) izin formatı hazırlanır
        wildcard_perm = f"{resource_type}:*"

        # 3. Kullanıcının sahip olduğu tüm etkin izinler hesaplanır
        effective_perms = self.get_effective_permissions(subject.roles)

        # 4. İzin kontrolü yapılır
        if required_perm in effective_perms or wildcard_perm in effective_perms or "*:*" in effective_perms:
            # Yetki mevcut
            return True, f"RBAC İzin Verildi: '{required_perm}' yetkisi etkin rollerde mevcut."

        # Yetki bulunamadıysa ret kararı döner (Fail-Closed Default Deny)
        return False, f"RBAC Yetki Eksikliği (CWE-862): '{required_perm}' izni kullanıcının rollerinde tanımlı değil."


# ==============================================================================
# 4. ABAC MOTORU (ATTRIBUTE-BASED ACCESS CONTROL - NIST SP 800-162)
# ==============================================================================

class ABACPolicyEngine:
    """
    NIST SP 800-162 Uyumlu Öznitelik Tabanlı Erişim Kontrol Motoru.
    Özne, Kaynak, Eylem ve Çevre özniteliklerini 'Deny-Overrides' mantığıyla değerlendirir.
    """

    def __init__(self, corporate_cidrs: Optional[List[str]] = None):
        # Güvenilir kurumsal IP ağ blokları listesi
        self.corporate_networks = [
            ipaddress.ip_network(cidr) for cidr in (corporate_cidrs or ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1/32"])
        ]

    def is_ip_trusted(self, ip_str: str) -> bool:
        """Gelen IP adresinin güvenilir kurumsal ağ bloğunda olup olmadığını denetler."""
        try:
            # IP adresi nesnesi oluşturulur
            ip_obj = ipaddress.ip_address(ip_str)
            # Ağ blokları kontrol edilir
            for net in self.corporate_networks:
                # IP ağ bloğuna dahil mi?
                if ip_obj in net:
                    # Dahil ise güvenilirdir
                    return True
            # Hiçbir bloğa uymadıysa güvensizdir
            return False
        except ValueError:
            # Geçersiz IP formatı gelirse doğrudan güvensiz kabul edilir
            return False

    def evaluate_request(
        self,
        subject: SubjectContext,
        resource: ResourceContext,
        action: ActionContext,
        environment: EnvironmentContext
    ) -> Tuple[bool, List[str]]:
        """
        Tüm öznitelikleri 'Deny-Overrides' (Reddetme Öncelikli) kuralı ile değerlendirir.
        Tek bir kural ihlal edilirse erişim derhal engellenir (CWE-862/CWE-284).
        """
        # Hata ve ihlal gerekçelerini saklayacak liste
        denial_reasons: List[str] = []

        # ----------------------------------------------------------------------
        # KURAL 1: Çok Kiracılı İzolasyon Denetimi (CWE-284 / CWE-639)
        # Özne ile kaynak aynı kiracıya (tenant) ait olmak zorundadır.
        # ----------------------------------------------------------------------
        if subject.tenant_id != resource.tenant_id:
            # Kiracı ihlali gerekçesi eklenir
            denial_reasons.append(
                f"Multi-Tenant İzolasyon İhlali (CWE-284): Özne kiracısı '{subject.tenant_id}' ile "
                f"kaynak kiracısı '{resource.tenant_id}' uyuşmuyor!"
            )

        # ----------------------------------------------------------------------
        # KURAL 2: Kaynak Kilit Durumu (Write/Delete Engeli)
        # Kaynak kilitli ise okuma dışındaki değiştirme/silme eylemleri yasaktır.
        # ----------------------------------------------------------------------
        if resource.is_locked and action.name in ("write", "delete", "modify"):
            # Kilit ihlali gerekçesi eklenir
            denial_reasons.append(
                f"Kaynak Kilitli (CWE-863): '{resource.resource_id}' arşivlenmiş veya kilitli olduğundan '{action.name}' yapılamaz."
            )

        # ----------------------------------------------------------------------
        # KURAL 3: Gizlilik Seviyesi ve Yetki Derecesi (Classification vs Clearance)
        # Öznitelik kuralı: subject.clearance_level >= resource.classification (CWE-285)
        # ----------------------------------------------------------------------
        if subject.clearance_level < resource.classification:
            # Yetki yetersizliği gerekçesi eklenir
            denial_reasons.append(
                f"Yetki Seviyesi Yetersiz (CWE-285): Özne yetkisi Seviye {subject.clearance_level}, "
                f"fakat kaynak gizliliği Seviye {resource.classification} gerektiriyor."
            )

        # ----------------------------------------------------------------------
        # KURAL 4: Departman Sahipliği ve Veri İzolasyonu (CWE-639 IDOR)
        # 'security_auditor' ve 'admin' rolleri hariç, özne sadece kendi departmanının
        # gizli (classification >= 2) verilerine erişebilir.
        # ----------------------------------------------------------------------
        is_global_role = any(r in subject.roles for r in ("admin", "security_auditor", "auditor", "compliance_officer"))
        # Eğer genel denetçi rolü yoksa ve kaynak gizli ise departman eşleşmelidir
        if not is_global_role and resource.classification >= 2:
            # Departman kontrolü yapılır
            if subject.department != resource.department_owner:
                # Departman ihlali gerekçesi eklenir
                denial_reasons.append(
                    f"Departman İzolasyon İhlali (CWE-639): '{subject.department}' personeli, "
                    f"'{resource.department_owner}' departmanına ait gizli kaynağa erişemez."
                )

        # ----------------------------------------------------------------------
        # KURAL 5: Kritik İşlemler İçin MFA Zorunluluğu (CWE-308)
        # 'delete' işlemi veya Seviye 4 (Çok Gizli) kaynaklar için MFA zorunludur.
        # ----------------------------------------------------------------------
        requires_mfa = (action.name == "delete") or (resource.classification >= 4)
        # Koşul sağlanıyor ancak MFA doğrulanmamışsa
        if requires_mfa and not subject.mfa_authenticated:
            # MFA eksikliği gerekçesi eklenir
            denial_reasons.append(
                f"MFA Doğrulaması Zorunlu (CWE-308): '{action.name}' eylemi veya Seviye {resource.classification} "
                f"kaynak erişimi için aktif MFA oturumu şarttır."
            )

        # ----------------------------------------------------------------------
        # KURAL 6: Çevresel Kısıtlar — Mesai Saatleri (CWE-284)
        # Finansal veya kritik yazma işlemleri sadece mesai saatleri içinde yapılabilir.
        # ----------------------------------------------------------------------
        if resource.resource_type in ("financial_ledger", "payroll", "production_db") and action.name in ("write", "delete"):
            # Mesai saati dışı kontrolü
            if not environment.is_business_hours:
                # Mesai dışı gerekçesi eklenir
                denial_reasons.append(
                    f"Mesai Saati Kısıtlaması (CWE-284): '{resource.resource_type}' üzerindeki kritik değişiklikler "
                    f"yalnızca mesai saatleri (08:00 - 18:00) içerisinde icra edilebilir."
                )

        # ----------------------------------------------------------------------
        # KURAL 7: Çevresel Kısıtlar — Kurumsal Ağ ve Risk Skoru (CWE-284)
        # Dış ağdan gelen ve risk skoru yüksek olan istekler engellenir.
        # ----------------------------------------------------------------------
        is_trusted_network = self.is_ip_trusted(subject.ip_address)
        # Kurumsal ağda değilse ve risk skoru yüksekse
        if not is_trusted_network and environment.risk_score >= 60:
            # Yüksek risk gerekçesi eklenir
            denial_reasons.append(
                f"Ağ Güvenlik ve Risk Engeli (CWE-284): Güvensiz ağdan ({subject.ip_address}) gelen ve "
                f"yüksek risk skoruna ({environment.risk_score}) sahip istek reddedildi."
            )

        # ----------------------------------------------------------------------
        # KARAR ENTEGRASYONU: Deny-Overrides
        # ----------------------------------------------------------------------
        if denial_reasons:
            # En az bir kural engellendiyse ret kararı verilir
            return False, denial_reasons

        # Tüm kurallar başarıyla geçildiyse izin verilir
        return True, ["ABAC İlkesi Onaylandı: Tüm bağlamsal öznitelikler izin koşullarını sağladı."]


# ==============================================================================
# 5. HİBRİT ERİŞİM YÖNETİCİSİ (HYBRID RBAC + ABAC ORCHESTRATOR)
# ==============================================================================

class HybridAccessManager:
    """
    RBAC ve ABAC politikalarını birleştiren Kurumsal Yetkilendirme Motoru.
    1. Aşama: RBAC ile kaba taneli rol ve SoD denetimi (Gatekeeper).
    2. Aşama: ABAC ile ince taneli bağlamsal öznitelik denetimi (Contextual Policy).
    """

    def __init__(self, rbac_engine: RBACEngine, abac_engine: ABACPolicyEngine):
        # RBAC motor referansı
        self.rbac = rbac_engine
        # ABAC motor referansı
        self.abac = abac_engine
        # Denetim izi günlükleri (Audit Trail) hafıza deposu
        self.audit_log: List[Dict[str, Any]] = []

    def enforce_access(
        self,
        subject: SubjectContext,
        resource: ResourceContext,
        action: ActionContext,
        environment: EnvironmentContext
    ) -> AccessDecision:
        """
        Erişim isteğini değerlendirir, kararı üretir ve denetim kaydına yazar.
        İhlal tespit edilirse uygun güvenlik istisnasını fırlatır.
        """
        # Benzersiz denetim kimliği oluşturulur
        audit_id = f"AUD-{uuid.uuid4().hex[:12].upper()}"
        # Tüm gerekçeleri toplayacak liste
        all_reasons: List[str] = []

        # ----------------------------------------------------------------------
        # AŞAMA 1: RBAC DEĞERLENDİRMESİ
        # ----------------------------------------------------------------------
        try:
            # RBAC değerlendirmesi çalıştırılır
            rbac_allowed, rbac_reason = self.rbac.evaluate(
                subject=subject,
                resource_type=resource.resource_type,
                action=action.name
            )
            # Gerekçe listeye eklenir
            all_reasons.append(rbac_reason)
        except RBACSoDRuleConflictError as sod_err:
            # SoD çakışması tespit edilirse denetim loguna yazılır ve hata yükseltilir
            self._log_audit(audit_id, subject, resource, action, False, "RBAC_SOD_CONFLICT", [str(sod_err)])
            # İstisna yukarı fırlatılır
            raise

        # Eğer RBAC izin vermediyse doğrudan ret kararı üretilir (CWE-862)
        if not rbac_allowed:
            # Denetim günlüğüne ret kaydedilir
            self._log_audit(audit_id, subject, resource, action, False, "RBAC_DENIED", all_reasons)
            # Güvenlik istisnası fırlatılır
            raise RBACPermissionDeniedError(rbac_reason)

        # ----------------------------------------------------------------------
        # AŞAMA 2: ABAC BAĞLAMSAL DEĞERLENDİRMESİ
        # ----------------------------------------------------------------------
        abac_allowed, abac_reasons = self.abac.evaluate_request(
            subject=subject,
            resource=resource,
            action=action,
            environment=environment
        )
        # ABAC gerekçeleri birleştirilir
        all_reasons.extend(abac_reasons)

        # Eğer ABAC reddettiyse
        if not abac_allowed:
            # Hatanın türüne göre özelleşmiş güvenlik istisnası belirlenir
            first_err = abac_reasons[0]
            # Denetim günlüğüne ret kaydedilir
            self._log_audit(audit_id, subject, resource, action, False, "ABAC_DENIED", all_reasons)

            # Özel istisna sınıflandırması
            if "Multi-Tenant" in first_err:
                raise MultiTenantIsolationBreachError(first_err)
            elif "Yetki Seviyesi Yetersiz" in first_err:
                raise ClassificationClearanceInsufficientError(first_err)
            elif "Mesai Saati Kısıtlaması" in first_err or "Ağ Güvenlik" in first_err:
                raise EnvironmentalConstraintError(first_err)
            else:
                raise ABACPolicyDeniedError(first_err)

        # ----------------------------------------------------------------------
        # AŞAMA 3: NİHAİ BAŞARILI KARAR (HYBRID PASS)
        # ----------------------------------------------------------------------
        decision = AccessDecision(
            is_allowed=True,
            model_used="HYBRID (RBAC + ABAC)",
            decision_rule="NIST RBAC Rol İzni Ve NIST ABAC Bağlamsal İlkeler Sağlandı",
            reasons=all_reasons,
            audit_id=audit_id
        )

        # Denetim günlüğüne başarılı erişim kaydedilir
        self._log_audit(audit_id, subject, resource, action, True, "PERMITTED", all_reasons)
        # Karar döndürülür
        return decision

    def _log_audit(
        self,
        audit_id: str,
        subject: SubjectContext,
        resource: ResourceContext,
        action: ActionContext,
        allowed: bool,
        status: str,
        reasons: List[str]
    ) -> None:
        """Yapılandırılmış JSON denetim kaydını dahili depoya yazar."""
        # Denetim kaydı sözlüğü hazırlanır
        record = {
            "audit_id": audit_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "status": status,
            "allowed": allowed,
            "user_id": subject.user_id,
            "user_roles": list(subject.roles),
            "user_department": subject.department,
            "user_tenant": subject.tenant_id,
            "resource_id": resource.resource_id,
            "resource_type": resource.resource_type,
            "resource_tenant": resource.tenant_id,
            "action": action.name,
            "reasons": reasons
        }
        # Listeye eklenir
        self.audit_log.append(record)

    def export_audit_logs_json(self) -> str:
        """Tüm denetim loglarını biçimlendirilmiş JSON formatında dışa aktarır."""
        # JSON dizisi olarak serileştirilir
        return json.dumps(self.audit_log, indent=2, ensure_ascii=False)
