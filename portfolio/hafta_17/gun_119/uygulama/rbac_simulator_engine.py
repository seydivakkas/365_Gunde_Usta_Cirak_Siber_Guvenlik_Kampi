# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 119: Mini Proje 16 — Rol Tabanlı Erişim Simülatörü ve Politika Doğrulama Motoru.
(NIST ANSI/INCITS 359-2004 RBAC Standardı & Görevler Ayrılığı Denetleyicisi).

Bu modül; Hiyerarşik Rol Çözümlemesi (Miras DAG), Statik ve Dinamik Görevler Ayrılığı
(SSD & DSD), Oturum Bazlı Dinamik Rol Aktivasyonu, Yetki Birikimi (Privilege Creep) Tespiti
ve Toplu Erişim Simülasyonunu (Batch Policy Simulation) tam teşekküllü olarak sunar.
"""

# JSON yapılandırması ve kayıt tutma işlemleri için json kütüphanesi
import json
# Zaman damgaları ve denetim kayıtları için datetime modülü
import datetime
# Güvenli rastgele oturum anahtarları için secrets modülü
import secrets
# Benzersiz takip kimlikleri için uuid modülü
import uuid
# Veri yapılarını tip güvenli tanımlamak için dataclass
from dataclasses import dataclass, field
# Tip ipuçları ve statik analiz desteği için typing modülü
from typing import Dict, List, Set, Optional, Any, Tuple


# ==============================================================================
# 1. GÜVENLİK İSTİSNALARI HİYERARŞİSİ (CWE MAPPING)
# ==============================================================================

class RBACSimulatorError(Exception):
    """Rol tabanlı erişim simülatörü temel güvenlik istisnası."""
    pass


class PermissionDeniedError(RBACSimulatorError):
    """CWE-862: Kullanıcının etkin oturumunda talep edilen iznin bulunmaması durumu."""
    pass


class StaticSoDViolationError(RBACSimulatorError):
    """CWE-863: Statik Görevler Ayrılığı (SSD) ihlali — Çatışan rollerin aynı kişiye atanması."""
    pass


class DynamicSoDViolationError(RBACSimulatorError):
    """CWE-863: Dinamik Görevler Ayrılığı (DSD) ihlali — Çatışan rollerin aynı oturumda açılması."""
    pass


class RoleHierarchyCycleDetectedError(RBACSimulatorError):
    """CWE-674: Rol hiyerarşisinde döngüsel bağımlılık (Circular Dependency) tespiti."""
    pass


class UnassignedRoleActivationError(RBACSimulatorError):
    """CWE-285: Kullanıcıya atanmamış bir rolün oturumda etkinleştirilmeye çalışılması."""
    pass


class PrivilegeCreepWarningError(RBACSimulatorError):
    """CWE-250: Aşırı yetki birikimi (Privilege Creep) ve gereksiz rol fazlalığı uyarısı."""
    pass


class SessionInvalidOrExpiredError(RBACSimulatorError):
    """CWE-613: Geçersiz, süresi dolmuş veya bulunamayan simülasyon oturumu."""
    pass


# ==============================================================================
# 2. VERİ YAPILARI VE MODELLER
# ==============================================================================

@dataclass
class SimulationUser:
    """Simülatörde tanımlı kullanıcı kimliği ve atanmış kalıcı rolleri."""
    # Tekil kullanıcı kimliği
    user_id: str
    # Kullanıcı adı ve soyadı
    full_name: str
    # Kullanıcının çalıştığı departman
    department: str
    # Kullanıcıya atanmış doğrudan roller kümesi
    assigned_roles: Set[str] = field(default_factory=set)


@dataclass
class UserSession:
    """Kullanıcının aktif oturumu ve dinamik olarak etkinleştirdiği roller."""
    # Tekil oturum jetonu
    session_id: str
    # Oturumun ait olduğu kullanıcı
    user_id: str
    # Bu oturumda anlık olarak aktif kılınmış roller alt kümesi (DSD için kritik)
    active_roles: Set[str] = field(default_factory=set)
    # Oturum açılış zamanı
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    # Son hareket zamanı
    last_activity: datetime.datetime = field(default_factory=datetime.datetime.now)


@dataclass
class SimulationRequest:
    """Erişim simülasyon isteği paketi."""
    # İstek kimliği
    request_id: str
    # Oturumu açan kullanıcı kimliği
    user_id: str
    # Hedef nesne (örn: 'invoice_ledger', 'salary_table', 'firewall_rule')
    target_object: str
    # İcra edilmek istenen işlem (örn: 'read', 'write', 'approve', 'delete')
    action: str
    # İsteğin yapılacağı oturum kimliği (boş ise tüm atanmış roller varsayılır)
    session_id: Optional[str] = None


@dataclass
class SimulationResult:
    """Simülasyonun ürettiği değerlendirme karnesi."""
    # İstek kimliği
    request_id: str
    # İzin verildi mi?
    is_permitted: bool
    # İznin sağlandığı veya reddedildiği etkin izinler
    effective_permissions: Set[str]
    # Karar gerekçesi veya hata açıklaması
    reason: str
    # Tetiklenen güvenlik kuralı
    security_event: str


# ==============================================================================
# 3. RBAC SİMÜLATÖR MOTORU (CORE RBAC ENGINE)
# ==============================================================================

class RBACSimulatorEngine:
    """
    NIST ANSI/INCITS 359-2004 Standartlarına Uyumlu
    Kurumsal Rol Tabanlı Erişim Simülasyon ve Politika Denetim Motoru.
    """

    def __init__(self, max_roles_per_user: int = 5):
        # Kullanıcı veritabanı: user_id -> SimulationUser
        self.users: Dict[str, SimulationUser] = {}
        # Rol tanımları ve izinleri: role_name -> Set['object:action']
        self.role_permissions: Dict[str, Set[str]] = {}
        # Hiyerarşi grafı: parent_role -> Set[child_roles]
        self.hierarchy: Dict[str, Set[str]] = {}
        # Statik Görevler Ayrılığı (SSD) çakışma çiftleri: List[Tuple[role_a, role_b]]
        self.ssd_rules: List[Tuple[str, str]] = []
        # Dinamik Görevler Ayrılığı (DSD) çakışma çiftleri: List[Tuple[role_a, role_b]]
        self.dsd_rules: List[Tuple[str, str]] = []
        # Aktif kullanıcı oturumları: session_id -> UserSession
        self.sessions: Dict[str, UserSession] = {}
        # Yapılandırılmış denetim izi günlüğü
        self.audit_log: List[Dict[str, Any]] = []
        # Yetki birikimi (Privilege Creep) eşiği
        self.max_roles_per_user = max_roles_per_user

    # --------------------------------------------------------------------------
    # ROL VE HİYERARŞİ YÖNETİMİ
    # --------------------------------------------------------------------------

    def define_role(self, role_name: str, permissions: Set[str]) -> None:
        """Sisteme yeni bir rol ve bu role ait doğrudan izinleri tanımlar."""
        # Rol izinleri atanır
        self.role_permissions[role_name] = set(permissions)
        # Hiyerarşide kaydı yoksa açılır
        if role_name not in self.hierarchy:
            self.hierarchy[role_name] = set()
        self._log_audit("ROLE_DEFINED", {"role": role_name, "permission_count": len(permissions)})

    def add_hierarchy_edge(self, parent_role: str, child_role: str) -> None:
        """
        Üst role alt rolün izinlerini miras verir (parent -> child).
        Döngüsel bağımlılık (Cycle) tespit edilirse işlemi reddeder (CWE-674).
        """
        # Rollerin tanımlı olup olmadığı kontrol edilir
        if parent_role not in self.role_permissions or child_role not in self.role_permissions:
            raise RBACSimulatorError(f"Tanımsız rol hiyerarşiye eklenemez: {parent_role} -> {child_role}")

        # Döngü denetimi yapılır: child_role zaten parent_role'ün atası mı?
        if self._is_descendant(child_role, parent_role):
            raise RoleHierarchyCycleDetectedError(
                f"Döngüsel Hiyerarşi Hatası (CWE-674): '{parent_role}' ve '{child_role}' "
                f"arasında sonsuz döngü tespit edildi!"
            )

        # Miras ilişkisi kaydedilir
        self.hierarchy[parent_role].add(child_role)
        self._log_audit("HIERARCHY_ADDED", {"parent": parent_role, "child": child_role})

    def _is_descendant(self, potential_child: str, target: str) -> bool:
        """DFS ile target rolünün potential_child rolünden türeyip türemediğini saptar."""
        visited: Set[str] = set()
        stack: List[str] = [potential_child]

        while stack:
            current = stack.pop()
            if current == target:
                return True
            if current not in visited:
                visited.add(current)
                # Alt rolleri yığına ekle
                stack.extend(self.hierarchy.get(current, set()))

        return False

    def get_effective_roles_for_set(self, initial_roles: Set[str]) -> Set[str]:
        """Verilen başlangıç rol kümesinin hiyerarşi üzerinden miras aldığı tüm rolleri döner."""
        effective: Set[str] = set(initial_roles)
        to_process: List[str] = list(initial_roles)

        while to_process:
            role = to_process.pop(0)
            if role in self.hierarchy:
                for child in self.hierarchy[role]:
                    if child not in effective:
                        effective.add(child)
                        to_process.append(child)

        return effective

    def get_effective_permissions_for_roles(self, roles: Set[str]) -> Set[str]:
        """Tüm miraslı etkin rollerin izinlerini birleştirip döner."""
        all_roles = self.get_effective_roles_for_set(roles)
        perms: Set[str] = set()
        for r in all_roles:
            if r in self.role_permissions:
                perms.update(self.role_permissions[r])
        return perms

    # --------------------------------------------------------------------------
    # GÖREVLER AYRILIĞI (SoD) KURALLARI
    # --------------------------------------------------------------------------

    def add_ssd_conflict(self, role_a: str, role_b: str) -> None:
        """CWE-863: Statik Görevler Ayrılığı (SSD) çakışma kuralı ekler."""
        self.ssd_rules.append((role_a, role_b))

    def add_dsd_conflict(self, role_a: str, role_b: str) -> None:
        """CWE-863: Dinamik Görevler Ayrılığı (DSD) çakışma kuralı ekler."""
        self.dsd_rules.append((role_a, role_b))

    def check_ssd_compliance(self, roles: Set[str]) -> None:
        """Rollerin Statik SoD kurallarını ihlal edip etmediğini kontrol eder."""
        for r_a, r_b in self.ssd_rules:
            if r_a in roles and r_b in roles:
                raise StaticSoDViolationError(
                    f"Statik SoD Çakışması (CWE-863): '{r_a}' ve '{r_b}' rolleri aynı kullanıcıya atanamaz."
                )

    def check_dsd_compliance(self, active_roles: Set[str]) -> None:
        """Aktif oturumdaki rollerin Dinamik SoD kurallarını ihlal edip etmediğini kontrol eder."""
        for r_a, r_b in self.dsd_rules:
            if r_a in active_roles and r_b in active_roles:
                raise DynamicSoDViolationError(
                    f"Dinamik SoD Çakışması (CWE-863): '{r_a}' ve '{r_b}' rolleri aynı aktif oturumda bir arada çalıştırılamaz."
                )

    # --------------------------------------------------------------------------
    # KULLANICI VE YETKİ BİRİKİMİ (PRIVILEGE CREEP) YÖNETİMİ
    # --------------------------------------------------------------------------

    def register_user(self, user_id: str, full_name: str, department: str) -> SimulationUser:
        """Simülatöre yeni bir kullanıcı kaydeder."""
        user = SimulationUser(user_id=user_id, full_name=full_name, department=department)
        self.users[user_id] = user
        return user

    def assign_role_to_user(self, user_id: str, role_name: str) -> None:
        """
        Kullanıcıya rol atar. SSD kurallarını ve Yetki Birikimini (Privilege Creep) denetler.
        """
        if user_id not in self.users:
            raise RBACSimulatorError(f"Kullanıcı bulunamadı: {user_id}")
        if role_name not in self.role_permissions:
            raise RBACSimulatorError(f"Rol bulunamadı: {role_name}")

        user = self.users[user_id]
        prospective_roles = user.assigned_roles | {role_name}

        # 1. Statik Görevler Ayrılığı (SSD) denetimi
        self.check_ssd_compliance(prospective_roles)

        # 2. Yetki Birikimi (Privilege Creep) denetimi (CWE-250)
        if len(prospective_roles) > self.max_roles_per_user:
            raise PrivilegeCreepWarningError(
                f"Yetki Birikimi Tehlikesi (CWE-250): '{user.user_id}' kullanıcısına "
                f"{len(prospective_roles)} rol atanmaya çalışıldı (Azami Eşik: {self.max_roles_per_user})."
            )

        user.assigned_roles.add(role_name)
        self._log_audit("ROLE_ASSIGNED", {"user_id": user_id, "role": role_name})

    def revoke_role_from_user(self, user_id: str, role_name: str) -> None:
        """Kullanıcıdan rol geri alır."""
        if user_id in self.users and role_name in self.users[user_id].assigned_roles:
            self.users[user_id].assigned_roles.remove(role_name)
            self._log_audit("ROLE_REVOKED", {"user_id": user_id, "role": role_name})

    # --------------------------------------------------------------------------
    # OTURUM VE DİNAMİK ROL AKTİVASYONU (SESSION & DSD)
    # --------------------------------------------------------------------------

    def create_session(self, user_id: str, roles_to_activate: Optional[Set[str]] = None) -> UserSession:
        """
        Kullanıcı için yeni bir oturum açar ve seçilen rolleri aktive eder.
        Dinamik SoD (DSD) kurallarını denetler.
        """
        if user_id not in self.users:
            raise RBACSimulatorError(f"Kullanıcı bulunamadı: {user_id}")

        user = self.users[user_id]
        # Belirtilmemişse kullanıcının tüm atanmış rolleri denenir
        active = roles_to_activate if roles_to_activate is not None else set(user.assigned_roles)

        # Kullanıcının sahip olmadığı bir rol aktive edilemez (CWE-285)
        unassigned = active - user.assigned_roles
        if unassigned:
            raise UnassignedRoleActivationError(
                f"Yetkisiz Rol Aktivasyonu (CWE-285): '{user_id}' kullanıcısı sahip olmadığı "
                f"'{unassigned}' rollerini aktive edemez."
            )

        # Dinamik SoD (DSD) denetimi yapılır (CWE-863)
        self.check_dsd_compliance(active)

        session_id = f"SES-{secrets.token_hex(6).upper()}"
        session = UserSession(session_id=session_id, user_id=user_id, active_roles=active)
        self.sessions[session_id] = session

        self._log_audit("SESSION_CREATED", {"session_id": session_id, "user_id": user_id, "roles": list(active)})
        return session

    # --------------------------------------------------------------------------
    # ERİŞİM SİMÜLASYONU VE KARAR VERİCİ (SIMULATION EVALUATOR)
    # --------------------------------------------------------------------------

    def evaluate_access(self, request: SimulationRequest) -> SimulationResult:
        """Tek bir erişim simülasyon isteğini NIST RBAC kurallarıyla değerlendirir."""
        if request.user_id not in self.users:
            return SimulationResult(
                request_id=request.request_id,
                is_permitted=False,
                effective_permissions=set(),
                reason=f"Kullanıcı bulunamadı: {request.user_id}",
                security_event="USER_NOT_FOUND"
            )

        user = self.users[request.user_id]

        # Oturum belirtilmişse oturumdaki aktif roller, değilse kullanıcının atanmış rolleri kullanılır
        if request.session_id:
            if request.session_id not in self.sessions:
                raise SessionInvalidOrExpiredError(f"Oturum bulunamadı veya geçersiz: {request.session_id}")
            eval_roles = self.sessions[request.session_id].active_roles
        else:
            eval_roles = user.assigned_roles

        # Etkin tüm izinler hiyerarşi üzerinden hesaplanır
        effective_perms = self.get_effective_permissions_for_roles(eval_roles)

        # Aranacak izin varyasyonları
        exact_perm = f"{request.target_object}:{request.action}"
        obj_wildcard = f"{request.target_object}:*"
        action_wildcard = f"*:{request.action}"
        global_wildcard = "*:*"

        # İzin kontrolü yapılır
        if (
            exact_perm in effective_perms
            or obj_wildcard in effective_perms
            or action_wildcard in effective_perms
            or global_wildcard in effective_perms
        ):
            res = SimulationResult(
                request_id=request.request_id,
                is_permitted=True,
                effective_permissions=effective_perms,
                reason=f"Erişim İzni Onaylandı: '{exact_perm}' yetkisi etkin rollerde mevcuttur.",
                security_event="ACCESS_PERMITTED"
            )
            self._log_audit("ACCESS_EVALUATED", {"request_id": request.request_id, "permitted": True, "target": exact_perm})
            return res

        # İzin eksikliği durumunda Fail-Closed
        res = SimulationResult(
            request_id=request.request_id,
            is_permitted=False,
            effective_permissions=effective_perms,
            reason=f"Yetki Eksikliği (CWE-862): '{exact_perm}' izni kullanıcının etkin rollerinde yok.",
            security_event="ACCESS_DENIED_CWE_862"
        )
        self._log_audit("ACCESS_EVALUATED", {"request_id": request.request_id, "permitted": False, "target": exact_perm})
        return res

    def run_batch_simulation(self, requests: List[SimulationRequest]) -> List[SimulationResult]:
        """Çoklu istek paketini toplu olarak simüle eder ve sonuç listesi üretir."""
        return [self.evaluate_access(req) for req in requests]

    def _log_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Denetim günlüğüne zaman damgalı kayıt yazar."""
        self.audit_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "event": event_type,
            "details": details
        })

    def export_audit_log_json(self) -> str:
        """Tüm simülasyon denetim loglarını biçimlendirilmiş JSON olarak döner."""
        return json.dumps(self.audit_log, indent=2, ensure_ascii=False)
