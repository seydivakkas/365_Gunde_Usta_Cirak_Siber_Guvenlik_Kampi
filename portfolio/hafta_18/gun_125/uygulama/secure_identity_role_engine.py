# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 125: Mini Proje 17 — Güvenli Kimlik ve Rol Yönetim Prototipi.
Hafta 18 Sentez Projesi:
1. PBKDF2 Parola Kriptografisi ve Çok Faktörlü Doğrulama (MFA - CWE-287/308).
2. Hiyerarşik RBAC ve Statik Görevler Ayrılığı (SoD - CWE-863).
3. Saltzer-Schroeder 'Fail-Safe Defaults' (Default-Deny) Prensibi.
4. Arıza Anında Güvenli Kapanma (Fail-Secure / Fail-Closed - CWE-636).
5. Zarflı Kasa Mimarisi ve Log Maskeleme Filtresi (CWE-532 / CWE-798).
"""

# Standart enum modülü içe aktarılıyor
from enum import Enum
# Veri sınıfları için dataclass ve field içe aktarılıyor
from dataclasses import dataclass, field
# Tip ipuçları için tipler içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any, Set
# Zaman ve süre hesapları için datetime ve timedelta içe aktarılıyor
from datetime import datetime, timedelta
# Kriptografik özetleme ve PBKDF2 için hashlib içe aktarılıyor
import hashlib
# Mesaj doğrulama kodu (HMAC) için hmac içe aktarılıyor
import hmac
# Kriptografik güvenli rastgele değer üretimi için secrets içe aktarılıyor
import secrets
# Düzenli ifadeler için re modülü içe aktarılıyor
import re
# JSON serileştirme işlemleri için json modülü içe aktarılıyor
import json


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class SecureIdentityEngineError(Exception):
    """Güvenli kimlik ve rol motoru temel istisna sınıfı."""
    pass


class AuthenticationFailedError(SecureIdentityEngineError):
    """Kullanıcı kimlik doğrulama başarısız olduğunda fırlatılır (CWE-287)."""
    pass


class StepUpMFARequiredError(SecureIdentityEngineError):
    """Kritik rol veya eylem için MFA doğrulaması eksik olduğunda fırlatılır (CWE-308)."""
    pass


class AccessDeniedError(SecureIdentityEngineError):
    """Yetkilendirme kuralları eşleşmediğinde veya Default-Deny durumunda fırlatılır (CWE-285)."""
    pass


class SeparationOfDutyConflictError(SecureIdentityEngineError):
    """Kullanıcıya atanmış zehirli (çatışan) rol kombinasyonu tespit edildiğinde fırlatılır (CWE-863)."""
    pass


class FailSecureInterventionError(SecureIdentityEngineError):
    """Sistem arızası anında Fail-Secure kapıları kilitlediğinde fırlatılır (CWE-636)."""
    pass


class SessionExpiredError(SecureIdentityEngineError):
    """Oturum anahtarının (token) geçerlilik süresi dolduğunda fırlatılır (CWE-613)."""
    pass


class InsecureConfigurationError(SecureIdentityEngineError):
    """Güvenli olmayan varsayılan yapılandırma tespit edildiğinde fırlatılır (CWE-1188)."""
    pass


class DuplicateEntityError(SecureIdentityEngineError):
    """Mükerrer kullanıcı, rol veya kural tanımlanmaya çalışıldığında fırlatılır."""
    pass


class WeakPasswordError(SecureIdentityEngineError):
    """NIST SP 800-63B standardına uymayan zayıf parola durumunda fırlatılır (CWE-521)."""
    pass


class AccountLockedError(AuthenticationFailedError):
    """Ardışık hatalı girişler sonrası kilitlenen hesaba erişim denendiğinde fırlatılır (CWE-307)."""
    pass


class CircularRoleHierarchyError(SecureIdentityEngineError):
    """Rol mirasında döngü tespit edildiğinde sonsuz özyinelemeyi önlemek için fırlatılır (CWE-674)."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class SystemFailureType(Enum):
    """Erişim anında simüle edilebilecek harici altyapı arızaları."""
    IDENTITY_STORE_TIMEOUT = "Kimlik Deposu Zaman Aşımı"
    DATABASE_UNAVAILABLE = "Veritabanı Servis Dışı"
    MFA_PROVIDER_DOWN = "MFA Sağlayıcısı Çöktü"
    POLICY_CORRUPTION = "Politika Dosyası Bozuldu"


@dataclass
class RoleDefinition:
    """Hiyerarşik RBAC rol tanımı modeli."""
    role_name: str                       # Rol adı (örn: 'finance_analyst')
    permissions: Set[str]                # Doğrudan izinler kümesi (örn: {'report:read'})
    parent_roles: List[str] = field(default_factory=list) # Kalıtım alınan üst roller
    requires_mfa: bool = False           # Bu rol için MFA zorunlu mu?


@dataclass
class UserAccount:
    """Kullanıcı hesap modeli (Zarflı parola hash'i ile korunur)."""
    user_id: str                         # Kullanıcı kimliği (örn: 'USR-101')
    username: str                        # Kullanıcı adı
    salt_hex: str                        # PBKDF2 tuzu
    password_hash_hex: str               # PBKDF2 parola özeti
    roles: List[str]                     # Kullanıcıya atanmış roller
    department: str                      # Departman / Bölüm
    is_active: bool = True               # Hesap aktif mi?
    mfa_secret: Optional[str] = None     # TOTP MFA sırrı
    failed_attempts: int = 0             # Hatalı giriş sayısı
    is_locked: bool = False              # Hesap kilitli mi?


@dataclass
class AuthToken:
    """Başarılı kimlik doğrulama sonrası üretilen kısa ömürlü oturum belirteci."""
    token_id: str                        # Kriptografik oturum kimliği
    user_id: str                         # Ait olduğu kullanıcı
    roles: List[str]                     # Kullanıcının aktif rolleri
    issued_at: datetime                  # Verilme zamanı
    expires_at: datetime                 # Bitiş zamanı (TTL)
    mfa_verified: bool = False           # MFA doğrulandı mı?


@dataclass
class AccessEvaluationResult:
    """Erişim değerlendirme nihai kararı."""
    request_id: str                      # Talep kimliği
    decision: str                        # 'PERMIT' veya 'DENY'
    reason: str                          # Gerekçe
    matched_permission: Optional[str] = None # Eşleşen yetki
    is_fail_secure_intervention: bool = False # Fail-Secure devrede mi?
    failure_encountered: Optional[str] = None # Varsa arıza tipi


# ============================================================================
# KRİPTOGRAFİK VE GÜVENLİK YARDIMCILARI
# ============================================================================

class SecurityCryptoHelper:
    """Parola özetleme, güvenli token üretimi ve maskeleme yardımcı sınıfı."""

    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """PBKDF2-HMAC-SHA256 kullanarak parolayı 100.000 iterasyonla özetler."""
        # Eğer tuz verilmediyse 16 byte kriptografik tuz üretilir
        if salt is None:
            salt = secrets.token_bytes(16)
        # PBKDF2 özeti hesaplanır
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        # Tuz ve özet hex olarak döndürülür
        return salt.hex(), pwd_hash.hex()

    @staticmethod
    def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
        """Verilen parolanın saklanan PBKDF2 özetiyle eşleştiğini sabit zamanlı doğrular."""
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(expected_hash_hex)
        computed_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        # Zamanlama saldırılarını (Timing Attack) önlemek için compare_digest kullanılır
        return hmac.compare_digest(computed_hash, expected_hash)

    @staticmethod
    def mask_text(text: str, sensitive_values: Set[str]) -> str:
        """Metin içerisindeki hassas parolaları ve tokenları maskeler (CWE-532)."""
        masked = text
        for secret_val in sensitive_values:
            if len(secret_val) >= 4 and secret_val in masked:
                masked = masked.replace(secret_val, "[REDACTED_SENSITIVE_DATA]")
        return masked


# ============================================================================
# ANA YÖNETİCİ MOTORU (SECURE IDENTITY & ROLE MANAGER)
# ============================================================================

class SecureIdentityRoleManager:
    """
    Mini Proje 17 Çekirdek Güvenlik Yöneticisi:
    Kimlik Doğrulama, Hiyerarşik RBAC, ABAC, Fail-Secure ve Maskeleme Orkestratörü.
    """

    def __init__(self, system_name: str = "Enterprise Secure Identity Platform"):
        """Sistemi varsayılan kurallarla başlatır."""
        self.system_name = system_name
        # Kayıtlı roller haritası
        self.roles: Dict[str, RoleDefinition] = {}
        # Kayıtlı kullanıcılar haritası
        self.users: Dict[str, UserAccount] = {}
        # Aktif oturum belirteçleri haritası
        self.active_tokens: Dict[str, AuthToken] = {}
        # Görevler ayrılığı (SoD) çatışan rol çiftleri kümesi
        self.toxic_role_pairs: List[Tuple[str, str]] = []
        # Yapısal olay denetim günlüğü
        self.audit_log: List[Dict[str, Any]] = []
        # Maskeleme için bilinen hassas dizgiler kümesi
        self.sensitive_strings: Set[str] = set()

    def _log_event(self, action: str, details: Dict[str, Any]) -> None:
        """Denetim kütüğüne yapısal olay yazar."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        self.audit_log.append(event)

    def _is_descendant(self, current: str, target: str, visited: Optional[Set[str]] = None) -> bool:
        """current rolünün üst dallarında target rolünün bulunup bulunmadığını kontrol eder (CWE-674)."""
        if visited is None:
            visited = set()
        if current in visited or current not in self.roles:
            return False
        visited.add(current)
        for p in self.roles[current].parent_roles:
            if p == target or self._is_descendant(p, target, visited):
                return True
        return False

    def register_role(
        self,
        role_name: str,
        permissions: Set[str],
        parent_roles: Optional[List[str]] = None,
        requires_mfa: bool = False
    ) -> None:
        """Sisteme yeni bir hiyerarşik RBAC rolü tanımlar."""
        if role_name in self.roles:
            raise DuplicateEntityError(f"Rol zaten mevcut: {role_name}")

        # Döngüsel hiyerarşi denetimi (CWE-674)
        for parent in (parent_roles or []):
            if parent == role_name or self._is_descendant(parent, role_name):
                raise CircularRoleHierarchyError(
                    f"Döngüsel rol hiyerarşisi tespit edildi: '{role_name}' -> '{parent}' (CWE-674)!"
                )

        role = RoleDefinition(
            role_name=role_name,
            permissions=set(permissions),
            parent_roles=list(parent_roles or []),
            requires_mfa=requires_mfa
        )
        self.roles[role_name] = role
        self._log_event("ROLE_REGISTERED", {"role": role_name, "permissions_count": len(permissions)})

    def add_toxic_role_pair(self, role_a: str, role_b: str) -> None:
        """Statik Görevler Ayrılığı (Static SoD) zehirli rol çifti ekler (CWE-863)."""
        pair = (role_a, role_b)
        if pair not in self.toxic_role_pairs:
            self.toxic_role_pairs.append(pair)
            self._log_event("SOD_RULE_ADDED", {"pair": f"{role_a} <-> {role_b}"})

    def register_user(
        self,
        user_id: str,
        username: str,
        password: str,
        roles: List[str],
        department: str = "Engineering",
        mfa_secret: Optional[str] = None
    ) -> UserAccount:
        """Yeni bir kullanıcı hesabını PBKDF2 ile güvenli oluşturur."""
        if username in [u.username for u in self.users.values()]:
            raise DuplicateEntityError(f"Kullanıcı adı zaten kayıtlı: {username}")
        if user_id in self.users:
            raise DuplicateEntityError(f"Kullanıcı ID zaten kayıtlı: {user_id}")

        # Parola karmaşıklık ve asgari uzunluk denetimi (NIST SP 800-63B / CWE-521)
        if len(password) < 12:
            raise WeakPasswordError("Parola en az 12 karakter uzunluğunda olmalıdır (NIST SP 800-63B / CWE-521).")

        # 1. SoD Çatışma Denetimi (Kullanıcıya verilen roller birbiriyle çatışıyor mu?)
        self._check_sod_conflict(roles)

        # 2. Parola Güvenli Özetleme
        salt_hex, hash_hex = SecurityCryptoHelper.hash_password(password)
        # Hassas parolanın log maskesine eklenmesi
        self.sensitive_strings.add(password)

        user = UserAccount(
            user_id=user_id,
            username=username,
            salt_hex=salt_hex,
            password_hash_hex=hash_hex,
            roles=list(roles),
            department=department,
            mfa_secret=mfa_secret
        )
        self.users[user_id] = user
        self._log_event("USER_REGISTERED", {"user_id": user_id, "username": username, "roles": roles})
        return user

    def assign_role_to_user(self, user_id_or_username: str, role_name: str) -> None:
        """Mevcut bir kullanıcıya yeni bir rol atar ve SoD kısıtlarını denetler (CWE-863)."""
        user = self.users.get(user_id_or_username)
        if not user:
            user = next((u for u in self.users.values() if u.username == user_id_or_username), None)
        if not user:
            raise DuplicateEntityError(f"Kullanıcı bulunamadı: {user_id_or_username}")
        if role_name not in self.roles:
            raise InsecureConfigurationError(f"Tanımsız rol atanamaz: {role_name}")
        new_roles = list(set(user.roles + [role_name]))
        self._check_sod_conflict(new_roles)
        user.roles = new_roles
        self._log_event("ROLE_ASSIGNED_TO_USER", {"user_id": user.user_id, "role": role_name})

    def _check_sod_conflict(self, user_roles: List[str]) -> None:
        """Kullanıcının rolleri arasında SoD ihlali olup olmadığını denetler (CWE-863)."""
        role_set = set(user_roles)
        for r_a, r_b in self.toxic_role_pairs:
            if r_a in role_set and r_b in role_set:
                raise SeparationOfDutyConflictError(
                    f"Statik Görevler Ayrılığı (SoD) İhlali: Bir kullanıcı aynı anda hem '{r_a}' "
                    f"hem de '{r_b}' rollerine sahip olamaz (CWE-863)!"
                )

    def authenticate(self, username: str, password: str, session_ttl_seconds: int = 1800) -> AuthToken:
        """Kullanıcı adı ve parola ile kimlik doğrulaması yapar (CWE-287)."""
        user = next((u for u in self.users.values() if u.username == username), None)
        if not user:
            self._log_event("AUTH_FAILED_USER_NOT_FOUND", {"username": username})
            raise AuthenticationFailedError("Geçersiz kullanıcı adı veya parola.")

        if user.is_locked:
            self._log_event("AUTH_FAILED_ACCOUNT_LOCKED", {"username": username})
            raise AccountLockedError("Hesap güvenlik nedeniyle kilitlenmiştir. Lütfen yöneticiye başvurun.")

        # Parola doğrulanır
        is_valid = SecurityCryptoHelper.verify_password(password, user.salt_hex, user.password_hash_hex)
        if not is_valid:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.is_locked = True
                self._log_event("ACCOUNT_LOCKED_BRUTE_FORCE", {"username": username})
            else:
                self._log_event("AUTH_FAILED_INVALID_PASSWORD", {"username": username, "attempts": user.failed_attempts})
            raise AuthenticationFailedError("Geçersiz kullanıcı adı veya parola.")

        # Başarılı giriş: Hatalı sayaç sıfırlanır
        user.failed_attempts = 0
        now = datetime.now()
        token_id = secrets.token_urlsafe(32)
        token = AuthToken(
            token_id=token_id,
            user_id=user.user_id,
            roles=list(user.roles),
            issued_at=now,
            expires_at=now + timedelta(seconds=session_ttl_seconds),
            mfa_verified=False
        )
        self.active_tokens[token_id] = token
        self._log_event("AUTH_SUCCESS", {"user_id": user.user_id, "token_id": token_id[:8] + "..."})
        return token

    def verify_mfa(self, token_id: str, otp_code: str) -> AuthToken:
        """Oturum için Step-Up MFA doğrulamasını gerçekleştirir (CWE-308)."""
        if token_id not in self.active_tokens:
            raise SessionExpiredError("Oturum belirteci bulunamadı veya süresi doldu.")
        token = self.active_tokens[token_id]
        user = self.users[token.user_id]

        # Örnek statik test kodu doğrulaması (Prototip modelinde '123456' veya secret eşleşmesi)
        valid_code = "123456"
        if user.mfa_secret:
            valid_code = user.mfa_secret

        if otp_code != valid_code:
            self._log_event("MFA_FAILED", {"user_id": user.user_id})
            raise AuthenticationFailedError("MFA doğrulama kodu geçersiz.")

        token.mfa_verified = True
        self._log_event("MFA_VERIFIED", {"user_id": user.user_id})
        return token

    def _resolve_all_permissions(self, role_name: str, visited: Optional[Set[str]] = None) -> Set[str]:
        """Hiyerarşik RBAC rollerinde özyinelemeli (recursive) tüm yetkileri toplar."""
        if visited is None:
            visited = set()
        if role_name in visited or role_name not in self.roles:
            return set()
        visited.add(role_name)
        role_def = self.roles[role_name]
        effective_perms = set(role_def.permissions)
        for parent in role_def.parent_roles:
            effective_perms.update(self._resolve_all_permissions(parent, visited))
        return effective_perms

    def authorize(
        self,
        token_id: str,
        resource_id: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
        simulate_failure: Optional[SystemFailureType] = None
    ) -> AccessEvaluationResult:
        """
        Erişim talebini değerlendirir:
        1. Oturum geçerlilik denetimi (CWE-613).
        2. Arıza anında Fail-Secure / Fail-Closed koruması (CWE-636).
        3. Step-Up MFA denetimi (CWE-308).
        4. Hiyerarşik RBAC izin çözünürlüğü.
        5. Saltzer-Schroeder 'Default-Deny' kararı.
        """
        req_id = f"REQ-{secrets.token_hex(4).upper()}"
        ctx = context or {}

        # ADIM 1: Oturum Geçerlilik Denetimi
        if token_id not in self.active_tokens:
            self._log_event("AUTHZ_DENIED_INVALID_TOKEN", {"req_id": req_id})
            return AccessEvaluationResult(
                request_id=req_id,
                decision="DENY",
                reason="Geçersiz veya süresi dolmuş oturum belirteci (CWE-613)."
            )

        token = self.active_tokens[token_id]
        if datetime.now() > token.expires_at:
            del self.active_tokens[token_id]
            self._log_event("AUTHZ_DENIED_EXPIRED_TOKEN", {"req_id": req_id})
            return AccessEvaluationResult(
                request_id=req_id,
                decision="DENY",
                reason="Oturum süresi (TTL) sona ermiştir. Yeniden giriş yapılmalıdır (CWE-613)."
            )

        # ADIM 2: SİSTEM ARIZASI VE FAIL-SECURE DENETİMİ (CWE-636)
        if simulate_failure is not None:
            self._log_event(
                "FAIL_SECURE_TRIGGERED",
                {"req_id": req_id, "failure": simulate_failure.value}
            )
            # Fail-Secure ilkesi gereği arıza anında kapılar kilitlenir
            return AccessEvaluationResult(
                request_id=req_id,
                decision="DENY",
                reason=f"Kritik Altyapı Arızası ({simulate_failure.value}) tespit edildi. "
                       f"Fail-Secure ilkesi gereğince tüm erişim talepleri REDDEDİLDİ (CWE-636 Koruması).",
                is_fail_secure_intervention=True,
                failure_encountered=simulate_failure.value
            )

        # ADIM 3: STEP-UP MFA DENETİMİ (CWE-308)
        # Eğer kullanıcının rollerinden herhangi biri veya talep edilen eylem MFA istiyorsa
        requires_mfa = False
        for r_name in token.roles:
            if r_name in self.roles and self.roles[r_name].requires_mfa:
                requires_mfa = True
                break
        if ctx.get("critical_action", False):
            requires_mfa = True

        if requires_mfa and not token.mfa_verified:
            self._log_event("AUTHZ_DENIED_MFA_REQUIRED", {"req_id": req_id, "user_id": token.user_id})
            return AccessEvaluationResult(
                request_id=req_id,
                decision="DENY",
                reason="Bu kritik işlem için Step-Up Çok Faktörlü Doğrulama (MFA) zorunludur (CWE-308)."
            )

        # ADIM 4: HİYERARŞİK RBAC YETKİ ÇÖZÜMLEMESİ
        required_permission = f"{resource_id}:{action}"
        user_effective_permissions: Set[str] = set()
        for r_name in token.roles:
            user_effective_permissions.update(self._resolve_all_permissions(r_name))

        # Joker (*) yetkisi veya tam eşleşme kontrol edilir
        wildcard_perm = f"{resource_id}:*"
        if required_permission in user_effective_permissions or wildcard_perm in user_effective_permissions:
            self._log_event("AUTHZ_PERMITTED", {"req_id": req_id, "permission": required_permission})
            return AccessEvaluationResult(
                request_id=req_id,
                decision="PERMIT",
                reason=f"Yetkilendirme başarılı: '{required_permission}' izni doğrulandı.",
                matched_permission=required_permission
            )

        # ADIM 5: SALTZER-SCHROEDER DEFAULT-DENY
        self._log_event("AUTHZ_DENIED_DEFAULT_DENY", {"req_id": req_id, "required": required_permission})
        return AccessEvaluationResult(
            request_id=req_id,
            decision="DENY",
            reason=f"Gerekli yetki bulunamadı ('{required_permission}'). "
                   f"Saltzer-Schroeder 'Fail-Safe Defaults' prensibi gereği talep REDDEDİLDİ."
        )

    def mask_log_message(self, log_message: str) -> str:
        """Kasadaki tüm şifreleri ve oturum belirteçlerini loglardan temizler (CWE-532)."""
        active_tokens_set = {t.token_id for t in self.active_tokens.values()}
        all_sensitives = self.sensitive_strings.union(active_tokens_set)
        return SecurityCryptoHelper.mask_text(log_message, all_sensitives)

    def generate_capstone_report(self) -> str:
        """Mini Proje 17 Bitirme Raporunu Markdown formatında üretir."""
        lines: List[str] = []
        lines.append(f"# {self.system_name} — Mini Proje 17 Bitirme Raporu")
        lines.append(f"**Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        lines.append("## 1. Mimaride Tanımlı Roller ve İzin Hiyerarşisi")
        lines.append("| Rol Adı | Doğrudan İzinler | Üst Roller (Kalıtım) | MFA Zorunlu mu? |")
        lines.append("|---|---|---|---|")
        for r_name, r_def in self.roles.items():
            perms_str = ", ".join(r_def.permissions)
            parents_str = ", ".join(r_def.parent_roles) if r_def.parent_roles else "Yok (Kök)"
            mfa_str = "✅ Evet" if r_def.requires_mfa else "Hayır"
            lines.append(f"| {r_name} | {perms_str} | {parents_str} | {mfa_str} |")
        lines.append("")

        lines.append("## 2. Statik Görevler Ayrılığı (Static SoD) Kısıtları")
        lines.append("| Kural No | Çatışan Rol A | Çatışan Rol B | Zaafiyet Koruması |")
        lines.append("|---|---|---|---|")
        for idx, (ra, rb) in enumerate(self.toxic_role_pairs, start=1):
            lines.append(f"| SoD-{idx} | `{ra}` | `{rb}` | CWE-863 (Privilege Conflict) |")
        lines.append("")

        lines.append("## 3. Güvenlik ve Tasarım Güvencesi")
        lines.append("> [!NOTE]\n> **ENTEGRE GÜVENLİK GÜVENCESİ:**\n"
                     "> - **Saltzer-Schroeder:** Default-Deny prensibi işletilmektedir.\n"
                     "> - **Fail-Secure (CWE-636):** Altyapı arızalarında erişimler otomatik kilitlenmektedir.\n"
                     "> - **Step-Up MFA (CWE-308):** Kritik eylemlerde 2FA zorunludur.\n"
                     "> - **CWE-532:** Oturum belirteçleri ve parolalar loglardan dinamik maskelenmektedir.")
        lines.append("")
        return "\n".join(lines)

    def export_summary_dict(self) -> Dict[str, Any]:
        """Tüm mimariyi JSON uyumlu sözlük formatında dışa aktarır."""
        return {
            "system_name": self.system_name,
            "roles_count": len(self.roles),
            "users_count": len(self.users),
            "active_sessions_count": len(self.active_tokens),
            "sod_rules_count": len(self.toxic_role_pairs),
            "roles": [
                {
                    "name": r.role_name,
                    "permissions": list(r.permissions),
                    "parents": r.parent_roles,
                    "requires_mfa": r.requires_mfa
                }
                for r in self.roles.values()
            ],
            "users": [
                {
                    "user_id": u.user_id,
                    "username": u.username,
                    "roles": u.roles,
                    "department": u.department,
                    "is_locked": u.is_locked
                }
                for u in self.users.values()
            ]
        }
