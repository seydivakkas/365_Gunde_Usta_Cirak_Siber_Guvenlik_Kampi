# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 113: Kimlik Doğrulama (AuthN) ve Yetkilendirme (AuthZ) Motoru.

Bu modül, modern siber güvenlik mimarilerinde 'Kimlik Doğrulama' (Öznenin kim olduğunun kanıtı)
ile 'Yetkilendirme' (Öznenin hangi kaynağa hangi eylemle erişebileceğinin denetimi) arasındaki
katı ayrımı somutlaştıran, kriptografik olarak güvenli, saldırı dirençli referans motordur.

Kapsanan Güvenlik Açıkları ve Standartlar:
- CWE-287 / OWASP A07:2021: Kimlik Doğrulama Hataları (PBKDF2, Kriptografik Tuz, Hesap Kilitleme)
- CWE-285 / OWASP A01:2021: Bozuk Erişim Kontrolü (Default Deny - Açık Red İlkesi)
- CWE-639 / CWE-862: IDOR (Insecure Direct Object Reference) Nesne Düzeyinde Yetkisiz Erişim Savunması
- CWE-208: Sabit Zamanlı Özet Doğrulama (Timing-Attack Savunması - secrets.compare_digest)
- CWE-384: Oturum Sabitleme (Session Fixation) ve Kriptografik Belirteç Yenileme
- CWE-613: Süresi Dolan Oturumların (Session Expiration) Otomatik Reddi
- CWE-284: Çok Kiracılı (Multi-Tenant) İzolasyon ve Çapraz Kiracı Sızıntı Savunması
"""

# Kriptografik özetleme ve anahtar türetme fonksiyonları için hashlib modülü içe aktarılır
import hashlib
# Kriptografik olarak güvenli rastgele sayı ve belirteç üretimi için secrets modülü içe aktarılır
import secrets
# Sabit zamanlı karşılaştırma ve güvenli mesaj doğrulama için hmac modülü içe aktarılır
import hmac
# Yapılandırılmış veri serileştirme ve JSON kayıtları için json modülü içe aktarılır
import json
# Zaman damgaları ve süre hesaplamaları için datetime modülü içe aktarılır
from datetime import datetime, timezone, timedelta
# Kesin zaman ölçümleri ve bekleme simülasyonları için time modülü içe aktarılır
import time
# Veri yapılarını nesne yönelimli ve tip güvenli tanımlamak için dataclass ve field içe aktarılır
from dataclasses import dataclass, field, asdict
# Tip ipuçları ve statik analiz desteği için gerekli türler içe aktarılır
from typing import Dict, List, Optional, Set, Tuple, Any


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI (CUSTOM SECURITY EXCEPTIONS)
# ==============================================================================

class IAMSecurityError(Exception):
    """Tüm Kimlik ve Erişim Yönetimi (IAM) güvenlik hatalarının temel istisna sınıfı."""
    def __init__(self, message: str, cwe_id: str, error_code: str):
        # Üst sınıf Exception başlatıcısına hata mesajını iletir
        super().__init__(f"[{cwe_id}] {error_code}: {message}")
        # Hatanın ilişkili olduğu Ortak Zafiyet Numaralandırması (CWE) kodunu saklar
        self.cwe_id = cwe_id
        # Makine tarafından okunabilir hata kodunu saklar
        self.error_code = error_code
        # Kullanıcı dostu teknik açıklama metnini saklar
        self.message = message


class AuthenticationError(IAMSecurityError):
    """Kimlik doğrulama (AuthN) aşamasında meydana gelen güvenlik istisnası."""
    def __init__(self, message: str, error_code: str = "AUTHN_FAILED"):
        # Kimlik doğrulama zafiyetleri temel CWE-287 standardıyla eşleştirilir
        super().__init__(message, cwe_id="CWE-287", error_code=error_code)


class InvalidCredentialsError(AuthenticationError):
    """Geçersiz kullanıcı adı veya parola durumunda fırlatılan istisna."""
    def __init__(self, message: str = "Geçersiz kimlik bilgileri sunuldu."):
        # Hatalı kimlik bilgisi hata koduyla başlatılır
        super().__init__(message, error_code="INVALID_CREDENTIALS")


class AccountLockedError(AuthenticationError):
    """Çok sayıda başarısız deneme sonucu hesap kilitlendiğinde fırlatılan istisna (CWE-307)."""
    def __init__(self, message: str = "Hesap çok sayıda başarısız deneme nedeniyle kilitlendi."):
        # Kaba kuvvet saldırısı engelleme CWE-307 koduyla başlatılır
        super().__init__(message, error_code="ACCOUNT_LOCKED")
        # CWE kimliği özel olarak CWE-307 ile güncellenir
        self.cwe_id = "CWE-307"


class SessionExpiredError(AuthenticationError):
    """Oturum süresi (TTL veya inaktivite) dolduğunda fırlatılan istisna (CWE-613)."""
    def __init__(self, message: str = "Oturum belirtecinin geçerlilik süresi dolmuştur."):
        # Oturum zaman aşımı CWE-613 koduyla başlatılır
        super().__init__(message, error_code="SESSION_EXPIRED")
        # CWE kimliği CWE-613 olarak ayarlanır
        self.cwe_id = "CWE-613"


class SessionInvalidError(AuthenticationError):
    """Bilinmeyen, iptal edilmiş veya sahte oturum belirteçlerinde fırlatılan istisna (CWE-384)."""
    def __init__(self, message: str = "Oturum belirteci geçersiz veya iptal edilmiş."):
        # Oturum sabitleme ve sahtecilik CWE-384 koduyla başlatılır
        super().__init__(message, error_code="SESSION_INVALID")
        # CWE kimliği CWE-384 olarak güncellenir
        self.cwe_id = "CWE-384"


class MissingAuthenticationError(AuthenticationError):
    """Korumalı bir kaynağa oturum bilgisi olmadan erişilmek istendiğinde fırlatılır (CWE-306)."""
    def __init__(self, message: str = "Kritik fonksiyona erişim için kimlik doğrulama zorunludur."):
        # Eksik kimlik doğrulama CWE-306 koduyla başlatılır
        super().__init__(message, error_code="MISSING_AUTHENTICATION")
        # CWE kimliği CWE-306 olarak ayarlanır
        self.cwe_id = "CWE-306"


class AuthorizationError(IAMSecurityError):
    """Yetkilendirme (AuthZ) aşamasında erişim engellendiğinde fırlatılan temel istisna (CWE-285)."""
    def __init__(self, message: str, error_code: str = "AUTHZ_DENIED"):
        # Yetkilendirme ihlalleri temel CWE-285 standardıyla eşleştirilir
        super().__init__(message, cwe_id="CWE-285", error_code=error_code)


class AccessDeniedError(AuthorizationError):
    """Öznenin talep ettiği aksiyon için gerekli role veya izne sahip olmadığı durum (CWE-862)."""
    def __init__(self, message: str = "Bu kaynak üzerinde talep edilen işlem için yetkiniz bulunmamaktadır."):
        # Eksik yetkilendirme kontrolü CWE-862 koduyla başlatılır
        super().__init__(message, error_code="ACCESS_DENIED")
        # CWE kimliği CWE-862 olarak ayarlanır
        self.cwe_id = "CWE-862"


class InsecureDirectObjectReferenceError(AuthorizationError):
    """Başka bir kullanıcıya ait nesneye yetkisiz doğrudan erişim teşebbüsü (CWE-639 IDOR)."""
    def __init__(self, message: str = "Nesne düzeyinde erişim reddedildi: Kaynak sahibi değilsiniz."):
        # IDOR ihlali CWE-639 koduyla başlatılır
        super().__init__(message, error_code="IDOR_VIOLATION")
        # CWE kimliği CWE-639 olarak güncellenir
        self.cwe_id = "CWE-639"


class TenantMismatchError(AuthorizationError):
    """Çapraz kiracı (cross-tenant) veri erişimi veya izolasyon ihlali (CWE-284)."""
    def __init__(self, message: str = "Kiracı uyuşmazlığı: Farklı bir kiracının verisine erişilemez."):
        # Çok kiracılı izolasyon ihlali CWE-284 koduyla başlatılır
        super().__init__(message, error_code="TENANT_MISMATCH")
        # CWE kimliği CWE-284 olarak ayarlanır
        self.cwe_id = "CWE-284"


# ==============================================================================
# VERİ MODELLERİ (DATA MODELS)
# ==============================================================================

@dataclass
class UserCredential:
    """Kullanıcı kimlik doğrulama bilgilerini saklayan güvenli veri modeli."""
    # Tekil kullanıcı adı tanımı
    username: str
    # Parola karmalamada kullanılan 16-baytlık kriptografik rastgele tuz (onaltılık metin)
    salt_hex: str
    # PBKDF2-HMAC-SHA256 ile hesaplanmış parola özeti (onaltılık metin)
    hash_hex: str
    # PBKDF2 iterasyon sayısı (NIST SP 800-63B tavsiyesi doğrultusunda)
    iterations: int
    # Kullanıcıya atanmış roller kümesi (örn. 'admin', 'analyst', 'operator')
    roles: List[str]
    # Kullanıcının ait olduğu kiracı kimliği (Multi-tenancy ayrımı için)
    tenant_id: str
    # Art arda gelen başarısız kimlik doğrulama denemesi sayacı
    failed_attempts: int = 0
    # Hesabın kilitli olup olmadığını belirten bayrak
    is_locked: bool = False
    # Hesap kilitliyse kilidin otomatik açılacağı UTC zaman damgası
    lock_until: Optional[datetime] = None


@dataclass
class SessionToken:
    """Kimliği doğrulanmış aktif bir kullanıcı oturumunu temsil eden veri modeli."""
    # Kriptografik olarak güvenli 32-baytlık URL-uyumlu oturum belirteci
    token_str: str
    # Oturumun sahibi olan kullanıcı adı
    username: str
    # Kullanıcının ait olduğu kiracı kimliği
    tenant_id: str
    # Kullanıcının oturum anındaki aktif rolleri
    roles: List[str]
    # Oturumun oluşturulduğu UTC zaman damgası
    created_at: datetime
    # Oturumdaki son işlem zaman damgası (kayan süre aşımı için)
    last_active_at: datetime
    # Oturumun kesin olarak sonlanacağı mutlak bitiş zaman damgası
    expires_at: datetime
    # Oturumun iptal edilip edilmediğini belirten bayrak
    is_revoked: bool = False


@dataclass
class Resource:
    """Yetkilendirme denetimine tabi tutulan korumalı bir veri veya sistem kaynağı."""
    # Kaynağın benzersiz kimliği (örn. 'doc_101', 'server_node_5')
    resource_id: str
    # Kaynak türü (örn. 'financial_report', 'system_setting', 'audit_log')
    resource_type: str
    # Kaynağın sahibi olan kullanıcının adı (IDOR denetimi için)
    owner_username: str
    # Kaynağın ait olduğu organizasyon / kiracı kimliği
    tenant_id: str
    # Kaynak üzerinde tanımlı güvenlik sınıflandırması ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET')
    classification: str
    # Kaynak üzerindeki eylemler için gereken asgari izinler sözlüğü (örn. {'read': 'READ_REPORT', 'delete': 'DELETE_REPORT'})
    required_permissions: Dict[str, str] = field(default_factory=dict)


@dataclass
class AccessDecision:
    """Yetkilendirme Motoru (PDP - Policy Decision Point) tarafından verilen erişim kararı."""
    # Erişimin onaylanıp onaylanmadığı (True: İzin verildi, False: Reddedildi)
    is_allowed: bool
    # Kararın gerekçesini açıklayan teknik açıklama metni
    reason: str
    # Talep edilen işlemi gerçekleştiren özne (kullanıcı adı)
    subject_username: str
    # Hedef alınan kaynağın kimliği
    resource_id: str
    # Talep edilen eylem türü (örn. 'read', 'write', 'delete')
    action: str
    # Varsa fırlatılacak veya tetiklenen güvenlik hata kodu
    error_code: Optional[str] = None
    # İlgili CWE sınıflandırma numarası
    cwe_id: Optional[str] = None


@dataclass
class AuditLogEntry:
    """Gerçekleşen tüm kimlik doğrulama ve yetkilendirme olaylarının değişmez denetim kaydı."""
    # Olayın gerçekleştiği UTC zaman damgası
    timestamp: str
    # Olay kategorisi ('AUTHN_ATTEMPT', 'AUTHN_SUCCESS', 'AUTHN_LOCKOUT', 'AUTHZ_ALLOW', 'AUTHZ_DENY')
    event_type: str
    # İşlemi gerçekleştiren özne / kullanıcı adı
    subject: str
    # İşlem yapılan hedef kaynak veya alan
    target: str
    # İşlemin sonucu ('SUCCESS' veya 'FAILURE')
    outcome: str
    # Olayla ilgili detaylı teknik açıklama
    details: str
    # Güvenlik zafiyeti veya hata kodu referansı
    security_tag: str


# ==============================================================================
# KİMLİK DOĞRULAMA MOTORU (AUTHENTICATION ENGINE - AuthN)
# ==============================================================================

class AuthenticationEngine:
    """
    Kullanıcı kimlik doğrulama, güvenli parola yönetimi, oturum oluşturma
    ve brute-force kilitleme mekanizmalarını yöneten AuthN motoru.
    """

    def __init__(self, default_iterations: int = 10000, max_failed_attempts: int = 5, lockout_duration_seconds: int = 900):
        # Varsayılan PBKDF2 özetleme iterasyon sayısı (birim test hızını optimize ederken güvenliği korur)
        self.default_iterations = default_iterations
        # Hesabın kilitlenmesi için izin verilen maksimum ardışık hatalı deneme eşiği
        self.max_failed_attempts = max_failed_attempts
        # Hesap kilitleme süresi (varsayılan 15 dakika = 900 saniye)
        self.lockout_duration_seconds = lockout_duration_seconds
        # Bellek içi kullanıcı kimlik bilgileri deposu (username -> UserCredential)
        self._user_store: Dict[str, UserCredential] = {}
        # Bellek içi aktif oturumlar deposu (token_str -> SessionToken)
        self._session_store: Dict[str, SessionToken] = {}

    @staticmethod
    def hash_password(password: str, salt_hex: Optional[str] = None, iterations: int = 10000) -> Tuple[str, str]:
        """
        Düz metin parolayı PBKDF2-HMAC-SHA256 algoritması ve kriptografik tuz ile özetler.
        
        Args:
            password: Düz metin kullanıcı parolası.
            salt_hex: Varsa önceden üretilmiş 16-baytlık tuz (onaltılık metin), yoksa yeni üretilir.
            iterations: PBKDF2 döngü sayısı.
            
        Returns:
            Tuple[str, str]: (salt_hex, hash_hex) ikilisi döner.
        """
        # Tuz parametresi sağlanmamışsa kriptografik rastgele 16 bayt üretilir
        if salt_hex is None:
            # secrets modülü işletim sistemi entropi havuzundan (urandom) 16 bayt çeker
            salt_bytes = secrets.token_bytes(16)
            # Bayt dizisi saklama ve karşılaştırma kolaylığı için hex metnine dönüştürülür
            salt_hex = salt_bytes.hex()
        else:
            # Sağlanan hex tuz bayt formatına çözülür
            salt_bytes = bytes.fromhex(salt_hex)

        # Parola UTF-8 bayt dizisine çevrilir
        password_bytes = password.encode("utf-8")
        # hashlib.pbkdf2_hmac fonksiyonu SHA-256 ile belirtilen iterasyon kadar çalıştırılır
        derived_key = hashlib.pbkdf2_hmac("sha256", password_bytes, salt_bytes, iterations, dklen=32)
        # Elde edilen 32 baytlık türetilmiş anahtar hex metnine dönüştürülür
        hash_hex = derived_key.hex()
        # Üretilen tuz ve parola özeti ikili olarak döndürülür
        return salt_hex, hash_hex

    def register_user(self, username: str, password: str, roles: List[str], tenant_id: str) -> UserCredential:
        """
        Sisteme yeni bir kullanıcı kaydeder, parolasını tuzlayarak güvenli şekilde özetler.
        """
        # Kullanıcı adı boşluklardan arındırılır ve küçük harfe dönüştürülür
        clean_username = username.strip().lower()
        # Kullanıcı adı geçerliliği denetlenir
        if not clean_username:
            raise ValueError("Kullanıcı adı boş bırakılamaz.")
        # Kullanıcının zaten var olup olmadığı kontrol edilir
        if clean_username in self._user_store:
            raise ValueError(f"'{clean_username}' kullanıcı adı zaten kayıtlıdır.")

        # Parola kriptografik olarak güvenli tuz ve PBKDF2 ile özetlenir
        salt_hex, hash_hex = self.hash_password(password, iterations=self.default_iterations)
        # Yeni kullanıcı veri modeli oluşturulur
        user = UserCredential(
            username=clean_username,
            salt_hex=salt_hex,
            hash_hex=hash_hex,
            iterations=self.default_iterations,
            roles=list(roles),
            tenant_id=tenant_id
        )
        # Kullanıcı sözlüğe eklenir
        self._user_store[clean_username] = user
        # Oluşturulan kullanıcı nesnesi döndürülür
        return user

    def authenticate(self, username: str, password: str, now: Optional[datetime] = None) -> UserCredential:
        """
        Kullanıcı kimliğini doğrular. CWE-208 zamanlama saldırısı savunması ve
        CWE-307 kaba kuvvet (brute-force) hesap kilitleme mekanizmasını işletir.
        """
        # Zaman parametresi verilmemişse mevcut UTC zamanı alınır
        if now is None:
            now = datetime.now(timezone.utc)

        # Kullanıcı adı normalize edilir
        clean_username = username.strip().lower()
        # Kullanıcı sistemde mevcut değilse bile zamanlama analizi sızıntısını önlemek için sentetik karma hesaplanır
        if clean_username not in self._user_store:
            # Sahte tuz ve özet hesaplanarak zamanlama eşitlemesi sağlanır
            dummy_salt = "00" * 16
            self.hash_password(password, salt_hex=dummy_salt, iterations=self.default_iterations)
            # Kullanıcı bulunamadığı için standart hata fırlatılır
            raise InvalidCredentialsError("Kullanıcı adı veya parola hatalı.")

        # Gerçek kullanıcı kaydı çekilir
        user = self._user_store[clean_username]

        # 1. Hesap kilitli mi denetimi yapılır (CWE-307)
        if user.is_locked:
            # Kilit süresi dolmuş mu kontrol edilir
            if user.lock_until and now >= user.lock_until:
                # Kilit süresi dolduğu için hesap kilidi kaldırılır ve sayaç sıfırlanır
                user.is_locked = False
                user.failed_attempts = 0
                user.lock_until = None
            else:
                # Kilit süresi henüz dolmamışsa erişim engellenir
                raise AccountLockedError(f"Hesap geçici olarak kilitlenmiştir. Kilidin açılma zamanı: {user.lock_until}")

        # 2. Girilen parolanın özeti hesaplanır
        _, computed_hash = self.hash_password(password, salt_hex=user.salt_hex, iterations=user.iterations)

        # 3. Sabit zamanlı (constant-time) özet karşılaştırması yapılır (CWE-208 Timing Attack Defense)
        # secrets.compare_digest uzunluktan bağımsız sabit zamanlı karşılaştırma sunar
        is_valid = secrets.compare_digest(computed_hash, user.hash_hex)

        # Parola hatalıysa
        if not is_valid:
            # Başarısız deneme sayacı bir artırılır
            user.failed_attempts += 1
            # Eşik değerine ulaşıldıysa hesap kilitlenir
            if user.failed_attempts >= self.max_failed_attempts:
                user.is_locked = True
                user.lock_until = now + timedelta(seconds=self.lockout_duration_seconds)
                raise AccountLockedError(f"Çok sayıda başarısız deneme! Hesap {self.lockout_duration_seconds} saniye süreyle kilitlendi.")
            # Hatalı kimlik bilgisi istisnası fırlatılır
            raise InvalidCredentialsError(f"Kullanıcı adı veya parola hatalı. Kalan deneme hakkı: {self.max_failed_attempts - user.failed_attempts}")

        # Parola doğruysa başarısız sayaç sıfırlanır ve kilit açılır
        user.failed_attempts = 0
        user.is_locked = False
        user.lock_until = None
        # Başarıyla doğrulanan kullanıcı nesnesi döndürülür
        return user

    def create_session(self, username: str, ttl_seconds: int = 3600, now: Optional[datetime] = None) -> SessionToken:
        """
        Kullanıcı için kriptografik olarak güvenli, yeni bir oturum belirteci üretir.
        Oturum sabitleme (Session Fixation - CWE-384) saldırısını engellemek için
        kullanıcının mevcut tüm aktif oturumlarını geçersiz kılar (tekil oturum politikası).
        """
        # Zaman parametresi kontrol edilir
        if now is None:
            now = datetime.now(timezone.utc)

        # Kullanıcı adı normalize edilir
        clean_username = username.strip().lower()
        # Kullanıcının varlığı doğrulanır
        if clean_username not in self._user_store:
            raise InvalidCredentialsError(f"Kullanıcı bulunamadı: {clean_username}")

        # Kullanıcı nesnesi alınır
        user = self._user_store[clean_username]

        # Session Fixation (CWE-384) Önleme: Bu kullanıcının önceki aktif oturumları iptal edilir
        for token_id, session in list(self._session_store.items()):
            if session.username == clean_username and not session.is_revoked:
                session.is_revoked = True

        # Kriptografik rastgele 32-baytlık URL-safe oturum belirteci üretilir (CWE-330 engellemesi)
        raw_token = secrets.token_urlsafe(32)
        # Mutlak bitiş zamanı hesaplanır
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Yeni oturum nesnesi tanımlanır
        session = SessionToken(
            token_str=raw_token,
            username=clean_username,
            tenant_id=user.tenant_id,
            roles=list(user.roles),
            created_at=now,
            last_active_at=now,
            expires_at=expires_at,
            is_revoked=False
        )

        # Oturum sözlüğe kaydedilir
        self._session_store[raw_token] = session
        # Oluşturulan oturum nesnesi döndürülür
        return session

    def validate_session(self, token_str: str, now: Optional[datetime] = None) -> SessionToken:
        """
        Verilen oturum belirtecinin geçerliliğini, iptal durumunu ve süre aşımını denetler.
        Geçerliyse son işlem zaman damgasını (sliding window) günceller.
        """
        # Zaman parametresi kontrol edilir
        if now is None:
            now = datetime.now(timezone.utc)

        # Belirteç boşsa eksik kimlik doğrulama fırlatılır (CWE-306)
        if not token_str:
            raise MissingAuthenticationError("Oturum belirteci eksik veya boş.")

        # Belirteç sistemde kayıtlı değilse geçersiz oturum hatası fırlatılır (CWE-384)
        if token_str not in self._session_store:
            raise SessionInvalidError("Oturum belirteci geçersiz veya bulunamadı.")

        # Oturum nesnesi bellekten çekilir
        session = self._session_store[token_str]

        # Oturum iptal edilmiş mi kontrol edilir
        if session.is_revoked:
            raise SessionInvalidError("Oturum daha önce sonlandırılmış (iptal edilmiş).")

        # Oturumun geçerlilik süresi (TTL) dolmuş mu denetlenir (CWE-613)
        if now >= session.expires_at:
            # Süresi dolan oturum otomatik iptal edilir
            session.is_revoked = True
            raise SessionExpiredError("Oturum süresi (TTL) dolmuştur. Lütfen tekrar giriş yapınız.")

        # Oturum son etkinlik zaman damgası güncellenir
        session.last_active_at = now
        # Doğrulanmış oturum döndürülür
        return session

    def revoke_session(self, token_str: str) -> bool:
        """Aktif bir oturum belirtecini derhal iptal eder (Logout işlemi)."""
        # Belirteç sistemde varsa iptal edilir
        if token_str in self._session_store:
            self._session_store[token_str].is_revoked = True
            return True
        return False


# ==============================================================================
# YETKİLENDİRME MOTORU (AUTHORIZATION ENGINE - AuthZ)
# ==============================================================================

class AuthorizationEngine:
    """
    Politika Karar Noktası (PDP - Policy Decision Point).
    Açık Red (Default Deny - Whitelist) prensibine göre çalışır.
    Rol tabanlı izinler, kiracı izolasyonu ve nesne düzeyinde erişim (IDOR) denetimi yapar.
    """

    def __init__(self):
        # Rol ve İzin Matrisi (Role-Based Permissions Map)
        # Default Deny: Listede açıkça yer almayan tüm izinler otomatik reddedilir
        self._role_permissions: Dict[str, Set[str]] = {
            "admin": {
                "READ_DOCUMENT", "WRITE_DOCUMENT", "DELETE_DOCUMENT",
                "VIEW_AUDIT_LOG", "MANAGE_USERS", "SYSTEM_CONFIG"
            },
            "operator": {
                "READ_DOCUMENT", "WRITE_DOCUMENT", "VIEW_AUDIT_LOG"
            },
            "analyst": {
                "READ_DOCUMENT", "VIEW_AUDIT_LOG"
            },
            "guest": {
                "READ_PUBLIC"
            }
        }

    def add_role_permission(self, role: str, permission: str) -> None:
        """Yeni bir role yeni bir izin ekler."""
        if role not in self._role_permissions:
            self._role_permissions[role] = set()
        self._role_permissions[role].add(permission)

    def evaluate_access(
        self,
        subject_username: str,
        subject_roles: List[str],
        subject_tenant: str,
        resource: Resource,
        action: str
    ) -> AccessDecision:
        """
        Yetkilendirme talebini değerlendirir ve kesin bir AccessDecision kararı üretir.
        
        Adımlar:
        1. Eylemin bu kaynak türü için tanımlı bir izin gereksinimi var mı kontrol edilir.
        2. Kiracı İzolasyonu Denetimi (CWE-284): Kiracılar uyuşuyor mu?
        3. Rol Yetki Denetimi (CWE-862): Kullanıcının rolleri gerekli izni kapsıyor mu?
        4. Nesne Düzeyinde Erişim Denetimi / IDOR (CWE-639): Kullanıcı kaynağın sahibi mi veya admin mi?
        """
        # Eylem küçük harfe dönüştürülür
        clean_action = action.lower()

        # Kaynak üzerinde bu eylem için gereken izin tanımlanmış mı?
        required_perm = resource.required_permissions.get(clean_action)
        if not required_perm:
            # Default Deny İlkesi: Tanımlanmamış her işlem reddedilir
            return AccessDecision(
                is_allowed=False,
                reason=f"Kaynak '{resource.resource_id}' üzerinde '{clean_action}' eylemi için izin kuralı tanımlanmamış.",
                subject_username=subject_username,
                resource_id=resource.resource_id,
                action=clean_action,
                error_code="UNDEFINED_ACTION_DENIED",
                cwe_id="CWE-285"
            )

        # 1. Kiracı İzolasyonu Denetimi (Multi-Tenant Isolation - CWE-284)
        if subject_tenant != resource.tenant_id:
            return AccessDecision(
                is_allowed=False,
                reason=f"Kiracı uyuşmazlığı: Özne kiracısı '{subject_tenant}', kaynak kiracısı '{resource.tenant_id}' ile eşleşmiyor.",
                subject_username=subject_username,
                resource_id=resource.resource_id,
                action=clean_action,
                error_code="TENANT_MISMATCH",
                cwe_id="CWE-284"
            )

        # 2. Rol İzinleri Denetimi (Role-Based Permissions - CWE-862)
        has_permission = False
        for role in subject_roles:
            role_perms = self._role_permissions.get(role, set())
            if required_perm in role_perms:
                has_permission = True
                break

        if not has_permission:
            return AccessDecision(
                is_allowed=False,
                reason=f"Yetersiz yetki: Özne rolleri {subject_roles}, gereken '{required_perm}' iznine sahip değil.",
                subject_username=subject_username,
                resource_id=resource.resource_id,
                action=clean_action,
                error_code="MISSING_PERMISSION",
                cwe_id="CWE-862"
            )

        # 3. Nesne Düzeyinde Yetkilendirme / IDOR Denetimi (CWE-639)
        # Eğer kaynak gizli/özel bir veri ise ve kullanıcı 'admin' rolüne sahip değilse, kaynağın sahibi olmalıdır
        is_admin = "admin" in subject_roles
        if not is_admin and resource.owner_username and resource.owner_username != subject_username:
            # Kullanıcının izni olsa dahi nesne başkasına aitse erişim engellenir
            return AccessDecision(
                is_allowed=False,
                reason=f"Nesne düzeyinde erişim engellendi (IDOR Savunması): '{resource.resource_id}' kaynağının sahibi '{resource.owner_username}', ancak talep eden '{subject_username}'.",
                subject_username=subject_username,
                resource_id=resource.resource_id,
                action=clean_action,
                error_code="IDOR_VIOLATION",
                cwe_id="CWE-639"
            )

        # Tüm kontrollerden başarıyla geçti
        return AccessDecision(
            is_allowed=True,
            reason=f"Erişim onaylandı: Özne '{subject_username}', '{required_perm}' izni ve nesne sahipliği doğrulandı.",
            subject_username=subject_username,
            resource_id=resource.resource_id,
            action=clean_action
        )


# ==============================================================================
# BİRLEŞİK IAM GEÇİT YÖNETİCİSİ (IDENTITY AND ACCESS GATEWAY - PEP)
# ==============================================================================

class IdentityAndAccessGateway:
    """
    Politika Uygulama Noktası (PEP - Policy Enforcement Point).
    Gelen tüm isteklerde hem Kimlik Doğrulamayı (AuthN) hem de Yetkilendirmeyi (AuthZ)
    kesin bir sırayla çalıştıran ve tüm olayları yapılandırılmış JSON denetim günlüğüne kaydeden geçit.
    """

    def __init__(self, authn_engine: AuthenticationEngine, authz_engine: AuthorizationEngine):
        # AuthN motor bileşeni atanır
        self.authn = authn_engine
        # AuthZ motor bileşeni atanır
        self.authz = authz_engine
        # Kaynak deposu (resource_id -> Resource)
        self._resource_store: Dict[str, Resource] = {}
        # Değişmez denetim kayıtları listesi (Audit Logs)
        self._audit_logs: List[AuditLogEntry] = []

    def register_resource(self, resource: Resource) -> None:
        """Korumalı bir kaynağı geçit deposuna kaydeder."""
        self._resource_store[resource.resource_id] = resource

    def _log_audit(self, event_type: str, subject: str, target: str, outcome: str, details: str, security_tag: str) -> None:
        """Denetim izi kaydı ekler."""
        # Güncel UTC zaman damgası ISO 8601 formatında üretilir
        ts = datetime.now(timezone.utc).isoformat()
        # Yeni log girdisi oluşturulur
        entry = AuditLogEntry(
            timestamp=ts,
            event_type=event_type,
            subject=subject,
            target=target,
            outcome=outcome,
            details=details,
            security_tag=security_tag
        )
        # Listeye eklenir
        self._audit_logs.append(entry)

    def execute_request(
        self,
        session_token_str: Optional[str],
        resource_id: str,
        action: str,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Tek merkezden uçtan uca korumalı işlem yürütür.
        1. AuthN Kontrolü: Oturum doğrulanır (Yoksa veya geçersizse reddedilir).
        2. Kaynak Varlık Kontrolü: Kaynak mevcut mu?
        3. AuthZ Kontrolü: İzin, Kiracı ve IDOR doğrulanır.
        4. Denetim Günlüğü: Sonuç loglanır.
        """
        # Zaman parametresi kontrolü
        if now is None:
            now = datetime.now(timezone.utc)

        # 1. Aşama: Kimlik Doğrulama (AuthN) Denetimi
        if not session_token_str:
            self._log_audit(
                event_type="AUTHN_MISSING",
                subject="ANONYMOUS",
                target=resource_id,
                outcome="FAILURE",
                details="Oturum belirteci olmadan korumalı kaynağa erişim teşebbüsü.",
                security_tag="CWE-306"
            )
            raise MissingAuthenticationError("Erişim için geçerli bir oturum belirteci zorunludur.")

        # Oturum geçerliliği denetlenir
        try:
            session = self.authn.validate_session(session_token_str, now=now)
        except IAMSecurityError as e:
            self._log_audit(
                event_type="AUTHN_FAILURE",
                subject="UNKNOWN",
                target=resource_id,
                outcome="FAILURE",
                details=e.message,
                security_tag=e.cwe_id
            )
            raise e

        # 2. Aşama: Hedef Kaynağın Varlık Kontrolü
        if resource_id not in self._resource_store:
            self._log_audit(
                event_type="RESOURCE_NOT_FOUND",
                subject=session.username,
                target=resource_id,
                outcome="FAILURE",
                details=f"Talep edilen '{resource_id}' kaynağı sistemde bulunamadı.",
                security_tag="NOT_FOUND"
            )
            raise KeyError(f"Kaynak bulunamadı: {resource_id}")

        resource = self._resource_store[resource_id]

        # 3. Aşama: Yetkilendirme (AuthZ) Denetimi (PDP Çağrısı)
        decision = self.authz.evaluate_access(
            subject_username=session.username,
            subject_roles=session.roles,
            subject_tenant=session.tenant_id,
            resource=resource,
            action=action
        )

        # Karar olumsuzsa uygun istisna fırlatılır ve denetim kaydı oluşturulur
        if not decision.is_allowed:
            self._log_audit(
                event_type="AUTHZ_DENIED",
                subject=session.username,
                target=resource_id,
                outcome="FAILURE",
                details=decision.reason,
                security_tag=decision.cwe_id or "CWE-285"
            )

            # Zafiyet koduna göre spesifik istisna fırlatılır
            if decision.cwe_id == "CWE-639":
                raise InsecureDirectObjectReferenceError(decision.reason)
            elif decision.cwe_id == "CWE-284":
                raise TenantMismatchError(decision.reason)
            else:
                raise AccessDeniedError(decision.reason)

        # Karar olumluysa başarılı işlem loglanır
        self._log_audit(
            event_type="AUTHZ_ALLOWED",
            subject=session.username,
            target=resource_id,
            outcome="SUCCESS",
            details=decision.reason,
            security_tag="ACCESS_GRANTED"
        )

        # Başarılı sonuç yanıtı döndürülür
        return {
            "durum": "ONAYLANDI",
            "kullanici": session.username,
            "kiraci": session.tenant_id,
            "kaynak_id": resource.resource_id,
            "eylem": action,
            "mesaj": decision.reason,
            "zaman_damgasi": now.isoformat()
        }

    def get_audit_logs(self) -> List[Dict[str, Any]]:
        """Sistemde biriken tüm denetim izlerini sözlük listesi olarak döndürür."""
        return [asdict(entry) for entry in self._audit_logs]
