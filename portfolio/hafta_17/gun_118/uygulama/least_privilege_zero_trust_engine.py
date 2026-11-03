# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 118: En Az Ayrıcalık İlkesi (Principle of Least Privilege - PoLP)
ve Sıfır Güven Mimarisi (NIST SP 800-207 Zero Trust Architecture) Referans Güvenlik Motoru.

Bu modül; Kalıcı Ayrıcalıkların Kaldırılması (Zero Standing Privileges - ZSP),
Zaman Kısıtlı Anlık Yetki Yükseltme (Just-In-Time Elevation - JIT),
Cihaz Sağlık/Uç Nokta Doğrulaması (Device Posture Assessment),
Dinamik Güven Puanlaması (Continuous Dynamic Trust Scoring) ve
Mikro-Segmentasyon (Micro-Segmentation) mekanizmalarını tek çatı altında sunar.
"""

# JSON yapılandırması ve kayıt tutma için standart kütüphane
import json
# Zaman damgaları, TTL ve süre hesaplamaları için datetime modülü
import datetime
# Güvenli rastgele anahtar ve token üretimi için secrets modülü
import secrets
# Benzersiz oturum ve denetim takip kimlikleri için uuid modülü
import uuid
# Veri sınıfları ve şablon tanımları için dataclass
from dataclasses import dataclass, field
# Statik tip doğrulaması ve analiz desteği için typing modülü
from typing import Dict, List, Set, Optional, Any, Tuple


# ==============================================================================
# 1. GÜVENLİK İSTİSNALARI HİYERARŞİSİ (CWE MAPPING)
# ==============================================================================

class ZeroTrustSecurityError(Exception):
    """Sıfır Güven ve En Az Ayrıcalık mimarisi temel güvenlik istisnası."""
    pass


class StandingPrivilegeForbiddenError(ZeroTrustSecurityError):
    """CWE-250: Kalıcı yönetici/root ayrıcalığı kullanımı yasaklandığında fırlatılır."""
    pass


class ExcessiveScopeRequestedError(ZeroTrustSecurityError):
    """CWE-272: Görev için gerekenden fazla yetki talep edildiğinde (PoLP ihlali) fırlatılır."""
    pass


class JITElevationExpiredError(ZeroTrustSecurityError):
    """CWE-613: Süresi dolmuş geçici JIT yetkilendirmesi kullanıldığında fırlatılır."""
    pass


class DevicePostureUntrustedError(ZeroTrustSecurityError):
    """CWE-284: Cihaz sağlık/güvenlik gereksinimlerini karşılamadığında fırlatılır."""
    pass


class DynamicTrustScoreDegradedError(ZeroTrustSecurityError):
    """CWE-284: Dinamik güven skoru politika eşiğinin altına düştüğünde fırlatılır."""
    pass


class StepUpAuthenticationRequiredError(ZeroTrustSecurityError):
    """CWE-308: Yüksek riskli işlemde ikinci bir doğrulama (Step-Up MFA) şart koşulduğunda fırlatılır."""
    pass


class NetworkMicroSegmentationViolationError(ZeroTrustSecurityError):
    """CWE-284: Mikro-segmentasyon sınırları dışındaki yanal harekette (Lateral Movement) fırlatılır."""
    pass


# ==============================================================================
# 2. VERİ VE BAĞLAM MODELLERİ
# ==============================================================================

@dataclass
class DevicePosture:
    """Uç nokta cihazının sağlık ve uyumluluk metrikleri (NIST SP 800-207 Posture)."""
    # Cihazın tekil donanım kimliği
    device_id: str
    # Cihazın kurumsal MDM/EDR tarafından yönetilip yönetilmediği
    is_managed: bool = True
    # Cihaz işletim sistemi sürümü
    os_version: str = "Windows 11 Enterprise"
    # Antivirüs / EDR ajanı aktif ve güncel mi?
    antivirus_active: bool = True
    # Disk şifreleme (BitLocker / FileVault) etkin mi?
    disk_encrypted: bool = True
    # En son güvenlik yamasının üzerinden geçen gün sayısı
    patch_lag_days: int = 2

    def calculate_posture_score(self) -> float:
        """Cihazın sağlık özniteliklerinden 0-100 arası sağlık puanı hesaplar."""
        score = 100.0
        # Yönetilmeyen cihazlara ağır puan kırılır (-40)
        if not self.is_managed:
            score -= 40.0
        # Antivirüs kapalıysa kritik tehlikedir (-30)
        if not self.antivirus_active:
            score -= 30.0
        # Disk şifrelenmemişse veri sızıntısı riski vardır (-20)
        if not self.disk_encrypted:
            score -= 20.0
        # Yama gecikmesi 14 günü aşmışsa ceza uygulanır
        if self.patch_lag_days > 14:
            # Her geciken gün için 2 puan düşülür
            lag_penalty = min(30.0, (self.patch_lag_days - 14) * 2.0)
            score -= lag_penalty
        # Skor 0 ile 100 arasında sınırlandırılır
        return max(0.0, min(100.0, score))


@dataclass
class JITElevationGrant:
    """Zaman kısıtlı Just-In-Time (JIT) geçici ayrıcalık belgesi."""
    # Tekil hibe kimliği
    grant_id: str
    # Ayrıcalığı alan kullanıcı
    user_id: str
    # İzin verilen spesifik kapsam (örn: 'db:patch_critical_table')
    granted_scope: str
    # İzni onaylayan yönetici/otomasyon kimliği
    approved_by: str
    # Onay zamanı
    granted_at: datetime.datetime
    # Son geçerlilik tarihi
    expires_at: datetime.datetime
    # İptal edilme bayrağı
    is_revoked: bool = False

    def is_valid(self, current_time: datetime.datetime) -> bool:
        """Hibenin süresinin dolup dolmadığını ve iptal durumunu teyit eder."""
        # Eğer manuel iptal edilmişse geçersizdir
        if self.is_revoked:
            return False
        # Geçerlilik süresi aşılmışsa geçersizdir
        if current_time > self.expires_at:
            return False
        # Tüm kontroller sağlandıysa geçerlidir
        return True


@dataclass
class ZeroTrustSession:
    """NIST SP 800-207 sürekli doğrulanan sıfır güven oturumu."""
    # Oturum tekil kimliği
    session_id: str
    # Oturum sahibi kullanıcı
    user_id: str
    # Kullanıcının çalıştığı cihazın sağlık durumu
    device: DevicePosture
    # Oturumun başlatıldığı IP adresi
    ip_address: str
    # Başlangıçta MFA doğrulaması yapıldı mı?
    mfa_verified: bool
    # Bulunulan ağ mikro-segmenti (örn: 'workstation_tier', 'dmz', 'core_banking')
    network_segment: str
    # Dinamik olarak hesaplanan güncel güven skoru (0.0 - 100.0)
    current_trust_score: float = 100.0
    # Aktif JIT yetki hibeleri sözlüğü (grant_id -> JITElevationGrant)
    jit_grants: Dict[str, JITElevationGrant] = field(default_factory=dict)
    # Şüpheli hareket sayacı
    anomaly_counter: int = 0


@dataclass
class ProtectedResource:
    """Sıfır güven koruması altındaki hedef kaynak ve erişim politikası."""
    # Kaynak tekil kimliği
    resource_id: str
    # Kaynak adı
    name: str
    # Kaynağın ait olduğu mikro-segment
    target_segment: str
    # Kaynağa erişmek için gereken asgari dinamik güven skoru
    min_trust_score: float = 75.0
    # Erişim için spesifik bir JIT kapsamı şart mı? (Boş ise standart erişim)
    required_jit_scope: Optional[str] = None
    # Ekstra Step-Up MFA doğrulaması gerekli mi?
    requires_step_up_mfa: bool = False


# ==============================================================================
# 3. EN AZ AYRICALIK (LEAST PRIVILEGE) VE JIT MOTORU
# ==============================================================================

class LeastPrivilegeManager:
    """
    Sıfır Kalıcı Ayrıcalık (Zero Standing Privileges - ZSP) ve
    İhtiyaç Anında Geçici Yetki Yükseltme (JIT Elevation) Yöneticisi.
    """

    # Kurumsal olarak izin verilen meşru JIT kapsamları ve azami TTL süreleri (saniye)
    PERMITTED_JIT_SCOPES: Dict[str, int] = {
        "db:maintenance_backup": 3600,       # 1 Saat
        "server:emergency_patch": 1800,      # 30 Dakika
        "billing:dispute_investigation": 7200, # 2 Saat
        "log:forensics_export": 900          # 15 Dakika
    }

    # Asla JIT ile dahi doğrudan izin verilmeyen aşırı/tehlikeli kapsamlar (CWE-250)
    FORBIDDEN_STANDING_SCOPES: Set[str] = {
        "*:*", "root", "superuser", "admin", "global:write", "db:drop_database"
    }

    def __init__(self):
        # Aktif veya geçmiş tüm hibeleri saklayan kayıt deposu
        self.grants_registry: Dict[str, JITElevationGrant] = {}

    def request_jit_elevation(
        self,
        user_id: str,
        target_scope: str,
        justification: str,
        approver_id: str,
        duration_seconds: int = 1800
    ) -> JITElevationGrant:
        """
        Kullanıcı için zaman kısıtlı ve gerekçelendirilmiş geçici yetki üretir.
        Kalıcı veya aşırı yetki taleplerini derhal engeller (CWE-250 / CWE-272).
        """
        # 1. Aşırı ve tehlikeli yetki talepleri engellenir (PoLP ihlali - CWE-250)
        if target_scope in self.FORBIDDEN_STANDING_SCOPES or "*:" in target_scope:
            raise StandingPrivilegeForbiddenError(
                f"Kalıcı/Sınırsız Ayrıcalık Yasağı (CWE-250): '{target_scope}' kapsamı "
                f"En Az Ayrıcalık (PoLP) ilkelerine aykırıdır; doğrudan atanamaz."
            )

        # 2. İzin verilen katalog dışındaki yetki talepleri reddedilir (CWE-272)
        if target_scope not in self.PERMITTED_JIT_SCOPES:
            raise ExcessiveScopeRequestedError(
                f"Aşırı Kapsam Talebi Reddedildi (CWE-272): '{target_scope}' yetkisi onaylı JIT listesinde yok."
            )

        # 3. Süre sınırı (TTL) kontrolü yapılır
        max_allowed_ttl = self.PERMITTED_JIT_SCOPES[target_scope]
        actual_ttl = min(duration_seconds, max_allowed_ttl)

        # 4. Geçici hibe nesnesi inşa edilir
        now = datetime.datetime.now()
        grant_id = f"JIT-{secrets.token_hex(6).upper()}"
        expires_at = now + datetime.timedelta(seconds=actual_ttl)

        grant = JITElevationGrant(
            grant_id=grant_id,
            user_id=user_id,
            granted_scope=target_scope,
            approved_by=approver_id,
            granted_at=now,
            expires_at=expires_at,
            is_revoked=False
        )

        # Sicil kaydına işlenir
        self.grants_registry[grant_id] = grant
        return grant

    def verify_jit_grant(self, grant_id: str, current_time: Optional[datetime.datetime] = None) -> JITElevationGrant:
        """Hibenin geçerliliğini teyit eder; süresi dolmuşsa istisna fırlatır."""
        check_time = current_time or datetime.datetime.now()
        # Hibe kaydı var mı?
        if grant_id not in self.grants_registry:
            raise JITElevationExpiredError("Belirtilen JIT yetki belgesi bulunamadı veya geçersiz.")

        grant = self.grants_registry[grant_id]
        # Süresi dolmuş mu veya iptal edilmiş mi? (CWE-613)
        if not grant.is_valid(check_time):
            raise JITElevationExpiredError(
                f"JIT Yetki Süresi Doldu (CWE-613): '{grant.granted_scope}' yetkisinin geçerliliği "
                f"{grant.expires_at.isoformat()} itibarıyla sona ermiştir."
            )

        return grant


# ==============================================================================
# 4. SIFIR GÜVEN (ZERO TRUST) POLİTİKA VE SÜREKLİ GÜVEN MOTORU
# ==============================================================================

class ZeroTrustPolicyEngine:
    """
    NIST SP 800-207 Sıfır Güven Mimarisi Sürekli Değerlendirme Motoru.
    Ağ konumunu (LAN/VPN) tamamen göz ardı ederek cihaz sağlığını,
    anlık risk puanını ve mikro-segment sınırlarını doğrular.
    """

    def __init__(self, least_privilege_mgr: LeastPrivilegeManager):
        # En az ayrıcalık yöneticisi referansı
        self.lp_mgr = least_privilege_mgr
        # İzin verilen mikro-segmentler arası geçiş kuralları (Source -> Allowed Targets)
        self.segment_transitions: Dict[str, Set[str]] = {
            "management_jumpbox": {"core_banking", "db_tier", "internal_apps"},
            "workstation_tier": {"internal_apps", "dmz"},
            "dmz": {"internal_apps"},
            "guest_wifi": set() # Misafir ağı hiçbir iç segmente erişemez
        }

    def evaluate_dynamic_trust_score(self, session: ZeroTrustSession) -> float:
        """
        Oturumun anlık güven skorunu sürekli hesaplar:
        Güven Skoru = (Cihaz Sağlığı * 0.40) + (MFA Gücü * 0.30) - (Anomali Cezası)
        """
        # 1. Cihaz sağlık puanı (0-100)
        posture_score = session.device.calculate_posture_score()

        # 2. MFA doğrulama katkısı (Doğrulanmışsa 100, yoksa 30)
        auth_score = 100.0 if session.mfa_verified else 30.0

        # 3. Temel güven skoru ağırlıklı ortalaması
        base_trust = (posture_score * 0.50) + (auth_score * 0.50)

        # 4. Şüpheli hareket / anomali cezası (Her anomali için 20 puan kırılır)
        anomaly_deduction = session.anomaly_counter * 20.0
        final_score = max(0.0, min(100.0, base_trust - anomaly_deduction))

        # Oturumun skoru güncellenir
        session.current_trust_score = final_score
        return final_score

    def record_session_anomaly(self, session: ZeroTrustSession, anomaly_reason: str) -> None:
        """Şüpheli veya sıra dışı işlem tespit edildiğinde anomali sayacını artırır."""
        session.anomaly_counter += 1
        # Güven skoru derhal yeniden hesaplanır
        self.evaluate_dynamic_trust_score(session)

    def enforce_micro_segmentation(self, source_segment: str, target_segment: str) -> None:
        """
        Yanal Hareketi (Lateral Movement) önlemek için mikro-segment kuralını zorlar.
        İzin verilmeyen ağ geçişleri doğrudan engellenir (CWE-284).
        """
        # Aynı segment içi iletişim veya izinli hedef kontrolü
        if source_segment == target_segment:
            return

        # Kaynak segmentin izinli hedefleri kontrol edilir
        allowed_targets = self.segment_transitions.get(source_segment, set())
        if target_segment not in allowed_targets:
            raise NetworkMicroSegmentationViolationError(
                f"Yanal Hareket Engellendi (CWE-284): '{source_segment}' segmentinden "
                f"'{target_segment}' segmentine doğrudan ağ erişimi yasaktır."
            )

    def authorize_transaction(
        self,
        session: ZeroTrustSession,
        resource: ProtectedResource,
        current_time: Optional[datetime.datetime] = None
    ) -> Tuple[bool, List[str]]:
        """
        Kaynağa erişim işlemini NIST SP 800-207 kurallarıyla doğrular.
        Tek bir şart eksikse işlem derhal durdurulur (Never Trust, Always Verify).
        """
        check_time = current_time or datetime.datetime.now()
        decision_reasons: List[str] = []

        # ----------------------------------------------------------------------
        # ADIM 1: Ağ Mikro-Segmentasyon Denetimi (CWE-284)
        # ----------------------------------------------------------------------
        self.enforce_micro_segmentation(session.network_segment, resource.target_segment)
        decision_reasons.append(f"Mikro-Segmentasyon Geçişi Onaylandı: {session.network_segment} -> {resource.target_segment}")

        # ----------------------------------------------------------------------
        # ADIM 2: Cihaz Sağlık (Posture) Denetimi (CWE-284)
        # ----------------------------------------------------------------------
        posture_score = session.device.calculate_posture_score()
        if posture_score < 60.0:
            raise DevicePostureUntrustedError(
                f"Güvenilmeyen Uç Nokta (CWE-284): Cihaz sağlık puanı {posture_score:.1f} yetersiz "
                f"(Yönetimsiz veya yamasız cihaz)."
            )
        decision_reasons.append(f"Cihaz Sağlığı Uygun (Puan: {posture_score:.1f})")

        # ----------------------------------------------------------------------
        # ADIM 3: Step-Up MFA Doğrulama Denetimi (CWE-308)
        # ----------------------------------------------------------------------
        if resource.requires_step_up_mfa and not session.mfa_verified:
            raise StepUpAuthenticationRequiredError(
                "Kritik İşlem Güvenliği (CWE-308): Bu kaynağa erişim anlık Step-Up MFA doğrulaması gerektirir."
            )
        if resource.requires_step_up_mfa:
            decision_reasons.append("Step-Up MFA Doğrulaması Başarılı")

        # ----------------------------------------------------------------------
        # ADIM 4: Dinamik Güven Skoru Doğrulaması (CWE-284)
        # ----------------------------------------------------------------------
        trust_score = self.evaluate_dynamic_trust_score(session)
        if trust_score < resource.min_trust_score:
            raise DynamicTrustScoreDegradedError(
                f"Yetersiz Güven Skoru (CWE-284): Mevcut skor ({trust_score:.1f}), "
                f"kaynağın gerektirdiği asgari skoru ({resource.min_trust_score:.1f}) karşılamıyor."
            )
        decision_reasons.append(f"Dinamik Güven Skoru Yeterli ({trust_score:.1f} >= {resource.min_trust_score:.1f})")

        # ----------------------------------------------------------------------
        # ADIM 5: En Az Ayrıcalık — JIT Kapsam Doğrulaması (CWE-272 / CWE-613)
        # ----------------------------------------------------------------------
        if resource.required_jit_scope:
            # Oturumda bu kapsama sahip geçerli bir JIT hibesi var mı?
            matching_grant = None
            for grant in session.jit_grants.values():
                if grant.granted_scope == resource.required_jit_scope and grant.is_valid(check_time):
                    matching_grant = grant
                    break

            if not matching_grant:
                raise JITElevationExpiredError(
                    f"Geçerli JIT Yetkisi Bulunamadı (CWE-613): '{resource.name}' kaynağına erişmek için "
                    f"aktif '{resource.required_jit_scope}' JIT hibesi zorunludur."
                )
            decision_reasons.append(f"Geçerli JIT Hibesi Teyit Edildi ({matching_grant.grant_id})")

        # Tüm adımlar başarıyla geçildi
        return True, decision_reasons


# ==============================================================================
# 5. ORKESTRASYON VE DENETİM İZİ YÖNETİCİSİ
# ==============================================================================

class ZeroTrustOrchestrator:
    """Sıfır Güven ve En Az Ayrıcalık mimarisinin merkezi koordinatörü."""

    def __init__(self):
        # En az ayrıcalık yöneticisi
        self.lp_mgr = LeastPrivilegeManager()
        # Sıfır güven politika motoru
        self.zt_engine = ZeroTrustPolicyEngine(self.lp_mgr)
        # Aktif oturumlar deposu (session_id -> ZeroTrustSession)
        self.active_sessions: Dict[str, ZeroTrustSession] = {}
        # Denetim günlükleri
        self.audit_log: List[Dict[str, Any]] = []

    def create_session(
        self,
        user_id: str,
        device: DevicePosture,
        ip_address: str,
        mfa_verified: bool,
        network_segment: str
    ) -> ZeroTrustSession:
        """Yeni bir sıfır güven oturumu başlatır ve başlangıç güven skorunu hesaplar."""
        session_id = f"ZTS-{uuid.uuid4().hex[:12].upper()}"
        session = ZeroTrustSession(
            session_id=session_id,
            user_id=user_id,
            device=device,
            ip_address=ip_address,
            mfa_verified=mfa_verified,
            network_segment=network_segment
        )
        # İlk güven skoru hesaplanır
        self.zt_engine.evaluate_dynamic_trust_score(session)
        self.active_sessions[session_id] = session
        return session

    def request_access(
        self,
        session_id: str,
        resource: ProtectedResource,
        current_time: Optional[datetime.datetime] = None
    ) -> Dict[str, Any]:
        """Erişim talebini baştan sona değerlendirir ve yapılandırılmış denetim izi üretir."""
        check_time = current_time or datetime.datetime.now()
        audit_id = f"AUD-ZT-{secrets.token_hex(4).upper()}"

        if session_id not in self.active_sessions:
            raise ZeroTrustSecurityError("Geçersiz veya sonlandırılmış oturum kimliği.")

        session = self.active_sessions[session_id]

        try:
            allowed, reasons = self.zt_engine.authorize_transaction(session, resource, check_time)
            record = {
                "audit_id": audit_id,
                "timestamp": check_time.isoformat(),
                "status": "ACCESS_GRANTED",
                "user_id": session.user_id,
                "session_id": session_id,
                "resource_id": resource.resource_id,
                "resource_name": resource.name,
                "trust_score": session.current_trust_score,
                "reasons": reasons
            }
            self.audit_log.append(record)
            return record
        except ZeroTrustSecurityError as zt_err:
            record = {
                "audit_id": audit_id,
                "timestamp": check_time.isoformat(),
                "status": "ACCESS_DENIED",
                "user_id": session.user_id,
                "session_id": session_id,
                "resource_id": resource.resource_id,
                "resource_name": resource.name,
                "trust_score": session.current_trust_score,
                "reasons": [str(zt_err)],
                "error_class": zt_err.__class__.__name__
            }
            self.audit_log.append(record)
            raise

    def export_audit_logs_json(self) -> str:
        """Tüm sıfır güven denetim izlerini JSON formatında döndürür."""
        return json.dumps(self.audit_log, indent=2, ensure_ascii=False)
