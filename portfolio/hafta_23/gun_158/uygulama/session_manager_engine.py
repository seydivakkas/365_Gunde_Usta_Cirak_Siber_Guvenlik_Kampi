# -*- coding: utf-8 -*-
"""
Kurumsal Web Oturum Yönetimi ve Süresi Güvenlik Motoru
Hafta 23 / Gün 158 - Aşama 7 (Web Güvenliği)

Bu motor; HTTP oturumlarının tüm yaşam döngüsünü (Oluşturma, Doğrulama, Boşta Kalma
ve Mutlak Zaman Aşımları, Oturum Sabitleme/Fixation Koruması, Oturum Rotasyonu,
Eşzamanlı Oturum Sınırlandırması ve Sunucu Taraflı İptal) OWASP Session Management
standartlarına göre yönetir ve denetler.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import secrets
import math
import time
import json


class SessionState(str, Enum):
    """Oturumun yaşam döngüsü durumları."""
    # Aktif ve geçerli oturum
    ACTIVE = "Aktif"
    # Boşta kalma (inactivity/idle) zaman aşımı nedeniyle sonlandırılmış
    EXPIRED_IDLE = "ZamanAsimi_Bosta"
    # Mutlak (absolute) ömür tamamlandığı için zorla sonlandırılmış
    EXPIRED_ABSOLUTE = "ZamanAsimi_Mutlak"
    # Kullanıcı çıkışı veya yönetici tarafından sunucu tarafında iptal edilmiş
    REVOKED = "IptalEdildi"
    # User-Agent veya IP uyuşmazlığı nedeniyle oturum hırsızlığı şüphesiyle askıya alınmış
    SUSPENDED_HIJACK_RISK = "Askida_HirsizlikSuphesi"


@dataclass
class UserSession:
    """Tek bir kullanıcı oturumunun bellek kaydı ve güvenlik bağlamı."""
    # Kriptografik yüksek entropili benzersiz oturum belirteci
    session_id: str
    # Kullanıcı kimlik numarası
    user_id: str
    # Kullanıcı adı
    username: str
    # Kullanıcı yetki rolü (User, Admin, Auditor vb.)
    role: str
    # Oturumun başlatıldığı istemci IP adresi
    client_ip: str
    # Oturumun başlatıldığı istemci tarayıcı kimliği (User-Agent)
    user_agent: str
    # Oturumun oluşturulduğu Unix zaman damgası
    created_at_epoch: float
    # Son aktivite / istek Unix zaman damgası
    last_activity_epoch: float
    # Mevcut oturum durumu
    state: SessionState = SessionState.ACTIVE
    # Ayrıcalık yükseltme (Privilege Escalation) yapılıp yapılmadığı
    privilege_escalated: bool = False
    # Oturum kimliği kaç kez güvenli rotasyona uğradı
    rotation_count: int = 0


@dataclass
class SessionPolicy:
    """Kurumsal oturum yaşam döngüsü ve güvenlik politikaları."""
    # Boşta kalma zaman aşımı (saniye cinsinden - örn: 15 dakika = 900 sn)
    idle_timeout_seconds: int = 900
    # Mutlak maksimum oturum ömrü (saniye cinsinden - örn: 8 saat = 28800 sn)
    absolute_timeout_seconds: int = 28800
    # Kullanıcı başına izin verilen maksimum eşzamanlı aktif oturum sayısı
    max_concurrent_sessions: int = 3
    # User-Agent bağlama kontrolü aktif mi?
    bind_user_agent: bool = True
    # IP adresi bağlama kontrolü aktif mi?
    bind_ip: bool = True
    # Asgari oturum belirteci entropi gereksinimi (bit cinsinden)
    min_session_id_entropy_bits: int = 128
    # Otomatik periyodik kimlik rotasyonu süresi (saniye cinsinden - örn: 30 dk = 1800 sn)
    rotation_interval_seconds: int = 1800


@dataclass
class SessionValidationResult:
    """Oturum doğrulama isteğinin güvenlik sonucu."""
    # Oturum geçerli mi ve isteğe devam edebilir mi?
    is_valid: bool
    # Oturumun nihai durumu
    status: SessionState
    # Doğrulanan oturum kimliği
    session_id: str
    # Güvenlik kararı açıklama metni
    reason: str
    # Oturum kimliğinin periyodik olarak yenilenmesi gerekiyor mu?
    requires_rotation: bool = False
    # Rotasyon gerçekleştiyse üretilen yeni oturum kimliği
    new_session_id: Optional[str] = None


class SessionManagerEngine:
    """OWASP Standartlarında Oturum Yönetimi ve Süresi Güvenlik Motoru."""

    def __init__(self, policy: Optional[SessionPolicy] = None):
        """Oturum motorunu belirtilen veya varsayılan kurumsal politika ile başlatır."""
        # Oturum güvenlik politikası nesnesi
        self.policy = policy if policy is not None else SessionPolicy()
        # Sunucu tarafında saklanan oturum tablosu (In-Memory / Redis simülasyonu)
        self.active_sessions: Dict[str, UserSession] = {}
        # Denetim logları listesi
        self.audit_logs: List[Dict[str, Any]] = []

    def calculate_entropy_bits(self, token: str) -> float:
        """Verilen oturum anahtarının Shannon entropisini hesaplar."""
        if not token:
            return 0.0
        # Karakter frekanslarını sayma
        freq: Dict[str, int] = {}
        for char in token:
            freq[char] = freq.get(char, 0) + 1
        
        # Shannon entropi formülü: -sum(p * log2(p))
        entropy = 0.0
        length = len(token)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        # Toplam teorik bit entropisi
        return round(entropy * length, 2)

    def generate_secure_session_id(self) -> str:
        """Kriptografik olarak güvenli 256-bit (32 bayt hex) rastgele oturum kimliği üretir."""
        # secrets modülü CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) kullanır
        raw_id = secrets.token_hex(32)
        # Entropi kontrolü: 32 bayt hex en az 128 bit Shannon entropisine sahip olmalıdır
        entropy = self.calculate_entropy_bits(raw_id)
        if entropy < self.policy.min_session_id_entropy_bits:
            raise ValueError(f"Yetersiz oturum entropisi: {entropy} bit (Asgari: {self.policy.min_session_id_entropy_bits})")
        return raw_id

    def create_session(
        self,
        user_id: str,
        username: str,
        role: str,
        client_ip: str,
        user_agent: str,
        current_time: Optional[float] = None
    ) -> UserSession:
        """Yeni bir kullanıcı oturumu başlatır ve eşzamanlı oturum politikasını uygular."""
        now = current_time if current_time is not None else time.time()

        # 1. Adım: Kullanıcının mevcut aktif oturumlarını sayma ve eşzamanlı sınır kontrolü
        user_sessions = [
            s for s in self.active_sessions.values()
            if s.user_id == user_id and s.state == SessionState.ACTIVE
        ]

        # Eğer kullanıcı eşzamanlı oturum limitine ulaştıysa en eski oturumu otomatik sonlandırma (FIFO)
        if len(user_sessions) >= self.policy.max_concurrent_sessions:
            user_sessions.sort(key=lambda s: s.created_at_epoch)
            oldest_session = user_sessions[0]
            oldest_session.state = SessionState.REVOKED
            self._log_event(
                "CONCURRENT_SESSION_LIMIT_EXCEEDED",
                f"Kullanıcı '{username}' eşzamanlı limit ({self.policy.max_concurrent_sessions}) aştı. Eski oturum ({oldest_session.session_id[:8]}...) sonlandırıldı.",
                oldest_session.session_id
            )

        # 2. Adım: Kriptografik güvenli oturum kimliği üretme
        session_id = self.generate_secure_session_id()

        # 3. Adım: Oturum nesnesini oluşturma ve bağlama bilgilerini mühürleme
        new_session = UserSession(
            session_id=session_id,
            user_id=user_id,
            username=username,
            role=role,
            client_ip=client_ip,
            user_agent=user_agent,
            created_at_epoch=now,
            last_activity_epoch=now,
            state=SessionState.ACTIVE
        )

        # Oturum tablosuna kaydetme
        self.active_sessions[session_id] = new_session
        self._log_event("SESSION_CREATED", f"Kullanıcı '{username}' için yeni güvenli oturum açıldı.", session_id)
        return new_session

    def validate_session(
        self,
        session_id: str,
        client_ip: str,
        user_agent: str,
        current_time: Optional[float] = None
    ) -> SessionValidationResult:
        """Gelen HTTP isteğindeki oturum kimliğini tüm güvenlik ve zaman aşımı kurallarına göre denetler."""
        now = current_time if current_time is not None else time.time()

        # 1. Kontrol: Oturum kimliği sunucu tablosunda var mı?
        if session_id not in self.active_sessions:
            self._log_event("SESSION_NOT_FOUND", "Bilinmeyen veya önceden silinmiş oturum kimliği ile istek geldi.", session_id)
            return SessionValidationResult(
                is_valid=False,
                status=SessionState.REVOKED,
                session_id=session_id,
                reason="Geçersiz veya sunucu tarafında bulunamayan oturum kimliği."
            )

        session = self.active_sessions[session_id]

        # 2. Kontrol: Oturum zaten iptal edilmiş veya askıya alınmış mı?
        if session.state != SessionState.ACTIVE:
            self._log_event("SESSION_INACTIVE", f"İnaktif oturumla erişim denemesi: {session.state.value}", session_id)
            return SessionValidationResult(
                is_valid=False,
                status=session.state,
                session_id=session_id,
                reason=f"Oturum aktif değil (Durum: {session.state.value})."
            )

        # 3. Kontrol: Mutlak Maksimum Oturum Ömrü Zaman Aşımı (Absolute Timeout)
        if (now - session.created_at_epoch) > self.policy.absolute_timeout_seconds:
            session.state = SessionState.EXPIRED_ABSOLUTE
            self._log_event("ABSOLUTE_TIMEOUT", f"Oturum mutlak ömrünü doldurdu ({self.policy.absolute_timeout_seconds} sn).", session_id)
            return SessionValidationResult(
                is_valid=False,
                status=SessionState.EXPIRED_ABSOLUTE,
                session_id=session_id,
                reason="Oturum mutlak süresi doldu; yeniden kimlik doğrulanmalıdır."
            )

        # 4. Kontrol: Boşta Kalma Zaman Aşımı (Idle / Inactivity Timeout)
        if (now - session.last_activity_epoch) > self.policy.idle_timeout_seconds:
            session.state = SessionState.EXPIRED_IDLE
            self._log_event("IDLE_TIMEOUT", f"Oturum boşta kalma süresini aştı ({self.policy.idle_timeout_seconds} sn).", session_id)
            return SessionValidationResult(
                is_valid=False,
                status=SessionState.EXPIRED_IDLE,
                session_id=session_id,
                reason="Oturum hareketsizlik nedeniyle zaman aşımına uğradı."
            )

        # 5. Kontrol: User-Agent Parmak İzi Bağlamı (Session Hijacking Savunması)
        if self.policy.bind_user_agent and session.user_agent != user_agent:
            session.state = SessionState.SUSPENDED_HIJACK_RISK
            self._log_event(
                "USER_AGENT_MISMATCH_SUSPECTED_HIJACK",
                f"Oturum hırsızlığı şüphesi! Kayıtlı: '{session.user_agent}' | Gelen: '{user_agent}'",
                session_id
            )
            return SessionValidationResult(
                is_valid=False,
                status=SessionState.SUSPENDED_HIJACK_RISK,
                session_id=session_id,
                reason="Tarayıcı parmak izi uyuşmazlığı; potansiyel oturum kaçırma girişimi tespit edildi."
            )

        # 6. Kontrol: IP Adresi Bağlamı (IP Binding)
        if self.policy.bind_ip and session.client_ip != client_ip:
            session.state = SessionState.SUSPENDED_HIJACK_RISK
            self._log_event(
                "IP_MISMATCH_SUSPECTED_HIJACK",
                f"Farklı IP adresinden erişim! Kayıtlı: '{session.client_ip}' | Gelen: '{client_ip}'",
                session_id
            )
            return SessionValidationResult(
                is_valid=False,
                status=SessionState.SUSPENDED_HIJACK_RISK,
                session_id=session_id,
                reason="İstemci IP adresi uyuşmazlığı; oturum askıya alındı."
            )

        # Başarılı doğrulama: Son etkinlik zaman damgasını güncelleme
        session.last_activity_epoch = now

        # Periyodik Oturum Rotasyonu Gereksinimi Kontrolü
        requires_rotation = (now - session.created_at_epoch) > (self.policy.rotation_interval_seconds * (session.rotation_count + 1))
        new_session_id = None
        if requires_rotation:
            rotated_session = self.regenerate_session_id(session_id, current_time=now)
            new_session_id = rotated_session.session_id

        return SessionValidationResult(
            is_valid=True,
            status=SessionState.ACTIVE,
            session_id=session_id,
            reason="Oturum geçerli ve aktif.",
            requires_rotation=requires_rotation,
            new_session_id=new_session_id
        )

    def regenerate_session_id(self, old_session_id: str, current_time: Optional[float] = None) -> UserSession:
        """Oturum Sabitleme (Fixation) koruması için eski ID'yi iptal edip yeni ID üretir."""
        now = current_time if current_time is not None else time.time()

        if old_session_id not in self.active_sessions:
            raise KeyError(f"Rotasyon yapılacak oturum bulunamadı: {old_session_id}")

        old_session = self.active_sessions[old_session_id]

        # Yeni kriptografik anahtar üretme
        new_id = self.generate_secure_session_id()

        # Eski oturumu sunucu tarafında iptal etme
        old_session.state = SessionState.REVOKED
        del self.active_sessions[old_session_id]

        # Yeni oturum nesnesini oluşturma
        new_session = UserSession(
            session_id=new_id,
            user_id=old_session.user_id,
            username=old_session.username,
            role=old_session.role,
            client_ip=old_session.client_ip,
            user_agent=old_session.user_agent,
            created_at_epoch=old_session.created_at_epoch,  # Mutlak ömür korunur!
            last_activity_epoch=now,
            state=SessionState.ACTIVE,
            privilege_escalated=old_session.privilege_escalated,
            rotation_count=old_session.rotation_count + 1
        )

        self.active_sessions[new_id] = new_session
        self._log_event(
            "SESSION_ID_ROTATED",
            f"Oturum kimliği yenilendi ({old_session_id[:8]}... -> {new_id[:8]}...).",
            new_id
        )
        return new_session

    def elevate_privilege(self, session_id: str, new_role: str, current_time: Optional[float] = None) -> UserSession:
        """Kullanıcı rol yükseltmesi yaptığında oturum sabitlemeyi önlemek için ID'yi zorla yeniler."""
        now = current_time if current_time is not None else time.time()

        if session_id not in self.active_sessions:
            raise KeyError(f"Yetki yükseltilecek oturum bulunamadı: {session_id}")

        old_session = self.active_sessions[session_id]
        old_session.role = new_role
        old_session.privilege_escalated = True

        # OWASP Kuralı: Yetki seviyesi değiştiğinde (Privilege Escalation) oturum kimliği ZORUNLU YENİLENİR
        rotated = self.regenerate_session_id(session_id, current_time=now)
        rotated.role = new_role
        rotated.privilege_escalated = True

        self._log_event(
            "PRIVILEGE_ELEVATION_WITH_ROTATION",
            f"Rol '{new_role}' seviyesine yükseltildi ve oturum kimliği güvenle yenilendi.",
            rotated.session_id
        )
        return rotated

    def terminate_session(self, session_id: str, reason: str = "User Logout") -> bool:
        """Sunucu tarafında oturumu kalıcı olarak iptal eder (Server-side Invalidation)."""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session.state = SessionState.REVOKED
            self._log_event("SESSION_TERMINATED", f"Oturum sunucu tarafında sonlandırıldı: {reason}", session_id)
            return True
        return False

    def terminate_all_user_sessions(self, user_id: str, reason: str = "Password Changed") -> int:
        """Bir kullanıcının tüm açık oturumlarını sonlandırır (Örn: Parola değiştiğinde)."""
        count = 0
        for session in list(self.active_sessions.values()):
            if session.user_id == user_id and session.state == SessionState.ACTIVE:
                session.state = SessionState.REVOKED
                count += 1
                self._log_event("GLOBAL_USER_REVOCATION", f"Kullanıcıya ait tüm oturumlar kapatıldı: {reason}", session.session_id)
        return count

    def clean_expired_sessions(self, current_time: Optional[float] = None) -> int:
        """Süresi dolmuş veya iptal edilmiş oturumları bellekten temizler (Garbage Collection)."""
        now = current_time if current_time is not None else time.time()
        to_delete = []

        for sid, session in self.active_sessions.items():
            # Mutlak süre kontrolü
            if (now - session.created_at_epoch) > self.policy.absolute_timeout_seconds:
                to_delete.append(sid)
            # Boşta kalma süresi kontrolü
            elif (now - session.last_activity_epoch) > self.policy.idle_timeout_seconds:
                to_delete.append(sid)
            # Zaten iptal edilmiş durumlar
            elif session.state in (SessionState.REVOKED, SessionState.SUSPENDED_HIJACK_RISK):
                to_delete.append(sid)

        for sid in to_delete:
            del self.active_sessions[sid]

        return len(to_delete)

    def _log_event(self, event_type: str, message: str, session_id: str):
        """Güvenlik denetim günlüğüne olay kaydeder."""
        self.audit_logs.append({
            "timestamp": time.time(),
            "event_type": event_type,
            "message": message,
            "session_id_prefix": session_id[:8] if session_id else "NONE"
        })

    def audit_lifecycle(self) -> Dict[str, Any]:
        """Tüm oturum tablosunun istatistiksel durumunu ve güvenlik karnesini döndürür."""
        total = len(self.active_sessions)
        active = sum(1 for s in self.active_sessions.values() if s.state == SessionState.ACTIVE)
        revoked = sum(1 for s in self.active_sessions.values() if s.state == SessionState.REVOKED)
        suspended = sum(1 for s in self.active_sessions.values() if s.state == SessionState.SUSPENDED_HIJACK_RISK)
        expired_idle = sum(1 for s in self.active_sessions.values() if s.state == SessionState.EXPIRED_IDLE)
        expired_abs = sum(1 for s in self.active_sessions.values() if s.state == SessionState.EXPIRED_ABSOLUTE)

        return {
            "total_tracked_sessions": total,
            "active_sessions_count": active,
            "revoked_sessions_count": revoked,
            "suspended_sessions_count": suspended,
            "expired_idle_count": expired_idle,
            "expired_absolute_count": expired_abs,
            "total_audit_events": len(self.audit_logs),
            "policy": asdict(self.policy)
        }

    def generate_ascii_lifecycle(self) -> str:
        """Konsol için görsel ASCII oturum durumu panosu üretir."""
        stats = self.audit_lifecycle()
        lines: List[str] = []
        lines.append("=" * 86)
        lines.append(" KURUMSAL OTURUM YÖNETİMİ VE SÜRESİ DENETİM PANOSU (GÜN 158)")
        lines.append("=" * 86)
        lines.append(f" Boşta Kalma Zaman Aşımı (Idle)     : {self.policy.idle_timeout_seconds} sn ({round(self.policy.idle_timeout_seconds / 60)} dakika)")
        lines.append(f" Mutlak Oturum Ömrü (Absolute)      : {self.policy.absolute_timeout_seconds} sn ({round(self.policy.absolute_timeout_seconds / 3600)} saat)")
        lines.append(f" Eşzamanlı Oturum Limiti (Maks)     : {self.policy.max_concurrent_sessions} oturum/kullanıcı")
        lines.append(f" User-Agent / IP Bağlama Güvenliği  : {'ETKİN' if self.policy.bind_user_agent else 'DEVRE DIŞI'}")
        lines.append("-" * 86)
        lines.append(f" Toplam Kayıtlı Oturum Sayısı       : {stats['total_tracked_sessions']}")
        lines.append(f" Aktif Oturumlar                    : {stats['active_sessions_count']}")
        lines.append(f" Boşta Kalarak Süresi Dolanlar      : {stats['expired_idle_count']}")
        lines.append(f" Mutlak Ömrü Bitenler               : {stats['expired_absolute_count']}")
        lines.append(f" İptal Edilen / Çıkış Yapılanlar    : {stats['revoked_sessions_count']}")
        lines.append(f" Hırsızlık Şüphesiyle Askıya Alınan : {stats['suspended_sessions_count']}")
        lines.append("=" * 86)
        return "\n".join(lines)
