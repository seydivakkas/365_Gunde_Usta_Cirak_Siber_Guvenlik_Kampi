# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 124: Secrets Yönetimi ve Çevre Değişkenleri Çekirdek Motoru.
Bu modül; kurumsal Secret Vault mimarisini, zarflı şifrelemeyi (Envelope Encryption),
otomatik secret rotasyonunu, CWE-798 Hardcoded Secret statik tespit tarayıcısını (Shannon Entropy)
ve CWE-532 log içi gizli veri maskeleme mekanizmasını içerir.
"""

# Standart enum modülü içe aktarılıyor
from enum import Enum
# Veri sınıfları için dataclass ve field içe aktarılıyor
from dataclasses import dataclass, field
# Tip ipuçları için tipler içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any, Set
# Zaman ve süre işlemleri için datetime ve timedelta içe aktarılıyor
from datetime import datetime, timedelta
# Kriptografik özet ve PBKDF2 için hashlib içe aktarılıyor
import hashlib
# Mesaj doğrulama kodu (HMAC) için hmac içe aktarılıyor
import hmac
# Kriptografik güvenli rastgele byte üretimi için secrets modülü içe aktarılıyor
import secrets
# Düzenli ifadeler ve kalıp eşleme için re modülü içe aktarılıyor
import re
# Shannon entropi hesaplaması için log2 math modülünden içe aktarılıyor
from math import log2
# JSON serileştirme işlemleri için json modülü içe aktarılıyor
import json


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class SecretsEngineError(Exception):
    """Secrets yönetim motoru temel istisna sınıfı."""
    pass


class HardcodedSecretDetectedError(SecretsEngineError):
    """Kaynak kodda veya yapılandırmada sabit kodlanmış gizli anahtar bulunduğunda fırlatılır (CWE-798)."""
    pass


class SecretAccessDeniedError(SecretsEngineError):
    """Talep eden rolün gizli anahtara erişim yetkisi olmadığında fırlatılır (CWE-285)."""
    pass


class SecretExpiredError(SecretsEngineError):
    """Gizli anahtarın kullanım süresi (TTL) dolduğunda fırlatılır (CWE-613)."""
    pass


class SecretRevokedError(SecretsEngineError):
    """İptal edilmiş (revoked) bir gizli anahtara erişilmeye çalışıldığında fırlatılır."""
    pass


class SecretRotationRequiredError(SecretsEngineError):
    """Rotasyon süresi geçmiş bir anahtar yenilenmeden kullanılmaya çalışıldığında fırlatılır."""
    pass


class InvalidSecretPayloadError(SecretsEngineError):
    """Gizli anahtar içeriği veya parametreleri geçersiz olduğunda fırlatılır."""
    pass


class DuplicateSecretError(SecretsEngineError):
    """Aynı kimliğe sahip mükerrer gizli anahtar kaydedilmeye çalışıldığında fırlatılır."""
    pass


class SecretNotFoundError(SecretsEngineError):
    """Kayıtlı olmayan bir secret ID talep edildiğinde fırlatılır."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class SecretType(Enum):
    """Gizli veri sınıflandırma kategorileri."""
    API_KEY = "API Anahtarı (API Key)"
    DATABASE_PASSWORD = "Veritabanı Parolası (Database Password)"
    PRIVATE_KEY = "Asimetrik Özel Anahtar (Private Key)"
    JWT_SECRET = "JWT İmza Sırrı (HMAC Secret)"
    OAUTH_CLIENT_SECRET = "OAuth İstemci Parolası"
    ENCRYPTION_KEY = "Veri Şifreleme Anahtarı (DEK)"


class SecretState(Enum):
    """Gizli anahtar yaşam döngüsü durumları."""
    ACTIVE = "AKTİF"             # Normal kullanımda ve geçerli
    ROTATED = "ROTASYONA_UĞRADI"  # Yeni versiyon üretildi, geçici zarafet süresinde
    REVOKED = "İPTAL_EDİLDİ"      # Güvenlik ihlali nedeniyle kullanıma kapatıldı
    EXPIRED = "SÜRESİ_DOLDU"      # Yaşam döngüsü süresi (TTL) bitti


@dataclass
class EncryptedSecretPayload:
    """Zarflı şifreleme (Envelope Encryption) ile korunmuş gizli veri nesnesi."""
    ciphertext_hex: str                  # Şifrelenmiş veri (Hex)
    salt_hex: str                        # PBKDF2 tuz değeri (Hex)
    nonce_hex: str                       # Tek kullanımlık rastgele değer (Hex)
    tag_hex: str                         # Bütünlük doğrulama HMAC etiketi (Hex)


@dataclass
class SecretMetadata:
    """Gizli anahtar meta verisi ve yaşam döngüsü bilgileri."""
    secret_id: str                       # Benzersiz kimlik (örn: 'SEC-DB-PROD')
    name: str                            # Okunabilir anahtar adı
    secret_type: SecretType              # Anahtar sınıfı
    version: int                         # Versiyon numarası (1, 2, 3...)
    state: SecretState                   # Yaşam döngüsü durumu
    created_at: datetime                 # Oluşturulma zamanı
    expires_at: datetime                 # Son kullanma zamanı (TTL)
    rotation_interval_days: int          # Zorunlu rotasyon sıklığı (gün)
    allowed_roles: List[str]             # Erişebilen roller (Least Privilege)
    access_count: int = 0                # Toplam erişim sayısı
    last_accessed_at: Optional[datetime] = None # Son erişim zamanı


# ============================================================================
# KRİPTOGRAFİK ZARFLI ŞİFRELEME YARDIMCISI (ENVELOPE ENCRYPTION)
# ============================================================================

class CryptoVaultHelper:
    """Saf Python standart kütüphanesiyle zarflı şifreleme ve bütünlük sağlayan yardımcı sınıf."""

    @staticmethod
    def derive_key(master_key: str, salt: bytes) -> bytes:
        """Ana anahtardan PBKDF2-HMAC-SHA256 kullanarak 256 bitlik oturum anahtarı türetir."""
        # PBKDF2 ile 100.000 iterasyon yapılarak 32 byte anahtar türetilir
        return hashlib.pbkdf2_hmac("sha256", master_key.encode("utf-8"), salt, 100000, dklen=32)

    @staticmethod
    def encrypt(plaintext: str, master_key: str) -> EncryptedSecretPayload:
        """Metni tuz, nonce ve HMAC etiketiyle şifreler."""
        # 16 byte kriptografik tuz üretilir
        salt = secrets.token_bytes(16)
        # 16 byte nonce üretilir
        nonce = secrets.token_bytes(16)
        # Oturum anahtarı türetilir
        derived_key = CryptoVaultHelper.derive_key(master_key, salt)
        # Düz metin byte dizisine dönüştürülür
        data_bytes = plaintext.encode("utf-8")
        # Güvenli XOR akış şifrelemesi simülasyonu için anahtar genişletilir
        keystream = hashlib.sha256(derived_key + nonce).digest()
        # Veri boyutu kadar keystream genişletilir
        extended_stream = bytearray()
        counter = 0
        while len(extended_stream) < len(data_bytes):
            extended_stream.extend(hashlib.sha256(keystream + counter.to_bytes(4, "big")).digest())
            counter += 1
        # XOR işlemiyle şifreli metin elde edilir
        ciphertext = bytes([b ^ k for b, k in zip(data_bytes, extended_stream[:len(data_bytes)])])
        # Verinin bütünlüğünü garanti etmek için HMAC-SHA256 etiketi hesaplanır
        tag = hmac.new(derived_key, ciphertext + nonce, hashlib.sha256).digest()
        # Şifreli yük nesnesi döndürülür
        return EncryptedSecretPayload(
            ciphertext_hex=ciphertext.hex(),
            salt_hex=salt.hex(),
            nonce_hex=nonce.hex(),
            tag_hex=tag.hex()
        )

    @staticmethod
    def decrypt(payload: EncryptedSecretPayload, master_key: str) -> str:
        """Şifreli yükün bütünlüğünü doğrular ve düz metne dönüştürür."""
        # Hex değerler byte dizilerine çevrilir
        salt = bytes.fromhex(payload.salt_hex)
        nonce = bytes.fromhex(payload.nonce_hex)
        ciphertext = bytes.fromhex(payload.ciphertext_hex)
        tag = bytes.fromhex(payload.tag_hex)
        # Anahtar türetilir
        derived_key = CryptoVaultHelper.derive_key(master_key, salt)
        # HMAC etiketi doğrulanır
        expected_tag = hmac.new(derived_key, ciphertext + nonce, hashlib.sha256).digest()
        # Sabit zamanlı karşılaştırma (Timing Attack önlemi)
        if not hmac.compare_digest(tag, expected_tag):
            # Bütünlük hatası fırlatılır
            raise InvalidSecretPayloadError("Kriptografik bütünlük hatası: Secret tahrif edilmiş veya anahtar yanlış!")
        # Keystream tekrar üretilir
        keystream = hashlib.sha256(derived_key + nonce).digest()
        extended_stream = bytearray()
        counter = 0
        while len(extended_stream) < len(ciphertext):
            extended_stream.extend(hashlib.sha256(keystream + counter.to_bytes(4, "big")).digest())
            counter += 1
        # XOR ile orijinal metin çözülür
        plaintext_bytes = bytes([b ^ k for b, k in zip(ciphertext, extended_stream[:len(ciphertext)])])
        # UTF-8 dizgesi olarak döndürülür
        return plaintext_bytes.decode("utf-8")


# ============================================================================
# STATİK SECRET TESPİT VE ENTROPİ TARAYICISI (CWE-798 SCANNER)
# ============================================================================

class SecretScanner:
    """Kaynak kodlarda veya dosyalarda sabit kodlanmış gizli verileri (CWE-798) tarar."""

    # Bilinen gizli anahtar regex kalıpları
    PATTERNS: Dict[str, str] = {
        "AWS_ACCESS_KEY": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "STRIPE_SECRET_KEY": r"(?:sk_live_|sk_test_)[0-9a-zA-Z]{24}",
        "SLACK_BOT_TOKEN": r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        "JWT_TOKEN": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "GENERIC_PASSWORD": r"(?i)(?:password|passwd|pwd|secret|api_key|apikey)\s*=\s*['\"][^'\"]{8,}['\"]",
        "PRIVATE_KEY_BLOCK": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    }

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Shannon entropi formülü ile bir dizginin rastgelelik / karmaşıklık derecesini hesaplar."""
        # Boş dizgide entropi sıfırdır
        if not data:
            return 0.0
        # Karakter frekansları hesaplanır
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        # Toplam uzunluk alınır
        length = len(data)
        # Shannon entropi toplamı: - sum(p * log2(p))
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * log2(p)
        return entropy

    @classmethod
    def scan_text(cls, content: str, entropy_threshold: float = 4.2) -> List[Dict[str, Any]]:
        """Metin içeriğini hem regex kalıplarıyla hem de yüksek entropi analiziyle tarar."""
        findings: List[Dict[str, Any]] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            # 1. Regex Kalıp Taraması
            for pat_name, pat_regex in cls.PATTERNS.items():
                match = re.search(pat_regex, line_str)
                if match:
                    findings.append({
                        "line_number": idx,
                        "detection_type": "REGEX_PATTERN",
                        "pattern_name": pat_name,
                        "matched_sample": match.group(0)[:8] + "..." + match.group(0)[-4:] if len(match.group(0)) > 12 else "[KORUMALI]",
                        "description": f"Satır {idx} üzerinde bilinen '{pat_name}' kalıbı tespit edildi (CWE-798)."
                    })

            # 2. Yüksek Entropili Token Taraması (Tırnak içindeki tokenlar)
            tokens = re.findall(r"['\"]([^'\"\s]{16,})['\"]", line_str)
            for tok in tokens:
                entropy = cls.calculate_shannon_entropy(tok)
                if entropy >= entropy_threshold:
                    findings.append({
                        "line_number": idx,
                        "detection_type": "HIGH_ENTROPY_TOKEN",
                        "pattern_name": f"Shannon Entropy: {entropy:.2f}",
                        "matched_sample": tok[:6] + "..." + tok[-4:],
                        "description": f"Satır {idx} üzerinde yüksek entropili ({entropy:.2f} >= {entropy_threshold}) gizli anahtar bulundu (CWE-798)."
                    })

        return findings


# ============================================================================
# MERKEZİ SECRET KASASI YÖNETİCİSİ (SECRET VAULT MANAGER)
# ============================================================================

class SecretVaultManager:
    """
    Kurumsal düzeyde gizli anahtarları şifreli depolayan,
    rol bazlı erişim sağlayan, süre aşımını (TTL) yöneten ve logları maskeleyen kasa yöneticisi.
    """

    def __init__(self, vault_name: str, master_key: str):
        """Kasa yöneticisini benzersiz anahtar ile başlatır."""
        # Kasa adı saklanır
        self.vault_name = vault_name
        # Ana şifreleme anahtarı saklanır
        self._master_key = master_key
        # Anahtar meta verileri haritası
        self.metadata_store: Dict[str, SecretMetadata] = {}
        # Şifreli yüklerin saklandığı güvenli depo
        self.encrypted_payload_store: Dict[str, EncryptedSecretPayload] = {}
        # Denetim izi kütüğü
        self.audit_log: List[Dict[str, Any]] = []

    def _log_event(self, action: str, details: Dict[str, Any]) -> None:
        """Denetim kütüğüne yapısal olay yazar."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        self.audit_log.append(event)

    def store_secret(
        self,
        secret_id: str,
        name: str,
        secret_type: SecretType,
        plaintext_value: str,
        allowed_roles: List[str],
        ttl_seconds: int = 86400,
        rotation_interval_days: int = 30
    ) -> SecretMetadata:
        """Yeni bir gizli anahtarı zarflı şifreleme ile kasaya kaydeder."""
        # ID kontrol edilir
        if secret_id in self.metadata_store:
            raise DuplicateSecretError(f"Bu ID ile gizli anahtar zaten mevcut: {secret_id}")
        # Boş değer kontrolü
        if not plaintext_value or not plaintext_value.strip():
            raise InvalidSecretPayloadError("Gizli anahtar değeri boş bırakılamaz.")
        # Roller kontrol edilir
        if not allowed_roles:
            raise InvalidSecretPayloadError("Gizli anahtara en az bir yetkili rol tanımlanmalıdır.")

        now = datetime.now()
        expires = now + timedelta(seconds=ttl_seconds)

        meta = SecretMetadata(
            secret_id=secret_id,
            name=name,
            secret_type=secret_type,
            version=1,
            state=SecretState.ACTIVE,
            created_at=now,
            expires_at=expires,
            rotation_interval_days=rotation_interval_days,
            allowed_roles=list(allowed_roles)
        )

        # Zarflı şifreleme icra edilir
        payload = CryptoVaultHelper.encrypt(plaintext_value, self._master_key)
        self.metadata_store[secret_id] = meta
        self.encrypted_payload_store[secret_id] = payload

        self._log_event(
            "SECRET_STORED",
            {"secret_id": secret_id, "name": name, "version": 1, "expires_at": expires.isoformat()}
        )
        return meta

    def get_secret(self, secret_id: str, requester_role: str) -> str:
        """Yetkili bir role gizli anahtarın düz metin değerini döndürür."""
        # Anahtar var mı kontrol edilir
        if secret_id not in self.metadata_store:
            raise SecretNotFoundError(f"Gizli anahtar bulunamadı: {secret_id}")

        meta = self.metadata_store[secret_id]
        now = datetime.now()

        # 1. Kontrol: İptal durumu (Revoked)
        if meta.state == SecretState.REVOKED:
            self._log_event("SECRET_ACCESS_DENIED_REVOKED", {"secret_id": secret_id, "role": requester_role})
            raise SecretRevokedError(f"'{secret_id}' anahtarı güvenlik nedeniyle İPTAL EDİLMİŞTİR.")

        # 2. Kontrol: Süre aşımı (TTL Expired)
        if now > meta.expires_at or meta.state == SecretState.EXPIRED:
            meta.state = SecretState.EXPIRED
            self._log_event("SECRET_ACCESS_DENIED_EXPIRED", {"secret_id": secret_id, "role": requester_role})
            raise SecretExpiredError(f"'{secret_id}' anahtarının kullanım süresi dolmuştur (CWE-613).")

        # 3. Kontrol: Rol Yetkilendirmesi (CWE-285 Least Privilege)
        if requester_role not in meta.allowed_roles:
            self._log_event("SECRET_ACCESS_DENIED_UNAUTHORIZED_ROLE", {"secret_id": secret_id, "role": requester_role})
            raise SecretAccessDeniedError(
                f"Rol '{requester_role}', '{secret_id}' anahtarına erişim yetkisine sahip değil (CWE-285)."
            )

        # 4. Kontrol: Rotasyon Zamanı Geçmiş mi?
        days_active = (now - meta.created_at).days
        if days_active > meta.rotation_interval_days and meta.state == SecretState.ACTIVE:
            self._log_event("SECRET_ROTATION_WARNING", {"secret_id": secret_id, "days_active": days_active})

        # Erişim sayaçları güncellenir
        meta.access_count += 1
        meta.last_accessed_at = now
        payload = self.encrypted_payload_store[secret_id]

        # Şifre çözülür
        plaintext = CryptoVaultHelper.decrypt(payload, self._master_key)
        self._log_event("SECRET_ACCESSED", {"secret_id": secret_id, "role": requester_role, "version": meta.version})
        return plaintext

    def rotate_secret(self, secret_id: str, new_plaintext_value: Optional[str] = None) -> SecretMetadata:
        """Anahtarı yeni versiyon ile yeniler ve eski anahtarı rotasyona çeker."""
        if secret_id not in self.metadata_store:
            raise SecretNotFoundError(f"Gizli anahtar bulunamadı: {secret_id}")

        meta = self.metadata_store[secret_id]
        if meta.state == SecretState.REVOKED:
            raise SecretRevokedError(f"İptal edilmiş anahtar rotasyona tabi tutulamaz: {secret_id}")

        # Eğer yeni değer verilmediyse kriptografik güvenli yeni anahtar üretilir
        if not new_plaintext_value:
            new_plaintext_value = secrets.token_urlsafe(32)

        now = datetime.now()
        meta.version += 1
        meta.created_at = now
        meta.expires_at = now + timedelta(days=meta.rotation_interval_days * 2)
        meta.state = SecretState.ACTIVE

        # Yeni değer şifrelenir ve depoya yazılır
        new_payload = CryptoVaultHelper.encrypt(new_plaintext_value, self._master_key)
        self.encrypted_payload_store[secret_id] = new_payload

        self._log_event(
            "SECRET_ROTATED",
            {"secret_id": secret_id, "new_version": meta.version, "expires_at": meta.expires_at.isoformat()}
        )
        return meta

    def revoke_secret(self, secret_id: str) -> None:
        """Gizli anahtarı derhal iptal eder ve kullanıma kapatır."""
        if secret_id not in self.metadata_store:
            raise SecretNotFoundError(f"Gizli anahtar bulunamadı: {secret_id}")
        meta = self.metadata_store[secret_id]
        meta.state = SecretState.REVOKED
        self._log_event("SECRET_REVOKED", {"secret_id": secret_id, "version": meta.version})

    def mask_log_message(self, log_message: str) -> str:
        """Log kayıtlarında bulunabilecek hassas verileri ve anahtarları maskeler (CWE-532)."""
        masked = log_message
        # 1. Bilinen regex kalıpları maskelenir
        for pat_name, pat_regex in SecretScanner.PATTERNS.items():
            masked = re.sub(pat_regex, f"[REDACTED_{pat_name}]", masked)
        # 2. Kasadaki aktif anahtarların çözülmüş değerleri taranıp temizlenir
        for s_id, payload in self.encrypted_payload_store.items():
            try:
                raw_val = CryptoVaultHelper.decrypt(payload, self._master_key)
                if len(raw_val) >= 6 and raw_val in masked:
                    masked = masked.replace(raw_val, f"[REDACTED_SECRET_{s_id}]")
            except Exception:
                continue
        return masked

    def generate_vault_report(self) -> str:
        """Kasa durumu ve anahtar yaşam döngüsü hakkında detaylı Markdown raporu üretir."""
        lines: List[str] = []
        lines.append(f"# {self.vault_name} — Kurumsal Secrets Yönetimi Raporu")
        lines.append(f"**Rapor Tarihi:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Toplam Yönetilen Gizli Anahtar:** {len(self.metadata_store)}")
        lines.append("")

        lines.append("## 1. Gizli Anahtarlar Envanteri ve Yaşam Döngüsü")
        lines.append("| Secret ID | Adı | Türü | Sürüm | Durum | Kalan TTL | Yetkili Roller | Erişim Sayısı |")
        lines.append("|---|---|---|---|---|---|---|---|")

        now = datetime.now()
        for s_id, meta in self.metadata_store.items():
            remaining_seconds = max(0, int((meta.expires_at - now).total_seconds()))
            ttl_str = f"{remaining_seconds // 3600}s {(remaining_seconds % 3600) // 60}d" if remaining_seconds > 0 else "SÜRESİ BİTTİ"
            roles_str = ", ".join(meta.allowed_roles)
            state_str = meta.state.value
            lines.append(
                f"| {s_id} | {meta.name} | {meta.secret_type.value} | v{meta.version} | {state_str} | {ttl_str} | {roles_str} | {meta.access_count} |"
            )
        lines.append("")

        lines.append("## 2. Güvenlik Standartları ve Uyumluluk Notu")
        lines.append("> [!NOTE]\n> **CWE-798 & CWE-532 KORUMASI:** Tüm gizli anahtarlar kod depoları ve çevre dosyaları yerine "
                     "merkezi kasada zarflı şifreleme (Envelope Encryption) ile saklanmaktadır. Log maskeleme filtresi aktiftir.")
        lines.append("")
        return "\n".join(lines)

    def export_summary_dict(self) -> Dict[str, Any]:
        """Tüm kasa özetini JSON uyumlu sözlük olarak döndürür."""
        return {
            "vault_name": self.vault_name,
            "total_secrets_count": len(self.metadata_store),
            "secrets": [
                {
                    "secret_id": m.secret_id,
                    "name": m.name,
                    "type": m.secret_type.name,
                    "version": m.version,
                    "state": m.state.name,
                    "expires_at": m.expires_at.isoformat(),
                    "allowed_roles": m.allowed_roles,
                    "access_count": m.access_count
                }
                for m in self.metadata_store.values()
            ]
        }
