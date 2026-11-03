# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
NIST SP 800-57 Uyumlu Anahtar Yönetimi ve Rotasyon Motoru (key_management_engine.py).

Bu modül; asimetrik ve simetrik anahtarların yaşam döngüsü evrelerini (Pre-Activation,
Active, Deprecated, Compromised, Destroyed), Zarf Şifreleme (Envelope Encryption - KEK vs DEK),
yeniden sarma (Re-wrapping), Kriptoperiyot denetimi, Çift Kontrol (Dual Control / Split Knowledge)
ve Kriptografik Sıfırlamayı (Zeroization / Crypto-Shredding) harici kütüphane bağımlılığı olmaksızın
(Pure Python) simüle eder.
"""

import os
import sys
import json
import time
import hmac
import secrets
import hashlib
import datetime
from typing import Dict, List, Tuple, Optional, Any, Set

# ==============================================================================
# 1. ÖZEL İSTİSNA SINIFLARI (CWE GÜVENLİK KONTROLLERİ)
# ==============================================================================

class KeyManagementError(Exception):
    """Anahtar yönetim motorundaki tüm hataların temel sınıfı."""
    pass

class KeyExpiredError(KeyManagementError):
    """CWE-320: Kriptoperiyodu (geçerlilik süresi) dolmuş anahtarla işlem yapılması."""
    pass

class KeyCompromisedError(KeyManagementError):
    """CWE-320: Güvenliği ihlal edilmiş (COMPROMISED) anahtarın kullanılması."""
    pass

class InadequateKeyLengthError(KeyManagementError):
    """CWE-326: NIST standartlarına aykırı yetersiz anahtar bit boyutu (örn. <128 bit)."""
    pass

class KeyUsageLimitExceededError(KeyManagementError):
    """CWE-329: Aynı anahtar ile azami güvenli şifreleme hacminin (hacim limiti) aşılması."""
    pass

class EncryptedDEKIntegrityError(KeyManagementError):
    """CWE-353: Zarf şifrelemede KEK ile sarılmış şifreli DEK bütünlük/etiket hatası."""
    pass

class KeyAlreadyDestroyedError(KeyManagementError):
    """CWE-226: Sıfırlanmış ve imha edilmiş (DESTROYED) anahtar materyaline erişim girişimi."""
    pass

class InsufficientKeySharesError(KeyManagementError):
    """CWE-320: Dual Control / Split Knowledge için gereken asgari anahtar parçası eksikliği."""
    pass

class KeyDeprecatedError(KeyManagementError):
    """CWE-320: Emekliye ayrılmış (DEPRECATED) anahtar ile yeni şifreleme yapılması."""
    pass

class PredictableKeyError(KeyManagementError):
    """CWE-321: Sabit, tahmin edilebilir veya aşırı düşük entropili anahtar kullanımı."""
    pass


# ==============================================================================
# 2. KRİPTOGRAFİK YARDIMCI İŞLEMLER (AEAD SİMÜLATÖRÜ)
# ==============================================================================

def simulated_aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """Pure Python AEAD (AES-GCM tarzı) şifreleme ve 16-bayt kimlik doğrulama etiketi türetir."""
    # Akış şifreleme: Keystream = HMAC-SHA256(key, nonce || sayac)
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(plaintext):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        keystream.extend(block)
        counter += 1
    keystream = bytes(keystream[:len(plaintext)])
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    # Kimlik doğrulama etiketi (Auth Tag): HMAC(key, aad || ciphertext || len(aad))
    tag_input = aad + ciphertext + len(aad).to_bytes(8, "big")
    tag = hmac.new(key, tag_input, hashlib.sha256).digest()[:16]
    return ciphertext, tag

def simulated_aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> bytes:
    """AEAD etiketini zamanlama analizine dirençli doğrular ve açık metni çözer."""
    tag_input = aad + ciphertext + len(aad).to_bytes(8, "big")
    expected_tag = hmac.new(key, tag_input, hashlib.sha256).digest()[:16]
    # CWE-208 / CWE-353: Sabit zamanlı karşılaştırma
    if not hmac.compare_digest(tag, expected_tag):
        raise EncryptedDEKIntegrityError("CWE-353: AEAD kimlik doğrulama etiketi geçersiz veya veri tahrif edilmiş!")
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(ciphertext):
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        keystream.extend(block)
        counter += 1
    keystream = bytes(keystream[:len(ciphertext)])
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))


# ==============================================================================
# 3. NIST SP 800-57 ANAHTAR METAVERİ VE YAŞAM DÖNGÜSÜ MODELİ
# ==============================================================================

class KeyState:
    """NIST SP 800-57 Kriptografik Anahtar Durumları."""
    PRE_ACTIVATION = "PRE_ACTIVATION" # Anahtar üretildi, henüz aktif değil
    ACTIVE = "ACTIVE"                 # Hem şifreleme hem de deşifre için kullanılabilir
    SUSPENDED = "SUSPENDED"           # Geçici olarak durduruldu
    DEPRECATED = "DEPRECATED"         # Yalnızca geçmiş veriyi deşifre için (yeni şifreleme yasak)
    COMPROMISED = "COMPROMISED"       # Anahtar sızdı/ihlal edildi; hiçbir işlem yapılamaz
    DESTROYED = "DESTROYED"           # Kriptografik olarak sıfırlandı (Zeroized)

class KeyMetadata:
    """Bir kriptografik anahtarın yaşam döngüsü metaverilerini ve baytlarını temsil eder."""
    def __init__(self, key_id: str, version: int, algorithm: str, bit_length: int,
                 key_bytes: bytes, cryptoperiod_days: int = 365, max_usage_limit: int = 1000000):
        self.key_id = key_id
        self.version = version
        self.algorithm = algorithm
        self.bit_length = bit_length
        # Anahtar baytları bellekte güvenli tutulur
        self.key_material: Optional[bytearray] = bytearray(key_bytes)
        self.state = KeyState.ACTIVE
        self.usage_count = 0
        self.max_usage_limit = max_usage_limit

        now = datetime.datetime.now(datetime.timezone.utc)
        self.created_at = now.isoformat()
        self.expires_at = (now + datetime.timedelta(days=cryptoperiod_days)).isoformat()

    def check_cryptoperiod(self, current_time: Optional[datetime.datetime] = None) -> None:
        """CWE-320: Kriptoperiyot geçerlilik sınırlarını denetler."""
        if self.state == KeyState.DESTROYED:
            raise KeyAlreadyDestroyedError(f"CWE-226: {self.key_id} anahtarı imha edilmiştir!")
        if self.state == KeyState.COMPROMISED:
            raise KeyCompromisedError(f"CWE-320: {self.key_id} anahtarı ihlal edilmiş (COMPROMISED) durumdadır!")

        now = current_time or datetime.datetime.now(datetime.timezone.utc)
        exp = datetime.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if now > exp:
            raise KeyExpiredError(f"CWE-320: {self.key_id} anahtarının kriptoperiyodu dolmuştur! (Bitiş: {self.expires_at})")

    def increment_usage(self) -> None:
        """CWE-329: Anahtar kullanım sayacını artırır ve azami hacim sınırını denetler."""
        if self.usage_count >= self.max_usage_limit:
            raise KeyUsageLimitExceededError(
                f"CWE-329: {self.key_id} anahtarının azami kullanım sınırı ({self.max_usage_limit}) aşıldı! Rotasyon zorunlu."
            )
        self.usage_count += 1

    def zeroize(self) -> None:
        """CWE-226: Kriptografik Sıfırlama (Zeroization) - Bellekteki anahtarı ezer."""
        if self.key_material is not None:
            # 1. Geçiş: 0x00 ile ez
            for i in range(len(self.key_material)):
                self.key_material[i] = 0x00
            # 2. Geçiş: 0xFF ile ez
            for i in range(len(self.key_material)):
                self.key_material[i] = 0xFF
            # 3. Geçiş: CSPRNG rastgele baytları ile ez
            rand_bytes = secrets.token_bytes(len(self.key_material))
            for i in range(len(self.key_material)):
                self.key_material[i] = rand_bytes[i]
            # Bellekten sil
            self.key_material = None
        self.state = KeyState.DESTROYED


# ==============================================================================
# 4. ZARF ŞİFRELEME MOTORU (ENVELOPE ENCRYPTION - KEK VS DEK)
# ==============================================================================

class EnvelopeEncryptionEngine:
    """KEK (Master Anahtar) ile DEK (Veri Anahtarı) hiyerarşisini ve Re-wrapping'i yönetir."""
    def __init__(self, key_manager: "KeyManagementService"):
        self.km = key_manager

    def encrypt_data(self, plaintext_bytes: bytes, associated_data: bytes = b"") -> Dict[str, Any]:
        """Zarf Şifreleme: Tek kullanımlık DEK üretir, veriyi şifreler, DEK'i aktif KEK ile sarar."""
        # 1. Aktif KEK'i al
        active_kek = self.km.get_active_kek()
        # KEK durum ve kriptoperiyot denetimi
        if active_kek.state == KeyState.DEPRECATED:
            raise KeyDeprecatedError("CWE-320: DEPRECATED durumdaki KEK ile yeni veri şifrelenemez!")
        active_kek.check_cryptoperiod()
        active_kek.increment_usage()

        # 2. Tek kullanımlık 256-bit DEK üret
        dek_bytes = secrets.token_bytes(32)
        dek_nonce = secrets.token_bytes(12)
        # 3. Veriyi DEK ile şifrele
        data_ciphertext, data_tag = simulated_aead_encrypt(dek_bytes, dek_nonce, plaintext_bytes, associated_data)

        # 4. DEK'i aktif KEK ile şifrele (Key Wrapping)
        kek_nonce = secrets.token_bytes(12)
        if active_kek.key_material is None:
            raise KeyAlreadyDestroyedError("KEK materyali mevcut değil!")
        wrapped_dek, dek_tag = simulated_aead_encrypt(
            bytes(active_kek.key_material), kek_nonce, dek_bytes, aad=active_kek.key_id.encode("utf-8")
        )

        # Zarf Şifreleme Paketi
        envelope = {
            "version": "1.0",
            "kek_id": active_kek.key_id,
            "kek_version": active_kek.version,
            "kek_nonce_hex": kek_nonce.hex(),
            "wrapped_dek_hex": wrapped_dek.hex(),
            "dek_tag_hex": dek_tag.hex(),
            "data_nonce_hex": dek_nonce.hex(),
            "ciphertext_hex": data_ciphertext.hex(),
            "data_tag_hex": data_tag.hex(),
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        return envelope

    def decrypt_data(self, envelope: Dict[str, Any], associated_data: bytes = b"") -> bytes:
        """Zarf Deşifreleme: KEK ile sarılmış DEK'i çözer, ardından veriyi açar."""
        kek_id = envelope["kek_id"]
        kek = self.km.get_key(kek_id)
        if kek.state == KeyState.COMPROMISED:
            raise KeyCompromisedError(f"CWE-320: {kek_id} anahtarı ihlal edilmiştir, deşifre yapılamaz!")
        if kek.state == KeyState.DESTROYED or kek.key_material is None:
            raise KeyAlreadyDestroyedError(f"CWE-226: {kek_id} anahtarı imha edilmiştir!")

        kek_nonce = bytes.fromhex(envelope["kek_nonce_hex"])
        wrapped_dek = bytes.fromhex(envelope["wrapped_dek_hex"])
        dek_tag = bytes.fromhex(envelope["dek_tag_hex"])

        # 1. DEK'i KEK ile çöz
        dek_bytes = simulated_aead_decrypt(
            bytes(kek.key_material), kek_nonce, wrapped_dek, aad=kek.key_id.encode("utf-8"), tag=dek_tag
        )

        # 2. Veriyi DEK ile çöz
        data_nonce = bytes.fromhex(envelope["data_nonce_hex"])
        ciphertext = bytes.fromhex(envelope["ciphertext_hex"])
        data_tag = bytes.fromhex(envelope["data_tag_hex"])
        return simulated_aead_decrypt(dek_bytes, data_nonce, ciphertext, associated_data, data_tag)

    def re_wrap_envelope(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Re-wrapping: Devasa veriyi yeniden şifrelemeden SADECE DEK'i yeni KEK ile yeniden sarar (O(1) süre)."""
        # 1. Eski KEK ile DEK'i çöz
        old_kek = self.km.get_key(envelope["kek_id"])
        if old_kek.key_material is None:
            raise KeyAlreadyDestroyedError("Eski KEK imha edilmiş!")
        kek_nonce = bytes.fromhex(envelope["kek_nonce_hex"])
        wrapped_dek = bytes.fromhex(envelope["wrapped_dek_hex"])
        dek_tag = bytes.fromhex(envelope["dek_tag_hex"])

        dek_bytes = simulated_aead_decrypt(
            bytes(old_kek.key_material), kek_nonce, wrapped_dek, aad=old_kek.key_id.encode("utf-8"), tag=dek_tag
        )

        # 2. Yeni aktif KEK'i al
        new_kek = self.km.get_active_kek()
        new_kek.check_cryptoperiod()
        new_kek.increment_usage()

        # 3. DEK'i yeni KEK ile sar
        new_kek_nonce = secrets.token_bytes(12)
        if new_kek.key_material is None:
            raise KeyAlreadyDestroyedError("Yeni KEK materyali mevcut değil!")
        new_wrapped_dek, new_dek_tag = simulated_aead_encrypt(
            bytes(new_kek.key_material), new_kek_nonce, dek_bytes, aad=new_kek.key_id.encode("utf-8")
        )

        # Güncellenmiş zarf paketi (Ciphertext aynı kaldı!)
        updated_envelope = dict(envelope)
        updated_envelope["kek_id"] = new_kek.key_id
        updated_envelope["kek_version"] = new_kek.version
        updated_envelope["kek_nonce_hex"] = new_kek_nonce.hex()
        updated_envelope["wrapped_dek_hex"] = new_wrapped_dek.hex()
        updated_envelope["dek_tag_hex"] = new_dek_tag.hex()
        updated_envelope["re_wrapped_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return updated_envelope


# ==============================================================================
# 5. ANAHTAR YÖNETİM SERVİSİ (KMS & ROTASYON ORKESTRASYONU)
# ==============================================================================

class KeyManagementService:
    """NIST SP 800-57 uyumlu Anahtar Yönetim Servisi (KMS)."""
    def __init__(self):
        # Anahtar veritabanı: {key_id: KeyMetadata}
        self.keys: Dict[str, KeyMetadata] = {}
        self.active_kek_id: Optional[str] = None
        self.audit_log: List[Dict[str, Any]] = []

    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """KMS denetim izi günlüğü oluşturur."""
        self.audit_log.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event_type,
            "details": details
        })

    def create_kek(self, key_id: str, bit_length: int = 256, cryptoperiod_days: int = 365,
                   custom_bytes: Optional[bytes] = None) -> KeyMetadata:
        """Yeni bir KEK (Master Anahtar) türetir ve kaydeder."""
        # CWE-326 Kontrolü: 128 bit altı anahtarlar reddedilir
        if bit_length < 128:
            raise InadequateKeyLengthError(f"CWE-326: Yetersiz anahtar uzunluğu ({bit_length} bit)! Asgari 128-bit gereklidir.")

        # Anahtar materyali üretimi
        if custom_bytes is not None:
            raw_bytes = custom_bytes
            # CWE-321 Kontrolü: Sıfırlardan veya sabit desenden oluşan tahmin edilebilir anahtarlar reddedilir
            if len(set(raw_bytes)) <= 1 or raw_bytes == b"\x00" * len(raw_bytes):
                raise PredictableKeyError("CWE-321: Tahmin edilebilir veya düşük entropili sabit anahtar tespit edildi!")
        else:
            raw_bytes = secrets.token_bytes(bit_length // 8)

        metadata = KeyMetadata(
            key_id=key_id,
            version=1,
            algorithm=f"AES-{bit_length}",
            bit_length=bit_length,
            key_bytes=raw_bytes,
            cryptoperiod_days=cryptoperiod_days
        )
        self.keys[key_id] = metadata
        if not self.active_kek_id:
            self.active_kek_id = key_id
        self.log_event("KEY_CREATED", {"key_id": key_id, "bit_length": bit_length})
        return metadata

    def get_key(self, key_id: str) -> KeyMetadata:
        """Belirtilen ID'ye sahip anahtarı döner."""
        if key_id not in self.keys:
            raise KeyManagementError(f"Anahtar bulunamadı: {key_id}")
        return self.keys[key_id]

    def get_active_kek(self) -> KeyMetadata:
        """Aktif olarak şifrelemede kullanılan geçerli KEK'i döner."""
        if not self.active_kek_id or self.active_kek_id not in self.keys:
            raise KeyManagementError("Sistemde aktif KEK tanımlı değil!")
        return self.keys[self.active_kek_id]

    def rotate_kek(self, new_key_id: str, bit_length: int = 256) -> KeyMetadata:
        """Otomatik Anahtar Rollover: Mevcut aktif KEK'i DEPRECATED yapar, yenisini ACTIVE atar."""
        old_active = self.get_active_kek()
        # Eski aktif anahtarı emekliye ayır (Artık yalnızca eski verileri deşifre edebilir)
        old_active.state = KeyState.DEPRECATED

        # Yeni KEK oluştur
        new_kek = self.create_kek(new_key_id, bit_length=bit_length)
        self.active_kek_id = new_key_id

        self.log_event("KEY_ROTATED", {
            "old_kek_id": old_active.key_id,
            "new_kek_id": new_kek.key_id
        })
        return new_kek

    def compromise_key(self, key_id: str) -> None:
        """Anahtarı sızmış (COMPROMISED) olarak işaretler; tüm işlemleri kilitler."""
        key = self.get_key(key_id)
        key.state = KeyState.COMPROMISED
        self.log_event("KEY_COMPROMISED", {"key_id": key_id})

    def destroy_key(self, key_id: str) -> None:
        """Kriptografik İmha (Zeroization): Anahtarı bellekten siler ve durumunu DESTROYED yapar."""
        key = self.get_key(key_id)
        key.zeroize()
        self.log_event("KEY_DESTROYED", {"key_id": key_id})


# ==============================================================================
# 6. DUAL CONTROL / SPLIT KNOWLEDGE (M-OF-N ANAHTAR PARÇALAMA SİMÜLASYONU)
# ==============================================================================

class DualControlKeySplitter:
    """Çift Kontrol (Dual Control / Split Knowledge) simülatörü."""
    @staticmethod
    def split_secret_2_of_2(secret_bytes: bytes) -> Tuple[bytes, bytes]:
        """2-of-2 eşik paylaşımı: Tek bir kişi anahtarı bilemez, ikisi bir araya gelmelidir."""
        share1 = secrets.token_bytes(len(secret_bytes))
        share2 = bytes(s ^ r for s, r in zip(secret_bytes, share1))
        return share1, share2

    @staticmethod
    def combine_secret_2_of_2(shares: List[bytes]) -> bytes:
        """2 parçayı birleştirerek anahtarı yeniden inşa eder."""
        if len(shares) < 2:
            raise InsufficientKeySharesError("CWE-320: Dual Control için asgari 2 anahtar parçası sunulmalıdır!")
        return bytes(s1 ^ s2 for s1, s2 in zip(shares[0], shares[1]))
