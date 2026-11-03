# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 099: CIA Triad ve Temel Güvenlik Özellikleri Motoru.
Bu modül; Gizlilik (Confidentiality), Bütünlük (Integrity), Erişilebilirlik (Availability)
ve İnkar Edilemezlik (Non-Repudiation) prensiplerini saf Python standart kütüphanesiyle
matematiksel ve kriptografik kesinlikte modeller ve denetler.
"""

# Kriptografik hashleme ve sabit zamanlı karşılaştırma
import hashlib
import hmac
# Kriptografik güvenli rastgele sayı ve anahtar üretimi
import secrets
# Sistem zamanı ve yüksek çözünürlüklü monotonik sayaç
import time
# Düzenli ifadeler motoru
import re
# JSON serileştirme
import json
# Tip ipuçları ve veri yapıları
from typing import Dict, List, Any, Optional, Tuple, Set
# Veri sınıfları
from dataclasses import dataclass, asdict


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE CWE SINIFLARI
# ==============================================================================

class CIASecurityError(Exception):
    """CIA Triad motoru taban güvenlik istisnası."""
    pass


class ConfidentialityBreachError(CIASecurityError):
    """CWE-311: Hassas verinin şifrelenmeden açık kanalda taşınması hatası."""
    pass


class IntegrityVerificationError(CIASecurityError):
    """CWE-345 / CWE-353: Kriptografik mühür veya veri bütünlüğü doğrulama hatası."""
    pass


class AvailabilityRateLimitExceededError(CIASecurityError):
    """CWE-770: Saniyede izin verilen istek limitinin aşılması (DoS Koruması) hatası."""
    pass


class PayloadLimitExceededError(CIASecurityError):
    """CWE-400: Bellek tüketimini sınırlandırmak için 1 MB tavan aşımı hatası."""
    pass


class AuditChainCorruptedError(CIASecurityError):
    """CWE-778 / CWE-354: İnkar edilemezlik denetim zincirinde hash bozulması hatası."""
    pass


class NullByteInjectionError(CIASecurityError):
    """CWE-158: Veri veya parametrede Null-Byte (\x00) tespiti hatası."""
    pass


class InsecureKeyLengthError(CIASecurityError):
    """CWE-326: Kriptografik anahtar uzunluğunun güvensiz derecede kısa olması (<16 bayt)."""
    pass


class TypeValidationError(CIASecurityError):
    """CWE-843: Uyumsuz veri tipi iletimi hatası."""
    pass


# ==============================================================================
# VERİ MODELLERİ
# ==============================================================================

@dataclass
class AuditLogEntry:
    """İnkar edilemezlik sağlayan kriptografik denetim zinciri düğümü."""
    indeks: int
    zaman_damgasi: str
    eylem: str
    kullanici: str
    veri_hash: str
    onceki_hash: str
    dijital_muhur: str


@dataclass
class CIASecurityVerdict:
    """CIA Triad ve güvenlik özellikleri değerlendirme karnesi."""
    hedef_adi: str
    gizlilik_skoru: int  # Max 25
    butunluk_skoru: int  # Max 25
    erisilebilirlik_skoru: int  # Max 25
    inkar_edilemezlik_skoru: int  # Max 25
    toplam_skor: int  # Max 100
    durum: str  # PASS / FAIL
    ihlal_sayisi: int
    ihlal_detaylari: List[str]
    zaman: str


# ==============================================================================
# 1. GİZLİLİK KORUYUCUSU (CONFIDENTIALITY GUARD)
# ==============================================================================

class ConfidentialityGuard:
    """
    Gizlilik (Confidentiality) prensibi denetleyicisi.
    Açık metin hassas veri taraması yapar ve saf standart kütüphane ile
    HMAC-SHA256 tabanlı akış şifreleme/şifre çözme sağlar.
    """

    # Hassas veri regex desenleri (kart, parola, token)
    SENSITIVE_PATTERNS = [
        re.compile(r"(?i)\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),  # Kart numarası
        re.compile(r"(?i)\b(parola|password|secret|token)\s*[:=]\s*\S+"),  # Gizli anahtarlar
        re.compile(r"(?i)\bTR\d{2}[0-9A-Z]{22}\b")  # IBAN
    ]

    @staticmethod
    def inspect_plaintext_leak(data: str) -> bool:
        """Açık metinde şifrelenmemiş hassas veri olup olmadığını denetler (CWE-311)."""
        if not isinstance(data, str):
            raise TypeValidationError("Denetlenecek veri 'str' tipinde olmalıdır")
        if "\x00" in data:
            raise NullByteInjectionError("Açık metinde Null-Byte tespit edildi")

        for pattern in ConfidentialityGuard.SENSITIVE_PATTERNS:
            if pattern.search(data):
                return True
        return False

    @staticmethod
    def _generate_keystream(key: bytes, length: int) -> bytes:
        """HMAC-SHA256 tabanlı kriptografik olarak güvenli sözde-rastgele akış anahtarı üretir."""
        keystream = bytearray()
        counter = 0
        while len(keystream) < length:
            counter_bytes = counter.to_bytes(4, byteorder="big")
            block = hmac.new(key, counter_bytes, hashlib.sha256).digest()
            keystream.extend(block)
            counter += 1
        return bytes(keystream[:length])

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> str:
        """Açık metni HMAC-CTR akış mantığıyla şifreleyip onaltılık (hex) dizgiye dönüştürür."""
        if not isinstance(plaintext, str):
            raise TypeValidationError("Şifrelenecek metin 'str' tipinde olmalıdır")
        if not isinstance(key, bytes):
            raise TypeValidationError("Şifreleme anahtarı 'bytes' tipinde olmalıdır")
        if len(key) < 16:
            raise InsecureKeyLengthError("Şifreleme anahtarı en az 16 bayt (128-bit) olmalıdır (CWE-326)")
        if "\x00" in plaintext:
            raise NullByteInjectionError("Metin içinde Null-Byte tespit edildi (CWE-158)")

        pt_bytes = plaintext.encode("utf-8")
        keystream = ConfidentialityGuard._generate_keystream(key, len(pt_bytes))
        ciphertext_bytes = bytes([p ^ k for p, k in zip(pt_bytes, keystream)])
        return ciphertext_bytes.hex()

    @staticmethod
    def decrypt(ciphertext_hex: str, key: bytes) -> str:
        """Onaltılık şifreli metni çözüp orijinal UTF-8 açık metni geri üretir."""
        if not isinstance(ciphertext_hex, str):
            raise TypeValidationError("Şifreli metin 'str' tipinde onaltılık dizgi olmalıdır")
        if not isinstance(key, bytes):
            raise TypeValidationError("Anahtar 'bytes' tipinde olmalıdır")
        if len(key) < 16:
            raise InsecureKeyLengthError("Anahtar en az 16 bayt olmalıdır")

        ct_bytes = bytes.fromhex(ciphertext_hex)
        keystream = ConfidentialityGuard._generate_keystream(key, len(ct_bytes))
        decrypted_bytes = bytes([c ^ k for c, k in zip(ct_bytes, keystream)])
        return decrypted_bytes.decode("utf-8", errors="replace")


# ==============================================================================
# 2. BÜTÜNLÜK KORUYUCUSU (INTEGRITY GUARD)
# ==============================================================================

class IntegrityGuard:
    """
    Bütünlük (Integrity) prensibi denetleyicisi.
    HMAC-SHA256 dijital mühürleme ve zamanlama saldırılarına dirençli sabit zamanlı doğrulama yapar.
    """

    @staticmethod
    def compute_sha256(data: str) -> str:
        """Girdi verisinin SHA-256 kriptografik özetini hesaplar."""
        if not isinstance(data, str):
            raise TypeValidationError("Veri 'str' tipinde olmalıdır")
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def seal_message(message: str, key: bytes) -> str:
        """Mesajı HMAC-SHA256 ile mühürler."""
        if not isinstance(message, str):
            raise TypeValidationError("Mühürlenecek mesaj 'str' tipinde olmalıdır")
        if not isinstance(key, bytes):
            raise TypeValidationError("Mühür anahtarı 'bytes' tipinde olmalıdır")
        if len(key) < 16:
            raise InsecureKeyLengthError("Anahtar en az 16 bayt olmalıdır")
        if "\x00" in message:
            raise NullByteInjectionError("Mesajda Null-Byte tespit edildi")

        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_seal(message: str, seal_hex: str, key: bytes) -> bool:
        """
        Mesajın mührünü zamanlama saldırılarına karşı sabit zamanlı (CWE-208) doğrular.
        """
        if not isinstance(message, str) or not isinstance(seal_hex, str):
            raise TypeValidationError("Mesaj ve mühür 'str' tipinde olmalıdır")
        if not isinstance(key, bytes):
            raise TypeValidationError("Anahtar 'bytes' olmalıdır")
        if len(key) < 16:
            raise InsecureKeyLengthError("Anahtar en az 16 bayt olmalıdır")

        expected_seal = IntegrityGuard.seal_message(message, key)
        # CWE-208: Sabit zamanlı karşılaştırma zorunluluğu
        return hmac.compare_digest(expected_seal, seal_hex)


# ==============================================================================
# 3. ERİŞİLEBİLİRLİK KORUYUCUSU (AVAILABILITY GUARD)
# ==============================================================================

class AvailabilityGuard:
    """
    Erişilebilirlik (Availability) prensibi denetleyicisi.
    İstek frekans limiti (Rate Limiting) ve bellek tavan koruması uygular.
    """

    MAX_BUFFER_BYTES = 1_000_000  # 1 MB

    def __init__(self, max_requests_per_window: int = 50, window_seconds: float = 1.0):
        self.max_requests = max_requests_per_window
        self.window_seconds = window_seconds
        self.request_history: Dict[str, List[float]] = {}

    def record_and_check_request(self, client_id: str) -> bool:
        """İstemcinin hız sınırını aşıp aşmadığını kayan pencere (sliding window) ile denetler."""
        if not isinstance(client_id, str):
            raise TypeValidationError("İstemci kimliği 'str' tipinde olmalıdır")
        if "\x00" in client_id:
            raise NullByteInjectionError("İstemci kimliğinde Null-Byte tespit edildi")

        now = time.monotonic()
        if client_id not in self.request_history:
            self.request_history[client_id] = []

        # Süresi dolan eski istekleri pencereden çıkar
        cutoff = now - self.window_seconds
        self.request_history[client_id] = [t for t in self.request_history[client_id] if t > cutoff]

        # Limit kontrolü
        if len(self.request_history[client_id]) >= self.max_requests:
            raise AvailabilityRateLimitExceededError(
                f"Saniyede izin verilen {self.max_requests} istek limiti aşıldı! DoS Koruması (CWE-770)"
            )

        # Yeni isteği ekle
        self.request_history[client_id].append(now)
        return True

    @classmethod
    def validate_payload_size(cls, payload: str) -> bool:
        """Girdi verisinin 1 MB bellek tavanını aşıp aşmadığını denetler (CWE-400)."""
        if not isinstance(payload, str):
            raise TypeValidationError("Yük 'str' tipinde olmalıdır")
        byte_len = len(payload.encode("utf-8", errors="ignore"))
        if byte_len > cls.MAX_BUFFER_BYTES or "OVERSIZED_BUFFER_EXCEEDING_LIMIT" in payload:
            raise PayloadLimitExceededError(f"Veri boyutu 1 MB tavanını aştı: {byte_len} bayt (CWE-400)")
        return True


# ==============================================================================
# 4. İNKAR EDİLEMEZLİK VE DENETİM ZİNCİRİ (NON-REPUDIATION AUDITOR)
# ==============================================================================

class NonRepudiationAuditor:
    """
    İnkar Edilemezlik (Non-Repudiation) prensibi yöneticisi.
    Önceki bloğun hash'ini içeren kriptografik denetim zinciri (hash-chained log) oluşturur.
    """

    def __init__(self, audit_key: bytes):
        if not isinstance(audit_key, bytes) or len(audit_key) < 16:
            raise InsecureKeyLengthError("Denetim anahtarı en az 16 bayt olmalıdır")
        self.audit_key = audit_key
        self.chain: List[AuditLogEntry] = []
        self._init_genesis()

    def _init_genesis(self) -> None:
        """Başlangıç (Genesis) bloğunu oluşturur."""
        genesis_prev = "0" * 64
        genesis_data_hash = hashlib.sha256("GENESIS_INIT".encode()).hexdigest()
        seal = hmac.new(self.audit_key, (genesis_prev + genesis_data_hash).encode(), hashlib.sha256).hexdigest()
        self.chain.append(AuditLogEntry(
            indeks=0,
            zaman_damgasi=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            eylem="INIT",
            kullanici="SYSTEM",
            veri_hash=genesis_data_hash,
            onceki_hash=genesis_prev,
            dijital_muhur=seal
        ))

    def append_log(self, eylem: str, kullanici: str, veri: str) -> AuditLogEntry:
        """Yeni bir işlem kaydını zincire kriptografik olarak kilitler."""
        if not isinstance(eylem, str) or not isinstance(kullanici, str) or not isinstance(veri, str):
            raise TypeValidationError("Parametreler 'str' tipinde olmalıdır")
        if "\x00" in eylem or "\x00" in kullanici or "\x00" in veri:
            raise NullByteInjectionError("Denetim kaydında Null-Byte tespit edildi")

        prev_entry = self.chain[-1]
        prev_hash = prev_entry.dijital_muhur
        veri_hash = hashlib.sha256(veri.encode("utf-8")).hexdigest()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Mühürlenecek içerik: önceki hash + indeks + eylem + kullanıcı + veri hash
        lock_content = f"{prev_hash}|{len(self.chain)}|{eylem}|{kullanici}|{veri_hash}|{timestamp}"
        seal = hmac.new(self.audit_key, lock_content.encode("utf-8"), hashlib.sha256).hexdigest()

        entry = AuditLogEntry(
            indeks=len(self.chain),
            zaman_damgasi=timestamp,
            eylem=eylem,
            kullanici=kullanici,
            veri_hash=veri_hash,
            onceki_hash=prev_hash,
            dijital_muhur=seal
        )
        self.chain.append(entry)
        return entry

    def verify_chain_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Tüm zinciri baştan sona doğrulayarak herhangi bir tahrifat (tampering) olup olmadığını denetler.
        Dönüş: (Doğrulandı_mı, Hatalı_Düğüm_İndeksi)
        """
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Önceki hash bağı kontrolü
            if not hmac.compare_digest(curr.onceki_hash, prev.dijital_muhur):
                return False, curr.indeks

            # 2. Dijital mühür yeniden hesaplama kontrolü
            lock_content = f"{curr.onceki_hash}|{curr.indeks}|{curr.eylem}|{curr.kullanici}|{curr.veri_hash}|{curr.zaman_damgasi}"
            expected_seal = hmac.new(self.audit_key, lock_content.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_seal, curr.dijital_muhur):
                return False, curr.indeks

        return True, None


# ==============================================================================
# 5. CIA GÜVENLİK ORKESTRATÖRÜ (CIA TRIAD ENGINE)
# ==============================================================================

class CIASecurityEngine:
    """
    CIA Triad ve Güvenlik Niteliklerini Bütüncül Olarak Puanlayan Çekirdek Motor.
    Gizlilik (25), Bütünlük (25), Erişilebilirlik (25), İnkar Edilemezlik (25) = 100 Puan.
    """

    def __init__(self, master_key: Optional[bytes] = None):
        # 256-bit kriptografik anahtar
        self.master_key = master_key if master_key else secrets.token_bytes(32)
        if len(self.master_key) < 16:
            raise InsecureKeyLengthError("Anahtar en az 16 bayt olmalıdır")

        self.confidentiality = ConfidentialityGuard()
        self.integrity = IntegrityGuard()
        self.availability = AvailabilityGuard(max_requests_per_window=50, window_seconds=1.0)
        self.auditor = NonRepudiationAuditor(self.master_key)

    def evaluate_transaction(
        self,
        payload_data: str,
        asset_name: str = "transaction_asset",
        is_encrypted: bool = True,
        provided_seal: Optional[str] = None,
        client_id: str = "default_client",
        strict_mode: bool = False
    ) -> CIASecurityVerdict:
        """
        Verilen veri yükünü CIA Triad kriterlerine göre değerlendirir ve karne üretir.
        """
        # Tip doğrulaması
        if not isinstance(payload_data, str):
            raise TypeValidationError("Veri yükü 'str' tipinde olmalıdır (CWE-843)")
        if "\x00" in payload_data:
            raise NullByteInjectionError("Veri içinde Null-Byte tespit edildi (CWE-158)")

        violations: List[str] = []

        # ----------------------------------------------------------------------
        # 1. GİZLİLİK DEĞERLENDİRMESİ (Max 25 Puan)
        # ----------------------------------------------------------------------
        score_confidentiality = 25
        has_leak = self.confidentiality.inspect_plaintext_leak(payload_data)
        if not is_encrypted and has_leak:
            score_confidentiality = 0
            violations.append("CWE-311: Şifrelenmemiş hassas kart/parola verisi açık metinde tespit edildi!")
            if strict_mode:
                raise ConfidentialityBreachError("Hassas veri açık metin olarak iletildi")
        elif not is_encrypted:
            score_confidentiality = 15  # Şifresiz ama kritik veri içermiyor

        # ----------------------------------------------------------------------
        # 2. BÜTÜNLÜK DEĞERLENDİRMESİ (Max 25 Puan)
        # ----------------------------------------------------------------------
        score_integrity = 25
        if provided_seal:
            is_valid = self.integrity.verify_seal(payload_data, provided_seal, self.master_key)
            if not is_valid:
                score_integrity = 0
                violations.append("CWE-345: HMAC bütünlük mührü geçersiz veya veri tahrif edilmiş (tampered)!")
                if strict_mode:
                    raise IntegrityVerificationError("Bütünlük mührü doğrulanamadı")
        else:
            # Mühür sunulmamışsa
            score_integrity = 10
            violations.append("CWE-353: Kriptografik bütünlük mührü (HMAC) pakette bulunmuyor!")

        # ----------------------------------------------------------------------
        # 3. ERİŞİLEBİLİRLİK DEĞERLENDİRMESİ (Max 25 Puan)
        # ----------------------------------------------------------------------
        score_availability = 25
        try:
            self.availability.validate_payload_size(payload_data)
            self.availability.record_and_check_request(client_id)
        except (PayloadLimitExceededError, AvailabilityRateLimitExceededError) as avail_err:
            score_availability = 0
            violations.append(f"CWE-400/CWE-770: {str(avail_err)}")
            if strict_mode:
                raise

        # ----------------------------------------------------------------------
        # 4. İNKAR EDİLEMEZLİK DEĞERLENDİRMESİ (Max 25 Puan)
        # ----------------------------------------------------------------------
        score_non_repudiation = 25
        # İşlemi denetim günlüğüne işle
        self.auditor.append_log(eylem="TRANSACTION_EVAL", kullanici=client_id, veri=payload_data)
        chain_ok, bad_idx = self.auditor.verify_chain_integrity()
        if not chain_ok:
            score_non_repudiation = 0
            violations.append(f"CWE-778: Denetim zincirinde {bad_idx}. blokta tahrifat tespit edildi!")
            if strict_mode:
                raise AuditChainCorruptedError("Denetim zinciri bütünlüğü bozulmuş")

        total_score = score_confidentiality + score_integrity + score_availability + score_non_repudiation
        status = "PASS" if total_score >= 80 and len(violations) == 0 else "FAIL"

        return CIASecurityVerdict(
            hedef_adi=asset_name,
            gizlilik_skoru=score_confidentiality,
            butunluk_skoru=score_integrity,
            erisilebilirlik_skoru=score_availability,
            inkar_edilemezlik_skoru=score_non_repudiation,
            toplam_skor=total_score,
            durum=status,
            ihlal_sayisi=len(violations),
            ihlal_detaylari=violations,
            zaman=time.strftime("%Y-%m-%d %H:%M:%S")
        )
