# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 102: Salt, Pepper ve KDF Tabanlı Güvenli Parola Saklama Motoru.
Bu modül; PBKDF2-HMAC-SHA256 anahtar türetme fonksiyonu (KDF), kriptografik tuz (salt),
izole sistem biberi (pepper) ve sabit zamanlı doğrulama ile kurumsal parola yönetimini sağlar.
Gökkuşağı tabloları (Rainbow Tables) ve çevrimdışı GPU sözlük saldırılarını engeller.
"""

# Kriptografik anahtar türetme ve hashleme modülü
import hashlib
import hmac
# Kriptografik güvenli rastgele sayı üreticisi
import secrets
# Zaman ve performans ölçümü
import time
# Düzenli ifadeler motoru
import re
# Tip ipuçları ve veri yapıları
from typing import Dict, List, Any, Optional, Tuple, Union, Set
# Veri sınıfları
from dataclasses import dataclass, asdict


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE CWE EŞLEŞTİRMELERİ
# ==============================================================================

class PasswordVaultError(Exception):
    """Parola saklama motoru taban güvenlik istisnası."""
    pass


class UnsaltedHashError(PasswordVaultError):
    """CWE-759: Parolanın tuzlama (salt) yapılmaksızın düz hash ile saklanması hatası."""
    pass


class InsufficientIterationsError(PasswordVaultError):
    """CWE-916: Kriptografik kabul eşiğinin (100.000) altında kalan yetersiz KDF iterasyonu."""
    pass


class InsecureSaltLengthError(PasswordVaultError):
    """CWE-326: Tuz (salt) uzunluğunun 16 bayt (128-bit) altında olması hatası."""
    pass


class PredictableSaltError(PasswordVaultError):
    """CWE-760: Statik, tahmin edilebilir veya kullanıcı adına bağlı tuz tespiti hatası."""
    pass


class PasswordVerificationMismatchError(PasswordVaultError):
    """CWE-208 / CWE-345: Parola veya biber (pepper) doğrulama uyuşmazlığı hatası."""
    pass


class PayloadLimitExceededError(PasswordVaultError):
    """CWE-400: Bellek tüketimini sınırlandırmak için 1 MB tavan aşımı hatası."""
    pass


class NullByteInjectionError(PasswordVaultError):
    """CWE-158: Parola veya tuz parametresinde Null-Byte (\x00) tespiti hatası."""
    pass


class TypeValidationError(PasswordVaultError):
    """CWE-843 / CWE-1284: Geçersiz veri tipi iletimi hatası."""
    pass


# ==============================================================================
# VERİ MODELLERİ VE YAPILANDIRMA
# ==============================================================================

@dataclass
class PasswordHashRecord:
    """Kriptografik olarak güvenli parola saklama kaydı modeli."""
    algoritma: str  # pbkdf2-sha256
    iterasyon: int  # >= 100000
    salt_hex: str
    has_pepper: bool
    hash_hex: str
    tam_format: str


@dataclass
class PasswordVerificationResult:
    """Parola doğrulama süreci detaylı sonuç karnesi."""
    dogrulandi: bool
    algoritma: str
    iterasyon: int
    pepper_kullanildi: bool
    gecen_sure_ms: float


class PasswordSecurityConfig:
    """NIST SP 800-132 ve OWASP standartları parola güvenlik yapılandırması."""
    MIN_SALT_BYTES: int = 16  # En az 128 bit
    MIN_ITERATIONS: int = 100_000  # PBKDF2-SHA256 minimum eşiği
    MAX_BUFFER_BYTES: int = 1_000_000  # 1 MB DoS koruma sınırı
    # Yasaklanmış statik tuzlar (CWE-760)
    PREDICTABLE_SALTS: Set[str] = {
        "1234567812345678",
        "0000000000000000",
        "abcdefabcdefabcd",
        "passwordpassword",
        "saltsaltsaltsalt"
    }


# ==============================================================================
# ÇEKİRDEK GÜVENLİ PAROLA MOTORU
# ==============================================================================

class PasswordHasher:
    """
    PBKDF2-HMAC-SHA256, Salt ve Pepper ile Güvenli Parola Yöneticisi.
    """

    @classmethod
    def generate_salt(cls, length_bytes: int = 16) -> bytes:
        """Kriptografik olarak güvenli rastgele tuz (salt) üretir (CWE-760 önleme)."""
        if not isinstance(length_bytes, int):
            raise TypeValidationError("Tuz uzunluğu tamsayı olmalıdır")
        if length_bytes < PasswordSecurityConfig.MIN_SALT_BYTES:
            raise InsecureSaltLengthError(
                f"Tuz uzunluğu en az {PasswordSecurityConfig.MIN_SALT_BYTES} bayt (128 bit) olmalıdır (CWE-326)!"
            )
        return secrets.token_bytes(length_bytes)

    @classmethod
    def _apply_pepper(cls, password: str, pepper: Optional[bytes] = None) -> bytes:
        """
        Biber (pepper) varsa, parolayı HMAC-SHA256 ile harmanlayarak KDF'e iletir.
        Böylece veritabanı sızsa dahi pepper olmadan hash kırılamaz.
        """
        raw_pw = password.encode("utf-8")
        if pepper is None:
            return raw_pw
        if not isinstance(pepper, (bytes, bytearray)):
            raise TypeValidationError("Biber (pepper) 'bytes' tipinde olmalıdır")
        # Pepper ile parolanın HMAC özetini çıkar
        return hmac.new(pepper, raw_pw, hashlib.sha256).digest()

    @classmethod
    def hash_password(
        cls,
        password: str,
        salt: Optional[bytes] = None,
        pepper: Optional[bytes] = None,
        iterations: int = 100_000
    ) -> PasswordHashRecord:
        """
        Kullanıcı parolasını PBKDF2-HMAC-SHA256, benzersiz tuz ve sistem biberi ile kilitler.
        """
        # Tip ve güvenlik kontrolleri
        if not isinstance(password, str):
            raise TypeValidationError("Parola 'str' tipinde olmalıdır (CWE-843)")
        if "\x00" in password:
            raise NullByteInjectionError("Parolada Null-Byte tespit edildi (CWE-158)")
        if len(password.encode("utf-8")) > PasswordSecurityConfig.MAX_BUFFER_BYTES:
            raise PayloadLimitExceededError("Parola 1 MB tavanını aştı (CWE-400)")

        # İterasyon kontrolü (CWE-916)
        if not isinstance(iterations, int) or iterations < PasswordSecurityConfig.MIN_ITERATIONS:
            raise InsufficientIterationsError(
                f"PBKDF2 iterasyon sayısı en az {PasswordSecurityConfig.MIN_ITERATIONS} olmalıdır ({iterations} yetersiz - CWE-916)!"
            )

        # Tuz (salt) kontrolü
        if salt is None:
            salt = cls.generate_salt(16)
        elif not isinstance(salt, (bytes, bytearray)):
            raise TypeValidationError("Tuz (salt) 'bytes' tipinde olmalıdır")
        elif len(salt) < PasswordSecurityConfig.MIN_SALT_BYTES:
            raise InsecureSaltLengthError("Tuz uzunluğu 16 bayttan kısa olamaz")

        # Tahmin edilebilir tuz kontrolü (CWE-760)
        salt_hex = salt.hex()
        salt_str_repr = salt.decode("utf-8", errors="ignore")
        if salt_str_repr in PasswordSecurityConfig.PREDICTABLE_SALTS or salt_hex in PasswordSecurityConfig.PREDICTABLE_SALTS:
            raise PredictableSaltError(
                "Tahmin edilebilir veya statik tuz kullanımı engellendi! (CWE-760)"
            )

        # Pepper harmanlama
        effective_key = cls._apply_pepper(password, pepper)

        # PBKDF2-HMAC-SHA256 ile anahtar türetme (32 bayt = 256 bit çıktı)
        derived_bytes = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=effective_key,
            salt=salt,
            iterations=iterations,
            dklen=32
        )
        hash_hex = derived_bytes.hex()
        has_pepper = pepper is not None

        # Standart kurumsal serileştirilmiş format:
        # $pbkdf2-sha256$i={iterations}$s={salt_hex}$p={1/0}${hash_hex}
        formatted_record = f"$pbkdf2-sha256$i={iterations}$s={salt_hex}$p={1 if has_pepper else 0}${hash_hex}"

        return PasswordHashRecord(
            algoritma="pbkdf2-sha256",
            iterasyon=iterations,
            salt_hex=salt_hex,
            has_pepper=has_pepper,
            hash_hex=hash_hex,
            tam_format=formatted_record
        )

    @classmethod
    def parse_record(cls, record_str: str) -> Tuple[str, int, bytes, bool, str]:
        """Serileştirilmiş parola kaydını ayrıştırır. Standart dışı/tuzsuz kayıtları reddeder."""
        if not isinstance(record_str, str):
            raise TypeValidationError("Parola kaydı 'str' tipinde olmalıdır")
        if "\x00" in record_str:
            raise NullByteInjectionError("Parola kaydında Null-Byte tespit edildi")

        # Düz MD5, SHA-1 veya tek geçişli SHA-256 tespiti (CWE-759)
        record_clean = record_str.strip()
        if re.fullmatch(r"[a-fA-F0-9]{32}", record_clean) or re.fullmatch(r"[a-fA-F0-9]{40}", record_clean) or re.fullmatch(r"[a-fA-F0-9]{64}", record_clean):
            raise UnsaltedHashError(
                "Tuzsuz (unsalted) eski hash formatı tespit edildi! Güvenli parola saklama için PBKDF2 zorunludur (CWE-759)."
            )

        pattern = re.compile(r"^\$([a-zA-Z0-9_\-]+)\$i=(\d+)\$s=([a-fA-F0-9]+)\$p=([01])\$([a-fA-F0-9]+)$")
        match = pattern.match(record_clean)
        if not match:
            raise UnsaltedHashError("Bozuk veya desteklenmeyen parola kaydı formatı!")

        algo = match.group(1)
        iterations = int(match.group(2))
        salt_bytes = bytes.fromhex(match.group(3))
        has_pepper = match.group(4) == "1"
        stored_hash_hex = match.group(5)

        return algo, iterations, salt_bytes, has_pepper, stored_hash_hex

    @classmethod
    def verify_password(
        cls,
        password: str,
        stored_record: str,
        pepper: Optional[bytes] = None,
        strict_mode: bool = False
    ) -> PasswordVerificationResult:
        """
        Girilen parolanın doğruluğunu kayıtlı tuz, iterasyon ve biber ile sabit zamanlı doğrular.
        """
        start_time = time.perf_counter()
        algo, iterations, salt_bytes, has_pepper, expected_hash_hex = cls.parse_record(stored_record)

        # Pepper gereksinimi kontrolü
        effective_pepper = pepper if has_pepper else None

        # Parolayı aynı parametrelerle yeniden hashle
        candidate_record = cls.hash_password(
            password=password,
            salt=salt_bytes,
            pepper=effective_pepper,
            iterations=iterations
        )

        # CWE-208: Sabit zamanlı karşılaştırma (Timing Attack Koruması)
        is_match = hmac.compare_digest(candidate_record.hash_hex.lower(), expected_hash_hex.lower())
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        if strict_mode and not is_match:
            raise PasswordVerificationMismatchError("Parola doğrulama başarısız: Parola veya biber eşleşmedi!")

        return PasswordVerificationResult(
            dogrulandi=is_match,
            algoritma=algo,
            iterasyon=iterations,
            pepper_kullanildi=has_pepper,
            gecen_sure_ms=elapsed_ms
        )

    @classmethod
    def detect_insecure_hashing(cls, hash_candidate: str) -> Dict[str, Any]:
        """Verilen hash dizgisinin güvenlik derecesini ve zafiyetlerini inceler."""
        if not isinstance(hash_candidate, str):
            raise TypeValidationError("Hash dizgisi 'str' olmalıdır")

        candidate = hash_candidate.strip()
        if len(candidate) == 32 and re.fullmatch(r"[a-fA-F0-9]+", candidate):
            return {
                "tip": "MD5 (Tuzsuz)",
                "guvenlik": "KRİTİK GÜVENSİZ",
                "zafiyet": "CWE-759 / CWE-916: Gökkuşağı tablolarıyla saniyede çözülebilir",
                "onerilen": "PBKDF2-HMAC-SHA256"
            }
        elif len(candidate) == 40 and re.fullmatch(r"[a-fA-F0-9]+", candidate):
            return {
                "tip": "SHA-1 (Tuzsuz)",
                "guvenlik": "KRİTİK GÜVENSİZ",
                "zafiyet": "CWE-759 / CWE-916: LinkedIn 2012 sızıntısındaki gibi kırılabilir",
                "onerilen": "PBKDF2-HMAC-SHA256"
            }
        elif len(candidate) == 64 and re.fullmatch(r"[a-fA-F0-9]+", candidate):
            return {
                "tip": "Tek Geçişli SHA-256 (Tuzsuz)",
                "guvenlik": "YÜKSEK RİSKLİ",
                "zafiyet": "CWE-916: GPU kümesiyle saniyede milyarlarca denenir",
                "onerilen": "PBKDF2-HMAC-SHA256 (En az 100.000 iterasyon)"
            }
        elif candidate.startswith("$pbkdf2"):
            return {
                "tip": "PBKDF2-HMAC-SHA256",
                "guvenlik": "GÜVENLİ (NIST SP 800-132)",
                "zafiyet": "Yok",
                "onerilen": "Mevcut standart onaylandı"
            }
        else:
            return {
                "tip": "Bilinmeyen Format",
                "guvenlik": "BELİRSİZ",
                "zafiyet": "Standart dışı hashleme",
                "onerilen": "PBKDF2-HMAC-SHA256"
            }
