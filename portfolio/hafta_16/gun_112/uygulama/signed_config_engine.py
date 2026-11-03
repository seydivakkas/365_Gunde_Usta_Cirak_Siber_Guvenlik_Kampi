# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
Mini Proje 15: İmzalı Yapılandırma Konsepti Motoru (signed_config_engine.py).

Bu modül; kritik altyapı ve güvenlik servislerinin yapılandırma dosyalarını (Firewall,
KMS, TLS kuralları) asimetrik kriptografi ile imzalar, RFC 8785 standardında kanonikleştirir,
monotonik epoch ile Rollback (eski sürüme düşürme) saldırılarını engeller,
çift imza (Dual Signing) yetkilendirmesini ve tahrifat korumasını (Tamper-Evidence)
harici kütüphane bağımlılığı olmadan (Pure Python) uçtan uca yürütür.
"""

import os
import sys
import json
import time
import math
import hmac
import secrets
import hashlib
import datetime
from typing import Dict, List, Tuple, Optional, Any, Set

# ==============================================================================
# 1. ÖZEL İSTİSNA SINIFLARI (CWE GÜVENLİK KONTROLLERİ)
# ==============================================================================

class SignedConfigError(Exception):
    """İmzalı yapılandırma motorundaki tüm hataların temel sınıfı."""
    pass

class ConfigTamperingError(SignedConfigError):
    """CWE-353: Yapılandırma verisinde tek bir bayt bile değiştirildiğinde fırlatılır."""
    pass

class InvalidSignatureError(SignedConfigError):
    """CWE-347: Dijital imza doğrulaması matematiksel olarak başarısız olduğunda fırlatılır."""
    pass

class RollbackAttackDetectedError(SignedConfigError):
    """CWE-294: Mevcut sistem epoch'undan daha düşük/eski bir sürüm yüklendiğinde fırlatılır."""
    pass

class ConfigExpiredError(SignedConfigError):
    """CWE-298: Yapılandırma geçerlilik bitiş süresi (ExpiresAt) aşıldığında fırlatılır."""
    pass

class InsufficientSignaturesError(SignedConfigError):
    """CWE-285: Çoklu imza (Dual Signing) politikasında asgari onay eşiği sağlanamadığında fırlatılır."""
    pass

class UntrustedSignerError(SignedConfigError):
    """CWE-295: Güven deposunda (Trust Store) bulunmayan yetkisiz bir anahtarla imzalandığında fırlatılır."""
    pass

class MalformedConfigError(SignedConfigError):
    """CWE-20: Yapılandırma yükü geçerli bir kanonik JSON formatında olmadığında fırlatılır."""
    pass

class FutureTimestampError(SignedConfigError):
    """CWE-298: İmza zaman damgası sistem saatinden ileride (aşırı saat kayması) olduğunda fırlatılır."""
    pass

class InsecureAlgorithmError(SignedConfigError):
    """CWE-327: Onaylanmamış ('none' veya kırılmış) bir imza algoritması talep edildiğinde fırlatılır."""
    pass


# ==============================================================================
# 2. KRİPTOGRAFİK YARDIMCI İŞLEMLER (RSA VE KANONİKLEŞTİRME - RFC 8785)
# ==============================================================================

def canonicalize_json(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme (JCS) uyumlu deterministik bayt dizisi üretir."""
    try:
        # Anahtarlar alfabetik sıralanır, gereksiz boşluklar kaldırılır
        return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    except Exception as e:
        raise MalformedConfigError(f"CWE-20: Veri kanonik JSON formatına dönüştürülemedi: {e}")

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Genişletilmiş Öklid Algoritması."""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def modular_inverse(e: int, phi: int) -> int:
    """Modüler ters hesabı."""
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modüler ters mevcut değil.")
    return (x % phi + phi) % phi

def is_prime_miller_rabin(n: int, k: int = 25) -> bool:
    """Miller-Rabin asallık testi."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Belirtilen bit uzunluğunda rastgele asal sayı üretir."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(candidate):
            return candidate

class RSAKeyPair:
    """Hafif ve bağımsız RSA anahtar çifti modeli."""
    def __init__(self, key_id: str, public_key: Dict[str, int], private_key: Optional[Dict[str, int]] = None):
        self.key_id = key_id
        self.public_key = public_key
        self.private_key = private_key

    @classmethod
    def generate(cls, key_id: str, bits: int = 512, e: int = 65537) -> "RSAKeyPair":
        """Hızlı ve güvenli RSA anahtar çifti türetir."""
        half = bits // 2
        while True:
            p = generate_prime(half)
            q = generate_prime(half)
            if p != q:
                n = p * q
                phi = (p - 1) * (q - 1)
                if math.gcd(e, phi) == 1:
                    d = modular_inverse(e, phi)
                    return cls(key_id=key_id, public_key={"n": n, "e": e}, private_key={"n": n, "d": d})

    def sign_digest(self, digest_bytes: bytes) -> str:
        """Özet değerini özel anahtarla imzalayarak onaltılık (hex) dize üretir."""
        if not self.private_key:
            raise ValueError("İmzalama için özel anahtar gereklidir.")
        h_int = int.from_bytes(digest_bytes, byteorder="big")
        sig_int = pow(h_int, self.private_key["d"], self.private_key["n"])
        return hex(sig_int)[2:]

    @staticmethod
    def verify_digest(public_key: Dict[str, int], digest_bytes: bytes, signature_hex: str) -> bool:
        """Genel anahtarla imzanın doğruluğunu teyit eder."""
        try:
            sig_int = int(signature_hex, 16)
            rec_int = pow(sig_int, public_key["e"], public_key["n"])
            rec_bytes = rec_int.to_bytes((rec_int.bit_length() + 7) // 8, byteorder="big")
            # Sabit zamanlı karşılaştırma (CWE-208 önlemi)
            return hmac.compare_digest(digest_bytes.lstrip(b"\x00"), rec_bytes.lstrip(b"\x00"))
        except Exception:
            return False


# ==============================================================================
# 3. İMZALI YAPILANDIRMA ZARFI VE İMZALAYICI MOTOR
# ==============================================================================

class SignedConfigSigner:
    """Yapılandırma paketlerini kanonikleştirip asimetrik dijital imza ile mühürleyen motor."""
    def __init__(self, keypair: RSAKeyPair):
        self.keypair = keypair

    def sign_config(self, payload: Dict[str, Any], epoch: int,
                    validity_days: int = 90, algorithm: str = "RSA-SHA256") -> Dict[str, Any]:
        """Yapılandırmayı RFC 8785 ile kanonikleştirir ve dijital imza zarfı üretir."""
        # CWE-327 Kontrolü: Zayıf veya 'none' algoritması reddedilir
        if algorithm != "RSA-SHA256":
            raise InsecureAlgorithmError(f"CWE-327: Desteklenmeyen veya güvensiz algoritma: {algorithm}")

        # 1. Kanonik baytlar ve SHA-256 özeti
        canonical_bytes = canonicalize_json(payload)
        payload_hash = hashlib.sha256(canonical_bytes).hexdigest()

        # 2. Zaman damgaları
        now = datetime.datetime.now(datetime.timezone.utc)
        created_at = now.isoformat()
        expires_at = (now + datetime.timedelta(days=validity_days)).isoformat()

        # 3. İmzalanacak imza bloğu (Epoch, Tarih, Payload Hash)
        sign_block = {
            "epoch": epoch,
            "created_at": created_at,
            "expires_at": expires_at,
            "payload_sha256": payload_hash
        }
        sign_block_digest = hashlib.sha256(canonicalize_json(sign_block)).digest()

        # 4. Asimetrik dijital imzalama
        sig_hex = self.keypair.sign_digest(sign_block_digest)

        # 5. Mühürlü Zarf Paketi
        envelope = {
            "format": "SEC-SIGNED-CONFIG-V1",
            "epoch": epoch,
            "created_at": created_at,
            "expires_at": expires_at,
            "payload": payload,
            "payload_sha256": payload_hash,
            "signatures": [
                {
                    "signer_id": self.keypair.key_id,
                    "algorithm": algorithm,
                    "public_key": self.keypair.public_key,
                    "signature_hex": sig_hex
                }
            ]
        }
        return envelope

    def co_sign_envelope(self, envelope: Dict[str, Any], algorithm: str = "RSA-SHA256") -> Dict[str, Any]:
        """Var olan bir zarfa ek yetkili imzası (Dual Signing) ekler."""
        if algorithm != "RSA-SHA256":
            raise InsecureAlgorithmError(f"CWE-327: Desteklenmeyen algoritma: {algorithm}")

        sign_block = {
            "epoch": envelope["epoch"],
            "created_at": envelope["created_at"],
            "expires_at": envelope["expires_at"],
            "payload_sha256": envelope["payload_sha256"]
        }
        digest = hashlib.sha256(canonicalize_json(sign_block)).digest()
        sig_hex = self.keypair.sign_digest(digest)

        new_sig = {
            "signer_id": self.keypair.key_id,
            "algorithm": algorithm,
            "public_key": self.keypair.public_key,
            "signature_hex": sig_hex
        }
        updated_envelope = dict(envelope)
        updated_envelope["signatures"] = list(envelope.get("signatures", [])) + [new_sig]
        return updated_envelope


# ==============================================================================
# 4. İMZALI YAPILANDIRMA DOĞRULAYICI (CONFIG VERIFIER & TRUST STORE)
# ==============================================================================

class SignedConfigVerifier:
    """Sistem başlangıcında veya çalışma anında imzalı yapılandırmayı denetleyen doğrulayıcı."""
    def __init__(self, trust_store: Dict[str, Dict[str, int]], current_system_epoch: int = 1,
                 required_signatures: int = 1):
        # Güvenilen anahtarlar havuzu: {signer_id: public_key}
        self.trust_store = trust_store
        # Sistemin mevcut güvenlik epoch sayacı (Anti-Rollback koruması)
        self.current_system_epoch = current_system_epoch
        # Çoklu imza asgari eşiği (M-of-N)
        self.required_signatures = required_signatures

    def verify_and_load(self, envelope: Dict[str, Any],
                        current_time: Optional[datetime.datetime] = None) -> Dict[str, Any]:
        """Tüm güvenlik kontrollerini çalıştırır. Herhangi bir zafiyette ilgili hatayı fırlatır."""
        # 1. Adım: Format ve Kanonik Ayrıştırma Kontrolü (CWE-20)
        if not isinstance(envelope, dict) or envelope.get("format") != "SEC-SIGNED-CONFIG-V1":
            raise MalformedConfigError("CWE-20: Geçersiz veya desteklenmeyen yapılandırma formatı!")

        # 2. Adım: Anti-Rollback ve Monotonik Epoch Denetimi (CWE-294)
        config_epoch = envelope.get("epoch", 0)
        if config_epoch < self.current_system_epoch:
            raise RollbackAttackDetectedError(
                f"CWE-294: Rollback saldırısı engellendi! Sistem epoch: {self.current_system_epoch}, sunulan epoch: {config_epoch}"
            )

        # 3. Adım: Zaman Sınırları Denetimi (CWE-298)
        now = current_time or datetime.datetime.now(datetime.timezone.utc)
        created_at = datetime.datetime.fromisoformat(envelope["created_at"].replace("Z", "+00:00"))
        expires_at = datetime.datetime.fromisoformat(envelope["expires_at"].replace("Z", "+00:00"))

        # Gelecek zaman anomalisi (Saat kayması toleransı: 60 saniye)
        if (created_at - now).total_seconds() > 60:
            raise FutureTimestampError(
                f"CWE-298: İmza zaman damgası sistem saatinden ileride! ({envelope['created_at']})"
            )
        # Geçerlilik süresi dolmuş mu?
        if now > expires_at:
            raise ConfigExpiredError(
                f"CWE-298: Yapılandırma dosyasının geçerlilik süresi dolmuştur! ({envelope['expires_at']})"
            )

        # 4. Adım: Bütünlük ve Tahrifat Denetimi (Tamper-Evidence / CWE-353)
        payload = envelope.get("payload")
        canonical_payload_bytes = canonicalize_json(payload)
        actual_hash = hashlib.sha256(canonical_payload_bytes).hexdigest()
        declared_hash = envelope.get("payload_sha256", "")

        if not hmac.compare_digest(actual_hash, declared_hash):
            raise ConfigTamperingError(
                "CWE-353: Yapılandırma yükünde tahrifat tespit edildi! Hesaplanan hash ile beyan edilen hash uyuşmuyor."
            )

        # 5. Adım: Dijital İmza ve Güven Kökü Denetimi (CWE-347 & CWE-295)
        signatures = envelope.get("signatures", [])
        if len(signatures) < self.required_signatures:
            raise InsufficientSignaturesError(
                f"CWE-285: Asgari imza sayısı ({self.required_signatures}) sağlanamadı! Bulunan: {len(signatures)}"
            )

        sign_block = {
            "epoch": config_epoch,
            "created_at": envelope["created_at"],
            "expires_at": envelope["expires_at"],
            "payload_sha256": declared_hash
        }
        sign_block_digest = hashlib.sha256(canonicalize_json(sign_block)).digest()

        valid_signers: Set[str] = set()

        for sig_entry in signatures:
            alg = sig_entry.get("algorithm")
            # Algoritma kontrolü
            if alg != "RSA-SHA256":
                raise InsecureAlgorithmError(f"CWE-327: Güvensiz veya yasaklanmış imza algoritması: {alg}")

            signer_id = sig_entry.get("signer_id", "")
            # CWE-295: Güven deposunda kayıtlı mı?
            if signer_id not in self.trust_store:
                raise UntrustedSignerError(f"CWE-295: İmzalayıcı ({signer_id}) güvenilen anahtarlar deposunda kayıtlı değil!")

            trusted_pub_key = self.trust_store[signer_id]
            sig_hex = sig_entry.get("signature_hex", "")

            # CWE-347: İmza doğrulama
            is_valid = RSAKeyPair.verify_digest(trusted_pub_key, sign_block_digest, sig_hex)
            if not is_valid:
                raise InvalidSignatureError(f"CWE-347: {signer_id} tarafından atılan dijital imza matematiksel olarak geçersiz!")

            valid_signers.add(signer_id)

        # Çift imzada benzersiz yetkili sayısı kontrolü
        if len(valid_signers) < self.required_signatures:
            raise InsufficientSignaturesError(
                f"CWE-285: Çift imzada farklı yetkililerden imza alınmalıdır! Geçerli imzalayıcı sayısı: {len(valid_signers)}"
            )

        # Başarıyla doğrulandı; sistem epoch sayacını güncelle ve açık yükü döndür
        self.current_system_epoch = max(self.current_system_epoch, config_epoch)
        return payload
