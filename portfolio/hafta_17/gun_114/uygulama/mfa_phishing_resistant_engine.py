# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 114: Çok Faktörlü Kimlik Doğrulama (MFA) ve Oltalama (Phishing) Direnci Motoru.

Bu modül, modern siber güvenlik mimarilerinde kullanılan MFA yöntemlerinin
(RFC 6238 TOTP, SMS/Push yaklaşımları ve FIDO2/WebAuthn donanım anahtarları)
güvenlik sınırlarını ve Oltalama (Phishing / AiTM - Adversary-in-the-Middle)
saldırılarına karşı direnç dinamiklerini inceler.

Kapsanan Güvenlik Açıkları ve Standartlar:
- RFC 6238: TOTP (Time-Based One-Time Password Algorithm)
- FIDO2 / W3C WebAuthn: Kriptografik Menşe Bağlama (Cryptographic Origin Binding)
- CWE-346: Origin Validation Error (Menşe Doğrulama Hatası ve Phishing Savunması)
- CWE-294: Authentication Bypass by Capture-replay (Meydan Okuma Tekrar Saldırıları)
- CWE-347: Improper Verification of Cryptographic Signature (Geçersiz Asimetrik İmza)
- CWE-307: MFA Fatigue / Spamming (Kaba Kuvvet ve Onay Bıkkınlığı)
- CWE-287: Improper Authentication (Genel Kimlik Doğrulama Zafiyetleri)
"""

# Kriptografik özetleme fonksiyonları için hashlib modülü içe aktarılır
import hashlib
# Mesaj doğrulama kodları için hmac modülü içe aktarılır
import hmac
# Kriptografik rastgele bayt ve belirteç üretimi için secrets modülü içe aktarılır
import secrets
# Bayt paketleme ve tamsayı dönüşümleri için struct modülü içe aktarılır
import struct
# Sistem saati ve Unix zaman damgaları için time modülü içe aktarılır
import time
# Base32 ve Base64 kodlama/çözme işlemleri için base64 modülü içe aktarılır
import base64
# JSON serileştirme işlemleri için json modülü içe aktarılır
import json
# Zaman damgaları ve zaman aralığı hesaplamaları için datetime ve timezone içe aktarılır
from datetime import datetime, timezone, timedelta
# URL ayrıştırma ve menşe (origin) çıkarma için urllib.parse içe aktarılır
from urllib.parse import urlparse
# Nesne veri yapıları için dataclass ve field içe aktarılır
from dataclasses import dataclass, field, asdict
# Tip ipuçları için gerekli türler içe aktarılır
from typing import Dict, List, Optional, Tuple, Any, Set


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI (CUSTOM SECURITY EXCEPTIONS)
# ==============================================================================

class MFASecurityError(Exception):
    """Tüm MFA ve kimlik doğrulama güvenlik istisnalarının temel sınıfı."""
    def __init__(self, message: str, cwe_id: str, error_code: str):
        # Üst sınıf Exception başlatıcısına hata mesajını iletir
        super().__init__(f"[{cwe_id}] {error_code}: {message}")
        # Hata ile ilişkili CWE zafiyet kimliğini saklar
        self.cwe_id = cwe_id
        # Makine tarafından okunabilir hata kodunu saklar
        self.error_code = error_code
        # Kullanıcı dostu teknik açıklama metnini saklar
        self.message = message


class InvalidTOTPCodeError(MFASecurityError):
    """Girilen TOTP kodunun hatalı veya zaman aralığı dışında olması durumunda fırlatılır (CWE-287)."""
    def __init__(self, message: str = "Geçersiz veya süresi dolmuş TOTP tek kullanımlık kodu sunuldu."):
        # CWE-287 kimlik doğrulama hatası olarak tanımlanır
        super().__init__(message, cwe_id="CWE-287", error_code="INVALID_TOTP_CODE")


class TOTPReplayError(MFASecurityError):
    """Aynı 30 saniyelik zaman diliminde kullanılan bir TOTP kodunun tekrar sunulması durumunda fırlatılır (CWE-294)."""
    def __init__(self, message: str = "TOTP kodu tekrar kullanılamaz (Replay saldırısı engellendi)."):
        # CWE-294 tekrar saldırısı zafiyeti olarak tanımlanır
        super().__init__(message, cwe_id="CWE-294", error_code="TOTP_REPLAY_ATTACK")


class MFAFatigueError(MFASecurityError):
    """MFA onay bıkkınlığı (Push Spamming) veya aşırı istek durumunda fırlatılır (CWE-307)."""
    def __init__(self, message: str = "Aşırı MFA doğrulama isteği! MFA Fatigue engelleme eşiği aşıldı."):
        # CWE-307 kaba kuvvet ve aşırı istek kodu olarak tanımlanır
        super().__init__(message, cwe_id="CWE-307", error_code="MFA_FATIGUE_BLOCKED")


class PhishingOriginMismatchError(MFASecurityError):
    """WebAuthn FIDO2 menşe (Origin / RP ID) uyuşmazlığında fırlatılır (CWE-346 Phishing Engeli)."""
    def __init__(self, message: str = "Menşe uyuşmazlığı tespit edildi! Oltalama (Phishing/AiTM) saldırısı engellendi."):
        # CWE-346 menşe doğrulama hatası olarak tanımlanır
        super().__init__(message, cwe_id="CWE-346", error_code="PHISHING_ORIGIN_MISMATCH")


class WebAuthnChallengeMismatchError(MFASecurityError):
    """Sunulan meydan okuma (challenge) tokenının geçersiz veya süresi dolmuş olması durumu (CWE-294)."""
    def __init__(self, message: str = "WebAuthn meydan okuma (challenge) tokenı geçersiz veya süresi dolmuş."):
        # CWE-294 tekrar saldırısı ve geçersiz challenge hatası olarak tanımlanır
        super().__init__(message, cwe_id="CWE-294", error_code="CHALLENGE_MISMATCH")


class WebAuthnInvalidSignatureError(MFASecurityError):
    """FIDO2 donanım anahtarının ürettiği asimetrik imzanın doğrulanamaması durumu (CWE-347)."""
    def __init__(self, message: str = "WebAuthn asimetrik dijital imzası doğrulanamadı."):
        # CWE-347 geçersiz imza doğrulama hatası olarak tanımlanır
        super().__init__(message, cwe_id="CWE-347", error_code="INVALID_FIDO2_SIGNATURE")


class AuthenticatorCloneDetectedError(MFASecurityError):
    """Donanım anahtarının imza sayacının (SignCount) gerilemesi veya donanım klonlama tespiti (CWE-347)."""
    def __init__(self, message: str = "İmza sayacı anomalisi! Donanım güvenlik anahtarının klonlandığı tespit edildi."):
        # Donanım anahtarı klonlama tespiti için CWE-347 atanır
        super().__init__(message, cwe_id="CWE-347", error_code="AUTHENTICATOR_CLONE_DETECTED")


# ==============================================================================
# VERİ MODELLERİ (DATA MODELS)
# ==============================================================================

@dataclass
class TOTPCredential:
    """Kullanıcının RFC 6238 TOTP yapılandırma ve durum bilgilerini saklar."""
    # Kullanıcı adı
    username: str
    # Base32 kodlu paylaşımlı gizli anahtar
    secret_base32: str
    # Üretilecek kodun basamak sayısı (standart 6 basamak)
    digits: int = 6
    # Zaman aralığı adımı (standart 30 saniye)
    period_seconds: int = 30
    # Kodun başarıyla kullanıldığı en son zaman adımı (Replay CWE-294 savunması)
    last_used_step: int = -1


@dataclass
class FIDO2Credential:
    """Kullanıcının FIDO2/WebAuthn genel anahtar ve kimlik bilgilerini saklar."""
    # Güvenlik anahtarı donanım kimliği (Credential ID)
    credential_id: str
    # Kullanıcı adı
    username: str
    # Asimetrik genel anahtar (Modulus ve Public Exponent çifti)
    public_key_n: int
    public_key_e: int
    # Donanım anahtarı üzerinde her imzada artan monotonik sayaç (Clone Detection)
    sign_count: int
    # Kayıtlı olduğu Relying Party ID (örn. 'mevzuat.siber.local')
    rp_id: str
    # Kayıt zaman damgası
    created_at: str


@dataclass
class WebAuthnChallenge:
    """Sunucu tarafından üretilen ve doğrulanmayı bekleyen tek kullanımlık meydan okuma."""
    # 32-baytlık kriptografik rastgele meydan okuma onaltılık metni
    challenge_hex: str
    # Hedef Relying Party kimliği
    rp_id: str
    # İlgili kullanıcı adı
    username: str
    # Meydan okumanın geçerlilik sonu (UTC)
    expires_at: datetime
    # Kullanılıp kullanılmadığını belirten bayrak (Tek kullanımlık - Nonce)
    is_used: bool = False


# ==============================================================================
# RFC 6238 TOTP MOTORU (TIME-BASED ONE-TIME PASSWORD)
# ==============================================================================

class TOTPEngine:
    """
    RFC 6238 Time-Based One-Time Password (TOTP) Referans Motoru.
    HMAC-SHA1 algoritmasını, dinamik kırpmayı (Dynamic Truncation) ve
    zaman adımı kaydırma (Replay) korumasını uygular.
    """

    def __init__(self, period_seconds: int = 30, digits: int = 6):
        # Zaman aralığı adımı atanır
        self.period_seconds = period_seconds
        # Kod basamak sayısı atanır
        self.digits = digits
        # Kullanıcı TOTP kimlik bilgileri deposu (username -> TOTPCredential)
        self._credentials: Dict[str, TOTPCredential] = {}

    @staticmethod
    def generate_secret(byte_length: int = 20) -> str:
        """Kriptografik olarak güvenli Base32 formatında rastgele gizli anahtar üretir."""
        # secrets modülü ile kriptografik güvenli rastgele baytlar çekilir
        raw_bytes = secrets.token_bytes(byte_length)
        # Bayt dizisi RFC 3548 Base32 formatına dönüştürülür ve dolguları temizlenir
        return base64.b32encode(raw_bytes).decode("ascii").rstrip("=")

    def register_user(self, username: str, secret_base32: Optional[str] = None) -> TOTPCredential:
        """Kullanıcı için TOTP kaydı oluşturur."""
        clean_user = username.strip().lower()
        if not secret_base32:
            secret_base32 = self.generate_secret()
        cred = TOTPCredential(
            username=clean_user,
            secret_base32=secret_base32,
            digits=self.digits,
            period_seconds=self.period_seconds
        )
        self._credentials[clean_user] = cred
        return cred

    def get_credential(self, username: str) -> Optional[TOTPCredential]:
        """Kullanıcının TOTP kaydını getirir."""
        return self._credentials.get(username.strip().lower())

    def generate_code(self, secret_base32: str, timestamp: Optional[float] = None) -> Tuple[str, int]:
        """
        RFC 6238 standardına göre verilen zaman damgası için TOTP kodu üretir.
        
        Returns:
            Tuple[str, int]: (6-haneli kod, zaman_adımı) ikilisi döner.
        """
        # Zaman damgası belirtilmemişse geçerli Unix zamanı alınır
        if timestamp is None:
            timestamp = time.time()

        # Zaman adımı T = floor((CurrentTime - T0) / X) hesaplanır
        time_step = int(timestamp // self.period_seconds)

        # Base32 anahtarı bayt dizisine dönüştürülür (Eksik dolgular tamamlanır)
        padding = "=" * ((8 - len(secret_base32) % 8) % 8)
        key_bytes = base64.b32decode(secret_base32.upper() + padding)

        # Zaman adımı 8-baytlık Big-Endian tamsayı olarak paketlenir
        msg_bytes = struct.pack(">Q", time_step)

        # HMAC-SHA1 özet değeri hesaplanır (RFC 6238 standardı)
        hmac_digest = hmac.new(key_bytes, msg_bytes, hashlib.sha1).digest()

        # Dinamik Kırpma (Dynamic Truncation): Son baytın alt 4 biti ofset olarak alınır
        offset = hmac_digest[-1] & 0x0F

        # 4 baytlık ikili kod çekilir ve işaret biti (0x7FFFFFFF) maskelenir
        binary_code = struct.unpack(">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF

        # İstenen basamak modülüne (10^digits) indirgenir
        modulo = 10 ** self.digits
        totp_int = binary_code % modulo

        # Başına sıfır eklenerek sabit uzunlukta metin formatı elde edilir
        totp_str = f"{totp_int:0{self.digits}d}"
        return totp_str, time_step

    def verify_code(self, username: str, submitted_code: str, timestamp: Optional[float] = None, window: int = 1) -> bool:
        """
        Kullanıcının sunduğu TOTP kodunu zaman sapması penceresi (drift window) ve
        tekrar kullanım (replay) korumasıyla doğrular.
        """
        if timestamp is None:
            timestamp = time.time()

        clean_user = username.strip().lower()
        cred = self.get_credential(clean_user)
        if not cred:
            raise InvalidTOTPCodeError("Kullanıcı için aktif TOTP kaydı bulunamadı.")

        current_step = int(timestamp // self.period_seconds)

        # Zaman sapması penceresi taranır (-window, 0, +window)
        for offset in range(-window, window + 1):
            target_step = current_step + offset
            target_time = target_step * self.period_seconds
            expected_code, step = self.generate_code(cred.secret_base32, timestamp=target_time)

            # Sabit zamanlı karşılaştırma (CWE-208 zamanlama koruması)
            if secrets.compare_digest(submitted_code.strip(), expected_code):
                # CWE-294 Replay Saldırısı Denetimi: Bu adım daha önce kullanıldı mı?
                if step <= cred.last_used_step:
                    raise TOTPReplayError(f"Bu TOTP kodu ({step}. adım) daha önce kullanılmıştır. Yeni bir kod bekleyiniz.")

                # Başarılı doğrulama: Adım güncellenir
                cred.last_used_step = step
                return True

        # Hiçbir pencerede eşleşmediyse geçersiz kod
        raise InvalidTOTPCodeError("Sunulan TOTP kodu hatalı veya süresi geçmiş.")


# ==============================================================================
# FIDO2 / WEBAUTHN SİMÜLATÖR MOTORU (PHISHING-RESISTANT MFA)
# ==============================================================================

class WebAuthnFIDO2Engine:
    """
    FIDO2 / WebAuthn standardının Kriptografik Menşe Bağlama (Origin Binding)
    ve Oltalama Direnci (Phishing-Resistance) özelliklerini simüle eden referans motor.
    
    Kritik İlke:
    Kimlik doğrulama sırasında donanım güvenlik anahtarı 'clientDataJSON' içinde yer alan
    'origin' bilgisini (tarayıcının bağlandığı gerçek web adresini) imzalar.
    Eğer saldırgan kullanıcıyı sahte bir oltalama sitesine (phishing domain) yönlendirirse,
    donanım anahtarı sahte adresi imzalar. Gerçek sunucu bu imzayı aldığında
    Menşe Uyuşmazlığı (CWE-346) tespit ederek saldırıyı anında çökertecektir.
    """

    def __init__(self, relying_party_id: str = "mevzuat.siber.local", relying_party_origin: str = "https://mevzuat.siber.local"):
        # Güvenen Taraf (Relying Party - RP) kimliği
        self.rp_id = relying_party_id
        # Güvenen Tarafın beklenen meşru web menşei (Origin)
        self.rp_origin = relying_party_origin
        # Kayıtlı genel anahtarlar (credential_id -> FIDO2Credential)
        self._credentials: Dict[str, FIDO2Credential] = {}
        # Aktif meydan okumalar (challenge_hex -> WebAuthnChallenge)
        self._challenges: Dict[str, WebAuthnChallenge] = {}

    def create_authentication_challenge(self, username: str, ttl_seconds: int = 120) -> WebAuthnChallenge:
        """Sunucu tarafında tek kullanımlık 32-baytlık kriptografik meydan okuma (challenge) üretir."""
        # Kriptografik güvenli 32 bayt üretilir
        raw_challenge = secrets.token_bytes(32)
        challenge_hex = raw_challenge.hex()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        challenge = WebAuthnChallenge(
            challenge_hex=challenge_hex,
            rp_id=self.rp_id,
            username=username.strip().lower(),
            expires_at=expires_at,
            is_used=False
        )
        self._challenges[challenge_hex] = challenge
        return challenge

    def register_credential(
        self,
        credential_id: str,
        username: str,
        public_key_n: int,
        public_key_e: int = 65537,
        initial_sign_count: int = 0
    ) -> FIDO2Credential:
        """Kullanıcının donanım güvenlik anahtarını sisteme kaydeder (Attestation sonucu)."""
        clean_user = username.strip().lower()
        cred = FIDO2Credential(
            credential_id=credential_id,
            username=clean_user,
            public_key_n=public_key_n,
            public_key_e=public_key_e,
            sign_count=initial_sign_count,
            rp_id=self.rp_id,
            created_at=datetime.now(timezone.utc).isoformat()
        )
        self._credentials[credential_id] = cred
        return cred

    def get_credential(self, credential_id: str) -> Optional[FIDO2Credential]:
        """Kayıtlı kimlik bilgisini döndürür."""
        return self._credentials.get(credential_id)

    @staticmethod
    def _modular_pow_verify(signature_int: int, e: int, n: int, expected_hash_bytes: bytes) -> bool:
        """Basitleştirilmiş saf Python RSA imza doğrulaması (PKCS#1 v1.5 özet kıyası)."""
        try:
            # s^e mod n hesaplanır
            decrypted_val = pow(signature_int, e, n)
            # Bayt formatına dönüştürülür
            byte_len = (n.bit_length() + 7) // 8
            decrypted_bytes = decrypted_val.to_bytes(byte_len, byteorder="big")
            # En sağdaki 32 bayt SHA-256 özetiyle sabit zamanlı karşılaştırılır
            recovered_hash = decrypted_bytes[-32:]
            return secrets.compare_digest(recovered_hash, expected_hash_bytes)
        except Exception:
            return False

    def verify_assertion(
        self,
        credential_id: str,
        client_data_json_str: str,
        authenticator_data_bytes: bytes,
        signature_int: int,
        now: Optional[datetime] = None
    ) -> bool:
        """
        FIDO2 / WebAuthn doğrulama yanıtını (Assertion) katı güvenlik kontrolleriyle denetler.
        
        Adımlar:
        1. clientDataJSON parse edilir.
        2. Challenge doğrulanır (Süresi dolmamış ve tek kullanımlık olmalıdır - CWE-294).
        3. Menşe (Origin) doğrulanır (CWE-346 Phishing Engelleme): Beklenen origin ile birebir eşleşmelidir!
        4. İmza Sayacı (SignCount) denetlenir (CWE-347 Klonlama Tespiti).
        5. Asimetrik imza doğrulanır (CWE-347).
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # 1. Kayıtlı kimlik bilgisi çekilir
        cred = self.get_credential(credential_id)
        if not cred:
            raise WebAuthnInvalidSignatureError(f"Bilinmeyen donanım anahtarı kimliği: {credential_id}")

        # 2. clientDataJSON ayrıştırılır
        try:
            client_data = json.loads(client_data_json_str)
        except Exception:
            raise WebAuthnChallengeMismatchError("clientDataJSON geçerli bir JSON verisi değil.")

        submitted_challenge = client_data.get("challenge")
        submitted_origin = client_data.get("origin")
        operation_type = client_data.get("type")

        # İşlem türü doğrulaması
        if operation_type != "webauthn.get":
            raise WebAuthnChallengeMismatchError(f"Beklenmeyen WebAuthn işlem türü: {operation_type}")

        # 3. Challenge Varlık ve Süre Denetimi (CWE-294 Anti-Replay)
        if not submitted_challenge or submitted_challenge not in self._challenges:
            raise WebAuthnChallengeMismatchError("Geçersiz veya sunucu tarafından üretilmemiş challenge.")

        challenge_obj = self._challenges[submitted_challenge]
        if challenge_obj.is_used:
            raise WebAuthnChallengeMismatchError("Bu challenge daha önce kullanılmış (Tekrar kullanımı engellendi).")
        if now > challenge_obj.expires_at:
            raise WebAuthnChallengeMismatchError("Meydan okuma (challenge) süresi dolmuş.")

        # 4. KRİTİK GÜVENLİK ADIMI: Menşe (Origin) Doğrulaması (CWE-346 Phishing Savunması)
        # Oltalama saldırganı sahte sitede (örn. https://phishing-site.com) imza üretse dahi,
        # bu origin beklenen rp_origin ile eşleşmeyecektir!
        if submitted_origin != self.rp_origin:
            raise PhishingOriginMismatchError(
                f"Kritik Oltalama (Phishing) Girişimi! Beklenen Menşe: '{self.rp_origin}', "
                f"Donanım Anahtarının İmzaladığı Menşe: '{submitted_origin}'"
            )

        # 5. İmza Sayacı (SignCount) Klonlama Kontrolü (CWE-347)
        # authenticator_data içindeki 33. ila 36. baytlar 4-baytlık Big-Endian sayaçtır
        if len(authenticator_data_bytes) < 37:
            raise WebAuthnInvalidSignatureError("authenticatorData boyutu geçersiz.")

        incoming_sign_count = struct.unpack(">I", authenticator_data_bytes[33:37])[0]

        # Donanım anahtarı sayacı artmadıysa veya gerilediyse klon şüphesi vardır
        if incoming_sign_count > 0 and incoming_sign_count <= cred.sign_count:
            raise AuthenticatorCloneDetectedError(
                f"Güvenlik anahtarı sayacı geriledi veya tekrarlandı! "
                f"Kayıtlı Sayaç: {cred.sign_count}, Gelen Sayaç: {incoming_sign_count}"
            )

        # 6. Asimetrik İmza Doğrulaması (CWE-347)
        # İmzalanan veri: authenticatorData + SHA256(clientDataJSON)
        client_data_hash = hashlib.sha256(client_data_json_str.encode("utf-8")).digest()
        signed_data = authenticator_data_bytes + client_data_hash
        expected_hash = hashlib.sha256(signed_data).digest()

        is_valid_sig = self._modular_pow_verify(
            signature_int=signature_int,
            e=cred.public_key_e,
            n=cred.public_key_n,
            expected_hash_bytes=expected_hash
        )

        if not is_valid_sig:
            raise WebAuthnInvalidSignatureError("FIDO2 donanım anahtarının asimetrik imzası doğrulanamadı!")

        # Tüm kontroller başarılı: Challenge kullanıldı olarak işaretlenir ve sayaç güncellenir
        challenge_obj.is_used = True
        cred.sign_count = incoming_sign_count
        return True


# ==============================================================================
# AiTM / EVILGINX PHISHING SİMÜLATÖRÜ (SALDIRI VE SAVUNMA ANALİZİ)
# ==============================================================================

class PhishingAttackSimulator:
    """
    Ters Vekil (Reverse Proxy / AiTM - Adversary in the Middle, örn. Evilginx2)
    saldırılarını simüle ederek TOTP ile FIDO2 WebAuthn arasındaki
    oltalama direnci farkını somutlaştıran laboratuvar simülatörü.
    """

    @staticmethod
    def simulate_totp_phishing_attack(
        totp_engine: TOTPEngine,
        username: str,
        totp_code: str
    ) -> Dict[str, Any]:
        """
        TOTP'nin Phishing Dirençsizliğini gösterir:
        Kullanıcı oltalama sitesine (phishing domain) TOTP kodunu girer.
        Ters vekil (Evilginx) bu kodu anında yakalar ve kurbanın yerine gerçek sunucuya iletir.
        Sonuç: TOTP'de menşe bağlama olmadığı için saldırı BAŞARILI olur!
        """
        try:
            # Gerçek sunucuya vekil üzerinden iletilen kod doğrulanır
            is_valid = totp_engine.verify_code(username, totp_code)
            return {
                "yontem": "TOTP (RFC 6238)",
                "saldiri_turu": "AiTM Reverse Proxy Phishing (Evilginx)",
                "saldiri_basarili_mi": True,
                "aciklama": (
                    "ZAFİYET: TOTP kodunda web sitesi menşei (Origin) bilgisi bulunmaz. "
                    "Saldırgan sahte sitede çaldığı 6-haneli kodu 30 saniye içinde meşru siteye ileterek "
                    "kullanıcının oturumunu başarıyla ele geçirmiştir (CWE-287)."
                )
            }
        except MFASecurityError as e:
            return {
                "yontem": "TOTP (RFC 6238)",
                "saldiri_turu": "AiTM Reverse Proxy Phishing",
                "saldiri_basarili_mi": False,
                "hata": str(e)
            }

    @staticmethod
    def simulate_fido2_phishing_attack(
        fido2_engine: WebAuthnFIDO2Engine,
        credential_id: str,
        phishing_origin: str,
        challenge_hex: str,
        authenticator_data: bytes,
        signature_int: int
    ) -> Dict[str, Any]:
        """
        FIDO2 / WebAuthn'un Phishing Direncini gösterir:
        Kullanıcı sahte oltalama sitesindedir (phishing_origin).
        Donanım güvenlik anahtarı tarayıcı tarafından bildirilen sahte menşei imzalar.
        Saldırgan bu yanıtı alıp meşru sunucuya (rp_origin) ilettiğinde,
        sunucu Menşe Uyuşmazlığı tespit eder ve saldırıyı bertaraf eder!
        """
        # Sahte menşe ile oluşturulan clientDataJSON
        phishing_client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": challenge_hex,
            "origin": phishing_origin
        })

        try:
            fido2_engine.verify_assertion(
                credential_id=credential_id,
                client_data_json_str=phishing_client_data,
                authenticator_data_bytes=authenticator_data,
                signature_int=signature_int
            )
            return {
                "yontem": "FIDO2 / WebAuthn",
                "saldiri_turu": "AiTM Reverse Proxy Phishing",
                "saldiri_basarili_mi": True,
                "aciklama": "Beklenmeyen durum: FIDO2 doğrulaması geçmemeliydi!"
            }
        except PhishingOriginMismatchError as e:
            return {
                "yontem": "FIDO2 / WebAuthn",
                "saldiri_turu": "AiTM Reverse Proxy Phishing (Evilginx)",
                "saldiri_basarili_mi": False,
                "yakalanan_zafiyet": "CWE-346: Origin Validation Error",
                "hata_mesaji": str(e),
                "aciklama": (
                    "GÜVENLİ: Donanım anahtarı istemci menşeini (Origin) kriptografik imzaya dahil etmiştir. "
                    "Meşru sunucu, imzanın sahte oltalama sitesi için atıldığını tespit ederek "
                    "AiTM vekil saldırısını tamamen engellemiştir."
                )
            }
