# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 116: JSON Web Token (JWT) Yapısı ve Güvenli Doğrulama Motoru.

Bu modül, RFC 7519 (JWT) ve RFC 7515 (JWS) standartlarına tam uyumlu olarak;
üç parçalı belirteç ayrıştırma, Base64URL kodlama/çözme, 'alg: none' zafiyeti savunması,
algoritma karışıklığı (Algorithm Confusion RS256 -> HS256) engellemesi,
zaman aşımı (exp/nbf), kimlik sınırları (iss/aud) ve jti tabanlı iptal kara listesini
%100 saf Python standart kütüphanesiyle yönetir.

Kapsanan Güvenlik Açıkları ve Standartlar:
- RFC 7519: JSON Web Token (JWT)
- RFC 7515: JSON Web Signature (JWS)
- CWE-347: Improper Verification of Cryptographic Signature ('alg: none' saldırısı)
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm (Algorithm Confusion)
- CWE-298: Improper Validation of Certificate Expiration (exp ve nbf kontrolleri)
- CWE-613: Insufficient Session Expiration
- CWE-294: Authentication Bypass by Capture-replay (jti kara liste iptali)
- CWE-287: Improper Authentication (iss ve aud doğrulama hataları)
- CWE-208: Observable Timing Discrepancy (secrets.compare_digest ile sabit zamanlı imza kontrolü)
"""

# Kriptografik özet fonksiyonları için hashlib modülü içe aktarılır
import hashlib
# Mesaj doğrulama kodları ve sabit zamanlı karşılaştırma için hmac modülü içe aktarılır
import hmac
# Kriptografik güvenli rastgele sayı ve belirteç üretimi için secrets modülü içe aktarılır
import secrets
# URL-safe Base64 dönüştürme işlemleri için base64 modülü içe aktarılır
import base64
# JSON verisi serileştirme ve ayrıştırma için json modülü içe aktarılır
import json
# Zaman damgaları ve zaman dilimi hesaplamaları için datetime ve timezone içe aktarılır
from datetime import datetime, timezone, timedelta
# Unix zaman damgası hesaplamaları için time modülü içe aktarılır
import time
# Veri sınıfları için dataclass ve field içe aktarılır
from dataclasses import dataclass, field, asdict
# Tip ipuçları için typing modülü içe aktarılır
from typing import Dict, List, Optional, Set, Tuple, Any


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI (CUSTOM SECURITY EXCEPTIONS)
# ==============================================================================

class JWTSecurityError(Exception):
    """Tüm JWT güvenlik ve doğrulama istisnalarının temel sınıfı."""
    def __init__(self, message: str, cwe_id: str, error_code: str):
        # Hata mesajı standart CWE ve hata kodu formatında üst sınıfa iletilir
        super().__init__(f"[{cwe_id}] {error_code}: {message}")
        # CWE zafiyet kimliği saklanır
        self.cwe_id = cwe_id
        # Hata kodu saklanır
        self.error_code = error_code
        # Detaylı teknik açıklama saklanır
        self.message = message


class AlgorithmNoneAttackError(JWTSecurityError):
    """'alg: none' veya imzasız belirteç saldırısı tespit edildiğinde fırlatılır (CWE-347)."""
    def __init__(self, message: str = "'alg: none' saldırısı tespit edildi! İmzasız belirteçler kesinlikle yasaktır."):
        super().__init__(message, cwe_id="CWE-347", error_code="ALGORITHM_NONE_FORBIDDEN")


class AlgorithmConfusionError(JWTSecurityError):
    """Algoritma karışıklığı veya izin verilmeyen algoritma sunulduğunda fırlatılır (CWE-327)."""
    def __init__(self, message: str = "Algoritma karışıklığı (Algorithm Confusion) veya yetkisiz algoritma tespit edildi."):
        super().__init__(message, cwe_id="CWE-327", error_code="ALGORITHM_CONFUSION_DETECTED")


class InvalidSignatureError(JWTSecurityError):
    """JWT kriptografik imzası doğrulanamadığında veya sahte olduğunda fırlatılır (CWE-347)."""
    def __init__(self, message: str = "JWT dijital imzası geçersiz! Belirteç kurcalanmış veya sahte."):
        super().__init__(message, cwe_id="CWE-347", error_code="INVALID_SIGNATURE")


class TokenExpiredError(JWTSecurityError):
    """Belirtecin geçerlilik süresi (exp claim'i) dolduğunda fırlatılır (CWE-298 / CWE-613)."""
    def __init__(self, message: str = "JWT geçerlilik süresi (exp) dolmuştur."):
        super().__init__(message, cwe_id="CWE-298", error_code="TOKEN_EXPIRED")


class TokenNotYetValidError(JWTSecurityError):
    """Belirteç henüz geçerli olmadan önce (nbf claim'i) sunulduğunda fırlatılır (CWE-298)."""
    def __init__(self, message: str = "JWT henüz geçerlilik kazanmamıştır (nbf ihlali)."):
        super().__init__(message, cwe_id="CWE-298", error_code="TOKEN_NOT_YET_VALID")


class InvalidIssuerError(JWTSecurityError):
    """Belirteçteki üretici (iss) değeri beklenen IdP ile uyuşmadığında fırlatılır (CWE-287)."""
    def __init__(self, message: str = "JWT üreticisi (iss) beklenen Kimlik Sağlayıcı ile uyuşmuyor."):
        super().__init__(message, cwe_id="CWE-287", error_code="INVALID_ISSUER")


class InvalidAudienceError(JWTSecurityError):
    """Belirteçteki hedef kitle (aud) değeri bu servis ile uyuşmadığında fırlatılır (CWE-287)."""
    def __init__(self, message: str = "JWT hedef kitlesi (aud) bu servis için yetkilendirilmemiş."):
        super().__init__(message, cwe_id="CWE-287", error_code="INVALID_AUDIENCE")


class TokenRevokedError(JWTSecurityError):
    """İptal edilmiş (kara listedeki jti) bir belirteç tekrar sunulduğunda fırlatılır (CWE-294 Replay)."""
    def __init__(self, message: str = "Bu belirteç (jti) iptal edilmiştir (Kara listede kayıtlı)."):
        super().__init__(message, cwe_id="CWE-294", error_code="TOKEN_REVOKED")


class MalformedJWTError(JWTSecurityError):
    """JWT formatı 3 parçalı değilse veya bozuk Base64URL içeriyorsa fırlatılır (CWE-20)."""
    def __init__(self, message: str = "Bozuk veya geçersiz JWT formatı sunuldu."):
        super().__init__(message, cwe_id="CWE-20", error_code="MALFORMED_JWT")


# ==============================================================================
# VERİ MODELLERİ VE POLİTİKALAR (DATA MODELS & POLICIES)
# ==============================================================================

@dataclass
class JWTValidationPolicy:
    """JWT doğrulayıcı için zorunlu kılınan güvenlik politikaları."""
    # İzin verilen kriptografik algoritmalar beyaz listesi (örn. {'HS256', 'RS256'})
    allowed_algorithms: Set[str] = field(default_factory=lambda: {"HS256", "RS256"})
    # Beklenen Kimlik Üreticisi (Issuer)
    expected_issuer: Optional[str] = None
    # Beklenen Hedef Kitle (Audience)
    expected_audience: Optional[str] = None
    # Saat kayması (clock skew) toleransı saniye cinsinden (standart 5 saniye)
    leeway_seconds: int = 5
    # 'alg: none' saldırısını koşulsuz engelleme bayrağı
    reject_none_algorithm: bool = True


# ==============================================================================
# BASE64URL VE DÖNÜŞÜM YARDIMCILARI (RFC 7515)
# ==============================================================================

class Base64URL:
    """RFC 7515 standardına uygun URL-safe Base64 dönüştürücü."""

    @staticmethod
    def encode(data: bytes) -> str:
        """Bayt verisini Base64URL metnine dönüştürür ve sondaki '=' dolgularını temizler."""
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def decode(b64_str: str) -> bytes:
        """Eksik dolguları tamamlayarak Base64URL metnini bayt dizisine çözer."""
        clean_str = b64_str.strip()
        padding = "=" * ((4 - len(clean_str) % 4) % 4)
        try:
            return base64.urlsafe_b64decode(clean_str + padding)
        except Exception as e:
            raise MalformedJWTError(f"Base64URL çözme hatası: {e}")


# ==============================================================================
# JWT ÜRETİM MOTORU (JWT ISSUER ENGINE)
# ==============================================================================

class JWTIssuerEngine:
    """
    RFC 7519 uyumlu güvenli JWT üreteci.
    HS256 (HMAC-SHA256) ve RS256 (RSA-SHA256) algoritmalarını destekler.
    """

    @staticmethod
    def issue_token_hs256(
        claims: Dict[str, Any],
        secret_key: str,
        ttl_seconds: int = 3600,
        not_before_offset_seconds: int = 0,
        issuer: Optional[str] = "https://idp.siber.local",
        audience: Optional[str] = "siber_api_servisi"
    ) -> str:
        """
        HS256 algoritması ve simetrik gizli anahtar ile imzalı bir JWT üretir.
        
        Args:
            claims: Kullanıcıya ve yetkilere ait özel talepler sözlüğü.
            secret_key: HMAC-SHA256 gizli anahtarı.
            ttl_seconds: Belirtecin geçerlilik süresi (varsayılan 1 saat).
            not_before_offset_seconds: nbf claim'i için bekleme ofseti.
            issuer: Belirteci üreten kimlik sağlayıcı (iss).
            audience: Belirtecin hedef kitlesi (aud).
            
        Returns:
            str: Üç parçalı 'Header.Payload.Signature' JWT dizgesi.
        """
        now = datetime.now(timezone.utc)
        now_ts = int(now.timestamp())

        # Header nesnesi hazırlanır
        header = {
            "typ": "JWT",
            "alg": "HS256"
        }

        # Standart kayıtlı talepler (Registered Claims) eklenir
        payload = dict(claims)
        payload["iat"] = now_ts
        payload["exp"] = now_ts + ttl_seconds
        payload["nbf"] = now_ts + not_before_offset_seconds
        if issuer:
            payload["iss"] = issuer
        if audience:
            payload["aud"] = audience
        if "jti" not in payload:
            # Replay saldırılarına karşı benzersiz 16-baytlık belirteç kimliği
            payload["jti"] = secrets.token_hex(16)

        # 1. Parça: Header Base64URL
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        header_b64 = Base64URL.encode(header_bytes)

        # 2. Parça: Payload Base64URL
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        payload_b64 = Base64URL.encode(payload_bytes)

        # İmzalanacak veri: Header.Payload
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        # 3. Parça: HMAC-SHA256 İmzası
        signature_bytes = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        signature_b64 = Base64URL.encode(signature_bytes)

        # Üç parçalı JWT birleştirilir
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @staticmethod
    def issue_token_rs256(
        claims: Dict[str, Any],
        private_key_d: int,
        modulus_n: int,
        ttl_seconds: int = 3600,
        issuer: Optional[str] = "https://idp.siber.local",
        audience: Optional[str] = "siber_api_servisi"
    ) -> str:
        """RS256 (RSA-SHA256) algoritması ve asimetrik özel anahtar ile JWT üretir."""
        now = datetime.now(timezone.utc)
        now_ts = int(now.timestamp())

        header = {"typ": "JWT", "alg": "RS256"}
        payload = dict(claims)
        payload["iat"] = now_ts
        payload["exp"] = now_ts + ttl_seconds
        payload["nbf"] = now_ts
        if issuer:
            payload["iss"] = issuer
        if audience:
            payload["aud"] = audience
        if "jti" not in payload:
            payload["jti"] = secrets.token_hex(16)

        header_b64 = Base64URL.encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = Base64URL.encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        # SHA-256 özeti hesaplanır
        digest = hashlib.sha256(signing_input).digest()

        # Basit RSA PKCS#1 v1.5 dolgulama
        byte_len = (modulus_n.bit_length() + 7) // 8
        padding = b"\x00\x01" + (b"\xFF" * (byte_len - 3 - len(digest))) + b"\x00" + digest
        int_to_sign = int.from_bytes(padding, byteorder="big")
        sig_int = pow(int_to_sign, private_key_d, modulus_n)
        sig_bytes = sig_int.to_bytes(byte_len, byteorder="big")
        signature_b64 = Base64URL.encode(sig_bytes)

        return f"{header_b64}.{payload_b64}.{signature_b64}"


# ==============================================================================
# GÜVENLİ JWT DOĞRULAMA MOTORU (SECURE JWT VALIDATOR ENGINE)
# ==============================================================================

class JWTValidatorEngine:
    """
    Saldırılara karşı güçlendirilmiş, katı JWT Doğrulayıcı Motor.
    'alg: none', algoritma karışıklığı (RS256 vs HS256), süre aşımı,
    kimlik sınırları ve jti iptal kara listesini titizlikle denetler.
    """

    def __init__(self, policy: Optional[JWTValidationPolicy] = None):
        # Varsayılan politika atanır
        self.policy = policy or JWTValidationPolicy()
        # İptal edilmiş belirteçlerin tekil kimlik kümesi (jti Blacklist / CWE-294 Replay Savunması)
        self._revocation_store: Set[str] = set()

    def revoke_token(self, jti: str) -> None:
        """Belirteci kara listeye ekleyerek derhal geçersiz kılar (Logout / Revocation)."""
        self._revocation_store.add(jti)

    def is_token_revoked(self, jti: str) -> bool:
        """Belirtecin iptal edilip edilmediğini sorgular."""
        return jti in self._revocation_store

    def validate_token(
        self,
        jwt_str: str,
        secret_key: Optional[str] = None,
        public_key_n: Optional[int] = None,
        public_key_e: int = 65537,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Sunulan JWT dizgesini tüm güvenlik filtrelerinden geçirerek doğrular.
        
        Adımlar:
        1. 3 parçalı yapı kontrolü (Header.Payload.Signature).
        2. 'alg: none' Zafiyeti Savunması (CWE-347): alg=='none' ise anında imha edilir.
        3. Algoritma Beyaz Liste Denetimi (CWE-327): İzin verilen algoritmalar harici reddedilir.
        4. Kriptografik İmza Doğrulaması (CWE-347): Sabit zamanlı (constant-time CWE-208) kıyas.
        5. 'exp' ve 'nbf' Zaman Doğrulamaları (CWE-298 / CWE-613): Leeway toleranslı.
        6. 'iss' ve 'aud' Kimlik Sınırları Denetimi (CWE-287).
        7. 'jti' Kara Liste / İptal Denetimi (CWE-294 Replay Savunması).
        """
        if now is None:
            now = datetime.now(timezone.utc)
        now_ts = int(now.timestamp())

        # 1. Aşama: Parça Sayısı Kontrolü
        parts = jwt_str.strip().split(".")
        if len(parts) != 3:
            raise MalformedJWTError("JWT tam olarak 3 adet Base64URL parçadan oluşmalıdır.")

        header_b64, payload_b64, signature_b64 = parts

        # Header ve Payload çözülür
        try:
            header_json = json.loads(Base64URL.decode(header_b64).decode("utf-8"))
            payload_json = json.loads(Base64URL.decode(payload_b64).decode("utf-8"))
        except Exception as e:
            raise MalformedJWTError(f"JWT başlık veya yük verisi JSON olarak çözülemedi: {e}")

        alg = header_json.get("alg")

        # 2. Aşama: KRİTİK GÜVENLİK ADIMI — 'alg: none' Saldırısı Savunması (CWE-347)
        # Saldırgan başlığı {"alg": "none"} yaparak imzasız token ile girmeye çalışırsa kapıda kesilir
        if not alg or alg.lower() == "none":
            raise AlgorithmNoneAttackError("Kritik Güvenlik İhlali! 'alg: none' imzasız belirteç reddedildi.")

        # 3. Aşama: Algoritma Beyaz Liste ve Karışıklık (Confusion) Denetimi (CWE-327)
        if alg not in self.policy.allowed_algorithms:
            raise AlgorithmConfusionError(
                f"Güvenlik İhlali! Algoritma '{alg}' izin verilen {self.policy.allowed_algorithms} listesinde yok."
            )

        # İmzalanan veri: Header.Payload
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        # 4. Aşama: Kriptografik İmza Doğrulaması (CWE-347)
        if alg == "HS256":
            if not secret_key:
                raise InvalidSignatureError("HS256 doğrulaması için simetrik secret_key sağlanmalıdır.")

            # Beklenen HMAC-SHA256 imzası hesaplanır
            expected_sig_bytes = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
            expected_sig_b64 = Base64URL.encode(expected_sig_bytes)

            # Sabit zamanlı karşılaştırma (CWE-208 zamanlama yan kanalı engellemesi)
            if not secrets.compare_digest(signature_b64, expected_sig_b64):
                raise InvalidSignatureError("HMAC-SHA256 dijital imzası doğrulanamadı!")

        elif alg == "RS256":
            if not public_key_n:
                raise InvalidSignatureError("RS256 doğrulaması için asimetrik public_key_n sağlanmalıdır.")

            try:
                sig_bytes = Base64URL.decode(signature_b64)
                sig_int = int.from_bytes(sig_bytes, byteorder="big")
                decrypted_val = pow(sig_int, public_key_e, public_key_n)
                byte_len = (public_key_n.bit_length() + 7) // 8
                decrypted_bytes = decrypted_val.to_bytes(byte_len, byteorder="big")
                recovered_hash = decrypted_bytes[-32:]
                expected_hash = hashlib.sha256(signing_input).digest()

                if not secrets.compare_digest(recovered_hash, expected_hash):
                    raise InvalidSignatureError("RS256 asimetrik dijital imzası doğrulanamadı!")
            except Exception as e:
                raise InvalidSignatureError(f"RSA imza çözme hatası: {e}")

        # 5. Aşama: Zaman Doğrulamaları (exp ve nbf - CWE-298 / CWE-613)
        leeway = self.policy.leeway_seconds

        # exp (Expiration Time) Denetimi
        if "exp" in payload_json:
            exp_ts = payload_json["exp"]
            if now_ts > exp_ts + leeway:
                raise TokenExpiredError(f"Belirtecin geçerlilik süresi dolmuştur. (exp: {exp_ts}, şimdi: {now_ts})")

        # nbf (Not Before) Denetimi
        if "nbf" in payload_json:
            nbf_ts = payload_json["nbf"]
            if now_ts < nbf_ts - leeway:
                raise TokenNotYetValidError(f"Belirteç henüz geçerli değildir. (nbf: {nbf_ts}, şimdi: {now_ts})")

        # 6. Aşama: Kimlik Sınırları Denetimi (iss ve aud - CWE-287)
        if self.policy.expected_issuer and payload_json.get("iss") != self.policy.expected_issuer:
            raise InvalidIssuerError(
                f"Beklenen Issuer: '{self.policy.expected_issuer}', Gelen: '{payload_json.get('iss')}'"
            )

        if self.policy.expected_audience and payload_json.get("aud") != self.policy.expected_audience:
            raise InvalidAudienceError(
                f"Beklenen Audience: '{self.policy.expected_audience}', Gelen: '{payload_json.get('aud')}'"
            )

        # 7. Aşama: jti Kara Liste / İptal Denetimi (CWE-294 Replay Savunması)
        jti = payload_json.get("jti")
        if jti and self.is_token_revoked(jti):
            raise TokenRevokedError(f"Belirteç iptal edilmiştir (jti: {jti}).")

        # Tüm doğrulamalar başarıyla tamamlandı: Payload döndürülür
        return payload_json
