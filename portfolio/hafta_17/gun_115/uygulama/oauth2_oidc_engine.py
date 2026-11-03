# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 115: OAuth 2.0 ve OpenID Connect (OIDC) Referans Güvenlik Motoru.

Bu modül, modern dağıtık sistemlerde yetki devri (delegated authorization - OAuth 2.0)
ve federatif kimlik doğrulama (identity assertion - OpenID Connect) mimarisini
RFC 6749, RFC 7636 (PKCE) ve OIDC Core 1.0 standartlarına tam uyumlu olarak gerçekleştirir.

Kapsanan Güvenlik Açıkları ve Standartlar:
- RFC 6749: The OAuth 2.0 Authorization Framework
- RFC 7636: Proof Key for Code Exchange by OAuth Public Clients (PKCE)
- OIDC Core 1.0: OpenID Connect Core Specification (ID Token, Nonce)
- CWE-601: URL Redirection to Untrusted Site ('Open Redirector')
- CWE-352: Cross-Site Request Forgery (CSRF - state parametresi doğrulaması)
- CWE-294: Authentication Bypass by Capture-replay (Code ve Nonce tekrar kullanımı)
- CWE-287: Improper Authentication (PKCE kod yakalama savunması)
- CWE-285: Improper Authorization (Erişim belirteci kapsam/scope denetimi)
"""

# Kriptografik özetleme fonksiyonları için hashlib modülü içe aktarılır
import hashlib
# Mesaj doğrulama kodları ve sabit zamanlı kıyas için hmac modülü içe aktarılır
import hmac
# Kriptografik rastgele bayt ve güvenli dizgiler için secrets modülü içe aktarılır
import secrets
# URL-safe Base64 kodlama ve çözme işlemleri için base64 modülü içe aktarılır
import base64
# JSON veri serileştirme ve ayrıştırma için json modülü içe aktarılır
import json
# Zaman damgaları ve geçerlilik süreleri için datetime ve timezone içe aktarılır
from datetime import datetime, timezone, timedelta
# URL ayrıştırma ve parametre kontrolü için urllib.parse içe aktarılır
from urllib.parse import urlparse, parse_qs, urlencode
# Nesne yönelimli veri modelleri için dataclass ve field içe aktarılır
from dataclasses import dataclass, field, asdict
# Tip belirteçleri için typing modülü içe aktarılır
from typing import Dict, List, Optional, Set, Tuple, Any


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI (CUSTOM SECURITY EXCEPTIONS)
# ==============================================================================

class OAuthSecurityError(Exception):
    """Tüm OAuth 2.0 ve OIDC güvenlik istisnalarının temel sınıfı."""
    def __init__(self, message: str, cwe_id: str, error_code: str):
        # Üst sınıf Exception başlatıcısına hata mesajını iletir
        super().__init__(f"[{cwe_id}] {error_code}: {message}")
        # İlgili CWE zafiyet numarasını saklar
        self.cwe_id = cwe_id
        # Makine tarafından okunabilir hata kodunu saklar
        self.error_code = error_code
        # Kullanıcı dostu teknik açıklama metnini saklar
        self.message = message


class InvalidClientError(OAuthSecurityError):
    """Kayıtsız veya kimliği doğrulanamayan istemci durumunda fırlatılır (CWE-287)."""
    def __init__(self, message: str = "Geçersiz istemci kimliği veya gizli anahtarı."):
        super().__init__(message, cwe_id="CWE-287", error_code="INVALID_CLIENT")


class InvalidRedirectURIError(OAuthSecurityError):
    """Kayıtlı beyaz listede (whitelist) yer almayan yönlendirme adresi sunulduğunda fırlatılır (CWE-601)."""
    def __init__(self, message: str = "Yönlendirme adresi (redirect_uri) kayıtlı beyaz listede yer almamaktadır."):
        super().__init__(message, cwe_id="CWE-601", error_code="UNAUTHORIZED_REDIRECT_URI")


class PKCEVerificationFailedError(OAuthSecurityError):
    """PKCE code_verifier ve code_challenge doğrulaması başarısız olduğunda fırlatılır (CWE-287)."""
    def __init__(self, message: str = "PKCE doğrulaması başarısız! code_verifier özeti code_challenge ile eşleşmiyor."):
        super().__init__(message, cwe_id="CWE-287", error_code="PKCE_VERIFICATION_FAILED")


class AuthorizationCodeExpiredOrUsedError(OAuthSecurityError):
    """Yetkilendirme kodunun süresi dolduğunda veya tekrar kullanıldığında fırlatılır (CWE-294 Replay)."""
    def __init__(self, message: str = "Yetkilendirme kodu (auth_code) geçersiz, süresi dolmuş veya daha önce kullanılmış."):
        super().__init__(message, cwe_id="CWE-294", error_code="INVALID_OR_REUSED_CODE")


class StateMismatchCSRFError(OAuthSecurityError):
    """İstemci tarafında state parametresi uyuşmadığında fırlatılır (CWE-352 CSRF Saldırısı)."""
    def __init__(self, message: str = "OAuth state parametresi uyuşmazlığı tespit edildi! CSRF saldırısı engellendi."):
        super().__init__(message, cwe_id="CWE-352", error_code="CSRF_STATE_MISMATCH")


class OIDCNonceMismatchError(OAuthSecurityError):
    """ID Token içindeki nonce değeri yetkilendirme isteğindekiyle eşleşmediğinde fırlatılır (CWE-294)."""
    def __init__(self, message: str = "ID Token içindeki nonce değeri istemcinin gönderdiği ile eşleşmiyor (Replay koruması)."):
        super().__init__(message, cwe_id="CWE-294", error_code="OIDC_NONCE_MISMATCH")


class InsufficientScopeError(OAuthSecurityError):
    """Erişim belirtecinin talep edilen işlem için gerekli kapsama (scope) sahip olmaması durumu (CWE-285)."""
    def __init__(self, message: str = "Erişim belirteci bu işlem için gereken kapsama (scope) sahip değildir."):
        super().__init__(message, cwe_id="CWE-285", error_code="INSUFFICIENT_SCOPE")


class InvalidAccessTokenError(OAuthSecurityError):
    """Erişim belirtecinin geçersiz veya süresi dolmuş olması durumu (CWE-287)."""
    def __init__(self, message: str = "Sunulan erişim belirteci (access_token) geçersiz veya süresi dolmuştur."):
        super().__init__(message, cwe_id="CWE-287", error_code="INVALID_ACCESS_TOKEN")


# ==============================================================================
# VERİ MODELLERİ (DATA MODELS)
# ==============================================================================

@dataclass
class OAuthClient:
    """Yetkilendirme Sunucusuna kayıtlı istemci uygulamanın konfigürasyonu."""
    # İstemcinin benzersiz kimliği (örn. 'portal_spa_app_01')
    client_id: str
    # Gizli istemciler (confidential clients) için parola; genel istemcilerde (public SPA) None olabilir
    client_secret: Optional[str]
    # İstemcinin yönlendirilebileceği izin verilen kesin beyaz liste adresleri
    redirect_uris: List[str]
    # İstemcinin talep etmesine izin verilen kapsamlar kümesi
    allowed_scopes: Set[str]
    # İstemci türü ('confidential' veya 'public')
    client_type: str = "confidential"


@dataclass
class AuthorizationCodeEntry:
    """Üretilen tek kullanımlık yetkilendirme kodunun durum ve bağlam bilgileri."""
    # Tek kullanımlık 32-baytlık rastgele yetkilendirme kodu
    code: str
    # Kodu talep eden istemci kimliği
    client_id: str
    # İstekte kullanılan yönlendirme adresi
    redirect_uri: str
    # Onaylanan yetki kapsamı
    scope: str
    # Giriş yapan kullanıcının kimliği (subject)
    username: str
    # RFC 7636 PKCE code_challenge değeri
    code_challenge: str
    # PKCE yöntemi (daima 'S256' zorunlu kılınmalıdır)
    code_challenge_method: str
    # Varsa OpenID Connect tek kullanımlık nonce değeri
    nonce: Optional[str]
    # Kodun geçerlilik sonu (standart 60 saniye)
    expires_at: datetime
    # Kodun tüketilip tüketilmediği bayrağı (Replay CWE-294 savunması)
    is_used: bool = False


@dataclass
class AccessTokenEntry:
    """Aktif erişim belirtecinin (Access Token) yetki ve süre bilgileri."""
    # 32-baytlık rastgele erişim belirteci dizgisi
    token_str: str
    # Belirtecin sahibi olan istemci kimliği
    client_id: str
    # Belirtecin temsil ettiği kullanıcı adı
    username: str
    # Belirtece atanmış yetki kapsamları kümesi
    scopes: Set[str]
    # Belirtecin son kullanma zamanı (UTC)
    expires_at: datetime
    # Belirtecin iptal durumu
    is_revoked: bool = False


# ==============================================================================
# PKCE VE JWT YARDIMCI İŞLEVLERİ (RFC 7636 & RFC 7519)
# ==============================================================================

class PKCEHelper:
    """RFC 7636 Proof Key for Code Exchange (PKCE) hesaplama ve doğrulama araçları."""

    @staticmethod
    def generate_code_verifier(length: int = 64) -> str:
        """Kriptografik güvenli, yüksek entropili rastgele bir code_verifier dizisi üretir."""
        # RFC 7636: unreserved karakterler [A-Z, a-z, 0-9, -, ., _, ~]
        # secrets.token_urlsafe güvenli bir karakter kümesi üretir
        raw = secrets.token_urlsafe(length)
        return raw[:length]

    @staticmethod
    def compute_code_challenge_s256(code_verifier: str) -> str:
        """code_verifier dizisinin SHA-256 özetini alıp Base64URL kodlamasıyla döndürür."""
        # 1. code_verifier UTF-8 bayt dizisine çevrilir
        verifier_bytes = code_verifier.encode("utf-8")
        # 2. SHA-256 özeti hesaplanır
        digest = hashlib.sha256(verifier_bytes).digest()
        # 3. Base64URL kodlaması yapılır ve dolgu '=' karakterleri temizlenir
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return challenge

    @staticmethod
    def verify_pkce(code_verifier: str, stored_code_challenge: str, method: str = "S256") -> bool:
        """Sunulan code_verifier ile kayıtlı code_challenge'ı sabit zamanlı karşılaştırır."""
        # Sadece S256 yöntemi kabul edilir ('plain' güvensiz olduğu için reddedilir)
        if method != "S256":
            return False
        computed_challenge = PKCEHelper.compute_code_challenge_s256(code_verifier)
        # CWE-208 zamanlama yan kanalına karşı sabit zamanlı özet karşılaştırması
        return secrets.compare_digest(computed_challenge, stored_code_challenge)


class JWTHelper:
    """OpenID Connect ID Token'ları için saf Python HMAC-SHA256 JWT kodlayıcı ve doğrulayıcı."""

    @staticmethod
    def encode_jwt(payload: Dict[str, Any], secret_key: str) -> str:
        """Payload sözlüğünü HS256 algoritmasıyla imzalayarak JWT formatında döndürür."""
        header = {"typ": "JWT", "alg": "HS256"}
        # Başlık ve gövde JSON olarak serileştirilip Base64URL kodlanır
        header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
        # İmzalanacak mesaj: Header.Payload
        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        # HMAC-SHA256 imzası hesaplanır
        signature = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        # Üç parçalı JWT dizgesi oluşturulur
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @staticmethod
    def decode_and_verify_jwt(jwt_str: str, secret_key: str) -> Dict[str, Any]:
        """JWT imzasını doğrular ve payload sözlüğünü döndürür."""
        parts = jwt_str.split(".")
        if len(parts) != 3:
            raise OAuthSecurityError("Geçersiz JWT formatı.", "CWE-287", "MALFORMED_JWT")
        header_b64, payload_b64, signature_b64 = parts

        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode("ascii").rstrip("=")

        # Sabit zamanlı imza kontrolü (CWE-208)
        if not secrets.compare_digest(signature_b64, expected_sig_b64):
            raise OAuthSecurityError("JWT imzası doğrulanamadı (Sahtecilik tespit edildi).", "CWE-347", "INVALID_JWT_SIGNATURE")

        # Payload JSON verisi çözülür
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(payload_bytes.decode("utf-8"))


# ==============================================================================
# YETKİLENDİRME VE KİMLİK SUNUCUSU (AUTHORIZATION SERVER / IdP)
# ==============================================================================

class OAuth2AuthorizationServer:
    """
    OAuth 2.0 Yetkilendirme Sunucusu ve OpenID Connect Sağlayıcısı (IdP).
    /authorize ve /token uç noktalarını, PKCE zorunluluğunu ve
    yönlendirme adresi beyaz liste (CWE-601) kontrollerini yönetir.
    """

    def __init__(self, issuer_url: str = "https://idp.siber.local", token_secret: str = "GizliAnahtarIdP2026!HS256"):
        # Kimlik Sağlayıcının (Issuer) resmi URL adresi
        self.issuer_url = issuer_url
        # ID Token imzalamada kullanılan sunucu gizli anahtarı
        self.token_secret = token_secret
        # Kayıtlı istemciler deposu (client_id -> OAuthClient)
        self._clients: Dict[str, OAuthClient] = {}
        # Aktif yetkilendirme kodları deposu (code -> AuthorizationCodeEntry)
        self._auth_codes: Dict[str, AuthorizationCodeEntry] = {}
        # Aktif erişim belirteçleri deposu (token_str -> AccessTokenEntry)
        self._access_tokens: Dict[str, AccessTokenEntry] = {}

    def register_client(
        self,
        client_id: str,
        client_secret: Optional[str],
        redirect_uris: List[str],
        allowed_scopes: List[str],
        client_type: str = "confidential"
    ) -> OAuthClient:
        """Sisteme yeni bir OAuth/OIDC istemcisi kaydeder."""
        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=list(redirect_uris),
            allowed_scopes=set(allowed_scopes),
            client_type=client_type
        )
        self._clients[client_id] = client
        return client

    def authorize_endpoint(
        self,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        nonce: Optional[str] = None,
        authenticated_user: str = "seydi_kullanici",
        now: Optional[datetime] = None
    ) -> str:
        """
        /authorize Uç Noktası:
        1. İstemci varlığı denetlenir.
        2. redirect_uri katı beyaz liste denetiminden geçer (CWE-601 Open Redirector Savunması).
        3. PKCE code_challenge zorunlu tutulur (OAuth 2.1 Güvenlik Standardı - CWE-287).
        4. Tek kullanımlık authorization_code üretilir ve geri dönüş URL'i döndürülür.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # 1. İstemci Doğrulaması
        if client_id not in self._clients:
            raise InvalidClientError(f"Bilinmeyen istemci kimliği: {client_id}")

        client = self._clients[client_id]

        # 2. KRİTİK GÜVENLİK ADIMI: Açık Yönlendirici (Open Redirector - CWE-601) Savunması
        # redirect_uri istemcinin önceden kayıtlı beyaz listesinde birebir yer almalıdır
        if redirect_uri not in client.redirect_uris:
            raise InvalidRedirectURIError(
                f"Güvenlik İhlali! Yönlendirme adresi '{redirect_uri}' kayıtlı listede bulunamadı."
            )

        # 3. response_type kontrolü (Sadece 'code' yetkilendirme kodu akışı desteklenir)
        if response_type != "code":
            raise OAuthSecurityError("Sadece 'code' response_type desteklenmektedir.", "CWE-287", "UNSUPPORTED_RESPONSE_TYPE")

        # 4. PKCE Doğrulaması: code_challenge zorunlu olmalıdır (RFC 7636)
        if not code_challenge or code_challenge_method != "S256":
            raise PKCEVerificationFailedError("PKCE zorunludur! 'S256' code_challenge parametresi eksik.")

        # 5. Kapsam (Scope) doğrulama
        requested_scopes = set(scope.split())
        if not requested_scopes.issubset(client.allowed_scopes):
            raise InsufficientScopeError("Talep edilen kapsamlar istemcinin izin verilen sınırlarını aşıyor.")

        # 6. Tek kullanımlık 32-baytlık URL-safe yetkilendirme kodu üretilir
        auth_code = secrets.token_urlsafe(32)
        # Kodun ömrü kısa tutulur (60 saniye)
        expires_at = now + timedelta(seconds=60)

        entry = AuthorizationCodeEntry(
            code=auth_code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            username=authenticated_user,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            expires_at=expires_at,
            is_used=False
        )

        self._auth_codes[auth_code] = entry

        # İstemcinin redirect_uri adresine code ve state eklenerek yönlendirme adresi oluşturulur
        callback_params = {"code": auth_code, "state": state}
        delimiter = "&" if "?" in redirect_uri else "?"
        callback_url = f"{redirect_uri}{delimiter}{urlencode(callback_params)}"
        return callback_url

    def token_endpoint(
        self,
        grant_type: str,
        client_id: str,
        client_secret: Optional[str],
        code: str,
        redirect_uri: str,
        code_verifier: str,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        /token Uç Noktası:
        1. grant_type == 'authorization_code' kontrolü.
        2. İstemci kimlik doğrulaması (Confidential client ise secret denetimi).
        3. authorization_code geçerlilik, tek kullanım (CWE-294) ve süre kontrolü.
        4. PKCE doğrulaması: verify_pkce(code_verifier, code_challenge) (CWE-287).
        5. Access Token ve OIDC ID Token üretimi.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        if grant_type != "authorization_code":
            raise OAuthSecurityError("Desteklenmeyen grant_type.", "CWE-287", "UNSUPPORTED_GRANT_TYPE")

        # İstemci doğrulaması
        if client_id not in self._clients:
            raise InvalidClientError("İstemci bulunamadı.")

        client = self._clients[client_id]

        # Gizli istemci ise parola kontrol edilir
        if client.client_type == "confidential":
            if not client_secret or not secrets.compare_digest(client_secret, client.client_secret or ""):
                raise InvalidClientError("İstemci gizli anahtarı hatalı.")

        # Yetkilendirme kodu sistemde var mı?
        if code not in self._auth_codes:
            raise AuthorizationCodeExpiredOrUsedError("Yetkilendirme kodu bulunamadı.")

        code_entry = self._auth_codes[code]

        # Kod daha önce kullanılmış mı? (CWE-294 Replay Saldırısı Savunması)
        if code_entry.is_used:
            raise AuthorizationCodeExpiredOrUsedError("Bu yetkilendirme kodu daha önce kullanılmıştır!")

        # Kodun süresi dolmuş mu?
        if now > code_entry.expires_at:
            raise AuthorizationCodeExpiredOrUsedError("Yetkilendirme kodunun geçerlilik süresi dolmuştur.")

        # İstemci ve redirect_uri istekle eşleşiyor mu?
        if code_entry.client_id != client_id or code_entry.redirect_uri != redirect_uri:
            raise OAuthSecurityError("İstemci veya yönlendirme adresi eşleşmiyor.", "CWE-287", "CLIENT_MISMATCH")

        # KRİTİK GÜVENLİK ADIMI: PKCE Doğrulaması (CWE-287 Kod Yakalama Saldırısı Savunması)
        # Saldırgan authorization_code'u yakalasa dahi, istemcinin hafızasındaki code_verifier'a sahip olamaz!
        if not PKCEHelper.verify_pkce(code_verifier, code_entry.code_challenge, code_entry.code_challenge_method):
            raise PKCEVerificationFailedError("Sunulan code_verifier ile code_challenge uyuşmuyor!")

        # Kod başarıyla doğrulandı: Derhal 'kullanıldı' olarak işaretlenir (Tek Kullanımlık)
        code_entry.is_used = True

        # Erişim Belirteci (Access Token) üretimi (3600 saniye = 1 saat)
        access_token_str = secrets.token_urlsafe(32)
        token_expires_at = now + timedelta(seconds=3600)
        scopes_set = set(code_entry.scope.split())

        token_entry = AccessTokenEntry(
            token_str=access_token_str,
            client_id=client_id,
            username=code_entry.username,
            scopes=scopes_set,
            expires_at=token_expires_at,
            is_revoked=False
        )
        self._access_tokens[access_token_str] = token_entry

        response_data: Dict[str, Any] = {
            "access_token": access_token_str,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": code_entry.scope
        }

        # Eğer talep edilen kapsamlar içinde 'openid' varsa, OIDC ID Token üretilir
        if "openid" in scopes_set:
            id_token_payload = {
                "iss": self.issuer_url,
                "sub": code_entry.username,
                "aud": client_id,
                "exp": int((now + timedelta(seconds=3600)).timestamp()),
                "iat": int(now.timestamp()),
                "auth_time": int(now.timestamp())
            }
            # Eğer istekte nonce varsa, replay koruması için ID Token'a eklenir
            if code_entry.nonce:
                id_token_payload["nonce"] = code_entry.nonce

            id_token_jwt = JWTHelper.encode_jwt(id_token_payload, self.token_secret)
            response_data["id_token"] = id_token_jwt

        return response_data

    def validate_access_token(self, token_str: str, required_scope: str, now: Optional[datetime] = None) -> AccessTokenEntry:
        """Kaynak Sunucusu için erişim belirteci geçerlilik ve kapsam denetimi."""
        if now is None:
            now = datetime.now(timezone.utc)

        if not token_str or token_str not in self._access_tokens:
            raise InvalidAccessTokenError("Erişim belirteci geçersiz veya bulunamadı.")

        entry = self._access_tokens[token_str]

        if entry.is_revoked:
            raise InvalidAccessTokenError("Erişim belirteci iptal edilmiş.")

        if now > entry.expires_at:
            raise InvalidAccessTokenError("Erişim belirtecinin süresi dolmuş.")

        # Kapsam (Scope) denetimi (CWE-285)
        if required_scope not in entry.scopes:
            raise InsufficientScopeError(f"Bu kaynağa erişim için '{required_scope}' kapsamı zorunludur.")

        return entry


# ==============================================================================
# KAYNAK SUNUCUSU (RESOURCE SERVER - KORUMALI API)
# ==============================================================================

class OAuth2ResourceServer:
    """OAuth 2.0 Erişim Belirteci ile korunan API uç noktaları."""

    def __init__(self, auth_server: OAuth2AuthorizationServer):
        self.auth_server = auth_server

    def get_user_profile(self, authorization_header: str) -> Dict[str, Any]:
        """Kullanıcı profil verisini döner ('read:profile' veya 'openid' kapsamı gerektirir)."""
        token_str = self._extract_bearer_token(authorization_header)
        token_entry = self.auth_server.validate_access_token(token_str, required_scope="read:profile")
        return {
            "durum": "ONAYLANDI",
            "kullanici": token_entry.username,
            "eposta": f"{token_entry.username}@siber.local",
            "kapsamlar": list(token_entry.scopes)
        }

    def get_confidential_reports(self, authorization_header: str) -> Dict[str, Any]:
        """Gizli raporları döner ('read:reports' kapsamı gerektirir)."""
        token_str = self._extract_bearer_token(authorization_header)
        token_entry = self.auth_server.validate_access_token(token_str, required_scope="read:reports")
        return {
            "durum": "ONAYLANDI",
            "rapor_id": "RAPOR_2026_Q4",
            "icerik": "Mali denetim ve risk analizi tamamlandı."
        }

    @staticmethod
    def _extract_bearer_token(auth_header: str) -> str:
        """HTTP Authorization başlığından Bearer belirtecini ayıklar."""
        if not auth_header or not auth_header.startswith("Bearer "):
            raise InvalidAccessTokenError("Eksik veya geçersiz Authorization Bearer başlığı.")
        return auth_header[7:].strip()


# ==============================================================================
# İSTEMCİ / GÜVENEN TARAF DOĞRULAYICI (OIDC CLIENT / RELYING PARTY)
# ==============================================================================

class OIDCClientRelyingParty:
    """
    İstemci tarafında çalışan, CSRF state kontrolünü ve
    OIDC ID Token doğrulamasını (nonce, iss, aud, exp) yürüten bileşen.
    """

    def __init__(self, client_id: str, expected_issuer: str, idp_secret: str):
        self.client_id = client_id
        self.expected_issuer = expected_issuer
        self.idp_secret = idp_secret

    def verify_callback_and_id_token(
        self,
        callback_state: str,
        original_state: str,
        id_token_jwt: str,
        original_nonce: Optional[str] = None,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        1. State parametresi doğrulanır (CWE-352 CSRF Savunması).
        2. ID Token JWT imzası doğrulanır.
        3. 'iss' (Issuer) ve 'aud' (Audience) doğrulanır.
        4. 'nonce' parametresi doğrulanır (CWE-294 Replay Savunması).
        5. 'exp' (Zaman aşımı) doğrulanır.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # 1. CSRF Savunması: state kontrolü
        if not secrets.compare_digest(callback_state, original_state):
            raise StateMismatchCSRFError("state parametresi uyuşmuyor! Muhtemel CSRF saldırısı.")

        # 2. JWT İmzası Çözülür ve Doğrulanır
        payload = JWTHelper.decode_and_verify_jwt(id_token_jwt, self.idp_secret)

        # 3. Issuer ve Audience Kontrolü
        if payload.get("iss") != self.expected_issuer:
            raise OAuthSecurityError("ID Token geçersiz bir Issuer tarafından üretilmiş.", "CWE-287", "INVALID_ISSUER")
        if payload.get("aud") != self.client_id:
            raise OAuthSecurityError("ID Token bu istemci için üretilmemiş.", "CWE-287", "INVALID_AUDIENCE")

        # 4. Nonce Replay Savunması (CWE-294)
        if original_nonce:
            token_nonce = payload.get("nonce")
            if not token_nonce or not secrets.compare_digest(token_nonce, original_nonce):
                raise OIDCNonceMismatchError("ID Token içindeki nonce değeri istemci ile uyuşmuyor.")

        # 5. Zaman Aşımı Kontrolü
        exp_ts = payload.get("exp", 0)
        if now.timestamp() > exp_ts:
            raise OAuthSecurityError("ID Token süresi dolmuş.", "CWE-613", "EXPIRED_ID_TOKEN")

        return payload
