# -*- coding: utf-8 -*-
"""
Gün 164: CSRF ve Oturum Bağlamı Savunma Motoru (csrf_engine.py)

Bu modül; Siteler Arası İstek Sahteciliği (Cross-Site Request Forgery - CSRF / CWE-352)
tehditlerini, tarayıcıların ortam yetkisi (ambient authority) mekanizmalarını,
oturum bağlamı denetimlerini (Synchronizer Token Pattern, Double Submit Cookie,
SameSite çerez ilkeleri, Origin/Referer doğrulaması ve Step-up Re-authentication)
kurumsal düzeyde modelleyen ve denetleyen tam teşekküllü savunma motorudur.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri içe aktarılır
import hmac  # Kriptografik mesaj doğrulama kodu (HMAC) hesaplamak için
import hashlib  # Güvenli özetleme fonksiyonları (SHA-256) için
import secrets  # Kriptografik güvenli sözde rastgele sayı ve belirteç üretimi için
import time  # Zaman damgası ve süre aşımı (TTL) doğrulaması için
import json  # JSON serileştirme ve veri yapıları yönetimi için
import urllib.parse  # URL ayrıştırma, köken (origin) ve referer çözümleme için
from enum import Enum  # Sabit durum sınıfları oluşturmak için
from typing import Dict, Any, List, Optional, Tuple, Set  # Tip ipuçları için
from dataclasses import dataclass, field  # Veri sınıfları tanımlamak için


class SameSiteMode(str, Enum):
    """HTTP çerez SameSite öznitelik modlarını belirten numaralandırma."""
    STRICT = "Strict"  # Çerez yalnızca birinci taraf (same-site) bağlamda iletilir
    LAX = "Lax"  # Üst düzey güvenli GET gezintileri hariç üçüncü taraf isteklerde engellenir
    NONE = "None"  # Çerez tüm siteler arası isteklerde iletilir (Secure şarttır)


class HTTPMethod(str, Enum):
    """HTTP istek yöntemlerini temsil eden numaralandırma."""
    GET = "GET"  # Güvenli / Durum değiştirmemesi gereken okuma yöntemi
    POST = "POST"  # Durum değiştiren veri gönderme yöntemi
    PUT = "PUT"  # Kaynak güncelleme yöntemi
    DELETE = "DELETE"  # Kaynak silme yöntemi
    PATCH = "PATCH"  # Kısmi güncelleme yöntemi
    HEAD = "HEAD"  # Üstveri sorgulama yöntemi
    OPTIONS = "OPTIONS"  # CORS ön kontrol yöntemi


class CSRFStrategy(str, Enum):
    """Uygulanan anti-CSRF koruma stratejisini belirten numaralandırma."""
    SYNCHRONIZER_TOKEN = "Synchronizer_Token_Pattern"  # Oturumla eşleşen sunucu saklı gizli belirteç
    DOUBLE_SUBMIT_COOKIE = "Double_Submit_Cookie"  # Çerez ve istek gövdesi çift gönderim doğrulaması
    ORIGIN_REFERER_CHECK = "Origin_Referer_Verification"  # HTTP köken başlığı denetimi
    STEP_UP_REAUTH = "Step_Up_Reauthentication"  # Kritik işlemler için yeniden kimlik doğrulama


@dataclass
class HTTPRequest:
    """Gelen HTTP isteğini simüle eden veri yapısı."""
    method: str  # İstek yöntemi (GET, POST vb.)
    path: str  # İstek yolu (/api/transfer vb.)
    headers: Dict[str, str] = field(default_factory=dict)  # İstek başlıkları
    cookies: Dict[str, str] = field(default_factory=dict)  # Tarayıcı tarafından iletilen çerezler
    form_data: Dict[str, Any] = field(default_factory=dict)  # Form gövdesi verileri
    json_body: Dict[str, Any] = field(default_factory=dict)  # JSON gövdesi verileri
    client_ip: str = "127.0.0.1"  # İstemci IP adresi


@dataclass
class UserSession:
    """Kimliği doğrulanmış kullanıcı oturumunu temsil eden veri yapısı."""
    session_id: str  # Kriptografik rastgele oturum kimliği
    user_id: int  # Kullanıcı veritabanı ID'si
    username: str  # Kullanıcı adı
    csrf_secret: str  # Oturuma özel anti-CSRF tohumu (HMAC anahtarı)
    created_at: float  # Oturum başlangıç zamanı (saniye)
    expires_at: float  # Oturum bitiş zamanı (saniye)
    last_reauth_at: float  # Son başarılı şifreli yeniden doğrulama zamanı
    is_authenticated: bool = True  # Oturumun geçerlilik durumu


class AntiCSRFTokenManager:
    """Kriptografik olarak güvenli Anti-CSRF belirteçleri üreten ve doğrulayan yönetici."""

    def __init__(self, master_secret: Optional[str] = None, token_ttl_seconds: int = 1800):
        # Eğer ana sır verilmemişse 256-bit CSPRNG rastgele anahtar üretilir
        self.master_secret: str = master_secret or secrets.token_hex(32)
        # Belirteç geçerlilik süresi (varsayılan: 30 dakika / 1800 saniye)
        self.token_ttl: int = token_ttl_seconds
        # Kullanılmış tek kullanımlık belirteçler (nonce) takip kümesi (Replay önleme)
        self.used_nonces: Set[str] = set()

    def generate_token(self, session: UserSession) -> str:
        """
        Oturum bağlamına zincirlenmiş kriptografik anti-CSRF belirteci üretir.
        Format: <session_id>.<timestamp>.<nonce>.<hmac_signature>
        """
        # Anlık zaman damgası tamsayı olarak alınır
        current_ts = int(time.time())
        # 128-bit rastgele tek kullanımlık değer (nonce) üretilir
        nonce = secrets.token_hex(16)
        # İmzalanacak veri bloğu oluşturulur
        raw_payload = f"{session.session_id}:{session.csrf_secret}:{current_ts}:{nonce}"
        # Oturum sırrı ve master anahtar birleştirilerek HMAC anahtarı elde edilir
        signing_key = f"{self.master_secret}:{session.csrf_secret}".encode("utf-8")
        # SHA-256 algoritmasıyla kriptografik imza hesaplanır
        signature = hmac.new(signing_key, raw_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        # Birleşik belirteç dizesi döndürülür
        return f"{session.session_id}.{current_ts}.{nonce}.{signature}"

    def validate_token(self, token: str, session: UserSession, consume: bool = True) -> Tuple[bool, str]:
        """
        Gelen anti-CSRF belirtecini oturum bağlamına göre doğrular ve replay koruması uygular.
        """
        # Belirtecin boş veya dize olmadığı durumlar reddedilir
        if not token or not isinstance(token, str):
            return False, "Eksik veya geçersiz CSRF belirteç tipi."

        # Noktadan parçalama işlemi yapılır
        parts = token.split(".")
        # 4 bileşenin eksiksiz olduğu kontrol edilir
        if len(parts) != 4:
            return False, "Bozuk CSRF belirteç formatı. (Beklenen: 4 bileşenli yapı)"

        token_sid, token_ts_str, nonce, signature = parts  # Bileşenler ayrıştırılır

        # 1. Oturum kimliği uyuşmazlığı kontrolü (Başka oturumun belirteci kullanılamaz)
        if not hmac.compare_digest(token_sid, session.session_id):
            return False, "Belirteç oturum kimliği ile mevcut oturum kimliği uyuşmuyor."

        # Zaman damgası sayısal değere dönüştürülür
        try:
            token_ts = int(token_ts_str)
        except ValueError:
            return False, "Geçersiz belirteç zaman damgası."

        current_ts = int(time.time())  # Anlık zaman
        # 2. Süre aşımı (TTL) kontrolü yapılır
        if current_ts - token_ts > self.token_ttl:
            return False, f"CSRF belirtecinin süresi dolmuş. ({current_ts - token_ts}s > {self.token_ttl}s)"

        # 3. İleri tarihli hileli zaman damgaları reddedilir (Saat kayması toleransı: 60 saniye)
        if token_ts > current_ts + 60:
            return False, "İleri tarihli manipüle edilmiş belirteç zaman damgası."

        # 4. Tek kullanımlık nonce (Replay saldırısı) denetimi
        if nonce in self.used_nonces:
            return False, "CSRF belirteci daha önce kullanılmış. (Yeniden oynatma saldırısı)"

        # 5. Kriptografik imza doğrulaması (Sabit zamanlı karşılaştırma ile)
        raw_payload = f"{session.session_id}:{session.csrf_secret}:{token_ts}:{nonce}"
        signing_key = f"{self.master_secret}:{session.csrf_secret}".encode("utf-8")
        expected_sig = hmac.new(signing_key, raw_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return False, "Geçersiz CSRF belirteç imzası. (Veri tahrifatı algılandı)"

        # İsteğe bağlı olarak tek kullanım için nonce kaydedilir
        if consume:
            self.used_nonces.add(nonce)

        return True, "CSRF belirteci başarıyla doğrulandı."


class OriginRefererValidator:
    """HTTP Origin ve Referer başlıklarını kurumsal beyaz listeye göre doğrulayan bileşen."""

    def __init__(self, allowed_origins: List[str]):
        # İzin verilen kökenler küçük harfe çevrilerek normalize edilir
        self.allowed_origins: Set[str] = {o.lower().rstrip("/") for o in allowed_origins}

    def validate_request_origin(self, request: HTTPRequest) -> Tuple[bool, str]:
        """
        Gelen istekteki Origin veya Referer başlığını katı köken kurallarına göre inceler.
        """
        # Başlıklar küçük harfe normalize edilmiş sözlükten aranır
        headers_normalized = {k.lower(): v for k, v in request.headers.items()}
        origin_val = headers_normalized.get("origin")  # Origin başlığı
        referer_val = headers_normalized.get("referer")  # Referer başlığı

        # 1. Eğer Origin başlığı mevcutsa öncelikle o denetlenir
        if origin_val is not None:
            # null origin (iframe sandbox veya veri URI'leri saldırganlarca kullanılır) reddedilir
            if origin_val.strip().lower() == "null":
                return False, "Güvensiz 'null' Origin başlığı reddedildi."

            normalized_origin = origin_val.strip().lower().rstrip("/")
            if normalized_origin in self.allowed_origins:
                return True, f"Origin başarıyla doğrulandı: {normalized_origin}"
            else:
                return False, f"İzin verilmeyen yabancı köken (Cross-Origin): '{normalized_origin}'"

        # 2. Origin yoksa (eski tarayıcılar veya bazı POST'lar) Referer denetlenir
        if referer_val is not None:
            parsed = urllib.parse.urlparse(referer_val)
            if not parsed.scheme or not parsed.netloc:
                return False, "Geçersiz veya bozuk Referer URL'si."

            # Şema ve host:port birleştirilerek referer kökeni elde edilir
            extracted_origin = f"{parsed.scheme}://{parsed.netloc}".lower().rstrip("/")
            if extracted_origin in self.allowed_origins:
                return True, f"Referer kökeni başarıyla doğrulandı: {extracted_origin}"
            else:
                return False, f"İzin verilmeyen yabancı Referer: '{extracted_origin}'"

        # 3. Her iki başlık da yoksa siteler arası istek şüphesiyle reddedilir
        return False, "Eksik köken bilgisi: İstekte ne 'Origin' ne de 'Referer' başlığı mevcut."


class CSRFDefenseEngine:
    """
    Merkezi CSRF Savunma Motoru:
    Zafiyetli ve güvenli bankacılık transfer uç noktalarını simüle ederek
    saldırıların nasıl gerçekleştiğini ve katmanlı kontrollerle nasıl önlendiğini gösterir.
    """

    def __init__(self, enterprise_origin: str = "https://banka.kurum.internal"):
        self.enterprise_origin: str = enterprise_origin  # Kurumsal meşru köken
        self.token_manager = AntiCSRFTokenManager()  # Belirteç yöneticisi
        self.origin_validator = OriginRefererValidator(allowed_origins=[enterprise_origin])  # Köken denetleyicisi
        
        # Test için sanal oturum veritabanı
        self.sessions: Dict[str, UserSession] = {}
        # Sanal bankacılık bakiye defteri (User ID -> Bakiye TL)
        self.accounts: Dict[int, float] = {
            1: 50000.0,  # Yönetici hesabı
            2: 15000.0,  # Meşru kurban (Ahmet Kaya)
            3: 100.0     # Saldırgan hesabı (Attacker Bob)
        }
        # Yapılan transferlerin kayıt defteri
        self.transfer_log: List[Dict[str, Any]] = []

    def create_mock_session(self, user_id: int, username: str) -> UserSession:
        """Yeni bir kullanıcı oturumu başlatır ve sanal depoya kaydeder."""
        session_id = f"sess_{secrets.token_hex(16)}"  # Güvenli oturum ID
        csrf_secret = secrets.token_hex(24)  # Oturuma özel anti-CSRF tohumu
        now = time.time()  # Anlık zaman
        session = UserSession(
            session_id=session_id,
            user_id=user_id,
            username=username,
            csrf_secret=csrf_secret,
            created_at=now,
            expires_at=now + 3600,  # 1 saat oturum süresi
            last_reauth_at=now,  # Yeni açıldığı için re-auth güncel
            is_authenticated=True
        )
        self.sessions[session_id] = session  # Depoya eklenir
        return session  # Oturum döndürülür

    def vulnerable_transfer_funds(self, request: HTTPRequest) -> Dict[str, Any]:
        """
        ZAFİYETLİ İŞLEM:
        Yalnızca çerezdeki oturum kimliğine güvenir (Ambient Authority).
        Ne Origin denetimi ne de Anti-CSRF belirteci arar!
        GET ile durum değişimine bile izin verir.
        """
        # 1. Çerezden oturum kimliği okunur
        session_id = request.cookies.get("session_id")
        session = self.sessions.get(session_id) if session_id else None

        if not session or not session.is_authenticated:
            return {
                "success": False,
                "status_code": 401,
                "error": "Kimlik doğrulama başarısız. Oturum çerezi bulunamadı."
            }

        # Hedef hesap ve miktar formdan veya query/json'dan okunur
        target_account = request.form_data.get("target_account") or request.json_body.get("target_account")
        amount = request.form_data.get("amount") or request.json_body.get("amount")

        # GET parametresiyle transferi de kabul eden devasa hata simülasyonu
        if not target_account and request.method == "GET":
            # Path üzerinden query çözümlenir
            parsed = urllib.parse.urlparse(request.path)
            q_params = urllib.parse.parse_qs(parsed.query)
            target_account = q_params.get("target_account", [None])[0]
            amount = q_params.get("amount", [None])[0]

        try:
            target_id = int(target_account)
            transfer_amount = float(amount)
        except (TypeError, ValueError):
            return {"success": False, "status_code": 400, "error": "Geçersiz hedef hesap veya miktar."}

        # Bakiye kontrolü
        sender_id = session.user_id
        if self.accounts.get(sender_id, 0.0) < transfer_amount:
            return {"success": False, "status_code": 400, "error": "Yetersiz bakiye."}

        # Bakiye aktarılır (Zafiyet gerçekleşti!)
        self.accounts[sender_id] -= transfer_amount
        self.accounts[target_id] = self.accounts.get(target_id, 0.0) + transfer_amount

        transaction = {
            "tx_id": f"tx_vuln_{secrets.token_hex(6)}",
            "from_user": sender_id,
            "to_user": target_id,
            "amount": transfer_amount,
            "method_used": request.method,
            "timestamp": time.time(),
            "vulnerability_note": "ZAFİYET: İstek hiçbir CSRF koruması olmadan Ambient Cookie ile onaylandı!"
        }
        self.transfer_log.append(transaction)
        return {"success": True, "status_code": 200, "transaction": transaction}

    def secure_transfer_funds(self, request: HTTPRequest, require_step_up: bool = False) -> Dict[str, Any]:
        """
        GÜVENLİ İŞLEM:
        Çok Katmanlı Savunma (Defense-in-Depth):
        1. Güvenli Olmayan Metot Kısıtlaması (GET ile durum değişimi YASAK).
        2. Katı Origin/Referer Doğrulaması.
        3. Kriptografik Anti-CSRF Belirteç Doğrulaması (Synchronizer Token).
        4. Kritik Miktarlar İçin Yeniden Kimlik Doğrulama (Step-Up Re-Authentication).
        """
        # 1. KONTROL: Metot kontrolü (Yalnızca POST/PUT durum değiştirebilir)
        if request.method.upper() not in ["POST", "PUT"]:
            return {
                "success": False,
                "status_code": 405,
                "error": f"Metot İzin Verilmiyor: '{request.method}'. Durum değiştiren işlemler GET ile yürütülemez."
            }

        # 2. KONTROL: Oturum kontrolü
        session_id = request.cookies.get("session_id")
        session = self.sessions.get(session_id) if session_id else None
        if not session or not session.is_authenticated:
            return {"success": False, "status_code": 401, "error": "Geçersiz veya süresi dolmuş oturum."}

        # 3. KONTROL: Origin / Referer doğrulama katmanı
        origin_ok, origin_msg = self.origin_validator.validate_request_origin(request)
        if not origin_ok:
            return {
                "success": False,
                "status_code": 403,
                "error": f"CSRF Koruması - Köken Doğrulama Hatası: {origin_msg}"
            }

        # 4. KONTROL: Anti-CSRF Token doğrulaması
        # Belirteç hem HTTP başlığından (X-CSRF-Token) hem de form gövdesinden aranır
        token_candidate = (
            request.headers.get("X-CSRF-Token")
            or request.headers.get("x-csrf-token")
            or request.form_data.get("csrf_token")
            or request.json_body.get("csrf_token")
        )

        token_ok, token_msg = self.token_manager.validate_token(token_candidate, session, consume=True)
        if not token_ok:
            return {
                "success": False,
                "status_code": 403,
                "error": f"CSRF Koruması - Belirteç Doğrulama Hatası: {token_msg}"
            }

        # Veri ayrıştırma
        target_account = request.form_data.get("target_account") or request.json_body.get("target_account")
        amount = request.form_data.get("amount") or request.json_body.get("amount")

        try:
            target_id = int(target_account)
            transfer_amount = float(amount)
        except (TypeError, ValueError):
            return {"success": False, "status_code": 400, "error": "Geçersiz hedef hesap veya miktar."}

        # 5. KONTROL: Yüksek miktarlı transferler için Step-up Kimlik Doğrulama kontrolü (Örn: >= 5000 TL)
        if require_step_up or transfer_amount >= 5000.0:
            reauth_window = 300  # 5 dakika (300 saniye)
            if time.time() - session.last_reauth_at > reauth_window:
                return {
                    "success": False,
                    "status_code": 403,
                    "error": "Kritik işlem için son 5 dakika içinde parola doğrulaması (Step-Up Re-auth) gereklidir."
                }

        # Bakiye kontrolü
        sender_id = session.user_id
        if self.accounts.get(sender_id, 0.0) < transfer_amount:
            return {"success": False, "status_code": 400, "error": "Yetersiz bakiye."}

        # Güvenli transfer yürütülür
        self.accounts[sender_id] -= transfer_amount
        self.accounts[target_id] = self.accounts.get(target_id, 0.0) + transfer_amount

        transaction = {
            "tx_id": f"tx_sec_{secrets.token_hex(6)}",
            "from_user": sender_id,
            "to_user": target_id,
            "amount": transfer_amount,
            "method_used": request.method,
            "timestamp": time.time(),
            "defense_mechanisms": [
                "Method_Enforcement_POST_ONLY",
                "Origin_Validation_MATCH",
                "Cryptographic_Synchronizer_Token_VERIFIED",
                "Step_Up_Reauth_SATISFIED"
            ]
        }
        self.transfer_log.append(transaction)
        return {"success": True, "status_code": 200, "transaction": transaction}

    def generate_cookie_header(self, session_id: str, samesite: SameSiteMode = SameSiteMode.STRICT) -> str:
        """Güvenlik bayraklarıyla donatılmış Set-Cookie başlığı üretir."""
        cookie_parts = [
            f"session_id={session_id}",
            "Path=/",
            "HttpOnly",  # XSS ile JavaScript tarafından okunamaz
            "Secure",    # Yalnızca HTTPS üzerinden iletilir
            f"SameSite={samesite.value}"  # CSRF engelleyici tarayıcı davranışı
        ]
        return "; ".join(cookie_parts)
