# -*- coding: utf-8 -*-
"""
Gün 161: Mini Proje 22 - Güvenli Form Arayüzü Motoru (secure_form_engine.py)

Bu modül; kurumsal seviyede uçtan uca güvenli bir web form arayüzü motoru sunar.
Kriptografik HMAC-SHA256 tabanlı CSRF token koruması, SameSite/HttpOnly/Secure çerez
bağlaması, katı girdi doğrulama, bağlama duyarlı çıktı kodlama, IP bazlı istek
oran sınırlama (rate limiting) ve CSP Seviye 3 başlık üretimini tek çatı altında birleştirir.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import re  # Düzenli ifadeler ile girdi deseni ve e-posta kontrolü için re modülü dahil edilir
import html  # Çıktı kodlama ve HTML varlık kaçışları için html modülü dahil edilir
import hmac  # Zamanlama saldırılarına dayanıklı kriptografik imzalama için hmac dahil edilir
import time  # Zaman damgası ve token süre aşımı kontrolleri için time modülü dahil edilir
import math  # Entropi hesaplamalarında logaritma işlemleri için math modülü dahil edilir
import hashlib  # Güvenli özetleme algoritmaları için hashlib dahil edilir
import secrets  # Kriptografik güvenli rastgele sayı ve anahtar üretimi için secrets dahil edilir
from typing import Dict, List, Optional, Tuple, Any  # Tip güvenliği için typing modülü dahil edilir


class CSRFProtectionManager:
    """HMAC-SHA256 ve zaman damgalı CSRF token üretim ve doğrulama yöneticisi."""

    def __init__(self, secret_key: Optional[str] = None, token_validity_seconds: int = 1800):
        self.secret_key: bytes = (secret_key or secrets.token_hex(32)).encode("utf-8")  # 256-bit gizli sunucu anahtarı atanır
        self.validity_seconds: int = token_validity_seconds  # Token geçerlilik süresi (varsayılan 30 dk)
        self.used_nonces: set = set()  # Tekrar oynatma saldırılarına (replay attack) karşı kullanılan nonce kümesi

    def generate_token(self, session_id: str) -> str:
        """Oturum kimliği ile kriptografik olarak bağlı tek kullanımlık CSRF tokenı üretir."""
        current_time = int(time.time())  # Güncel Unix zaman damgası alınır
        nonce = secrets.token_hex(8)  # 64-bitlik tekil rastgele nonce üretilir
        payload = f"{session_id}:{current_time}:{nonce}"  # Token gövdesi yapılandırılır
        signature = hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()  # HMAC imzası hesaplanır
        return f"{payload}:{signature}"  # Gövde ve imza iki nokta üst üste ile birleştirilir

    def validate_token(self, token: str, session_id: str) -> Tuple[bool, str]:
        """Gelen CSRF tokenının geçerliliğini, imzasını, süresini ve oturum bağını denetler."""
        if not token or not isinstance(token, str):  # Token boş veya geçersiz tipteyse
            return False, "CSRF tokenı eksik veya boş."  # Başarısızlık dönülür
            
        parts = token.split(":")  # Token bileşenlerine ayrılır
        if len(parts) != 4:  # Beklenen 4 parça (session_id, timestamp, nonce, signature) yoksa
            return False, "CSRF token biçimi geçersiz."  # Biçim hatası bildirilir
            
        t_session_id, t_timestamp_str, nonce, signature = parts  # Parçalar değişkenlere atanır
        
        # 1. Oturum kimliği uyuşmazlığı kontrolü
        if not hmac.compare_digest(t_session_id, session_id):  # Oturum uyuşmazlığı varsa
            return False, "CSRF token oturum kimliği ile eşleşmiyor."  # Hata mesajı dönülür
            
        # 2. Süre aşımı (Expiration) kontrolü
        try:  # Zaman damgası tamsayıya çevrilmeye çalışılır
            token_time = int(t_timestamp_str)  # Tamsayı zaman damgası elde edilir
        except ValueError:  # Hatalı zaman formatı durumunda
            return False, "CSRF token zaman damgası bozuk."  # Hata bildirilir
            
        current_time = int(time.time())  # Mevcut zaman alınır
        if current_time - token_time >= self.validity_seconds:  # Belirlenen süreden eskiyse veya eşitse
            return False, "CSRF tokenının süresi dolmuş."  # Süre aşımı hatası dönülür
            
        if token_time > current_time + 60:  # Gelecekten gelen zaman damgası saat sapması kontrolü
            return False, "CSRF token zaman damgası geleceğe ait."  # Hata bildirilir

        # 3. Nonce tekrar oynatma (Replay) kontrolü
        if nonce in self.used_nonces:  # Nonce daha önce kullanılmışsa
            return False, "CSRF tokenı daha önce kullanılmış (Replay tespit edildi)."  # Tekrar oynatma hatası dönülür
            
        # 4. Kriptografik imza doğrulaması (HMAC-SHA256)
        expected_payload = f"{t_session_id}:{token_time}:{nonce}"  # Beklenen gövde yeniden oluşturulur
        expected_sig = hmac.new(self.secret_key, expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()  # Beklenen imza hesaplanır
        if not hmac.compare_digest(signature, expected_sig):  # İmzalar sabit zamanlı karşılaştırılır
            return False, "CSRF token kriptografik imzası geçersiz."  # Sahtecilik hatası dönülür
            
        self.used_nonces.add(nonce)  # Nonce kullanılmışlar kümesine eklenerek harcanır
        return True, "CSRF tokenı başarıyla doğrulandı."  # Doğrulama başarılı


class RateLimiter:
    """İstemci IP ve oturum bazında brute-force engelleme amaçlı istek sınırlayıcı."""

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests: int = max_requests  # Zaman penceresindeki azami istek hakkı
        self.window_seconds: int = window_seconds  # Pencere süresi (saniye)
        self.requests: Dict[str, List[float]] = {}  # İstemci bazında istek zamanları sözlüğü

    def is_allowed(self, client_key: str) -> bool:
        """İstemcinin belirlenen limit dahilinde olup olmadığını kontrol eder."""
        now = time.time()  # Şu anki zaman saniyesi alınır
        if client_key not in self.requests:  # İstemci kaydı henüz yoksa
            self.requests[client_key] = [now]  # İlk istek kaydedilir
            return True  # İstek kabul edilir
            
        # Süresi dolmuş istekleri pencereden temizle
        valid_requests = [t for t in self.requests[client_key] if now - t < self.window_seconds]  # Geçerli istekler süzülür
        self.requests[client_key] = valid_requests  # Güncel liste atanır
        
        if len(valid_requests) >= self.max_requests:  # Limit aşıldıysa
            return False  # İstek reddedilir
            
        self.requests[client_key].append(now)  # Yeni istek listeye eklenir
        return True  # İzin verilir


class FormFieldValidator:
    """Form girdilerini katı kurallarla doğrulayan ve arındıran denetçi sınıf."""

    # E-posta RFC 5322 regex kalıbı
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    # Kullanıcı adı kalıbı (yalnızca alfanümerik ve alt çizgi, 3-32 karakter)
    USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
    # SQL Enjeksiyon şüpheli kalıpları
    SQLI_PATTERN = re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND)\b|'|--|#|/\*)", re.IGNORECASE)
    # XSS tehlikeli etiket ve olay yakalayıcıları
    XSS_PATTERN = re.compile(r"(<\s*script|onerror\s*=|onload\s*=|onclick\s*=|javascript\s*:)", re.IGNORECASE)

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Metnin Shannon bilgi entropisini hesaplar."""
        if not text:  # Boş metin kontrolü
            return 0.0  # Sıfır entropi
        length = len(text)  # Karakter sayısı
        freq: Dict[str, int] = {}  # Karakter frekansları
        for char in text:  # Her karakter taranır
            freq[char] = freq.get(char, 0) + 1  # Frekans artırılır
        entropy = 0.0  # Entropi toplamı
        for count in freq.values():  # Değerler döngüye alınır
            p = count / length  # Olasılık
            entropy -= p * math.log2(p)  # Shannon formülü uygulanır
        return entropy  # Entropi değeri döndürülür

    def validate_username(self, username: str) -> Tuple[bool, str, str]:
        """Kullanıcı adını doğrular ve enjeksiyonlara karşı korur."""
        if not username or not isinstance(username, str):  # Boş kontrolü
            return False, "Kullanıcı adı boş bırakılamaz.", ""  # Hata
        clean_user = username.strip()  # Baş ve son boşluklar temizlenir
        if len(clean_user) < 3 or len(clean_user) > 32:  # Boyut kontrolü
            return False, "Kullanıcı adı 3 ile 32 karakter arasında olmalıdır.", ""  # Hata
        if self.SQLI_PATTERN.search(clean_user) or self.XSS_PATTERN.search(clean_user):  # Enjeksiyon denetimi önceliklidir
            return False, "Kullanıcı adında zararlı enjeksiyon karakterleri tespit edildi.", ""  # Hata
        if not self.USERNAME_PATTERN.match(clean_user):  # Desen kontrolü
            return False, "Kullanıcı adı yalnızca harf, rakam ve alt çizgi içerebilir.", ""  # Hata
        return True, "Geçerli kullanıcı adı.", html.escape(clean_user, quote=True)  # Başarılı

    def validate_email(self, email: str) -> Tuple[bool, str, str]:
        """E-posta adresini RFC standartlarına göre doğrular."""
        if not email or not isinstance(email, str):  # Boş kontrolü
            return False, "E-posta adresi boş bırakılamaz.", ""  # Hata
        clean_email = email.strip().lower()  # Boşluklar temizlenir ve küçük harfe çevrilir
        if len(clean_email) > 254:  # RFC 5321 azami uzunluk
            return False, "E-posta adresi 254 karakterden uzun olamaz.", ""  # Hata
        if not self.EMAIL_PATTERN.match(clean_email):  # Regex kontrolü
            return False, "Geçerli bir e-posta biçimi girilmelidir (ör: kullanici@kurum.com).", ""  # Hata
        return True, "Geçerli e-posta.", html.escape(clean_email, quote=True)  # Başarılı

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """Parola karmaşıklığını ve Shannon entropisini denetler."""
        if not password or not isinstance(password, str):  # Boş kontrolü
            return False, "Parola alanı boş bırakılamaz."  # Hata
        if len(password) < 10:  # Asgari uzunluk kuralı
            return False, "Parola en az 10 karakter uzunluğunda olmalıdır."  # Hata
        if len(password) > 128:  # Azami uzunluk (DoS koruması)
            return False, "Parola 128 karakterden uzun olamaz."  # Hata
        if not re.search(r"[A-Z]", password):  # Büyük harf kontrolü
            return False, "Parola en az bir büyük harf içermelidir."  # Hata
        if not re.search(r"[a-z]", password):  # Küçük harf kontrolü
            return False, "Parola en az bir küçük harf içermelidir."  # Hata
        if not re.search(r"[0-9]", password):  # Rakam kontrolü
            return False, "Parola en az bir rakam içermelidir."  # Hata
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Özel karakter kontrolü
            return False, "Parola en az bir özel karakter içermelidir."  # Hata
        entropy = self.calculate_entropy(password)  # Entropi hesaplanır
        if entropy < 3.0:  # Asgari entropi eşiği
            return False, f"Parola tahmin edilebilirliği çok yüksek (Entropi: {entropy:.2f} < 3.00 bit/char)."  # Hata
        return True, "Parola güvenlik kriterlerini karşılıyor."  # Başarılı

    def validate_amount(self, amount_val: Any) -> Tuple[bool, str, float]:
        """Finansal işlem tutarını doğrular."""
        try:  # Sayısal dönüşüm denenir
            amt = float(amount_val)  # Kayan noktalı sayıya çevrilir
        except (ValueError, TypeError):  # Dönüştürülemezse
            return False, "Tutar geçerli bir sayı olmalıdır.", 0.0  # Hata
        if amt < 0.01:  # Sıfır veya negatif kontrolü
            return False, "İşlem tutarı en az 0.01 olmalıdır.", 0.0  # Hata
        if amt > 100000.00:  # Azami sınır kontrolü
            return False, "Tek seferde azami işlem tutarı 100.000,00 TL aşamaz.", 0.0  # Hata
        return True, "Geçerli işlem tutarı.", round(amt, 2)  # Yuvarlanmış tutar döner

    def validate_comment(self, comment: str) -> Tuple[bool, str, str]:
        """Açıklama alanını doğrular ve HTML varlık kaçışı uygular."""
        if not comment:  # Boş olabilir (isteğe bağlı alan)
            return True, "Boş açıklama.", ""  # Geçerli
        clean_comment = comment.strip()  # Boşluklar temizlenir
        if len(clean_comment) > 1000:  # Azami boyut kontrolü
            return False, "Açıklama alanı 1000 karakterden uzun olamaz.", ""  # Hata
        # XSS veya HTML enjeksiyonuna karşı katı gövde kaçışı
        safe_comment = html.escape(clean_comment, quote=True)  # Özel karakterler dönüştürülür
        return True, "Geçerli açıklama.", safe_comment  # Başarılı


class SecureFormEngine:
    """Güvenli form üretim, render ve işleme ana motoru."""

    def __init__(self, allowed_origin: str = "https://banka.kurum.internal"):
        self.csrf_manager = CSRFProtectionManager()  # CSRF yöneticisi başlatılır
        self.validator = FormFieldValidator()  # Alan doğrulayıcısı başlatılır
        self.rate_limiter = RateLimiter(max_requests=5, window_seconds=60)  # İstek sınırlayıcı başlatılır
        self.allowed_origin = allowed_origin  # İzin verilen köken (Origin) belirlenir

    def generate_security_headers(self, nonce: str) -> Dict[str, str]:
        """Form sayfası için zorunlu kurumsal güvenlik başlıklarını derler."""
        return {
            "Content-Security-Policy": (  # CSP Seviye 3 başlığı
                f"default-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script';"
            ),
            "X-Content-Type-Options": "nosniff",  # MIME türü koklama engeli
            "X-Frame-Options": "DENY",  # Clickjacking engeli
            "Referrer-Policy": "strict-origin-when-cross-origin",  # Referrer politikası
            "Set-Cookie": "__Host-SessionID=dummy_val; Secure; HttpOnly; SameSite=Strict; Path=/"  # Güvenli çerez bayrakları
        }

    def render_form_html(self, session_id: str) -> Tuple[str, str, Dict[str, str]]:
        """Güvenli CSRF tokenı gömülü form HTML içeriğini ve güvenlik başlıklarını üretir."""
        csrf_token = self.csrf_manager.generate_token(session_id)  # Yeni CSRF token üretilir
        script_nonce = secrets.token_urlsafe(16)  # CSP için rastgele nonce üretilir
        headers = self.generate_security_headers(script_nonce)  # Güvenlik başlıkları alınır
        
        # Güvenli HTML form şablonu
        form_html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Kurumsal Güvenli Transfer Formu</title>
</head>
<body>
    <h2>Güvenli Havale / EFT İşlem Formu</h2>
    <form action="/api/v1/transfer" method="POST" autocomplete="off">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        
        <div>
            <label for="username">Alıcı Kullanıcı Adı:</label>
            <input type="text" id="username" name="username" required maxlength="32">
        </div>
        
        <div>
            <label for="email">Alıcı E-posta:</label>
            <input type="email" id="email" name="email" required maxlength="254">
        </div>
        
        <div>
            <label for="amount">Gönderilecek Tutar (TL):</label>
            <input type="number" id="amount" name="amount" step="0.01" min="0.01" max="100000" required>
        </div>
        
        <div>
            <label for="password">İşlem Onay Parolası:</label>
            <input type="password" id="password" name="password" required maxlength="128">
        </div>
        
        <div>
            <label for="comment">Açıklama (İsteğe Bağlı):</label>
            <textarea id="comment" name="comment" maxlength="1000"></textarea>
        </div>
        
        <button type="submit">Güvenli Gönder</button>
    </form>
    <script nonce="{script_nonce}">
        // İstemci tarafı zararsız form telemetry betiği
        console.log("Güvenli form başarıyla yüklendi.");
    </script>
</body>
</html>"""
        return form_html, csrf_token, headers  # Form HTML, üretilen token ve başlıklar döndürülür

    def process_submission(
        self,
        post_data: Dict[str, Any],
        session_id: str,
        client_ip: str,
        origin_header: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Gelen form gönderimini tüm güvenlik filtrelerinden geçirir.
        Rate limiting, Origin doğrulaması, CSRF token kontrolü ve alan doğrulamasını yürütür.
        """
        # 1. Hız Sınırlaması (Rate Limiting) Kontrolü
        if not self.rate_limiter.is_allowed(client_ip):  # İstemci limiti aştıysa
            return {
                "success": False,  # Başarısız
                "status_code": 429,  # Too Many Requests
                "error": "İstek limitiniz aşıldı. Lütfen bir süre sonra tekrar deneyiniz."  # Hata mesajı
            }

        # 2. Origin / Referer Çapraz İstek Güvenliği Kontrolü
        if origin_header and origin_header != self.allowed_origin:  # Beklenmeyen kökenden geldiyse
            return {
                "success": False,  # Başarısız
                "status_code": 403,  # Forbidden
                "error": f"Geçersiz kaynak kökeni: '{origin_header}'. Çapraz site sahteciliği engellendi."  # Hata
            }

        # 3. CSRF Token Doğrulaması
        token = post_data.get("csrf_token", "")  # Gönderilen token alınır
        csrf_valid, csrf_msg = self.csrf_manager.validate_token(token, session_id)  # Doğrulama yapılır
        if not csrf_valid:  # Token geçersizse
            return {
                "success": False,  # Başarısız
                "status_code": 403,  # Forbidden
                "error": f"CSRF Güvenlik İhlali: {csrf_msg}"  # Hata mesajı
            }

        # 4. Alan Bazında Katı Doğrulamalar
        # Kullanıcı Adı
        u_valid, u_msg, clean_user = self.validator.validate_username(post_data.get("username", ""))  # Kullanıcı adı kontrolü
        if not u_valid:  # Geçersizse
            return {"success": False, "status_code": 400, "error": f"Kullanıcı Adı Hatası: {u_msg}"}  # Hata
            
        # E-posta
        e_valid, e_msg, clean_email = self.validator.validate_email(post_data.get("email", ""))  # E-posta kontrolü
        if not e_valid:  # Geçersizse
            return {"success": False, "status_code": 400, "error": f"E-posta Hatası: {e_msg}"}  # Hata

        # Parola
        p_valid, p_msg = self.validator.validate_password(post_data.get("password", ""))  # Parola kontrolü
        if not p_valid:  # Kriterleri karşılamıyorsa
            return {"success": False, "status_code": 400, "error": f"Parola Hatası: {p_msg}"}  # Hata

        # Tutar
        a_valid, a_msg, clean_amount = self.validator.validate_amount(post_data.get("amount", 0))  # Tutar kontrolü
        if not a_valid:  # Hatalıysa
            return {"success": False, "status_code": 400, "error": f"Tutar Hatası: {a_msg}"}  # Hata

        # Açıklama
        c_valid, c_msg, clean_comment = self.validator.validate_comment(post_data.get("comment", ""))  # Açıklama kontrolü
        if not c_valid:  # Hatalıysa
            return {"success": False, "status_code": 400, "error": f"Açıklama Hatası: {c_msg}"}  # Hata

        # 5. Tüm filtreler başarıyla aşıldı
        return {
            "success": True,  # Başarılı
            "status_code": 200,  # OK
            "message": "Form başarıyla doğrulandı ve işleme alındı.",  # Bilgi mesajı
            "sanitized_data": {  # Arındırılmış ve güvenli hale getirilmiş veriler
                "username": clean_user,  # Temiz kullanıcı adı
                "email": clean_email,  # Temiz e-posta
                "amount": clean_amount,  # Temiz tutar
                "comment": clean_comment  # Kaçış uygulanmış açıklama
            }
        }
