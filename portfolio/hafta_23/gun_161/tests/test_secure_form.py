# -*- coding: utf-8 -*-
"""
Gün 161: Mini Proje 22 - Güvenli Form Arayüzü Birim Testleri (test_secure_form.py)

Bu test paketi; CSRF koruma yöneticisini, form girdi doğrulama motorunu,
istek sınırlandırma (rate limiting) mekanizmasını ve uçtan uca güvenli form işleme
boru hattını 15 kapsamlı birim test senaryosuyla doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yolu manipülasyonu için os modülü dahil edilir
import sys  # Sistem yolu ve import önceliği için sys modülü dahil edilir
import time  # Zaman simülasyonları ve gecikmeler için time modülü dahil edilir
import unittest  # Birim test çerçevesi için unittest modülü dahil edilir

# Test edilecek dizinin sys.path içerisine eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Mevcut dosya dizini alınır
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama klasörü yolu oluşturulur
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # İlk sıraya eklenir

# Test edilecek motor sınıflarının içe aktarılması
from secure_form_engine import (  # secure_form_engine modülünden gerekli sınıflar çağrılır
    SecureFormEngine,  # Güvenli form ana motoru
    CSRFProtectionManager,  # CSRF token yöneticisi
    FormFieldValidator,  # Alan doğrulayıcısı
    RateLimiter  # İstek sınırlayıcısı
)


class TestSecureFormEngine(unittest.TestCase):
    """Güvenli form arayüzü motoru için 15 fonksiyonel birim test sınıfı."""

    def setUp(self):
        """Her testten önce temiz motor ve yönetici örnekleri oluşturulur."""
        self.engine = SecureFormEngine(allowed_origin="https://banka.kurum.internal")  # Ana motor başlatılır
        self.csrf_mgr = CSRFProtectionManager(token_validity_seconds=1800)  # CSRF yöneticisi başlatılır
        self.validator = FormFieldValidator()  # Alan doğrulayıcısı başlatılır
        self.rate_limiter = RateLimiter(max_requests=5, window_seconds=60)  # Sınırlayıcı başlatılır

    def test_01_csrf_token_generation_and_structure(self):
        """1. Test: CSRF tokenının beklenen 4 parçalı HMAC yapısını doğrular."""
        token = self.csrf_mgr.generate_token("session_abc_123")  # Token üretilir
        parts = token.split(":")  # İki nokta ile ayrıştırılır
        self.assertEqual(len(parts), 4)  # 4 bileşen içermelidir
        self.assertEqual(parts[0], "session_abc_123")  # İlk bileşen oturum kimliği olmalıdır
        self.assertEqual(len(parts[3]), 64)  # HMAC-SHA256 imzası 64 onaltılık karakter olmalıdır

    def test_02_csrf_token_valid_validation(self):
        """2. Test: Yeni üretilen geçerli bir CSRF tokenının doğrulandığını doğrular."""
        token = self.csrf_mgr.generate_token("user_sess_777")  # Token üretilir
        is_valid, msg = self.csrf_mgr.validate_token(token, "user_sess_777")  # Doğrulama icra edilir
        self.assertTrue(is_valid)  # Başarılı olmalıdır
        self.assertIn("başarıyla", msg)  # Başarı mesajı yer almalıdır

    def test_03_csrf_token_session_mismatch(self):
        """3. Test: Farklı bir oturuma ait CSRF tokenının reddedildiğini doğrular."""
        token = self.csrf_mgr.generate_token("sess_ali_1")  # Ali için token üretilir
        is_valid, msg = self.csrf_mgr.validate_token(token, "sess_veli_2")  # Veli oturumu ile denenir
        self.assertFalse(is_valid)  # Başarısız olmalıdır
        self.assertIn("eşleşmiyor", msg)  # Eşleşmeme hatası dönmelidir

    def test_04_csrf_token_tampered_signature(self):
        """4. Test: İmzası tahrif edilmiş CSRF tokenının yakalandığını doğrular."""
        token = self.csrf_mgr.generate_token("sess_valid")  # Geçerli token üretilir
        tampered_token = token[:-4] + "0000"  # İmzanın son 4 karakteri bozulur
        is_valid, msg = self.csrf_mgr.validate_token(tampered_token, "sess_valid")  # Doğrulama denenir
        self.assertFalse(is_valid)  # Sahtecilik engellenmelidir
        self.assertIn("imzası geçersiz", msg)  # İmza hatası dönmelidir

    def test_05_csrf_token_replay_attack_prevention(self):
        """5. Test: Aynı CSRF tokenının iki kez kullanılması durumunda (Replay) engellendiğini doğrular."""
        token = self.csrf_mgr.generate_token("sess_replay")  # Token üretilir
        ok1, _ = self.csrf_mgr.validate_token(token, "sess_replay")  # İlk kullanım
        self.assertTrue(ok1)  # İlk kullanım başarılı olmalı
        ok2, msg = self.csrf_mgr.validate_token(token, "sess_replay")  # İkinci kullanım (Replay atağı)
        self.assertFalse(ok2)  # İkinci kullanım engellenmeli
        self.assertIn("Replay", msg)  # Replay uyarısı dönmelidir

    def test_06_csrf_token_expiration(self):
        """6. Test: Süresi dolmuş CSRF tokenının reddedildiğini doğrular."""
        past_time = int(time.time()) - 3600  # 1 saat önceki zaman damgası
        nonce = "aabbccddeeff1122"  # Test nonce değeri
        payload = f"sess_timeout:{past_time}:{nonce}"  # Token gövdesi
        import hashlib, hmac  # Kripto modülleri
        signature = hmac.new(self.csrf_mgr.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()  # İmza
        expired_token = f"{payload}:{signature}"  # Süresi dolmuş geçerli imzalı token
        is_valid, msg = self.csrf_mgr.validate_token(expired_token, "sess_timeout")  # Doğrulama denenir
        self.assertFalse(is_valid)  # Reddedilmelidir
        self.assertIn("süresi dolmuş", msg)  # Süre aşımı uyarısı dönmelidir

    def test_07_valid_username_and_sqli_xss_blocking(self):
        """7. Test: Geçerli kullanıcı adının onaylandığını, SQLi/XSS içerenlerin engellendiğini doğrular."""
        ok_valid, _, clean = self.validator.validate_username("ahmet_yilmaz_99")  # Geçerli kullanıcı
        self.assertTrue(ok_valid)  # Onaylanmalıdır
        self.assertEqual(clean, "ahmet_yilmaz_99")  # Temiz metin doğrulanmalıdır
        
        ok_sqli, msg_sqli, _ = self.validator.validate_username("admin' OR '1'='1")  # SQLi denemesi
        self.assertFalse(ok_sqli)  # Reddedilmelidir
        
        ok_xss, _, _ = self.validator.validate_username("<script>alert(1)</script>")  # XSS denemesi
        self.assertFalse(ok_xss)  # Reddedilmelidir

    def test_08_valid_email_and_format_enforcement(self):
        """8. Test: RFC standartlarında e-posta doğrulamasını ve geçersizlerin reddini doğrular."""
        ok1, _, email = self.validator.validate_email("denetim.uzmani@kurum.com.tr")  # Geçerli kurumsal e-posta
        self.assertTrue(ok1)  # Kabul edilmelidir
        self.assertEqual(email, "denetim.uzmani@kurum.com.tr")  # Eşitlik kontrolü
        
        ok2, msg2, _ = self.validator.validate_email("gecersiz_eposta_adresi")  # Hatalı format
        self.assertFalse(ok2)  # Reddedilmelidir

    def test_09_password_complexity_and_entropy(self):
        """9. Test: Güçlü parolanın kabul edildiğini, zayıf/düşük entropili parolanın reddedildiğini doğrular."""
        strong_pass = "P@ssw0rdSecure!2026"  # Karmaşık ve yüksek entropili parola
        ok_strong, _ = self.validator.validate_password(strong_pass)  # Parola denetlenir
        self.assertTrue(ok_strong)  # Kabul edilmelidir
        
        weak_pass = "12345678"  # Kısa ve tekdüze parola
        ok_weak, msg_weak = self.validator.validate_password(weak_pass)  # Zayıf parola denetlenir
        self.assertFalse(ok_weak)  # Reddedilmelidir

    def test_10_amount_boundary_and_type_check(self):
        """10. Test: Finansal işlem tutarı sınırlarını ve negatif değer engellemesini doğrular."""
        ok_amt, _, val = self.validator.validate_amount("1250.50")  # Geçerli tutar
        self.assertTrue(ok_amt)  # Kabul edilmelidir
        self.assertEqual(val, 1250.50)  # Tutar eşitliği
        
        ok_neg, _, _ = self.validator.validate_amount("-500.00")  # Negatif tutar
        self.assertFalse(ok_neg)  # Reddedilmelidir
        
        ok_high, _, _ = self.validator.validate_amount("99999999.00")  # Sınır aşımı
        self.assertFalse(ok_high)  # Reddedilmelidir

    def test_11_comment_field_html_escaping(self):
        """11. Test: Açıklama alanındaki HTML/XSS karakterlerinin kaçışa uğradığını doğrular."""
        dirty_comment = "Fatura bedeli <script>alert('xss')</script> & borç."  # Zararlı açıklama
        ok_c, _, clean_c = self.validator.validate_comment(dirty_comment)  # Açıklama temizlenir
        self.assertTrue(ok_c)  # Kabul edilir
        self.assertNotIn("<script>", clean_c)  # script etiketi ham kalmamalıdır
        self.assertIn("&lt;script&gt;", clean_c)  # Kaçış varlığı doğrulanmalıdır
        self.assertIn("&amp;", clean_c)  # Ve işareti kaçırılmalıdır

    def test_12_rate_limiter_allows_under_limit(self):
        """12. Test: İstek sınırlandırıcının limit altındaki 5 isteğe izin verdiğini doğrular."""
        ip = "10.0.0.1"  # İstemci IP
        for _ in range(5):  # 5 adet istek simüle edilir
            self.assertTrue(self.rate_limiter.is_allowed(ip))  # Hepsi kabul edilmelidir

    def test_13_rate_limiter_blocks_on_excess(self):
        """13. Test: İzin verilen 5 isteğin ardından 6. isteğin engellendiğini doğrular."""
        ip = "10.0.0.2"  # İstemci IP
        for _ in range(5):  # Limit doldurulur
            self.rate_limiter.is_allowed(ip)  # İstek yapılır
        self.assertFalse(self.rate_limiter.is_allowed(ip))  # 6. istek engellenmelidir

    def test_14_origin_header_validation(self):
        """14. Test: Farklı kökenden (Origin) gelen sahte isteklerin 403 ile engellendiğini doğrular."""
        post_data = {"username": "test_user"}  # Sahte istek verisi
        res = self.engine.process_submission(  # Gönderim işlenir
            post_data=post_data,
            session_id="sess_origin",
            client_ip="192.168.1.100",
            origin_header="https://attacker.evil.com"  # Saldırgan kökeni
        )
        self.assertFalse(res["success"])  # Başarısız olmalıdır
        self.assertEqual(res["status_code"], 403)  # 403 Forbidden dönmelidir

    def test_15_end_to_end_successful_form_submission(self):
        """15. Test: Tüm kriterleri karşılayan eksiksiz form gönderiminin 200 OK ile işlendiğini doğrular."""
        session_id = "sess_master_999"  # Meşru oturum
        client_ip = "192.168.1.15"  # Meşru istemci
        
        # 1. Form render edilir ve geçerli CSRF tokenı elde edilir
        _, csrf_token, _ = self.engine.render_form_html(session_id)  # Form üretilir
        
        # 2. Geçerli form verisi hazırlanır
        valid_payload = {  # Form gönderim verisi
            "csrf_token": csrf_token,  # Üretilen meşru token
            "username": "mehmet_demir",  # Geçerli kullanıcı adı
            "email": "mehmet.demir@kurum.com",  # Geçerli e-posta
            "password": "M3hmetSecure!2026",  # Güçlü parola
            "amount": "4500.00",  # Geçerli tutar
            "comment": "Nisan ayı aidat ödemesi."  # Açıklama
        }
        
        # 3. Form gönderimi işlenir
        res = self.engine.process_submission(  # Gönderim test edilir
            post_data=valid_payload,
            session_id=session_id,
            client_ip=client_ip,
            origin_header="https://banka.kurum.internal"
        )
        self.assertTrue(res["success"])  # Başarılı olmalıdır
        self.assertEqual(res["status_code"], 200)  # 200 OK dönmelidir
        self.assertEqual(res["sanitized_data"]["username"], "mehmet_demir")  # Veri doğrulanmalıdır
        self.assertEqual(res["sanitized_data"]["amount"], 4500.0)  # Tutar doğrulanmalıdır


if __name__ == "__main__":  # Doğrudan çalıştırıldığında
    unittest.main()  # Birim testler başlatılır
