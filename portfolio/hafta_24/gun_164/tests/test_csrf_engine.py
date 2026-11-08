# -*- coding: utf-8 -*-
"""
Gün 164: CSRF ve Oturum Bağlamı Birim Testleri (test_csrf_engine.py)

Bu test paketi; Anti-CSRF belirteç yönetimini, zaman damgası ve imza doğrulamasını,
tek kullanımlık nonce (replay) önlemini, Origin/Referer köken denetimlerini,
GET durum değişimi kısıtlamalarını ve bankacılık transfer uç noktalarının
zafiyetli/güvenli davranışlarını 15 kapsamlı birim testle doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yolu işlemleri
import sys  # Sistem çalışma yolu modifikasyonu
import time  # Zaman hesaplamaları ve zaman damgası manipülasyonu
import unittest  # Birim test çerçevesi

# Uygulama modülünün sistem yoluna eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Test dosyası dizini
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # En başa ekle

# Test edilecek motor bileşenleri
from csrf_engine import (
    CSRFDefenseEngine,  # Merkezi savunma motoru
    AntiCSRFTokenManager,  # Belirteç yöneticisi
    OriginRefererValidator,  # Köken doğrulayıcı
    HTTPRequest,  # İstek veri yapısı
    SameSiteMode  # SameSite modları
)


class TestCSRFDefenseEngine(unittest.TestCase):
    """CSRF ve oturum bağlamı korumaları için 15 fonksiyonel birim test sınıfı."""

    def setUp(self):
        """Her testten önce temiz motor, kurban oturumu ve bileşenler oluşturulur."""
        self.enterprise_origin = "https://banka.kurum.internal"  # Meşru köken
        self.engine = CSRFDefenseEngine(enterprise_origin=self.enterprise_origin)  # Savunma motoru
        self.token_manager = self.engine.token_manager  # Belirteç yöneticisi
        self.victim_session = self.engine.create_mock_session(user_id=2, username="ahmet_kaya")  # Kurban oturumu

    def test_01_token_generation_structure(self):
        """1. Test: Üretilen Anti-CSRF belirtecinin 4 bileşenli yapısını doğrular."""
        token = self.token_manager.generate_token(self.victim_session)  # Belirteç üretilir
        parts = token.split(".")  # Noktadan parçalanır
        self.assertEqual(len(parts), 4)  # 4 parça olmalıdır: sid, ts, nonce, imza
        self.assertEqual(parts[0], self.victim_session.session_id)  # İlk parça oturum ID olmalıdır
        self.assertTrue(parts[1].isdigit())  # İkinci parça tamsayı zaman damgası olmalıdır

    def test_02_token_validation_success(self):
        """2. Test: Tahrif edilmemiş taze belirtecin başarıyla doğrulandığını doğrular."""
        token = self.token_manager.generate_token(self.victim_session)  # Belirteç üretilir
        is_valid, msg = self.token_manager.validate_token(token, self.victim_session, consume=False)  # Doğrulanır
        self.assertTrue(is_valid)  # Geçerli olmalıdır
        self.assertIn("başarıyla doğrulandı", msg)  # Başarı mesajı

    def test_03_token_tampered_signature_rejected(self):
        """3. Test: İmzası tahrif edilmiş (tampered) belirtecin reddedildiğini doğrular."""
        token = self.token_manager.generate_token(self.victim_session)  # Belirteç üretilir
        parts = token.split(".")  # Parçalanır
        tampered_sig = parts[3][:-4] + "dead"  # Son 4 karakter bozulur
        tampered_token = f"{parts[0]}.{parts[1]}.{parts[2]}.{tampered_sig}"  # Yeniden birleştirilir
        is_valid, msg = self.token_manager.validate_token(tampered_token, self.victim_session)  # Doğrulanır
        self.assertFalse(is_valid)  # Geçersiz olmalıdır
        self.assertIn("Geçersiz CSRF belirteç imzası", msg)  # İmza tahrifat uyarısı

    def test_04_token_session_mismatch_rejected(self):
        """4. Test: Başka bir kullanıcının oturumuna ait belirtecin reddedildiğini doğrular."""
        other_session = self.engine.create_mock_session(user_id=3, username="attacker_bob")  # Farklı oturum
        token_for_other = self.token_manager.generate_token(other_session)  # Saldırganın belirteci
        is_valid, msg = self.token_manager.validate_token(token_for_other, self.victim_session)  # Kurbanda denenir
        self.assertFalse(is_valid)  # Reddedilmelidir
        self.assertIn("oturum kimliği ile mevcut oturum kimliği uyuşmuyor", msg)  # Hata mesajı

    def test_05_token_ttl_expiration(self):
        """5. Test: Süresi dolmuş (TTL expired) belirtecin reddedildiğini doğrular."""
        short_ttl_manager = AntiCSRFTokenManager(token_ttl_seconds=1)  # 1 saniyelik yönetici
        token = short_ttl_manager.generate_token(self.victim_session)  # Belirteç üretilir
        parts = token.split(".")  # Parçalara ayrılır
        # Zaman damgası geçmişe alınır (3600 saniye önce)
        old_ts = int(time.time()) - 3600  # 1 saat önce
        # Geçmiş zaman damgasıyla yeni imza oluşturularak deterministik test kurulur
        raw = f"{self.victim_session.session_id}:{self.victim_session.csrf_secret}:{old_ts}:{parts[2]}"
        key = f"{short_ttl_manager.master_secret}:{self.victim_session.csrf_secret}".encode("utf-8")
        import hmac, hashlib
        sig = hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()
        expired_token = f"{self.victim_session.session_id}.{old_ts}.{parts[2]}.{sig}"
        is_valid, msg = short_ttl_manager.validate_token(expired_token, self.victim_session)  # Doğrulanır
        self.assertFalse(is_valid)  # Süre dolduğu için geçersizdir
        self.assertIn("süresi dolmuş", msg)  # Süre dolumu mesajı

    def test_06_token_future_timestamp_rejected(self):
        """6. Test: İleri tarihli manipüle edilmiş zaman damgasının reddedildiğini doğrular."""
        future_ts = int(time.time()) + 10000  # Çok ileri bir zaman
        nonce = "abcdef0123456789"  # Örnek nonce
        raw = f"{self.victim_session.session_id}:{self.victim_session.csrf_secret}:{future_ts}:{nonce}"
        key = f"{self.token_manager.master_secret}:{self.victim_session.csrf_secret}".encode("utf-8")
        import hmac, hashlib
        sig = hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()
        future_token = f"{self.victim_session.session_id}.{future_ts}.{nonce}.{sig}"
        is_valid, msg = self.token_manager.validate_token(future_token, self.victim_session)  # Doğrulanır
        self.assertFalse(is_valid)  # Reddedilmelidir
        self.assertIn("İleri tarihli manipüle edilmiş", msg)  # Uyarı kontrolü

    def test_07_token_replay_prevention_nonce(self):
        """7. Test: Kullanılmış tek kullanımlık belirtecin (Replay Attack) engellendiğini doğrular."""
        token = self.token_manager.generate_token(self.victim_session)  # Belirteç üretilir
        first_valid, _ = self.token_manager.validate_token(token, self.victim_session, consume=True)  # İlk kullanım
        self.assertTrue(first_valid)  # İlk kullanım başarılı
        second_valid, msg = self.token_manager.validate_token(token, self.victim_session, consume=True)  # İkinci kullanım
        self.assertFalse(second_valid)  # Tekrar kullanımı engellenmelidir
        self.assertIn("daha önce kullanılmış", msg)  # Replay tespiti

    def test_08_origin_validator_allowed_origin(self):
        """8. Test: İzin verilen kurumsal kökene (Origin) sahip isteğin onaylandığını doğrular."""
        req = HTTPRequest(
            method="POST", path="/api/transfer",
            headers={"Origin": "https://banka.kurum.internal"}
        )
        is_ok, msg = self.engine.origin_validator.validate_request_origin(req)  # Doğrulanır
        self.assertTrue(is_ok)  # Geçerli olmalıdır
        self.assertIn("Origin başarıyla doğrulandı", msg)  # Başarı kontrolü

    def test_09_origin_validator_rejects_foreign_origin(self):
        """9. Test: Saldırgana ait yabancı kökenin (Cross-Origin) 403 ile engellendiğini doğrular."""
        req = HTTPRequest(
            method="POST", path="/api/transfer",
            headers={"Origin": "https://evil-phishing-bank.com"}
        )
        is_ok, msg = self.engine.origin_validator.validate_request_origin(req)  # Doğrulanır
        self.assertFalse(is_ok)  # Reddedilmelidir
        self.assertIn("İzin verilmeyen yabancı köken", msg)  # Hata mesajı

    def test_10_origin_validator_rejects_null_origin(self):
        """10. Test: İframe sandbox veya data URL saldırılarında kullanılan 'null' Origin'in engellendiğini doğrular."""
        req = HTTPRequest(
            method="POST", path="/api/transfer",
            headers={"Origin": "null"}
        )
        is_ok, msg = self.engine.origin_validator.validate_request_origin(req)  # Doğrulanır
        self.assertFalse(is_ok)  # Reddedilmelidir
        self.assertIn("Güvensiz 'null' Origin", msg)  # Null uyarısı

    def test_11_origin_validator_referer_fallback(self):
        """11. Test: Origin başlığı yoksa meşru Referer başlığının başarıyla çözümlendiğini doğrular."""
        req = HTTPRequest(
            method="POST", path="/api/transfer",
            headers={"Referer": "https://banka.kurum.internal/hesaplar/transfer.html"}
        )
        is_ok, msg = self.engine.origin_validator.validate_request_origin(req)  # Doğrulanır
        self.assertTrue(is_ok)  # Geçerli sayılmalıdır
        self.assertIn("Referer kökeni başarıyla doğrulandı", msg)  # Referer başarısı

    def test_12_vulnerable_endpoint_allows_csrf_attack(self):
        """12. Test: Zafiyetli uç noktanın yabancı siteden gelen ambient çerezli transferi onayladığını doğrular."""
        attack_req = HTTPRequest(
            method="POST", path="/api/transfer",
            headers={"Origin": "https://evil-phishing.com"},  # Yabancı köken
            cookies={"session_id": self.victim_session.session_id},  # Tarayıcı çerezi otomatik yolladı!
            form_data={"target_account": 3, "amount": 3000.0}
        )
        resp = self.engine.vulnerable_transfer_funds(attack_req)  # Zafiyetli çağrı
        self.assertTrue(resp["success"])  # ZAFİYET: Transfer onaylandı!
        self.assertEqual(resp["status_code"], 200)  # 200 OK döndü
        self.assertEqual(self.engine.accounts[2], 12000.0)  # Kurbanın 3000 TL'si çalındı

    def test_13_secure_endpoint_blocks_get_state_change(self):
        """13. Test: Güvenli uç noktanın durum değiştiren GET isteğini 405 Method Not Allowed ile reddettiğini doğrular."""
        get_req = HTTPRequest(
            method="GET", path="/api/transfer?target_account=3&amount=1000",
            headers={"Origin": self.enterprise_origin},
            cookies={"session_id": self.victim_session.session_id}
        )
        resp = self.engine.secure_transfer_funds(get_req)  # Güvenli çağrı
        self.assertFalse(resp["success"])  # İşlem reddedilmelidir
        self.assertEqual(resp["status_code"], 405)  # 405 dönmelidir
        self.assertIn("Metot İzin Verilmiyor", resp["error"])  # Hata mesajı

    def test_14_secure_endpoint_blocks_cross_origin(self):
        """14. Test: Güvenli uç noktanın yabancı kökenli isteği 403 Forbidden ile engellediğini doğrular."""
        attack_req = HTTPRequest(
            method="POST", path="/api/transfer",
            headers={"Origin": "https://evil-phishing.com"},  # Saldırgan domaini
            cookies={"session_id": self.victim_session.session_id},
            form_data={"target_account": 3, "amount": 2000.0}
        )
        resp = self.engine.secure_transfer_funds(attack_req)  # Güvenli çağrı
        self.assertFalse(resp["success"])  # Saldırı engellenmelidir
        self.assertEqual(resp["status_code"], 403)  # 403 Forbidden dönmelidir
        self.assertIn("Köken Doğrulama Hatası", resp["error"])  # Origin hatası

    def test_15_secure_endpoint_valid_transfer_with_token(self):
        """15. Test: Güvenli uç noktanın meşru Origin ve geçerli Anti-CSRF token ile transferi başarıyla onayladığını doğrular."""
        valid_token = self.token_manager.generate_token(self.victim_session)  # Geçerli token
        legit_req = HTTPRequest(
            method="POST", path="/api/transfer",
            headers={
                "Origin": self.enterprise_origin,
                "X-CSRF-Token": valid_token  # Meşru token başlıkta iletilir
            },
            cookies={"session_id": self.victim_session.session_id},
            form_data={"target_account": 3, "amount": 1000.0}
        )
        resp = self.engine.secure_transfer_funds(legit_req)  # Güvenli çağrı
        self.assertTrue(resp["success"])  # Transfer tamamlanmalıdır
        self.assertEqual(resp["status_code"], 200)  # 200 OK
        self.assertEqual(self.engine.accounts[2], 14000.0)  # Kurbanın bakiyesi 1000 azaldı
        self.assertEqual(self.engine.accounts[3], 1100.0)  # Hedef bakiye arttı


if __name__ == "__main__":
    unittest.main()
