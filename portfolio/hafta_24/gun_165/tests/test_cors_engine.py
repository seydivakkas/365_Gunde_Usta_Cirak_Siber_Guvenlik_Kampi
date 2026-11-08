# -*- coding: utf-8 -*-
"""
Gün 165: CORS ile Güvenlik Sınırı Birim Testleri (test_cors_engine.py)

Bu test paketi; kurumsal CORS beyaz liste (Allowlist) denetimlerini,
preflight (OPTIONS) isteklerinin metot/başlık doğrulamalarını,
şema ve port izolasyonunu, 'null' origin korumasını, önbellek zehirlenmesine
karşı 'Vary: Origin' başlığını ve tehlikeli CORS yanlış yapılandırmalarını
15 kapsamlı fonksiyonel testle doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import os  # Dosya ve dizin yolu işlemleri için
import sys  # Sistem çalışma yolu modifikasyonu için
import unittest  # Birim test çerçevesi için

# Uygulama dizininin eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Test dosyası dizini
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # En başa ekle

# Test edilecek motor bileşenleri
from cors_engine import (
    CORSDefenseEngine,  # Merkezi savunma motoru
    CORSRequest,  # İstek veri yapısı
    EnterpriseCORSPolicy,  # Kurumsal politika
    CORSRiskType  # Risk türleri
)


class TestCORSDefenseEngine(unittest.TestCase):
    """CORS güvenlik sınırları için 15 fonksiyonel birim test sınıfı."""

    def setUp(self):
        """Her testten önce temiz kurumsal politika ve motor örneği oluşturulur."""
        self.policy = EnterpriseCORSPolicy(
            allowed_origins={
                "https://portal.kurum.internal",
                "https://mobil.kurum.internal",
                "https://yonetim.kurum.internal:8443"
            },
            allowed_methods={"GET", "POST", "PUT", "DELETE", "OPTIONS"},
            allowed_headers={"content-type", "authorization", "x-csrf-token", "x-requested-with"},
            allow_credentials=True,
            max_age_seconds=86400,
            enforce_vary_origin=True
        )
        self.engine = CORSDefenseEngine(policy=self.policy)  # Motor başlatılır

    def test_01_allowed_origin_returns_headers(self):
        """1. Test: Beyaz listedeki meşru kökene ACAO ve ACAC başlıklarının eksiksiz döndüğünü doğrular."""
        req = CORSRequest(method="GET", path="/api/veri", origin="https://portal.kurum.internal")  # İstek
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 200)  # 200 OK
        self.assertTrue(resp.is_cross_origin_allowed)  # İzin verilmeli
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "https://portal.kurum.internal")  # ACAO
        self.assertEqual(resp.headers.get("Access-Control-Allow-Credentials"), "true")  # ACAC

    def test_02_vary_origin_header_present(self):
        """2. Test: Önbellek zehirlenmesini (Cache Poisoning) önlemek için Vary: Origin başlığını doğrular."""
        req = CORSRequest(method="GET", path="/api/profil", origin="https://mobil.kurum.internal")  # İstek
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertIn("Vary", resp.headers)  # Vary başlığı mevcut olmalı
        self.assertEqual(resp.headers.get("Vary"), "Origin")  # Vary değeri Origin olmalı

    def test_03_foreign_origin_rejected_403(self):
        """3. Test: İzin verilmeyen üçüncü taraf yabancı kökenin 403 ile engellendiğini ve ACAO dönülmediğini doğrular."""
        req = CORSRequest(method="GET", path="/api/gizli", origin="https://evil-attacker.com")  # Saldırgan
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 403)  # 403 Forbidden
        self.assertFalse(resp.is_cross_origin_allowed)  # İzin verilmemeli
        self.assertNotIn("Access-Control-Allow-Origin", resp.headers)  # ACAO kesinlikle olmamalı

    def test_04_null_origin_rejected_403(self):
        """4. Test: Sandbox iframe veya local file kaynaklı 'null' Origin'in 403 ile reddedildiğini doğrular."""
        req = CORSRequest(method="GET", path="/api/bakiye", origin="null")  # null köken
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 403)  # 403 Forbidden
        self.assertFalse(resp.is_cross_origin_allowed)  # İzin verilmemeli
        self.assertIn(CORSRiskType.NULL_ORIGIN_ALLOWED, resp.detected_risks)  # Risk tespit edilmeli

    def test_05_preflight_valid_options_request(self):
        """5. Test: Geçerli Preflight OPTIONS isteğinin 204 No Content ve onay başlıklarıyla döndüğünü doğrular."""
        req = CORSRequest(
            method="OPTIONS", path="/api/transfer",
            origin="https://portal.kurum.internal",
            access_control_request_method="POST",
            access_control_request_headers="content-type,x-csrf-token"
        )
        resp = self.engine.secure_cors_handler(req)  # Preflight işlenir
        self.assertEqual(resp.status_code, 204)  # 204 No Content
        self.assertTrue(resp.is_cross_origin_allowed)  # Preflight onaylanmalı
        self.assertIn("Access-Control-Allow-Methods", resp.headers)  # Metotlar
        self.assertIn("Access-Control-Allow-Headers", resp.headers)  # Başlıklar
        self.assertEqual(resp.headers.get("Access-Control-Max-Age"), "86400")  # Önbellek süresi

    def test_06_preflight_disallowed_method_405(self):
        """6. Test: Preflight isteğinde izin verilmeyen güvensiz bir metodun (örn: TRACE) 405 ile reddedildiğini doğrular."""
        req = CORSRequest(
            method="OPTIONS", path="/api/transfer",
            origin="https://portal.kurum.internal",
            access_control_request_method="TRACE"  # Yasaklı metot
        )
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 405)  # 405 Method Not Allowed
        self.assertFalse(resp.is_cross_origin_allowed)  # Onaylanmamalı

    def test_07_preflight_disallowed_header_403(self):
        """7. Test: Preflight isteğinde izin verilmeyen yabancı bir özel başlığın 403 ile engellendiğini doğrular."""
        req = CORSRequest(
            method="OPTIONS", path="/api/transfer",
            origin="https://portal.kurum.internal",
            access_control_request_method="POST",
            access_control_request_headers="x-malicious-custom-header"  # İzin dışı başlık
        )
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 403)  # 403 Forbidden
        self.assertFalse(resp.is_cross_origin_allowed)  # Onaylanmamalı

    def test_08_vulnerable_server_arbitrary_reflection(self):
        """8. Test: Zafiyetli sunucunun yabancı kökeni körlemesine yansıttığını (Arbitrary Reflection) doğrular."""
        req = CORSRequest(method="GET", path="/api/gizli", origin="https://evil-phishing.com")  # Saldırgan
        resp = self.engine.vulnerable_cors_handler(req)  # Zafiyetli işleyici
        self.assertEqual(resp.status_code, 200)  # 200 OK döndü (ZAFİYET!)
        self.assertTrue(resp.is_cross_origin_allowed)  # Veri sızdırıldı
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "https://evil-phishing.com")  # Yansıtıldı
        self.assertIn(CORSRiskType.ARBITRARY_ORIGIN_REFLECTION, resp.detected_risks)  # Risk teşhisi

    def test_09_vulnerable_server_null_origin_reflection(self):
        """9. Test: Zafiyetli sunucunun 'null' origin'e izin verdiğini doğrular."""
        req = CORSRequest(method="GET", path="/api/gizli", origin="null")  # null origin
        resp = self.engine.vulnerable_cors_handler(req)  # Zafiyetli işleyici
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "null")  # null yansıtıldı
        self.assertEqual(resp.headers.get("Access-Control-Allow-Credentials"), "true")  # Credentials açık
        self.assertIn(CORSRiskType.NULL_ORIGIN_ALLOWED, resp.detected_risks)  # Risk teşhisi

    def test_10_same_origin_request_handled(self):
        """10. Test: Origin başlığı içermeyen aynı köken (Same-Origin) doğrudan isteğinin sorunsuz çalıştığını doğrular."""
        req = CORSRequest(method="GET", path="/api/profil", origin=None)  # Origin yok
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 200)  # 200 OK
        self.assertFalse(resp.is_cross_origin_allowed)  # CORS başlıkları üretilmez
        self.assertNotIn("Access-Control-Allow-Origin", resp.headers)  # Başlık gerekmez

    def test_11_origin_normalization_case_and_slash(self):
        """11. Test: Büyük harf veya sağdaki eğik çizgi içeren kökenin başarıyla normalize edildiğini doğrular."""
        normalized = self.engine.normalize_origin("HTTPS://PORTAL.KURUM.INTERNAL/")  # Normalize çağrısı
        self.assertEqual(normalized, "https://portal.kurum.internal")  # Temiz çıktı

    def test_12_regex_subdomain_prefix_misconfig_detection(self):
        """12. Test: Hatalı regex kullanımının (ön ek/son ek atlatması) zafiyet oluşturduğunu doğrular."""
        flawed_pattern = r"portal\.kurum\.internal"  # Başı ve sonu sınırlanmamış zayıf regex
        attacker_origin = "https://evil-portal.kurum.internal"  # Saldırgan alt alan adı
        matched = self.engine.test_regex_misconfiguration(attacker_origin, flawed_pattern)  # Test
        self.assertTrue(matched)  # Zayıf regex bu saldırganı onaylar (ZAFİYET KANITI)

    def test_13_regex_unescaped_dot_misconfig_detection(self):
        """13. Test: Kaçılmamış nokta içeren regex'in yabancı alan adlarını yanlışlıkla onayladığını doğrular."""
        flawed_pattern = r"^https://portal.kurum.internal$"  # Noktalar kaçılmamış!
        attacker_origin = "https://portalxkurumxinternal"  # Nokta yerine 'x' konmuş saldırgan domaini
        matched = self.engine.test_regex_misconfiguration(attacker_origin, flawed_pattern)  # Test
        self.assertTrue(matched)  # Kaçılmamış nokta 'x' ile eşleşir (ZAFİYET KANITI)

    def test_14_port_isolation_enforcement(self):
        """14. Test: Farklı porta sahip kökenin (Origin Port İzolasyonu) yetkisiz sayıldığını doğrular."""
        req = CORSRequest(method="GET", path="/api/veri", origin="https://portal.kurum.internal:8080")  # Farklı port
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 403)  # Port uyuşmadığı için 403 dönmelidir
        self.assertFalse(resp.is_cross_origin_allowed)  # İzin verilmemeli

    def test_15_scheme_isolation_http_vs_https(self):
        """15. Test: Güvensiz düz metin HTTP kökeninin HTTPS beyaz listesi tarafından reddedildiğini doğrular."""
        req = CORSRequest(method="GET", path="/api/veri", origin="http://portal.kurum.internal")  # Güvensiz HTTP
        resp = self.engine.secure_cors_handler(req)  # İşlenir
        self.assertEqual(resp.status_code, 403)  # Şema uyuşmadığı için 403 dönmelidir
        self.assertFalse(resp.is_cross_origin_allowed)  # İzin verilmemeli


if __name__ == "__main__":
    unittest.main()
