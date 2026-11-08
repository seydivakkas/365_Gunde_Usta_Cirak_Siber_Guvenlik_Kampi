# -*- coding: utf-8 -*-
"""
Web Uygulama Mimarisi ve Güven Sınırı Birim Test Paketi
Hafta 23 / Gün 155 - Aşama 7 (Web Güvenliği)

Bu test paketi; istemci-sunucu güven sınırlarını, HTTP taşıma güvenliğini,
güvenlik başlıklarını (HSTS, CSP, XFO, nosniff), çerez ve oturum güvenliğini
(Secure, HttpOnly, SameSite) ve otomatik yanıt sertleştirmesini 15 birim testi
ile %100 kapsama oranıyla test eder.
"""

import unittest
import os
import sys

# Üst dizini Python import yoluna ekler
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.web_architecture_engine import (
    HttpRequest,
    HttpResponse,
    CookieSpec,
    WebTrustBoundaryEngine,
    WebAuditReport,
    ViolationSeverity,
)


class TestWebArchitectureEngine(unittest.TestCase):
    """Web mimarisi ve güven sınırı test sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        self.engine = WebTrustBoundaryEngine()

        # Kusursuz güvenli referans HTTP isteği
        self.clean_request = HttpRequest(
            method="POST",
            path="/api/v1/checkout/process",
            headers={
                "Host": "api.kurumsalbanka.com",
                "User-Agent": "KurumsalMobilApp/2.4.0",
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "Content-Type": "application/json",
            },
            query_params={"order_id": "ORD-98421"},
            body={"payment_method_id": "pm_card_9981", "currency": "TRY"},
            client_ip="203.0.113.42",
            is_https=True,
            cookies={"session_id": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"},
        )

        # Kusursuz güvenli referans HTTP yanıtı
        self.clean_response = HttpResponse(
            status_code=200,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Cache-Control": "no-store, no-cache, must-revalidate",
            },
            body='{"status":"success","transaction_id":"TX-10928"}',
            cookies=[
                CookieSpec(
                    name="session_id",
                    value="9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
                    secure=True,
                    httponly=True,
                    samesite="Strict",
                    path="/",
                    max_age=3600,
                )
            ],
        )

    def test_01_clean_https_request_and_hardened_response(self):
        """Kusursuz güvenli akışın 100 tam puan aldığını ve güvenli onaylandığını doğrular."""
        report = self.engine.full_audit(self.clean_request, self.clean_response)
        self.assertEqual(report.overall_score, 100.0)
        self.assertTrue(report.is_secure)
        self.assertEqual(len(report.request_violations), 0)
        self.assertTrue(report.header_audit.hsts_valid)
        self.assertEqual(len(report.header_audit.disclosed_server_tokens), 0)

    def test_02_insecure_http_transport_violation(self):
        """Şifresiz HTTP isteğinde kritik InsecureTransport ihlali üretildiğini doğrular."""
        req = HttpRequest(**self.clean_request.__dict__)
        req.is_https = False
        violations = self.engine.audit_request(req)
        self.assertTrue(any(v.violation_type == "InsecureTransport" for v in violations))
        crit_v = [v for v in violations if v.violation_type == "InsecureTransport"][0]
        self.assertEqual(crit_v.severity, ViolationSeverity.CRITICAL)

    def test_03_invalid_http_method_tampering(self):
        """Standart dışı veya küçük harfli HTTP yöntemlerinin tespit edildiğini test eder."""
        req = HttpRequest(**self.clean_request.__dict__)
        req.method = "post"  # Küçük harfli veya TRACE
        violations = self.engine.audit_request(req)
        self.assertTrue(any(v.violation_type == "InvalidHttpMethod" for v in violations))

    def test_04_path_traversal_in_url(self):
        """İstek yolunda dizin geçiş kalıplarının tespit edildiğini doğrular."""
        req = HttpRequest(**self.clean_request.__dict__)
        req.path = "/static/../../etc/passwd"
        violations = self.engine.audit_request(req)
        self.assertTrue(any(v.violation_type == "PathTraversalAttempt" for v in violations))

    def test_05_sensitive_data_in_query_parameters(self):
        """URL parametrelerinde parola veya token taşınmasının engellendiğini test eder."""
        req = HttpRequest(**self.clean_request.__dict__)
        req.query_params = {"user": "admin", "password": "SecretPassword123!"}
        violations = self.engine.audit_request(req)
        self.assertTrue(any(v.violation_type == "SensitiveDataInQueryString" for v in violations))

    def test_06_client_side_trust_role_manipulation(self):
        """İstemciden rol (role=admin) gönderilmesinin kritik ihlal sayıldığını test eder."""
        req = HttpRequest(**self.clean_request.__dict__)
        req.body = {"username": "john", "role": "admin"}
        violations = self.engine.audit_request(req)
        self.assertTrue(any(v.violation_type == "ClientSideTrustAssumption" for v in violations))

    def test_07_client_side_trust_price_manipulation(self):
        """İstemciden fiyat veya indirim gönderilmesinin güven sınırı ihlali olduğunu doğrular."""
        req = HttpRequest(**self.clean_request.__dict__)
        req.body = {"item_id": 105, "price": 0.01, "discount": 99.0}
        violations = self.engine.audit_request(req)
        self.assertTrue(any(v.violation_type == "ClientSideTrustAssumption" for v in violations))

    def test_08_hsts_missing_and_invalid_detection(self):
        """HSTS başlığı eksik olduğunda veya yetersiz sürede başlık puanının düştüğünü test eder."""
        res = HttpResponse(status_code=200, headers={})
        audit = self.engine.audit_response(res)
        self.assertFalse(audit.hsts_present)
        self.assertLess(audit.score, 80.0)

    def test_09_csp_missing_or_unsafe_inline(self):
        """CSP başlığında unsafe-inline kullanılmasının ceza puanı aldığını doğrular."""
        res = HttpResponse(
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline';",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            }
        )
        audit = self.engine.audit_response(res)
        self.assertTrue(audit.csp_has_unsafe_inline)
        self.assertLess(audit.score, 100.0)

    def test_10_clickjacking_and_mime_sniffing_headers(self):
        """X-Frame-Options ve X-Content-Type-Options başlıklarının varlığının denetlendiğini kontrol eder."""
        res = HttpResponse(
            status_code=200,
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            }
        )
        audit = self.engine.audit_response(res)
        self.assertTrue(audit.x_frame_options_present)
        self.assertTrue(audit.x_content_type_options_present)

    def test_11_server_information_disclosure(self):
        """Server ve X-Powered-By başlıklarının bilgi ifşası olarak işaretlendiğini doğrular."""
        res = HttpResponse(
            status_code=200,
            headers={
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3",
            }
        )
        audit = self.engine.audit_response(res)
        self.assertEqual(len(audit.disclosed_server_tokens), 2)
        self.assertTrue(any("Apache" in tok for tok in audit.disclosed_server_tokens))

    def test_12_cookie_missing_secure_flag(self):
        """Secure bayrağı olmayan çerezin ceza aldığını doğrular."""
        bad_cookie = CookieSpec(name="session_id", value="1234567890abcdef", secure=False, httponly=True)
        audits = self.engine.audit_cookies([bad_cookie], is_https=True)
        self.assertEqual(len(audits), 1)
        self.assertFalse(audits[0].secure_valid)
        self.assertLess(audits[0].cookie_score, 70.0)

    def test_13_cookie_missing_httponly_and_samesite(self):
        """HttpOnly ve SameSite bayraklarının eksikliğinin tespit edildiğini test eder."""
        bad_cookie = CookieSpec(name="session_token", value="token1234567890abcdef", secure=True, httponly=False, samesite="None")
        audits = self.engine.audit_cookies([bad_cookie], is_https=True)
        self.assertFalse(audits[0].httponly_valid)
        self.assertFalse(audits[0].samesite_valid)
        self.assertLess(audits[0].cookie_score, 50.0)

    def test_14_harden_response_cleans_and_injects_headers(self):
        """harden_response fonksiyonunun başlıkları ve çerezleri eksiksiz düzelttiğini doğrular."""
        vuln_response = HttpResponse(
            status_code=200,
            headers={
                "Server": "nginx/1.18.0",
                "X-Powered-By": "Express",
            },
            cookies=[CookieSpec(name="auth_token", value="weak123", secure=False, httponly=False, samesite="None")]
        )
        hardened = self.engine.harden_response(vuln_response)
        
        # Bilgi ifşası temizlenmiş olmalı
        self.assertNotIn("Server", hardened.headers)
        self.assertNotIn("X-Powered-By", hardened.headers)
        
        # Güvenlik başlıkları eklenmiş olmalı
        self.assertIn("Strict-Transport-Security", hardened.headers)
        self.assertIn("Content-Security-Policy", hardened.headers)
        self.assertIn("X-Frame-Options", hardened.headers)
        self.assertIn("X-Content-Type-Options", hardened.headers)
        
        # Çerezler sertleştirilmiş olmalı
        self.assertTrue(hardened.cookies[0].secure)
        self.assertTrue(hardened.cookies[0].httponly)
        self.assertEqual(hardened.cookies[0].samesite, "Lax")

    def test_15_nginx_config_generation(self):
        """Nginx güvenlik yapılandırma çıktısının anahtar direktifleri içerdiğini test eder."""
        conf = self.engine.generate_nginx_security_config()
        self.assertIn("Strict-Transport-Security", conf)
        self.assertIn("Content-Security-Policy", conf)
        self.assertIn("server_tokens off;", conf)
        self.assertIn("X-Frame-Options", conf)


if __name__ == "__main__":
    unittest.main()
