# -*- coding: utf-8 -*-
"""
HTTP Cookies ve Güvenlik Bayrakları Birim Test Paketi (15 Test)
Hafta 23 / Gün 157 - Aşama 7 (Web Güvenliği)

Bu test paketi; Secure, HttpOnly, SameSite (Strict/Lax/None), RFC 6265bis
önekleri (__Host-, __Secure-), çerez ömrü ve hassas veri sızıntısı denetimlerini
15 bağımsız senaryoda doğrular.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.cookie_security_engine import (
    CookieSecurityEngine,
    HttpCookie,
    SameSitePolicy,
    CookieType,
    CookiePrefix,
    FleetCookieReport
)


class TestCookieSecurityEngine(unittest.TestCase):
    """CookieSecurityEngine sınıfının tüm fonksiyonlarını test eden sınıf."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        self.engine = CookieSecurityEngine()

    def test_01_fully_compliant_host_session_cookie(self):
        """Kusursuz __Host- önekli oturum çerezinin 100 tam puanla geçtiğini doğrular."""
        cookie = HttpCookie(
            name="__Host-session_id",
            value="a8f5e9c1d2e3b4a5f6e7d8c9b0a1f2e3",
            secure=True,
            http_only=True,
            same_site=SameSitePolicy.STRICT,
            domain=None,
            path="/",
            max_age=86400,
            cookie_type=CookieType.SESSION_AUTH,
            is_encrypted_or_opaque=True
        )
        report = self.engine.audit_cookie(cookie)
        self.assertEqual(report.security_score, 100.0)
        self.assertEqual(report.status, "GECTI")
        self.assertEqual(len(report.issues), 0)

    def test_02_missing_secure_flag_session_cookie(self):
        """Oturum çerezinde Secure bayrağı eksikliğinin kritik ceza aldığını test eder."""
        cookie = HttpCookie(
            name="auth_token",
            value="token123",
            secure=False,
            http_only=True,
            same_site=SameSitePolicy.LAX,
            cookie_type=CookieType.SESSION_AUTH
        )
        report = self.engine.audit_cookie(cookie)
        self.assertLess(report.security_score, 80.0)
        self.assertEqual(report.status, "KALDI")
        issue_codes = [i.code for i in report.issues]
        self.assertIn("MISSING_SECURE_FLAG", issue_codes)

    def test_03_missing_httponly_flag_session_cookie(self):
        """Oturum çerezinde HttpOnly eksikliğinin yüksek risk cezası aldığını doğrular."""
        cookie = HttpCookie(
            name="session_key",
            value="abc456",
            secure=True,
            http_only=False,
            same_site=SameSitePolicy.STRICT,
            cookie_type=CookieType.SESSION_AUTH
        )
        report = self.engine.audit_cookie(cookie)
        self.assertLess(report.security_score, 80.0)
        self.assertEqual(report.status, "KALDI")
        issue_codes = [i.code for i in report.issues]
        self.assertIn("MISSING_HTTPONLY_FLAG", issue_codes)

    def test_04_missing_samesite_policy(self):
        """SameSite bayrağı tanımlanmamış çerezin ceza aldığını doğrular."""
        cookie = HttpCookie(
            name="pref_theme",
            value="dark",
            secure=True,
            http_only=False,
            same_site=SameSitePolicy.MISSING,
            cookie_type=CookieType.PREFERENCE
        )
        report = self.engine.audit_cookie(cookie)
        issue_codes = [i.code for i in report.issues]
        self.assertIn("MISSING_SAMESITE_FLAG", issue_codes)

    def test_05_samesite_none_without_secure(self):
        """SameSite=None politikasının Secure olmadan kullanılmasının kritik hata olduğunu doğrular."""
        cookie = HttpCookie(
            name="cross_site_tracker",
            value="track999",
            secure=False,
            http_only=False,
            same_site=SameSitePolicy.NONE,
            cookie_type=CookieType.TRACKING
        )
        report = self.engine.audit_cookie(cookie)
        self.assertEqual(report.status, "KALDI")
        issue_codes = [i.code for i in report.issues]
        self.assertIn("SAMESITE_NONE_WITHOUT_SECURE", issue_codes)

    def test_06_samesite_none_with_secure_valid(self):
        """SameSite=None ile Secure birlikte kullanıldığında tarayıcı reddi oluşmadığını test eder."""
        cookie = HttpCookie(
            name="b2b_widget_session",
            value="secure_external_token",
            secure=True,
            http_only=True,
            same_site=SameSitePolicy.NONE,
            cookie_type=CookieType.SESSION_AUTH
        )
        report = self.engine.audit_cookie(cookie)
        issue_codes = [i.code for i in report.issues]
        self.assertNotIn("SAMESITE_NONE_WITHOUT_SECURE", issue_codes)

    def test_07_invalid_host_prefix_with_domain(self):
        """__Host- çerezinde Domain özniteliği bulunmasının ihlal olduğunu test eder."""
        cookie = HttpCookie(
            name="__Host-session",
            value="token_val",
            secure=True,
            http_only=True,
            same_site=SameSitePolicy.STRICT,
            domain="bank.example.com",  # __Host- çerezinde Domain YASAKTIR!
            path="/"
        )
        report = self.engine.audit_cookie(cookie)
        self.assertEqual(report.status, "KALDI")
        issue_codes = [i.code for i in report.issues]
        self.assertIn("INVALID_HOST_PREFIX_USAGE", issue_codes)

    def test_08_invalid_host_prefix_non_root_path(self):
        """__Host- çerezinde Path='/' dışında bir yol bulunmasının ihlal olduğunu test eder."""
        cookie = HttpCookie(
            name="__Host-api_key",
            value="secret123",
            secure=True,
            http_only=True,
            same_site=SameSitePolicy.STRICT,
            domain=None,
            path="/api/v1"  # Path='/' olmak zorundadır!
        )
        report = self.engine.audit_cookie(cookie)
        issue_codes = [i.code for i in report.issues]
        self.assertIn("INVALID_HOST_PREFIX_USAGE", issue_codes)

    def test_09_invalid_secure_prefix_without_secure(self):
        """__Secure- çerezinde Secure=False olmasının ihlal oluşturduğunu test eder."""
        cookie = HttpCookie(
            name="__Secure-user_id",
            value="usr_882",
            secure=False,  # __Secure- mutlaka Secure=True olmalıdır
            http_only=True,
            same_site=SameSitePolicy.LAX
        )
        report = self.engine.audit_cookie(cookie)
        issue_codes = [i.code for i in report.issues]
        self.assertIn("INVALID_SECURE_PREFIX_USAGE", issue_codes)

    def test_10_broad_domain_wildcard_penalty(self):
        """Geniş etki alanı (örn: .example.com) tanımlamasının ceza aldığını doğrular."""
        cookie = HttpCookie(
            name="sso_token",
            value="sso_val_123",
            secure=True,
            http_only=True,
            same_site=SameSitePolicy.LAX,
            domain=".corporate.corp"  # Geniş domain tüm subdomainleri riske atar
        )
        report = self.engine.audit_cookie(cookie)
        issue_codes = [i.code for i in report.issues]
        self.assertIn("BROAD_DOMAIN_SCOPE", issue_codes)

    def test_11_excessive_max_age_penalty(self):
        """Oturum çerezinde 1 yıllık aşırı Max-Age değerinin ceza aldığını test eder."""
        cookie = HttpCookie(
            name="persistent_session",
            value="token_infinite",
            secure=True,
            http_only=True,
            same_site=SameSitePolicy.STRICT,
            max_age=31536000,  # 1 yıl = 31.536.000 saniye (aşırı)
            cookie_type=CookieType.SESSION_AUTH
        )
        report = self.engine.audit_cookie(cookie)
        issue_codes = [i.code for i in report.issues]
        self.assertIn("EXCESSIVE_COOKIE_LIFESPAN", issue_codes)

    def test_12_plaintext_sensitive_data_in_cookie(self):
        """Çerez değeri içerisinde 'role=admin' veya 'password=' bulunmasının ceza aldığını doğrular."""
        cookie = HttpCookie(
            name="user_profile",
            value="id=42&role=admin&auth=true",
            secure=True,
            http_only=True,
            same_site=SameSitePolicy.STRICT
        )
        report = self.engine.audit_cookie(cookie)
        issue_codes = [i.code for i in report.issues]
        self.assertIn("PLAINTEXT_SENSITIVE_DATA", issue_codes)

    def test_13_auto_hardening_fixes_all_vulnerabilities(self):
        """Sertleştirme fonksiyonunun zafiyetli çerezi tam uyumlu hale getirdiğini doğrular."""
        vulnerable_cookie = HttpCookie(
            name="insecure_session",
            value="simple_opaque_hash_val",
            secure=False,
            http_only=False,
            same_site=SameSitePolicy.MISSING,
            domain=".company.local",
            max_age=99999999,
            cookie_type=CookieType.SESSION_AUTH
        )
        hardened = self.engine.harden_cookie(vulnerable_cookie)
        
        # Sertleştirilmiş çerezi denetleme
        hardened_report = self.engine.audit_cookie(hardened)
        self.assertEqual(hardened_report.security_score, 100.0)
        self.assertEqual(hardened_report.status, "GECTI")
        self.assertTrue(hardened.name.startswith("__Host-"))
        self.assertTrue(hardened.secure)
        self.assertTrue(hardened.http_only)
        self.assertEqual(hardened.same_site, SameSitePolicy.STRICT)
        self.assertIsNone(hardened.domain)

    def test_14_parse_set_cookie_header_roundtrip(self):
        """Set-Cookie başlık metninin doğru ayrıştırıldığını ve yeniden üretildiğini doğrular."""
        header = "session_id=opaque123; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=86400"
        cookie = HttpCookie.parse_set_cookie_header(header, cookie_type=CookieType.SESSION_AUTH)
        
        self.assertEqual(cookie.name, "session_id")
        self.assertEqual(cookie.value, "opaque123")
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, SameSitePolicy.STRICT)
        self.assertEqual(cookie.max_age, 86400)
        self.assertEqual(cookie.path, "/")

    def test_15_fleet_audit_and_ascii_generation(self):
        """Çoklu çerez envanteri denetiminin ve ASCII pano çıktısının doğrulanması."""
        c1 = HttpCookie(name="__Host-auth", value="h1", secure=True, http_only=True, same_site=SameSitePolicy.STRICT)
        c2 = HttpCookie(name="csrf_tok", value="c2", secure=True, http_only=False, same_site=SameSitePolicy.LAX, cookie_type=CookieType.CSRF_TOKEN)
        
        fleet_rep = self.engine.audit_fleet([c1, c2])
        self.assertEqual(fleet_rep.total_cookies, 2)
        self.assertEqual(fleet_rep.compliant_cookies_count, 2)
        self.assertEqual(fleet_rep.overall_status, "GECTI")
        
        ascii_out = self.engine.generate_ascii_audit(fleet_rep)
        self.assertIn("HTTP ÇEREZLERİ VE GÜVENLİK BAYRAKLARI DENETİM RAPORU", ascii_out)
        self.assertIn("__Host-auth", ascii_out)


if __name__ == "__main__":
    unittest.main()
