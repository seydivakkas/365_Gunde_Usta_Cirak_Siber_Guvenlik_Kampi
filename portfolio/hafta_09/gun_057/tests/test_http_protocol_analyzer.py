# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G057 - HTTP İstek ve Yanıt Yapısı Test Süiti.
14 Adet Kapsamlı Birim, Entegrasyon, Güvenlik Zafiyeti ve Negatif Sınır Testi.
"""

# Standart birim test kütüphanesi
import unittest
# Test veri dosyalarını okumak için json modülü
import json
# Dosya yolları yönetimi için pathlib
from pathlib import Path

# Test edilecek HTTP protokol analiz motorundan bileşenler içe aktarılır
from portfolio.hafta_09.gun_057.uygulama.http_protocol_analyzer import (
    HTTPRequest,
    HTTPResponse,
    HTTPSecurityAuditor,
    HTTPParsingError,
    HTTPSecurityViolation
)


class TestHTTPProtocolAnalyzer(unittest.TestCase):
    """HTTP/1.1 protokol ayrıştırma, serileştirme ve güvenlik denetimi test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz test ortamını ve örnek veri dosyasını hazırlar."""
        self.sample_file = Path("portfolio/hafta_09/gun_057/ornek_veri/sample_http_messages.json")
        with open(self.sample_file, "r", encoding="utf-8") as f:
            self.samples = json.load(f)["mesajlar"]

    def test_01_valid_get_request_parsing_and_serialization(self) -> None:
        """Test 1: Standart HTTP/1.1 GET isteğinin ayrıştırılması ve geri kablo formatına serileştirilmesi."""
        raw_get = self.samples["gecerli_get_istegi"]["ham_metin"]
        # Ham metinden nesne ayrıştırılır
        req = HTTPRequest.parse(raw_get)
        # Metot, yol ve sürüm doğrulanır
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.path, "/api/v1/users?role=analyst")
        self.assertEqual(req.version, "HTTP/1.1")
        self.assertEqual(req.headers["Host"], "api.kurum.local")
        self.assertEqual(req.content_length, 0)
        # Serileştirme çıktısı çift CRLF ile bitmelidir
        serialized = req.serialize()
        self.assertTrue(serialized.startswith("GET /api/v1/users?role=analyst HTTP/1.1\r\n"))
        self.assertTrue(serialized.endswith("\r\n\r\n"))

    def test_02_valid_post_request_with_body(self) -> None:
        """Test 2: JSON yükü içeren POST isteğinin ayrıştırılması ve gövde uzunluğunun doğrulanması."""
        raw_post = self.samples["gecerli_post_istegi"]["ham_metin"]
        req = HTTPRequest.parse(raw_post)
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.path, "/api/v1/auth/token")
        self.assertEqual(req.headers["Content-Type"], "application/json")
        self.assertEqual(req.content_length, 46)
        self.assertIn("seydi_analyst", req.body)

    def test_03_http_methods_properties(self) -> None:
        """Test 3: HTTP metotlarının Güvenli (Safe) ve Eşgüçlü (Idempotent) özelliklerinin RFC 7231 denetimi."""
        get_req = HTTPRequest(method="GET", path="/", headers={"Host": "test.local"})
        post_req = HTTPRequest(method="POST", path="/", headers={"Host": "test.local"})
        put_req = HTTPRequest(method="PUT", path="/", headers={"Host": "test.local"})
        del_req = HTTPRequest(method="DELETE", path="/", headers={"Host": "test.local"})

        # GET hem güvenli hem eşgüçlüdür
        self.assertTrue(get_req.is_safe)
        self.assertTrue(get_req.is_idempotent)

        # POST ne güvenli ne de eşgüçlüdür
        self.assertFalse(post_req.is_safe)
        self.assertFalse(post_req.is_idempotent)

        # PUT ve DELETE güvenli değildir ama eşgüçlüdür (idempotent)
        self.assertFalse(put_req.is_safe)
        self.assertTrue(put_req.is_idempotent)
        self.assertFalse(del_req.is_safe)
        self.assertTrue(del_req.is_idempotent)

    def test_04_valid_response_200_ok(self) -> None:
        """Test 4: 200 OK yanıt mesajının ayrıştırılması ve durum kodunun doğrulanması."""
        raw_resp = self.samples["gecerli_200_ok_yaniti"]["ham_metin"]
        resp = HTTPResponse.parse(raw_resp)
        self.assertEqual(resp.version, "HTTP/1.1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.reason_phrase, "OK")
        self.assertEqual(resp.headers["Content-Type"], "application/json; charset=utf-8")
        self.assertIn("authenticated", resp.body)

    def test_05_valid_response_status_codes(self) -> None:
        """Test 5: Farklı HTTP durum kodlarının (201, 301, 404, 500) yanıt modellerinde doğrulanması."""
        r201 = HTTPResponse(status_code=201, reason_phrase="Created")
        r301 = HTTPResponse(status_code=301, reason_phrase="Moved Permanently", headers={"Location": "https://test.local/"})
        r404 = HTTPResponse(status_code=404, reason_phrase="Not Found")
        r500 = HTTPResponse(status_code=500, reason_phrase="Internal Server Error")

        self.assertEqual(r201.status_code, 201)
        self.assertEqual(r301.headers["Location"], "https://test.local/")
        self.assertEqual(r404.status_code, 404)
        self.assertEqual(r500.status_code, 500)

    def test_06_crlf_injection_detection(self) -> None:
        """Test 6: İstemci isteğindeki CRLF enjeksiyonu ve yanıt bölme girişiminin engellenmesi."""
        raw_crlf = self.samples["crlf_enjeksiyonu_ornek"]["ham_metin"]
        req = HTTPRequest.parse(raw_crlf)
        # Denetçi HTTPSecurityViolation fırlatmalıdır
        with self.assertRaises(HTTPSecurityViolation) as ctx:
            HTTPSecurityAuditor.inspect_crlf_injection(req)
        self.assertIn("CRLF Enjeksiyonu Algilandi", str(ctx.exception))

    def test_07_request_smuggling_cl_te_detection(self) -> None:
        """Test 7: Content-Length ve Transfer-Encoding çatışmasıyla HTTP Request Smuggling saldırısının tespiti."""
        raw_smuggle = self.samples["request_smuggling_cl_te"]["ham_metin"]
        req = HTTPRequest.parse(raw_smuggle)
        with self.assertRaises(HTTPSecurityViolation) as ctx:
            HTTPSecurityAuditor.inspect_request_smuggling(req)
        self.assertIn("HTTP Request Smuggling Tehlikesi", str(ctx.exception))

    def test_08_hardened_response_security_headers_audit(self) -> None:
        """Test 8: Sıkılaştırılmış ve OWASP güvenlik başlıkları tam olan sunucu yanıtının 100 puan alması."""
        raw_hardened = self.samples["guvenli_sikilastirilmis_yanit"]["ham_metin"]
        resp = HTTPResponse.parse(raw_hardened)
        audit = HTTPSecurityAuditor.audit_response_security_headers(resp)
        self.assertEqual(audit["guvenlik_skoru"], 100)
        self.assertEqual(len(audit["eksik_guvenlik_basliklari"]), 0)
        self.assertEqual(audit["durum"], "GUVENLI")

    def test_09_vulnerable_response_banner_leak_audit(self) -> None:
        """Test 9: Güvensiz sunucu yanıtında eksik başlıklar ve afiş bilgi sızıntısının (Server banner) tespiti."""
        raw_vuln = self.samples["guvensiz_acik_bilgi_veren_yanit"]["ham_metin"]
        resp = HTTPResponse.parse(raw_vuln)
        audit = HTTPSecurityAuditor.audit_response_security_headers(resp)
        self.assertLess(audit["guvenlik_skoru"], 50)
        self.assertGreater(len(audit["afis_bilgi_sizintisi"]), 0)
        self.assertIn("Server: Apache/2.4.41 (Ubuntu) mod_ssl/2.4.41 OpenSSL/1.1.1f", audit["afis_bilgi_sizintisi"])

    def test_10_risky_http_method_detection(self) -> None:
        """Test 10: XST riskine yol açan TRACE ve dosya manipülasyonu sağlayan PUT metotlarının tespiti."""
        trace_req = HTTPRequest(method="TRACE", path="/", headers={"Host": "test.local"})
        put_req = HTTPRequest(method="PUT", path="/upload.php", headers={"Host": "test.local"})

        trace_risks = HTTPSecurityAuditor.inspect_risky_methods(trace_req)
        put_risks = HTTPSecurityAuditor.inspect_risky_methods(put_req)

        self.assertTrue(any("TRACE" in r for r in trace_risks))
        self.assertTrue(any("PUT" in r for r in put_risks))

    def test_11_negative_empty_or_malformed_request_line(self) -> None:
        """Test 11 (Negatif): Boş mesaj ve 3 parçadan oluşmayan bozuk istek satırında HTTPParsingError fırlatılması."""
        with self.assertRaises(HTTPParsingError) as ctx:
            HTTPRequest.parse("")
        self.assertIn("HTTP mesaji bos olamaz", str(ctx.exception))

        with self.assertRaises(HTTPParsingError) as ctx:
            HTTPRequest.parse("GET /index.html\r\nHost: test.local\r\n\r\n")
        self.assertIn("Gecersiz HTTP istek satiri", str(ctx.exception))

    def test_12_negative_unsupported_method_and_version(self) -> None:
        """Test 12 (Negatif): Standart dışı HTTP metodu ve desteklenmeyen HTTP versiyonunun reddedilmesi."""
        with self.assertRaises(HTTPParsingError) as ctx:
            HTTPRequest.parse("HACK /api HTTP/1.1\r\nHost: test.local\r\n\r\n")
        self.assertIn("Desteklenmeyen veya gecersiz HTTP metodu", str(ctx.exception))

        with self.assertRaises(HTTPParsingError) as ctx:
            HTTPRequest.parse("GET / HTTP/9.9\r\nHost: test.local\r\n\r\n")
        self.assertIn("Desteklenmeyen HTTP versiyonu", str(ctx.exception))

    def test_13_negative_missing_host_header_in_http11(self) -> None:
        """Test 13 (Negatif): RFC 7230 gereği HTTP/1.1 isteklerinde Host başlığı yoksa 400 Bad Request hatası."""
        bad_req = "GET /index.html HTTP/1.1\r\nUser-Agent: Scanner\r\n\r\n"
        with self.assertRaises(HTTPParsingError) as ctx:
            HTTPRequest.parse(bad_req)
        self.assertIn("zorunlu 'Host' basligi bulunamadi", str(ctx.exception))

    def test_14_negative_invalid_status_code_and_negative_content_length(self) -> None:
        """Test 14 (Negatif): 100-599 dışındaki geçersiz durum kodu ve negatif Content-Length denetimi."""
        with self.assertRaises(HTTPParsingError):
            HTTPResponse(status_code=999)

        neg_cl = "POST /data HTTP/1.1\r\nHost: test.local\r\nContent-Length: -50\r\n\r\n"
        with self.assertRaises(HTTPParsingError) as ctx:
            HTTPRequest.parse(neg_cl)
        self.assertIn("Gecersiz Content-Length degeri", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
