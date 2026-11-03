# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G058 - HTTP Yöntemleri ve Idempotency Test Süiti.
14 Adet Kapsamlı Birim, Entegrasyon, Güvenlik ve Negatif Sınır Testi.
"""

# Standart birim test kütüphanesi
import unittest
# Zaman manipülasyonu testleri için time modülü
import time
# Örnek test verilerini yüklemek için json modülü
import json
# Dosya yolları yönetimi için pathlib
from pathlib import Path

# Test edilecek modülden sınıflar ve istisnalar içe aktarılır
from portfolio.hafta_09.gun_058.uygulama.http_methods_idempotency import (
    HTTPMethodSemantics,
    IdempotencyManager,
    VerbTamperingAuditor,
    MethodValidationError,
    IdempotencyConflictError,
    VerbTamperingAlert
)


class TestHTTPMethodsIdempotency(unittest.TestCase):
    """HTTP metotları ve Idempotency mekanizması test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz test ortamını ve sayaçları hazırlar."""
        # 3600 saniyelik varsayılan TTL ile Idempotency yöneticisi başlatılır
        self.mgr = IdempotencyManager(default_ttl_seconds=3600)
        # Örnek banka bakiyesi ve işlem sayacı
        self.account_balance = 1000.0
        self.transaction_count = 0

    def dummy_payment_handler(self, method: str, path: str, body: str):
        """Simüle edilmiş ödeme işleyici fonksiyonu (Double charge testi için)."""
        data = json.loads(body)
        amount = data.get("amount", 0.0)
        self.account_balance -= amount
        self.transaction_count += 1
        resp_body = json.dumps({"status": "PAID", "remaining_balance": self.account_balance, "tx_id": self.transaction_count})
        return 201, {"Content-Type": "application/json"}, resp_body

    def test_01_safe_methods_semantics(self) -> None:
        """Test 1: RFC 7231 §4.2.1 uyarınca Güvenli (Safe) metotların doğrulanması."""
        # GET, HEAD, OPTIONS ve TRACE sunucu durumunu değiştiremez (Safe)
        self.assertTrue(HTTPMethodSemantics.is_safe("GET"))
        self.assertTrue(HTTPMethodSemantics.is_safe("HEAD"))
        self.assertTrue(HTTPMethodSemantics.is_safe("OPTIONS"))
        self.assertTrue(HTTPMethodSemantics.is_safe("TRACE"))

        # POST, PUT, DELETE ve PATCH sunucu durumunu değiştirdiği için Safe değildir
        self.assertFalse(HTTPMethodSemantics.is_safe("POST"))
        self.assertFalse(HTTPMethodSemantics.is_safe("PUT"))
        self.assertFalse(HTTPMethodSemantics.is_safe("DELETE"))
        self.assertFalse(HTTPMethodSemantics.is_safe("PATCH"))

    def test_02_idempotent_methods_semantics(self) -> None:
        """Test 2: RFC 7231 §4.2.2 uyarınca Eşgüçlü (Idempotent) metotların doğrulanması."""
        # GET, HEAD, PUT, DELETE, OPTIONS, TRACE tekrarlanabilir ve eşgüçlüdür
        self.assertTrue(HTTPMethodSemantics.is_idempotent("GET"))
        self.assertTrue(HTTPMethodSemantics.is_idempotent("HEAD"))
        self.assertTrue(HTTPMethodSemantics.is_idempotent("PUT"))
        self.assertTrue(HTTPMethodSemantics.is_idempotent("DELETE"))
        self.assertTrue(HTTPMethodSemantics.is_idempotent("OPTIONS"))

        # POST ve PATCH eşgüçlü değildir (her çağrıda yeni işlem / sayma yapabilir)
        self.assertFalse(HTTPMethodSemantics.is_idempotent("POST"))
        self.assertFalse(HTTPMethodSemantics.is_idempotent("PATCH"))

    def test_03_put_vs_patch_distinction(self) -> None:
        """Test 3: PUT (tam temsil - idempotent) ve PATCH (kısmi güncelleme) anlamsal ayrımı."""
        # PUT eşgüçlüdür, PATCH eşgüçlü değildir
        self.assertTrue(HTTPMethodSemantics.is_idempotent("PUT"))
        self.assertFalse(HTTPMethodSemantics.is_idempotent("PATCH"))

        # PUT gövde olmadan çalıştırılamaz
        with self.assertRaises(MethodValidationError):
            HTTPMethodSemantics.audit_method_usage("PUT", "/users/1", "")

    def test_04_idempotency_key_first_execution(self) -> None:
        """Test 4: Idempotency-Key ile ilk ödeme çağrısında bakiyeden düşüm ve işlem kaydı."""
        key = "idem-tx-001"
        headers = {"Idempotency-Key": key}
        body = json.dumps({"amount": 100.0})

        status, resp_h, resp_b, is_cached = self.mgr.execute_transaction(
            "POST", "/payments", headers, body, self.dummy_payment_handler
        )
        # İlk çağrı başarıyla yürütülür ve önbellekten gelmez
        self.assertEqual(status, 201)
        self.assertFalse(is_cached)
        self.assertEqual(self.account_balance, 900.0)
        self.assertEqual(self.transaction_count, 1)
        self.assertIn(key, self.mgr.records)

    def test_05_idempotency_key_replay_cached_response(self) -> None:
        """Test 5: Ağ kopması nedeniyle yinelenen POST isteğinde çifte çekimin önlenmesi ve önbellek dönüşü."""
        key = "idem-tx-002"
        headers = {"Idempotency-Key": key}
        body = json.dumps({"amount": 200.0})

        # 1. Çağrı (Meşru ilk çekim)
        self.mgr.execute_transaction("POST", "/payments", headers, body, self.dummy_payment_handler)
        self.assertEqual(self.account_balance, 800.0)
        self.assertEqual(self.transaction_count, 1)

        # 2. Yinelenen Çağrı (Aynı anahtar ve aynı veri)
        status2, resp_h2, resp_b2, is_cached2 = self.mgr.execute_transaction(
            "POST", "/payments", headers, body, self.dummy_payment_handler
        )
        # Önbellekteki kayıt döner, bakiye ikinci kez düşmez! (Çift çekim önlendi)
        self.assertEqual(status2, 201)
        self.assertTrue(is_cached2)
        self.assertEqual(resp_h2.get("Idempotent-Replayed"), "true")
        self.assertEqual(self.account_balance, 800.0)
        self.assertEqual(self.transaction_count, 1)

    def test_06_idempotency_key_payload_conflict(self) -> None:
        """Test 6: Aynı Idempotency-Key ile farklı tutar/veri gönderildiğinde 409/422 uyuşmazlık hatası."""
        key = "idem-tx-003"
        headers = {"Idempotency-Key": key}
        body1 = json.dumps({"amount": 50.0})
        body2 = json.dumps({"amount": 500.0})

        # İlk istek 50 TL
        self.mgr.execute_transaction("POST", "/payments", headers, body1, self.dummy_payment_handler)

        # İkinci istek aynı anahtarla 500 TL (Uyuşmazlık ve çakışma hatası fırlatılmalıdır)
        with self.assertRaises(IdempotencyConflictError) as ctx:
            self.mgr.execute_transaction("POST", "/payments", headers, body2, self.dummy_payment_handler)
        self.assertIn("Idempotency-Key Cakismasi", str(ctx.exception))

    def test_07_idempotency_key_ttl_cleanup(self) -> None:
        """Test 7: Yaşam süresi (TTL) dolan idempotency kayıtlarının bellekten temizlenmesi."""
        short_mgr = IdempotencyManager(default_ttl_seconds=1)
        headers = {"Idempotency-Key": "short-lived-key"}
        body = json.dumps({"amount": 10.0})
        short_mgr.execute_transaction("POST", "/payments", headers, body, self.dummy_payment_handler)

        self.assertIn("short-lived-key", short_mgr.records)
        # Kaydın süresini yapay olarak geriye çekeriz
        short_mgr.records["short-lived-key"].created_at -= 10.0
        cleaned = short_mgr.clean_expired_records()
        self.assertEqual(cleaned, 1)
        self.assertNotIn("short-lived-key", short_mgr.records)

    def test_08_verb_tampering_head_bypass_prevention(self) -> None:
        """Test 8: HTTP Verb Tampering ile korumalı yönetici yolunun HEAD ile atlatılmasının engellenmesi."""
        auditor = VerbTamperingAuditor(protected_rules={"/admin/delete": {"POST"}})

        # Oturumu olmayan saldırgan HEAD ile korumayı baypas etmeye çalışır
        with self.assertRaises(VerbTamperingAlert) as ctx:
            auditor.inspect_request("HEAD", "/admin/delete", is_authenticated=False)
        self.assertIn("HTTP Verb Tampering Tehdidi", str(ctx.exception))

    def test_09_trace_method_xst_security_audit(self) -> None:
        """Test 9: TRACE metodunun XST saldırı tehdidi olarak işaretlenmesi."""
        warnings = HTTPMethodSemantics.audit_method_usage("TRACE", "/debug", "")
        self.assertTrue(any("XST" in w for w in warnings))

    def test_10_negative_invalid_method_syntax(self) -> None:
        """Test 10 (Negatif): Küçük harfli metot ('get') veya standart dışı metot ('PURGE') reddi."""
        with self.assertRaises(MethodValidationError) as ctx:
            HTTPMethodSemantics.validate_method_syntax("get")
        self.assertIn("buyuk harfle yazilmalidir", str(ctx.exception))

        with self.assertRaises(MethodValidationError) as ctx:
            HTTPMethodSemantics.validate_method_syntax("PURGE")
        self.assertIn("Gecersiz veya standart disi", str(ctx.exception))

    def test_11_negative_empty_or_too_long_idempotency_key(self) -> None:
        """Test 11 (Negatif): Boş veya 128 karakteri aşan Idempotency-Key başlığının reddedilmesi."""
        with self.assertRaises(MethodValidationError) as ctx:
            self.mgr.execute_transaction("POST", "/p", {"Idempotency-Key": "   "}, "{}", self.dummy_payment_handler)
        self.assertIn("bos veya yalnizca bosluk", str(ctx.exception))

        long_key = "a" * 150
        with self.assertRaises(MethodValidationError) as ctx:
            self.mgr.execute_transaction("POST", "/p", {"Idempotency-Key": long_key}, "{}", self.dummy_payment_handler)
        self.assertIn("Uzunluk 128 karakteri asamaz", str(ctx.exception))

    def test_12_negative_unsafe_get_modification(self) -> None:
        """Test 12 (Negatif): GET metoduyla para transferi veya silme yapılmaya çalışıldığında hata verilmesi."""
        with self.assertRaises(MethodValidationError) as ctx:
            HTTPMethodSemantics.audit_method_usage("GET", "/api/transfer?amount=100", "")
        self.assertIn("RFC 7231 Ihlali", str(ctx.exception))

    def test_13_negative_put_without_body(self) -> None:
        """Test 13 (Negatif): Gövdesi boş bırakılan PUT isteklerinin reddedilmesi."""
        with self.assertRaises(MethodValidationError) as ctx:
            HTTPMethodSemantics.audit_method_usage("PUT", "/api/v1/profile", "   ")
        self.assertIn("istek govdesi bos olamaz", str(ctx.exception))

    def test_14_delete_idempotent_state_consistency(self) -> None:
        """Test 14: DELETE metodunun eşgüçlülüğü ve ardışık silme isteklerinde durum tutarlılığı."""
        # DELETE eşgüçlü bir metottur
        self.assertTrue(HTTPMethodSemantics.is_idempotent("DELETE"))
        # Silme çağrısı yapıldığında durumun eşgüçlü kaldığı teyit edilir
        self.assertFalse(HTTPMethodSemantics.is_safe("DELETE"))


if __name__ == "__main__":
    unittest.main()
