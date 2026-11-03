# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G080: Hata Yönetimi ve Özel Durumlar Test Paketi (14 Birim Test)
"""

# Birim test çerçevesi için Python standart unittest modülünü içeri aktarıyoruz.
import unittest

# Test edilecek güvenlik istisnalarını ve geçit motorunu içeri aktarıyoruz.
from portfolio.hafta_12.gun_080.uygulama.secure_exception_and_error_handler import (
    AuthenticationFailureException,
    AuthorizationDeniedException,
    DefensiveSecurityGateway,
    InputSanitizationException,
    RateLimitExceededException,
    SecureErrorHandler,
    SecureResourceContext,
    SecurityException,
    SecurityResourceException,
)


class TestSecureExceptionAndErrorHandler(unittest.TestCase):
    """
    Hata yönetimi, özel durum hiyerarşisi ve fail-closed mimarisini doğrulayan test sınıfı.
    """

    def setUp(self) -> None:
        """
        Her test öncesinde bağımsız hata işleyici ve güvenlik geçidi nesnelerini hazırlar.
        """
        # Hata işleyici nesnesini başlatıyoruz.
        self.handler = SecureErrorHandler()
        # Güvenlik geçidi nesnesini başlatıyoruz.
        self.gateway = DefensiveSecurityGateway(self.handler)

    def test_01_security_exception_base_incident_id(self) -> None:
        """
        SecurityException sınıfının benzersiz olay referans kodu ve zaman damgası ürettiğini doğrular.
        """
        # Örnek temel istisna oluşturuyoruz.
        exc = SecurityException("Test güvenlik uyarısı")
        # incident_id alanının varlığını sınıyoruz.
        self.assertTrue(exc.incident_id.startswith("SEC-ERR-"))
        # Zaman damgası alanının boş olmadığını teyit ediyoruz.
        self.assertIsNotNone(exc.timestamp)
        # Mesaj alanının doğru saklandığını kontrol ediyoruz.
        self.assertEqual(exc.message, "Test güvenlik uyarısı")

    def test_02_custom_exception_subclasses_hierarchy(self) -> None:
        """
        Tüm özel güvenlik istisnalarının SecurityException temel sınıfından türediğini doğrular.
        """
        # Kimlik doğrulama istisnasının miras hiyerarşisini sınıyoruz.
        self.assertTrue(issubclass(AuthenticationFailureException, SecurityException))
        # Yetkilendirme istisnasının miras hiyerarşisini sınıyoruz.
        self.assertTrue(issubclass(AuthorizationDeniedException, SecurityException))
        # Girdi temizleme istisnasının miras hiyerarşisini sınıyoruz.
        self.assertTrue(issubclass(InputSanitizationException, SecurityException))
        # Hız sınırı istisnasının miras hiyerarşisini sınıyoruz.
        self.assertTrue(issubclass(RateLimitExceededException, SecurityException))
        # Kaynak yönetimi istisnasının miras hiyerarşisini sınıyoruz.
        self.assertTrue(issubclass(SecurityResourceException, SecurityException))

    def test_03_sanitize_log_message_removes_crlf_and_ansi(self) -> None:
        """
        Hata mesajındaki satır başı ve kontrol karakterlerinin log zehirlenmesine karşı temizlendiğini sınar.
        """
        # CRLF ve kaçış karakterleri içeren zararlı log girdisi hazırlıyoruz.
        poisoned_msg = "KritikHata\r\n[INFO] 2026-11-01 Admin oturum açtı\x1b[31m"
        # Mesajı temizleme fonksiyonundan geçiriyoruz.
        sanitized = self.handler.sanitize_log_message(poisoned_msg)
        # Satır başı (\r) kalmadığını doğruluyoruz.
        self.assertNotIn("\r", sanitized)
        # Yeni satır (\n) kalmadığını doğruluyoruz.
        self.assertNotIn("\n", sanitized)
        # Terminal kaçış kodunun temizlendiğini teyit ediyoruz.
        self.assertNotIn("\x1b", sanitized)

    def test_04_build_sanitized_client_response_suppresses_stack_trace(self) -> None:
        """
        Dış istemciye döndürülen yanıtta iç dosya yolu veya yığın izi bulunmadığını doğrular.
        """
        # Örnek güvenlik istisnası oluşturuyoruz.
        sec_exc = SecurityException("Veritabanı bağlantı hatası /opt/secure/db.py:42")
        # İstemci yanıtını üretiyoruz.
        client_resp = self.handler.build_sanitized_client_response(sec_exc)
        # Yanıt durumunun HATA_ERISIM_ENGEL olduğunu sınıyoruz.
        self.assertEqual(client_resp["durum"], "HATA_ERISIM_ENGEL")
        # Yanıt mesajında iç dosya yolunun geçmediğini teyit ediyoruz.
        self.assertNotIn("/opt/secure/db.py", client_resp["mesaj"])
        # Olay referans kodunun yanıtta bulunduğunu doğruluyoruz.
        self.assertIn("SEC-ERR-", client_resp["olay_referans_kodu"])

    def test_05_record_forensic_incident_records_details(self) -> None:
        """
        Dahili adli kaydın istemci IP ve temizlenmiş mesajla eksiksiz tutulduğunu test eder.
        """
        # İstisna nesnesi oluşturuyoruz.
        auth_exc = AuthenticationFailureException("Yetkisiz parola denemesi")
        # Adli olayı kaydediyoruz.
        inc_id = self.handler.record_forensic_incident(auth_exc, "198.51.100.5", "LOGIN")
        # Adli kayıt listesinde 1 kayıt olduğunu teyit ediyoruz.
        self.assertEqual(len(self.handler.forensic_log_records), 1)
        # Kaydın referans kodunu sınıyoruz.
        self.assertEqual(self.handler.forensic_log_records[0]["incident_id"], inc_id)
        # Kaydın IP adresini sınıyoruz.
        self.assertEqual(self.handler.forensic_log_records[0]["client_ip"], "198.51.100.5")

    def test_06_resource_context_manager_acquires_and_releases(self) -> None:
        """
        SecureResourceContext yöneticisinin bağlama girişte tahsis, çıkışta serbest bıraktığını doğrular.
        """
        # Kaynak yöneticisini başlatıyoruz.
        res_ctx = SecureResourceContext("TestKilit")
        # Henüz açık olmadığını sınıyoruz.
        self.assertFalse(res_ctx.is_acquired)
        # Bağlam bloğunu çalıştırıyoruz.
        with res_ctx:
            # Blok içinde tahsis edilmiş olduğunu test ediyoruz.
            self.assertTrue(res_ctx.is_acquired)
            # Henüz serbest bırakılmadığını sınıyoruz.
            self.assertFalse(res_ctx.is_released)
        # Blok bitiminde serbest bırakıldığını teyit ediyoruz.
        self.assertTrue(res_ctx.is_released)
        # Tahsis bayrağının kapandığını sınıyoruz.
        self.assertFalse(res_ctx.is_acquired)

    def test_07_resource_context_manager_releases_on_exception(self) -> None:
        """
        Bağlam bloğu içinde istisna fırlatılsa dahi kaynağın serbest bırakıldığını (Fail-Closed) doğrular.
        """
        # Kaynak yöneticisini başlatıyoruz.
        res_ctx = SecureResourceContext("KritikVeriKilidi")
        # İstisna fırlatılacak bloğu sınıyoruz.
        with self.assertRaises(ValueError):
            # Bağlam yöneticisine giriyoruz.
            with res_ctx:
                # Blok içinde kasıtlı istisna üretiyoruz.
                raise ValueError("İşlem ortasında beklenmeyen çökme")
        # Hata olsa bile kaynağın serbest bırakıldığını teyit ediyoruz.
        self.assertTrue(res_ctx.is_released)
        # Tahsis bayrağının kapalı olduğunu sınıyoruz.
        self.assertFalse(res_ctx.is_acquired)

    def test_08_gateway_valid_transaction_success(self) -> None:
        """
        Geçerli token ve parametrelerle yapılan işlemin başarıyla tamamlandığını test eder.
        """
        # Meşru istek sözlüğü hazırlıyoruz.
        req = {
            "client_ip": "10.0.0.1",
            "action": "LIST_ASSETS",
            "token": "TOKEN_USER_456",
            "required_role": "analyst",
            "parameter": "server_cluster_a"
        }
        # İsteği işleme alıyoruz.
        resp = self.gateway.process_secure_transaction(req)
        # Durumun BASARILI olduğunu teyit ediyoruz.
        self.assertEqual(resp["durum"], "BASARILI")
        # Kullanıcı rolünü kontrol ediyoruz.
        self.assertEqual(resp["rol"], "analyst")

    def test_09_gateway_invalid_token_fails_closed(self) -> None:
        """
        Geçersiz belirteçle yapılan istekte erişimin fail-closed gereği engellendiğini sınar.
        """
        # Sahte token içeren istek hazırlıyoruz.
        req = {
            "client_ip": "198.51.100.22",
            "action": "SECRET_DATA",
            "token": "FORGED_TOKEN_999",
            "required_role": "admin",
            "parameter": "confidential"
        }
        # İsteği işliyoruz.
        resp = self.gateway.process_secure_transaction(req)
        # Yanıt durumunun HATA_ERISIM_ENGEL olduğunu teyit ediyoruz.
        self.assertEqual(resp["durum"], "HATA_ERISIM_ENGEL")
        # Olay referans kodunun üretildiğini sınıyoruz.
        self.assertIn("SEC-ERR-", resp["olay_referans_kodu"])

    def test_10_gateway_unauthorized_role_denied(self) -> None:
        """
        Yetkisiz role sahip kullanıcının işlem denemesinde AuthorizationDeniedException ile engellendiğini test eder.
        """
        # Analist rolündeki token ile admin işlemi yapmayı deniyoruz.
        req = {
            "client_ip": "10.0.0.2",
            "action": "DROP_DATABASE",
            "token": "TOKEN_USER_456",
            "required_role": "admin",
            "parameter": "clean_logs"
        }
        # İsteği işliyoruz.
        resp = self.gateway.process_secure_transaction(req)
        # Yanıtın engellendiğini sınıyoruz.
        self.assertEqual(resp["durum"], "HATA_ERISIM_ENGEL")

    def test_11_gateway_input_sanitization_violation_caught(self) -> None:
        """
        Girdi parametresinde yasaklı karakter dizisi olduğunda işlemin durdurulduğunu doğrular.
        """
        # Zararlı script enjeksiyonu içeren istek hazırlıyoruz.
        req = {
            "client_ip": "10.0.0.3",
            "action": "SUBMIT_REPORT",
            "token": "TOKEN_ADMIN_123",
            "required_role": "admin",
            "parameter": "<script>alert('xss')</script>"
        }
        # İsteği işliyoruz.
        resp = self.gateway.process_secure_transaction(req)
        # İsteğin engellendiğini teyit ediyoruz.
        self.assertEqual(resp["durum"], "HATA_ERISIM_ENGEL")

    def test_12_gateway_rate_limit_exceeded(self) -> None:
        """
        Aynı IP'den gelen ardışık başarısız isteklerin eşik aşıldığında hız sınırı ile engellendiğini sınar.
        """
        # Saldırgan IP belirliyoruz.
        bad_ip = "198.51.100.88"
        # 5 kez bilerek hatalı istek gönderiyoruz.
        for _ in range(5):
            # Hatalı token gönderiyoruz.
            self.gateway.process_secure_transaction({
                "client_ip": bad_ip,
                "token": "BAD_TOKEN"
            })
        # 6. istekte hız sınırı aşımına uğramasını bekliyoruz.
        req = {
            "client_ip": bad_ip,
            "token": "TOKEN_ADMIN_123",
            "required_role": "admin",
            "parameter": "legit"
        }
        # İsteği yürütüyoruz.
        resp = self.gateway.process_secure_transaction(req)
        # Hız sınırından ötürü engellendiğini teyit ediyoruz.
        self.assertEqual(resp["durum"], "HATA_ERISIM_ENGEL")

    def test_13_gateway_unhandled_system_exception_fails_closed(self) -> None:
        """
        Bilinmeyen genel bir sistem hatası durumunda da en dış kalkanın fail-closed çalıştığını doğrular.
        """
        # Belirteç parametresini None vererek TypeError simüle ediyoruz.
        req = {
            "client_ip": "10.0.0.9",
            "token": None,
            "action": "CRASH_TEST"
        }
        # İsteği yürütüyoruz.
        resp = self.gateway.process_secure_transaction(req)
        # Sistemin çökmediğini ve güvenli hata döndürdüğünü sınıyoruz.
        self.assertEqual(resp["durum"], "HATA_ERISIM_ENGEL")

    def test_14_gateway_io_error_ensures_resource_released(self) -> None:
        """
        G/Ç hatası simüle edildiğinde kaynak kilidinin güvenle serbest bırakıldığını sınar.
        """
        # Donanım arızası simülasyonu içeren istek gönderiyoruz.
        req = {
            "client_ip": "10.0.0.10",
            "token": "TOKEN_ADMIN_123",
            "required_role": "admin",
            "parameter": "safe_param",
            "simulate_io_error": True
        }
        # İsteği yürütüyoruz.
        resp = self.gateway.process_secure_transaction(req)
        # İsteğin hata olarak döndüğünü teyit ediyoruz.
        self.assertEqual(resp["durum"], "HATA_ERISIM_ENGEL")


# Modül doğrudan çağrıldığında testleri ayrıntılı modda başlatıyoruz.
if __name__ == "__main__":
    # Test yürütücüyü çalıştırıyoruz.
    unittest.main()
