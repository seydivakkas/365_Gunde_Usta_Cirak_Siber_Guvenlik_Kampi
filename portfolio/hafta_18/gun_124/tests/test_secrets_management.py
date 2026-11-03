# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 124: Secrets Yönetimi ve Çevre Değişkenleri Birim Testleri.
15 birim test senaryosu: Zarflı şifreleme, yetki denetimi (CWE-285),
süre aşımı (CWE-613), rotasyon, HMAC tahrifat koruması, Shannon entropi analizi,
CWE-798 statik secret taraması ve CWE-532 log maskeleme doğrulamaları.
"""

# Standart unittest çerçevesi içe aktarılıyor
import unittest
# Sistem ve dizin yönetimi için sys ve os içe aktarılıyor
import sys
import os
# Süre manipülasyonu için datetime ve timedelta içe aktarılıyor
from datetime import datetime, timedelta

# Uygulama dizini arama yoluna ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
sys.path.insert(0, app_dir)

# Test edilecek motor sınıfları ve istisnalar içe aktarılıyor
from secrets_management_engine import (
    SecretVaultManager,
    SecretScanner,
    SecretType,
    SecretState,
    CryptoVaultHelper,
    SecretAccessDeniedError,
    SecretExpiredError,
    SecretRevokedError,
    InvalidSecretPayloadError,
    DuplicateSecretError,
    SecretNotFoundError
)


class TestSecretsManagementEngine(unittest.TestCase):
    """Secrets Yönetimi ve Güvenlik Kasa Motoru test takımı."""

    def setUp(self):
        """Her testten önce temiz bir kasa örneği oluşturur."""
        self.master_key = "GuvenliKurumsalMasterKey2026!#"
        self.vault = SecretVaultManager(vault_name="Test Kasası", master_key=self.master_key)
        # Örnek bir veritabanı parolası kaydedilir
        self.vault.store_secret(
            secret_id="SEC-DB-01",
            name="Prod PostgreSQL Parolası",
            secret_type=SecretType.DATABASE_PASSWORD,
            plaintext_value="SuperSecretDBPass2026!$",
            allowed_roles=["db_admin", "backend_service"],
            ttl_seconds=3600,
            rotation_interval_days=30
        )

    def test_01_store_and_retrieve_secret_success(self):
        """Yetkili rol ile zarflı şifrelenmiş secret başarıyla okunabilmelidir."""
        val = self.vault.get_secret("SEC-DB-01", requester_role="backend_service")
        self.assertEqual(val, "SuperSecretDBPass2026!$")
        meta = self.vault.metadata_store["SEC-DB-01"]
        self.assertEqual(meta.access_count, 1)

    def test_02_unauthorized_role_access_denied(self):
        """Yetkisiz rol erişmeye çalıştığında SecretAccessDeniedError fırlatılmalıdır (CWE-285)."""
        with self.assertRaises(SecretAccessDeniedError):
            self.vault.get_secret("SEC-DB-01", requester_role="intern_developer")

    def test_03_ttl_expiration_blocks_access(self):
        """Süresi (TTL) dolmuş secret çağrıldığında SecretExpiredError fırlatılmalıdır (CWE-613)."""
        meta = self.vault.metadata_store["SEC-DB-01"]
        # Süresi geçmişe çekilir
        meta.expires_at = datetime.now() - timedelta(seconds=10)
        with self.assertRaises(SecretExpiredError):
            self.vault.get_secret("SEC-DB-01", requester_role="db_admin")

    def test_04_revoked_secret_blocks_access(self):
        """İptal edilmiş (revoked) bir gizli anahtara erişim engellenmelidir."""
        self.vault.revoke_secret("SEC-DB-01")
        meta = self.vault.metadata_store["SEC-DB-01"]
        self.assertEqual(meta.state, SecretState.REVOKED)
        with self.assertRaises(SecretRevokedError):
            self.vault.get_secret("SEC-DB-01", requester_role="db_admin")

    def test_05_secret_rotation_generates_new_version(self):
        """Secret rotasyonu yapıldığında versiyon artmalı ve yeni değer şifrelenmelidir."""
        new_pass = "RotatedDBPass2027!#$"
        meta = self.vault.rotate_secret("SEC-DB-01", new_plaintext_value=new_pass)
        self.assertEqual(meta.version, 2)
        self.assertEqual(meta.state, SecretState.ACTIVE)
        # Yeni değer yetkili rolden başarıyla okunmalıdır
        retrieved = self.vault.get_secret("SEC-DB-01", requester_role="db_admin")
        self.assertEqual(retrieved, new_pass)

    def test_06_envelope_encryption_tamper_detection(self):
        """Şifreli metin veya HMAC etiketi tahrif edildiğinde bütünlük hatası verilmelidir."""
        payload = self.vault.encrypted_payload_store["SEC-DB-01"]
        # Şifreli metnin son byte'ı değiştirilir
        corrupted_cipher = payload.ciphertext_hex[:-2] + "ff"
        payload.ciphertext_hex = corrupted_cipher
        with self.assertRaises(InvalidSecretPayloadError):
            self.vault.get_secret("SEC-DB-01", requester_role="db_admin")

    def test_07_shannon_entropy_calculation_accuracy(self):
        """Shannon entropi hesaplaması düşük ve yüksek karmaşıklıktaki dizgileri ayırt etmelidir."""
        # Tekrar eden düşük entropili metin
        low_ent = SecretScanner.calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
        self.assertLess(low_ent, 1.0)
        # Kriptografik rastgele yüksek entropili anahtar
        high_ent = SecretScanner.calculate_shannon_entropy("qW8#kL2$vP9@zX4!mN7%yR1^")
        self.assertGreater(high_ent, 4.0)

    def test_08_scanner_detects_aws_key_pattern(self):
        """Statik tarayıcı AWS erişim anahtarı kalıbını (AKIA...) doğru tespit etmelidir."""
        sample_code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nprint("Connected")'
        findings = SecretScanner.scan_text(sample_code)
        self.assertTrue(any(f["pattern_name"] == "AWS_ACCESS_KEY" for f in findings))

    def test_09_scanner_detects_github_token_pattern(self):
        """Statik tarayıcı GitHub kişisel erişim belirtecini (ghp_...) yakalamalıdır."""
        sample_code = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        findings = SecretScanner.scan_text(sample_code)
        self.assertTrue(any(f["pattern_name"] == "GITHUB_TOKEN" for f in findings))

    def test_10_scanner_detects_stripe_key_pattern(self):
        """Statik tarayıcı Stripe gizli anahtarını (sk_live_...) yakalamalıdır."""
        sample_code = 'stripe.api_key = "sk_test_51Abcdefghijklmnopqrstuvwx"'
        findings = SecretScanner.scan_text(sample_code)
        self.assertTrue(any(f["pattern_name"] == "STRIPE_SECRET_KEY" for f in findings))

    def test_11_scanner_detects_high_entropy_token(self):
        """Statik tarayıcı yüksek entropili tırnak içi token'ı yakalamalıdır."""
        sample_code = 'SECRET_TOKEN = "k9#vL2$mP8@zX4!qN7%yR1^wT5*"'
        findings = SecretScanner.scan_text(sample_code, entropy_threshold=4.0)
        self.assertTrue(any("Shannon Entropy" in f["pattern_name"] for f in findings))

    def test_12_clean_code_scan_yields_zero_findings(self):
        """Gizli anahtar içermeyen temiz kodda hiçbir bulgu üretilmemelidir."""
        clean_code = '''
def add(a, b):
    return a + b

import os
db_url = os.environ.get("DATABASE_URL")
'''
        findings = SecretScanner.scan_text(clean_code)
        self.assertEqual(len(findings), 0)

    def test_13_log_masking_redacts_stored_secrets(self):
        """Log maskeleyici kasada saklanan aktif bir parolayı günlükten temizlemelidir (CWE-532)."""
        raw_log = "HATA: Veritabanına SuperSecretDBPass2026!$ parolası ile bağlanırken timeout oluştu."
        masked = self.vault.mask_log_message(raw_log)
        self.assertNotIn("SuperSecretDBPass2026!$", masked)
        self.assertIn("[REDACTED_SECRET_SEC-DB-01]", masked)

    def test_14_log_masking_redacts_regex_patterns(self):
        """Log maskeleyici metindeki AWS veya Stripe anahtar kalıplarını maskelemelidir."""
        raw_log = "Ödeme isteği başarısız: sk_test_51Abcdefghijklmnopqrstuvwx kullanıldı."
        masked = self.vault.mask_log_message(raw_log)
        self.assertNotIn("sk_test_51Abcdefghijklmnopqrstuvwx", masked)
        self.assertIn("[REDACTED_STRIPE_SECRET_KEY]", masked)

    def test_15_duplicate_secret_id_rejection(self):
        """Aynı ID'ye sahip iki farklı secret kaydedilmeye çalışıldığında DuplicateSecretError verilmelidir."""
        with self.assertRaises(DuplicateSecretError):
            self.vault.store_secret(
                secret_id="SEC-DB-01",  # Zaten setUp'ta eklendi
                name="Çift DB",
                secret_type=SecretType.DATABASE_PASSWORD,
                plaintext_value="AnotherPassword123!",
                allowed_roles=["admin"]
            )


if __name__ == "__main__":
    unittest.main()
