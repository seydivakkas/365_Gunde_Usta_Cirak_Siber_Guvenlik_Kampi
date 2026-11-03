# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 097: Mini Proje 13 — Çevrimdışı (Air-Gapped) Güvenlik Araç Seti Birim Testleri.
14 adet kapsamlı test senaryosu ile izole ortam uyumu, ağ doğrulama, FIM tahrifat tespiti,
DLP maskeleme, SLA profilleme ve zafiyet kalkanları doğrulanır.
"""

# Birim test çerçevesi
import unittest
# Sistem modülü
import sys
# Dosya yolu işlemleri
import os
# Geçici dizin ve dosya yönetimi
import tempfile
import shutil
# Zaman modülü
import time

# Uygulama modülünü içe aktarmak için kök dizini ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek araç seti fonksiyonlarını ve istisnalarını içe aktar
from uygulama.offline_security_toolkit import (
    run_airgap_doctor,
    validate_ipv4,
    validate_port,
    validate_network_asset,
    calculate_file_hash,
    verify_file_hash,
    create_directory_baseline,
    scan_directory_fim,
    verify_luhn_algorithm,
    verify_tckn_algorithm,
    mask_sensitive_text,
    profile_execution,
    ToolkitSecurityError,
    IntegrityVerificationError,
    AssetValidationError,
    PathTraversalSecurityError,
    NullByteInjectionError,
    PerformanceBudgetExceededError,
    ReDoSProtectionTriggered,
    TypeValidationError
)


class TestOfflineSecurityToolkit(unittest.TestCase):
    """Çevrimdışı güvenlik araç seti test sınıfı."""

    def setUp(self):
        """Test öncesi geçici izole ortam oluşturur."""
        self.test_dir = tempfile.mkdtemp(prefix="airgap_test_")
        # Örnek dosya yaz
        self.sample_file = os.path.join(self.test_dir, "config.ini")
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write("node_id=101\nstatus=secure\n")

    def tearDown(self):
        """Test sonrası geçici ortamı temizler."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_doctor_compliance(self):
        """Test 01: AirGap Doctor kontrolünün ortamı onayladığını doğrular."""
        rep = run_airgap_doctor()
        self.assertEqual(rep["durum"], "AIRGAP_COMPLIANT")
        self.assertTrue(rep["pure_standard_library"])

    def test_02_validate_ipv4_valid(self):
        """Test 02: Geçerli IPv4 adreslerinin onaylandığını doğrular."""
        self.assertTrue(validate_ipv4("10.20.30.40"))
        self.assertTrue(validate_ipv4("192.168.1.1"))
        self.assertFalse(validate_ipv4("256.1.1.1"))

    def test_03_validate_ipv4_octal_rejected(self):
        """Test 03: Baştaki sıfır (Octal IP) içeren adreslerin reddedildiğini doğrular (CWE-704)."""
        self.assertFalse(validate_ipv4("10.020.30.40"))
        self.assertFalse(validate_ipv4("01.02.03.04"))

    def test_04_validate_port_boundaries(self):
        """Test 04: Port sınırlarının [1, 65535] olduğunu ve bool tipinin reddedildiğini doğrular (CWE-1284/843)."""
        self.assertTrue(validate_port(80))
        self.assertTrue(validate_port(65535))
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(70000))
        self.assertFalse(validate_port(True))

    def test_05_calculate_file_hash_sha256(self):
        """Test 05: Dosya hash fonksiyonunun geçerli 64 karakter SHA-256 ürettiğini doğrular."""
        h = calculate_file_hash(self.sample_file, algo="sha256")
        self.assertEqual(len(h), 64)

    def test_06_verify_file_hash_constant_time(self):
        """Test 06: Bütünlük doğrulamasının eşleşmede True döndüğünü, bozulmada hata fırlattığını doğrular."""
        h = calculate_file_hash(self.sample_file, algo="sha256")
        self.assertTrue(verify_file_hash(self.sample_file, h, algo="sha256"))
        with self.assertRaises(IntegrityVerificationError):
            verify_file_hash(self.sample_file, "0" * 64, algo="sha256")

    def test_07_fim_tamper_detection(self):
        """Test 07: Dosya tahrifatının FIM tarafından MODIFIED olarak tespit edildiğini doğrular."""
        base = create_directory_baseline(self.test_dir)
        # Dosyayı değiştir
        with open(self.sample_file, "a", encoding="utf-8") as f:
            f.write("tamper_attack=true\n")
        scan = scan_directory_fim(self.test_dir, base)
        self.assertIn("config.ini", scan["MODIFIED"])

    def test_08_fim_path_traversal_rejection(self):
        """Test 08: Dosya hashlemede dizin aşımı (..) denemelerinin engellendiğini doğrular (CWE-22)."""
        with self.assertRaises(PathTraversalSecurityError):
            calculate_file_hash("../../../etc/passwd")

    def test_09_luhn_algorithm(self):
        """Test 09: Luhn kart algoritması doğrulamasını test eder."""
        self.assertTrue(verify_luhn_algorithm("4532015112830366"))
        self.assertFalse(verify_luhn_algorithm("4532015112830367"))

    def test_10_tckn_algorithm(self):
        """Test 10: TCKN modüler algoritma doğrulamasını test eder."""
        self.assertTrue(verify_tckn_algorithm("12345678950"))
        self.assertFalse(verify_tckn_algorithm("12345678959"))
        self.assertFalse(verify_tckn_algorithm("01234567890"))

    def test_11_mask_sensitive_text(self):
        """Test 11: DLP maskeleme motorunun TCKN, kart ve token'ları başarıyla gizlediğini doğrular."""
        raw = "User tckn=12345678950 card=4532015112830366 token='secret_token_12345678' mail=op@corp.com"
        masked, stats = mask_sensitive_text(raw, mask_style="MASK")
        self.assertNotIn("12345678950", masked)
        self.assertNotIn("4532015112830366", masked)
        self.assertNotIn("secret_token_12345678", masked)
        self.assertGreaterEqual(stats["tckn"], 1)
        self.assertGreaterEqual(stats["credit_card"], 1)

    def test_12_redos_defense(self):
        """Test 12: ReDoS kötücül şablonlarının tespit edilip durdurulduğunu doğrular (CWE-1333)."""
        evil = "test: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!@corp.com"
        with self.assertRaises(ReDoSProtectionTriggered):
            mask_sensitive_text(evil)

    def test_13_null_byte_rejection(self):
        """Test 13: Null-Byte karakterlerinin engellendiğini doğrular (CWE-158)."""
        with self.assertRaises(NullByteInjectionError):
            mask_sensitive_text("safe_text\x00poison")
        with self.assertRaises(NullByteInjectionError):
            calculate_file_hash("safe.txt\x00poison")

    def test_14_profile_execution_budget_exceeded(self):
        """Test 14: SLA bütçesini aşan yavaş fonksiyonlarda PerformanceBudgetExceededError fırlatıldığını doğrular."""
        def slow_routine():
            time.sleep(0.005)
            return True
        with self.assertRaises(PerformanceBudgetExceededError):
            profile_execution(slow_routine, threshold_ms=0.1)


if __name__ == "__main__":
    unittest.main()
