# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 092: Veri Doğrulama ve Tip Güvenliği Kalkanı Birim Test Paketi.

Bu modül; runtime tip denetimlerini, IPv4, MAC, Port, Hostname ve SHA-256
doğrulamalarını, Null-Byte korumasını ve Type Confusion savunmasını 14 kapsamlı
test senaryosuyla doğrular.
"""

# Test ve sistem kütüphaneleri
import unittest
import sys
import os
import json

# Uygulama modülünü arama yoluna dahil et
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Doğrulama motorunu, dekoratörü ve istisnaları içe aktar
from security_data_validator import (
    SecurityDataValidator,
    SecurityAsset,
    enforce_types,
    SecurityValidationError,
    TypeValidationError,
    InvalidIpAddressError,
    PortRangeError,
    InvalidMacAddressError,
    InvalidHostnameError,
    NullByteInjectionError,
    InvalidHashChecksumError,
    ValueRangeError,
    PayloadTooLargeError
)

class TestSecurityDataValidator(unittest.TestCase):
    """Veri doğrulama ve tip güvenliği test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz bir doğrulayıcı nesnesi hazırlar."""
        self.validator = SecurityDataValidator()

    def test_01_valid_ipv4_validation(self) -> None:
        """1. Test: Geçerli IPv4 adreslerinin doğrulanması."""
        ip = "192.168.1.1"
        dogrulanmis = self.validator.validate_ipv4(ip)
        self.assertEqual(dogrulanmis, "192.168.1.1")

    def test_02_invalid_ipv4_out_of_bounds(self) -> None:
        """2. Test: 255'ten büyük oktet içeren IP'nin reddedilmesi (CWE-20)."""
        with self.assertRaises(InvalidIpAddressError):
            self.validator.validate_ipv4("192.168.1.300")

    def test_03_invalid_ipv4_octal_prevention(self) -> None:
        """3. Test: Baştaki sıfırlarla gelen octal karışıklığı yaratan IP'nin engellenmesi."""
        with self.assertRaises(InvalidIpAddressError):
            self.validator.validate_ipv4("192.168.01.1")

    def test_04_valid_port_validation(self) -> None:
        """4. Test: 1-65535 aralığındaki geçerli port numaralarının kabulü."""
        port = self.validator.validate_port(443)
        self.assertEqual(port, 443)
        self.assertEqual(self.validator.validate_port(1), 1)
        self.assertEqual(self.validator.validate_port(65535), 65535)

    def test_05_invalid_port_type_confusion(self) -> None:
        """5. Test: Port alanına bool veya metin girildiğinde Type Confusion tespiti (CWE-843)."""
        with self.assertRaises(TypeValidationError):
            self.validator.validate_port(True) # bool int alt sınıfıdır, ama port olamaz
        with self.assertRaises(TypeValidationError):
            self.validator.validate_port("80") # string girilemez

    def test_06_invalid_port_range(self) -> None:
        """6. Test: 0 veya 65535'ten büyük portların sınır hatası vermesi (CWE-1284)."""
        with self.assertRaises(PortRangeError):
            self.validator.validate_port(0)
        with self.assertRaises(PortRangeError):
            self.validator.validate_port(70000)

    def test_07_valid_mac_address(self) -> None:
        """7. Test: EUI-48 standardı MAC adresinin büyük harfe ve iki noktaya dönüştürülmesi."""
        mac = "00-50-56-a1-b2-c3"
        dogrulanmis = self.validator.validate_mac_address(mac)
        self.assertEqual(dogrulanmis, "00:50:56:A1:B2:C3")

    def test_08_invalid_mac_format(self) -> None:
        """8. Test: Bozuk veya eksik oktetli MAC adresinin reddedilmesi."""
        with self.assertRaises(InvalidMacAddressError):
            self.validator.validate_mac_address("00:50:56:A1:B2") # 5 oktet
        with self.assertRaises(InvalidMacAddressError):
            self.validator.validate_mac_address("00:50:56:ZZ:B2:C3") # Z hex değil

    def test_09_valid_hostname_rfc1123(self) -> None:
        """9. Test: RFC-1123 uyumlu geçerli alan adının doğrulanması."""
        host = "web-edge-01.corp.internal"
        dogrulanmis = self.validator.validate_hostname(host)
        self.assertEqual(dogrulanmis, "web-edge-01.corp.internal")

    def test_10_invalid_hostname_shell_injection(self) -> None:
        """10. Test: Hostname içinde kabuk komut karakterleri bulunduğunda engelleme (CWE-88)."""
        with self.assertRaises(InvalidHostnameError):
            self.validator.validate_hostname("srv01;rm -rf /")
        with self.assertRaises(InvalidHostnameError):
            self.validator.validate_hostname("srv01|netcat")

    def test_11_null_byte_injection_detection(self) -> None:
        """11. Test: Metin alanlarında Null-Byte (\\x00) enjeksiyonunun anında engellenmesi (CWE-158)."""
        with self.assertRaises(NullByteInjectionError):
            self.validator.sanitize_string_field("test_field", "asset_id\x00_malicious")

    def test_12_valid_sha256_checksum(self) -> None:
        """12. Test: 64 karakterlik SHA-256 sağlama toplamının doğrulanması."""
        gecerli_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        dogrulanmis = self.validator.validate_sha256(gecerli_hash.upper())
        self.assertEqual(dogrulanmis, gecerli_hash)
        # 63 karakterlik eksik hash
        with self.assertRaises(InvalidHashChecksumError):
            self.validator.validate_sha256(gecerli_hash[:-1])

    def test_13_enforce_types_decorator(self) -> None:
        """13. Test: @enforce_types dekoratörünün çalışma anında tip uyuşmazlığını yakalaması."""
        @enforce_types
        def dummy_secure_call(ip: str, port: int) -> str:
            return f"{ip}:{port}"

        # Geçerli çağrı
        self.assertEqual(dummy_secure_call("127.0.0.1", 8080), "127.0.0.1:8080")

        # Hatalı tip: port int beklenirken string verildi
        with self.assertRaises(TypeValidationError):
            dummy_secure_call("127.0.0.1", "8080")

    def test_14_batch_validate_and_asset_conversion(self) -> None:
        """14. Test: Toplu varlık doğrulamasının geçerli ve hatalı kayıtları hatasız ayrıştırması."""
        ham_veriler = [
            {
                "asset_id": "AST-01",
                "ipv4_address": "10.0.0.1",
                "mac_address": "00:11:22:33:44:55",
                "port": 443,
                "hostname": "srv1.local",
                "protocol": "TCP",
                "sha256_checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "risk_score": 1.5,
                "tags": ["web"],
                "is_active": True
            },
            {
                "asset_id": "AST-02",
                "ipv4_address": "999.999.999.999", # Bozuk IP
                "mac_address": "00:11:22:33:44:55",
                "port": 80,
                "hostname": "srv2.local",
                "protocol": "TCP",
                "sha256_checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "risk_score": 2.0
            }
        ]
        valid, errors = self.validator.batch_validate(ham_veriler)
        self.assertEqual(len(valid), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(valid[0].asset_id, "AST-01")
        self.assertEqual(errors[0]["hata_tipi"], "InvalidIpAddressError")

if __name__ == "__main__":
    unittest.main()
