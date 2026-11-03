# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G040: Güvenli Uzaktan Yönetim ve Erişim Matrisi Denetçisi Birim Test Paketi (Unit Tests)

Bu modül, SecureRemoteManagementAuditor sınıfının şema doğrulama, şifresiz Telnet protokolü,
internete doğrudan açılan RDP/SSH portları, SSH root girişi, RDP NLA eksikliği ve
kaba kuvvet (brute-force) koruması kontrollerini 14 bağımsız birim testle denetler.
"""

# Standart Python birim test kütüphanesini içeri aktarıyoruz.
import unittest

# Dosya ve dizin işlemleri için os modülünü kullanıyoruz.
import os

# JSON yüklerini ayrıştırmak için json kütüphanesini dahil ediyoruz.
import json

# Denetlenecek ana sınıfı ve özel hata sınıfını uygulama paketinden dahil ediyoruz.
from portfolio.hafta_06.gun_040.uygulama.secure_remote_management_auditor import (
    # Denetim motorunu alıyoruz.
    SecureRemoteManagementAuditor,
    # Özel doğrulama hatasını alıyoruz.
    RemoteAccessValidationError
)


# Test sınıfımızı tanımlıyoruz.
class TestSecureRemoteManagementAuditor(unittest.TestCase):
    """
    Güvenli uzaktan yönetim denetçisi kapsamlı birim testleri.
    """

    # Her test öncesinde çalışan hazırlık metodu.
    def setUp(self) -> None:
        """
        Test ortamını hazırlar ve örnek erişim matrisi verilerini yükler.
        """
        # Yeni bir denetçi nesnesi oluşturuyoruz.
        self.auditor = SecureRemoteManagementAuditor()

        # Mevcut dosya dizinini alıyoruz.
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Geçerli örnek matris yolunu belirliyoruz.
        self.sample_matrix_path = os.path.join(current_dir, "..", "ornek_veri", "sample_remote_access_matrix.json")
        # Bozuk test senaryolarının yolunu belirliyoruz.
        self.corrupted_matrix_path = os.path.join(current_dir, "..", "ornek_veri", "corrupted_remote_access_matrix_test_cases.json")

        # Geçerli veriyi dosyadan okuyoruz.
        with open(self.sample_matrix_path, "r", encoding="utf-8") as f:
            # JSON olarak yüklüyoruz.
            self.valid_matrix = json.load(f)

    # 1. Test: Geçerli erişim matrisi verisinin şema doğrulamasını hatasız geçmesi.
    def test_01_matrix_schema_validation_success(self) -> None:
        """
        Geçerli erişim matrisi verisinin şema doğrulamasından başarıyla geçtiğini doğrular.
        """
        # Doğrulamayı çağırıyoruz.
        res = self.auditor.validate_matrix_schema(self.valid_matrix)
        # Sonucun True olduğunu test ediyoruz.
        self.assertTrue(res, "Geçerli erişim matrisi şema doğrulamasını geçmelidir.")

    # 2. Test: 'remote_services' anahtarı bulunmadığında RemoteAccessValidationError fırlatılması.
    def test_02_missing_services_key_raises_validation_error(self) -> None:
        """
        'remote_services' anahtarı eksik olduğunda hata fırlatıldığını denetler.
        """
        # Eksik anahtarlı sahte veri hazırlıyoruz.
        bad_data = {"matrix_metadata": {"org": "No Services"}}
        # Hata beklentisini sınıyoruz.
        with self.assertRaises(RemoteAccessValidationError) as ctx:
            # Doğrulamayı tetikliyoruz.
            self.auditor.validate_matrix_schema(bad_data)
        # Hata mesajında 'remote_services' geçtiğini kontrol ediyoruz.
        self.assertIn("remote_services", str(ctx.exception))

    # 3. Test: Port sınırları dışında (negatif veya > 65535) hata fırlatılması.
    def test_03_invalid_port_boundary_raises_validation_error(self) -> None:
        """
        Port 1'den küçük veya 65535'ten büyük olduğunda hata fırlatıldığını doğrular.
        """
        # Negatif portlu veri hazırlıyoruz.
        bad_data = {
            "remote_services": [
                {"service_id": "SVC-BAD", "target_hostname": "h1", "protocol": "SSH", "port": -22}
            ]
        }
        # Hata fırlatma kontrolü yapıyoruz.
        with self.assertRaises(RemoteAccessValidationError) as ctx:
            # Fonksiyonu çalıştırıyoruz.
            self.auditor.validate_matrix_schema(bad_data)
        # Hata mesajında port sınır uyarısını sınıyoruz.
        self.assertIn("1 ile 65535 arasında olmalıdır", str(ctx.exception))

    # 4. Test: Sayısal olmayan port numarasında hata fırlatılması.
    def test_04_non_numeric_port_raises_error(self) -> None:
        """
        Port string olduğunda hata fırlatıldığını denetler.
        """
        # String port değerli veri oluşturuyoruz.
        bad_data = {
            "remote_services": [
                {"service_id": "SVC-BAD", "target_hostname": "h1", "protocol": "SSH", "port": "yirmi_iki"}
            ]
        }
        # Hata beklentisini test ediyoruz.
        with self.assertRaises(RemoteAccessValidationError) as ctx:
            # Doğrulamayı çağırıyoruz.
            self.auditor.validate_matrix_schema(bad_data)
        # Hata mesajında sayısal uyarısını sınıyoruz.
        self.assertIn("tamsayı olmalıdır", str(ctx.exception))

    # 5. Test: Sunucu adı metin olmadığında hata fırlatılması.
    def test_05_non_string_hostname_raises_error(self) -> None:
        """
        target_hostname int veya liste olduğunda hata fırlatıldığını doğrular.
        """
        # Sayısal hostname değerli veri oluşturuyoruz.
        bad_data = {
            "remote_services": [
                {"service_id": "SVC-BAD", "target_hostname": 127001, "protocol": "SSH", "port": 22}
            ]
        }
        # Hata kontrolü yapıyoruz.
        with self.assertRaises(RemoteAccessValidationError) as ctx:
            # Fonksiyonu çalıştırıyoruz.
            self.auditor.validate_matrix_schema(bad_data)
        # Hata mesajında metin uyarısını sınıyoruz.
        self.assertIn("metin olmalıdır", str(ctx.exception))

    # 6. Test: Protokol adı metin olmadığında hata fırlatılması.
    def test_06_non_string_protocol_raises_error(self) -> None:
        """
        protocol string olmadığında hata fırlatıldığını doğrular.
        """
        # Hatalı protokol tipli veri hazırlıyoruz.
        bad_data = {
            "remote_services": [
                {"service_id": "SVC-BAD", "target_hostname": "h1", "protocol": 22, "port": 22}
            ]
        }
        # Hata beklentisini sınıyoruz.
        with self.assertRaises(RemoteAccessValidationError) as ctx:
            # Doğrulamayı icra ediyoruz.
            self.auditor.validate_matrix_schema(bad_data)
        # Hata mesajında metin ibaresini sınıyoruz.
        self.assertIn("metin olmalıdır", str(ctx.exception))

    # 7. Test: Şifresiz Telnet protokolünün CRITICAL seviyesinde tespit edilmesi.
    def test_07_plaintext_telnet_detected_as_critical(self) -> None:
        """
        Telnet (port 23) protokolünün CRITICAL açık metin koklama riski ürettiğini doğrular.
        """
        # Telnet servisi içeren girdi hazırlıyoruz.
        services = [
            {"service_id": "S1", "target_hostname": "db01", "protocol": "TELNET", "port": 23, "is_legacy_plaintext_protocol": True}
        ]
        # Protokol denetimini çağırıyoruz.
        findings = self.auditor.audit_legacy_plaintext_protocols(services)
        # En az bir bulgu bekliyoruz.
        self.assertEqual(len(findings), 1)
        # Önem seviyesinin CRITICAL olduğunu test ediyoruz.
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        # Başlıkta TELNET kelimesinin geçtiğini sınıyoruz.
        self.assertIn("TELNET", findings[0]["title"])

    # 8. Test: Doğrudan internete açık RDP/SSH portunun CRITICAL olarak raporlanması.
    def test_08_direct_internet_perimeter_exposure_detected_as_critical(self) -> None:
        """
        İnternete (0.0.0.0/0) doğrudan açık ve Bastion/VPN korumasız portun CRITICAL olduğunu doğrular.
        """
        # Doğrudan internete açık RDP servisi hazırlıyoruz.
        services = [
            {"service_id": "S2", "target_hostname": "rdp-host", "protocol": "RDP", "port": 3389, "is_exposed_to_internet": True, "requires_bastion_or_vpn": False}
        ]
        # Ağ çevresi denetimini çağırıyoruz.
        findings = self.auditor.audit_perimeter_exposure_and_bastion(services)
        # 1 bulgu bekliyoruz.
        self.assertEqual(len(findings), 1)
        # Önem derecesinin CRITICAL olduğunu sınıyoruz.
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        # Başlıkta İnternete Doğrudan Açık uyarısını denetliyoruz.
        self.assertIn("İnternete Doğrudan Açık", findings[0]["title"])

    # 9. Test: SSH PermitRootLogin açık olduğunda CRITICAL bulgu üretilmesi.
    def test_09_ssh_permit_root_login_detected_as_critical(self) -> None:
        """
        SSH root girişinin izinli olmasının CRITICAL seviyesinde raporlandığını doğrular.
        """
        # Root girişi açık SSH servisi hazırlıyoruz.
        services = [
            {"service_id": "S3", "target_hostname": "srv01", "protocol": "SSH", "port": 22, "permit_root_login": True}
        ]
        # Kimlik doğrulama denetimini icra ediyoruz.
        findings = self.auditor.audit_authentication_hardening(services)
        # Root bulgusunu filtreliyoruz.
        root_findings = [f for f in findings if f["category"] == "SSH_ROOT_LOGIN_PERMITTED"]
        # 1 bulgu olmalıdır.
        self.assertEqual(len(root_findings), 1)
        # Önem seviyesinin CRITICAL olduğunu test ediyoruz.
        self.assertEqual(root_findings[0]["severity"], "CRITICAL")

    # 10. Test: RDP NLA (Ağ Düzeyinde Kimlik Doğrulama) kapalı olduğunda CRITICAL bulgu üretilmesi.
    def test_10_rdp_nla_disabled_detected_as_critical(self) -> None:
        """
        RDP üzerinde NLA kapalı olduğunda BlueKeep riski sebebiyle CRITICAL raporlandığını doğrular.
        """
        # NLA kapalı RDP servisi hazırlıyoruz.
        services = [
            {"service_id": "S4", "target_hostname": "rdp-svr", "protocol": "RDP", "port": 3389, "nla_enforced": False}
        ]
        # Denetimi çağırıyoruz.
        findings = self.auditor.audit_authentication_hardening(services)
        # NLA bulgusunu filtreliyoruz.
        nla_findings = [f for f in findings if f["category"] == "RDP_NLA_DISABLED_VULNERABILITY"]
        # 1 bulgu olmalıdır.
        self.assertEqual(len(nla_findings), 1)
        # Önem derecesinin CRITICAL olduğunu sınıyoruz.
        self.assertEqual(nla_findings[0]["severity"], "CRITICAL")

    # 11. Test: SSH parola ile giriş açık ve anahtar zorunlu değilse HIGH bulgu üretilmesi.
    def test_11_ssh_password_auth_unhardened_detected_as_high(self) -> None:
        """
        SSH üzerinde anahtar zorunlu olmadan parola ile girişin açık olmasının HIGH raporlandığını doğrular.
        """
        # Parola açık, anahtar kapalı servis hazırlıyoruz.
        services = [
            {"service_id": "S5", "target_hostname": "web01", "protocol": "SSH", "port": 22, "permit_root_login": False, "password_auth_allowed": True, "public_key_auth_enforced": False}
        ]
        # Denetimi çağırıyoruz.
        findings = self.auditor.audit_authentication_hardening(services)
        # Parola bulgusunu filtreliyoruz.
        pwd_findings = [f for f in findings if f["category"] == "SSH_PASSWORD_AUTH_UNHARDENED"]
        # 1 bulgu olmalıdır.
        self.assertEqual(len(pwd_findings), 1)
        # Önem derecesinin HIGH olduğunu sınıyoruz.
        self.assertEqual(pwd_findings[0]["severity"], "HIGH")

    # 12. Test: Kaba kuvvet koruması (Fail2ban vb.) eksikliğinin HIGH olarak tespit edilmesi.
    def test_12_brute_force_protection_missing_detected_as_high(self) -> None:
        """
        brute_force_protection=False olduğunda HIGH önem derecesinde bulgu üretildiğini doğrular.
        """
        # Kaba kuvvet korumasız servis hazırlıyoruz.
        services = [
            {"service_id": "S6", "target_hostname": "app01", "protocol": "SSH", "port": 22, "brute_force_protection": False, "session_logging_enabled": True}
        ]
        # Kaba kuvvet denetimini icra ediyoruz.
        findings = self.auditor.audit_brute_force_and_logging(services)
        # Kaba kuvvet bulgusunu filtreliyoruz.
        brute_findings = [f for f in findings if f["category"] == "BRUTE_FORCE_PROTECTION_MISSING"]
        # 1 bulgu bekliyoruz.
        self.assertEqual(len(brute_findings), 1)
        # Önem derecesinin HIGH olduğunu test ediyoruz.
        self.assertEqual(brute_findings[0]["severity"], "HIGH")

    # 13. Test: Bozuk test senaryoları dosyasındaki tüm girdilerin güvenle reddedilmesi.
    def test_13_corrupted_test_cases_suite_robustness(self) -> None:
        """
        corrupted_remote_access_matrix_test_cases.json dosyasındaki tüm girdilerin yakalandığını doğrular.
        """
        # Bozuk test dosyasını açıyoruz.
        with open(self.corrupted_matrix_path, "r", encoding="utf-8") as f:
            # JSON olarak yüklüyoruz.
            suite = json.load(f)

        # Tüm senaryoları sınıyoruz.
        for case in suite.get("test_cases", []):
            # Test adını alıyoruz.
            tname = case.get("test_name")
            # Gövdeyi alıyoruz.
            payload = case.get("payload")
            # Hata beklentisini sınıyoruz.
            with self.assertRaises(RemoteAccessValidationError, msg=f"Test '{tname}' hata fırlatmalıdır"):
                # Denetimi başlatıyoruz.
                self.auditor.execute_full_audit(payload)

    # 14. Test: Uçtan uca tam denetim iş akışı ve Markdown rapor çıktısı.
    def test_14_markdown_and_full_audit_workflow(self) -> None:
        """
        Tam denetim iş akışının hatasız çalıştığını ve Markdown raporu ürettiğini doğrular.
        """
        # Örnek geçerli matris üzerinde tam denetimi çalıştırıyoruz.
        result = self.auditor.execute_full_audit(self.valid_matrix)
        # Sonucun sözlük olduğunu kontrol ediyoruz.
        self.assertIsInstance(result, dict)
        # Güvenlik puanının 0 ile 100 arasında olduğunu sınıyoruz.
        self.assertTrue(0 <= result["security_score"] <= 100)
        # Metrik tablosunun varlığını sınıyoruz.
        self.assertIn("metrics", result)

        # Markdown raporu üretiyoruz.
        report_md = self.auditor.export_markdown_report(result)
        # Raporun boş olmadığını sınıyoruz.
        self.assertTrue(len(report_md) > 0)
        # Raporda lisans başlığının yer aldığını kontrol ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", report_md)
        # Raporda ana başlığı sınıyoruz.
        self.assertIn("Güvenli Uzaktan Yönetim ve Erişim Matrisi Denetim Raporu", report_md)


# Testler doğrudan icra edildiğinde unittest.main'i çalıştırıyoruz.
if __name__ == "__main__":
    # Testleri detaylı modda icra ediyoruz.
    unittest.main()
