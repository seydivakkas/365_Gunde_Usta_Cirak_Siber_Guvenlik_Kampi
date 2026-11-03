# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G086: PowerShell betik parametreleri ve güvenlik motoru birim testleri (unittest).
Bu test paketi; param() AST ayrıştırmasını, Validate özniteliklerini, açık metin parola
tespitini (CWE-312), argüman enjeksiyonunu (CWE-88) ve çalışma zamanı bağlama sınırlarını doğrular.
"""

from pathlib import Path  # Dosya sistemi yollari icin Path modulu ice aktarilir
import unittest  # Birim test cercevesi ice aktarilir

from portfolio.hafta_13.gun_086.uygulama.powershell_parameter_security_auditor import (  # Uygulama modulleri
    ArgumentInjectionDetectedException,  # Arguman enjeksiyonu istisnasi
    ArgumentInjectionDetector,  # Arguman enjeksiyonu tespit edici
    InvalidParameterSetException,  # Gecersiz set degeri istisnasi
    NullByteForbiddenException,  # Null byte istisnasi
    ParameterOutOfRangeException,  # Sinir disi aralik istisnasi
    ParameterPathTraversalException,  # Dizin atlama istisnasi
    ParameterPatternMismatchException,  # Desen uyumsuzluk istisnasi
    ParameterSeverity,  # Ciddiyet enum degeri
    ParameterSizeLimitExceededException,  # Boyut asim istisnasi
    PlaintextCredentialParameterException,  # Acik metin parola istisnasi
    PowerShellParameterSecurityAuditor,  # Façade ana denetim motoru
    RuntimeParameterValidator,  # Calisma zamani dogrulayici
    ScriptParamBlockParser,  # Betik param blogu ayrastirici
)


class TestPowerShellParameterSecurityAuditor(unittest.TestCase):
    """PowerShell betik parametreleri guvenlik motoru test senaryolari."""

    def setUp(self) -> None:
        """Her test kosumundan once taze motor ornegi ve ornek betik dosyalarini yukler."""
        self.auditor = PowerShellParameterSecurityAuditor()  # Denetim motoru ornegi olusturulur
        base_dir = Path(__file__).resolve().parent.parent / "ornek_veri"  # Ornek veri yolu
        self.secure_script_path = base_dir / "sample_secure_script.ps1"  # Guvenli betik yolu
        self.vulnerable_script_path = base_dir / "sample_vulnerable_script.ps1"  # Zaafiyetli betik yolu

    def test_01_parse_secure_script_parameters(self) -> None:
        """Guvenli ornek betikteki 5 parametrenin dogru tipler ve dogrulama kurallariyla ayrastirildigini test eder."""
        with open(self.secure_script_path, "r", encoding="utf-8") as f:  # Guvenli betik acilir
            content = f.read()  # Metin okunur
        has_binding, params = ScriptParamBlockParser.parse_script_parameters(content)  # Parametreler ayrastirilir
        self.assertTrue(has_binding)  # [CmdletBinding()] bulunmali
        self.assertEqual(len(params), 5)  # 5 adet parametre tanimli olmali
        param_names = [p.name for p in params]  # Parametre isimleri listelenir
        self.assertIn("LogPath", param_names)  # LogPath bulunmali
        self.assertIn("ApiKey", param_names)  # ApiKey bulunmali
        self.assertIn("TargetPort", param_names)  # TargetPort bulunmali

    def test_02_detect_cmdlet_binding_presence(self) -> None:
        """Zaafiyetli betikte [CmdletBinding()] eksikliginin tespit edildigini test eder."""
        report = self.auditor.audit_script_file(self.vulnerable_script_path)  # Zaafiyetli betik denetlenir
        self.assertFalse(report.has_cmdlet_binding)  # CmdletBinding olmadigi dogrulanir
        self.assertTrue(any(f.rule_name == "MISSING_CMDLET_BINDING" for f in report.findings))  # Bulgu kontrol edilir

    def test_03_detect_plaintext_password_parameter(self) -> None:
        """Acik metin [string]$Password parametre bildiriminin CRITICAL olarak yakalandigini test eder."""
        vulnerable_snippet = "param([string]$UserPassword, [int]$Port)"  # Acik metin parola bildirimi
        report = self.auditor.audit_script_text(vulnerable_snippet)  # Denetim yapilir
        self.assertTrue(any(f.rule_name == "PLAINTEXT_CREDENTIAL_PARAMETER" for f in report.findings))  # Kural kontrolu
        self.assertTrue(any(f.severity == ParameterSeverity.CRITICAL for f in report.findings))  # Seviye kontrolu

    def test_04_detect_plaintext_password_strict_exception(self) -> None:
        """strict=True modunda acik metin parola parametresinde PlaintextCredentialParameterException firlatildigini test eder."""
        vulnerable_snippet = "param([string]$SecretApiKey)"  # Hassas anahtar
        with self.assertRaises(PlaintextCredentialParameterException):  # Istisna beklenir
            self.auditor.audit_script_text(vulnerable_snippet, strict=True)  # Kati modda calistirilir

    def test_05_detect_unvalidated_path_parameter(self) -> None:
        """ValidateScript ile sinirlandirilmamis dosya yolu parametresinin HIGH olarak tespit edildigini test eder."""
        snippet = "param([string]$TargetFilePath)"  # Dogrulanmamis yol
        report = self.auditor.audit_script_text(snippet)  # Denetim calistirilir
        self.assertTrue(any(f.rule_name == "UNVALIDATED_PATH_PARAMETER" for f in report.findings))  # Bulgu kontrolu

    def test_06_detect_untyped_parameter(self) -> None:
        """Tip belirtilmemis (untyped) parametrenin MEDIUM seviyede zayiflik olarak yakalandigini dogrular."""
        snippet = "param($UnTypedConfig)"  # Tip belirtilmemis
        report = self.auditor.audit_script_text(snippet)  # Denetim yapilir
        self.assertTrue(any(f.rule_name == "UNTYPED_PARAMETER_DECLARATION" for f in report.findings))  # Bulgu

    def test_07_detect_subprocess_argument_injection_risk(self) -> None:
        """Dis komutlara parametre baglarken olusan arguman enjeksiyonu riskinin CRITICAL olarak raporlandigini test eder."""
        report = self.auditor.audit_script_file(self.vulnerable_script_path)  # Zaafiyetli betik denetlenir
        self.assertTrue(any(f.rule_name == "SUBPROCESS_ARGUMENT_INJECTION_RISK" for f in report.findings))  # Bulgu

    def test_08_runtime_validator_reject_null_byte(self) -> None:
        """Parametre degerinde null-byte (0x00) bulunmasi durumunda NullByteForbiddenException firlatildigini dogrular."""
        with self.assertRaises(NullByteForbiddenException):  # Istisna beklenir
            RuntimeParameterValidator.validate_string_param("Host", "server\x00.local")  # Null byte ile denenir

    def test_09_runtime_validator_reject_oversized_payload(self) -> None:
        """4096 karakterden uzun parametre girdisinin DoS korumasiyla engellendigini dogrular."""
        huge_input = "A" * 5000  # 5000 karakterlik asiri uzun girdi
        with self.assertRaises(ParameterSizeLimitExceededException):  # Istisna beklenir
            RuntimeParameterValidator.validate_string_param("Data", huge_input)  # Uzun girdi denenir

    def test_10_runtime_validator_path_traversal(self) -> None:
        """Dosya yolu parametresinde dizin atlama (..) girisiminin engellendigini test eder."""
        with self.assertRaises(ParameterPathTraversalException):  # Istisna beklenir
            RuntimeParameterValidator.validate_path_param("ConfigPath", "../../etc/passwd")  # Traversal denenir

    def test_11_runtime_validator_set_violation(self) -> None:
        """ValidateSet kumesi disinda bir deger girildiginde InvalidParameterSetException firlatildigini test eder."""
        allowed = {"Audit", "Enforce", "Report"}  # Izin verilen kume
        with self.assertRaises(InvalidParameterSetException):  # Istisna beklenir
            RuntimeParameterValidator.validate_set_param("Mode", "MaliciousMode", allowed)  # Hatali mod girilir

    def test_12_runtime_validator_range_violation(self) -> None:
        """ValidateRange sinirlari disinda sayi girildiginde ParameterOutOfRangeException firlatildigini test eder."""
        with self.assertRaises(ParameterOutOfRangeException):  # Istisna beklenir
            RuntimeParameterValidator.validate_range_param("Port", 75000, 1, 65535)  # 75000 portu denenir

    def test_13_runtime_validator_pattern_mismatch(self) -> None:
        """ValidatePattern kuralini ihlal eden karakterlerde ParameterPatternMismatchException firlatildigini test eder."""
        pattern = r"^[a-zA-Z0-9_\-\.]+$"  # Yalnizca guvenli karakter kalibi
        with self.assertRaises(ParameterPatternMismatchException):  # Istisna beklenir
            RuntimeParameterValidator.validate_pattern_param("Host", "srv; rm -rf /", pattern)  # Zararli metin

    def test_14_argument_injection_detector_strict_exception(self) -> None:
        """Arguman enjeksiyonu iceren degerlerde strict modda ArgumentInjectionDetectedException firlatildigini test eder."""
        zararli_deger = "127.0.0.1 && whoami"  # Komut zincirleme degeri
        with self.assertRaises(ArgumentInjectionDetectedException):  # Istisna beklenir
            ArgumentInjectionDetector.scan_argument_value(zararli_deger, strict=True)  # Kati modda denenir


if __name__ == "__main__":
    unittest.main()  # Modul calistirildiginda birim testler yurutulur
