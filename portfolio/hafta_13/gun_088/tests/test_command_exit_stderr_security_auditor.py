# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G088: Komut Çıkış Kodu ve stderr Güvenlik Motoru Birim Testleri (unittest).
Bu test paketi; POSIX çıkış kodlarını, stderr akışındaki kimlik bilgisi sızıntılarını (CWE-209),
sessiz hata yutmayı (CWE-390), süreç zaman aşımlarını ve sınır kontrollerini doğrular.
"""

from pathlib import Path  # Dosya yollari yonetimi icin Path modulu
import sys  # Python calistirici yolu icin sys modulu
import unittest  # Birim test cercevesi

from portfolio.hafta_13.gun_088.uygulama.command_exit_stderr_security_auditor import (  # Uygulama bilesenleri
    CommandExecutionFailedException,  # Komut hata istisnasi
    CommandExitStderrSecurityAuditor,  # Façade motor sinifi
    CommandNotFoundSecurityException,  # Komut bulunamadi istisnasi
    ExecutionResult,  # Yurutme sonucu modeli
    ExitSeverity,  # Ciddiyet enum modeli
    NullByteForbiddenException,  # Null byte istisnasi
    OversizedStderrPayloadException,  # Boyut asim istisnasi
    ProcessExecutionInspector,  # Surec denetleyici bilesen
    ProcessExecutionTimeoutException,  # Zaman asimi istisnasi
    ScriptErrorHandlingAuditor,  # Betik hata analizcisi
    SensitiveDataInStderrException,  # Hassas veri istisnasi
    SilentErrorSuppressionException,  # Sessiz hata istisnasi
    StderrSecurityScanner,  # Stderr tarayici bilesen
)


class TestCommandExitStderrSecurityAuditor(unittest.TestCase):
    """Komut cikis kodu ve stderr guvenlik motoru test senaryolari."""

    def setUp(self) -> None:
        """Her testten once taze motor ornegi ve ornek veri yollarini hazirlar."""
        self.auditor = CommandExitStderrSecurityAuditor()  # Denetim motoru ornegi
        base_dir = Path(__file__).resolve().parent.parent / "ornek_veri"  # Ornek veri dizini
        self.secure_script_path = base_dir / "sample_secure_exit_script.sh"  # Guvenli betik yolu
        self.vulnerable_script_path = base_dir / "sample_vulnerable_exit_script.sh"  # Zaafiyetli betik yolu

    def test_01_successful_command_exit_zero(self) -> None:
        """Basarili bir komutun cikis kodunun 0 ve is_success=True oldugunu test eder."""
        cmd = [sys.executable, "-c", "print('Guvenli Cikti')"]  # Basarili python komutu
        res = ProcessExecutionInspector.execute_command_safely(cmd)  # Komut yurutulur
        self.assertEqual(res.exit_code, 0)  # Cikis kodu 0 olmali
        self.assertTrue(res.is_success)  # Basarili sayilmali
        self.assertIn("Guvenli Cikti", res.stdout)  # Cikti dogrulanmali

    def test_02_detect_nonzero_exit_code(self) -> None:
        """Sifir disi cikis kodu (ornek: 42) uretildiginde basarisiz durumunun yakalandigini test eder."""
        cmd = [sys.executable, "-c", "import sys; sys.exit(42)"]  # 42 cikis kodlu komut
        res = ProcessExecutionInspector.execute_command_safely(cmd)  # Yurutulur
        self.assertEqual(res.exit_code, 42)  # Cikis kodu 42 olmali
        self.assertFalse(res.is_success)  # Basarisiz olarak isaretlenmeli

    def test_03_detect_silent_error_suppression_dev_null(self) -> None:
        """2> /dev/null ile hata yutulmasinin HIGH seviyeli bulgu olarak tespit edildigini test eder."""
        snippet = "curl -s http://internal.api 2> /dev/null\n"  # Sessizce yutulan hata
        report = self.auditor.audit_script_text(snippet)  # Denetim yapilir
        self.assertTrue(any(f.rule_name == "SILENT_ERROR_SUPPRESSION" for f in report.findings))  # Bulgu kontrolu

    def test_04_detect_silent_error_suppression_strict_exception(self) -> None:
        """strict=True modunda 2> /dev/null tespit edildiginde SilentErrorSuppressionException firlatildigini test eder."""
        snippet = "tar -czf backup.tar.gz /data 2> /dev/null\n"  # Sessiz hata
        with self.assertRaises(SilentErrorSuppressionException):  # Istisna beklenir
            self.auditor.audit_script_text(snippet, strict=True)  # Kati modda calistirilir

    def test_05_detect_stderr_password_leakage(self) -> None:
        """stderr akisina parola yazdirilmasinin CRITICAL olarak yakalandigini test eder."""
        err_msg = "Database auth failed. Password: SuperSecretAdminPass123!\n"  # Parola iceren stderr
        findings = StderrSecurityScanner.scan_stderr_for_secrets(err_msg)  # Tarama yapilir
        self.assertTrue(any(f.rule_name == "STDERR_PLAINTEXT_PASSWORD_LEAKAGE" for f in findings))  # Kural kontrolu
        self.assertTrue(any(f.severity == ExitSeverity.CRITICAL for f in findings))  # Seviye kontrolu

    def test_06_detect_stderr_password_leakage_strict_exception(self) -> None:
        """strict=True modunda stderr parolasinda SensitiveDataInStderrException firlatildigini test eder."""
        err_msg = "Auth error: pwd: MySecretToken12345\n"  # Hassas hata metni
        with self.assertRaises(SensitiveDataInStderrException):  # Istisna beklenir
            StderrSecurityScanner.scan_stderr_for_secrets(err_msg, strict=True)  # Kati modda denenir

    def test_07_detect_stderr_db_uri_leakage(self) -> None:
        """stderr akisinda veritabani kimlikli baglanti URI'sinin tespit edildigini test eder."""
        err_msg = "Connection failed to postgres://admin:P@ssw0rd@db.internal:5432/corp\n"  # URI hatasi
        findings = StderrSecurityScanner.scan_stderr_for_secrets(err_msg)  # Tarama yapilir
        self.assertTrue(any(f.rule_name == "STDERR_DATABASE_URI_LEAKAGE" for f in findings))  # Bulgu kontrolu

    def test_08_detect_fraudulent_fake_exit_zero(self) -> None:
        """set -e olmadan en sonda 'exit 0' donulmesinin sahte basari (CWE-390) olarak yakalandigini test eder."""
        snippet = "tar -czf b.tar /missing\nrm -rf /tmp/data\nexit 0\n"  # set -e siz sahte basari
        report = self.auditor.audit_script_text(snippet)  # Denetim yapilir
        self.assertTrue(any(f.rule_name == "FRAUDULENT_SUCCESS_EXIT_ZERO" for f in report.findings))  # Bulgu

    def test_09_command_not_found_127_handling(self) -> None:
        """Sistemde bulunamayan bir komut calistirildiginda CommandNotFoundSecurityException firlatildigini test eder."""
        cmd = ["non_existent_binary_xyz_12345"]  # Olmayan komut
        with self.assertRaises(CommandNotFoundSecurityException):  # Istisna beklenir
            ProcessExecutionInspector.execute_command_safely(cmd, strict=True)  # Kati modda denenir

    def test_10_execution_timeout_detection(self) -> None:
        """Surecin zaman asimina ugramasi durumunda ProcessExecutionTimeoutException firlatildigini test eder."""
        cmd = [sys.executable, "-c", "import time; time.sleep(1.0)"]  # 1 saniye uyuyan komut
        with self.assertRaises(ProcessExecutionTimeoutException):  # Istisna beklenir
            ProcessExecutionInspector.execute_command_safely(cmd, timeout_sec=0.1, strict=True)  # 0.1 sn zaman asimi

    def test_11_reject_null_byte_in_command(self) -> None:
        """Komut argumaninda null byte (0x00) bulunmasi durumunda NullByteForbiddenException firlatildigini dogrular."""
        cmd = [sys.executable, "-c", "print('hello\x00world')"]  # Null byte iceren arguman
        with self.assertRaises(NullByteForbiddenException):  # Istisna beklenir
            ProcessExecutionInspector.execute_command_safely(cmd)  # Calistirilir

    def test_12_reject_null_byte_in_script_text(self) -> None:
        """Betik metninde null-byte tespit edildiginde NullByteForbiddenException firlatildigini test eder."""
        with self.assertRaises(NullByteForbiddenException):  # Istisna beklenir
            self.auditor.audit_script_text("echo 'valid\x00injected'\n")  # Null byte'li betik

    def test_13_reject_oversized_stderr_payload(self) -> None:
        """64 KB limitini asan stderr ciktisinda OversizedStderrPayloadException firlatildigini test eder."""
        huge_stderr = "ERROR: " + ("A" * 70000)  # 70 KB hata metni
        with self.assertRaises(OversizedStderrPayloadException):  # Istisna beklenir
            StderrSecurityScanner.scan_stderr_for_secrets(huge_stderr)  # Limit kontrolu

    def test_14_audit_vulnerable_script_full_report(self) -> None:
        """Zaafiyetli ornek betigin tum aciklarinin tespit edildigini ve is_secure=False dondugunu dogrular."""
        report = self.auditor.audit_script_file(self.vulnerable_script_path)  # Zaafiyetli betik taranir
        self.assertFalse(report.is_secure)  # Guvenli olmamali
        rule_names = [f.rule_name for f in report.findings]  # Kural isimleri listelenir
        self.assertIn("SILENT_ERROR_SUPPRESSION", rule_names)  # 2> /dev/null bulunmali
        self.assertIn("STDERR_CREDENTIAL_PRINT", rule_names)  # Stderr parola sizintisi bulunmali
        self.assertIn("FRAUDULENT_SUCCESS_EXIT_ZERO", rule_names)  # Sahte exit 0 bulunmali


if __name__ == "__main__":
    unittest.main()  # Modul calistirildiginda birim testler yurutulur
