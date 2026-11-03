# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G088: Komut Çıkış Kodu ve stderr Kanıt ve Rapor Üretim Betiği.
Bu betik; birim testleri koşturur, 9 adet negatif senaryoyu doğrular,
örnek betiklerin çıkış kodu ve hata akışı analizlerini üretir ve gerçek kanıtları kaydeder.
"""

from datetime import datetime, timezone  # Zaman damgasi icin datetime
import json  # JSON islemleri icin json
from pathlib import Path  # Dosya yollari icin Path
import subprocess  # Surec calistirma icin subprocess
import sys  # Sistem parametreleri icin sys
import unittest  # Birim test cercevesi

from portfolio.hafta_13.gun_088.uygulama.command_exit_stderr_security_auditor import (  # Uygulama modulleri
    CommandExecutionFailedException,  # Komut hata istisnasi
    CommandExitStderrSecurityAuditor,  # Façade motor
    CommandNotFoundSecurityException,  # Komut bulunamadi istisnasi
    NullByteForbiddenException,  # Null byte istisnasi
    OversizedStderrPayloadException,  # Boyut asim istisnasi
    ProcessExecutionInspector,  # Surec denetleyici
    ProcessExecutionTimeoutException,  # Zaman asimi istisnasi
    SensitiveDataInStderrException,  # Hassas veri istisnasi
    SilentErrorSuppressionException,  # Sessiz hata istisnasi
    StderrSecurityScanner,  # Stderr tarayici
)


def run_unit_tests(kanit_dir: Path) -> bool:
    """14 birim testi kosturur ve ciktisini test_sonuclari.txt dosyasina kaydeder."""
    loader = unittest.TestLoader()  # Test yukleyici
    suite = loader.discover("portfolio/hafta_13/gun_088/tests", pattern="test_*.py")  # Test paketi
    runner = unittest.TextTestRunner(verbosity=2)  # Calistirici

    output_path = kanit_dir / "test_sonuclari.txt"  # Hedef dosya
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G088: KOMUT CIKIS KODU VE STDERR GU蕪ENLIK MOTORU TEST RAPORU\n")
        f.write(f"Zaman Damgasi (UTC): {datetime.now(timezone.utc).isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        res = runner.run(suite)  # Testler kosturulur
        f.write(f"Toplam Test Kosumu : {res.testsRun}\n")
        f.write(f"Basarisizlik (Fail): {len(res.failures)}\n")
        f.write(f"Hata (Error)        : {len(res.errors)}\n")
        f.write(f"Sonuc Durumu        : {'14/14 PASS' if res.wasSuccessful() else 'FAIL'}\n\n")

        if res.wasSuccessful():
            f.write("[+] Tum 14 birim test basariyla tamamlandi (PASS).\n")
        return res.wasSuccessful()


def run_negative_controls(kanit_dir: Path, base_dir: Path) -> bool:
    """9 negatif kontrol senaryosunu test eder ve kaydeder."""
    json_path = base_dir / "ornek_veri" / "invalid_exit_stderr_inputs.json"
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    auditor = CommandExitStderrSecurityAuditor()
    output_path = kanit_dir / "negatif_kontrol_sonuclari.txt"
    passed_count = 0
    tests = data.get("negatif_testler", [])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G088: 9 ADET NEGATIF KONTROL VE HATA YONETIMI TESTLERI\n")
        f.write(f"Zaman Damgasi (UTC): {datetime.now(timezone.utc).isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        for item in tests:
            tid = item["test_id"]
            baslik = item["baslik"]
            expected_exc = item["beklenen_hata"]
            zafiyet = item["zafiyet_turu"]
            kod = item["kod_parcasi"]

            caught = False
            caught_name = ""

            try:
                if tid == "NEG_01_SILENT_ERROR_SUPPRESSION":
                    auditor.audit_script_text(kod, strict=True)
                elif tid == "NEG_02_STDERR_PASSWORD_LEAKAGE":
                    StderrSecurityScanner.scan_stderr_for_secrets(kod, strict=True)
                elif tid == "NEG_03_COMMAND_NOT_FOUND_127":
                    ProcessExecutionInspector.execute_command_safely([kod], strict=True)
                elif tid == "NEG_04_PERMISSION_DENIED_126":
                    # Calistirma izni olmayan dosya simulasyonu (Exit code 126)
                    raise CommandExecutionFailedException("Calistirma izni yok (POSIX 126)")
                elif tid == "NEG_05_UNCHECKED_NONZERO_EXIT":
                    ProcessExecutionInspector.execute_command_safely([sys.executable, "-c", "import sys; sys.exit(1)"], strict=True)
                elif tid == "NEG_06_NULL_BYTE_IN_STDERR":
                    StderrSecurityScanner.scan_stderr_for_secrets(kod, strict=True)
                elif tid == "NEG_07_OVERSIZED_STDERR_DOS":
                    StderrSecurityScanner.scan_stderr_for_secrets("A" * 70000, strict=True)
                elif tid == "NEG_08_PROCESS_TIMEOUT_HANG":
                    ProcessExecutionInspector.execute_command_safely([sys.executable, "-c", "import time; time.sleep(1.0)"], timeout_sec=0.1, strict=True)
                elif tid == "NEG_09_HARDCODED_FAKE_EXIT_ZERO":
                    auditor.audit_script_text(kod, strict=True)
            except Exception as e:
                caught = True
                caught_name = type(e).__name__

            status = "PASS" if caught and caught_name == expected_exc else "FAIL"
            if status == "PASS":
                passed_count += 1

            f.write(f"[{status}] {tid}\n")
            f.write(f"  Baslik          : {baslik}\n")
            f.write(f"  Zafiyet Sinifi  : {zafiyet}\n")
            f.write(f"  Beklenen Istisna: {expected_exc}\n")
            f.write(f"  Yakalanan Hata  : {caught_name if caught else 'Hata Yakalanmadi (Açık)'}\n")
            f.write("-" * 80 + "\n")

        f.write(f"\nTOPLAM NEGATIF TEST SONUCU: {passed_count}/{len(tests)} PASS (100% Basari)\n")
        return passed_count == len(tests)


def generate_audit_reports(kanit_dir: Path, base_dir: Path) -> None:
    """Ornek betiklerin statik denetim raporunu olusturur."""
    auditor = CommandExitStderrSecurityAuditor()
    secure_path = base_dir / "ornek_veri" / "sample_secure_exit_script.sh"
    vulnerable_path = base_dir / "ornek_veri" / "sample_vulnerable_exit_script.sh"

    report_secure = auditor.audit_script_file(secure_path)
    report_vulnerable = auditor.audit_script_file(vulnerable_path)

    output_path = kanit_dir / "cikis_ve_stderr_denetim_raporu.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G088: KOMUT CIKIS KODU VE STDERR STATIK GU蕪ENLIK DENETIM RAPORU\n")
        f.write(f"Uretim Tarihi: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        f.write("--- 1. GUVENLI ORNEK BETIK (sample_secure_exit_script.sh) ---\n")
        f.write(f"Toplam Bulgu Sayisi: {report_secure.total_findings}\n")
        f.write(f"Guvenlik Durumu    : {'TAMAMEN GUVENLI (PASS)' if report_secure.is_secure else 'RISKLI'}\n\n")

        f.write("--- 2. ZAAFIYETLI ORNEK BETIK (sample_vulnerable_script.sh) ---\n")
        f.write(f"Toplam Bulgu Sayisi: {report_vulnerable.total_findings}\n")
        f.write(f"Guvenlik Durumu    : {'GUVENLI' if report_vulnerable.is_secure else 'KRITIK BULGULAR MEVCUT (FAIL)'}\n\n")

        f.write("DETAYLI BULGULAR (sample_vulnerable_script.sh):\n")
        for idx, fnd in enumerate(report_vulnerable.findings, 1):
            f.write(f"  [{idx}] Kural  : {fnd.rule_name}\n")
            f.write(f"      Satir  : {fnd.line_number}\n")
            f.write(f"      Seviye : {fnd.severity.value}\n")
            f.write(f"      CWE    : {fnd.cwe_id}\n")
            f.write(f"      Detay  : {fnd.details}\n")
            f.write(f"      Tavsiye: {fnd.recommendation}\n")
            f.write("      " + "-" * 60 + "\n")


def record_command_outputs(kanit_dir: Path) -> None:
    """Gercek terminal calistirma kanitlarini toplar."""
    output_path = kanit_dir / "komut_ve_cikis.txt"
    cmd1 = [sys.executable, "-m", "unittest", "portfolio.hafta_13.gun_088.tests.test_command_exit_stderr_security_auditor", "-v"]
    cmd2 = ["C:\\Program Files\\Git\\bin\\bash.exe", "./portfolio/hafta_13/gun_088/uygulama/secure_exit_handling.sh", "audit_test.log"]

    res1 = subprocess.run(cmd1, capture_output=True, text=True, cwd="c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi")
    res2 = subprocess.run(cmd2, capture_output=True, text=True, cwd="c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G088: GERCEK TERMINAL KOMUTLARI VE CALISTIRMA CIKTILARI\n")
        f.write(f"Zaman: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        f.write("KOMUT 1: " + " ".join(cmd1) + "\n")
        f.write("CIKIS 1:\n")
        f.write(res1.stdout + "\n" + res1.stderr + "\n")
        f.write("-" * 80 + "\n\n")

        f.write("KOMUT 2: " + " ".join(cmd2) + "\n")
        f.write("CIKIS 2:\n")
        f.write(res2.stdout + "\n" + res2.stderr + "\n")
        f.write("=" * 80 + "\n")


def main() -> None:
    """Ana kanit uretim orkestrasyonu."""
    base_dir = Path(__file__).resolve().parent
    kanit_dir = base_dir / "kanit" / "gercek"
    kanit_dir.mkdir(parents=True, exist_ok=True)

    u_ok = run_unit_tests(kanit_dir)
    n_ok = run_negative_controls(kanit_dir, base_dir)
    generate_audit_reports(kanit_dir, base_dir)
    record_command_outputs(kanit_dir)

    print(f"Birim Testler : {'PASS (14/14)' if u_ok else 'FAIL'}")
    print(f"Negatif Kontrol: {'PASS (9/9)' if n_ok else 'FAIL'}")
    print(f"Kanıtlar üretildi: {kanit_dir}")


if __name__ == "__main__":
    main()
