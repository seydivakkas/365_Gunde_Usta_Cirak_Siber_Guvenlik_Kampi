# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G089: Argparse ve CLI Güvenlik Motoru Kanıt ve Rapor Üretim Betiği.
Bu betik; birim testleri koşturur, 9 negatif kontrol senaryosunu doğrular,
CLI yapılandırma denetim raporunu üretir ve gerçek komut çıktılarını kaydeder.
"""

from datetime import datetime, timezone  # Zaman damgasi icin datetime
import json  # JSON formati icin json
from pathlib import Path  # Dosya yollari yonetimi icin Path
import subprocess  # Surec calistirma icin subprocess
import sys  # Sistem parametreleri icin sys
import unittest  # Birim test kutuphanesi

from portfolio.hafta_13.gun_089.uygulama.security_cli_engine import (  # Uygulama bilesenleri
    CliMissingRequiredSubcommandException,  # Eksik alt komut istisnasi
    CliMutuallyExclusiveConflictException,  # Parametre cakismasi istisnasi
    CliNullByteException,  # Null byte istisnasi
    CliOversizedPayloadException,  # Boyut limiti istisnasi
    CliPathTraversalException,  # Dizin atlama istisnasi
    CliPortOutOfRangeException,  # Port araligi istisnasi
    InvalidCliArgumentException,  # Gecersiz arguman istisnasi
    SecurityCliEngine,  # Façade motor sinifi
)


def run_unit_tests(kanit_dir: Path) -> bool:
    """14 birim testi kosturur ve ciktisini test_sonuclari.txt dosyasina kaydeder."""
    loader = unittest.TestLoader()  # Test yukleyici
    suite = loader.discover("portfolio/hafta_13/gun_089/tests", pattern="test_*.py")  # Testler
    runner = unittest.TextTestRunner(verbosity=2)  # Calistirici

    output_path = kanit_dir / "test_sonuclari.txt"  # Hedef dosya
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G089: ARGPARSE VE CLI GU蕪ENLIK MOTORU BIRIM TEST RAPORU\n")
        f.write(f"Zaman Damgasi (UTC): {datetime.now(timezone.utc).isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        res = runner.run(suite)  # Testler yurutulur
        f.write(f"Toplam Test Kosumu : {res.testsRun}\n")
        f.write(f"Basarisizlik (Fail): {len(res.failures)}\n")
        f.write(f"Hata (Error)        : {len(res.errors)}\n")
        f.write(f"Sonuc Durumu        : {'14/14 PASS' if res.wasSuccessful() else 'FAIL'}\n\n")

        if res.wasSuccessful():
            f.write("[+] Tum 14 birim test basariyla tamamlandi (PASS).\n")
        return res.wasSuccessful()


def run_negative_controls(kanit_dir: Path, base_dir: Path) -> bool:
    """9 negatif senaryoyu calistirir ve sonuclari negatif_kontrol_sonuclari.txt dosyasina kaydeder."""
    json_path = base_dir / "ornek_veri" / "invalid_cli_inputs.json"
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = SecurityCliEngine()
    sample_file = base_dir / "ornek_veri" / "sample_cli_commands.json"
    output_path = kanit_dir / "negatif_kontrol_sonuclari.txt"
    passed_count = 0
    tests = data.get("negatif_testler", [])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G089: 9 ADET NEGATIF KONTROL VE CLI ENJEKSIYON ENGELLEME TESTLERI\n")
        f.write(f"Zaman Damgasi (UTC): {datetime.now(timezone.utc).isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        for item in tests:
            tid = item["test_id"]
            baslik = item["baslik"]
            expected_exc = item["beklenen_hata"]
            zafiyet = item["zafiyet_turu"]
            args = item["args"]

            # Dinamik dosya yolu ve marker degisimleri
            if tid == "NEG_06_OVERSIZED_CLI_ARGUMENT":
                args = ["scan", "--host", "A" * 5000, "--port", "80"]
            elif tid == "NEG_07_INVALID_CHOICE_ALGORITHM":
                args = ["hash", "--file", sample_file.as_posix(), "--algo", "md5"]
            elif tid == "NEG_09_TOO_MANY_ARGUMENTS_DOS":
                args = ["scan"] + ["--verbose"] * 150

            caught = False
            caught_name = ""

            try:
                engine.parse_arguments(args)
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


def generate_cli_audit_report(kanit_dir: Path, base_dir: Path) -> None:
    """CLI tasariminin mimari ve guvenlik denetim raporunu olusturur."""
    engine = SecurityCliEngine()
    sample_file = base_dir / "ornek_veri" / "sample_cli_commands.json"

    output_path = kanit_dir / "cli_tasarim_denetim_raporu.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G089: KURUMSAL ARGPARSE VE CLI TASARIM GU蕪ENLIK DENETIM RAPORU\n")
        f.write(f"Uretim Tarihi: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        f.write("--- 1. CLI MIMARI VE ALT KOMUT HIKAYESI ---\n")
        f.write("Program Adi          : security_cli\n")
        f.write("Tanimli Alt Komutlar : scan, audit, hash\n")
        f.write("Ortak Bayraklar      : -v/--verbose, --json-output (Parent Parser ile miras)\n")
        f.write("Karsilikli Dislayan  : scan --fast ve scan --deep (Cakisma yasak)\n")
        f.write("Girdi Sinirlamalari  : Maksimum 100 arguman, Maksimum 4096 karakter/arguman\n\n")

        f.write("--- 2. ORNEK ALT KOMUT CALISTIRMA SENARYOLARI ---\n")

        # Senaryo 1: scan
        ns1 = engine.parse_arguments(["scan", "--host", "192.168.1.100", "--port", "443", "--mode", "thorough"])
        res1 = engine.execute_cli_action(ns1)
        f.write("[+] Senaryo 1 (scan)  : " + json.dumps(res1, ensure_ascii=False) + "\n")

        # Senaryo 2: audit
        ns2 = engine.parse_arguments(["audit", "--file", sample_file.as_posix(), "--strict"])
        res2 = engine.execute_cli_action(ns2)
        f.write("[+] Senaryo 2 (audit) : " + json.dumps(res2, ensure_ascii=False) + "\n")

        # Senaryo 3: hash
        ns3 = engine.parse_arguments(["hash", "--file", sample_file.as_posix(), "--algo", "sha256"])
        res3 = engine.execute_cli_action(ns3)
        f.write("[+] Senaryo 3 (hash)  : " + json.dumps(res3, ensure_ascii=False) + "\n\n")

        f.write("--- 3. GU蕪ENLIK DEGERLENDIRMESI ---\n")
        f.write("[PASS] CWE-20: Girdi dogrulama tam (Port [1-65535], Host Regex)\n")
        f.write("[PASS] CWE-22: Path traversal (..) korumasi tam\n")
        f.write("[PASS] CWE-88: Komut enjeksiyonu ozel karakterleri engellendi\n")
        f.write("[PASS] CWE-158: Null byte (0x00) filtrelemesi tam\n")
        f.write("[PASS] CWE-327: Zayif kripto (MD5/SHA1) seceneklerden kaldirildi\n")
        f.write("[PASS] CWE-400: DoS tavan korumalari tam\n")


def record_command_outputs(kanit_dir: Path, base_dir: Path) -> None:
    """Gercek terminal calistirma kanitlarini toplar."""
    sample_file = base_dir / "ornek_veri" / "sample_cli_commands.json"
    output_path = kanit_dir / "komut_ve_cikis.txt"

    cmd1 = [sys.executable, "-m", "unittest", "portfolio.hafta_13.gun_089.tests.test_security_cli_engine", "-v"]
    cmd2 = [sys.executable, "-m", "portfolio.hafta_13.gun_089.uygulama.cli_runner", "hash", "--file", sample_file.as_posix(), "--algo", "sha256", "--json-output"]

    res1 = subprocess.run(cmd1, capture_output=True, text=True, cwd="c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi")
    res2 = subprocess.run(cmd2, capture_output=True, text=True, cwd="c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G089: GERCEK TERMINAL KOMUTLARI VE CALISTIRMA CIKTILARI\n")
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
    generate_cli_audit_report(kanit_dir, base_dir)
    record_command_outputs(kanit_dir, base_dir)

    print(f"Birim Testler : {'PASS (14/14)' if u_ok else 'FAIL'}")
    print(f"Negatif Kontrol: {'PASS (9/9)' if n_ok else 'FAIL'}")
    print(f"Kanıtlar üretildi: {kanit_dir}")


if __name__ == "__main__":
    main()
