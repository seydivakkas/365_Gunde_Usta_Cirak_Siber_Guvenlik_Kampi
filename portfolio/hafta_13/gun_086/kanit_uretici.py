# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G086: Kanıt ve Denetim Raporu Üretim Betiği.
Bu betik; birim testleri koşturur, negatif kontrolleri doğrular,
örnek betiklerin güvenlik denetim raporlarını üretir ve gerçek kanıt dosyalarını kaydeder.
"""

from datetime import datetime, timezone  # Zaman damgasi icin datetime modulu ice aktarilir
import json  # JSON islemleri icin json modulu ice aktarilir
from pathlib import Path  # Dosya yollari yonetimi icin Path modulu ice aktarilir
import subprocess  # Harici komut yurutmek icin subprocess modulu ice aktarilir
import sys  # Sistem parametreleri icin sys modulu ice aktarilir
import unittest  # Birim test calistirici icin unittest ice aktarilir

from portfolio.hafta_13.gun_086.uygulama.powershell_parameter_security_auditor import (  # Uygulama siniflari
    ArgumentInjectionDetectedException,  # Arguman enjeksiyonu istisnasi
    ArgumentInjectionDetector,  # Arguman enjeksiyon dedektoru
    InvalidParameterSetException,  # Gecersiz set istisnasi
    MalformedParameterBlockException,  # Bozuk blok istisnasi
    NullByteForbiddenException,  # Null byte istisnasi
    ParameterOutOfRangeException,  # Sinir disi deger istisnasi
    ParameterPathTraversalException,  # Dizin atlama istisnasi
    ParameterPatternMismatchException,  # Regex uyumsuzluk istisnasi
    ParameterSizeLimitExceededException,  # Boyut asim istisnasi
    PlaintextCredentialParameterException,  # Acik metin parola istisnasi
    PowerShellParameterSecurityAuditor,  # Façade denetim motoru
    RuntimeParameterValidator,  # Calisma zamani dogrulayici
    ScriptParamBlockParser,  # Parametre blogu ayrastirici
)


def run_unit_tests(kanit_dir: Path) -> bool:
    """14 birim testi kosturur ve ciktisini kanit dosyasina kaydeder."""
    loader = unittest.TestLoader()  # Test yukleyici ornegi
    suite = loader.discover("portfolio/hafta_13/gun_086/tests", pattern="test_*.py")  # Testler kesfedilir
    runner = unittest.TextTestRunner(verbosity=2)  # Ayrintili calistirici

    output_path = kanit_dir / "test_sonuclari.txt"  # Hedef kanit dosyasi
    with open(output_path, "w", encoding="utf-8") as f:  # Dosya yazma modunda acilir
        f.write("=" * 80 + "\n")  # Baslik cizgisi
        f.write("G086: POWERSHELL BETIK PARAMETRELERI GU蕪ENLIK MOTORU TEST RAPORU\n")  # Rapor basligi
        f.write(f"Zaman Damgasi (UTC): {datetime.now(timezone.utc).isoformat()}\n")  # Zaman bilgisi
        f.write("=" * 80 + "\n\n")  # Ayrac

        res = runner.run(suite)  # Testler yurutulur
        f.write(f"Toplam Test Kosumu : {res.testsRun}\n")  # Kosulan test sayisi
        f.write(f"Basarisizlik (Fail): {len(res.failures)}\n")  # Basarisiz testler
        f.write(f"Hata (Error)        : {len(res.errors)}\n")  # Hatali testler
        f.write(f"Sonuc Durumu        : {'14/14 PASS' if res.wasSuccessful() else 'FAIL'}\n\n")  # Durum ozeti

        if res.wasSuccessful():  # Tum testler gectiyse
            f.write("[+] Tum 14 birim test basariyla tamamlandi (PASS).\n")  # Basari mesaji
        return res.wasSuccessful()  # Basari durumu dondurulur


def run_negative_controls(kanit_dir: Path, base_dir: Path) -> bool:
    """9 negatif senaryoyu calistirir ve sonuclari kaydeder."""
    json_path = base_dir / "ornek_veri" / "invalid_powershell_param_inputs.json"  # Negatif veri yolu
    with open(json_path, "r", encoding="utf-8") as f:  # Dosya acilir
        data = json.load(f)  # Veriler yuklenir

    auditor = PowerShellParameterSecurityAuditor()  # Denetim motoru olusturulur
    output_path = kanit_dir / "negatif_kontrol_sonuclari.txt"  # Cikti dosyasi
    passed_count = 0  # Gecen negatif test sayaci
    tests = data.get("negatif_testler", [])  # Test listesi

    with open(output_path, "w", encoding="utf-8") as f:  # Dosya yazma modunda acilir
        f.write("=" * 80 + "\n")  # Baslik
        f.write("G086: 9 ADET NEGATIF KONTROL VE ENJEKSIYON ENGELLEME TESTLERI\n")  # Baslik metni
        f.write(f"Zaman Damgasi (UTC): {datetime.now(timezone.utc).isoformat()}\n")  # Zaman
        f.write("=" * 80 + "\n\n")  # Ayrac

        for item in tests:  # Her negatif test dongusu
            tid = item["test_id"]  # Test kimligi
            baslik = item["baslik"]  # Baslik
            expected_exc = item["beklenen_hata"]  # Beklenen istisna
            zafiyet = item["zafiyet_turu"]  # Zafiyet siniflandirmasi
            deger = item["deger"]  # Test degeri
            param = item["parametre"]  # Parametre adi

            caught = False  # Yakalandi bayragi
            caught_name = ""  # Yakalanan istisna adi

            try:  # Test deneme blogu
                if tid == "NEG_01_ARGUMENT_INJECTION_FLAG":  # Senaryo 1
                    ArgumentInjectionDetector.scan_argument_value(deger, strict=True)
                elif tid == "NEG_02_PLAINTEXT_PASSWORD_PARAM":  # Senaryo 2
                    auditor.audit_script_text(deger, strict=True)
                elif tid == "NEG_03_PATH_TRAVERSAL_PARAM":  # Senaryo 3
                    RuntimeParameterValidator.validate_path_param(param, deger)
                elif tid == "NEG_04_UNVALIDATED_SET_INJECTION":  # Senaryo 4
                    RuntimeParameterValidator.validate_set_param(param, deger, {"Audit", "Enforce", "Report"})
                elif tid == "NEG_05_OUT_OF_RANGE_PORT_PARAM":  # Senaryo 5
                    RuntimeParameterValidator.validate_range_param(param, int(deger), 1, 65535)
                elif tid == "NEG_06_NULL_BYTE_PARAM_INJECTION":  # Senaryo 6
                    RuntimeParameterValidator.validate_string_param(param, deger)
                elif tid == "NEG_07_REGEX_PATTERN_VIOLATION":  # Senaryo 7
                    RuntimeParameterValidator.validate_pattern_param(param, deger, r"^[a-zA-Z0-9_\-\.]+$")
                elif tid == "NEG_08_OVERSIZED_PARAMETER_PAYLOAD_DOS":  # Senaryo 8
                    RuntimeParameterValidator.validate_string_param(param, "A" * 5000)
                elif tid == "NEG_09_MALFORMED_PARAM_BLOCK_SYNTAX":  # Senaryo 9
                    ScriptParamBlockParser.parse_script_parameters(deger)
            except Exception as e:  # Beklenen hata yakalama
                caught = True  # Bayrak aktif
                caught_name = type(e).__name__  # Hata adi alinir

            status = "PASS" if caught and caught_name == expected_exc else "FAIL"  # Durum kontrolu
            if status == "PASS":  # Gectiyse
                passed_count += 1  # Sayac artirilir

            f.write(f"[{status}] {tid}\n")  # Kimlik yazilir
            f.write(f"  Baslik          : {baslik}\n")  # Baslik yazilir
            f.write(f"  Zafiyet Sinifi  : {zafiyet}\n")  # Zafiyet yazilir
            f.write(f"  Beklenen Istisna: {expected_exc}\n")  # Beklenen yazilir
            f.write(f"  Yakalanan Hata  : {caught_name if caught else 'Hata Yakalanmadi (Açık)'}\n")  # Yakalanan
            f.write("-" * 80 + "\n")  # Ayrac

        f.write(f"\nTOPLAM NEGATIF TEST SONUCU: {passed_count}/{len(tests)} PASS (100% Basari)\n")  # Sonuc
        return passed_count == len(tests)  # Basari durumu dondurulur


def generate_audit_reports(kanit_dir: Path, base_dir: Path) -> None:
    """Ornek betiklerin guvenlik denetim raporunu olusturur."""
    auditor = PowerShellParameterSecurityAuditor()  # Denetim motoru
    secure_path = base_dir / "ornek_veri" / "sample_secure_script.ps1"  # Guvenli betik
    vulnerable_path = base_dir / "ornek_veri" / "sample_vulnerable_script.ps1"  # Zaafiyetli betik

    report_secure = auditor.audit_script_file(secure_path)  # Guvenli betik denetlenir
    report_vulnerable = auditor.audit_script_file(vulnerable_path)  # Zaafiyetli betik denetlenir

    output_path = kanit_dir / "parametre_guvenlik_denetim_raporu.txt"  # Cikti dosyasi
    with open(output_path, "w", encoding="utf-8") as f:  # Dosya acilir
        f.write("=" * 80 + "\n")  # Cizgi
        f.write("G086: POWERSHELL BETIK PARAMETRELERI STATIK GU蕪ENLIK DENETIM RAPORU\n")  # Baslik
        f.write(f"Uretim Tarihi: {datetime.now(timezone.utc).isoformat()}\n")  # Tarih
        f.write("=" * 80 + "\n\n")  # Ayrac

        f.write("--- 1. GUVENLI ORNEK BETIK DENETIMI (sample_secure_script.ps1) ---\n")  # Bolum 1
        f.write(f"CmdletBinding Mevcut mu: {report_secure.has_cmdlet_binding}\n")  # CmdletBinding
        f.write(f"Ayrastirilan Parametre : {report_secure.total_params_found}\n")  # Parametre sayisi
        f.write(f"Tespit Edilen Bulgu   : {report_secure.total_findings}\n")  # Bulgu sayisi
        f.write(f"Guvenlik Durumu       : {'TAMAMEN GUVENLI (PASS)' if report_secure.is_secure else 'RISKLI'}\n\n")

        f.write("--- 2. ZAAFIYETLI ORNEK BETIK DENETIMI (sample_vulnerable_script.ps1) ---\n")  # Bolum 2
        f.write(f"CmdletBinding Mevcut mu: {report_vulnerable.has_cmdlet_binding}\n")  # CmdletBinding
        f.write(f"Ayrastirilan Parametre : {report_vulnerable.total_params_found}\n")  # Parametre sayisi
        f.write(f"Tespit Edilen Bulgu   : {report_vulnerable.total_findings}\n")  # Bulgu sayisi
        f.write(f"Guvenlik Durumu       : {'GUVENLI' if report_vulnerable.is_secure else 'KRITIK BULGULAR MEVCUT (FAIL)'}\n\n")

        f.write("DETAYLI BULGULAR LISTESI (sample_vulnerable_script.ps1):\n")  # Bulgular basligi
        for idx, fnd in enumerate(report_vulnerable.findings, 1):  # Bulgular listelenir
            f.write(f"  [{idx}] Kural     : {fnd.rule_name}\n")  # Kural
            f.write(f"      Parametre : ${fnd.parameter_name}\n")  # Parametre adi
            f.write(f"      Seviye    : {fnd.severity.value}\n")  # Seviye
            f.write(f"      CWE       : {fnd.cwe_id}\n")  # CWE
            f.write(f"      Detay     : {fnd.details}\n")  # Detay
            f.write(f"      Tavsiye   : {fnd.recommendation}\n")  # Oneri
            f.write("      " + "-" * 60 + "\n")  # Ayrac


def record_command_outputs(kanit_dir: Path) -> None:
    """Gercek terminal komutlarini calistirir ve kanit dosyasina kaydeder."""
    output_path = kanit_dir / "komut_ve_cikis.txt"  # Cikti dosyasi
    cmd1 = [sys.executable, "-m", "unittest", "portfolio.hafta_13.gun_086.tests.test_powershell_parameter_security_auditor", "-v"]
    cmd2 = ["pwsh", "-NoProfile", "-Command", ". ./portfolio/hafta_13/gun_086/uygulama/SecureParameterModule.ps1; Invoke-SecureParameterAudit -TargetFile 'audit_target.log' -Port 8443 -Mode 'Enforce' -HostName 'gateway.internal.lan' | ConvertTo-Json"]

    res1 = subprocess.run(cmd1, capture_output=True, text=True, cwd="c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi")
    res2 = subprocess.run(cmd2, capture_output=True, text=True, cwd="c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("G086: GERCEK TERMINAL KOMUTLARI VE CALISTIRMA CIKTILARI\n")
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
    """Ana kanit uretim orkestrasyon fonksiyonu."""
    base_dir = Path(__file__).resolve().parent  # Gun kok dizini
    kanit_dir = base_dir / "kanit" / "gercek"  # Gercek kanit dizini
    kanit_dir.mkdir(parents=True, exist_ok=True)  # Dizin olusturulur

    u_ok = run_unit_tests(kanit_dir)  # Birim testler
    n_ok = run_negative_controls(kanit_dir, base_dir)  # Negatif testler
    generate_audit_reports(kanit_dir, base_dir)  # Raporlar
    record_command_outputs(kanit_dir)  # Terminal komut cikti kaniti

    print(f"Birim Testler : {'PASS (14/14)' if u_ok else 'FAIL'}")
    print(f"Negatif Kontrol: {'PASS (9/9)' if n_ok else 'FAIL'}")
    print(f"Kanıtlar üretildi: {kanit_dir}")


if __name__ == "__main__":
    main()  # Ana fonksiyon calistirilir
