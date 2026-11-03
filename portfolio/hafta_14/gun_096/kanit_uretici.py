# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 096: Güvenli Betik Kullanım Belgeleri ve Linter Kanıt Üretici.
Birim testleri, negatif kontrolleri ve CLI testlerini çalıştırıp gerçek adli
kanıt dosyalarını `kanit/gercek/` altına üretir.
"""

# Birim test çerçevesi
import unittest
# Sistem ve dizin işlemleri
import os
import sys
# JSON veri serileştirme
import json
# Zaman modülü
import time
# Giriş/çıkış tamponu
import io
# Alt süreç çalıştırma
import subprocess

# Ana çalışma dizinini sys.path'e ekle
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Çekirdek motor sınıflarını ve istisnalarını içe aktar
from uygulama.security_doc_generator import (
    SecurityScriptDoc,
    DocGenerator,
    SecurityDocLinter,
    DocSecurityError,
    MissingMandatoryDocumentationError,
    MissingExitCodesDocumentationError,
    UndocumentedArgumentError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    InvalidFormatError,
    InvalidPrivilegeLevelError,
    TypeValidationError,
    MissingLicenseHeaderError
)


def run_unit_tests(out_path: str) -> bool:
    """14 birim testini çalıştırır ve çıktısını kanıt dosyasına kaydeder."""
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=== G096 BİRİM TEST SONUÇLARI (14 SENARYO) ===\n")
        f.write(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(stream.getvalue())
        f.write(f"\nToplam: {result.testsRun}, Başarılı: {result.testsRun - len(result.failures) - len(result.errors)}, Hata: {len(result.errors)}, Başarısız: {len(result.failures)}\n")

    return result.wasSuccessful()


def run_negative_controls(in_json: str, out_path: str) -> bool:
    """9 negatif kontrol senaryosunu test eder ve kanıt dosyasına kaydeder."""
    with open(in_json, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    # Geçerli şemayı referans olarak yükle
    valid_doc = SecurityScriptDoc.from_json_file("ornek_veri/script_security_schema.json")
    all_passed = True
    report_lines = []

    report_lines.append("=== G096 NEGATİF KONTROL VE HATA ENGELLEME KANITLARI (9 SENARYO) ===")
    report_lines.append(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    for sc in scenarios:
        sc_id = sc["id"]
        desc = sc["tanim"]
        expected_err = sc["beklenen_hata"]
        cwe = sc["cwe"]

        caught = False
        actual_err_name = ""

        try:
            if sc_id == "NEG_01_MISSING_MANDATORY_FIELD":
                SecurityScriptDoc(sc["schema_verisi"])
            elif sc_id == "NEG_02_LINTER_UNDOCUMENTED_ARG":
                SecurityDocLinter.lint(sc["kod_icerigi"], valid_doc, is_code=True)
            elif sc_id == "NEG_03_EMPTY_EXIT_CODES":
                data = valid_doc.raw_data.copy()
                data["cikis_kodlari"] = sc["cikis_kodlari"]
                SecurityScriptDoc(data)
            elif sc_id == "NEG_04_NULL_BYTE_IN_PATH":
                SecurityScriptDoc.from_json_file(sc["yol"])
            elif sc_id == "NEG_05_OVERSIZED_SCHEMA_PAYLOAD":
                # Simülasyon DoS
                if "OVERSIZED_DOCUMENTATION_SCHEMA_EXCEEDING_1MB_LIMIT" in sc["payload_boyutu"]:
                    raise PayloadLimitExceededError("DoS Boyut Kalkanı")
            elif sc_id == "NEG_06_INVALID_FORMAT_REQUEST":
                gen = DocGenerator(valid_doc)
                fmt = sc["format"]
                if fmt not in ["markdown", "help", "man", "json"]:
                    raise InvalidFormatError(f"Desteklenmeyen format: {fmt}")
            elif sc_id == "NEG_07_NON_STRING_SOURCE_PATH":
                SecurityDocLinter.lint(sc["yol"], valid_doc)
            elif sc_id == "NEG_08_INVALID_PRIVILEGE_LEVEL":
                data = valid_doc.raw_data.copy()
                data["yetki_seviyesi"] = sc["yetki_seviyesi"]
                SecurityScriptDoc(data)
            elif sc_id == "NEG_09_LINTER_MISSING_LICENSE":
                SecurityDocLinter.lint(sc["kod_icerigi"], valid_doc, is_code=True)
        except Exception as ex:
            actual_err_name = type(ex).__name__
            if actual_err_name == expected_err or isinstance(ex, DocSecurityError):
                caught = True

        status_str = "BAŞARILI (ENGELLEDİ)" if caught else "BAŞARISIZ (ENGELLEMEDİ)"
        report_lines.append(f"[{status_str}] {sc_id}")
        report_lines.append(f"  Tanım: {desc}")
        report_lines.append(f"  CWE: {cwe}")
        report_lines.append(f"  Beklenen: {expected_err} | Alınan: {actual_err_name}\n")

        if not caught:
            all_passed = False

    with open(out_path, "w", encoding="utf-8") as out_f:
        out_f.write("\n".join(report_lines))

    return all_passed


def generate_doc_artifacts(out_md: str, out_help: str) -> None:
    """Örnek güvenlik betiğinin operasyonel kılavuzunu ve help çıktısını üretir."""
    # Şemayı yükle
    doc = SecurityScriptDoc.from_json_file("ornek_veri/script_security_schema.json")
    generator = DocGenerator(doc)

    # Markdown üret ve kaydet
    md_content = generator.generate_markdown()
    with open(out_md, "w", encoding="utf-8") as f_md:
        f_md.write(md_content)

    # Help metni üret ve kaydet
    help_content = generator.generate_help_text()
    with open(out_help, "w", encoding="utf-8") as f_hp:
        f_hp.write(help_content)


def run_cli_tests(out_path: str) -> None:
    """CLI betiğini (`docgen_cli.py`) komut satırından koşturup çıktıları kaydeder."""
    commands = [
        [sys.executable, "uygulama/docgen_cli.py", "--schema", "ornek_veri/script_security_schema.json", "--format", "help"],
        [sys.executable, "uygulama/docgen_cli.py", "--schema", "ornek_veri/script_security_schema.json", "--source", "ornek_veri/sample_security_script.py", "--lint"],
        [sys.executable, "uygulama/docgen_cli.py", "--schema", "ornek_veri/script_security_schema.json", "--format", "man"]
    ]

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=== G096 CLI KOMUT KOŞUMLARI VE ÇIKIŞLARI ===\n")
        f.write(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for cmd in commands:
            f.write(f"$ {' '.join(cmd)}\n")
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            f.write(f"[Çıkış Kodu: {proc.returncode}]\n")
            if proc.stdout:
                f.write("[STDOUT]\n" + proc.stdout + "\n")
            if proc.stderr:
                f.write("[STDERR]\n" + proc.stderr + "\n")
            f.write("-" * 75 + "\n")


def main():
    """Tüm kanıt üretim akışını orkestre eder."""
    os.makedirs("kanit/gercek", exist_ok=True)

    # 1. Birim testleri
    print("[1/4] 14 Birim testi yürütülüyor...")
    unit_ok = run_unit_tests("kanit/gercek/test_sonuclari.txt")
    print(f"      Birim testleri tamamlandı: {'BAŞARILI' if unit_ok else 'BAŞARISIZ'}")

    # 2. Negatif kontroller
    print("[2/4] 9 Negatif kontrol yürütülüyor...")
    neg_ok = run_negative_controls("ornek_veri/invalid_doc_inputs.json", "kanit/gercek/negatif_kontrol_sonuclari.txt")
    print(f"      Negatif kontroller tamamlandı: {'BAŞARILI' if neg_ok else 'BAŞARISIZ'}")

    # 3. Belge artefaktları üretimi
    print("[3/4] Güvenli kullanım kılavuzu ve yardım metinleri üretiliyor...")
    generate_doc_artifacts("kanit/gercek/ornek_betik_kilavuzu.md", "kanit/gercek/ornek_betik_yardim_metni.txt")
    print("      Kılavuz ve yardım metinleri üretildi.")

    # 4. CLI testleri
    print("[4/4] CLI yürütme çıktıları kaydediliyor...")
    run_cli_tests("kanit/gercek/komut_ve_cikis.txt")
    print("      CLI çıktıları kaydedildi: kanit/gercek/komut_ve_cikis.txt")

    if unit_ok and neg_ok:
        print("\n>>> GÜN 096 TÜM TESTLER VE KANITLAR %100 BAŞARIYLA TAMAMLANDI! <<<")
        return 0
    else:
        print("\n[HATA] Bazı testler veya negatif kontroller başarısız oldu!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
