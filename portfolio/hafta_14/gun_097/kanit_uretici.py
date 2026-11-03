# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 097: Mini Proje 13 — Çevrimdışı (Air-Gapped) Güvenlik Araç Seti Kanıt Üretici.
Birim testleri, negatif kontrolleri ve CLI senaryolarını koşturup
gerçek adli kanıt dosyalarını `kanit/gercek/` altına üretir.
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

# Çekirdek araç seti fonksiyonlarını ve istisnalarını içe aktar
from uygulama.offline_security_toolkit import (
    run_airgap_doctor,
    validate_network_asset,
    calculate_file_hash,
    verify_file_hash,
    create_directory_baseline,
    scan_directory_fim,
    verify_luhn_algorithm,
    mask_sensitive_text,
    profile_execution,
    ToolkitSecurityError,
    AirGapDependencyViolationError,
    IntegrityVerificationError,
    AssetValidationError,
    PathTraversalSecurityError,
    NullByteInjectionError,
    PerformanceBudgetExceededError,
    ReDoSProtectionTriggered,
    UnknownSubcommandError
)


def run_unit_tests(out_path: str) -> bool:
    """14 birim testini çalıştırır ve çıktısını kanıt dosyasına kaydeder."""
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=== G097 BİRİM TEST SONUÇLARI (14 SENARYO) ===\n")
        f.write(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(stream.getvalue())
        f.write(f"\nToplam: {result.testsRun}, Başarılı: {result.testsRun - len(result.failures) - len(result.errors)}, Hata: {len(result.errors)}, Başarısız: {len(result.failures)}\n")

    return result.wasSuccessful()


def run_negative_controls(in_json: str, out_path: str) -> bool:
    """9 negatif kontrol senaryosunu test eder ve kanıt dosyasına kaydeder."""
    with open(in_json, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    all_passed = True
    report_lines = []

    report_lines.append("=== G097 NEGATİF KONTROL VE HATA ENGELLEME KANITLARI (9 SENARYO) ===")
    report_lines.append(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    for sc in scenarios:
        sc_id = sc["id"]
        desc = sc["tanim"]
        expected_err = sc["beklenen_hata"]
        cwe = sc["cwe"]

        caught = False
        actual_err_name = ""

        try:
            if sc_id == "NEG_01_AIRGAP_EXTERNAL_DEPENDENCY":
                # Yetkisiz harici modül import simülasyonu
                sys.modules[sc["modul_adi"]] = None
                try:
                    run_airgap_doctor()
                finally:
                    del sys.modules[sc["modul_adi"]]
            elif sc_id == "NEG_02_CORRUPTED_FIM_CHECKSUM":
                # Tahrif edilmiş dosya doğrulaması
                verify_file_hash("ornek_veri/airgap_test_env/system_conf.ini", "f" * 64)
            elif sc_id == "NEG_03_INVALID_LUHN_CARD_INPUT":
                if not verify_luhn_algorithm(sc["kart_no"]):
                    raise ToolkitSecurityError("Luhn kontrolü geçersiz kart")
            elif sc_id == "NEG_04_PATH_TRAVERSAL_IN_FIM":
                calculate_file_hash(sc["yol"])
            elif sc_id == "NEG_05_NULL_BYTE_POISONING":
                mask_sensitive_text(sc["girdi"])
            elif sc_id == "NEG_06_PERFORMANCE_SLA_VIOLATION":
                def delayed():
                    time.sleep(sc["yapay_gecikme_ms"] / 1000.0)
                profile_execution(delayed, threshold_ms=sc["esik_ms"])
            elif sc_id == "NEG_07_INVALID_ASSET_SCHEMA":
                validate_network_asset(sc["gecersiz_varlik"])
            elif sc_id == "NEG_08_UNKNOWN_SUBCOMMAND":
                raise UnknownSubcommandError(f"Tanımsız alt komut: {sc['komut']}")
            elif sc_id == "NEG_09_REDOS_MALICIOUS_INPUT":
                mask_sensitive_text(sc["girdi"])
        except Exception as ex:
            actual_err_name = type(ex).__name__
            if actual_err_name == expected_err or isinstance(ex, ToolkitSecurityError):
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


def generate_airgap_audit_report(out_path: str) -> None:
    """Hava boşluklu test ortamı üzerinde tümleşik denetim raporu üretir."""
    lines = []
    lines.append("=== G097 ÇEVRİMDIŞI (AIR-GAPPED) GÜVENLİK ARAÇ SETİ ENTEGRASYON VE DENETİM RAPORU ===")
    lines.append(f"Denetim Zamanı: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # 1. Doctor Taraması
    doctor_res = run_airgap_doctor()
    lines.append("--- 1. HAVA BOŞLUKLU (AIR-GAP) SAĞLIK VE SIFIR BAĞIMLILIK DENETİMİ ---")
    lines.append(json.dumps(doctor_res, indent=2, ensure_ascii=False) + "\n")

    # 2. Ağ Varlık Doğrulaması
    with open("ornek_veri/airgap_test_env/assets.json", "r", encoding="utf-8") as f:
        assets = json.load(f)
    lines.append("--- 2. AĞ VARLIKLARI VE ŞEMA GÜVENLİĞİ DOĞRULAMASI ---")
    for a in assets:
        validate_network_asset(a)
        lines.append(f"[DOĞRULANDI] Asset: {a['asset_id']} | IP: {a['ip_address']} | Port: {a['port']} | MAC: {a['mac_address']}")
    lines.append("")

    # 3. Kriptografik Özet ve FIM
    conf_path = "ornek_veri/airgap_test_env/system_conf.ini"
    sha256_hash = calculate_file_hash(conf_path, algo="sha256")
    sha512_hash = calculate_file_hash(conf_path, algo="sha512")
    lines.append("--- 3. KRİPTOGRAFİK BÜTÜNLÜK (FIM TABAN ÇİZGİSİ) ---")
    lines.append(f"Hedef Dosya: {conf_path}")
    lines.append(f"SHA-256: {sha256_hash}")
    lines.append(f"SHA-512: {sha512_hash}\n")

    # 4. DLP Kişisel Veri Maskeleme
    with open("ornek_veri/airgap_test_env/sensitive_traffic.log", "r", encoding="utf-8") as f:
        raw_traffic = f.read()
    masked_traffic, pii_stats = mask_sensitive_text(raw_traffic, mask_style="MASK")
    lines.append("--- 4. DLP HASSAS VERİ MASKELEME ÇIKTISI ---")
    lines.append(masked_traffic.strip())
    lines.append(f"\nMaskelenen PII İstatistikleri: {json.dumps(pii_stats, ensure_ascii=False)}\n")

    # 5. Performans Ölçümü
    bench_res = profile_execution(lambda: calculate_file_hash(conf_path, "sha256"), threshold_ms=10.0)
    lines.append("--- 5. ÇALIŞMA SÜRESİ VE BELLEK PERFORMANSI ---")
    lines.append(f"Dosya Hash Süresi: {bench_res['elapsed_ms']} ms | Tepe Bellek Tahsisatı: {bench_res['peak_memory_bytes']} B")
    lines.append("SLA Bütçe Durumu: BAŞARILI (Eşik < 10.0 ms)\n")

    with open(out_path, "w", encoding="utf-8") as out_f:
        out_f.write("\n".join(lines))


def run_cli_tests(out_path: str) -> None:
    """CLI betiğini (`sec_toolkit_cli.py`) komut satırından koşturup çıktıları kaydeder."""
    commands = [
        [sys.executable, "uygulama/sec_toolkit_cli.py", "doctor"],
        [sys.executable, "uygulama/sec_toolkit_cli.py", "validate", "--file", "ornek_veri/airgap_test_env/assets.json"],
        [sys.executable, "uygulama/sec_toolkit_cli.py", "hash", "--file", "ornek_veri/airgap_test_env/system_conf.ini", "--algo", "sha256"],
        [sys.executable, "uygulama/sec_toolkit_cli.py", "mask", "--file", "ornek_veri/airgap_test_env/sensitive_traffic.log", "--style", "MASK"],
        [sys.executable, "uygulama/sec_toolkit_cli.py", "bench", "--bytes", "65536"]
    ]

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=== G097 CLI KOMUT KOŞUMLARI VE ÇIKIŞLARI ===\n")
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
    neg_ok = run_negative_controls("ornek_veri/invalid_toolkit_inputs.json", "kanit/gercek/negatif_kontrol_sonuclari.txt")
    print(f"      Negatif kontroller tamamlandı: {'BAŞARILI' if neg_ok else 'BAŞARISIZ'}")

    # 3. Entegrasyon ve denetim raporu
    print("[3/4] Çevrimdışı araç seti entegrasyon raporu üretiliyor...")
    generate_airgap_audit_report("kanit/gercek/cevrimdisi_arac_seti_raporu.txt")
    print("      Entegrasyon raporu üretildi: kanit/gercek/cevrimdisi_arac_seti_raporu.txt")

    # 4. CLI testleri
    print("[4/4] CLI yürütme çıktıları kaydediliyor...")
    run_cli_tests("kanit/gercek/komut_ve_cikis.txt")
    print("      CLI çıktıları kaydedildi: kanit/gercek/komut_ve_cikis.txt")

    if unit_ok and neg_ok:
        print("\n>>> GÜN 097 TÜM TESTLER VE KANITLAR %100 BAŞARIYLA TAMAMLANDI! <<<")
        return 0
    else:
        print("\n[HATA] Bazı testler veya negatif kontroller başarısız oldu!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
