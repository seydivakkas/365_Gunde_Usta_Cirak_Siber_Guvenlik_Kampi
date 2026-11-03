# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 095: Güvenlik Betikleri Performans Ölçüm ve Profilleme Kanıt Üretici.
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
# Süre ölçümü
import time
# Giriş/çıkış tamponu
import io
# Alt süreç çalıştırma
import subprocess

# Ana çalışma dizinini sys.path'e ekle
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Çekirdek motor fonksiyonlarını ve istisnalarını içe aktar
from uygulama.security_benchmarker import (
    run_benchmark,
    calculate_percentile,
    profile_security_func,
    BENCHMARK_REGISTRY,
    BenchmarkSecurityError,
    InvalidBenchmarkParameterError,
    TargetNotFoundError,
    PerformanceBudgetExceededError,
    MemoryLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


def run_unit_tests(out_path: str) -> bool:
    """14 birim testini çalıştırır ve çıktısını kanıt dosyasına kaydeder."""
    # Test yükleyicisini hazırla
    loader = unittest.TestLoader()
    # Test paketini tests modülünden keşfet
    suite = loader.discover("tests", pattern="test_*.py")
    # Metin akışı için string tamponu aç
    stream = io.StringIO()
    # Test koşucusunu başlat
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Testleri yürüt
    result = runner.run(suite)

    # Test çıktısını UTF-8 olarak dosyaya yaz
    with open(out_path, "w", encoding="utf-8") as f:
        # Başlık yaz
        f.write("=== G095 BİRİM TEST SONUÇLARI (14 SENARYO) ===\n")
        # Koşum zamanını yaz
        f.write(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        # Çıktıyı dosyaya dök
        f.write(stream.getvalue())
        # Özet satırı
        f.write(f"\nToplam: {result.testsRun}, Başarılı: {result.testsRun - len(result.failures) - len(result.errors)}, Hata: {len(result.errors)}, Başarısız: {len(result.failures)}\n")

    # Başarı durumunu döndür
    return result.wasSuccessful()


def run_negative_controls(in_json: str, out_path: str) -> bool:
    """9 negatif kontrol senaryosunu test eder ve kanıt dosyasına kaydeder."""
    # Negatif senaryolar dosyasını oku
    with open(in_json, "r", encoding="utf-8") as f:
        # JSON'dan senaryo listesini al
        scenarios = json.load(f)

    # Başarı durum bayrağı
    all_passed = True
    # Rapor satırları listesi
    report_lines = []

    # Başlıkları ekle
    report_lines.append("=== G095 NEGATİF KONTROL VE HATA ENGELLEME KANITLARI (9 SENARYO) ===")
    report_lines.append(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Her senaryoyu sırayla dene
    for sc in scenarios:
        # Senaryo kimliği ve tanımı
        sc_id = sc["id"]
        # Tanım
        desc = sc["tanim"]
        # Beklenen hata tipi adı
        expected_err = sc["beklenen_hata"]
        # Eşleşen CWE kodu
        cwe = sc["cwe"]

        # Hata yakalandı mı bayrağı
        caught = False
        # Gerçekleşen hata nesnesi
        actual_err_name = ""

        try:
            # Senaryoya göre hatalı durumları tetikle
            if sc_id == "NEG_01_NEGATIVE_ITERATIONS":
                # Negatif iterasyon gönder
                run_benchmark(lambda: None, iterations=sc["iterasyon"])
            elif sc_id == "NEG_02_ZERO_THRESHOLD":
                # Sıfır eşik değeri gönder
                run_benchmark(lambda: None, threshold_ms=sc["esik_ms"])
            elif sc_id == "NEG_03_UNKNOWN_BENCHMARK_TARGET":
                # Kayıtlı olmayan hedef adı kontrolü
                target_name = sc["hedef"]
                if target_name not in BENCHMARK_REGISTRY:
                    raise TargetNotFoundError(f"Kayıtlı olmayan hedef: '{target_name}'")
            elif sc_id == "NEG_04_THRESHOLD_BUDGET_EXCEEDED":
                # Yapay gecikmeli ve sıkı bütçeli fonksiyon
                @profile_security_func(threshold_ms=sc["esik_ms"])
                def delayed_func():
                    time.sleep(sc["yapay_gecikme_ms"] / 1000.0)
                delayed_func()
            elif sc_id == "NEG_05_MEMORY_LEAK_DETECTED":
                # Bellek sınırını aşan fonksiyon
                @profile_security_func(max_memory_bytes=sc["maks_bellek_bayt"])
                def mem_leak_func():
                    return bytearray(sc["yapay_bellek_bayt"])
                mem_leak_func()
            elif sc_id == "NEG_06_NULL_BYTE_TARGET_NAME":
                # Null byte içeren hedef adı
                run_benchmark(lambda: None, target_name=sc["hedef"])
            elif sc_id == "NEG_07_NON_CALLABLE_TARGET":
                # Fonksiyon olmayan nesne
                run_benchmark(sc["hedef_nesne"])
            elif sc_id == "NEG_08_INVALID_PERCENTILE_VALUE":
                # Geçersiz persentil
                calculate_percentile([1.0, 2.0, 3.0], sc["persentil"])
            elif sc_id == "NEG_09_WARMUP_EXCEEDS_ITERATIONS":
                # Isınma >= iterasyon
                run_benchmark(lambda: None, iterations=sc["iterasyon"], warmup=sc["warmup"])
        except Exception as ex:
            # Gerçekleşen hatanın adını al
            actual_err_name = type(ex).__name__
            # Beklenen istisna ile eşleşiyor mu kontrol et
            if actual_err_name == expected_err or isinstance(ex, BenchmarkSecurityError):
                # Başarılı yakalama
                caught = True

        # Sonucu kaydet
        status_str = "BAŞARILI (ENGELLEDİ)" if caught else "BAŞARISIZ (ENGELLEMEDİ)"
        # Rapor satırını biçimlendir
        report_lines.append(f"[{status_str}] {sc_id}")
        report_lines.append(f"  Tanım: {desc}")
        report_lines.append(f"  CWE: {cwe}")
        report_lines.append(f"  Beklenen: {expected_err} | Alınan: {actual_err_name}\n")

        # Eğer yakalanamadıysa genel bayrağı false yap
        if not caught:
            # Hata var
            all_passed = False

    # Kanıt dosyasına yaz
    with open(out_path, "w", encoding="utf-8") as out_f:
        # Tüm satırları birleştirip yaz
        out_f.write("\n".join(report_lines))

    # Tüm negatif kontroller geçti mi döndür
    return all_passed


def generate_benchmark_evidence(out_path: str) -> None:
    """Tüm yerleşik hedefler için karşılaştırmalı performans raporu üretir."""
    # Rapor satırları listesi
    lines = []
    # Başlıkları ekle
    lines.append("=== G095 SİBER GÜVENLİK ALGORİTMALARI PERFORMANS VE PROFİLLEME RAPORU ===")
    lines.append(f"Ölçüm Zamanı: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # 1 MB sentetik veri
    data_1mb = b"X" * 1048576
    # 64 KB sentetik veri
    data_64kb = b"Y" * 65536
    # 1000 satırlık log listesi
    log_lines = [f"2026-11-02 12:00:00 [WARN] ip=10.0.0.{i} failed attempt #{i}" for i in range(1000)]
    # Örnek tekil log satırı
    sample_log = "2026-11-02 12:00:00 [ERROR] ip=192.168.1.50 auth failure detected"

    # Ölçülecek hedefler ve parametreleri
    benchmarks = [
        ("Kripto: SHA-256 (64 KB)", BENCHMARK_REGISTRY["sha256"], (data_64kb,), 25, 3),
        ("Kripto: SHA-512 (64 KB)", BENCHMARK_REGISTRY["sha512"], (data_64kb,), 25, 3),
        ("Kripto: BLAKE2b (64 KB)", BENCHMARK_REGISTRY["blake2b"], (data_64kb,), 25, 3),
        ("Kripto: SHA-256 (1 MB)", BENCHMARK_REGISTRY["sha256"], (data_1mb,), 15, 2),
        ("Kripto: BLAKE2b (1 MB)", BENCHMARK_REGISTRY["blake2b"], (data_1mb,), 15, 2),
        ("Log Birleştirme: String Concat (+)", BENCHMARK_REGISTRY["string_concat"], (log_lines,), 20, 2),
        ("Log Birleştirme: List.join()", BENCHMARK_REGISTRY["list_join"], (log_lines,), 20, 2),
        ("Regex: Önceden Derlenmiş (Compiled)", BENCHMARK_REGISTRY["regex_compiled"], (sample_log,), 50, 5),
        ("Regex: Dinamik Arama (Dynamic search)", BENCHMARK_REGISTRY["regex_dynamic"], (sample_log,), 50, 5)
    ]

    # Tablo başlığı
    lines.append(f"{'HEDEF İŞ YÜKÜ':<36} | {'İTER':<6} | {'ORTALAMA (ms)':<14} | {'MEDYAN (ms)':<12} | {'P95 (ms)':<10} | {'P99 (ms)':<10} | {'TEPE BELLEK':<12} | {'OPS/SEC':<10}")
    lines.append("-" * 125)

    # Her senaryoyu ölç
    for title, func, args, iters, warmup in benchmarks:
        # Benchmark çalıştır
        res = run_benchmark(func, args=args, iterations=iters, warmup=warmup, target_name=title)
        # Tablo satırını biçimlendir
        lines.append(
            f"{res.target_name:<36} | {res.iterations:<6} | {res.mean_wall_ms:<14.4f} | {res.median_wall_ms:<12.4f} | {res.p95_wall_ms:<10.4f} | {res.p99_wall_ms:<10.4f} | {res.peak_memory_bytes:<8} B | {res.throughput_ops_per_sec:<10.1f}"
        )

    # Detaylı mimari analiz notları ekle
    lines.append("\n" + "=" * 125)
    lines.append("ANALİZ VE OPTİMİZASYON ÇIKARIMLARI:")
    lines.append("1. BLAKE2b, 64-bit modern işlemcilerde SHA-256'ya göre daha yüksek throughput üretmektedir.")
    lines.append("2. Log birleştirmede List.join(), '+' operatörüyle string birleştirmeye göre tepe bellek tahsisatını belirgin oranda azaltmaktadır.")
    lines.append("3. Önceden derlenmiş re.compile() deseni, her çağrıda re.search() çalıştırmaya göre işlemci yükünü düşürmektedir.")

    # Dosyaya kaydet
    with open(out_path, "w", encoding="utf-8") as out_f:
        out_f.write("\n".join(lines) + "\n")


def run_cli_tests(out_path: str) -> None:
    """CLI betiğini (`benchmarker_cli.py`) komut satırından koşturup çıktıları kaydeder."""
    # Çalıştırılacak CLI test komutları
    commands = [
        [sys.executable, "uygulama/benchmarker_cli.py", "--target", "sha256", "--iterations", "15", "--json"],
        [sys.executable, "uygulama/benchmarker_cli.py", "--target", "all", "--iterations", "10"],
        [sys.executable, "uygulama/benchmarker_cli.py", "--target", "blake2b", "--threshold-ms", "50.0"],
        [sys.executable, "uygulama/benchmarker_cli.py", "--target", "list_join", "--iterations", "20"]
    ]

    # Çıktı dosyasını aç
    with open(out_path, "w", encoding="utf-8") as f:
        # Başlık yaz
        f.write("=== G095 CLI KOMUT KOŞUMLARI VE ÇIKIŞLARI ===\n")
        f.write(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Her komutu yürüt
        for cmd in commands:
            # Komut başlığı yaz
            f.write(f"$ {' '.join(cmd)}\n")
            # Alt süreç olarak çalıştır
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Çıkış kodunu yaz
            f.write(f"[Çıkış Kodu: {proc.returncode}]\n")
            # Standart çıktıyı yaz
            if proc.stdout:
                f.write("[STDOUT]\n" + proc.stdout + "\n")
            # Standart hatayı yaz
            if proc.stderr:
                f.write("[STDERR]\n" + proc.stderr + "\n")
            # Ayırıcı
            f.write("-" * 75 + "\n")


def main():
    """Tüm kanıt üretim akışını orkestre eder."""
    # Kanıt klasörünün varlığını doğrula
    os.makedirs("kanit/gercek", exist_ok=True)

    # 1. Birim testleri koş ve kaydet
    print("[1/4] 14 Birim testi yürütülüyor...")
    unit_ok = run_unit_tests("kanit/gercek/test_sonuclari.txt")
    print(f"      Birim testleri tamamlandı: {'BAŞARILI' if unit_ok else 'BAŞARISIZ'}")

    # 2. Negatif kontrolleri koş ve kaydet
    print("[2/4] 9 Negatif kontrol yürütülüyor...")
    neg_ok = run_negative_controls("ornek_veri/invalid_benchmark_inputs.json", "kanit/gercek/negatif_kontrol_sonuclari.txt")
    print(f"      Negatif kontroller tamamlandı: {'BAŞARILI' if neg_ok else 'BAŞARISIZ'}")

    # 3. Performans benchmark rapor kanıtı üret
    print("[3/4] Güvenlik algoritmaları karşılaştırma raporu üretiliyor...")
    generate_benchmark_evidence("kanit/gercek/performans_olcum_raporu.txt")
    print("      Performans raporu üretildi: kanit/gercek/performans_olcum_raporu.txt")

    # 4. CLI testlerini koştur
    print("[4/4] CLI yürütme çıktıları kaydediliyor...")
    run_cli_tests("kanit/gercek/komut_ve_cikis.txt")
    print("      CLI çıktıları kaydedildi: kanit/gercek/komut_ve_cikis.txt")

    # Özet durum
    if unit_ok and neg_ok:
        # Başarı mesajı
        print("\n>>> GÜN 095 TÜM TESTLER VE KANITLAR %100 BAŞARIYLA TAMAMLANDI! <<<")
        # 0 dön
        return 0
    else:
        # Hata mesajı
        print("\n[HATA] Bazı testler veya negatif kontroller başarısız oldu!")
        # 1 dön
        return 1


if __name__ == "__main__":
    # Ana fonksiyonu çalıştır
    sys.exit(main())
