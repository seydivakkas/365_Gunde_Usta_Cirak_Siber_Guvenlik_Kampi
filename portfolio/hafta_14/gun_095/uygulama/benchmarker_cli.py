# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 095: Güvenlik Betikleri Performans Ölçüm ve Profilleme Komut Satırı Arayüzü (CLI).
Standart Unix ve PowerShell boru hatları (pipeline) ile tam uyumlu çalışır.
"""

# Komut satırı argüman ayrıştırıcısı
import argparse
# Sistem giriş/çıkış ve çıkış kodları modülü
import sys
# Dosya ve dizin işlemleri
import os
# JSON veri serileştirme
import json

# Yerel modülü içe aktarabilmek için dosya yolunu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek profilleme fonksiyonunu ve hata sınıflarını içe aktar
from uygulama.security_benchmarker import (
    run_benchmark,
    BENCHMARK_REGISTRY,
    BenchmarkSecurityError,
    InvalidBenchmarkParameterError,
    TargetNotFoundError,
    PerformanceBudgetExceededError,
    MemoryLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını oluşturur ve parametreleri yapılandırır."""
    # Parser nesnesi oluştur
    parser = argparse.ArgumentParser(
        prog="benchmarker_cli",
        description="G095: Siber Güvenlik Betikleri Performans ve Profilleme Aracı"
    )
    # Hedef seçimi parametresi
    parser.add_argument(
        "-t", "--target",
        type=str,
        default="sha256",
        help="Ölçülecek hedef güvenlik fonksiyonu (sha256, sha512, blake2b, string_concat, list_join, regex_compiled, regex_dynamic, all)"
    )
    # İterasyon sayısı parametresi
    parser.add_argument(
        "-i", "--iterations",
        type=int,
        default=20,
        help="Yürütülecek toplam ölçüm iterasyonu (varsayılan: 20)"
    )
    # Isınma sayısı parametresi
    parser.add_argument(
        "-w", "--warmup",
        type=int,
        default=3,
        help="Ölçüm öncesi ısınma döngüsü sayısı (varsayılan: 3)"
    )
    # Performans eşik değeri (ms)
    parser.add_argument(
        "--threshold-ms",
        type=float,
        default=None,
        help="Maksimum kabul edilebilir ortalama süre (milisaniye). Aşılırsa hata üretir."
    )
    # Maksimum bellek sınırı (bayt)
    parser.add_argument(
        "--max-memory",
        type=int,
        default=None,
        help="Maksimum kabul edilebilir tepe bellek tahsisatı (bayt)"
    )
    # Test veri boyutu (bayt)
    parser.add_argument(
        "--size-bytes",
        type=int,
        default=65536,
        help="Test verisi boyutu bayt cinsinden (varsayılan: 65536 - 64 KB)"
    )
    # Çıktı dosyası yolu
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Sonuçların kaydedileceği metin/rapor dosyasının yolu"
    )
    # JSON formatında çıktı bayrağı
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları JSON formatında standart çıktıya (stdout) basar"
    )
    # Yapılandırılmış parser'ı döndür
    return parser


def get_target_args(target_name: str, size_bytes: int):
    """Hedef fonksiyona uygun test girdisi verilerini hazırlar."""
    # Kriptografik fonksiyonlar için rastgele bayt dizisi
    if target_name in ["sha256", "sha512", "blake2b"]:
        # Sentetik veri
        return (b"A" * size_bytes,)
    # Dize birleştirme testleri için liste
    elif target_name in ["string_concat", "list_join"]:
        # 1000 adet log satırı
        lines = [f"2026-11-02 10:00:00 [INFO] User #{idx} login success" for idx in range(1000)]
        return (lines,)
    # Regex testleri için örnek log metni
    elif target_name in ["regex_compiled", "regex_dynamic"]:
        # Eşleşecek test log satırı
        return ("2026-11-02 12:45:01 [ERROR] ip=192.168.1.105 authentication failed",)
    # Varsayılan boş parametre
    return ()


def main() -> int:
    """CLI ana yürütme fonksiyonu. Standart POSIX çıkış kodları döner."""
    # Argüman ayrıştırıcıyı kur
    parser = build_parser()
    # Komut satırı argümanlarını ayrıştır
    args = parser.parse_args()

    # Hedefleri belirle
    targets_to_run = []
    # 'all' seçeneği kontrolü
    if args.target.lower() == "all":
        # Tüm kayıtlı hedefleri listele
        targets_to_run = list(BENCHMARK_REGISTRY.keys())
    else:
        # Tekil hedef kontrolü
        if args.target not in BENCHMARK_REGISTRY:
            # Standart hata akışına yazdır
            sys.stderr.write(f"[HATA] Tanımsız hedef fonksiyon: '{args.target}'\n")
            sys.stderr.write(f"Mevcut hedefler: {', '.join(BENCHMARK_REGISTRY.keys())}\n")
            # Çıkış kodu dön
            return 2
        # Tek hedefi ekle
        targets_to_run = [args.target]

    # Sonuçların toplanacağı liste
    results_list = []

    try:
        # Her hedef için benchmark çalıştır
        for tgt in targets_to_run:
            # Hedef fonksiyonu al
            func = BENCHMARK_REGISTRY[tgt]
            # Hedef parametrelerini hazırla
            call_args = get_target_args(tgt, args.size_bytes)

            # Benchmark'ı yürüt
            res = run_benchmark(
                target_func=func,
                args=call_args,
                iterations=args.iterations,
                warmup=args.warmup,
                threshold_ms=args.threshold_ms,
                max_memory_bytes=args.max_memory,
                target_name=tgt
            )
            # Sonuç listesine ekle
            results_list.append(res.to_dict())

        # Eğer JSON çıktısı istenmişse
        if args.json:
            # JSON formatında stdout'a yaz
            print(json.dumps(results_list, indent=2, ensure_ascii=False))
        else:
            # Okunabilir tablo çıktısı üret
            print("=" * 80)
            print(f"{'HEDEF':<18} | {'İTER':<6} | {'ORTALAMA (ms)':<14} | {'MEDYAN (ms)':<12} | {'TEPE BELLEK':<12} | {'OPS/SEC':<10}")
            print("-" * 80)
            for r in results_list:
                print(f"{r['target_name']:<18} | {r['iterations']:<6} | {r['mean_wall_ms']:<14.4f} | {r['median_wall_ms']:<12.4f} | {r['peak_memory_bytes']:<8} B | {r['throughput_ops_per_sec']:<10.1f}")
            print("=" * 80)

        # Eğer dosya çıktısı istenmişse
        if args.output:
            # Dosyaya yaz
            with open(args.output, "w", encoding="utf-8") as out_f:
                # JSON veya metin olarak yaz
                json.dump(results_list, out_f, indent=2, ensure_ascii=False)
            sys.stderr.write(f"[BİLGİ] Performans raporu kaydedildi: {args.output}\n")

        # Başarılı çıkış kodu
        return 0

    except PerformanceBudgetExceededError as budget_err:
        # Performans bütçesi aşımı
        sys.stderr.write(f"[UYARI / EŞİK AŞIMI] {str(budget_err)}\n")
        # SLA ihlali kodu ile çık
        return 1
    except MemoryLimitExceededError as mem_err:
        # Bellek aşımı
        sys.stderr.write(f"[UYARI / BELLEK AŞIMI] {str(mem_err)}\n")
        return 1
    except BenchmarkSecurityError as sec_err:
        # Güvenlik ve doğrulama hatası
        sys.stderr.write(f"[HATA] {type(sec_err).__name__}: {str(sec_err)}\n")
        return 2
    except Exception as exc:
        # Beklenmeyen hata
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        return 2


if __name__ == "__main__":
    # Ana fonksiyonu çalıştır
    sys.exit(main())
