# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 095: Güvenlik Betikleri Performans Ölçüm ve Profilleme Birim Testleri.
14 adet kapsamlı test senaryosu ile hassas süre ölçümü, bellek takibi, persentil hesapları,
bütçe aşım savunması ve negatif kontroller doğrulanır.
"""

# Birim test çerçevesi
import unittest
# Sistem modülü
import sys
# Dosya yolu işlemleri
import os
# Zaman modülü
import time

# Uygulama modülünü içe aktarmak için kök dizini ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor fonksiyonlarını ve hata sınıflarını içe aktar
from uygulama.security_benchmarker import (
    run_benchmark,
    calculate_percentile,
    profile_security_func,
    bench_sha256,
    bench_sha512,
    bench_blake2b,
    bench_string_concat,
    bench_list_join,
    bench_regex_compiled,
    bench_regex_dynamic,
    BenchmarkSecurityError,
    InvalidBenchmarkParameterError,
    PerformanceBudgetExceededError,
    MemoryLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


class TestSecurityBenchmarker(unittest.TestCase):
    """Güvenlik betikleri performans ölçüm motoru test sınıfı."""

    def test_01_run_benchmark_basic(self):
        """Test 01: Temel benchmark çalıştırmasının geçerli sonuç nesnesi döndürdüğünü doğrular."""
        # Basit toplama fonksiyonu
        def dummy_func():
            # Döngü çalıştır
            return sum(x for x in range(1000))

        # Benchmark koştur
        res = run_benchmark(dummy_func, iterations=10, warmup=2, target_name="dummy_test")
        # Hedef adı eşleşmeli
        self.assertEqual(res.target_name, "dummy_test")
        # Ölçülen iterasyon sayısı 8 olmalı (10 - 2)
        self.assertEqual(res.iterations, 8)
        # Ortalama süre pozitif olmalı
        self.assertGreater(res.mean_wall_ms, 0.0)
        # Throughput pozitif olmalı
        self.assertGreater(res.throughput_ops_per_sec, 0.0)

    def test_02_iterations_and_warmup(self):
        """Test 02: Isınma ve iterasyon sayılarının ölçüm dizisine doğru yansıdığını doğrular."""
        # Basit hedef
        def target():
            # Boş işlem
            pass

        # 15 iterasyon, 5 ısınma
        res = run_benchmark(target, iterations=15, warmup=5)
        # Ölçülen iterasyon 10 olmalı
        self.assertEqual(len(res.wall_times_ms), 10)
        # CPU süreleri de 10 adet olmalı
        self.assertEqual(len(res.cpu_times_ms), 10)

    def test_03_wall_vs_cpu_time(self):
        """Test 03: Duvar saati ve CPU saati metriklerinin negatif olmadığını doğrular."""
        # Basit iş yükü
        def target():
            # Kısa hesaplama
            return [i**2 for i in range(500)]

        # Benchmark çalıştır
        res = run_benchmark(target, iterations=5, warmup=1)
        # Tüm duvar süreleri >= 0 olmalı
        for wt in res.wall_times_ms:
            self.assertGreaterEqual(wt, 0.0)
        # Tüm CPU süreleri >= 0 olmalı
        for ct in res.cpu_times_ms:
            self.assertGreaterEqual(ct, 0.0)

    def test_04_peak_memory_tracking(self):
        """Test 04: tracemalloc ile bellek tahsisatının ölçüldüğünü doğrular."""
        # Bellek tüketen hedef
        def memory_hog():
            # 500 KB bayt dizisi oluştur
            return bytearray(500_000)

        # Benchmark çalıştır
        res = run_benchmark(memory_hog, iterations=3, warmup=1)
        # Tepe bellek en az 400.000 bayt olmalı
        self.assertGreaterEqual(res.peak_memory_bytes, 400_000)

    def test_05_calculate_percentile(self):
        """Test 05: Persentil hesaplama fonksiyonunun matematiksel doğruluğunu test eder."""
        # 1'den 100'e kadar sayılar
        data = [float(x) for x in range(1, 101)]
        # 50. persentil (medyan)
        p50 = calculate_percentile(data, 50.0)
        self.assertAlmostEqual(p50, 50.5, places=1)
        # 95. persentil
        p95 = calculate_percentile(data, 95.0)
        self.assertAlmostEqual(p95, 95.05, places=1)
        # Sınır aşımlarında hata
        with self.assertRaises(InvalidBenchmarkParameterError):
            calculate_percentile(data, 105.0)

    def test_06_profile_decorator(self):
        """Test 06: @profile_security_func dekoratörünün fonksiyonu şeffaf şekilde yürüttüğünü doğrular."""
        # Dekore edilmiş fonksiyon
        @profile_security_func()
        def add(a, b):
            # Topla
            return a + b

        # Çağır ve sonucu test et
        self.assertEqual(add(10, 20), 30)

    def test_07_profile_decorator_threshold_exceeded(self):
        """Test 07: Süre eşiği aşıldığında PerformanceBudgetExceededError fırlatıldığını doğrular."""
        # 0.1 ms eşikli fonksiyon
        @profile_security_func(threshold_ms=0.1)
        def slow_func():
            # Yapay gecikme (5 ms)
            time.sleep(0.005)
            return True

        # Bütçe aşım hatası beklenmeli
        with self.assertRaises(PerformanceBudgetExceededError):
            slow_func()

    def test_08_profile_decorator_memory_exceeded(self):
        """Test 08: Bellek tavanı aşıldığında MemoryLimitExceededError fırlatıldığını doğrular."""
        # 10 KB bellek eşikli fonksiyon
        @profile_security_func(max_memory_bytes=10_000)
        def heavy_mem():
            # 100 KB tahsis et
            return bytearray(100_000)

        # Bellek aşım hatası beklenmeli
        with self.assertRaises(MemoryLimitExceededError):
            heavy_mem()

    def test_09_crypto_targets(self):
        """Test 09: Yerleşik kriptografik özet hedeflerinin doğru hash ürettiğini doğrular."""
        # Test verisi
        data = b"SiberGuvenlik365"
        # SHA-256 çıktısını test et
        h256 = bench_sha256(data)
        self.assertEqual(len(h256), 64)
        # SHA-512 çıktısını test et
        h512 = bench_sha512(data)
        self.assertEqual(len(h512), 128)
        # BLAKE2b çıktısını test et
        hb2 = bench_blake2b(data)
        self.assertEqual(len(hb2), 128)

    def test_10_string_vs_join_efficiency(self):
        """Test 10: bench_string_concat ve bench_list_join hedeflerinin çalıştığını doğrular."""
        # 100 satırlık log
        lines = [f"log_entry_{i}" for i in range(100)]
        # Concat çalışmalı
        res1 = bench_string_concat(lines)
        self.assertIn("log_entry_0", res1)
        # Join çalışmalı
        res2 = bench_list_join(lines)
        self.assertIn("log_entry_0", res2)

    def test_11_regex_compiled_vs_dynamic(self):
        """Test 11: Regex benchmark hedeflerinin beklenen log kalıplarını eşleştirdiğini doğrular."""
        # Test log satırı
        log = "2026-11-02 10:11:12 [ERROR] ip=10.0.0.1 failed to authenticate"
        # Derlenmiş regex eşleşmeli
        self.assertTrue(bench_regex_compiled(log))
        # Dinamik regex eşleşmeli
        self.assertTrue(bench_regex_dynamic(log))

    def test_12_null_byte_target_rejection(self):
        """Test 12: Hedef adında Null-Byte tespit edildiğinde engellendiğini doğrular (CWE-158)."""
        # Hedef adı zehirlenmiş çağrı
        with self.assertRaises(NullByteInjectionError):
            run_benchmark(lambda: None, target_name="safe_func\x00poison")

    def test_13_non_callable_rejection(self):
        """Test 13: Çağrılamayan bir nesne iletildiğinde TypeValidationError fırlatıldığını doğrular (CWE-843)."""
        # String bir nesne ilet
        with self.assertRaises(TypeValidationError):
            run_benchmark("bu_bir_fonksiyon_degil")

    def test_14_invalid_parameters(self):
        """Test 14: Negatif iterasyon veya geçersiz ısınma parametrelerinin reddedildiğini doğrular (CWE-20)."""
        # Negatif iterasyon
        with self.assertRaises(InvalidBenchmarkParameterError):
            run_benchmark(lambda: None, iterations=-5)
        # Isınma >= iterasyon
        with self.assertRaises(InvalidBenchmarkParameterError):
            run_benchmark(lambda: None, iterations=5, warmup=5)
        # Sıfır eşik değeri
        with self.assertRaises(InvalidBenchmarkParameterError):
            run_benchmark(lambda: None, iterations=5, warmup=1, threshold_ms=0.0)


if __name__ == "__main__":
    # Test paketini verbose modda çalıştır
    unittest.main()
