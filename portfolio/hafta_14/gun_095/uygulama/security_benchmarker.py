# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 095: Güvenlik Betikleri Performans Ölçüm ve Profilleme Çekirdek Motoru.
Bu modül zaman duyarlı siber güvenlik işlevlerinin (kriptografi, log analizi, DLP)
yürütme sürelerini, CPU maliyetlerini ve bellek tahsisatlarını yüksek hassasiyetle ölçer.
"""

# Yüksek hassasiyetli saat ve CPU sayaçları
import time
# Bellek tahsisat takibi ve profilleme kütüphanesi
import tracemalloc
# İstatistiksel hesaplamalar için matematik ve istatistik modülü
import statistics
# Kriptografik fonksiyonlar ve algoritmalar
import hashlib
# Düzenli ifadeler
import re
# Fonksiyon dekoratörleri ve sarmalayıcılar
import functools
# Tip ipuçları ve veri yapıları
from typing import Callable, Any, Dict, List, Optional, Tuple
# Değiştirilemez veri yapıları
from dataclasses import dataclass, asdict


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE HATA SINIFLARI (CWE EŞLEŞTİRMELİ)
# ==============================================================================

class BenchmarkSecurityError(Exception):
    """Performans ölçüm motoru taban güvenlik istisnası."""
    pass


class InvalidBenchmarkParameterError(BenchmarkSecurityError):
    """CWE-20 / CWE-1284: Geçersiz parametre, iterasyon veya persentil iletimi hatası."""
    pass


class TargetNotFoundError(BenchmarkSecurityError):
    """CWE-20: Tanımsız veya bulunamayan hedef fonksiyon hatası."""
    pass


class PerformanceBudgetExceededError(BenchmarkSecurityError):
    """CWE-400: Güvenlik SLA bütçesini aşan aşırı yavaş yürütme hatası (DoS uyarısı)."""
    pass


class MemoryLimitExceededError(BenchmarkSecurityError):
    """CWE-401: Belirlenen tepe bellek tahsisat sınırının aşılması hatası."""
    pass


class NullByteInjectionError(BenchmarkSecurityError):
    """CWE-158: Hedef fonksiyon veya parametre adında Null-Byte enjeksiyonu hatası."""
    pass


class TypeValidationError(BenchmarkSecurityError):
    """CWE-843: Çalıştırılamaz veya uyumsuz nesne tipi iletimi hatası."""
    pass


# ==============================================================================
# PERFORMANS METRİKLERİ VE SONUÇ VERİ YAPISI
# ==============================================================================

@dataclass
class BenchmarkResult:
    """Tek bir güvenlik hedefinin detaylı performans profili ve istatistikleri."""
    # Hedef fonksiyonun adı
    target_name: str
    # Gerçekleştirilen ölçüm döngüsü sayısı
    iterations: int
    # Her iterasyonda geçen duvar saati süreleri (milisaniye)
    wall_times_ms: List[float]
    # Her iterasyonda harcanan CPU süreleri (milisaniye)
    cpu_times_ms: List[float]
    # Ortalama duvar saati süresi (ms)
    mean_wall_ms: float
    # Medyan duvar saati süresi (ms)
    median_wall_ms: float
    # Standart sapma (ms)
    stdev_wall_ms: float
    # En hızlı çalışma süresi (ms)
    min_wall_ms: float
    # En yavaş çalışma süresi (ms)
    max_wall_ms: float
    # 95. persentil süresi (ms)
    p95_wall_ms: float
    # 99. persentil süresi (ms)
    p99_wall_ms: float
    # Ulaşılan tepe bellek tahsisatı (bayt)
    peak_memory_bytes: int
    # Saniyede gerçekleştirilen işlem kapasitesi (Ops/Sec)
    throughput_ops_per_sec: float

    def to_dict(self) -> Dict[str, Any]:
        """Sonuçları serileştirilebilir sözlüğe dönüştürür."""
        # dataclass'ı doğrudan sözlüğe çevir
        return asdict(self)


# ==============================================================================
# HESAPLAMA VE İSTATİSTİK YARDIMCILARI
# ==============================================================================

def calculate_percentile(data: List[float], percentile: float) -> float:
    """
    Sıralanmış veri listesinden istenen persentil değerini (0-100) enterpolasyonla hesaplar.
    """
    # Persentil sınır kontrolü (CWE-1284)
    if percentile < 0.0 or percentile > 100.0:
        # Geçersiz persentil hatası fırlat
        raise InvalidBenchmarkParameterError(f"Persentil 0 ile 100 arasında olmalıdır: {percentile}")
    # Boş liste kontrolü
    if not data:
        # Boş veri sıfır döner
        return 0.0
    # Verileri küçükten büyüğe sırala
    sorted_data = sorted(data)
    # İndeks hesaplaması yap
    k = (len(sorted_data) - 1) * (percentile / 100.0)
    # Alt taban indeksi
    f = int(k)
    # Tavan indeksi
    c = f + 1
    # Eğer sınırda ise doğrudan değeri al
    if c >= len(sorted_data):
        # En büyük elemanı dön
        return float(sorted_data[-1])
    # Enterpolasyon ağırlığı
    weight = k - f
    # Ağırlıklı persentil değerini döndür
    return float(sorted_data[f] * (1.0 - weight) + sorted_data[c] * weight)


# ==============================================================================
# ÇEKİRDEK PROFİLLEME VE BENCHMARK MOTORU
# ==============================================================================

def run_benchmark(
    target_func: Callable[..., Any],
    args: Tuple[Any, ...] = (),
    kwargs: Optional[Dict[str, Any]] = None,
    iterations: int = 10,
    warmup: int = 2,
    threshold_ms: Optional[float] = None,
    max_memory_bytes: Optional[int] = None,
    target_name: Optional[str] = None
) -> BenchmarkResult:
    """
    Belirtilen hedef fonksiyonu ısınma ve ölçüm döngüleriyle profiller.
    Duvar süresi (perf_counter), CPU süresi (process_time) ve tepe bellek (tracemalloc) ölçer.
    """
    # Fonksiyonun çalıştırılabilirliğini doğrula (CWE-843)
    if not callable(target_func):
        # Tip doğrulama hatası fırlat
        raise TypeValidationError(f"Hedef nesne çağrılabilir bir fonksiyon olmalıdır: {type(target_func).__name__}")

    # Hedef adını belirle
    name = target_name or getattr(target_func, "__name__", "isimsiz_hedef")

    # Null-byte enjeksiyonu denetimi (CWE-158)
    if "\x00" in name:
        # Null-byte hatası fırlat
        raise NullByteInjectionError("Hedef fonksiyon adında zararlı Null-Byte (\x00) tespit edildi")

    # İterasyon parametre doğrulaması (CWE-20)
    if iterations <= 0:
        # Pozitif iterasyon zorunludur
        raise InvalidBenchmarkParameterError(f"İterasyon sayısı pozitif bir tamsayı olmalıdır: {iterations}")

    # Eşik değeri doğrulaması
    if threshold_ms is not None and threshold_ms <= 0.0:
        # Pozitif eşik zorunludur
        raise InvalidBenchmarkParameterError(f"Performans eşiği pozitif olmalıdır: {threshold_ms}")

    # Isınma parametre doğrulaması
    if warmup < 0:
        # Negatif ısınma olamaz
        raise InvalidBenchmarkParameterError(f"Isınma sayısı negatif olamaz: {warmup}")
    if warmup >= iterations:
        # Isınma toplam iterasyondan küçük olmalıdır
        raise InvalidBenchmarkParameterError(f"Isınma sayısı ({warmup}) toplam iterasyondan ({iterations}) küçük olmalıdır")

    # Argüman sözlüğünü hazırla
    call_kwargs = kwargs if kwargs is not None else {}

    # 1. Isınma (Warmup) Döngüleri (JIT, CPU önbellek ve modül yükleme etkisini nötrler)
    for _ in range(warmup):
        # Fonksiyonu çağır
        target_func(*args, **call_kwargs)

    # Ölçüm listelerini başlat
    wall_times: List[float] = []
    cpu_times: List[float] = []

    # Bellek izlemeyi başlat
    tracemalloc.start()
    # Bellek başlangıç durumunu sıfırla
    tracemalloc.reset_peak()

    # Gerçek ölçüm iterasyonları sayısı
    measured_iterations = iterations - warmup

    # 2. Ölçüm Döngüsü
    for _ in range(measured_iterations):
        # Başlangıç CPU süresini al
        t_cpu_start = time.process_time()
        # Başlangıç yüksek hassasiyetli duvar süresini al
        t_wall_start = time.perf_counter()

        # Hedef fonksiyonu yürüt
        target_func(*args, **call_kwargs)

        # Bitiş duvar süresini al
        t_wall_end = time.perf_counter()
        # Bitiş CPU süresini al
        t_cpu_end = time.process_time()

        # Geçen süreleri milisaniye cinsine çevirip kaydet
        wall_times.append((t_wall_end - t_wall_start) * 1000.0)
        cpu_times.append((t_cpu_end - t_cpu_start) * 1000.0)

    # Ulaşılan tepe bellek tahsisatını al
    _, peak_memory = tracemalloc.get_traced_memory()
    # Bellek izlemeyi durdur
    tracemalloc.stop()

    # İstatistiksel metrikleri hesapla
    mean_wall = statistics.mean(wall_times)
    median_wall = statistics.median(wall_times)
    # Tek iterasyon durumunda standart sapma 0 kabul edilir
    stdev_wall = statistics.stdev(wall_times) if len(wall_times) > 1 else 0.0
    min_wall = min(wall_times)
    max_wall = max(wall_times)
    p95_wall = calculate_percentile(wall_times, 95.0)
    p99_wall = calculate_percentile(wall_times, 99.0)

    # Toplam geçen süre (saniye) üzerinden saniye başına işlem sayısını hesapla
    total_wall_sec = sum(wall_times) / 1000.0
    # Sıfıra bölme koruması
    throughput = (measured_iterations / total_wall_sec) if total_wall_sec > 0 else 0.0

    # 3. Güvenlik Bütçesi ve Tepe Sınır Kontrolleri
    # Performans bütçesi aşımı kontrolü (CWE-400 DoS / ReDoS savunması)
    if threshold_ms is not None and mean_wall > threshold_ms:
        # Bütçe aşım hatası fırlat
        raise PerformanceBudgetExceededError(
            f"Hedef '{name}' performans bütçesini aştı: {mean_wall:.3f} ms > {threshold_ms:.3f} ms"
        )

    # Bellek sınırı aşımı kontrolü (CWE-401 Bellek Tavanı)
    if max_memory_bytes is not None and peak_memory > max_memory_bytes:
        # Bellek aşım hatası fırlat
        raise MemoryLimitExceededError(
            f"Hedef '{name}' bellek sınırını aştı: {peak_memory} bayt > {max_memory_bytes} bayt"
        )

    # Sonuç nesnesini oluştur ve döndür
    return BenchmarkResult(
        target_name=name,
        iterations=measured_iterations,
        wall_times_ms=[round(t, 4) for t in wall_times],
        cpu_times_ms=[round(t, 4) for t in cpu_times],
        mean_wall_ms=round(mean_wall, 4),
        median_wall_ms=round(median_wall, 4),
        stdev_wall_ms=round(stdev_wall, 4),
        min_wall_ms=round(min_wall, 4),
        max_wall_ms=round(max_wall, 4),
        p95_wall_ms=round(p95_wall, 4),
        p99_wall_ms=round(p99_wall, 4),
        peak_memory_bytes=peak_memory,
        throughput_ops_per_sec=round(throughput, 2)
    )


# ==============================================================================
# GÜVENLİK FONKSİYONLARI İÇİN PROFİLLEME DEKORATÖRÜ
# ==============================================================================

def profile_security_func(
    threshold_ms: Optional[float] = None,
    max_memory_bytes: Optional[int] = None
) -> Callable:
    """
    Herhangi bir güvenlik fonksiyonunun üzerine eklenerek her çağrıda
    çalışma süresi ve bellek tüketimini izleyen dekoratör.
    """
    # İç dekoratör fonksiyonu
    def decorator(func: Callable) -> Callable:
        # Orijinal fonksiyon imzasını koru
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Bellek takibini başlat
            tracemalloc.start()
            tracemalloc.reset_peak()
            # Başlangıç zamanı
            t_start = time.perf_counter()

            # Orijinal fonksiyonu yürüt
            res = func(*args, **kwargs)

            # Geçen duvar süresi (ms)
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            # Tepe bellek
            _, peak_mem = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            # Eşik kontrolü (CWE-400)
            if threshold_ms is not None and elapsed_ms > threshold_ms:
                # İstisna fırlat
                raise PerformanceBudgetExceededError(
                    f"Fonksiyon '{func.__name__}' eşiği aştı: {elapsed_ms:.2f} ms > {threshold_ms:.2f} ms"
                )

            # Bellek kontrolü (CWE-401)
            if max_memory_bytes is not None and peak_mem > max_memory_bytes:
                # İstisna fırlat
                raise MemoryLimitExceededError(
                    f"Fonksiyon '{func.__name__}' bellek sınırını aştı: {peak_mem} B > {max_memory_bytes} B"
                )

            # Sonucu dön
            return res
        # Sarmalayıcıyı dön
        return wrapper
    # Dekoratörü dön
    return decorator


# ==============================================================================
# YERLEŞİK SİBER GÜVENLİK BENCHMARK HEDEFLERİ
# ==============================================================================

def bench_sha256(data: bytes) -> str:
    """SHA-256 kriptografik özetleme testi."""
    # SHA-256 özetini al
    return hashlib.sha256(data).hexdigest()


def bench_sha512(data: bytes) -> str:
    """SHA-512 kriptografik özetleme testi."""
    # SHA-512 özetini al
    return hashlib.sha512(data).hexdigest()


def bench_blake2b(data: bytes) -> str:
    """BLAKE2b yüksek hızlı kriptografik özetleme testi."""
    # BLAKE2b özetini al
    return hashlib.blake2b(data).hexdigest()


def bench_string_concat(lines: List[str]) -> str:
    """Kötü pratik: Tek tek string birleştirme (+ operatörü) bellek maliyeti."""
    # Boş dize başlat
    s = ""
    # Her satırı toplayarak ekle
    for line in lines:
        s += line + "\n"
    # Sonucu dön
    return s


def bench_list_join(lines: List[str]) -> str:
    """İyi pratik: Tek seferde list.join() bellek ve CPU optimizasyonu."""
    # Listenin join fonksiyonunu çağır
    return "\n".join(lines)


# Güvenlik amaçlı önceden derlenmiş regex
COMPILED_PATTERN = re.compile(r"\[(ERROR|WARN|FATAL)\]\s+ip=([0-9.]+)")


def bench_regex_compiled(log_line: str) -> bool:
    """Önceden derlenmiş regex ile eşleştirme."""
    # Derlenmiş desen ile ara
    return bool(COMPILED_PATTERN.search(log_line))


def bench_regex_dynamic(log_line: str) -> bool:
    """Kötü pratik: Her çağrıda sıfırdan re.search() çalıştırma."""
    # Her seferinde string üzerinden ara
    return bool(re.search(r"\[(ERROR|WARN|FATAL)\]\s+ip=([0-9.]+)", log_line))


# Kayıtlı hedef fonksiyonlar tablosu
BENCHMARK_REGISTRY: Dict[str, Callable] = {
    "sha256": bench_sha256,
    "sha512": bench_sha512,
    "blake2b": bench_blake2b,
    "string_concat": bench_string_concat,
    "list_join": bench_list_join,
    "regex_compiled": bench_regex_compiled,
    "regex_dynamic": bench_regex_dynamic
}
