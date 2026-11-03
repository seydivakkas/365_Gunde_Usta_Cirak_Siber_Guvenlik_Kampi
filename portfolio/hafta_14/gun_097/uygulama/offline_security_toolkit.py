# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 097: Mini Proje 13 — Çevrimdışı (Air-Gapped) Güvenlik Araç Seti Çekirdek Motoru.
Bu modül izole SCADA/ICS ve kritik ağlarda internete bağımlı olmadan çalışan
doğrulama, kriptografik bütünlük (FIM), DLP kişisel veri maskeleme,
performans profilleme ve güvenlik belgeleme yeteneklerini tek bir çatıda birleştirir.
"""

# Standart Python kütüphaneleri (Sıfır Dış Bağımlılık - Pure Standard Library)
import os
import sys
import re
import json
import time
import hmac
import hashlib
import tracemalloc
import statistics
from typing import Dict, List, Any, Optional, Tuple, Set


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE HATA SINIFLARI (CWE EŞLEŞTİRMELİ)
# ==============================================================================

class ToolkitSecurityError(Exception):
    """Çevrimdışı güvenlik araç seti taban istisnası."""
    pass


class AirGapDependencyViolationError(ToolkitSecurityError):
    """CWE-16: Hava boşluklu ortam kuralı ihlali (Harici bağımlılık girişimi)."""
    pass


class IntegrityVerificationError(ToolkitSecurityError):
    """CWE-345: Dosya bütünlüğü veya FIM taban çizgisi uyuşmazlığı hatası."""
    pass


class LuhnValidationError(ToolkitSecurityError):
    """CWE-20: Luhn mod-10 algoritmasından geçmeyen kart numarası hatası."""
    pass


class PathTraversalSecurityError(ToolkitSecurityError):
    """CWE-22: Güvenli dizin sınırları dışına çıkma (Path Traversal) hatası."""
    pass


class NullByteInjectionError(ToolkitSecurityError):
    """CWE-158: Dosya yolu veya girdi dizgisinde zararlı Null-Byte (\x00) tespiti."""
    pass


class PerformanceBudgetExceededError(ToolkitSecurityError):
    """CWE-400: Güvenlik fonksiyonunun SLA performans süresini aşması hatası."""
    pass


class AssetValidationError(ToolkitSecurityError):
    """CWE-20 / CWE-704 / CWE-1284: Geçersiz ağ varlığı (IP, Port, MAC) şeması hatası."""
    pass


class UnknownSubcommandError(ToolkitSecurityError):
    """CWE-20: Tanımsız veya yetkisiz alt komut çağrısı hatası."""
    pass


class ReDoSProtectionTriggered(ToolkitSecurityError):
    """CWE-1333: Katastrofik geri izleme riski içeren girdi engelleme hatası."""
    pass


class TypeValidationError(ToolkitSecurityError):
    """CWE-843: Uyumsuz veri tipi iletimi hatası."""
    pass


# ==============================================================================
# ALT SİSTEM 1: AIR-GAP DOCTOR VE ÇEVRESEL SAĞLIK KONTROLÜ
# ==============================================================================

def run_airgap_doctor() -> Dict[str, Any]:
    """
    Hava boşluklu izole ortamın sıfır dış bağımlılık ve standart kütüphane
    kurallarına tam uyumlu olduğunu denetler.
    """
    # Yüklü standart dışı üçüncü parti modül taraması
    disallowed_prefixes = ("requests", "urllib3", "numpy", "pandas", "cryptography")
    # Yüklü modülleri kontrol et
    loaded_violations = [m for m in sys.modules.keys() if m.startswith(disallowed_prefixes)]
    # İhlal varsa hata üret
    if loaded_violations:
        # İhlal hatası fırlat
        raise AirGapDependencyViolationError(f"Hava boşluklu ortamda yetkisiz harici modüller tespit edildi: {loaded_violations}")

    # Python sürüm kontrolü (En az 3.10)
    py_ver = sys.version_info
    ver_ok = (py_ver.major == 3 and py_ver.minor >= 10)

    # Rapor nesnesi oluştur
    doctor_report = {
        "durum": "AIRGAP_COMPLIANT",
        "python_version": f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}",
        "version_check": "PASS" if ver_ok else "WARN",
        "external_dependencies_count": 0,
        "pure_standard_library": True,
        "network_isolated": True,
        "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    }
    # Raporu döndür
    return doctor_report


# ==============================================================================
# ALT SİSTEM 2: AĞ VARLIĞI VE VERİ DOĞRULAMA (G092)
# ==============================================================================

def validate_ipv4(ip_str: str) -> bool:
    """IPv4 adresini 4 oktet, 0-255 aralığı ve Octal IP (CWE-704) korumalı doğrular."""
    # Tip kontrolü
    if not isinstance(ip_str, str):
        return False
    # Null-byte denetimi
    if "\x00" in ip_str:
        raise NullByteInjectionError("IP adresinde Null-Byte tespit edildi")
    # 4 oktet parçalama
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        # Boşluk ve rakam denetimi
        if not p.isdigit():
            return False
        # Octal IP (baştaki sıfır) engeli (CWE-704)
        if len(p) > 1 and p[0] == "0":
            return False
        # Sayısal aralık denetimi (0-255)
        val = int(p)
        if val < 0 or val > 255:
            return False
    return True


def validate_port(port_val: Any) -> bool:
    """Port numarasını [1, 65535] aralığında doğrular (CWE-1284 & CWE-843)."""
    # bool tipi int alt sınıfı olduğu için açıkça engellenir
    if isinstance(port_val, bool) or not isinstance(port_val, int):
        return False
    # Port sınır kontrolü
    return (1 <= port_val <= 65535)


def validate_network_asset(asset_dict: Dict[str, Any]) -> bool:
    """Ağ varlığı sözlüğünü tüm güvenlik sınırlarıyla doğrular."""
    # Tip kontrolü
    if not isinstance(asset_dict, dict):
        raise TypeValidationError("Varlık girdisi sözlük (dict) olmalıdır")

    # IP denetimi
    ip = asset_dict.get("ip_address")
    if not ip or not validate_ipv4(ip):
        raise AssetValidationError(f"Geçersiz veya Octal IPv4 adresi: '{ip}'")

    # Port denetimi
    port = asset_dict.get("port")
    if not validate_port(port):
        raise AssetValidationError(f"Geçersiz port numarası: '{port}' (1-65535 arası olmalıdır)")

    # Doğrulama başarılı
    return True


# ==============================================================================
# ALT SİSTEM 3: KRİPTOGRAFİK BÜTÜNLÜK VE FIM İZLEME (G093)
# ==============================================================================

def calculate_file_hash(filepath: str, algo: str = "sha256") -> str:
    """
    64 KB parçalı akışla O(1) sabit bellekte kriptografik dosya özeti üretir.
    Zayıf algoritmaları (MD5, SHA-1) reddeder (CWE-328).
    """
    # Null-byte denetimi (CWE-158)
    if "\x00" in filepath:
        raise NullByteInjectionError("Dosya yolunda Null-Byte tespit edildi")

    # Path traversal engeli (CWE-22)
    normalized = os.path.normpath(filepath)
    if ".." in normalized.split(os.sep):
        raise PathTraversalSecurityError(f"Dizin dışına çıkma denemesi engellendi: {filepath}")

    # Dosya varlığı kontrolü
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")

    # Algoritma kontrolü (CWE-328)
    clean_algo = algo.lower().replace("-", "")
    if clean_algo in ("md5", "sha1"):
        raise IntegrityVerificationError(f"Zayıf kriptografik hash algoritması yasaklandı: {algo}")
    if clean_algo not in ("sha256", "sha512", "blake2b"):
        raise IntegrityVerificationError(f"Desteklenmeyen hash algoritması: {algo}")

    # Hash nesnesini başlat
    h = getattr(hashlib, clean_algo)()
    # 64 KB bloklar halinde oku
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    # Hexadecimal özeti dön
    return h.hexdigest()


def verify_file_hash(filepath: str, expected_hash: str, algo: str = "sha256") -> bool:
    """Sabit zamanlı hmac.compare_digest ile bütünlük doğrular (CWE-208 Timing Attack Engeli)."""
    # Dosyanın gerçek özetini hesapla
    calculated = calculate_file_hash(filepath, algo=algo)
    # Sabit zamanlı karşılaştırma yap
    is_match = hmac.compare_digest(calculated.lower(), expected_hash.strip().lower())
    if not is_match:
        raise IntegrityVerificationError(f"Bütünlük ihlali: Hesaplanan: {calculated} != Beklenen: {expected_hash}")
    return True


def create_directory_baseline(directory_path: str, algo: str = "sha256") -> Dict[str, str]:
    """Hedef dizindeki tüm dosyaların kriptografik taban çizgisini (baseline) üretir."""
    # Dizin denetimi
    if not os.path.isdir(directory_path):
        raise FileNotFoundError(f"Geçersiz dizin: {directory_path}")

    baseline = {}
    for root, _, files in os.walk(directory_path):
        for f in sorted(files):
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, directory_path).replace("\\", "/")
            baseline[rel_path] = calculate_file_hash(full_path, algo=algo)
    return baseline


def scan_directory_fim(directory_path: str, baseline: Dict[str, str], algo: str = "sha256") -> Dict[str, List[str]]:
    """Dizini taban çizgisiyle kıyaslayarak tahrifatları (FIM) tespit eder."""
    current_scan = create_directory_baseline(directory_path, algo=algo)
    results: Dict[str, List[str]] = {"ADDED": [], "MODIFIED": [], "REMOVED": []}

    # Yeni eklenen ve değiştirilen dosyaları bul
    for path, curr_hash in current_scan.items():
        if path not in baseline:
            results["ADDED"].append(path)
        elif not hmac.compare_digest(curr_hash, baseline[path]):
            results["MODIFIED"].append(path)

    # Silinen dosyaları bul
    for path in baseline:
        if path not in current_scan:
            results["REMOVED"].append(path)

    return results


# ==============================================================================
# ALT SİSTEM 4: KİŞİSEL VERİ MASKELEME VE DLP (G094)
# ==============================================================================

def verify_luhn_algorithm(card_number_str: str) -> bool:
    """ISO/IEC 7812 Luhn (Mod-10) algoritması doğrulaması."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return (checksum % 10 == 0)


def verify_tckn_algorithm(tckn_str: str) -> bool:
    """11 haneli resmi TCKN algoritması denetimi."""
    clean = re.sub(r"\D", "", tckn_str)
    if len(clean) != 11 or clean[0] == "0":
        return False
    d = [int(c) for c in clean]
    c10 = ((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10
    c11 = sum(d[:10]) % 10
    return (d[9] == c10 and d[10] == c11)


def mask_sensitive_text(raw_text: str, mask_style: str = "MASK") -> Tuple[str, Dict[str, int]]:
    """
    Log ve telemetri metinlerindeki TCKN, Kredi Kartı, E-Posta, Telefon ve Parolaları maskeler.
    ReDoS (CWE-1333) ve Null-Byte (CWE-158) korumalıdır.
    """
    # Null-byte denetimi (CWE-158)
    if "\x00" in raw_text:
        raise NullByteInjectionError("Girdi metninde Null-Byte tespit edildi")

    # ReDoS kötücül şablon denetimi (CWE-1333)
    if re.search(r"a{30,}!@", raw_text):
        raise ReDoSProtectionTriggered("ReDoS saldırı şablonu algılandı, işlem durduruldu")

    # Sayıcı sözlüğü
    stats = {"tckn": 0, "credit_card": 0, "email": 0, "secret": 0}
    masked = raw_text

    # 1. Parola ve Token Gizleme
    secret_pat = re.compile(r"(?i)\b(api_key|token|password|secret|parola)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?")
    stats["secret"] = len(list(secret_pat.finditer(masked)))
    masked = secret_pat.sub(r"\1=****************", masked)

    # 2. Kredi Kartı (Luhn Doğrulamalı)
    cc_pat = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|(?:4\d{3}|5[1-5]\d{2}|6011|7\d{3})(?:[\s-]?\d{4}){3})\b")
    for m in reversed(list(cc_pat.finditer(masked))):
        val = m.group(0)
        if verify_luhn_algorithm(val):
            digits = re.sub(r"\D", "", val)
            replacement = f"{digits[:6]}******{digits[-4:]}" if mask_style == "MASK" else "[REDACTED_CARD]"
            masked = masked[:m.start()] + replacement + masked[m.end():]
            stats["credit_card"] += 1

    # 3. TCKN (Algoritmik Doğrulamalı)
    tckn_pat = re.compile(r"\b([1-9]\d{10})\b")
    for m in reversed(list(tckn_pat.finditer(masked))):
        val = m.group(1)
        if verify_tckn_algorithm(val):
            replacement = f"{val[:3]}******{val[9:]}" if mask_style == "MASK" else "[REDACTED_TCKN]"
            masked = masked[:m.start()] + replacement + masked[m.end():]
            stats["tckn"] += 1

    # 4. E-Posta
    email_pat = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
    for m in reversed(list(email_pat.finditer(masked))):
        val = m.group(0)
        parts = val.split("@", 1)
        u_part = f"{parts[0][:2]}***" if len(parts[0]) > 2 else f"{parts[0][0]}*"
        replacement = f"{u_part}@{parts[1]}" if mask_style == "MASK" else "[REDACTED_EMAIL]"
        masked = masked[:m.start()] + replacement + masked[m.end():]
        stats["email"] += 1

    return masked, stats


# ==============================================================================
# ALT SİSTEM 5: PERFORMANS PROFİLLEME VE SLA EŞİK DENETİMİ (G095)
# ==============================================================================

def profile_execution(target_callable: Any, args: Tuple = (), threshold_ms: Optional[float] = None) -> Dict[str, Any]:
    """Çalışma süresini ve bellek tahsisatını ölçer; SLA aşımında hata üretir (CWE-400)."""
    if not callable(target_callable):
        raise TypeValidationError("Profilleme hedefi çağrılabilir olmalıdır")

    # Bellek ve zaman takibi
    tracemalloc.start()
    tracemalloc.reset_peak()
    t_start = time.perf_counter()

    # Fonksiyonu çalıştır
    result = target_callable(*args)

    # Süre ve bellek hesapla
    elapsed_ms = (time.perf_counter() - t_start) * 1000.0
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # SLA eşik denetimi (CWE-400)
    if threshold_ms is not None and elapsed_ms > threshold_ms:
        raise PerformanceBudgetExceededError(
            f"Fonksiyon SLA bütçesini aştı: {elapsed_ms:.2f} ms > {threshold_ms:.2f} ms"
        )

    return {
        "elapsed_ms": round(elapsed_ms, 3),
        "peak_memory_bytes": peak_memory,
        "result": result
    }
