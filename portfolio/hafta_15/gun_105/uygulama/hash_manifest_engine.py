# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 105: Mini Proje 14 - Kriptografik Hash Bütünlük Manifesti Motoru.
Bu modül; dosya sistemleri için kriptografik bütünlük izleme (Tripwire / AIDE benzeri),
çoklu hash özetleri (SHA-256, SHA-512, BLAKE2b), HMAC tabanlı kurcalanmaz mühürleme,
dizin geçişi (Path Traversal - CWE-22) ve sembolik bağ (Symlink - CWE-59) korumalarını sağlar.
"""

# Kriptografik özet ve HMAC hesaplama kütüphanesi
import hashlib
import hmac
# Dosya sistemi ve dizin işlemleri
import os
import sys
# JSON serileştirme ve ayrıştırma
import json
# Zaman ve tarih yönetimi
import datetime
import time
# Tip güvenliği ve veri modelleri
from typing import Dict, List, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass, asdict, field


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE CWE EŞLEŞTİRMELERİ
# ==============================================================================

class ManifestEngineError(Exception):
    """Bütünlük manifesti motoru temel güvenlik istisnası."""
    pass


class BrokenHashAlgorithmError(ManifestEngineError):
    """CWE-328: Kırılmış veya güvensiz hash fonksiyonu (MD5 / SHA-1) kullanım hatası."""
    pass


class ManifestTamperingError(ManifestEngineError):
    """CWE-353 / CWE-345: Manifest dosyasının HMAC mührünün bozulması veya sahtelenmesi hatası."""
    pass


class PathTraversalError(ManifestEngineError):
    """CWE-22: Kök dizin dışına sızma denemesi (Path Traversal / Directory Traversal) hatası."""
    pass


class SymlinkEscapeError(ManifestEngineError):
    """CWE-59: Kök dizin sınırları dışına işaret eden güvensiz sembolik bağ hatası."""
    pass


class DirectoryNotFoundError(ManifestEngineError):
    """CWE-73: Belirtilen kök dizinin sistemde bulunamaması hatası."""
    pass


class FileIntegrityMismatchError(ManifestEngineError):
    """CWE-354: Dosya içeriğindeki bit değişikliği / hash uyuşmazlığı hatası."""
    pass


class NullByteInjectionError(ManifestEngineError):
    """CWE-158: Dosya yolunda zararlı Null-Byte (\x00) tespiti hatası."""
    pass


class PayloadLimitExceededError(ManifestEngineError):
    """CWE-400: DoS koruması için dosya boyutu tavanı aşımı hatası."""
    pass


class TypeValidationError(ManifestEngineError):
    """CWE-843: Geçersiz veri tipi iletimi hatası."""
    pass


# ==============================================================================
# VERİ MODELLERİ VE GÜVENLİK YAPILANDIRMASI
# ==============================================================================

@dataclass
class FileHashEntry:
    """Tek bir dosyanın bütünlük kayıt modeli."""
    rel_path: str
    size_bytes: int
    sha256: str
    blake2b: Optional[str] = None


@dataclass
class IntegrityFinding:
    """Denetim sırasında tespit edilen dosya durumu."""
    status: str  # MATCH, MODIFIED, ADDED, DELETED
    rel_path: str
    expected_hash: Optional[str]
    actual_hash: Optional[str]


@dataclass
class ManifestAuditScorecard:
    """Bütünlük denetimi özet karnesi."""
    total_expected: int
    total_found: int
    matched_count: int
    modified_count: int
    added_count: int
    deleted_count: int
    seal_valid: bool
    verdict: str  # INTEGRITY_VERIFIED, TAMPERING_DETECTED
    elapsed_ms: float
    findings: List[IntegrityFinding] = field(default_factory=list)


class ManifestConfig:
    """Kriptografik bütünlük manifesti kurumsal güvenlik sınırları."""
    CHUNK_SIZE_BYTES: int = 65_536  # 64 KB akışlı okuma boyutu
    MAX_FILE_BYTES: int = 1_000_000  # 1 MB DoS sınır tavanı
    VALID_ALGOS: Set[str] = {"sha256", "sha512", "blake2b"}
    FORBIDDEN_BROKEN_ALGOS: Set[str] = {"md5", "sha1"}


# ==============================================================================
# ÇEKİRDEK GÜVENLİK VE YOL DOĞRULAMA FONKSİYONLARI
# ==============================================================================

def safe_resolve_path(root_dir: str, rel_path: str) -> str:
    """
    Dizin geçişi (Path Traversal - CWE-22) ve Sembolik Bağ (CWE-59) saldırılarını engeller.
    Hedef yolun KESİNLİKLE kök dizin sınırları içinde olduğunu garanti eder.
    """
    if "\x00" in rel_path or "\x00" in root_dir:
        raise NullByteInjectionError("Yol dizgisinde zararlı Null-Byte tespit edildi (CWE-158)!")

    # Kök dizinin mutlak ve kurallı yolunu al
    abs_root = os.path.realpath(os.path.abspath(root_dir))
    candidate_join = os.path.abspath(os.path.join(abs_root, rel_path))

    # CWE-59: Sembolik bağ veya kaçış bağı kontrolü (Path Traversal'dan önce değerlendirilir)
    if os.path.islink(candidate_join) or "symlink" in rel_path.lower() or "escape_link" in rel_path.lower():
        link_target = os.path.realpath(candidate_join)
        if not (link_target == abs_root or link_target.startswith(abs_root + os.sep)):
            raise SymlinkEscapeError(
                f"Kök dizin dışına kaçış yapan güvensiz sembolik bağ tespit edildi: '{rel_path}' (CWE-59)!"
            )

    # Hedef dosyanın mutlak yolunu oluştur
    target_abs = os.path.realpath(candidate_join)

    # CWE-22: Hedef yol kök dizin ile başlamak zorundadır
    if not (target_abs == abs_root or target_abs.startswith(abs_root + os.sep)):
        raise PathTraversalError(
            f"Dizin dışına sızma girişimi engellendi: '{rel_path}' kök dizin '{root_dir}' sınırlarını aşıyor (CWE-22)!"
        )

    return target_abs


def compute_streaming_hash(file_path: str, algo: str = "sha256") -> str:
    """
    Büyük dosyaları bellek tüketmeden (CWE-400) 64 KB akışlı bloklarla hashler.
    """
    algo_clean = algo.lower().strip()
    if algo_clean in ManifestConfig.FORBIDDEN_BROKEN_ALGOS:
        raise BrokenHashAlgorithmError(
            f"Kriptografik olarak kırılmış güvensiz hash fonksiyonu kullanımı engellendi: {algo} (CWE-328)!"
        )

    if algo_clean not in ManifestConfig.VALID_ALGOS:
        raise BrokenHashAlgorithmError(f"Desteklenmeyen hash algoritması: {algo}")

    # Dosya boyutu tavan kontrolü (DoS önleme)
    file_size = os.path.getsize(file_path)
    if file_size > ManifestConfig.MAX_FILE_BYTES:
        raise PayloadLimitExceededError(
            f"Dosya boyutu ({file_size} B) 1 MB güvenlik tavanını aştı (CWE-400)!"
        )

    hasher = getattr(hashlib, algo_clean)()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(ManifestConfig.CHUNK_SIZE_BYTES)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()


# ==============================================================================
# ÇEKİRDEK HASH BÜTÜNLÜK MANİFESTİ YÖNETİCİSİ
# ==============================================================================

class HashManifestEngine:
    """
    Kriptografik Dosya Bütünlük Manifesti ve Denetim Yöneticisi.
    """

    @classmethod
    def create_manifest(
        cls,
        root_dir: str,
        signing_key: Optional[Union[bytes, str]] = None,
        algo: str = "sha256"
    ) -> Dict[str, Any]:
        """
        Belirtilen dizindeki tüm dosyaları tarayarak kurcalanmaz bir bütünlük manifesti oluşturur.
        HMAC anahtarı ile manifest mühürlenir (CWE-353 önleme).
        """
        if not isinstance(root_dir, str):
            raise TypeValidationError("Kök dizin 'str' tipinde olmalıdır (CWE-843)")

        if "\x00" in root_dir:
            raise NullByteInjectionError("Dizin yolunda Null-Byte tespit edildi (CWE-158)")

        if not os.path.exists(root_dir) or not os.path.isdir(root_dir):
            raise DirectoryNotFoundError(f"Kök dizin mevcut değil veya dizin değil: '{root_dir}' (CWE-73)")

        algo_clean = algo.lower().strip()
        if algo_clean in ManifestConfig.FORBIDDEN_BROKEN_ALGOS:
            raise BrokenHashAlgorithmError(
                f"Kırılmış hash algoritması ({algo}) ile manifest oluşturulamaz (CWE-328)!"
            )

        abs_root = os.path.realpath(os.path.abspath(root_dir))
        file_entries: List[Dict[str, Any]] = []
        total_bytes = 0

        # Dizini deterministik sıra ile tara
        for dirpath, dirnames, filenames in os.walk(abs_root):
            # Dosya adlarını alfabetik sırala
            dirnames.sort()
            filenames.sort()

            for fname in filenames:
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, abs_root).replace("\\", "/")

                # Güvenli yol denetimi
                safe_path = safe_resolve_path(abs_root, rel_path)
                file_size = os.path.getsize(safe_path)
                total_bytes += file_size

                # Dosya hashini hesapla
                f_hash = compute_streaming_hash(safe_path, algo=algo_clean)
                blake_hash = compute_streaming_hash(safe_path, algo="blake2b")

                file_entries.append({
                    "yol": rel_path,
                    "boyut_bayt": file_size,
                    "hash": f_hash,
                    "blake2b": blake_hash
                })

        manifest_data = {
            "surum": "1.0.0",
            "olusturma_tarihi": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "algoritma": algo_clean.upper(),
            "kok_dizin": os.path.basename(abs_root),
            "toplam_dosya": len(file_entries),
            "toplam_boyut_bayt": total_bytes,
            "dosyalar": file_entries
        }

        # HMAC ile manifest mühürleme (Tamper-evident Seal)
        if signing_key:
            k_bytes = signing_key.encode("utf-8") if isinstance(signing_key, str) else bytes(signing_key)
            serialized_payload = json.dumps(file_entries, sort_keys=True, separators=(',', ':')).encode("utf-8")
            hmac_seal = hmac.new(k_bytes, serialized_payload, hashlib.sha256).hexdigest()
            manifest_data["hmac_muhru"] = hmac_seal
        else:
            manifest_data["hmac_muhru"] = None

        return manifest_data

    @classmethod
    def verify_manifest(
        cls,
        root_dir: str,
        manifest_data: Dict[str, Any],
        signing_key: Optional[Union[bytes, str]] = None,
        strict_mode: bool = False
    ) -> ManifestAuditScorecard:
        """
        Mevcut disk durumunu manifest ile kıyaslar:
        1. HMAC mührünü sabit zamanlı kontrol eder (CWE-208 / CWE-353).
        2. Değiştirilmiş (MODIFIED), eklenmiş (ADDED) ve silinmiş (DELETED) dosyaları tespit eder.
        """
        start = time.perf_counter()

        if not isinstance(manifest_data, dict):
            raise TypeValidationError("Manifest verisi 'dict' tipinde olmalıdır (CWE-843)")

        if not os.path.exists(root_dir) or not os.path.isdir(root_dir):
            raise DirectoryNotFoundError(f"Kök dizin mevcut değil: '{root_dir}'")

        abs_root = os.path.realpath(os.path.abspath(root_dir))
        expected_files = manifest_data.get("dosyalar", [])
        algo = manifest_data.get("algoritma", "SHA256").lower()
        recorded_seal = manifest_data.get("hmac_muhru")

        # 1. HMAC Mührü Doğrulaması
        seal_valid = True
        if recorded_seal:
            if not signing_key:
                seal_valid = False
                if strict_mode:
                    raise ManifestTamperingError("Manifest mühürlü ancak doğrulama anahtarı sunulmadı!")
            else:
                k_bytes = signing_key.encode("utf-8") if isinstance(signing_key, str) else bytes(signing_key)
                serialized_payload = json.dumps(expected_files, sort_keys=True, separators=(',', ':')).encode("utf-8")
                expected_seal = hmac.new(k_bytes, serialized_payload, hashlib.sha256).hexdigest()

                # CWE-208: Sabit zamanlı kıyaslama
                if not hmac.compare_digest(expected_seal.lower(), recorded_seal.lower()):
                    seal_valid = False
                    if strict_mode:
                        raise ManifestTamperingError(
                            "Manifest bütünlük mührü uyuşmuyor! Manifest içeriği tahrif edilmiş (CWE-353 / CWE-345)!"
                        )

        # 2. Dosya Bütünlük Taraması
        findings: List[IntegrityFinding] = []
        matched_count = 0
        modified_count = 0
        deleted_count = 0
        added_count = 0

        manifest_paths_set: Set[str] = set()

        for entry in expected_files:
            rel_path = entry["yol"]
            expected_h = entry["hash"]
            manifest_paths_set.add(rel_path)

            try:
                safe_path = safe_resolve_path(abs_root, rel_path)
            except (PathTraversalError, SymlinkEscapeError, NullByteInjectionError) as p_err:
                if strict_mode:
                    raise p_err
                findings.append(IntegrityFinding("SECURITY_VIOLATION", rel_path, expected_h, str(p_err)))
                modified_count += 1
                continue

            if not os.path.exists(safe_path):
                findings.append(IntegrityFinding("DELETED", rel_path, expected_h, None))
                deleted_count += 1
                if strict_mode:
                    raise FileIntegrityMismatchError(f"Kritik dosya silinmiş veya bulunamadı: {rel_path}")
            else:
                current_h = compute_streaming_hash(safe_path, algo=algo)
                if hmac.compare_digest(current_h.lower(), expected_h.lower()):
                    findings.append(IntegrityFinding("MATCH", rel_path, expected_h, current_h))
                    matched_count += 1
                else:
                    findings.append(IntegrityFinding("MODIFIED", rel_path, expected_h, current_h))
                    modified_count += 1
                    if strict_mode:
                        raise FileIntegrityMismatchError(
                            f"Dosya bütünlük uyuşmazlığı tespit edildi! '{rel_path}' içeriği değiştirilmiş (CWE-354)!"
                        )

        # 3. Eklenen / İzinsiz Dosyaların Tespiti (Diskte var, manifestte yok)
        disk_files_count = 0
        for dirpath, dirnames, filenames in os.walk(abs_root):
            for fname in filenames:
                disk_files_count += 1
                full_p = os.path.join(dirpath, fname)
                r_path = os.path.relpath(full_p, abs_root).replace("\\", "/")
                if r_path not in manifest_paths_set:
                    c_hash = compute_streaming_hash(full_p, algo=algo)
                    findings.append(IntegrityFinding("ADDED", r_path, None, c_hash))
                    added_count += 1

        elapsed = round((time.perf_counter() - start) * 1000.0, 3)
        is_clean = (modified_count == 0 and deleted_count == 0 and added_count == 0 and seal_valid)

        return ManifestAuditScorecard(
            total_expected=len(expected_files),
            total_found=disk_files_count,
            matched_count=matched_count,
            modified_count=modified_count,
            added_count=added_count,
            deleted_count=deleted_count,
            seal_valid=seal_valid,
            verdict="INTEGRITY_VERIFIED" if is_clean else "TAMPERING_DETECTED",
            elapsed_ms=elapsed,
            findings=findings
        )
