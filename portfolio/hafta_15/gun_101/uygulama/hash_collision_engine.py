# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 101: Kriptografik Hash Fonksiyonları, Çakışma ve Çığ Etkisi Analiz Motoru.
Bu modül; SHA-256, SHA-512 ve BLAKE2b algoritmalarının matematiksel dayanıklılığını,
çığ etkisini (Avalanche Effect) ve Doğum Günü Paradoksu (Birthday Attack) çakışma
dinamiklerini saf Python standart kütüphanesiyle modeller ve analiz eder.
"""

# Kriptografik özetleme ve sabit zamanlı karşılaştırma
import hashlib
import hmac
# Kriptografik güvenli rastgele sayı ve bayt üretimi
import secrets
# Matematiksel hesaplamalar
import math
# Zaman ve performans ölçümü
import time
# Tip ipuçları ve veri yapıları
from typing import Dict, List, Any, Optional, Tuple, Union
# Veri sınıfları
from dataclasses import dataclass, asdict


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE CWE SINIFLARI
# ==============================================================================

class HashSecurityError(Exception):
    """Hash ve çakışma analiz motoru taban güvenlik istisnası."""
    pass


class BrokenHashAlgorithmError(HashSecurityError):
    """CWE-328: Kırılmış veya güvensiz hash algoritması (MD5, SHA-1) kullanımı hatası."""
    pass


class HashCollisionDetectedError(HashSecurityError):
    """CWE-327: İki farklı girdi için aynı özet değerinin (çakışma) tespiti hatası."""
    pass


class AvalancheEffectFailureError(HashSecurityError):
    """CWE-328: Çığ etkisi testinde bit değişim oranının kabul aralığı dışında kalması hatası."""
    pass


class HashVerificationError(HashSecurityError):
    """CWE-208 / CWE-345: Hash özeti bütünlük doğrulaması uyuşmazlığı hatası."""
    pass


class PayloadLimitExceededError(HashSecurityError):
    """CWE-400: Bellek tüketimini sınırlandırmak için 1 MB tavan aşımı hatası."""
    pass


class NullByteInjectionError(HashSecurityError):
    """CWE-158: Algoritma adı veya girdi metninde Null-Byte (\x00) tespiti hatası."""
    pass


class TypeValidationError(HashSecurityError):
    """CWE-843 / CWE-1284: Geçersiz veri tipi veya sınır dışı parametre iletimi hatası."""
    pass


# ==============================================================================
# VERİ MODELLERİ
# ==============================================================================

@dataclass
class AvalancheResult:
    """Çığ etkisi (Avalanche Effect) istatistiksel sonuç modeli."""
    girdi_1: str
    girdi_2: str
    algoritma: str
    farkli_bit_sayisi: int
    toplam_bit_sayisi: int
    degisim_yuzdesi: float
    durum: str  # MÜKEMMEL (~50%), YETERLİ (40-60%), KUSURLU (<35% veya >65%)


@dataclass
class CollisionSimulationResult:
    """Doğum Günü Paradoksu çakışma simülasyonu sonuç modeli."""
    kirpma_bit: int
    deneme_sayisi: int
    teorik_beklenen_deneme: int
    cakisan_girdi_1: str
    cakisan_girdi_2: str
    ortak_ozet_hex: str
    harcanan_sure_ms: float


# ==============================================================================
# ÇEKİRDEK HASH VE ÇAKIŞMA ANALİZ MOTORU
# ==============================================================================

class HashAnalyzer:
    """
    Kriptografik hash fonksiyonları, çığ etkisi ve çakışma direnci denetçisi.
    """

    # Kullanımı yasaklanmış güvensiz algoritmalar (CWE-328)
    PROHIBITED_ALGORITHMS = {"md5", "sha1", "ripemd160"}

    # Kabul edilen modern güvenli algoritmalar (NIST / FIPS standartları)
    APPROVED_ALGORITHMS = {"sha256", "sha384", "sha512", "blake2b", "sha3_256", "sha3_512"}

    # DoS koruma tavanı (1 MB)
    MAX_BUFFER_BYTES = 1_000_000

    @classmethod
    def compute_digest(
        cls,
        data: Union[str, bytes],
        algorithm: str = "sha256",
        allow_insecure: bool = False
    ) -> str:
        """
        Belirtilen algoritma ile verinin kriptografik özetini hesaplar.
        Güvenli modda kırılmış algoritmaları (MD5, SHA-1) reddeder (CWE-328).
        """
        if not isinstance(algorithm, str):
            raise TypeValidationError("Algoritma adı 'str' tipinde olmalıdır")
        if "\x00" in algorithm:
            raise NullByteInjectionError("Algoritma adında Null-Byte tespit edildi (CWE-158)")

        algo_lower = algorithm.strip().lower()

        # Güvensiz algoritma denetimi (CWE-328)
        if not allow_insecure and algo_lower in cls.PROHIBITED_ALGORITHMS:
            raise BrokenHashAlgorithmError(
                f"Kırılmış ve çakışmalı algoritma kullanımı engellendi: '{algorithm}'. "
                f"Kriptografik güvenlik için SHA-256 veya BLAKE2b kullanınız (CWE-328)!"
            )

        # Girdi tipi denetimi (CWE-843)
        if isinstance(data, str):
            if "\x00" in data:
                raise NullByteInjectionError("Girdi metninde Null-Byte tespit edildi")
            raw_bytes = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray)):
            raw_bytes = bytes(data)
        else:
            raise TypeValidationError("Özetlenecek veri 'str' veya 'bytes' tipinde olmalıdır (CWE-843)")

        # DoS ve boyut kontrolü (CWE-400)
        if len(raw_bytes) > cls.MAX_BUFFER_BYTES:
            raise PayloadLimitExceededError(
                f"Veri boyutu 1 MB güvenlik sınırını aştı: {len(raw_bytes)} bayt (CWE-400)"
            )

        # Hash nesnesi oluştur
        try:
            hasher = hashlib.new(algo_lower)
            hasher.update(raw_bytes)
            return hasher.hexdigest()
        except ValueError as val_err:
            raise TypeValidationError(f"Desteklenmeyen hash algoritması: {algorithm} ({str(val_err)})")

    @classmethod
    def calculate_avalanche_effect(
        cls,
        text1: str,
        text2: str,
        algorithm: str = "sha256",
        strict_mode: bool = False
    ) -> AvalancheResult:
        """
        İki girdi arasındaki Çığ Etkisini (Avalanche Effect) bit seviyesinde hesaplar.
        İdeal bir kriptografik hash fonksiyonunda 1 bitlik girdi değişimi
        çıktı bitlerinin ortalama %50'sini değiştirmelidir.
        """
        if not isinstance(text1, str) or not isinstance(text2, str):
            raise TypeValidationError("Girdiler 'str' tipinde olmalıdır")

        digest1_hex = cls.compute_digest(text1, algorithm=algorithm, allow_insecure=True)
        digest2_hex = cls.compute_digest(text2, algorithm=algorithm, allow_insecure=True)

        bytes1 = bytes.fromhex(digest1_hex)
        bytes2 = bytes.fromhex(digest2_hex)

        # Bit farklarını (Hamming Mesafesi) hesapla
        total_bits = len(bytes1) * 8
        different_bits = 0
        for b1, b2 in zip(bytes1, bytes2):
            xor_val = b1 ^ b2
            different_bits += bin(xor_val).count("1")

        change_percentage = round((different_bits / total_bits) * 100.0, 2)

        if 45.0 <= change_percentage <= 55.0:
            status = "MÜKEMMEL (İdeal Çığ Etkisi ~50%)"
        elif 35.0 <= change_percentage <= 65.0:
            status = "YETERLİ (Kriptografik Olarak Kabul Edilebilir)"
        else:
            status = "KUSURLU (Zayıf Çığ Etkisi / Tahmin Edilebilir)"
            if strict_mode:
                raise AvalancheEffectFailureError(
                    f"Çığ etkisi yetersiz: %{change_percentage} değişim (Beklenen: %40 - %60)"
                )

        return AvalancheResult(
            girdi_1=text1,
            girdi_2=text2,
            algoritma=algorithm,
            farkli_bit_sayisi=different_bits,
            toplam_bit_sayisi=total_bits,
            degisim_yuzdesi=change_percentage,
            durum=status
        )

    @classmethod
    def birthday_collision_simulation(
        cls,
        bit_size: int = 16,
        max_attempts: int = 100_000
    ) -> CollisionSimulationResult:
        """
        Doğum Günü Paradoksu prensibiyle kırpılmış (truncated) hash üzerinde
        deneysel çakışma (collision) saldırısını simüle eder.
        Teorik karmaşıklık: O(2^(b/2)) deneme.
        """
        if not isinstance(bit_size, int):
            raise TypeValidationError("Bit boyutu tamsayı olmalıdır")
        if bit_size <= 0 or bit_size > 32:
            raise TypeValidationError(
                f"Kırpma bit boyutu 1 ile 32 arasında olmalıdır ({bit_size} geçersiz - CWE-1284)"
            )

        # Teorik beklenen deneme adedi: sqrt(pi/2 * 2^b)
        theoretical_expected = int(math.sqrt((math.pi / 2.0) * (2 ** bit_size)))

        # Maske hesapla (ilk bit_size biti almak için)
        hex_chars_needed = (bit_size + 3) // 4
        seen_hashes: Dict[str, str] = {}

        start_time = time.perf_counter()
        collision_found = False
        target_pair: Tuple[str, str, str] = ("", "", "")
        attempts = 0

        while attempts < max_attempts and not collision_found:
            attempts += 1
            # Rastgele aday girdi üret
            candidate = f"candidate_nonce_{attempts}_{secrets.token_hex(8)}"
            full_hash = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            # Kırpılmış özet
            truncated_hash = full_hash[:hex_chars_needed]

            if truncated_hash in seen_hashes:
                original_candidate = seen_hashes[truncated_hash]
                if original_candidate != candidate:
                    collision_found = True
                    target_pair = (original_candidate, candidate, truncated_hash)
                    break
            else:
                seen_hashes[truncated_hash] = candidate

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        if not collision_found:
            raise HashCollisionDetectedError(
                f"{max_attempts} denemede {bit_size}-bit çakışma bulunamadı"
            )

        return CollisionSimulationResult(
            kirpma_bit=bit_size,
            deneme_sayisi=attempts,
            teorik_beklenen_deneme=theoretical_expected,
            cakisan_girdi_1=target_pair[0],
            cakisan_girdi_2=target_pair[1],
            ortak_ozet_hex=target_pair[2],
            harcanan_sure_ms=elapsed_ms
        )

    @classmethod
    def verify_digest_constant_time(
        cls,
        actual_digest: str,
        expected_digest: str,
        strict_mode: bool = False
    ) -> bool:
        """
        Zamanlama saldırılarına karşı sabit zamanlı (CWE-208) hash doğrulama yapar.
        """
        if not isinstance(actual_digest, str) or not isinstance(expected_digest, str):
            raise TypeValidationError("Özet değerleri 'str' tipinde olmalıdır")
        if not actual_digest or not expected_digest:
            raise TypeValidationError("Özet değeri boş olamaz (CWE-20)")

        # CWE-208: Sabit zamanlı karşılaştırma
        is_match = hmac.compare_digest(actual_digest.lower(), expected_digest.lower())

        if strict_mode and not is_match:
            raise HashVerificationError("Özet doğrulaması başarısız: Veri bütünlüğü bozulmuş (CWE-345)!")

        return is_match
