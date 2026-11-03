# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 100: Entropi ve Kriptografik Rastgelelik Analiz Motoru.
Bu modül; Shannon Entropisi, Min-Entropi, Ki-Kare (Chi-Square) ve Monobit testleri ile
veri akışlarının rastgelelik kalitesini ölçer; CSPRNG ve zayıf PRNG ayrımını yapar.
"""

# Matematiksel hesaplama modülü
import math
# Kriptografik güvenli rastgele sayı üreticisi
import secrets
# İşletim sistemi entropi havuzu
import os
# Sistem ve bellek işlemleri
import sys
# Koleksiyon ve frekans sayıcı
from collections import Counter
# Zaman ve tarih ölçümü
import time
# Tip ipuçları ve veri yapıları
from typing import Dict, List, Any, Optional, Tuple, Union
# Veri sınıfları
from dataclasses import dataclass, asdict


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE HATA SINIFLARI (CWE EŞLEŞTİRMELİ)
# ==============================================================================

class EntropySecurityError(Exception):
    """Entropi ve rastgelelik motoru taban güvenlik istisnası."""
    pass


class WeakPRNGDetectedError(EntropySecurityError):
    """CWE-338: Kriptografik olarak zayıf sözde rastgele üreteç (MT19937) kullanımı hatası."""
    pass


class InsufficientEntropyError(EntropySecurityError):
    """CWE-331: Güvenlik eşiğinin altında yetersiz entropi veya boş veri hatası."""
    pass


class PredictableSeedError(EntropySecurityError):
    """CWE-337: Üretecin zaman damgası veya tahmin edilebilir tohumla başlatılması hatası."""
    pass


class SmallEntropySpaceError(EntropySecurityError):
    """CWE-334: Brute-force saldırılarına açık, 64 bitten küçük rastgele alan hatası."""
    pass


class PayloadLimitExceededError(EntropySecurityError):
    """CWE-400: Bellek tüketimini sınırlandırmak için 1 MB tavan aşımı hatası."""
    pass


class NullByteInjectionError(EntropySecurityError):
    """CWE-158: Dosya yolu veya etiket parametresinde Null-Byte (\x00) tespiti hatası."""
    pass


class TypeValidationError(EntropySecurityError):
    """CWE-843 / CWE-1284: Geçersiz veri tipi veya sınır dışı parametre iletimi hatası."""
    pass


# ==============================================================================
# VERİ MODELLERİ
# ==============================================================================

@dataclass
class EntropyMetrics:
    """Rastgelelik ve entropi istatistiksel analiz metrikleri."""
    shannon_entropi: float  # Bit/bayt (0.0 - 8.0)
    min_entropi: float  # En kötü durum entropisi (Bit/bayt)
    chi_kare: float  # Ki-Kare uygunluk testi değeri
    monobit_oran: float  # 1 bitlerinin toplam bitlere oranı
    monobit_p_degeri: float  # Frekans testi p-değeri (> 0.01 ise rastgele)
    bayt_sayisi: int  # Toplam analiz edilen bayt adedi
    tekil_bayt_sayisi: int  # Görülen farklı bayt adedi (0-256)
    degerlendirme: str  # YÜKSEK, ORTA, DÜŞÜK


@dataclass
class EntropyAuditReport:
    """Kapsamlı entropi denetim karnesi ve kriptografik uygunluk raporu."""
    hedef_adi: str
    metrikler: Dict[str, Any]
    kriptografik_guvenli_mi: bool
    uyarilar: List[str]
    tarih: str


# ==============================================================================
# 1. MATEMATİKSEL ENTROPİ VE İSTATİSTİK HESAPLAYICI (ENTROPY MATH)
# ==============================================================================

class EntropyMath:
    """
    Shannon Entropisi, Min-Entropi, Ki-Kare ve NIST SP 800-22 Monobit testlerini
    saf Python standart kütüphanesiyle hesaplayan matematik motoru.
    """

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """
        Girdi bayt dizisinin Shannon Entropisini hesaplar: H(X) = -sum(p_i * log2(p_i))
        Maksimum teorik değer 1 bayt için 8.0 bit/bayttır.
        """
        if not data:
            return 0.0
        n = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def min_entropy(data: bytes) -> float:
        """
        En kötü durum entropisini (Min-Entropy) hesaplar: H_inf = -log2(max(p_i))
        """
        if not data:
            return 0.0
        n = len(data)
        counts = Counter(data)
        max_p = max(counts.values()) / n
        return round(-math.log2(max_p), 4)

    @staticmethod
    def chi_square(data: bytes) -> float:
        """
        Ki-Kare uygunluk testi hesaplar: sum((O_i - E)^2 / E)
        E = N / 256 (Tekdüze/Uniform dağılım varsayımı)
        """
        if not data:
            return 0.0
        n = len(data)
        expected = n / 256.0
        counts = Counter(data)
        chi_sq = 0.0
        for b in range(256):
            observed = counts.get(b, 0)
            chi_sq += ((observed - expected) ** 2) / expected
        return round(chi_sq, 2)

    @staticmethod
    def monobit_frequency_test(data: bytes) -> Tuple[float, float]:
        """
        NIST SP 800-22 Monobit (Frekans) testi.
        0 ve 1 bitlerinin oranını ve p-değerini hesaplar.
        """
        if not data:
            return 0.0, 0.0
        total_bits = len(data) * 8
        ones_count = 0
        for b in data:
            ones_count += bin(b).count("1")

        one_ratio = ones_count / total_bits
        # S_n = |ones - zeros|
        zeros_count = total_bits - ones_count
        s_obs = abs(ones_count - zeros_count) / math.sqrt(total_bits)

        # p-değeri hesabı: erfc(s_obs / sqrt(2))
        p_val = math.erfc(s_obs / math.sqrt(2))
        return round(one_ratio, 4), round(p_val, 4)

    @classmethod
    def calculate_all(cls, data: bytes) -> EntropyMetrics:
        """Tüm istatistiksel metrikleri tek geçişte hesaplar."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeValidationError("Veri 'bytes' veya 'bytearray' tipinde olmalıdır (CWE-843)")

        shannon = cls.shannon_entropy(data)
        min_ent = cls.min_entropy(data)
        chi_sq = cls.chi_square(data)
        ratio, p_val = cls.monobit_frequency_test(data)
        unique_bytes = len(set(data))

        if shannon >= 7.5 and p_val >= 0.01:
            rating = "YÜKSEK (Kriptografik Güvenli)"
        elif shannon >= 6.0:
            rating = "ORTA (Kriptografi İçin Yetersiz)"
        else:
            rating = "DÜŞÜK (Tahmin Edilebilir / Güvensiz)"

        return EntropyMetrics(
            shannon_entropi=shannon,
            min_entropi=min_ent,
            chi_kare=chi_sq,
            monobit_oran=ratio,
            monobit_p_degeri=p_val,
            bayt_sayisi=len(data),
            tekil_bayt_sayisi=unique_bytes,
            degerlendirme=rating
        )


# ==============================================================================
# 2. KRİPTOGRAFİK GÜVENLİ RASTGELE SAYI ÜRETECİ (CSPRNG GENERATOR)
# ==============================================================================

class CSPRNGGenerator:
    """
    Kriptografik olarak güvenli anahtar, tuz (salt), IV ve token üreteci.
    İşletim sistemi entropi havuzunu (os.urandom / secrets) kullanır.
    Zayıf PRNG (random modülü) ve tahmin edilebilir tohumları engeller.
    """

    MIN_KEY_BITS = 64  # Brute-force önleme tavanı (CWE-334)

    @classmethod
    def generate_key(cls, bits: int = 256) -> bytes:
        """Kriptografik anahtar üretir. En az 64-bit zorunludur."""
        if not isinstance(bits, int):
            raise TypeValidationError("Bit uzunluğu tamsayı olmalıdır")
        if bits < cls.MIN_KEY_BITS:
            raise SmallEntropySpaceError(
                f"Kriptografik anahtar alanı en az {cls.MIN_KEY_BITS} bit olmalıdır! ({bits} bit yetersiz - CWE-334)"
            )
        byte_len = bits // 8
        return secrets.token_bytes(byte_len)

    @classmethod
    def generate_token(cls, length_bytes: int = 32) -> str:
        """Kriptografik güvenli onaltılık (hex) oturum/API token'ı üretir."""
        if not isinstance(length_bytes, int):
            raise TypeValidationError("Uzunluk tamsayı olmalıdır")
        if length_bytes <= 0:
            raise TypeValidationError("Token uzunluğu pozitif olmalıdır (CWE-1284)")
        if length_bytes < 8:
            raise SmallEntropySpaceError("Token en az 8 bayt (64 bit) olmalıdır (CWE-334)")
        return secrets.token_hex(length_bytes)

    @classmethod
    def generate_nonce(cls, length_bytes: int = 12) -> bytes:
        """AEAD/GCM için 96-bit (12 bayt) güvenli nonce üretir."""
        if length_bytes < 12:
            raise SmallEntropySpaceError("Nonce en az 12 bayt olmalıdır")
        return os.urandom(length_bytes)

    @classmethod
    def inspect_generator(cls, engine_name: str, seed_type: Optional[str] = None) -> None:
        """Üreteç mimarisini statik olarak denetler; zayıf PRNG ve tohumları yakalar."""
        if not isinstance(engine_name, str):
            raise TypeValidationError("Üreteç adı 'str' olmalıdır")
        if "\x00" in engine_name:
            raise NullByteInjectionError("Üreteç adında Null-Byte tespit edildi (CWE-158)")

        # Zayıf PRNG kontrolü (CWE-338)
        if "random" in engine_name.lower() or "mt19937" in engine_name.lower() or "mersenne" in engine_name.lower():
            raise WeakPRNGDetectedError(
                f"Zayıf PRNG tespit edildi: '{engine_name}'. Kriptografide Mersenne Twister kullanılamaz! (CWE-338)"
            )

        # Tahmin edilebilir tohum kontrolü (CWE-337)
        if seed_type in ("SYSTEM_TIMESTAMP", "TIMESTAMP", "TIME", "PID"):
            raise PredictableSeedError(
                f"Tahmin edilebilir tohum tespit edildi: '{seed_type}'. Zaman damgası tohum olarak kullanılamaz! (CWE-337)"
            )


# ==============================================================================
# 3. ENTROPİ VE RASTGELELİK DENETÇİSİ (ENTROPY AUDITOR)
# ==============================================================================

class EntropyAuditor:
    """
    Hedef veri dizgisi veya dosyanın rastgeleliğini denetleyen kurumsal motor.
    """

    MAX_BUFFER_BYTES = 1_000_000  # 1 MB DoS koruma tavanı

    def __init__(self, min_pass_shannon: float = 7.0):
        self.min_pass_shannon = min_pass_shannon

    def audit_bytes(
        self,
        data: bytes,
        target_name: str = "inline_bytes",
        strict_mode: bool = False
    ) -> EntropyAuditReport:
        """Bayt akışının entropisini ve güvenlik seviyesini denetler."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeValidationError("Denetlenecek veri 'bytes' olmalıdır (CWE-843)")

        if len(data) == 0:
            raise InsufficientEntropyError("Boş veri dizisi denetlenemez (Entropi = 0.0 - CWE-20/CWE-331)")

        if len(data) > self.MAX_BUFFER_BYTES:
            raise PayloadLimitExceededError(
                f"Veri boyutu 1 MB güvenlik tavanını aştı: {len(data)} bayt (CWE-400)"
            )

        metrics = EntropyMath.calculate_all(data)
        warnings: List[str] = []

        # Shannon entropi eşik kontrolü (CWE-331)
        if metrics.shannon_entropi < self.min_pass_shannon:
            warnings.append(
                f"CWE-331: Shannon entropisi ({metrics.shannon_entropi} bit/bayt) kabul eşiğinin ({self.min_pass_shannon}) altında!"
            )

        # Monobit p-değeri kontrolü (NIST standardı p >= 0.01)
        if metrics.monobit_p_degeri < 0.01:
            warnings.append(
                f"CWE-330: Monobit frekans testi başarısız (p={metrics.monobit_p_degeri} < 0.01). Bit dağılımı tekdüze değil!"
            )

        is_secure = len(warnings) == 0

        if strict_mode and not is_secure:
            raise InsufficientEntropyError(f"Entropi denetimi başarısız: {'; '.join(warnings)}")

        return EntropyAuditReport(
            hedef_adi=target_name,
            metrikler=asdict(metrics),
            kriptografik_guvenli_mi=is_secure,
            uyarilar=warnings,
            tarih=time.strftime("%Y-%m-%d %H:%M:%S")
        )

    def audit_file(
        self,
        filepath: str,
        strict_mode: bool = False
    ) -> EntropyAuditReport:
        """Diskteki bir dosyanın entropisini okuyup denetler."""
        if not isinstance(filepath, str):
            raise TypeValidationError("Dosya yolu 'str' olmalıdır")
        if "\x00" in filepath:
            raise NullByteInjectionError("Dosya yolunda Null-Byte tespit edildi (CWE-158)")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")

        file_size = os.path.getsize(filepath)
        if file_size > self.MAX_BUFFER_BYTES:
            raise PayloadLimitExceededError(f"Dosya boyutu 1 MB sınırını aştı: {file_size} bayt")

        with open(filepath, "rb") as f:
            content = f.read()

        return self.audit_bytes(content, target_name=os.path.basename(filepath), strict_mode=strict_mode)
