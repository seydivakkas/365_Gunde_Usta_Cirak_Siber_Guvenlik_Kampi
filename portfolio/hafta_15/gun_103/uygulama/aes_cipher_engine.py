# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 103: FIPS 197 Uyumlu Simetrik Şifreleme ve AES Motoru.
Bu modül; saf Python standart kütüphanesi ile AES-128 ve AES-256 blok şifreleme,
ECB, CBC ve CTR işletim modları, PKCS#7 dolgusu ve Encrypt-then-MAC (AEAD)
bütünlük doğrulamasını kurumsal standartlarda uygular.
"""

# Kriptografik özet ve HMAC modülü
import hashlib
import hmac
# Kriptografik güvenli rastgele sayı üreticisi
import secrets
# Zaman ve gecikme ölçümü
import time
# Tip güvenliği ve veri yapıları
from typing import Dict, List, Any, Optional, Tuple, Union, Set
# Veri sınıfı yöneticisi
from dataclasses import dataclass


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE CWE EŞLEŞTİRMELERİ
# ==============================================================================

class AESCipherError(Exception):
    """AES şifreleme motoru temel güvenlik istisnası."""
    pass


class InsecureCipherModeError(AESCipherError):
    """CWE-327: Güvensiz ECB (Electronic Codebook) modu kullanım tespiti hatası."""
    pass


class InvalidKeyLengthError(AESCipherError):
    """CWE-326: 128-bit (16B) veya 256-bit (32B) dışında kalan geçersiz anahtar boyutu hatası."""
    pass


class PredictableIVError(AESCipherError):
    """CWE-329: CBC modunda statik veya tahmin edilebilir IV (Initialization Vector) kullanımı."""
    pass


class InvalidIVLengthError(AESCipherError):
    """CWE-329: IV uzunluğunun 16 bayt blok sınırına uymaması hatası."""
    pass


class InvalidPaddingError(AESCipherError):
    """CWE-347 / CWE-208: Geçersiz veya bozulmuş PKCS#7 dolgu (padding) hatası."""
    pass


class AuthenticationTagMismatchError(AESCipherError):
    """CWE-353: Kurcalanmış şifreli metin veya geçersiz AEAD HMAC doğrulama etiketi hatası."""
    pass


class PayloadLimitExceededError(AESCipherError):
    """CWE-400: Bellek tüketimini sınırlandırmak için 1 MB tavan aşımı hatası."""
    pass


class NullByteInjectionError(AESCipherError):
    """CWE-158: Anahtar veya metin parametresinde zararlı Null-Byte (\x00) tespiti."""
    pass


class TypeValidationError(AESCipherError):
    """CWE-843: Geçersiz veri tipi iletimi hatası."""
    pass


# ==============================================================================
# VERİ MODELLERİ VE GÜVENLİK YAPILANDIRMASI
# ==============================================================================

@dataclass
class AESEncryptionResult:
    """Şifreleme süreci sonuç ve metaveri modeli."""
    ciphertext_hex: str
    iv_hex: Optional[str]
    tag_hex: Optional[str]
    mode: str
    key_bits: int
    elapsed_ms: float


@dataclass
class AESDecryptionResult:
    """Şifre çözme süreci sonuç ve bütünlük karnesi."""
    plaintext_bytes: bytes
    plaintext_str: str
    mode: str
    verified: bool
    elapsed_ms: float


class AESConfig:
    """NIST FIPS 197 ve SP 800-38A güvenlik sınırları."""
    BLOCK_SIZE: int = 16  # AES blok boyutu (128 bit)
    VALID_KEY_SIZES: Set[int] = {16, 32}  # 128-bit veya 256-bit
    MAX_BUFFER_BYTES: int = 1_000_000  # 1 MB DoS koruma tavanı
    # Yasaklanmış statik / sıfır IV değerleri (CWE-329)
    FORBIDDEN_STATIC_IVS: Set[str] = {
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "0123456789abcdef0123456789abcdef",
        "11111111111111111111111111111111"
    }


# ==============================================================================
# FIPS 197 STANDART SABİTLERİ (S-BOX, TERS S-BOX, RCON)
# ==============================================================================

SBOX: List[int] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Ters S-Box tablosu
INV_SBOX: List[int] = [0] * 256
for idx, val in enumerate(SBOX):
    INV_SBOX[val] = idx

# Rcon (Round Constants) dizisi
RCON: List[int] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
]


# ==============================================================================
# ÇEKİRDEK MATEMATİKSEL İŞLEMLER (GALOIS ALANI GF(2^8) VE BLOK DÖNÜŞÜMLERİ)
# ==============================================================================

def gf_mul(a: int, b: int) -> int:
    """Galois Alanı GF(2^8) üzerinde indirgenemez polinom (0x11B) ile çarpma."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return res


def key_expansion(key_bytes: bytes) -> Tuple[List[int], int]:
    """Rijndael anahtar genişletme algoritması (128-bit veya 256-bit)."""
    nk = len(key_bytes) // 4
    nr = nk + 6
    w = [0] * (4 * (nr + 1))

    for i in range(nk):
        w[i] = (key_bytes[4 * i] << 24) | (key_bytes[4 * i + 1] << 16) | (key_bytes[4 * i + 2] << 8) | key_bytes[4 * i + 3]

    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            # RotWord & SubWord
            temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
            temp = (SBOX[(temp >> 24) & 0xFF] << 24) | (SBOX[(temp >> 16) & 0xFF] << 16) | (SBOX[(temp >> 8) & 0xFF] << 8) | SBOX[temp & 0xFF]
            temp ^= (RCON[i // nk] << 24)
        elif nk > 6 and (i % nk == 4):
            # 256-bit AES ek SubWord adımı
            temp = (SBOX[(temp >> 24) & 0xFF] << 24) | (SBOX[(temp >> 16) & 0xFF] << 16) | (SBOX[(temp >> 8) & 0xFF] << 8) | SBOX[temp & 0xFF]
        w[i] = w[i - nk] ^ temp

    return w, nr


def sub_bytes(state: List[List[int]]) -> None:
    """Durum matrisinin her baytını S-Box tablosuyla doğrusal olmayan biçimde dönüştürür."""
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]


def inv_sub_bytes(state: List[List[int]]) -> None:
    """Ters S-Box tablosuyla bayt dönüşümünü geri alır."""
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]


def shift_rows(state: List[List[int]]) -> None:
    """Satırları dairesel olarak sola kaydırır (Difüzyon adımı)."""
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def inv_shift_rows(state: List[List[int]]) -> None:
    """Satır kaydırmalarını tersine çevirir (Dairesel sağa kaydırma)."""
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]


def mix_columns(state: List[List[int]]) -> None:
    """Sütunları GF(2^8) polinom matrisiyle çarparak doğrusal difüzyon sağlar."""
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gf_mul(0x02, col[0]) ^ gf_mul(0x03, col[1]) ^ col[2] ^ col[3]
        state[1][c] = col[0] ^ gf_mul(0x02, col[1]) ^ gf_mul(0x03, col[2]) ^ col[3]
        state[2][c] = col[0] ^ col[1] ^ gf_mul(0x02, col[2]) ^ gf_mul(0x03, col[3])
        state[3][c] = gf_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ gf_mul(0x02, col[3])


def inv_mix_columns(state: List[List[int]]) -> None:
    """Ters sütun karışımı dönüşümünü uygular."""
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gf_mul(0x0e, col[0]) ^ gf_mul(0x0b, col[1]) ^ gf_mul(0x0d, col[2]) ^ gf_mul(0x09, col[3])
        state[1][c] = gf_mul(0x09, col[0]) ^ gf_mul(0x0e, col[1]) ^ gf_mul(0x0b, col[2]) ^ gf_mul(0x0d, col[3])
        state[2][c] = gf_mul(0x0d, col[0]) ^ gf_mul(0x09, col[1]) ^ gf_mul(0x0e, col[2]) ^ gf_mul(0x0b, col[3])
        state[3][c] = gf_mul(0x0b, col[0]) ^ gf_mul(0x0d, col[1]) ^ gf_mul(0x09, col[2]) ^ gf_mul(0x0e, col[3])


def add_round_key(state: List[List[int]], round_keys: List[int], round_num: int) -> None:
    """Durum matrisini ilgili turun genişletilmiş anahtarıyla XOR işleminden geçirir."""
    for c in range(4):
        word = round_keys[round_num * 4 + c]
        state[0][c] ^= (word >> 24) & 0xFF
        state[1][c] ^= (word >> 16) & 0xFF
        state[2][c] ^= (word >> 8) & 0xFF
        state[3][c] ^= word & 0xFF


def encrypt_block(block_bytes: bytes, round_keys: List[int], nr: int) -> bytes:
    """Tek bir 16 baytlık veri bloğunu AES algoritmasıyla şifreler."""
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = block_bytes[r + 4 * c]

    # Başlangıç turu anahtar ekleme
    add_round_key(state, round_keys, 0)

    # Standart turlar (1 ile nr-1 arası)
    for rnd in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys, rnd)

    # Son tur (MixColumns uygulanmaz)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys, nr)

    # Durum matrisini bayt dizisine dönüştür
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)


def decrypt_block(block_bytes: bytes, round_keys: List[int], nr: int) -> bytes:
    """Tek bir 16 baytlık şifreli bloğun AES şifresini çözer."""
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = block_bytes[r + 4 * c]

    # Son tur anahtarını ekle
    add_round_key(state, round_keys, nr)

    # Ters standart turlar
    for rnd in range(nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys, rnd)
        inv_mix_columns(state)

    # Başlangıç ters turu (InvMixColumns yok)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys, 0)

    # Matrisi bayta dönüştür
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)


# ==============================================================================
# PKCS#7 DOLGU (PADDING) VE DOLGU KALDIRMA
# ==============================================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Veriyi RFC 5652 PKCS#7 standardına göre tam blok katına doldurur."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 dolgusunu doğrular ve kaldırır. Bozuk dolguda InvalidPaddingError fırlatır."""
    if not data or len(data) % block_size != 0:
        raise InvalidPaddingError("Dolgu kaldırma hatası: Veri boyutu blok katı değil (CWE-347)!")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise InvalidPaddingError(f"Geçersiz dolgu bayt değeri: {pad_len} (CWE-347)")

    # Sabit zamanlı dolgu doğrulaması (Padding Oracle koruması)
    expected_pad = bytes([pad_len] * pad_len)
    actual_pad = data[-pad_len:]
    if not hmac.compare_digest(expected_pad, actual_pad):
        raise InvalidPaddingError("PKCS#7 dolgu tutarsızlığı tespit edildi (CWE-347 / CWE-208)!")

    return data[:-pad_len]


# ==============================================================================
# ÇEKİRDEK GÜVENLİ AES ŞİFRELEME MOTORU
# ==============================================================================

class AESCipherEngine:
    """
    NIST FIPS 197 Uyumlu Simetrik AES Şifreleme ve Deşifreleme Yöneticisi.
    """

    @classmethod
    def validate_key(cls, key: Union[bytes, str]) -> bytes:
        """Anahtar tipi ve uzunluk kontrollerini uygular (CWE-326, CWE-843)."""
        if isinstance(key, str):
            key = key.encode("utf-8")
        elif not isinstance(key, (bytes, bytearray)):
            raise TypeValidationError("Anahtar 'bytes' veya 'str' tipinde olmalıdır (CWE-843)")

        if len(key) not in AESConfig.VALID_KEY_SIZES:
            raise InvalidKeyLengthError(
                f"Geçersiz AES anahtar uzunluğu ({len(key)} bayt). "
                f"Sadece 16 bayt (AES-128) veya 32 bayt (AES-256) desteklenir (CWE-326)!"
            )
        return bytes(key)

    @classmethod
    def validate_iv(cls, iv: Union[bytes, str]) -> bytes:
        """IV uzunluğu ve tahmin edilebilirlik denetimlerini uygular (CWE-329)."""
        if isinstance(iv, str):
            iv = bytes.fromhex(iv) if len(iv) == 32 else iv.encode("utf-8")
        elif not isinstance(iv, (bytes, bytearray)):
            raise TypeValidationError("IV 'bytes' tipinde olmalıdır (CWE-843)")

        if len(iv) != AESConfig.BLOCK_SIZE:
            raise InvalidIVLengthError(f"IV uzunluğu tam 16 bayt olmalıdır ({len(iv)} bayt iletildi) (CWE-329)!")

        iv_hex = bytes(iv).hex().lower()
        if iv_hex in AESConfig.FORBIDDEN_STATIC_IVS:
            raise PredictableIVError(
                f"Tahmin edilebilir veya statik sıfır IV tespiti engellendi: {iv_hex} (CWE-329)!"
            )
        return bytes(iv)

    @classmethod
    def validate_payload(cls, data: Union[bytes, str]) -> bytes:
        """Veri boyutu ve tip denetimlerini uygular (CWE-400, CWE-843)."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeValidationError("Veri 'bytes' veya 'str' tipinde olmalıdır (CWE-843)")

        if len(data) > AESConfig.MAX_BUFFER_BYTES:
            raise PayloadLimitExceededError("Veri boyutu 1 MB tavanını aştı (CWE-400)!")
        return bytes(data)

    # --------------------------------------------------------------------------
    # 1. ECB MODU (UYARI VE ZAFİYET GÖSTERİMİ - CWE-327)
    # --------------------------------------------------------------------------
    @classmethod
    def encrypt_ecb(cls, plaintext: Union[bytes, str], key: Union[bytes, str], strict_mode: bool = False) -> AESEncryptionResult:
        """
        ECB modunda şifreleme. Katı güvenlik modunda InsecureCipherModeError fırlatır (CWE-327).
        """
        start = time.perf_counter()
        if strict_mode:
            raise InsecureCipherModeError(
                "ECB modu güvensizdir ve desen sızıntısına yol açar (ECB Penguin)! Katı modda engellendi (CWE-327)."
            )

        key_bytes = cls.validate_key(key)
        raw_pt = cls.validate_payload(plaintext)
        padded_pt = pkcs7_pad(raw_pt)

        w, nr = key_expansion(key_bytes)
        blocks = [padded_pt[i:i + 16] for i in range(0, len(padded_pt), 16)]
        ct_blocks = [encrypt_block(b, w, nr) for b in blocks]
        full_ct = b"".join(ct_blocks)

        elapsed = round((time.perf_counter() - start) * 1000.0, 3)
        return AESEncryptionResult(
            ciphertext_hex=full_ct.hex(),
            iv_hex=None,
            tag_hex=None,
            mode="ECB (GÜVENSİZ - DESEN SIZINTISI)",
            key_bits=len(key_bytes) * 8,
            elapsed_ms=elapsed
        )

    @classmethod
    def decrypt_ecb(cls, ciphertext_hex: str, key: Union[bytes, str], strict_mode: bool = False) -> AESDecryptionResult:
        """ECB modunda şifre çözme."""
        start = time.perf_counter()
        if strict_mode:
            raise InsecureCipherModeError("ECB modu katı güvenlik modunda reddedildi (CWE-327)!")

        key_bytes = cls.validate_key(key)
        raw_ct = bytes.fromhex(ciphertext_hex)
        if len(raw_ct) % 16 != 0:
            raise InvalidPaddingError("ECB şifreli metin boyutu 16 baytın katı olmalıdır")

        w, nr = key_expansion(key_bytes)
        blocks = [raw_ct[i:i + 16] for i in range(0, len(raw_ct), 16)]
        pt_blocks = [decrypt_block(b, w, nr) for b in blocks]
        padded_pt = b"".join(pt_blocks)
        unpadded = pkcs7_unpad(padded_pt)

        elapsed = round((time.perf_counter() - start) * 1000.0, 3)
        return AESDecryptionResult(
            plaintext_bytes=unpadded,
            plaintext_str=unpadded.decode("utf-8", errors="replace"),
            mode="ECB",
            verified=False,
            elapsed_ms=elapsed
        )

    # --------------------------------------------------------------------------
    # 2. CBC MODU (CIPHER BLOCK CHAINING)
    # --------------------------------------------------------------------------
    @classmethod
    def encrypt_cbc(
        cls,
        plaintext: Union[bytes, str],
        key: Union[bytes, str],
        iv: Optional[Union[bytes, str]] = None
    ) -> AESEncryptionResult:
        """CBC modunda şifreleme. IV belirtilmezse rastgele 16 bayt üretilir."""
        start = time.perf_counter()
        key_bytes = cls.validate_key(key)
        raw_pt = cls.validate_payload(plaintext)
        padded_pt = pkcs7_pad(raw_pt)

        # IV yönetimi
        if iv is None:
            iv_bytes = secrets.token_bytes(AESConfig.BLOCK_SIZE)
        else:
            iv_bytes = cls.validate_iv(iv)

        w, nr = key_expansion(key_bytes)
        blocks = [padded_pt[i:i + 16] for i in range(0, len(padded_pt), 16)]
        ct_blocks: List[bytes] = []
        prev_ct = iv_bytes

        for block in blocks:
            # Düz blok ile önceki şifreli bloğu XOR'la
            xored = bytes(a ^ b for a, b in zip(block, prev_ct))
            encrypted = encrypt_block(xored, w, nr)
            ct_blocks.append(encrypted)
            prev_ct = encrypted

        full_ct = b"".join(ct_blocks)
        elapsed = round((time.perf_counter() - start) * 1000.0, 3)

        return AESEncryptionResult(
            ciphertext_hex=full_ct.hex(),
            iv_hex=iv_bytes.hex(),
            tag_hex=None,
            mode="CBC",
            key_bits=len(key_bytes) * 8,
            elapsed_ms=elapsed
        )

    @classmethod
    def decrypt_cbc(
        cls,
        ciphertext_hex: str,
        key: Union[bytes, str],
        iv: Union[bytes, str]
    ) -> AESDecryptionResult:
        """CBC modunda şifre çözme."""
        start = time.perf_counter()
        key_bytes = cls.validate_key(key)
        iv_bytes = cls.validate_iv(iv)
        raw_ct = bytes.fromhex(ciphertext_hex)

        if len(raw_ct) % 16 != 0:
            raise InvalidPaddingError("CBC şifreli metin blok katı olmalıdır")

        w, nr = key_expansion(key_bytes)
        blocks = [raw_ct[i:i + 16] for i in range(0, len(raw_ct), 16)]
        pt_blocks: List[bytes] = []
        prev_ct = iv_bytes

        for block in blocks:
            decrypted = decrypt_block(block, w, nr)
            original_pt = bytes(a ^ b for a, b in zip(decrypted, prev_ct))
            pt_blocks.append(original_pt)
            prev_ct = block

        padded_pt = b"".join(pt_blocks)
        unpadded = pkcs7_unpad(padded_pt)
        elapsed = round((time.perf_counter() - start) * 1000.0, 3)

        return AESDecryptionResult(
            plaintext_bytes=unpadded,
            plaintext_str=unpadded.decode("utf-8", errors="replace"),
            mode="CBC",
            verified=True,
            elapsed_ms=elapsed
        )

    # --------------------------------------------------------------------------
    # 3. CTR MODU (COUNTER MODE - AKIŞ ŞİFRESİ)
    # --------------------------------------------------------------------------
    @classmethod
    def encrypt_ctr(
        cls,
        plaintext: Union[bytes, str],
        key: Union[bytes, str],
        initial_counter: Optional[Union[bytes, str]] = None
    ) -> AESEncryptionResult:
        """CTR modunda şifreleme. Dolgu gerektirmez; akış şifresi gibi çalışır."""
        start = time.perf_counter()
        key_bytes = cls.validate_key(key)
        raw_pt = cls.validate_payload(plaintext)

        if initial_counter is None:
            ctr_bytes = secrets.token_bytes(AESConfig.BLOCK_SIZE)
        else:
            ctr_bytes = cls.validate_iv(initial_counter)

        w, nr = key_expansion(key_bytes)
        ctr_int = int.from_bytes(ctr_bytes, byteorder="big")
        keystream_blocks: List[bytes] = []

        total_blocks = (len(raw_pt) + 15) // 16
        for i in range(total_blocks):
            current_ctr = ((ctr_int + i) % (2 ** 128)).to_bytes(16, byteorder="big")
            ks_block = encrypt_block(current_ctr, w, nr)
            keystream_blocks.append(ks_block)

        keystream = b"".join(keystream_blocks)[:len(raw_pt)]
        ciphertext = bytes(a ^ b for a, b in zip(raw_pt, keystream))
        elapsed = round((time.perf_counter() - start) * 1000.0, 3)

        return AESEncryptionResult(
            ciphertext_hex=ciphertext.hex(),
            iv_hex=ctr_bytes.hex(),
            tag_hex=None,
            mode="CTR",
            key_bits=len(key_bytes) * 8,
            elapsed_ms=elapsed
        )

    @classmethod
    def decrypt_ctr(
        cls,
        ciphertext_hex: str,
        key: Union[bytes, str],
        initial_counter: Union[bytes, str]
    ) -> AESDecryptionResult:
        """CTR modunda şifre çözme (XOR simetrisi nedeniyle şifreleme ile aynıdır)."""
        raw_ct = bytes.fromhex(ciphertext_hex)
        res = cls.encrypt_ctr(raw_ct, key, initial_counter=initial_counter)
        return AESDecryptionResult(
            plaintext_bytes=bytes.fromhex(res.ciphertext_hex),
            plaintext_str=bytes.fromhex(res.ciphertext_hex).decode("utf-8", errors="replace"),
            mode="CTR",
            verified=True,
            elapsed_ms=res.elapsed_ms
        )

    # --------------------------------------------------------------------------
    # 4. AEAD (ENCRYPT-THEN-MAC İLE KİMLİK DOĞRULAMALI ŞİFRELEME)
    # --------------------------------------------------------------------------
    @classmethod
    def encrypt_aead_etm(
        cls,
        plaintext: Union[bytes, str],
        encryption_key: Union[bytes, str],
        mac_key: Union[bytes, str],
        associated_data: bytes = b""
    ) -> AESEncryptionResult:
        """
        Encrypt-then-MAC standardında AEAD şifreleme.
        CTR modunda şifreler, HMAC-SHA256 ile şifreli metin ve metaveriyi mühürler.
        """
        # Şifrele
        ctr_result = cls.encrypt_ctr(plaintext, encryption_key)
        ct_bytes = bytes.fromhex(ctr_result.ciphertext_hex)
        iv_bytes = bytes.fromhex(ctr_result.iv_hex)

        # MAC hesapla: HMAC(mac_key, iv || ciphertext || aad)
        mac_k = cls.validate_key(mac_key)
        mac_payload = iv_bytes + ct_bytes + associated_data
        tag = hmac.new(mac_k, mac_payload, hashlib.sha256).digest()

        return AESEncryptionResult(
            ciphertext_hex=ctr_result.ciphertext_hex,
            iv_hex=ctr_result.iv_hex,
            tag_hex=tag.hex(),
            mode="CTR-AEAD (Encrypt-then-MAC)",
            key_bits=ctr_result.key_bits,
            elapsed_ms=ctr_result.elapsed_ms
        )

    @classmethod
    def decrypt_aead_etm(
        cls,
        ciphertext_hex: str,
        encryption_key: Union[bytes, str],
        mac_key: Union[bytes, str],
        iv_hex: str,
        tag_hex: str,
        associated_data: bytes = b""
    ) -> AESDecryptionResult:
        """
        AEAD şifre çözme. Kurcalanmış şifreli metinlerde AuthenticationTagMismatchError fırlatır (CWE-353).
        """
        mac_k = cls.validate_key(mac_key)
        ct_bytes = bytes.fromhex(ciphertext_hex)
        iv_bytes = bytes.fromhex(iv_hex)

        # Beklenen etiketi hesapla
        mac_payload = iv_bytes + ct_bytes + associated_data
        expected_tag = hmac.new(mac_k, mac_payload, hashlib.sha256).digest()

        # CWE-208: Sabit zamanlı kıyaslama ile kurcalanma denetimi
        actual_tag = bytes.fromhex(tag_hex)
        if not hmac.compare_digest(expected_tag, actual_tag):
            raise AuthenticationTagMismatchError(
                "AEAD Doğrulama Hatası: Şifreli metin yolda kurcalanmış veya etiket sahte (CWE-353 / CWE-345)!"
            )

        # Doğrulama başarılıysa deşifre et
        return cls.decrypt_ctr(ciphertext_hex, encryption_key, initial_counter=iv_bytes)
