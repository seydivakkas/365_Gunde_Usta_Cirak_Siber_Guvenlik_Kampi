# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 104: AEAD (Authenticated Encryption with Associated Data) ve Nonce Yönetim Motoru.
Bu modül; kurumsal seviyede AEAD şifreleme, durum bilgili Nonce takip önbelleği (CWE-323 engeli),
Two-Time Pad (XOR anahtar akışı iptali) zafiyet analizi ve SIV (Synthetic IV)
deterministik savunma mimarisini saf Python standart kütüphanesi ile uygular.
"""

# Kriptografik özet ve HMAC hesaplama modülü
import hashlib
import hmac
# Kriptografik güvenli rastgele sayı üreticisi
import secrets
# Süre ve gecikme ölçümü
import time
# Tip güvenliği ve veri yapıları
from typing import Dict, List, Any, Optional, Tuple, Union, Set
# Veri sınıfı yöneticisi
from dataclasses import dataclass, field


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE CWE EŞLEŞTİRMELERİ
# ==============================================================================

class AEADEngineError(Exception):
    """AEAD motoru temel güvenlik istisnası."""
    pass


class NonceReuseDetectedError(AEADEngineError):
    """CWE-323: Aynı anahtar ile daha önce kullanılmış bir Nonce'un tekrar kullanılması hatası."""
    pass


class InsecureNonceLengthError(AEADEngineError):
    """CWE-326: Nonce uzunluğunun standart kabul edilen 12 bayt (96 bit) altında olması hatası."""
    pass


class PredictableNonceError(AEADEngineError):
    """CWE-329: Statik, ardışık veya tahmin edilebilir Nonce (IV) kullanımı hatası."""
    pass


class AuthenticationTagMismatchError(AEADEngineError):
    """CWE-353 / CWE-345: Kurcalanmış şifreli metin, sahte etiket veya bozuk AAD hatası."""
    pass


class InvalidKeyLengthError(AEADEngineError):
    """CWE-326: 16 bayt (128-bit) veya 32 bayt (256-bit) dışında kalan anahtar boyutu hatası."""
    pass


class NullByteInjectionError(AEADEngineError):
    """CWE-158: Düz metin veya AAD girdisinde Null-Byte (\x00) tespiti hatası."""
    pass


class PayloadLimitExceededError(AEADEngineError):
    """CWE-400: DoS koruması için 1 MB tavan aşımı hatası."""
    pass


class TypeValidationError(AEADEngineError):
    """CWE-843: Geçersiz veri tipi iletimi hatası."""
    pass


# ==============================================================================
# VERİ MODELLERİ VE GÜVENLİK YAPILANDIRMASI
# ==============================================================================

@dataclass
class AEADResult:
    """AEAD şifreleme süreci sonuç ve metaveri modeli."""
    ciphertext_hex: str
    nonce_hex: str
    tag_hex: str
    aad: str
    is_siv: bool
    elapsed_ms: float


@dataclass
class TwoTimePadAnalysis:
    """Two-Time Pad sızıntısı matematiksel analiz raporu."""
    c1_xor_c2_hex: str
    p1_xor_p2_hex: str
    is_identical_leakage: bool
    crib_drag_match: bool
    aciklama: str


class AEADConfig:
    """NIST SP 800-38D ve RFC 5116 AEAD parametreleri."""
    NONCE_SIZE_BYTES: int = 12  # Standart 96-bit Nonce
    VALID_KEY_SIZES: Set[int] = {16, 32}  # 128-bit veya 256-bit
    MAX_BUFFER_BYTES: int = 1_000_000  # 1 MB DoS koruma sınırı
    # Yasaklanmış statik / sıfır Nonce değerleri (CWE-329)
    FORBIDDEN_STATIC_NONCES: Set[str] = {
        "000000000000000000000000",
        "ffffffffffffffffffffffff",
        "0123456789abcdef01234567",
        "111111111111111111111111"
    }


# ==============================================================================
# BAĞIMSIZ GÜVENLİ AES BLOK ÇEKİRDEĞİ (STANDALONE PURE PYTHON)
# ==============================================================================

# FIPS 197 S-Box tablosu
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

# Rcon sabitleri
RCON: List[int] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]


def _gf_mul(a: int, b: int) -> int:
    """GF(2^8) Galois Alanında matris çarpımı."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return res


def _aes_key_expansion(key_bytes: bytes) -> Tuple[List[int], int]:
    """Rijndael anahtar genişletmesi."""
    nk = len(key_bytes) // 4
    nr = nk + 6
    w = [0] * (4 * (nr + 1))
    for i in range(nk):
        w[i] = (key_bytes[4 * i] << 24) | (key_bytes[4 * i + 1] << 16) | (key_bytes[4 * i + 2] << 8) | key_bytes[4 * i + 3]
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
            temp = (SBOX[(temp >> 24) & 0xFF] << 24) | (SBOX[(temp >> 16) & 0xFF] << 16) | (SBOX[(temp >> 8) & 0xFF] << 8) | SBOX[temp & 0xFF]
            temp ^= (RCON[i // nk] << 24)
        elif nk > 6 and (i % nk == 4):
            temp = (SBOX[(temp >> 24) & 0xFF] << 24) | (SBOX[(temp >> 16) & 0xFF] << 16) | (SBOX[(temp >> 8) & 0xFF] << 8) | SBOX[temp & 0xFF]
        w[i] = w[i - nk] ^ temp
    return w, nr


def _aes_encrypt_block(block: bytes, round_keys: List[int], nr: int) -> bytes:
    """Tek bir 16 baytlık bloğun AES ile şifrelenmesi."""
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    # AddRoundKey 0
    for c in range(4):
        k = round_keys[c]
        state[0][c] ^= (k >> 24) & 0xFF
        state[1][c] ^= (k >> 16) & 0xFF
        state[2][c] ^= (k >> 8) & 0xFF
        state[3][c] ^= k & 0xFF

    for rnd in range(1, nr):
        # SubBytes
        for r in range(4):
            for c in range(4):
                state[r][c] = SBOX[state[r][c]]
        # ShiftRows
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        # MixColumns
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            state[0][c] = _gf_mul(0x02, col[0]) ^ _gf_mul(0x03, col[1]) ^ col[2] ^ col[3]
            state[1][c] = col[0] ^ _gf_mul(0x02, col[1]) ^ _gf_mul(0x03, col[2]) ^ col[3]
            state[2][c] = col[0] ^ col[1] ^ _gf_mul(0x02, col[2]) ^ _gf_mul(0x03, col[3])
            state[3][c] = _gf_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ _gf_mul(0x02, col[3])
        # AddRoundKey
        for c in range(4):
            k = round_keys[rnd * 4 + c]
            state[0][c] ^= (k >> 24) & 0xFF
            state[1][c] ^= (k >> 16) & 0xFF
            state[2][c] ^= (k >> 8) & 0xFF
            state[3][c] ^= k & 0xFF

    # Son Tur
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    for c in range(4):
        k = round_keys[nr * 4 + c]
        state[0][c] ^= (k >> 24) & 0xFF
        state[1][c] ^= (k >> 16) & 0xFF
        state[2][c] ^= (k >> 8) & 0xFF
        state[3][c] ^= k & 0xFF

    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)


# ==============================================================================
# DURUM BİLGİLİ NONCE TAKİP ÖNBELLEĞİ (STATEFUL NONCE TRACKER - CWE-323 ÖNLEME)
# ==============================================================================

class StatefulNonceTracker:
    """
    Aynı (Anahtar, Nonce) çiftinin ikinci kez kullanılmasını engelleyen koruma motoru.
    """

    def __init__(self, max_entries: int = 100_000):
        # Anahtar özeti bazında kullanılan Nonce'ları tutan küme sözlüğü
        self._seen_nonces: Dict[str, Set[str]] = {}
        # Maksimum kayıt tavanı (Bellek sızıntısı önleme)
        self._max_entries = max_entries

    def _get_key_hash(self, key_bytes: bytes) -> str:
        """Anahtarın bellekte açık durmaması için SHA-256 özetini kimlik olarak kullanır."""
        return hashlib.sha256(key_bytes).hexdigest()

    def record_and_verify(self, key_bytes: bytes, nonce_bytes: bytes) -> None:
        """Nonce'un daha önce kullanılıp kullanılmadığını denetler. Tekrarda CWE-323 fırlatır."""
        key_id = self._get_key_hash(key_bytes)
        nonce_hex = nonce_bytes.hex().lower()

        if key_id not in self._seen_nonces:
            self._seen_nonces[key_id] = set()

        # Nonce yeniden kullanımı kontrolü (CWE-323)
        if nonce_hex in self._seen_nonces[key_id]:
            raise NonceReuseDetectedError(
                f"KRİTİK GÜVENLİK İHLALİ: Nonce ({nonce_hex}) bu anahtar ile daha önce kullanıldı! "
                f"Two-Time Pad saldırısına yol açacağından işlem engellendi (CWE-323)!"
            )

        # Önbellek tavanı aşılırsa en eski anahtarı temizle
        if len(self._seen_nonces[key_id]) >= self._max_entries:
            self._seen_nonces[key_id].clear()

        # Yeni Nonce'u kaydet
        self._seen_nonces[key_id].add(nonce_hex)

    def is_nonce_used(self, key_bytes: bytes, nonce_bytes: bytes) -> bool:
        """Belirtilen Nonce'un kayıtlı olup olmadığını sorgular."""
        key_id = self._get_key_hash(key_bytes)
        return nonce_bytes.hex().lower() in self._seen_nonces.get(key_id, set())

    def reset(self) -> None:
        """Önbelleği sıfırlar (Yalnızca testler için)."""
        self._seen_nonces.clear()


# Küresel tekil Nonce takipçisi
GLOBAL_NONCE_TRACKER = StatefulNonceTracker()


# ==============================================================================
# ÇEKİRDEK AEAD MOTORU VE NONCE GÜVENLİK YÖNETİMİ
# ==============================================================================

class AEADNonceEngine:
    """
    AEAD (Authenticated Encryption with Associated Data) ve Nonce Yönetim Yöneticisi.
    """

    @classmethod
    def validate_key(cls, key: Union[bytes, str]) -> bytes:
        """Anahtar tip ve boyut denetimi (CWE-326, CWE-843)."""
        if isinstance(key, str):
            key = key.encode("utf-8")
        elif not isinstance(key, (bytes, bytearray)):
            raise TypeValidationError("Anahtar 'bytes' veya 'str' olmalıdır (CWE-843)")

        if len(key) not in AEADConfig.VALID_KEY_SIZES:
            raise InvalidKeyLengthError(
                f"Geçersiz AEAD anahtar uzunluğu: {len(key)} bayt. Sadece 16 bayt veya 32 bayt desteklenir (CWE-326)!"
            )
        return bytes(key)

    @classmethod
    def validate_nonce(cls, nonce: Union[bytes, str]) -> bytes:
        """Nonce boyut ve tahmin edilebilirlik denetimi (CWE-326, CWE-329)."""
        if isinstance(nonce, str):
            nonce = bytes.fromhex(nonce) if len(nonce) == 24 else nonce.encode("utf-8")
        elif not isinstance(nonce, (bytes, bytearray)):
            raise TypeValidationError("Nonce 'bytes' veya 'str' olmalıdır (CWE-843)")

        if len(nonce) < AEADConfig.NONCE_SIZE_BYTES:
            raise InsecureNonceLengthError(
                f"Nonce uzunluğu en az {AEADConfig.NONCE_SIZE_BYTES} bayt (96 bit) olmalıdır ({len(nonce)} bayt yetersiz - CWE-326)!"
            )

        nonce_hex = bytes(nonce).hex().lower()
        if nonce_hex in AEADConfig.FORBIDDEN_STATIC_NONCES:
            raise PredictableNonceError(
                f"Tahmin edilebilir veya statik sıfır Nonce kullanımı engellendi: {nonce_hex} (CWE-329)!"
            )
        return bytes(nonce)

    @classmethod
    def validate_payload(cls, data: Union[bytes, str], param_name: str = "Veri") -> bytes:
        """Veri boyutu ve zararlı karakter kontrolü (CWE-158, CWE-400, CWE-843)."""
        if isinstance(data, str):
            if "\x00" in data:
                raise NullByteInjectionError(f"{param_name} içinde zararlı Null-Byte tespit edildi (CWE-158)!")
            data = data.encode("utf-8")
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeValidationError(f"{param_name} 'bytes' veya 'str' tipinde olmalıdır (CWE-843)")

        if b"\x00" in data and param_name == "Düz Metin":
            raise NullByteInjectionError("Düz metinde Null-Byte enjeksiyonu tespit edildi (CWE-158)!")

        if len(data) > AEADConfig.MAX_BUFFER_BYTES:
            raise PayloadLimitExceededError(f"{param_name} boyutu 1 MB tavanını aştı (CWE-400)!")

        return bytes(data)

    @classmethod
    def generate_random_nonce(cls) -> bytes:
        """96-bitlik (12 bayt) kriptografik rastgele Nonce üretir."""
        return secrets.token_bytes(AEADConfig.NONCE_SIZE_BYTES)

    @classmethod
    def derive_synthetic_nonce(cls, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """
        SIV (Synthetic IV - RFC 5297) Prensibi:
        Düz metin ve AAD'nin HMAC-SHA256 özetinden 96-bitlik deterministik Nonce türetir.
        Kazara Nonce tekrarını önler (Nonce-Misuse Resistant AEAD).
        """
        h = hmac.new(key, b"SIV_NONCE_DERIVATION" + aad + plaintext, hashlib.sha256).digest()
        return h[:AEADConfig.NONCE_SIZE_BYTES]

    @classmethod
    def _generate_keystream(cls, key: bytes, nonce: bytes, length: int) -> bytes:
        """AES-CTR mantığında Nonce + 32-bit artan sayaç ile anahtar akışı (keystream) üretir."""
        w, nr = _aes_key_expansion(key)
        total_blocks = (length + 15) // 16
        keystream_blocks: List[bytes] = []

        # 96-bit Nonce + 32-bit Başlangıç Sayacı (0)
        nonce_base = nonce[:12]
        for ctr in range(total_blocks):
            counter_block = nonce_base + ctr.to_bytes(4, byteorder="big")
            block_out = _aes_encrypt_block(counter_block, w, nr)
            keystream_blocks.append(block_out)

        return b"".join(keystream_blocks)[:length]

    # --------------------------------------------------------------------------
    # 1. STANDART AEAD ŞİFRELEME (DURUM BİLGİLİ NONCE TAKİBİ İLE)
    # --------------------------------------------------------------------------
    @classmethod
    def encrypt_aead(
        cls,
        plaintext: Union[bytes, str],
        key: Union[bytes, str],
        nonce: Optional[Union[bytes, str]] = None,
        associated_data: Union[bytes, str] = "",
        tracker: Optional[StatefulNonceTracker] = None,
        use_siv: bool = False
    ) -> AEADResult:
        """
        AEAD standardında şifreleme yapar. Nonce belirtilmezse CSPRNG ile üretilir.
        Aynı Nonce'un tekrar kullanılması durumunda NonceReuseDetectedError fırlatır (CWE-323).
        """
        start = time.perf_counter()
        k_bytes = cls.validate_key(key)
        p_bytes = cls.validate_payload(plaintext, "Düz Metin")
        aad_bytes = cls.validate_payload(associated_data, "İlişkili Veri (AAD)")

        active_tracker = tracker if tracker is not None else GLOBAL_NONCE_TRACKER

        if use_siv:
            # SIV Modu: Deterministik türetim
            n_bytes = cls.derive_synthetic_nonce(k_bytes, p_bytes, aad_bytes)
        else:
            if nonce is None:
                n_bytes = cls.generate_random_nonce()
            else:
                n_bytes = cls.validate_nonce(nonce)

            # CWE-323: Nonce tekrarını önleme kontrolü
            active_tracker.record_and_verify(k_bytes, n_bytes)

        # 1. CTR ile anahtar akışı üret ve şifrele
        keystream = cls._generate_keystream(k_bytes, n_bytes, len(p_bytes))
        ciphertext = bytes(a ^ b for a, b in zip(p_bytes, keystream))

        # 2. AEAD Etiketi: HMAC(Key, Nonce || Ciphertext || AAD || Lengths)
        # RFC 5116 benzeri güvenli bağlama formatı
        len_block = len(aad_bytes).to_bytes(8, "big") + len(ciphertext).to_bytes(8, "big")
        mac_data = n_bytes + ciphertext + aad_bytes + len_block
        tag = hmac.new(k_bytes, mac_data, hashlib.sha256).digest()

        elapsed = round((time.perf_counter() - start) * 1000.0, 3)
        return AEADResult(
            ciphertext_hex=ciphertext.hex(),
            nonce_hex=n_bytes.hex(),
            tag_hex=tag.hex(),
            aad=associated_data if isinstance(associated_data, str) else associated_data.hex(),
            is_siv=use_siv,
            elapsed_ms=elapsed
        )

    # --------------------------------------------------------------------------
    # 2. STANDART AEAD ŞİFRE ÇÖZME VE ETİKET DOĞRULAMA
    # --------------------------------------------------------------------------
    @classmethod
    def decrypt_aead(
        cls,
        ciphertext_hex: str,
        key: Union[bytes, str],
        nonce_hex: str,
        tag_hex: str,
        associated_data: Union[bytes, str] = ""
    ) -> Tuple[bytes, str]:
        """
        AEAD şifresini çözer. Şifreli metin, Nonce veya AAD kurcalanmışsa
        AuthenticationTagMismatchError fırlatır (CWE-353 / CWE-345).
        """
        k_bytes = cls.validate_key(key)
        n_bytes = cls.validate_nonce(nonce_hex)
        aad_bytes = cls.validate_payload(associated_data, "İlişkili Veri (AAD)")
        ct_bytes = bytes.fromhex(ciphertext_hex)
        expected_tag = bytes.fromhex(tag_hex)

        # 1. Beklenen etiketi hesapla
        len_block = len(aad_bytes).to_bytes(8, "big") + len(ct_bytes).to_bytes(8, "big")
        mac_data = n_bytes + ct_bytes + aad_bytes + len_block
        computed_tag = hmac.new(k_bytes, mac_data, hashlib.sha256).digest()

        # 2. CWE-208: Sabit zamanlı karşılaştırma
        if not hmac.compare_digest(computed_tag, expected_tag):
            raise AuthenticationTagMismatchError(
                "AEAD Doğrulama Başarısız: Şifreli metin kurcalanmış, AAD uyuşmuyor veya sahte etiket tespit edildi (CWE-353 / CWE-345)!"
            )

        # 3. Doğrulandıysa deşifre et
        keystream = cls._generate_keystream(k_bytes, n_bytes, len(ct_bytes))
        plaintext = bytes(a ^ b for a, b in zip(ct_bytes, keystream))
        plaintext_str = plaintext.decode("utf-8", errors="replace")

        return plaintext, plaintext_str

    # --------------------------------------------------------------------------
    # 3. TWO-TIME PAD ZAFİYET VE SIZINTI SİMÜLASYONU
    # --------------------------------------------------------------------------
    @classmethod
    def simulate_two_time_pad_leakage(
        cls,
        plaintext_1: str,
        plaintext_2: str,
        key: Union[bytes, str],
        reused_nonce: Union[bytes, str]
    ) -> TwoTimePadAnalysis:
        """
        Aynı (Anahtar, Nonce) çifti kullanıldığında C1 ^ C2 = P1 ^ P2 olduğunu
        ve anahtar akışının (keystream) tamamen iptal olduğunu matematiksel olarak kanıtlar.
        """
        k_bytes = cls.validate_key(key)
        n_bytes = cls.validate_nonce(reused_nonce)

        p1_bytes = plaintext_1.encode("utf-8")
        p2_bytes = plaintext_2.encode("utf-8")
        min_len = min(len(p1_bytes), len(p2_bytes))

        # Tekrarlanan Nonce ile iki ayrı şifreli metin üret (Tracker'ı devre dışı bırakarak)
        ks = cls._generate_keystream(k_bytes, n_bytes, min_len)
        c1 = bytes(a ^ b for a, b in zip(p1_bytes[:min_len], ks))
        c2 = bytes(a ^ b for a, b in zip(p2_bytes[:min_len], ks))

        # C1 ^ C2 hesapla
        c1_xor_c2 = bytes(a ^ b for a, b in zip(c1, c2))
        # P1 ^ P2 hesapla
        p1_xor_p2 = bytes(a ^ b for a, b in zip(p1_bytes[:min_len], p2_bytes[:min_len]))

        # İki sonucun özdeş olup olmadığını doğrula (Anahtar Akışı İptali)
        is_identical = (c1_xor_c2 == p1_xor_p2)

        # Crib Dragging Gösterimi:
        # Eğer saldırgan P1 içindeki bir kelimeyi (Örn: "KREDI_KARTI") tahmin ederse (crib),
        # (C1 ^ C2) ^ crib işlemi doğrudan P2'nin o kısmını açığa çıkarır!
        crib = b"KREDI_KARTI"
        crib_drag_result = bytes(a ^ b for a, b in zip(c1_xor_c2[:len(crib)], crib))
        crib_matched = crib_drag_result in p2_bytes

        aciklama = (
            "C1 ^ C2 == P1 ^ P2 matematiksel eşitliği doğrulandı! "
            "Aynı Nonce kullanımı nedeniyle gizli anahtar akışı tamamen yok olmuştur. "
            "Saldırgan anahtarı hiç bilmeden düz metinleri çözebilir."
        )

        return TwoTimePadAnalysis(
            c1_xor_c2_hex=c1_xor_c2.hex(),
            p1_xor_p2_hex=p1_xor_p2.hex(),
            is_identical_leakage=is_identical,
            crib_drag_match=crib_matched,
            aciklama=aciklama
        )
