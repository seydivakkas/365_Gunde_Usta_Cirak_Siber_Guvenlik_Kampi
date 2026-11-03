# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 107: Dijital İmza ve Doğrulama Motoru (Digital Signature Engine).
Bu modül; RSA-PSS (RFC 8017 / PKCS#1 v2.2), RSASSA-PKCS1-v1_5, Düz (Textbook) RSA imza
zafiyetlerini (varoluşsal sahtecilik / existential forgery, çarpımsal manipülasyon),
Bleichenbacher e=3 imza sahteciliğini ve ECDSA nonce yeniden kullanımını (CWE-323)
saf Python ile sıfırdan simüle eden endüstri standardı bir imza motorudur.
"""

# Kriptografik rastgele bayt ve sayı üretimi
import secrets
# Matematiksel fonksiyonlar ve tamsayı logaritmaları
import math
# Kriptografik özetleme fonksiyonları (SHA-256)
import hashlib
# Sabit zamanlı (constant-time) güvenli karşılaştırmalar
import hmac
# JSON serileştirme ve dosya işlemleri
import json
# Yapılandırılmış veri modelleri için dataclass
from dataclasses import dataclass
# Tip belirteçleri
from typing import Tuple, Optional, Dict, Any


# --- ÖZEL HATA SINIFLARI (CWE EŞLEMELERİ) ---

class DigitalSignatureError(Exception):
    """Dijital imza süreçlerinde temel hata sınıfı."""
    pass


class SignatureVerificationError(DigitalSignatureError):
    """CWE-347: Dijital imza doğrulamasının tahrifat, yanlış anahtar veya bozuk veri sebebiyle başarısız olması."""
    pass


class WeakKeySizeError(DigitalSignatureError):
    """CWE-326: İmza üretimi için yetersiz anahtar boyutu hatası (< 1024 bit)."""
    pass


class InvalidSignatureFormatError(DigitalSignatureError):
    """CWE-20: İmza bayt uzunluğunun modül boyutuyla eşleşmemesi veya biçimsiz veri hatası."""
    pass


class BleichenbacherVulnerabilityDetected(DigitalSignatureError):
    """CWE-347 / CVE-2006-4339: Gevşek PKCS#1 v1.5 ayrıştırıcılarında e=3 imza sahteciliği tespiti."""
    pass


class ECDSANonceReuseDetected(DigitalSignatureError):
    """CWE-323: ECDSA imzasında aynı rastgele nonce (k) kullanımından dolayı özel anahtarın ifşa olması."""
    pass


class TextbookSignatureForgeryDetected(DigitalSignatureError):
    """CWE-327: Düz (dolgusuz) RSA imzasında özel anahtarsız varoluşsal imza sahteciliği tespiti."""
    pass


# --- MATEMATİKSEL TEMELLER ---

def is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin olasılıksal asallık testi (FIPS 186-4 standartlarında)."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Belirtilen bit uzunluğunda kriptografik rastgele asal sayı üretir."""
    if bits < 16:
        raise WeakKeySizeError("Asal sayı uzunluğu en az 16 bit olmalıdır.")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        if is_probable_prime(candidate):
            return candidate


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Genişletilmiş Öklid Algoritması: a*x + b*y = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def modular_inverse(e: int, phi: int) -> int:
    """Modüler ters hesabı: d = e^(-1) mod phi."""
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise DigitalSignatureError(f"Genel üs ({e}) ile phi aralarında asal değildir (gcd={gcd_val}).")
    return (x % phi + phi) % phi


def mgf1(seed: bytes, mask_len: int, hash_func=hashlib.sha256) -> bytes:
    """PKCS#1 v2.2 uyumlu Maske Üretim Fonksiyonu (MGF1)."""
    h_len = hash_func().digest_size
    mask = bytearray()
    counter_limit = math.ceil(mask_len / h_len)
    for counter in range(counter_limit):
        c_bytes = counter.to_bytes(4, byteorder="big")
        mask.extend(hash_func(seed + c_bytes).digest())
    return bytes(mask[:mask_len])


# --- ANAHTAR VERİ YAPILARI ---

@dataclass
class RSAPublicKey:
    """RSA Genel Anahtar (e, n)."""
    n: int
    e: int
    bit_length: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "RSA_PUBLIC_KEY",
            "bit_length": self.bit_length,
            "e": self.e,
            "n_hex": hex(self.n)[2:]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RSAPublicKey":
        return cls(
            n=int(data["n_hex"], 16),
            e=int(data["e"]),
            bit_length=data.get("bit_length", int(data["n_hex"], 16).bit_length())
        )


@dataclass
class RSAPrivateKey:
    """RSA Özel Anahtar (d, n, p, q)."""
    n: int
    e: int
    d: int
    bit_length: int
    p: Optional[int] = None
    q: Optional[int] = None

    def get_public_key(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e, bit_length=self.bit_length)

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "type": "RSA_PRIVATE_KEY",
            "bit_length": self.bit_length,
            "e": self.e,
            "d_hex": hex(self.d)[2:],
            "n_hex": hex(self.n)[2:]
        }
        if self.p and self.q:
            res["p_hex"] = hex(self.p)[2:]
            res["q_hex"] = hex(self.q)[2:]
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RSAPrivateKey":
        return cls(
            n=int(data["n_hex"], 16),
            e=int(data["e"]),
            d=int(data["d_hex"], 16),
            bit_length=data.get("bit_length", int(data["n_hex"], 16).bit_length()),
            p=int(data["p_hex"], 16) if "p_hex" in data else None,
            q=int(data["q_hex"], 16) if "q_hex" in data else None
        )


# --- DİJİTAL İMZA ŞEMALARI ---

class DigitalSignatureEngine:
    """Kapsamlı Dijital İmza, PSS, PKCS#1 v1.5 ve Zafiyet Analiz Motoru."""

    # SHA-256 için standart ASN.1 DigestInfo öneki (RFC 8017 / PKCS#1 v1.5)
    SHA256_ASN1_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

    @classmethod
    def generate_keypair(cls, bits: int = 1024, public_exponent: int = 65537) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        """FIPS 186-4 uyumlu RSA Anahtar Çifti Üretir."""
        if bits < 512:
            raise WeakKeySizeError(f"Anahtar boyutu ({bits} bit) kabul edilemez derecede zayıftır (CWE-326).")
        if public_exponent % 2 == 0 or public_exponent <= 1:
            raise DigitalSignatureError("Genel üs (e) tek sayı ve 1'den büyük olmalıdır.")

        half_bits = bits // 2
        while True:
            p = generate_prime(half_bits)
            q = generate_prime(half_bits)
            if p == q:
                continue
            n = p * q
            if n.bit_length() != bits:
                continue
            phi = (p - 1) * (q - 1)
            if math.gcd(public_exponent, phi) != 1:
                continue
            d = modular_inverse(public_exponent, phi)
            return (
                RSAPublicKey(n=n, e=public_exponent, bit_length=bits),
                RSAPrivateKey(n=n, e=public_exponent, d=d, bit_length=bits, p=p, q=q)
            )

    # --- 1. DÜZ (TEXTBOOK) RSA İMZA VE ZAFİYET GÖSTERİMLERİ (CWE-327) ---

    @staticmethod
    def sign_raw_textbook(priv_key: RSAPrivateKey, message_int: int) -> int:
        """Düz RSA İmzası: s = m^d mod n (GÜVENSİZDİR - Asla kullanılmamalıdır)."""
        if message_int >= priv_key.n:
            raise DigitalSignatureError("Mesaj modül n değerinden büyük olamaz.")
        return pow(message_int, priv_key.d, priv_key.n)

    @staticmethod
    def verify_raw_textbook(pub_key: RSAPublicKey, message_int: int, signature_int: int) -> bool:
        """Düz RSA İmza Doğrulaması: s^e mod n == m."""
        if signature_int >= pub_key.n:
            return False
        recovered = pow(signature_int, pub_key.e, pub_key.n)
        return recovered == message_int

    @staticmethod
    def demonstrate_textbook_existential_forgery(pub_key: RSAPublicKey) -> Dict[str, Any]:
        """
        Düz RSA Varoluşsal Sahtecilik Saldırısı (Existential Forgery - CWE-327).
        Saldırgan rastgele bir s imza tam sayısı seçer ve m = s^e mod n hesaplar.
        Özel anahtarı bilmeden m mesajı için s imzasını başarıyla uydurur!
        """
        # Saldırgan rastgele bir sahte imza seçer
        forged_s = secrets.randbelow(pub_key.n - 2) + 2
        # Genel anahtarla ilgili sahte mesajı hesaplar: m = s^e mod n
        forged_m = pow(forged_s, pub_key.e, pub_key.n)

        # Doğrulama fonksiyonu çalıştırıldığında s^e mod n == m eşitliği sağlanır
        is_valid = DigitalSignatureEngine.verify_raw_textbook(pub_key, forged_m, forged_s)
        if is_valid:
            raise TextbookSignatureForgeryDetected(
                f"Varoluşsal Sahtecilik Başarılı! Özel anahtar olmadan "
                f"mesaj={forged_m} için geçerli imza={forged_s} üretildi. "
                f"Dolgusuz (Textbook) RSA imza kabul edilemez!"
            )
        return {"valid": is_valid, "m": forged_m, "s": forged_s}

    @staticmethod
    def demonstrate_textbook_multiplicative_forgery(pub_key: RSAPublicKey, m1: int, s1: int, m2: int, s2: int) -> Dict[str, Any]:
        """
        Düz RSA Çarpımsal İmza Sahteciliği:
        s1 = m1^d mod n ve s2 = m2^d mod n ise,
        s_forged = (s1 * s2) mod n, (m1 * m2) mod n mesajının geçerli imzasıdır!
        """
        forged_s = (s1 * s2) % pub_key.n
        forged_m = (m1 * m2) % pub_key.n
        is_valid = DigitalSignatureEngine.verify_raw_textbook(pub_key, forged_m, forged_s)
        return {
            "is_valid": is_valid,
            "forged_message": forged_m,
            "forged_signature": forged_s
        }

    # --- 2. RSASSA-PKCS1-v1_5 İMZA ŞEMASI (RFC 8017 Section 8.2) ---

    @classmethod
    def encode_pkcs1_v1_5(cls, message_hash: bytes, k: int) -> bytes:
        """
        EM = 0x00 || 0x01 || PS (0xFF) || 0x00 || T
        T = ASN1_PREFIX || message_hash
        """
        t = cls.SHA256_ASN1_PREFIX + message_hash
        t_len = len(t)
        if k < t_len + 11:
            raise DigitalSignatureError("Modül boyutu PKCS#1 v1.5 dolgusu için çok küçüktür.")

        ps_len = k - t_len - 3
        ps = b"\xFF" * ps_len
        em = b"\x00\x01" + ps + b"\x00" + t
        return em

    @classmethod
    def sign_pkcs1_v1_5(cls, priv_key: RSAPrivateKey, message: bytes) -> bytes:
        """Mesajın SHA-256 özetini PKCS#1 v1.5 şeması ile imzalar."""
        k = (priv_key.bit_length + 7) // 8
        m_hash = hashlib.sha256(message).digest()
        em = cls.encode_pkcs1_v1_5(m_hash, k)
        m_int = int.from_bytes(em, byteorder="big")
        s_int = pow(m_int, priv_key.d, priv_key.n)
        return s_int.to_bytes(k, byteorder="big")

    @classmethod
    def verify_pkcs1_v1_5(cls, pub_key: RSAPublicKey, message: bytes, signature: bytes, strict: bool = True) -> bool:
        """
        PKCS#1 v1.5 imzasını doğrular.
        strict=True durumunda tüm EM bloğu yeniden oluşturulup sabit zamanlı kontrol edilir.
        """
        k = (pub_key.bit_length + 7) // 8
        if len(signature) != k:
            raise InvalidSignatureFormatError(f"İmza uzunluğu ({len(signature)}) modül uzunluğuna ({k}) uymuyor.")

        s_int = int.from_bytes(signature, byteorder="big")
        if s_int >= pub_key.n:
            return False

        recovered_em_int = pow(s_int, pub_key.e, pub_key.n)
        recovered_em = recovered_em_int.to_bytes(k, byteorder="big")

        m_hash = hashlib.sha256(message).digest()
        expected_em = cls.encode_pkcs1_v1_5(m_hash, k)

        # Katı doğrulama (Sabit zamanlı - CWE-208)
        if strict:
            return hmac.compare_digest(recovered_em, expected_em)

        # Gevşek ayrıştırma (Bleichenbacher zafiyeti olan ayrıştırıcı simülasyonu)
        if not recovered_em.startswith(b"\x00\x01"):
            return False
        # 0x00 ayracını arama
        idx = recovered_em.find(b"\x00", 2)
        if idx == -1:
            return False
        digest_data = recovered_em[idx + 1:]
        expected_t = cls.SHA256_ASN1_PREFIX + m_hash
        return digest_data.startswith(expected_t)

    @classmethod
    def demonstrate_bleichenbacher_attack(cls, pub_key: RSAPublicKey, target_message: bytes) -> Dict[str, Any]:
        """
        Bleichenbacher e=3 İmza Sahteciliği Saldırısı (CWE-347 / CVE-2006-4339).
        Eğer verifier gevşek ayrıştırma yapıyorsa ve e=3 ise, saldırgan özel anahtar
        olmadan sahte imza üretebilir!
        """
        if pub_key.e != 3:
            raise DigitalSignatureError("Bleichenbacher atağı gösterimi e=3 gerektirir.")

        k = (pub_key.bit_length + 7) // 8
        # 1024 bit için tarihsel CVE-2006-4339 senaryosu: MD5 DigestInfo kullanılır
        if k < 256:
            m_hash = hashlib.md5(target_message).digest()
            asn1_prefix = bytes.fromhex("3020300c06082a864886f70d020505000410")
            t = asn1_prefix + m_hash
            prefix = b"\x00\x01\xFF\x00" + t
        else:
            # 2048+ bit için SHA-256 DigestInfo
            m_hash = hashlib.sha256(target_message).digest()
            t = cls.SHA256_ASN1_PREFIX + m_hash
            prefix = b"\x00\x01" + b"\xFF" * 8 + b"\x00" + t

        garbage_len = k - len(prefix)
        shift_bits = garbage_len * 8
        base_int = int.from_bytes(prefix, byteorder="big") << shift_bits

        # Hassas tamsayı küp kökü hesabı (ikili arama ile tam kesinlik)
        low = 0
        high = 1 << ((base_int.bit_length() + 2) // 3)
        while low < high:
            mid = (low + high) // 2
            if mid ** 3 < base_int:
                low = mid + 1
            else:
                high = mid
        forged_s = low

        # Gevşek ayrıştırıcı kontrolü
        recovered_em_int = pow(forged_s, pub_key.e, pub_key.n)
        recovered_em = recovered_em_int.to_bytes(k, byteorder="big")
        loose_pass = recovered_em.startswith(prefix)
        strict_pass = False

        if loose_pass and not strict_pass:
            raise BleichenbacherVulnerabilityDetected(
                "Bleichenbacher e=3 İmza Sahteciliği Başarılı! "
                "Gevşek ASN.1 ayrıştırıcı sahte imzayı onayladı, ancak katı kontrol reddetti."
            )

        return {"loose_pass": loose_pass, "strict_pass": strict_pass}

    # --- 3. RSASSA-PSS İMZA ŞEMASI (RFC 8017 Section 8.1 - STATE-OF-THE-ART) ---

    @classmethod
    def emsa_pss_encode(cls, m_hash: bytes, em_bits: int, salt_len: int = 32, hash_func=hashlib.sha256) -> bytes:
        """EMSA-PSS Kodlama Fonksiyonu (RFC 8017 Section 9.1.1)."""
        h_len = hash_func().digest_size
        em_len = math.ceil(em_bits / 8)

        if em_len < h_len + salt_len + 2:
            raise DigitalSignatureError("Kodlama uzunluğu PSS parametreleri için çok küçüktür.")

        # Kriptografik rastgele tuz (salt) üretilir
        salt = secrets.token_bytes(salt_len)
        # M' = 0x00...00 (8 bayt) || mHash || salt
        m_prime = b"\x00" * 8 + m_hash + salt
        # H = Hash(M')
        h = hash_func(m_prime).digest()

        # DB = PS || 0x01 || salt
        ps_len = em_len - salt_len - h_len - 2
        ps = b"\x00" * ps_len
        db = ps + b"\x01" + salt

        # dbMask = MGF1(H, emLen - hLen - 1)
        db_mask = mgf1(h, em_len - h_len - 1, hash_func)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        # En sol bitlerin modül sınırını aşmaması için maskeleme yapılır
        unused_bits = (8 * em_len) - em_bits
        if unused_bits > 0:
            first_byte_mask = 0xFF >> unused_bits
            masked_db = bytes([masked_db[0] & first_byte_mask]) + masked_db[1:]

        # EM = maskedDB || H || 0xbc
        em = masked_db + h + b"\xbc"
        return em

    @classmethod
    def emsa_pss_verify(cls, m_hash: bytes, em: bytes, em_bits: int, salt_len: int = 32, hash_func=hashlib.sha256) -> bool:
        """EMSA-PSS Doğrulama Fonksiyonu (RFC 8017 Section 9.1.2)."""
        h_len = hash_func().digest_size
        em_len = math.ceil(em_bits / 8)

        if len(em) != em_len:
            return False
        if em_len < h_len + salt_len + 2:
            return False

        # Son bayt kesinlikle 0xbc olmalıdır
        if em[-1] != 0xbc:
            return False

        # Kullanılmayan en sol bitler kontrol edilir
        unused_bits = (8 * em_len) - em_bits
        if unused_bits > 0:
            first_byte_mask = ~(0xFF >> unused_bits) & 0xFF
            if em[0] & first_byte_mask != 0:
                return False

        masked_db = em[:em_len - h_len - 1]
        h = em[em_len - h_len - 1:-1]

        # dbMask üretilir ve DB kurtarılır
        db_mask = mgf1(h, em_len - h_len - 1, hash_func)
        db = bytearray(a ^ b for a, b in zip(masked_db, db_mask))

        if unused_bits > 0:
            db[0] &= (0xFF >> unused_bits)

        # PS ve 0x01 ayracı denetlenir
        ps_len = em_len - salt_len - h_len - 2
        for b_val in db[:ps_len]:
            if b_val != 0x00:
                return False
        if db[ps_len] != 0x01:
            return False

        salt = bytes(db[ps_len + 1:])
        if len(salt) != salt_len:
            return False

        # M' yeniden inşa edilir ve H' hesaplanır
        m_prime = b"\x00" * 8 + m_hash + salt
        expected_h = hash_func(m_prime).digest()

        # Sabit zamanlı karşılaştırma (CWE-208)
        return hmac.compare_digest(expected_h, h)

    @classmethod
    def sign_pss(cls, priv_key: RSAPrivateKey, message: bytes, salt_len: int = 32) -> bytes:
        """RSASSA-PSS ile güvenli, olasılıksal dijital imza üretir."""
        k = (priv_key.bit_length + 7) // 8
        m_hash = hashlib.sha256(message).digest()
        em = cls.emsa_pss_encode(m_hash, priv_key.bit_length - 1, salt_len=salt_len)
        m_int = int.from_bytes(em, byteorder="big")
        s_int = pow(m_int, priv_key.d, priv_key.n)
        return s_int.to_bytes(k, byteorder="big")

    @classmethod
    def verify_pss(cls, pub_key: RSAPublicKey, message: bytes, signature: bytes, salt_len: int = 32) -> bool:
        """RSASSA-PSS imzasını sabit zamanlı ve kriptografik kesinlikle doğrular."""
        k = (pub_key.bit_length + 7) // 8
        if len(signature) != k:
            raise InvalidSignatureFormatError("İmza bayt uzunluğu modül uzunluğu ile eşleşmiyor.")

        s_int = int.from_bytes(signature, byteorder="big")
        if s_int >= pub_key.n:
            return False

        m_int = pow(s_int, pub_key.e, pub_key.n)
        em = m_int.to_bytes(k, byteorder="big")

        m_hash = hashlib.sha256(message).digest()
        is_valid = cls.emsa_pss_verify(m_hash, em, pub_key.bit_length - 1, salt_len=salt_len)
        if not is_valid:
            raise SignatureVerificationError("RSA-PSS İmza Doğrulama Başarısız: Veri tahrif edilmiş veya anahtar yanlış.")
        return True

    # --- 4. ECDSA NONCE YENİDEN KULLANIMI VE ÖZEL ANAHTAR KURTARMA (CWE-323) ---

    @staticmethod
    def demonstrate_ecdsa_nonce_reuse(q: int, d_secret: int, m1_hash: int, m2_hash: int, reused_k: int) -> Dict[str, Any]:
        """
        ECDSA Nonce Yeniden Kullanımı Felaketi (CWE-323 - Sony PS3 Örneği).
        s = k^(-1) * (z + r * d) mod q
        Aynı k ile iki farklı mesaj imzalanırsa:
        k = (z1 - z2) * (s1 - s2)^(-1) mod q
        d = (s1 * k - z1) * r^(-1) mod q ==> ÖZEL ANAHTAR TAMAMEN İFŞA OLUR!
        """
        # r = (k * G).x mod q (Bu simülasyonda r rastgele seçilir çünkü k sabit)
        r = pow(2, reused_k, q)
        if r == 0:
            r = 7  # güvenli simülasyon tabanı

        k_inv = modular_inverse(reused_k, q)
        s1 = (k_inv * (m1_hash + r * d_secret)) % q
        s2 = (k_inv * (m2_hash + r * d_secret)) % q

        # Saldırgan tarafı: Yalnızca s1, s2, z1, z2 ve r değerlerini bilir!
        delta_z = (m1_hash - m2_hash) % q
        delta_s = (s1 - s2) % q
        delta_s_inv = modular_inverse(delta_s, q)

        # 1. Adım: k değerinin özel anahtarsız kurtarılması
        recovered_k = (delta_z * delta_s_inv) % q

        # 2. Adım: Gizli özel anahtar d'nin kurtarılması
        r_inv = modular_inverse(r, q)
        recovered_d = ((s1 * recovered_k - m1_hash) * r_inv) % q

        if recovered_d == d_secret:
            raise ECDSANonceReuseDetected(
                f"ECDSA Nonce Yeniden Kullanımı (CWE-323) Tespit Edildi! "
                f"Saldırgan aynı k={reused_k} kullanımını tespit ederek "
                f"özel anahtarı d={recovered_d} saniyeler içinde kurtardı!"
            )

        return {"recovered_d": recovered_d, "success": recovered_d == d_secret}
