# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 106: Asimetrik Kriptografi, RSA ve Güvenli Dolgu (OAEP) Motoru.
Bu modül, asimetrik şifrelemenin matematiksel temellerini (Miller-Rabin, Genişletilmiş Öklid),
FIPS 186-4 ve PKCS#1 v2.2 (RFC 8017) uyumlu RSA anahtar üretimini, RSA-OAEP güvenli dolgu
mekanizmasını ve düz (textbook) RSA zafiyetlerinin pratik analizlerini içerir.
"""

# Kriptografik rastgele sayı üretimi için standart kütüphane
import secrets
# Matematiksel işlemler ve logaritma hesaplamaları için
import math
# Güvenli özet (SHA-256) fonksiyonları için
import hashlib
# Sabit zamanlı (constant-time) karşılaştırmalar için hmac kütüphanesi
import hmac
# JSON formatında anahtar serileştirme için
import json
# Veri yapılarını düzenlemek için dataclass
from dataclasses import dataclass
# Tip belirteçleri için typing modülü
from typing import Tuple, Optional, Dict, Any, List


# --- ÖZEL HATA SINIFLARI (CWE EŞLEMELERİ) ---

class AsymmetricCryptoError(Exception):
    """Asimetrik kriptografi işlemlerinde temel hata sınıfı."""
    pass


class WeakKeySizeError(AsymmetricCryptoError):
    """CWE-326: Yetersiz veya zayıf anahtar boyutu hatası (< 1024 / 2048 bit)."""
    pass


class InvalidExponentError(AsymmetricCryptoError):
    """CWE-327: Geçersiz veya güvensiz genel/özel üs hatası."""
    pass


class CompositeNumberError(AsymmetricCryptoError):
    """Asal sayı beklenirken bileşik sayı sunulduğunda fırlatılan hata."""
    pass


class MalformedKeyError(AsymmetricCryptoError):
    """CWE-20: Bozuk, eksik veya biçimsiz anahtar verisi hatası."""
    pass


class MessageTooLargeError(AsymmetricCryptoError):
    """CWE-780: Mesaj boyutunun modül kapasitesini veya dolgu sınırını aşması hatası."""
    pass


class OAEPPaddingError(AsymmetricCryptoError):
    """CWE-780: RSA-OAEP dolgu doğrulamasının tahrifat veya yanlış anahtar sebebiyle başarısız olması."""
    pass


class TextbookRSAMalleabilityDetected(AsymmetricCryptoError):
    """CWE-327: Düz (dolgu uygulanmamış) RSA'da çarpımsal homomorfik manipülasyon tespiti."""
    pass


class CommonModulusExploitVulnerability(AsymmetricCryptoError):
    """CWE-327: Ortak modül kullanımı sebebiyle mesajın kırılması durumu tespiti."""
    pass


# --- MATEMATİKSEL VE KRİPTOGRAFİK İLKELER ---

def is_probable_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin olasılıksal asallık testi (FIPS 186-4 standartlarına uygun).
    n sayısının asal olup olmadığını k tur boyunca test eder (hata payı <= 4^(-k)).
    """
    # 2'den küçük sayılar asal olamaz
    if n < 2:
        return False
    # 2 ve 3 asal sayılardır
    if n in (2, 3):
        return True
    # 2'den büyük çift sayılar asal değildir
    if n % 2 == 0:
        return False

    # n - 1 = 2^s * d formunda çarpanlarına ayrılır (d tek sayıdır)
    d = n - 1
    # s değişkeni başlangıçta sıfırlanır
    s = 0
    # d çift olduğu sürece 2'ye bölünür
    while d % 2 == 0:
        d //= 2
        s += 1

    # k tur boyunca bağımsız rastgele tanık (witness) tabanlar seçilir
    for _ in range(k):
        # [2, n-2] aralığında kriptografik rastgele bir taban 'a' seçilir
        a = secrets.randbelow(n - 4) + 2
        # x = a^d mod n hesaplanır
        x = pow(a, d, n)
        # x 1 veya n - 1 ise bu tur için asallık olasılığı devam eder
        if x == 1 or x == n - 1:
            continue

        # s - 1 kez kare alma döngüsü koşturulur
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            # x n - 1 değerine ulaşırsa döngüden çıkılır
            if x == n - 1:
                composite = False
                break

        # Eğer x n-1 olamadıysa sayı kesinlikle bileşiktir (asal değildir)
        if composite:
            return False

    # Tüm turları geçen sayı yüksek olasılıkla asaldır
    return True


def generate_prime(bits: int) -> int:
    """
    Belirtilen bit uzunluğunda kriptografik olarak güvenli bir asal sayı üretir.
    En yüksek (MSB) ve en düşük (LSB) bitleri 1 yapılarak bit boyutu ve teklik garanti edilir.
    """
    # Asgari bit boyutu güvenliği denetlenir
    if bits < 16:
        raise WeakKeySizeError("Asal sayı boyutu en az 16 bit olmalıdır.")

    while True:
        # Kriptografik rastgele bit dizisi üretilir
        candidate = secrets.randbits(bits)
        # En yüksek biti 1 yapılarak istenen bit uzunluğunda kalması sağlanır
        candidate |= (1 << (bits - 1))
        # En düşük bit 1 yapılarak sayının tek olması güvenceye alınır
        candidate |= 1

        # Miller-Rabin asallık testi koşturulur
        if is_probable_prime(candidate):
            return candidate


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Genişletilmiş Öklid Algoritması (Extended Euclidean Algorithm).
    a*x + b*y = gcd(a, b) denklemini çözer.
    Dönen değer: (gcd, x, y)
    """
    # Başlangıç katsayıları ayarlanır
    if a == 0:
        return b, 0, 1

    # Özyinelemeli (veya yinelemeli) Öklid adımı yürütülür
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    # Geriye doğru katsayılar güncellenir
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def modular_inverse(e: int, phi: int) -> int:
    """
    Modüler ters hesaplama: d = e^(-1) mod phi.
    e * d ≡ 1 (mod phi) denklemini çözer.
    """
    # Genişletilmiş Öklid algoritması çağrılır
    gcd_val, x, _ = extended_gcd(e, phi)
    # Eğer e ile phi aralarında asal değilse modüler ters bulunamaz
    if gcd_val != 1:
        raise InvalidExponentError(f"Genel üs ({e}) ile phi aralarında asal değildir (gcd={gcd_val}).")
    # x negatif çıkabilir, phi modülünde pozitif karşılığı alınır
    return (x % phi + phi) % phi


# --- MASK GENERATION FUNCTION (MGF1 - RFC 8017 / PKCS#1 v2.2) ---

def mgf1(seed: bytes, mask_len: int, hash_func=hashlib.sha256) -> bytes:
    """
    PKCS#1 v2.2 uyumlu MGF1 Maske Üretim Fonksiyonu.
    Girdi tohumundan (seed) istenen uzunlukta maskeleme baytı türetir.
    """
    # Seçilen özet fonksiyonunun çıktı boyutu alınır (SHA-256 için 32 bayt)
    h_len = hash_func().digest_size
    # Maske tamponu başlatılır
    mask = bytearray()
    # Gerekli yineleme sayısı hesaplanır (tavan bölme)
    counter_limit = math.ceil(mask_len / h_len)

    # Sayaç 0'dan limite kadar artırılarak özetler birbirine eklenir
    for counter in range(counter_limit):
        # Sayaç 4 baytlık büyük sonlu (big-endian) formata çevrilir
        c_bytes = counter.to_bytes(4, byteorder="big")
        # tohum ve sayaç birleştirilerek özeti hesaplanır
        digest = hash_func(seed + c_bytes).digest()
        # Üretilen özet maskeye eklenir
        mask.extend(digest)

    # İstenen tam mask_len uzunluğuna kırpılarak döndürülür
    return bytes(mask[:mask_len])


# --- RSA-OAEP GÜVENLİ DOLGU ENKODİNG VE DEKODİNG ---

def oaep_encode(message: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha256) -> bytes:
    """
    RSA-OAEP Dolgulama Fonksiyonu (RFC 8017 Section 7.1.1).
    k: Modül bayt uzunluğu (örneğin 2048 bit için 256 bayt).
    label: İsteğe bağlı protokol bağlam etiketi.
    """
    # Özet bayt uzunluğu (SHA-256 için 32)
    h_len = hash_func().digest_size
    # Mesajın maksimum izin verilen uzunluğu hesaplanır
    max_msg_len = k - 2 * h_len - 2
    # Mesaj boyutu sınır kontrolü yapılır (CWE-780)
    if len(message) > max_msg_len:
        raise MessageTooLargeError(
            f"Mesaj boyutu ({len(message)} bayt) OAEP limitini ({max_msg_len} bayt) aşıyor."
        )

    # Etiketin hash özeti hesaplanır (lHash)
    l_hash = hash_func(label).digest()
    # Sıfır dolgu baytları (PS) uzunluğu hesaplanır
    ps_len = k - len(message) - 2 * h_len - 2
    # PS sıfır baytları oluşturulur
    ps = b"\x00" * ps_len
    # Veri Bloku (DB) = lHash || PS || 0x01 || M formatında inşa edilir
    db = l_hash + ps + b"\x01" + message

    # h_len boyutunda kriptografik rastgele tohum (seed) üretilir
    seed = secrets.token_bytes(h_len)
    # DB için maske türetilir
    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    # maskedDB = DB xor dbMask hesaplanır
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # seed için maske türetilir
    seed_mask = mgf1(masked_db, h_len, hash_func)
    # maskedSeed = seed xor seedMask hesaplanır
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    # Nihai Enkapsüle Mesaj (EM) = 0x00 || maskedSeed || maskedDB oluşturulur
    em = b"\x00" + masked_seed + masked_db
    return em


def oaep_decode(em: bytes, k: int, label: bytes = b"", hash_func=hashlib.sha256) -> bytes:
    """
    RSA-OAEP Dolgu Çözme Fonksiyonu (RFC 8017 Section 7.1.2).
    Zamanlama analizini (CWE-208) önlemek için sabit zamanlı doğrulama kullanılır.
    """
    # Özet boyutu
    h_len = hash_func().digest_size
    # EM uzunluğu modül boyutu ile birebir eşleşmelidir
    if len(em) != k:
        raise OAEPPaddingError("Şifreli blok uzunluğu modül boyutuyla uyuşmuyor.")

    # İlk bayt kesinlikle 0x00 olmalıdır
    first_byte = em[0]
    # maskedSeed ayrıştırılır
    masked_seed = em[1:1 + h_len]
    # maskedDB ayrıştırılır
    masked_db = em[1 + h_len:]

    # seedMask türetilir
    seed_mask = mgf1(masked_db, h_len, hash_func)
    # Orijinal tohum (seed) maskeden kurtarılır
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    # dbMask türetilir
    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    # DB maskeden kurtarılır
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # lHash doğrulaması için etiketin özeti hesaplanır
    expected_l_hash = hash_func(label).digest()
    # Çözülen DB içindeki lHash ayrıştırılır
    extracted_l_hash = db[:h_len]

    # Sabit zamanlı lHash karşılaştırması yapılır (CWE-208)
    hash_match = hmac.compare_digest(expected_l_hash, extracted_l_hash)

    # 0x01 ayraç baytı ve sıfır dolgular taranır
    db_payload = db[h_len:]
    one_index = -1
    bad_ps = False

    # Sabit zamanlı arama döngüsü
    for idx, byte in enumerate(db_payload):
        if byte == 0x01 and one_index == -1:
            one_index = idx
        elif byte != 0x00 and one_index == -1:
            bad_ps = True

    # Herhangi bir dolgu veya format hatasında genel OAEP hatası fırlatılır
    if first_byte != 0x00 or not hash_match or one_index == -1 or bad_ps:
        raise OAEPPaddingError("OAEP dolgu doğrulama hatası: Tahrif edilmiş veri veya geçersiz anahtar.")

    # Ayracın ardındaki orijinal mesaj çıkarılır
    original_message = db_payload[one_index + 1:]
    return original_message


# --- RSA ANAHTAR NESNELERİ VE MOTORU ---

@dataclass
class RSAPublicKey:
    """RSA Genel Anahtar Yapısı (e, n)."""
    n: int
    e: int
    bit_length: int

    def encrypt_raw(self, message_int: int) -> int:
        """Düz (Textbook) RSA Şifrelemesi: c = m^e mod n (GÜVENSİZDİR - CWE-327)."""
        if message_int >= self.n:
            raise MessageTooLargeError("Mesaj tam sayısı modül n değerinden büyük veya eşit olamaz.")
        return pow(message_int, self.e, self.n)

    def encrypt_oaep(self, message: bytes, label: bytes = b"") -> bytes:
        """Güvenli RSA-OAEP Şifrelemesi (PKCS#1 v2.2 Standardı)."""
        # Modülün bayt uzunluğu hesaplanır
        k = (self.bit_length + 7) // 8
        # Mesaj OAEP şeması ile dolgulanır
        em = oaep_encode(message, k, label)
        # Dolgulanmış EM baytları büyük tam sayıya çevrilir
        m_int = int.from_bytes(em, byteorder="big")
        # c = m^e mod n şifrelemesi yapılır
        c_int = pow(m_int, self.e, self.n)
        # Şifreli tam sayı tam k baytlık bayt dizisine dönüştürülür
        return c_int.to_bytes(k, byteorder="big")

    def to_dict(self) -> Dict[str, Any]:
        """Anahtar parametrelerini sözlük olarak dışa aktarır."""
        return {
            "type": "RSA_PUBLIC_KEY",
            "bit_length": self.bit_length,
            "e": self.e,
            "n_hex": hex(self.n)[2:]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RSAPublicKey":
        """Sözlükten genel anahtar nesnesi inşa eder."""
        if "n_hex" not in data or "e" not in data:
            raise MalformedKeyError("Genel anahtar sözlüğünde zorunlu alanlar (n_hex, e) eksik.")
        n = int(data["n_hex"], 16)
        e = int(data["e"])
        bit_length = data.get("bit_length", n.bit_length())
        return cls(n=n, e=e, bit_length=bit_length)


@dataclass
class RSAPrivateKey:
    """RSA Özel Anahtar Yapısı (d, n, p, q)."""
    n: int
    e: int
    d: int
    bit_length: int
    p: Optional[int] = None
    q: Optional[int] = None

    def decrypt_raw(self, cipher_int: int) -> int:
        """Düz (Textbook) RSA Şifre Çözümü: m = c^d mod n."""
        if cipher_int >= self.n:
            raise MessageTooLargeError("Şifreli metin modül n değerinden büyük veya eşit olamaz.")
        return pow(cipher_int, self.d, self.n)

    def decrypt_oaep(self, ciphertext: bytes, label: bytes = b"") -> bytes:
        """Güvenli RSA-OAEP Şifre Çözümü."""
        # Modülün bayt uzunluğu
        k = (self.bit_length + 7) // 8
        if len(ciphertext) != k:
            raise OAEPPaddingError("Şifreli metin bayt uzunluğu anahtar boyutuyla eşleşmiyor.")
        # Şifreli baytlar tam sayıya dönüştürülür
        c_int = int.from_bytes(ciphertext, byteorder="big")
        # m = c^d mod n çözümü hesaplanır
        m_int = pow(c_int, self.d, self.n)
        # Çözülen tam sayı k baytlık EM dizisine çevrilir
        em = m_int.to_bytes(k, byteorder="big")
        # OAEP dolgu çözme ve doğrulama işlemi yürütülür
        return oaep_decode(em, k, label)

    def get_public_key(self) -> RSAPublicKey:
        """İlgili genel anahtarı türetir."""
        return RSAPublicKey(n=self.n, e=self.e, bit_length=self.bit_length)

    def to_dict(self) -> Dict[str, Any]:
        """Özel anahtar parametrelerini sözlük olarak dışa aktarır."""
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
        """Sözlükten özel anahtar nesnesi üretir."""
        if "n_hex" not in data or "d_hex" not in data or "e" not in data:
            raise MalformedKeyError("Özel anahtar sözlüğünde n_hex, d_hex veya e eksik.")
        n = int(data["n_hex"], 16)
        d = int(data["d_hex"], 16)
        e = int(data["e"])
        bit_length = data.get("bit_length", n.bit_length())
        p = int(data["p_hex"], 16) if "p_hex" in data else None
        q = int(data["q_hex"], 16) if "q_hex" in data else None
        return cls(n=n, e=e, d=d, bit_length=bit_length, p=p, q=q)


class AsymmetricCryptoEngine:
    """Asimetrik Kriptografi ve RSA Yönetim Motoru."""

    DEFAULT_PUBLIC_EXPONENT = 65537  # F4 Fermat asalı (FIPS 186-4 standardı)
    MINIMUM_SECURE_BITS = 1024       # Asgari kabul edilen bit uzunluğu (testler için)
    RECOMMENDED_BITS = 2048          # Üretim için önerilen bit uzunluğu

    @classmethod
    def generate_keypair(cls, bits: int = 1024, public_exponent: int = DEFAULT_PUBLIC_EXPONENT) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        """
        FIPS 186-4 standardına uygun RSA Anahtar Çifti Üretimi.
        """
        # Zayıf anahtar boyutu kontrolü (CWE-326)
        if bits < 512:
            raise WeakKeySizeError(f"Anahtar boyutu ({bits} bit) kabul edilemez derecede zayıftır.")

        # Genel üs çift veya 1'e eşit/küçükse hata fırlatılır
        if public_exponent % 2 == 0 or public_exponent <= 1:
            raise InvalidExponentError("Genel üs (e) tek sayı ve 1'den büyük olmalıdır.")

        half_bits = bits // 2

        while True:
            # Bağımsız iki büyük asal sayı (p ve q) üretilir
            p = generate_prime(half_bits)
            q = generate_prime(half_bits)

            # p ve q birbirine eşit olmamalıdır
            if p == q:
                continue

            # Modül n hesaplanır
            n = p * q
            # Bit uzunluğunun hedeflenen boyutta kaldığı teyit edilir
            if n.bit_length() != bits:
                continue

            # Euler Totient fonksiyonu: phi(n) = (p - 1) * (q - 1)
            phi = (p - 1) * (q - 1)

            # e ile phi aralarında asal olmalıdır: gcd(e, phi) == 1
            if math.gcd(public_exponent, phi) != 1:
                continue

            # Özel üs hesaplanır: d = e^(-1) mod phi
            d = modular_inverse(public_exponent, phi)

            # Başarılı anahtar çifti oluşturulur ve döndürülür
            pub_key = RSAPublicKey(n=n, e=public_exponent, bit_length=bits)
            priv_key = RSAPrivateKey(n=n, e=public_exponent, d=d, bit_length=bits, p=p, q=q)
            return pub_key, priv_key

    @staticmethod
    def demonstrate_textbook_rsa_malleability(pub_key: RSAPublicKey, priv_key: RSAPrivateKey, m1: int, m2: int) -> Dict[str, Any]:
        """
        Düz (Textbook) RSA Çarpımsal Homomorfizm ve Şekillendirilebilirlik (Malleability) Gösterimi (CWE-327).
        c1 = m1^e mod n, c2 = m2^e mod n -> c_tampered = c1 * c2 mod n.
        Decrypt(c_tampered) = m1 * m2 mod n!
        """
        c1 = pub_key.encrypt_raw(m1)
        c2 = pub_key.encrypt_raw(m2)
        # Saldırgan şifreli metinleri çarparak yeni bir şifreli metin elde eder
        c_tampered = (c1 * c2) % pub_key.n
        # Kurban şifreyi çözdüğünde mesajların çarpımını elde eder
        decrypted_tampered = priv_key.decrypt_raw(c_tampered)
        expected_product = (m1 * m2) % pub_key.n

        if decrypted_tampered == expected_product:
            raise TextbookRSAMalleabilityDetected(
                f"Textbook RSA manipülasyonu başarılı! Şifreli metin çarpımı doğrudan "
                f"düz metin çarpımına ({decrypted_tampered}) dönüştü. Dolgu (OAEP) zorunludur!"
            )

        return {"c1": c1, "c2": c2, "c_tampered": c_tampered, "decrypted": decrypted_tampered}

    @staticmethod
    def demonstrate_small_exponent_vulnerability(pub_key: RSAPublicKey, message_int: int) -> Dict[str, Any]:
        """
        Küçük Genel Üs (e=3) ve Düz RSA Küp Kök Açığı (CWE-327).
        Eğer m^3 < n ise, c = m^3 olur ve doğrudan tam sayı küp kökü alınarak özel anahtarsız çözülür!
        """
        if pub_key.e != 3:
            raise InvalidExponentError("Bu gösterim için e=3 gereklidir.")

        c = pub_key.encrypt_raw(message_int)
        # Eğer m^3 modül n'i aşmadıysa modüler indirgeme gerçekleşmemiştir
        if pow(message_int, 3) < pub_key.n:
            # Doğrudan tam sayı küp kökü alınır
            recovered_m = round(c ** (1 / 3))
            return {
                "vulnerable": True,
                "ciphertext": c,
                "recovered_message": recovered_m,
                "original_message": message_int,
                "success": recovered_m == message_int
            }
        return {"vulnerable": False, "ciphertext": c}

    @staticmethod
    def demonstrate_common_modulus_attack(pub1: RSAPublicKey, pub2: RSAPublicKey, c1: int, c2: int) -> int:
        """
        Ortak Modül Saldırısı (Common Modulus Attack - CWE-327).
        İki kullanıcı aynı n modülünü farklı üslerle (e1, e2) paylaşıyorsa ve gcd(e1, e2) == 1 ise;
        Aynı m mesajı şifrelendiğinde, saldırgan r*e1 + s*e2 = 1 katsayılarıyla m'i kurtarabilir!
        """
        if pub1.n != pub2.n:
            raise AsymmetricCryptoError("Ortak modül saldırısı için her iki anahtarın n modülü aynı olmalıdır.")

        n = pub1.n
        e1 = pub1.e
        e2 = pub2.e

        # Genişletilmiş Öklid ile r*e1 + s*e2 = 1 hesaplanır
        gcd_val, r, s = extended_gcd(e1, e2)
        if gcd_val != 1:
            raise InvalidExponentError("e1 ve e2 aralarında asal olmalıdır.")

        # Negatif üsler için modüler ters kullanılır
        if r < 0:
            c1_inv = modular_inverse(c1, n)
            part1 = pow(c1_inv, -r, n)
        else:
            part1 = pow(c1, r, n)

        if s < 0:
            c2_inv = modular_inverse(c2, n)
            part2 = pow(c2_inv, -s, n)
        else:
            part2 = pow(c2, s, n)

        recovered_m = (part1 * part2) % n
        return recovered_m
