# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 108: X.509 ve Sertifika Zinciri Doğrulama Motoru (X.509 Chain Engine).
Bu modül; X.509 v3 sertifika veri modelini, ASN.1/PEM yapılarını, 3 kademeli PKI
(Root CA -> Intermediate CA -> Leaf) güven hiyerarşisini, RFC 5280 yol doğrulama kurallarını,
BasicConstraints (CA:TRUE/FALSE), KeyUsage, SAN alan adı eşleme (RFC 6125), süre denetimi
ve sertifika iptal (CRL/OCSP) kontrollerini saf Python ile sıfırdan yönetir.
"""

# Kriptografik rastgele veri ve sayı üretimi
import secrets
# Matematiksel fonksiyonlar ve tamsayı logaritmaları
import math
# Kriptografik özetleme fonksiyonları (SHA-256)
import hashlib
# Sabit zamanlı (constant-time) güvenli karşılaştırmalar
import hmac
# JSON formatında serileştirme
import json
# Zaman ve tarih denetimleri
from datetime import datetime, timezone, timedelta
# Yapılandırılmış veri sınıfları
from dataclasses import dataclass, field
# Tip belirteçleri
from typing import Tuple, Optional, Dict, Any, List, Set


# --- ÖZEL HATA SINIFLARI (CWE EŞLEMELERİ) ---

class X509SecurityError(Exception):
    """X.509 sertifika ve zincir işlemlerinde temel güvenlik hatası."""
    pass


class UntrustedRootCAError(X509SecurityError):
    """CWE-295: Sertifika zincirinin güvenilen kök deposunda (trust store) bitmemesi hatası."""
    pass


class CertificateExpiredError(X509SecurityError):
    """CWE-298: Sertifikanın geçerlilik süresinin (NotAfter) dolmuş olması hatası."""
    pass


class CertificateNotYetValidError(X509SecurityError):
    """CWE-298: Sertifikanın henüz geçerlilik tarihine (NotBefore) ulaşmamış olması hatası."""
    pass


class CertificateSignatureInvalidError(X509SecurityError):
    """CWE-295: Sertifikanın yetkili CA tarafından imzalanmadığı veya imzasının tahrif edildiği hatası."""
    pass


class HostnameMismatchError(X509SecurityError):
    """CWE-297: Sertifikadaki CN ve SAN alanlarının talep edilen alan adı ile uyuşmaması hatası."""
    pass


class NonCACertificateUsedAsCAError(X509SecurityError):
    """CWE-295: BasicConstraints is_ca=False olan bir uç sertifikanın yetkisiz CA gibi davranması hatası."""
    pass


class PathLengthExceededError(X509SecurityError):
    """CWE-295: BasicConstraints pathLenConstraint izin verilen zincir derinliğinin aşılması hatası."""
    pass


class RevokedCertificateError(X509SecurityError):
    """CWE-295: Sertifikanın iptal listesinde (CRL / OCSP) yer alması hatası."""
    pass


class MalformedCertificateError(X509SecurityError):
    """CWE-20: Sertifika verisinin eksik, bozuk veya geçersiz yapıda olması hatası."""
    pass


# --- MATEMATİKSEL VE KRİPTOGRAFİK TEMELLER ---

def is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin olasılıksal asallık testi."""
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
    """Belirtilen bit uzunluğunda güvenli rastgele asal sayı üretir."""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        if is_probable_prime(candidate):
            return candidate


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Genişletilmiş Öklid algoritması."""
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
        raise X509SecurityError("Modüler ters bulunamadı.")
    return (x % phi + phi) % phi


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


# --- X.509 VERİ YAPILARI (RFC 5280 STANDARDI) ---

@dataclass
class X509DistinguishedName:
    """X.509 Kimlik Bilgisi (Distinguished Name - DN)."""
    common_name: str
    organization: str
    country: str

    def to_string(self) -> str:
        return f"CN={self.common_name}, O={self.organization}, C={self.country}"

    def to_dict(self) -> Dict[str, str]:
        return {
            "CN": self.common_name,
            "O": self.organization,
            "C": self.country
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "X509DistinguishedName":
        return cls(
            common_name=data.get("CN", "Unknown"),
            organization=data.get("O", "Unknown"),
            country=data.get("C", "TR")
        )

    def matches(self, other: "X509DistinguishedName") -> bool:
        return (
            self.common_name == other.common_name and
            self.organization == other.organization and
            self.country == other.country
        )


@dataclass
class X509Validity:
    """Sertifika Geçerlilik Aralığı (NotBefore / NotAfter)."""
    not_before: str  # ISO 8601 UTC
    not_after: str   # ISO 8601 UTC

    def is_valid_at(self, check_time: datetime) -> Tuple[bool, Optional[str]]:
        """Verilen tarihte sertifikanın geçerli olup olmadığını denetler."""
        dt_before = datetime.fromisoformat(self.not_before.replace("Z", "+00:00"))
        dt_after = datetime.fromisoformat(self.not_after.replace("Z", "+00:00"))

        if check_time < dt_before:
            return False, "NOT_YET_VALID"
        if check_time > dt_after:
            return False, "EXPIRED"
        return True, None


@dataclass
class X509BasicConstraints:
    """Temel Kısıtlamalar Uzantısı (RFC 5280 Section 4.2.1.9)."""
    is_ca: bool = False
    path_len_constraint: Optional[int] = None


@dataclass
class X509Certificate:
    """X.509 v3 Sertifika Modeli."""
    serial_number: int
    issuer: X509DistinguishedName
    subject: X509DistinguishedName
    validity: X509Validity
    public_key: RSAPublicKey
    basic_constraints: X509BasicConstraints
    key_usage: List[str] = field(default_factory=list)
    subject_alt_names: List[str] = field(default_factory=list)
    signature_algorithm: str = "sha256WithRSAEncryption"
    signature_hex: Optional[str] = None
    version: int = 3

    # SHA-256 için standart PKCS#1 v1.5 ASN.1 öneki
    ASN1_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

    def get_tbs_dict(self) -> Dict[str, Any]:
        """Sertifikanın İmzalanacak Gövdesini (TBS - To-Be-Signed) sözlük olarak döner."""
        return {
            "version": self.version,
            "serial_number": hex(self.serial_number),
            "signature_algorithm": self.signature_algorithm,
            "issuer": self.issuer.to_dict(),
            "validity": {
                "not_before": self.validity.not_before,
                "not_after": self.validity.not_after
            },
            "subject": self.subject.to_dict(),
            "public_key": self.public_key.to_dict(),
            "extensions": {
                "basic_constraints": {
                    "is_ca": self.basic_constraints.is_ca,
                    "path_len_constraint": self.basic_constraints.path_len_constraint
                },
                "key_usage": self.key_usage,
                "subject_alt_names": self.subject_alt_names
            }
        }

    def get_tbs_bytes(self) -> bytes:
        """Deterministik kanonik bayt çıktısı üretir."""
        canonical_json = json.dumps(self.get_tbs_dict(), sort_keys=True, separators=(",", ":"))
        return canonical_json.encode("utf-8")

    def sign(self, issuer_priv_key: RSAPrivateKey) -> None:
        """Sertifika gövdesini veren makamın (Issuer) özel anahtarıyla imzalar."""
        tbs_bytes = self.get_tbs_bytes()
        tbs_hash = hashlib.sha256(tbs_bytes).digest()

        # PKCS#1 v1.5 dolgulaması
        k = (issuer_priv_key.bit_length + 7) // 8
        t = self.ASN1_SHA256_PREFIX + t_hash if hasattr(self, "t_hash") else self.ASN1_SHA256_PREFIX + tbs_hash
        ps_len = k - len(t) - 3
        em = b"\x00\x01" + (b"\xFF" * ps_len) + b"\x00" + t

        m_int = int.from_bytes(em, byteorder="big")
        sig_int = pow(m_int, issuer_priv_key.d, issuer_priv_key.n)
        sig_bytes = sig_int.to_bytes(k, byteorder="big")
        self.signature_hex = sig_bytes.hex()

    def verify_signature(self, issuer_pub_key: RSAPublicKey) -> bool:
        """Sertifikanın imzasını veren makamın (Issuer) genel anahtarıyla doğrular."""
        if not self.signature_hex:
            return False

        sig_bytes = bytes.fromhex(self.signature_hex)
        k = (issuer_pub_key.bit_length + 7) // 8
        if len(sig_bytes) != k:
            return False

        sig_int = int.from_bytes(sig_bytes, byteorder="big")
        if sig_int >= issuer_pub_key.n:
            return False

        recovered_em_int = pow(sig_int, issuer_pub_key.e, issuer_pub_key.n)
        recovered_em = recovered_em_int.to_bytes(k, byteorder="big")

        tbs_bytes = self.get_tbs_bytes()
        tbs_hash = hashlib.sha256(tbs_bytes).digest()
        t = self.ASN1_SHA256_PREFIX + tbs_hash
        ps_len = k - len(t) - 3
        expected_em = b"\x00\x01" + (b"\xFF" * ps_len) + b"\x00" + t

        # Sabit zamanlı karşılaştırma (CWE-208)
        return hmac.compare_digest(recovered_em, expected_em)

    def is_self_signed(self) -> bool:
        """Kendinden imzalı (Self-Signed / Root CA) olup olmadığını kontrol eder."""
        return self.issuer.matches(self.subject)

    def matches_hostname(self, hostname: str) -> bool:
        """
        RFC 6125 kurallarına göre alan adı eşleştirmesi yapar (SAN ve CN denetimi).
        Joker karakter (*.domain.com) desteği içerir.
        """
        check_names = list(self.subject_alt_names)
        if not check_names and self.subject.common_name:
            check_names.append(self.subject.common_name)

        target = hostname.lower().strip(".")

        for name in check_names:
            candidate = name.lower().strip(".")
            if candidate == target:
                return True
            # Joker (wildcard) karakter eşleme: *.bank.com -> secure.bank.com
            if candidate.startswith("*."):
                suffix = candidate[2:]
                target_parts = target.split(".")
                suffix_parts = suffix.split(".")
                # Sadece tek seviyeli alt alan adı jokerle eşleşebilir
                if len(target_parts) == len(suffix_parts) + 1:
                    if target.endswith("." + suffix):
                        return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Sertifikayı sözlük olarak serileştirir."""
        data = self.get_tbs_dict()
        data["signature_hex"] = self.signature_hex
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "X509Certificate":
        """Sözlükten sertifika nesnesi oluşturur."""
        try:
            val_data = data["validity"]
            ext_data = data.get("extensions", {})
            bc_data = ext_data.get("basic_constraints", {})

            cert = cls(
                serial_number=int(data["serial_number"], 16) if isinstance(data["serial_number"], str) else int(data["serial_number"]),
                issuer=X509DistinguishedName.from_dict(data["issuer"]),
                subject=X509DistinguishedName.from_dict(data["subject"]),
                validity=X509Validity(
                    not_before=val_data["not_before"],
                    not_after=val_data["not_after"]
                ),
                public_key=RSAPublicKey.from_dict(data["public_key"]),
                basic_constraints=X509BasicConstraints(
                    is_ca=bc_data.get("is_ca", False),
                    path_len_constraint=bc_data.get("path_len_constraint")
                ),
                key_usage=ext_data.get("key_usage", []),
                subject_alt_names=ext_data.get("subject_alt_names", []),
                signature_algorithm=data.get("signature_algorithm", "sha256WithRSAEncryption"),
                signature_hex=data.get("signature_hex"),
                version=data.get("version", 3)
            )
            return cert
        except Exception as ex:
            raise MalformedCertificateError(f"Bozuk sertifika verisi: {str(ex)}")

    def to_pem(self) -> str:
        """PEM formatında okunabilir sertifika dökümü."""
        json_str = json.dumps(self.to_dict(), indent=2)
        return f"-----BEGIN CERTIFICATE-----\n{json_str}\n-----END CERTIFICATE-----"


# --- PKI MİMARİSİ VE ZİNCİR DOĞRULAYICI (RFC 5280) ---

class PKIBuilder:
    """Kök CA, Ara CA ve Uç Sertifikaları Üreten PKI İnşa Edici."""

    @staticmethod
    def generate_rsa_key(bits: int = 1024) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        """Güvenli RSA anahtarı üretir."""
        half = bits // 2
        p = generate_prime(half)
        q = generate_prime(half)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while math.gcd(e, phi) != 1:
            p = generate_prime(half)
            q = generate_prime(half)
            n = p * q
            phi = (p - 1) * (q - 1)
        d = modular_inverse(e, phi)
        pub = RSAPublicKey(n=n, e=e, bit_length=bits)
        priv = RSAPrivateKey(n=n, e=e, d=d, bit_length=bits, p=p, q=q)
        return pub, priv

    @classmethod
    def create_root_ca(cls, cn: str = "Siber Guvenlik Global Root CA", bits: int = 1024, days_valid: int = 3650) -> Tuple[X509Certificate, RSAPrivateKey]:
        """Kendinden imzalı Kök Sertifika Otoritesi (Root CA) oluşturur."""
        pub, priv = cls.generate_rsa_key(bits)
        dn = X509DistinguishedName(common_name=cn, organization="Siber Guvenlik Baskanligi", country="TR")
        now = datetime.now(timezone.utc)
        val = X509Validity(
            not_before=now.isoformat(),
            not_after=(now + timedelta(days=days_valid)).isoformat()
        )
        cert = X509Certificate(
            serial_number=secrets.randbits(64),
            issuer=dn,
            subject=dn,
            validity=val,
            public_key=pub,
            basic_constraints=X509BasicConstraints(is_ca=True, path_len_constraint=2),
            key_usage=["keyCertSign", "cRLSign"]
        )
        cert.sign(priv)
        return cert, priv

    @classmethod
    def create_intermediate_ca(cls, parent_ca: X509Certificate, parent_priv: RSAPrivateKey, cn: str = "Siber Guvenlik Ara CA", bits: int = 1024, days_valid: int = 1825) -> Tuple[X509Certificate, RSAPrivateKey]:
        """Kök CA tarafından imzalanan Ara Sertifika Otoritesi (Intermediate CA) oluşturur."""
        if not parent_ca.basic_constraints.is_ca:
            raise NonCACertificateUsedAsCAError("Üst sertifika bir CA değildir!")
        if "keyCertSign" not in parent_ca.key_usage:
            raise X509SecurityError("Üst sertifikanın keyCertSign yetkisi bulunmuyor!")

        pub, priv = cls.generate_rsa_key(bits)
        dn = X509DistinguishedName(common_name=cn, organization="Siber Guvenlik Baskanligi", country="TR")
        now = datetime.now(timezone.utc)
        val = X509Validity(
            not_before=now.isoformat(),
            not_after=(now + timedelta(days=days_valid)).isoformat()
        )
        cert = X509Certificate(
            serial_number=secrets.randbits(64),
            issuer=parent_ca.subject,
            subject=dn,
            validity=val,
            public_key=pub,
            basic_constraints=X509BasicConstraints(is_ca=True, path_len_constraint=0),
            key_usage=["keyCertSign", "cRLSign", "digitalSignature"]
        )
        cert.sign(parent_priv)
        return cert, priv

    @classmethod
    def create_leaf_certificate(cls, issuer_ca: X509Certificate, issuer_priv: RSAPrivateKey, domain: str, san_list: Optional[List[str]] = None, bits: int = 1024, days_valid: int = 365) -> Tuple[X509Certificate, RSAPrivateKey]:
        """Ara CA tarafından imzalanan Uç Sunucu (Leaf) sertifikası üretir."""
        if not issuer_ca.basic_constraints.is_ca:
            raise NonCACertificateUsedAsCAError("Sertifika veren makam bir CA değildir (is_ca=False)!")
        if "keyCertSign" not in issuer_ca.key_usage:
            raise X509SecurityError("Sertifika veren makamın keyCertSign yetkisi yoktur!")

        pub, priv = cls.generate_rsa_key(bits)
        dn = X509DistinguishedName(common_name=domain, organization="Musteri Kurum", country="TR")
        now = datetime.now(timezone.utc)
        val = X509Validity(
            not_before=now.isoformat(),
            not_after=(now + timedelta(days=days_valid)).isoformat()
        )
        sans = san_list if san_list is not None else [domain]
        cert = X509Certificate(
            serial_number=secrets.randbits(64),
            issuer=issuer_ca.subject,
            subject=dn,
            validity=val,
            public_key=pub,
            basic_constraints=X509BasicConstraints(is_ca=False, path_len_constraint=None),
            key_usage=["digitalSignature", "keyEncipherment"],
            subject_alt_names=sans
        )
        cert.sign(issuer_priv)
        return cert, priv


class X509ChainValidator:
    """RFC 5280 Sertifika Güven Zinciri Doğrulayıcı (Path Validation)."""

    @classmethod
    def validate_chain(
        cls,
        leaf: X509Certificate,
        intermediates: List[X509Certificate],
        trust_store: List[X509Certificate],
        target_domain: Optional[str] = None,
        check_time: Optional[datetime] = None,
        revoked_serials: Optional[Set[int]] = None
    ) -> Dict[str, Any]:
        """
        Sertifika zincirini köke kadar uçtan uca doğrular.
        1. Alan adı doğrulaması (SAN / CN).
        2. Süre doğrulaması (NotBefore, NotAfter).
        3. İptal listesi (CRL) denetimi.
        4. Hiyerarşik imza ve BasicConstraints denetimi.
        5. Güvenilen kök (Trust Anchor) eşleştirmesi.
        """
        now = check_time if check_time is not None else datetime.now(timezone.utc)
        revoked = revoked_serials if revoked_serials is not None else set()

        # 1. Alan Adı Eşleme Kontrolü (CWE-297)
        if target_domain:
            if not leaf.matches_hostname(target_domain):
                raise HostnameMismatchError(
                    f"Alan Adı Uyuşmazlığı (CWE-297): Sertifika '{target_domain}' "
                    f"için geçerli değil. SAN: {leaf.subject_alt_names}, CN: {leaf.subject.common_name}"
                )

        # 2. Uç Sertifika Süre Kontrolü (CWE-298)
        valid_date, date_reason = leaf.validity.is_valid_at(now)
        if not valid_date:
            if date_reason == "EXPIRED":
                raise CertificateExpiredError("Uç sertifikanın geçerlilik süresi dolmuştur (CWE-298).")
            else:
                raise CertificateNotYetValidError("Uç sertifika henüz geçerlilik tarihine ulaşmamıştır (CWE-298).")

        # 3. İptal Kontrolü
        if leaf.serial_number in revoked:
            raise RevokedCertificateError(f"Sertifika (Seri No: {hex(leaf.serial_number)}) iptal edilmiştir (CWE-295).")

        # 4. Zincir Basamaklarının İnşası ve Doğrulanması
        current_cert = leaf
        visited_chain: List[str] = [current_cert.subject.common_name]
        path_length = 0

        while True:
            # Kendinden imzalı bir kök sertifikaya ulaşıldı mı?
            if current_cert.is_self_signed():
                # Güvenilen kök deposunda mevcut mu?
                is_trusted = False
                for root in trust_store:
                    if root.issuer.matches(current_cert.issuer) and root.public_key.n == current_cert.public_key.n:
                        # Kökün kendi imzası doğrulanır
                        if not current_cert.verify_signature(root.public_key):
                            raise CertificateSignatureInvalidError("Kök sertifika imza doğrulaması başarısız.")
                        is_trusted = True
                        break

                if not is_trusted:
                    raise UntrustedRootCAError(
                        f"Güvensiz Kök Otorite (CWE-295): '{current_cert.subject.common_name}' "
                        f"güvenilen kök deposunda (trust store) bulunamadı!"
                    )
                # Başarılı kök terminal noktası
                break

            # Veren makamı (Issuer) ara sertifikalarda veya güven deposunda bul
            issuer_cert = None
            for candidate in intermediates + trust_store:
                if candidate.subject.matches(current_cert.issuer):
                    issuer_cert = candidate
                    break

            if not issuer_cert:
                raise UntrustedRootCAError(
                    f"Eksik Zincir: '{current_cert.subject.common_name}' sertifikasını veren "
                    f"'{current_cert.issuer.common_name}' makamı zincirde veya depoda bulunamadı."
                )

            # BasicConstraints Kontrolü: İmzayı atan makam CA olmalıdır! (CWE-295)
            if not issuer_cert.basic_constraints.is_ca:
                raise NonCACertificateUsedAsCAError(
                    f"Yetkisiz CA Davranışı (CWE-295): '{issuer_cert.subject.common_name}' "
                    f"BasicConstraints is_ca=False olmasına rağmen alt sertifika imzalamıştır!"
                )

            # KeyUsage Kontrolü: keyCertSign yetkisi bulunmalıdır
            if "keyCertSign" not in issuer_cert.key_usage:
                raise X509SecurityError(f"'{issuer_cert.subject.common_name}' sertifikasında keyCertSign yetkisi yok!")

            # PathLengthConstraint Kontrolü
            if issuer_cert.basic_constraints.path_len_constraint is not None:
                if path_length > issuer_cert.basic_constraints.path_len_constraint:
                    raise PathLengthExceededError(
                        f"Zincir Derinliği Aşıldı (CWE-295): Maksimum izin verilen derinlik "
                        f"{issuer_cert.basic_constraints.path_len_constraint}, mevcut: {path_length}."
                    )

            # İmzayı Verenin Genel Anahtarıyla Doğrula (CWE-295)
            if not current_cert.verify_signature(issuer_cert.public_key):
                raise CertificateSignatureInvalidError(
                    f"Geçersiz İmza (CWE-295): '{current_cert.subject.common_name}' sertifikası "
                    f"'{issuer_cert.subject.common_name}' tarafından doğrulanmadı."
                )

            # Veren Makamın Süre Kontrolü
            ca_valid, ca_reason = issuer_cert.validity.is_valid_at(now)
            if not ca_valid:
                if ca_reason == "EXPIRED":
                    raise CertificateExpiredError(f"CA '{issuer_cert.subject.common_name}' süresi dolmuştur.")
                else:
                    raise CertificateNotYetValidError(f"CA '{issuer_cert.subject.common_name}' henüz geçerli değildir.")

            # Veren Makam İptal Kontrolü
            if issuer_cert.serial_number in revoked:
                raise RevokedCertificateError(f"CA '{issuer_cert.subject.common_name}' iptal edilmiştir.")

            # Zincirde bir üst basamağa geç
            current_cert = issuer_cert
            visited_chain.append(current_cert.subject.common_name)
            path_length += 1

        return {
            "status": "VALID",
            "leaf_domain": leaf.subject.common_name,
            "target_domain": target_domain,
            "chain_length": len(visited_chain),
            "validated_chain": visited_chain,
            "root_trust_anchor": current_cert.subject.common_name
        }
