# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
PKI ve Sertifika Yaşam Döngüsü Motoru (pki_lifecycle_engine.py).

Bu modül; asimetrik anahtar üretiminden başlayarak CSR (PKCS#10) oluşturulması,
mülkiyet ispatı (Proof-of-Possession), CA tarafından sertifika ihracı,
Certificate Transparency (CT Log / RFC 6962), CRL ve OCSP iptal mekanizmaları,
OCSP Stapling, ACME tabanlı otomatik yenileme ve güvenli anahtar rotasyonunu (Crypto-Shredding)
tamamen harici kütüphane bağımlılığı olmadan (Pure Python) simüle eder.
"""

import os
import sys
import json
import time
import math
import hmac
import secrets
import hashlib
import datetime
from typing import Dict, List, Tuple, Optional, Any

# ==============================================================================
# 1. ÖZEL İSTİSNA SINIFLARI (CWE GÜVENLİK KONTROLLERİ)
# ==============================================================================

class PKIError(Exception):
    """Tüm PKI yaşam döngüsü hatalarının temel ata sınıfı."""
    pass

class CSRSignatureVerificationError(PKIError):
    """CWE-347: CSR üzerindeki mülkiyet ispatı (Proof-of-Possession) imzasının doğrulanamaması."""
    pass

class InvalidCSRError(PKIError):
    """CWE-20: CSR içeriğinde eksik veya geçersiz alanlar bulunması (örn. CN olmaması)."""
    pass

class CertificateRevokedError(PKIError):
    """CWE-299: Sertifikanın CRL veya OCSP üzerinden iptal edildiğinin tespit edilmesi."""
    pass

class CertificateExpiredError(PKIError):
    """CWE-298: Sertifikanın geçerlilik bitiş tarihinin (NotAfter) aşılmış olması."""
    pass

class CertificateNotYetValidError(PKIError):
    """CWE-298: Sertifikanın geçerlilik başlangıç tarihinin (NotBefore) henüz gelmemiş olması."""
    pass

class OCSPNonceMismatchError(PKIError):
    """CWE-294: OCSP yanıtındaki nonce değerinin istekteki ile eşleşmemesi (Replay Saldırısı)."""
    pass

class RevocationStatusUnknownError(PKIError):
    """CWE-295: İptal sunucusuna erişilemediğinde fail-closed politikasının tetiklenmesi."""
    pass

class ACMEChallengeFailedError(PKIError):
    """CWE-295: ACME alan adı sahiplik doğrulama tokenının eşleşmemesi."""
    pass

class InsecureKeyStorageError(PKIError):
    """CWE-311: Özel anahtar dosyasında güvensiz erişim izinleri veya bozukluk tespit edilmesi."""
    pass


# ==============================================================================
# 2. KRİPTOGRAFİK YARDIMCI MATEMATİKSEL İŞLEMLER (RSA MOTORU)
# ==============================================================================

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Genişletilmiş Öklid Algoritması: gcd(a, b) = a*x + b*y bağıntısını çözer."""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def modular_inverse(e: int, phi: int) -> int:
    """Modüler ters hesabı: (e * d) % phi == 1 eşitliğini sağlayan d değerini bulur."""
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modüler ters mevcut değil: e ve phi aralarında asal olmalıdır.")
    return (x % phi + phi) % phi

def is_prime_miller_rabin(n: int, k: int = 25) -> bool:
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
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Belirtilen bit uzunluğunda kriptografik olarak rastgele asal sayı üretir."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(candidate):
            return candidate

class RSAKeyPair:
    """Hafif ve bağımsız RSA anahtar çifti modeli."""
    def __init__(self, public_key: Dict[str, int], private_key: Optional[Dict[str, int]] = None):
        # Genel anahtar bileşenleri: Modulus (n) ve Public Exponent (e)
        self.public_key = public_key
        # Özel anahtar bileşenleri: Modulus (n) ve Private Exponent (d)
        self.private_key = private_key

    @classmethod
    def generate(cls, bits: int = 512, e: int = 65537) -> "RSAKeyPair":
        """Belirtilen bit büyüklüğünde asimetrik RSA anahtar çifti türetir."""
        half_bits = bits // 2
        while True:
            p = generate_prime(half_bits)
            q = generate_prime(half_bits)
            if p != q:
                n = p * q
                phi = (p - 1) * (q - 1)
                if math.gcd(e, phi) == 1:
                    d = modular_inverse(e, phi)
                    return cls(public_key={"n": n, "e": e}, private_key={"n": n, "d": d})

    def sign_hash(self, message_hash_bytes: bytes) -> str:
        """Özet değerini özel anahtarla şifreleyerek dijital imza (hex) oluşturur."""
        if not self.private_key:
            raise ValueError("İmzalama işlemi için özel anahtar (private key) gereklidir.")
        # Özeti tamsayıya çevir ve RSA imza formülü: S = m^d mod n
        hash_int = int.from_bytes(message_hash_bytes, byteorder="big")
        signature_int = pow(hash_int, self.private_key["d"], self.private_key["n"])
        return hex(signature_int)[2:]

    @staticmethod
    def verify_signature(public_key: Dict[str, int], message_hash_bytes: bytes, signature_hex: str) -> bool:
        """Genel anahtar ile dijital imzanın doğruluğunu teyit eder: V = S^e mod n."""
        try:
            sig_int = int(signature_hex, 16)
            recovered_int = pow(sig_int, public_key["e"], public_key["n"])
            recovered_bytes = recovered_int.to_bytes((recovered_int.bit_length() + 7) // 8, byteorder="big")
            # Zamanlama analizine dirençli karşılaştırma (CWE-208 önlemi)
            return hmac.compare_digest(message_hash_bytes.lstrip(b"\x00"), recovered_bytes.lstrip(b"\x00"))
        except Exception:
            return False


# ==============================================================================
# 3. PKCS#10 SERTİFİKA İMZA TALEBİ (CSR) MOTORU
# ==============================================================================

class CertificateSigningRequest:
    """PKCS#10 / RFC 2986 standardına uygun Sertifika İmza Talebi (CSR) modeli."""
    def __init__(self, subject_dn: Dict[str, str], san_names: List[str],
                 public_key: Dict[str, int], signature: str, created_at: str):
        # Sertifikanın talep edildiği varlığın ayırt edici adı (DN: C, O, CN)
        self.subject_dn = subject_dn
        # Sunucu Alternatif İsimleri (Subject Alternative Names)
        self.san_names = san_names
        # Başvuru sahibinin genel anahtarı
        self.public_key = public_key
        # Mülkiyet ispatı (Proof-of-Possession) dijital imzası
        self.signature = signature
        # CSR oluşturulma zaman damgası
        self.created_at = created_at

    def to_canonical_bytes(self) -> bytes:
        """İmzalanacak CSR gövdesinin kurallı (kanonik) bayt temsilini üretir."""
        canonical_obj = {
            "subject_dn": self.subject_dn,
            "san_names": sorted(self.san_names),
            "public_key": self.public_key,
            "created_at": self.created_at
        }
        return json.dumps(canonical_obj, sort_keys=True).encode("utf-8")

    @classmethod
    def create(cls, keypair: RSAKeyPair, subject_dn: Dict[str, str], san_names: Optional[List[str]] = None) -> "CertificateSigningRequest":
        """Yeni bir CSR üretir ve başvuru sahibinin özel anahtarıyla imzalar (Proof-of-Possession)."""
        # CWE-20 Doğrulaması: Common Name veya en az bir SAN girilmelidir
        cn = subject_dn.get("CN", "").strip()
        san_list = san_names if san_names else ([cn] if cn else [])
        if not cn and not san_list:
            raise InvalidCSRError("CWE-20: CSR içinde geçerli bir Common Name (CN) veya SAN listesi bulunmalıdır.")

        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        temp_csr = cls(subject_dn=subject_dn, san_names=san_list,
                       public_key=keypair.public_key, signature="", created_at=created_at)
        
        # Kanonik gövdenin SHA-256 özetini al
        body_digest = hashlib.sha256(temp_csr.to_canonical_bytes()).digest()
        # Başvuru sahibi kendi özel anahtarıyla imzalar (Proof-of-Possession)
        signature = keypair.sign_hash(body_digest)
        temp_csr.signature = signature
        return temp_csr

    def verify_proof_of_possession(self) -> bool:
        """CWE-347 Koruması: CSR içindeki genel anahtarın bu imzanın sahibi olduğunu doğrular."""
        body_digest = hashlib.sha256(self.to_canonical_bytes()).digest()
        is_valid = RSAKeyPair.verify_signature(self.public_key, body_digest, self.signature)
        if not is_valid:
            raise CSRSignatureVerificationError("CWE-347: CSR mülkiyet ispatı (Proof-of-Possession) doğrulaması başarısız oldu!")
        return True


# ==============================================================================
# 4. CERTIFICATE TRANSPARENCY (CT LOG - RFC 6962) SİMÜLATÖRÜ
# ==============================================================================

class CertificateTransparencyLog:
    """RFC 6962 uyumlu Certificate Transparency (CT) Denetim Günlüğü simülatörü."""
    def __init__(self, log_id: str = "CT_LOG_ANADOLU_01"):
        # Günlük otoritesi kimliği
        self.log_id = log_id
        # Merkle Ağacı yaprakları (Hash listesi)
        self.leaf_hashes: List[str] = []
        # Günlük otoritesi imza anahtarı
        self.signer_key = RSAKeyPair.generate(bits=512)

    def submit_certificate(self, cert_data_bytes: bytes) -> Dict[str, Any]:
        """Sertifikayı CT günlüğüne ekler ve imzalı zaman damgası (SCT) üretir."""
        # Yaprak hash'i: SHA-256(0x00 || cert_data)
        leaf_hash = hashlib.sha256(b"\x00" + cert_data_bytes).hexdigest()
        self.leaf_hashes.append(leaf_hash)
        
        timestamp = int(time.time() * 1000)
        sct_payload = f"{self.log_id}:{timestamp}:{leaf_hash}".encode("utf-8")
        sct_digest = hashlib.sha256(sct_payload).digest()
        sct_signature = self.signer_key.sign_hash(sct_digest)

        # RFC 6962 Signed Certificate Timestamp (SCT)
        return {
            "sct_version": "v1",
            "log_id": self.log_id,
            "timestamp": timestamp,
            "leaf_hash": leaf_hash,
            "sct_signature": sct_signature,
            "log_public_key": self.signer_key.public_key
        }


# ==============================================================================
# 5. X.509 SERTİFİKA VE CA MOTORU (ISSUANCE)
# ==============================================================================

class X509Certificate:
    """Sertifika yaşam döngüsündeki aktif X.509 sertifika modeli."""
    def __init__(self, serial_number: int, issuer_dn: Dict[str, str], subject_dn: Dict[str, str],
                 san_names: List[str], not_before: str, not_after: str,
                 public_key: Dict[str, int], is_ca: bool, key_usage: List[str],
                 crl_url: str, ocsp_url: str, sct_info: Optional[Dict[str, Any]], signature: str):
        self.serial_number = serial_number
        self.issuer_dn = issuer_dn
        self.subject_dn = subject_dn
        self.san_names = san_names
        self.not_before = not_before
        self.not_after = not_after
        self.public_key = public_key
        self.is_ca = is_ca
        self.key_usage = key_usage
        self.crl_url = crl_url
        self.ocsp_url = ocsp_url
        self.sct_info = sct_info
        self.signature = signature

    def to_canonical_bytes(self) -> bytes:
        """Kanonik sertifika bayt dizisi."""
        payload = {
            "serial_number": self.serial_number,
            "issuer_dn": self.issuer_dn,
            "subject_dn": self.subject_dn,
            "san_names": sorted(self.san_names),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "public_key": self.public_key,
            "is_ca": self.is_ca,
            "key_usage": sorted(self.key_usage),
            "crl_url": self.crl_url,
            "ocsp_url": self.ocsp_url
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def check_temporal_validity(self, current_time: Optional[datetime.datetime] = None) -> None:
        """CWE-298 Koruması: Sertifikanın geçerlilik tarih sınırlarını denetler."""
        now = current_time or datetime.datetime.now(datetime.timezone.utc)
        nb = datetime.datetime.fromisoformat(self.not_before.replace("Z", "+00:00"))
        na = datetime.datetime.fromisoformat(self.not_after.replace("Z", "+00:00"))

        if now < nb:
            raise CertificateNotYetValidError(f"CWE-298: Sertifika henüz geçerli değil! (Başlangıç: {self.not_before})")
        if now > na:
            raise CertificateExpiredError(f"CWE-298: Sertifikanın süresi dolmuştur! (Bitiş: {self.not_after})")


class CertificateAuthority:
    """Kök (Root) veya Ara (Intermediate) Sertifika Otoritesi (CA) motoru."""
    def __init__(self, dn: Dict[str, str], keypair: RSAKeyPair,
                 crl_url: str = "http://crl.guvenlik.local/ca.crl",
                 ocsp_url: str = "http://ocsp.guvenlik.local",
                 is_root: bool = False):
        self.dn = dn
        self.keypair = keypair
        self.crl_url = crl_url
        self.ocsp_url = ocsp_url
        self.is_root = is_root
        # İptal edilen sertifikalar veritabanı: {seri_no: {iptal_tarihi, neden}}
        self.revocation_registry: Dict[int, Dict[str, Any]] = {}
        # CT Günlüğü bağlantısı
        self.ct_log = CertificateTransparencyLog()

    def issue_certificate(self, csr: CertificateSigningRequest, validity_days: int = 90,
                          is_ca: bool = False, key_usage: Optional[List[str]] = None) -> X509Certificate:
        """CSR'yi inceler, mülkiyet ispatını doğrular, sertifika basar ve CT kaydı oluşturur."""
        # 1. Adım: CSR Proof-of-Possession doğrulaması (CWE-347 Koruması)
        csr.verify_proof_of_possession()

        # 2. Adım: Benzersiz pozitif 128-bit seri numarası türet (RFC 5280)
        serial_no = secrets.randbits(128)
        
        # 3. Adım: Geçerlilik zaman aralığını hesapla
        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = now.isoformat()
        not_after = (now + datetime.timedelta(days=validity_days)).isoformat()

        # 4. Adım: Kullanım izinleri (Key Usage)
        ku = key_usage or (["digitalSignature", "keyCertSign", "cRLSign"] if is_ca else ["digitalSignature", "keyEncipherment"])

        # 5. Adım: Taslak sertifika nesnesi
        cert = X509Certificate(
            serial_number=serial_no,
            issuer_dn=self.dn,
            subject_dn=csr.subject_dn,
            san_names=csr.san_names,
            not_before=not_before,
            not_after=not_after,
            public_key=csr.public_key,
            is_ca=is_ca,
            key_usage=ku,
            crl_url=self.crl_url,
            ocsp_url=self.ocsp_url,
            sct_info=None,
            signature=""
        )

        # 6. Adım: CA özel anahtarı ile dijital imzalama
        body_digest = hashlib.sha256(cert.to_canonical_bytes()).digest()
        cert.signature = self.keypair.sign_hash(body_digest)

        # 7. Adım: Certificate Transparency (CT) kütüğüne tescil (RFC 6962)
        sct = self.ct_log.submit_certificate(cert.to_canonical_bytes())
        cert.sct_info = sct

        return cert

    def revoke_certificate(self, serial_number: int, reason: str = "keyCompromise") -> None:
        """Sertifikayı iptal listesine ekler (CRL/OCSP için tescil eder)."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.revocation_registry[serial_number] = {
            "revocation_time": now,
            "reason": reason
        }


# ==============================================================================
# 6. CRL VE OCSP İPTAL SİSTEMLERİ VE OCSP STAPLING
# ==============================================================================

class CertificateRevocationList:
    """RFC 5280 uyumlu İptal Edilmiş Sertifikalar Listesi (CRL)."""
    def __init__(self, issuer_dn: Dict[str, str], revoked_entries: List[Dict[str, Any]],
                 this_update: str, next_update: str, signature: str):
        self.issuer_dn = issuer_dn
        self.revoked_entries = revoked_entries
        self.this_update = this_update
        self.next_update = next_update
        self.signature = signature

    @classmethod
    def generate(cls, ca: CertificateAuthority, validity_hours: int = 24) -> "CertificateRevocationList":
        """CA veritabanındaki güncel iptalleri toplayıp imzalı bir CRL dosyası üretir."""
        now = datetime.datetime.now(datetime.timezone.utc)
        this_update = now.isoformat()
        next_update = (now + datetime.timedelta(hours=validity_hours)).isoformat()

        entries = []
        for sno, data in ca.revocation_registry.items():
            entries.append({
                "serial_number": sno,
                "revocation_time": data["revocation_time"],
                "reason": data["reason"]
            })

        payload = {
            "issuer_dn": ca.dn,
            "revoked_entries": sorted(entries, key=lambda x: x["serial_number"]),
            "this_update": this_update,
            "next_update": next_update
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).digest()
        sig = ca.keypair.sign_hash(digest)

        return cls(issuer_dn=ca.dn, revoked_entries=entries,
                   this_update=this_update, next_update=next_update, signature=sig)

    def is_revoked(self, serial_number: int) -> Tuple[bool, Optional[str]]:
        """Sertifika seri numarasının CRL listesinde olup olmadığını denetler."""
        for entry in self.revoked_entries:
            if entry["serial_number"] == serial_number:
                return True, entry["reason"]
        return False, None


class OCSPResponder:
    """RFC 6960 Çevrimiçi Sertifika Durum Protokolü (OCSP) Yanıtlayıcı Servisi."""
    def __init__(self, ca: CertificateAuthority):
        self.ca = ca
        # OCSP yanıtlayıcı kendi anahtarını veya CA anahtarını kullanır
        self.responder_key = ca.keypair

    def handle_request(self, serial_number: int, request_nonce: Optional[str] = None) -> Dict[str, Any]:
        """İstemciden gelen OCSP sorgusunu işler ve imzalı yanıt döner."""
        now = datetime.datetime.now(datetime.timezone.utc)
        this_update = now.isoformat()
        next_update = (now + datetime.timedelta(hours=1)).isoformat()

        if serial_number in self.ca.revocation_registry:
            rev_info = self.ca.revocation_registry[serial_number]
            status = "REVOKED"
            revocation_details = rev_info
        else:
            status = "GOOD"
            revocation_details = None

        response_body = {
            "responder_dn": self.ca.dn,
            "serial_number": serial_number,
            "status": status,
            "this_update": this_update,
            "next_update": next_update,
            "nonce": request_nonce,
            "revocation_details": revocation_details
        }

        # Yanıt gövdesini SHA-256 ile özetle ve imzala
        digest = hashlib.sha256(json.dumps(response_body, sort_keys=True).encode("utf-8")).digest()
        signature = self.responder_key.sign_hash(digest)

        return {
            "response_body": response_body,
            "signature": signature,
            "responder_public_key": self.responder_key.public_key
        }


class OCSPVerifier:
    """İstemci tarafında OCSP yanıtlarını ve OCSP Stapling paketlerini doğrulayan motor."""
    @staticmethod
    def verify_response(cert: X509Certificate, ocsp_response: Dict[str, Any],
                        expected_nonce: Optional[str] = None,
                        policy: str = "FAIL_CLOSED") -> bool:
        """CWE-294 (Replay) ve CWE-299/295 doğrulamalarını gerçekleştirir."""
        body = ocsp_response.get("response_body", {})
        sig = ocsp_response.get("signature", "")
        pub_key = ocsp_response.get("responder_public_key", {})

        # 1. Adım: İmza doğrulaması
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).digest()
        if not RSAKeyPair.verify_signature(pub_key, digest, sig):
            raise PKIError("OCSP yanıt imzası geçersiz!")

        # 2. Adım: Seri numarası doğrulaması
        if body.get("serial_number") != cert.serial_number:
            raise PKIError("OCSP yanıtı sorgulanan sertifikaya ait değil!")

        # 3. Adım: CWE-294 Replay Koruması (Nonce Eşleşmesi)
        if expected_nonce:
            response_nonce = body.get("nonce")
            if not response_nonce or response_nonce != expected_nonce:
                raise OCSPNonceMismatchError(
                    f"CWE-294: OCSP yanıt nonce değeri uyuşmuyor! Beklenen: {expected_nonce}, Alınan: {response_nonce}"
                )

        # 4. Adım: İptal durumu kontrolü (CWE-299)
        status = body.get("status")
        if status == "REVOKED":
            raise CertificateRevokedError(f"CWE-299: Sertifika iptal edilmiştir! Neden: {body.get('revocation_details')}")
        elif status != "GOOD":
            if policy == "FAIL_CLOSED":
                raise RevocationStatusUnknownError("CWE-295: Sertifika durumu bilinmiyor (FAIL_CLOSED politikası aktif).")
            return False

        return True


# ==============================================================================
# 7. ACME PROTOKOLÜ VE OTOMATİK ROTASYON (RFC 8555 & CRYPTO-SHREDDING)
# ==============================================================================

class ACMEManager:
    """RFC 8555 uyumlu Otomatik Sertifika Yönetim Ortamı (ACME) motoru."""
    def __init__(self, ca: CertificateAuthority):
        self.ca = ca
        # Alan adı doğrulama belirteçleri: {domain: {token: key_auth}}
        self.active_challenges: Dict[str, Dict[str, str]] = {}

    def request_http01_challenge(self, domain: str) -> Tuple[str, str]:
        """HTTP-01 doğrulaması için rastgele bir challenge token üretir."""
        token = secrets.token_urlsafe(32)
        key_authorization = hashlib.sha256(f"{token}:{domain}".encode("utf-8")).hexdigest()
        self.active_challenges[domain] = {"token": token, "key_auth": key_authorization}
        return token, key_authorization

    def validate_and_issue(self, domain: str, presented_token: str,
                           csr: CertificateSigningRequest, validity_days: int = 90) -> X509Certificate:
        """Alan adı sahipliğini doğrular (HTTP-01) ve otomatik olarak sertifika basar."""
        challenge = self.active_challenges.get(domain)
        if not challenge:
            raise ACMEChallengeFailedError(f"CWE-295: {domain} için aktif bir ACME challenge bulunamadı.")

        # Token doğrulaması
        if not hmac.compare_digest(challenge["token"], presented_token):
            raise ACMEChallengeFailedError(f"CWE-295: Sunulan ACME token geçersiz! Alan adı sahipliği kanıtlanamadı.")

        # Alan adı doğrulandıktan sonra sertifikayı bas
        del self.active_challenges[domain]
        return self.ca.issue_certificate(csr, validity_days=validity_days, is_ca=False)


class CertificateLifecycleOrchestrator:
    """Tüm yaşam döngüsünü (Oluşturma -> Denetim -> Rotasyon -> İmha) yöneten orkestratör."""
    def __init__(self, ca: CertificateAuthority, acme_manager: ACMEManager):
        self.ca = ca
        self.acme = acme_manager
        self.current_cert: Optional[X509Certificate] = None
        self.current_keypair: Optional[RSAKeyPair] = None
        self.audit_log: List[Dict[str, Any]] = []

    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Yaşam döngüsü denetim izini (Audit Trail) kayıt altına alır."""
        self.audit_log.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event_type,
            "details": details
        })

    def bootstrap_certificate(self, domain: str) -> Tuple[X509Certificate, RSAKeyPair]:
        """Sistemin ilk sertifikasını üretir ve TLS bağlantısına bağlar."""
        # 1. Yeni anahtar çifti üret
        keypair = RSAKeyPair.generate(bits=512)
        subject_dn = {"CN": domain, "O": "Akademi Güvenli Sunucu", "C": "TR"}
        # 2. CSR hazırla
        csr = CertificateSigningRequest.create(keypair, subject_dn, [domain])
        # 3. ACME Challenge al ve doğrula
        token, _ = self.acme.request_http01_challenge(domain)
        cert = self.acme.validate_and_issue(domain, token, csr, validity_days=90)

        self.current_cert = cert
        self.current_keypair = keypair
        self.log_event("BOOTSTRAP_SUCCESS", {"domain": domain, "serial": cert.serial_number})
        return cert, keypair

    def should_renew(self, threshold_days: int = 30) -> bool:
        """Sertifikanın yenileme eşiğine gelip gelmediğini kontrol eder."""
        if not self.current_cert:
            return True
        na = datetime.datetime.fromisoformat(self.current_cert.not_after.replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        remaining_days = (na - now).total_seconds() / 86400.0
        return remaining_days <= threshold_days

    def auto_rotate_and_crypto_shred(self, domain: str) -> Tuple[X509Certificate, RSAKeyPair]:
        """Kesintisiz anahtar rotasyonu yapar ve eski anahtarı bellekten/disktan güvenle imha eder."""
        old_cert = self.current_cert
        old_keypair = self.current_keypair

        # 1. Yeni anahtar ve CSR oluştur
        new_keypair = RSAKeyPair.generate(bits=512)
        subject_dn = {"CN": domain, "O": "Akademi Güvenli Sunucu", "C": "TR"}
        new_csr = CertificateSigningRequest.create(new_keypair, subject_dn, [domain])

        # 2. ACME ile doğrula ve yeni sertifikayı al
        token, _ = self.acme.request_http01_challenge(domain)
        new_cert = self.acme.validate_and_issue(domain, token, new_csr, validity_days=90)

        # 3. Aktif sertifikayı güncelle (Graceful Cutover)
        self.current_cert = new_cert
        self.current_keypair = new_keypair

        # 4. Eski sertifikayı iptal et (Superseded)
        if old_cert:
            self.ca.revoke_certificate(old_cert.serial_number, reason="superseded")

        # 5. Kriptografik İmha (Crypto-Shredding): Eski anahtarın üzerine rastgele bitler yaz
        if old_keypair and old_keypair.private_key:
            old_keypair.private_key["d"] = secrets.randbits(512)
            old_keypair.private_key = None

        self.log_event("ROTATION_AND_SHRED_COMPLETED", {
            "domain": domain,
            "old_serial": old_cert.serial_number if old_cert else None,
            "new_serial": new_cert.serial_number
        })

        return new_cert, new_keypair
