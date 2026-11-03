# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 108: X.509 ve Sertifika Zinciri Kapsamlı Birim Testleri.
15 Birim testi (%100 PASS hedefi), RFC 5280 yol doğrulama, BasicConstraints,
KeyUsage, SAN alan adı eşleme, süre ve iptal kontrollerini içerir.
"""

# Standart unittest modülü
import unittest
# Tarih ve zaman modülleri
from datetime import datetime, timezone, timedelta
# Sistem ve dizin yönetimi
import os
import sys

# Test edilen motor modülünü sistem yoluna ekleme
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
APP_DIR = os.path.join(PARENT_DIR, "uygulama")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

# Çekirdek motor sınıflarını içe aktarma
from x509_chain_engine import (
    X509Certificate,
    X509DistinguishedName,
    X509Validity,
    X509BasicConstraints,
    PKIBuilder,
    X509ChainValidator,
    UntrustedRootCAError,
    CertificateExpiredError,
    CertificateNotYetValidError,
    CertificateSignatureInvalidError,
    HostnameMismatchError,
    NonCACertificateUsedAsCAError,
    PathLengthExceededError,
    RevokedCertificateError,
    MalformedCertificateError
)


class TestX509Chain(unittest.TestCase):
    """X.509 sertifika yapısı ve RFC 5280 güven zinciri testleri."""

    @classmethod
    def setUpClass(cls):
        """Tüm testler için ortak 3 kademeli deterministik test PKI'ı kurar (hızlı 512-bit anahtarlar)."""
        cls.root_ca, cls.root_priv = PKIBuilder.create_root_ca(
            cn="Test Global Root CA", bits=512, days_valid=3650
        )
        cls.inter_ca, cls.inter_priv = PKIBuilder.create_intermediate_ca(
            parent_ca=cls.root_ca,
            parent_priv=cls.root_priv,
            cn="Test Finans Ara CA",
            bits=512,
            days_valid=1825
        )
        cls.leaf_cert, cls.leaf_priv = PKIBuilder.create_leaf_certificate(
            issuer_ca=cls.inter_ca,
            issuer_priv=cls.inter_priv,
            domain="secure.bank.com.tr",
            san_list=["secure.bank.com.tr", "api.bank.com.tr", "*.bank.com.tr"],
            bits=512,
            days_valid=365
        )
        cls.trust_store = [cls.root_ca]

    def test_01_root_ca_creation_and_self_signature(self):
        """1. Kök CA kendinden imzalı olmalı, is_ca=True ve keyCertSign yetkisine sahip olmalıdır."""
        self.assertTrue(self.root_ca.is_self_signed())
        self.assertTrue(self.root_ca.basic_constraints.is_ca)
        self.assertIn("keyCertSign", self.root_ca.key_usage)
        self.assertTrue(self.root_ca.verify_signature(self.root_ca.public_key))

    def test_02_intermediate_ca_issuance(self):
        """2. Ara CA kök CA tarafından imzalanmalı ve is_ca=True olmalıdır."""
        self.assertFalse(self.inter_ca.is_self_signed())
        self.assertTrue(self.inter_ca.basic_constraints.is_ca)
        self.assertTrue(self.inter_ca.verify_signature(self.root_ca.public_key))
        self.assertEqual(self.inter_ca.issuer.common_name, self.root_ca.subject.common_name)

    def test_03_leaf_certificate_issuance(self):
        """3. Uç sunucu sertifikası is_ca=False olmalı ve Ara CA tarafından doğrulanmalıdır."""
        self.assertFalse(self.leaf_cert.basic_constraints.is_ca)
        self.assertIn("digitalSignature", self.leaf_cert.key_usage)
        self.assertTrue(self.leaf_cert.verify_signature(self.inter_ca.public_key))
        self.assertEqual(self.leaf_cert.issuer.common_name, self.inter_ca.subject.common_name)

    def test_04_valid_3_tier_chain_validation(self):
        """4. 3 Kademeli meşru zincir (Leaf -> Intermediate -> Root) başarıyla doğrulanmalıdır."""
        res = X509ChainValidator.validate_chain(
            leaf=self.leaf_cert,
            intermediates=[self.inter_ca],
            trust_store=self.trust_store,
            target_domain="secure.bank.com.tr"
        )
        self.assertEqual(res["status"], "VALID")
        self.assertEqual(res["chain_length"], 3)
        self.assertEqual(res["root_trust_anchor"], self.root_ca.subject.common_name)

    def test_05_hostname_exact_and_san_match(self):
        """5. Sertifika hem ana CN hem de SAN listesindeki alan adlarıyla birebir eşleşmelidir."""
        self.assertTrue(self.leaf_cert.matches_hostname("secure.bank.com.tr"))
        self.assertTrue(self.leaf_cert.matches_hostname("api.bank.com.tr"))

    def test_06_wildcard_domain_matching(self):
        """6. *.bank.com.tr jokeri tek seviyeli alt alan adlarıyla eşleşmeli, çoklu seviyeyi reddetmelidir."""
        self.assertTrue(self.leaf_cert.matches_hostname("odeme.bank.com.tr"))
        self.assertTrue(self.leaf_cert.matches_hostname("portal.bank.com.tr"))
        self.assertFalse(self.leaf_cert.matches_hostname("nested.sub.bank.com.tr"))

    def test_07_hostname_mismatch_rejection(self):
        """7. Sertifikada listelenmeyen yabancı alan adı HostnameMismatchError fırlatmalıdır (CWE-297)."""
        with self.assertRaises(HostnameMismatchError):
            X509ChainValidator.validate_chain(
                leaf=self.leaf_cert,
                intermediates=[self.inter_ca],
                trust_store=self.trust_store,
                target_domain="evil-phishing.com"
            )

    def test_08_expired_certificate_rejection(self):
        """8. Süresi dolmuş sertifika CertificateExpiredError fırlatmalıdır (CWE-298)."""
        future = datetime.now(timezone.utc) + timedelta(days=400)
        with self.assertRaises(CertificateExpiredError):
            X509ChainValidator.validate_chain(
                leaf=self.leaf_cert,
                intermediates=[self.inter_ca],
                trust_store=self.trust_store,
                target_domain="secure.bank.com.tr",
                check_time=future
            )

    def test_09_not_yet_valid_certificate_rejection(self):
        """9. Geçerlilik tarihi henüz başlamamış sertifika reddedilmelidir (CWE-298)."""
        past = datetime.now(timezone.utc) - timedelta(days=10)
        with self.assertRaises(CertificateNotYetValidError):
            X509ChainValidator.validate_chain(
                leaf=self.leaf_cert,
                intermediates=[self.inter_ca],
                trust_store=self.trust_store,
                target_domain="secure.bank.com.tr",
                check_time=past
            )

    def test_10_untrusted_root_ca_rejection(self):
        """10. Güven deposunda bulunmayan sahte kök sertifika UntrustedRootCAError fırlatmalıdır (CWE-295)."""
        fake_root, _ = PKIBuilder.create_root_ca(cn="Rogue Fake Root CA", bits=512)
        with self.assertRaises(UntrustedRootCAError):
            X509ChainValidator.validate_chain(
                leaf=self.leaf_cert,
                intermediates=[self.inter_ca],
                trust_store=[fake_root],
                target_domain="secure.bank.com.tr"
            )

    def test_11_tampered_tbs_signature_rejection(self):
        """11. Sertifikanın TBS alanında tahrifat yapıldığında imza doğrulaması çökmelidir (CWE-295)."""
        tampered_cert = X509Certificate.from_dict(self.leaf_cert.to_dict())
        # Subject CN alanını yetkisiz olarak değiştiriyoruz
        tampered_cert.subject.common_name = "hacked.bank.com.tr"
        with self.assertRaises(CertificateSignatureInvalidError):
            X509ChainValidator.validate_chain(
                leaf=tampered_cert,
                intermediates=[self.inter_ca],
                trust_store=self.trust_store,
                target_domain="hacked.bank.com.tr"
            )

    def test_12_non_ca_cannot_issue_certificates(self):
        """12. is_ca=False olan uç sertifika ile alt sertifika üretimi engellenmelidir (CWE-295)."""
        with self.assertRaises(NonCACertificateUsedAsCAError):
            PKIBuilder.create_leaf_certificate(
                issuer_ca=self.leaf_cert,  # Uç sertifika yetkisiz CA yapılmaya çalışılıyor
                issuer_priv=self.leaf_priv,
                domain="unauthorized.org"
            )

    def test_13_revoked_certificate_rejection(self):
        """13. İptal listesinde (CRL) yer alan sertifika RevokedCertificateError fırlatmalıdır (CWE-295)."""
        revoked = {self.leaf_cert.serial_number}
        with self.assertRaises(RevokedCertificateError):
            X509ChainValidator.validate_chain(
                leaf=self.leaf_cert,
                intermediates=[self.inter_ca],
                trust_store=self.trust_store,
                target_domain="secure.bank.com.tr",
                revoked_serials=revoked
            )

    def test_14_path_length_constraint_enforcement(self):
        """14. pathLenConstraint=0 olan ara CA altından ikinci bir ara CA oluşturulamaz/doğrulanamaz."""
        # path_len=0 olan bir alt ara CA oluşturulursa zincir sınırı aşılır
        inter2, inter2_priv = PKIBuilder.create_intermediate_ca(
            parent_ca=self.inter_ca,
            parent_priv=self.inter_priv,
            cn="Derin Alt CA",
            bits=512
        )
        leaf_deep, _ = PKIBuilder.create_leaf_certificate(
            issuer_ca=inter2,
            issuer_priv=inter2_priv,
            domain="deep.bank.com.tr",
            bits=512
        )
        with self.assertRaises(PathLengthExceededError):
            X509ChainValidator.validate_chain(
                leaf=leaf_deep,
                intermediates=[inter2, self.inter_ca],
                trust_store=self.trust_store,
                target_domain="deep.bank.com.tr"
            )

    def test_15_certificate_dict_and_pem_serialization(self):
        """15. Sertifikalar sözlük ve PEM formatına serileştirilip kayıpsız geri yüklenebilmelidir."""
        pem_str = self.leaf_cert.to_pem()
        self.assertIn("-----BEGIN CERTIFICATE-----", pem_str)
        self.assertIn("-----END CERTIFICATE-----", pem_str)

        cert_dict = self.leaf_cert.to_dict()
        restored_cert = X509Certificate.from_dict(cert_dict)
        self.assertEqual(self.leaf_cert.serial_number, restored_cert.serial_number)
        self.assertEqual(self.leaf_cert.issuer.common_name, restored_cert.issuer.common_name)
        self.assertEqual(self.leaf_cert.subject.common_name, restored_cert.subject.common_name)


if __name__ == "__main__":
    unittest.main()
