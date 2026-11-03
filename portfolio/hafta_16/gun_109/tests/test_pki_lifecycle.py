# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
PKI ve Sertifika Yaşam Döngüsü Kapsamlı Birim Testleri (test_pki_lifecycle.py).

Bu test paketi; anahtar üretimi, CSR doğrulaması, Proof-of-Possession,
Certificate Authority ihracı, Certificate Transparency (CT/SCT),
zaman sınırları (NotBefore/NotAfter), CRL, OCSP ve Nonce Replay denetimleri,
ACME HTTP-01 challenge ve Kriptografik İmha (Crypto-Shredding) süreçlerini
15 bağımsız ve deterministik test senaryosuyla sınar.
"""

import os
import sys
import unittest
import hashlib
import datetime

# Test edilen modül yolunu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

from pki_lifecycle_engine import (
    RSAKeyPair,
    CertificateSigningRequest,
    CertificateAuthority,
    CertificateRevocationList,
    OCSPResponder,
    OCSPVerifier,
    ACMEManager,
    CertificateLifecycleOrchestrator,
    PKIError,
    CSRSignatureVerificationError,
    InvalidCSRError,
    CertificateRevokedError,
    CertificateExpiredError,
    CertificateNotYetValidError,
    OCSPNonceMismatchError,
    ACMEChallengeFailedError
)

class TestPKILifecycleEngine(unittest.TestCase):
    """PKI ve Sertifika Yaşam Döngüsü için 15 Kapsamlı Birim Testi."""

    @classmethod
    def setUpClass(cls):
        """Test sınıfı başlatılırken ortak CA ve anahtarları bir defa üret."""
        # Kök CA Anahtarı (Test hızı için optimize edilmiş 512-bit)
        cls.root_ca_key = RSAKeyPair.generate(bits=512)
        # Kök CA Otoritesi
        cls.root_ca = CertificateAuthority(
            dn={"CN": "Test Ulusal Kök CA", "O": "Test Guvenlik", "C": "TR"},
            keypair=cls.root_ca_key,
            is_root=True
        )
        # Test İstemci Anahtar Çifti
        cls.client_key = RSAKeyPair.generate(bits=512)

    def test_01_rsa_keypair_generation_and_math(self):
        """Test 01: RSA anahtar üretimi, özet imzalama ve doğrulama doğruluğu."""
        # Test mesajı ve SHA-256 özeti
        msg = b"PKI Test Mesaji"
        digest = hashlib.sha256(msg).digest()
        # İstemci anahtarı ile imza üret
        signature = self.client_key.sign_hash(digest)
        # Doğrula
        valid = RSAKeyPair.verify_signature(self.client_key.public_key, digest, signature)
        self.assertTrue(valid, "Geçerli RSA imzası başarıyla doğrulanmalıdır.")

    def test_02_csr_creation_and_pop_verification(self):
        """Test 02: PKCS#10 CSR oluşturulması ve Proof-of-Possession doğrulaması."""
        subject_dn = {"CN": "api.test.local", "O": "Test Kurum", "C": "TR"}
        # CSR üret (kendi özel anahtarıyla imzalar)
        csr = CertificateSigningRequest.create(self.client_key, subject_dn, ["api.test.local"])
        # Proof-of-Possession doğrula
        is_pop_valid = csr.verify_proof_of_possession()
        self.assertTrue(is_pop_valid, "CSR mülkiyet ispatı doğrulanmalıdır.")

    def test_03_csr_tampered_signature_rejection(self):
        """Test 03 (CWE-347): Tahrif edilmiş CSR imzasının reddedilmesi."""
        subject_dn = {"CN": "sahte.test.local"}
        csr = CertificateSigningRequest.create(self.client_key, subject_dn)
        # İmzayı tahrif et (sahte imza yerleştir)
        csr.signature = "a" * len(csr.signature)
        # Mülkiyet ispatı hatası fırlatılmalıdır
        with self.assertRaises(CSRSignatureVerificationError):
            csr.verify_proof_of_possession()

    def test_04_csr_missing_cn_rejection(self):
        """Test 04 (CWE-20): Boş Common Name (CN) ve boş SAN içeren CSR'nin reddi."""
        with self.assertRaises(InvalidCSRError):
            CertificateSigningRequest.create(self.client_key, {"O": "Isimsiz"}, [])

    def test_05_ca_certificate_issuance(self):
        """Test 05: CA tarafından geçerli bir X.509 sertifikasının ihraç edilmesi."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "portal.test.local"})
        cert = self.root_ca.issue_certificate(csr, validity_days=90)
        # Seri no pozitif ve 128-bit olmalıdır
        self.assertGreater(cert.serial_number, 0)
        self.assertEqual(cert.subject_dn["CN"], "portal.test.local")
        self.assertEqual(cert.issuer_dn["CN"], "Test Ulusal Kök CA")

    def test_06_ct_log_and_sct_issuance(self):
        """Test 06 (RFC 6962): Sertifikanın CT günlüğüne tescili ve SCT varlığı."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "ct.test.local"})
        cert = self.root_ca.issue_certificate(csr)
        # SCT bilgisi dolu olmalıdır
        self.assertIsNotNone(cert.sct_info)
        self.assertEqual(cert.sct_info["log_id"], "CT_LOG_ANADOLU_01")
        self.assertTrue("sct_signature" in cert.sct_info)

    def test_07_certificate_temporal_validity_success(self):
        """Test 07: Geçerli zaman dilimindeki sertifikanın zaman kontrolünü geçmesi."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "zaman.test.local"})
        cert = self.root_ca.issue_certificate(csr, validity_days=30)
        # Hata fırlatmamalıdır
        cert.check_temporal_validity()

    def test_08_certificate_expired_rejection(self):
        """Test 08 (CWE-298): NotAfter tarihi geçmiş sertifikanın reddedilmesi."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "eski.test.local"})
        cert = self.root_ca.issue_certificate(csr, validity_days=10)
        # 1 yıl sonrasındaki zaman ile test et
        future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        with self.assertRaises(CertificateExpiredError):
            cert.check_temporal_validity(current_time=future_time)

    def test_09_certificate_not_yet_valid_rejection(self):
        """Test 09 (CWE-298): NotBefore tarihi gelecekte olan sertifikanın reddedilmesi."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "gelecek.test.local"})
        cert = self.root_ca.issue_certificate(csr, validity_days=10)
        # Geçmiş zaman ile test et
        past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        with self.assertRaises(CertificateNotYetValidError):
            cert.check_temporal_validity(current_time=past_time)

    def test_10_crl_generation_and_lookup(self):
        """Test 10: CRL üretimi ve iptal edilen sertifikanın tespiti."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "crl.test.local"})
        cert = self.root_ca.issue_certificate(csr)
        # Sertifikayı iptal et
        self.root_ca.revoke_certificate(cert.serial_number, reason="keyCompromise")
        # CRL üret
        crl = CertificateRevocationList.generate(self.root_ca)
        is_rev, reason = crl.is_revoked(cert.serial_number)
        self.assertTrue(is_rev)
        self.assertEqual(reason, "keyCompromise")

    def test_11_ocsp_responder_good_status(self):
        """Test 11: Aktif sertifika için OCSP yanıtlayıcının GOOD durumu dönmesi."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "ocsp-good.test.local"})
        cert = self.root_ca.issue_certificate(csr)
        responder = OCSPResponder(self.root_ca)
        nonce = "test_valid_nonce_1"
        resp = responder.handle_request(cert.serial_number, request_nonce=nonce)
        valid = OCSPVerifier.verify_response(cert, resp, expected_nonce=nonce)
        self.assertTrue(valid)
        self.assertEqual(resp["response_body"]["status"], "GOOD")

    def test_12_ocsp_nonce_mismatch_replay_defense(self):
        """Test 12 (CWE-294): OCSP yanıtında Nonce uyuşmazlığının (Replay) engellenmesi."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "replay.test.local"})
        cert = self.root_ca.issue_certificate(csr)
        responder = OCSPResponder(self.root_ca)
        # Yanıttaki nonce ile istemcinin beklediği nonce uyuşmuyor
        resp = responder.handle_request(cert.serial_number, request_nonce="eski_nonce_replay")
        with self.assertRaises(OCSPNonceMismatchError):
            OCSPVerifier.verify_response(cert, resp, expected_nonce="yeni_beklenen_nonce")

    def test_13_ocsp_revoked_certificate_rejection(self):
        """Test 13 (CWE-299): İptal edilmiş sertifikanın OCSP doğrulamasında reddi."""
        csr = CertificateSigningRequest.create(self.client_key, {"CN": "iptal.test.local"})
        cert = self.root_ca.issue_certificate(csr)
        self.root_ca.revoke_certificate(cert.serial_number, reason="cessationOfOperation")
        responder = OCSPResponder(self.root_ca)
        resp = responder.handle_request(cert.serial_number, request_nonce="nonce_rev")
        with self.assertRaises(CertificateRevokedError):
            OCSPVerifier.verify_response(cert, resp, expected_nonce="nonce_rev")

    def test_14_acme_http01_challenge_workflow(self):
        """Test 14: ACME HTTP-01 alan adı doğrulama akışı ve otomatik sertifika basımı."""
        acme = ACMEManager(self.root_ca)
        domain = "servis.otomasyon.local"
        token, _ = acme.request_http01_challenge(domain)
        csr = CertificateSigningRequest.create(self.client_key, {"CN": domain})
        cert = acme.validate_and_issue(domain, presented_token=token, csr=csr)
        self.assertEqual(cert.subject_dn["CN"], domain)

    def test_15_lifecycle_rotation_and_crypto_shredding(self):
        """Test 15: Otomatik rotasyon, eski sertifika iptali ve kriptografik imha (Crypto-Shredding)."""
        acme = ACMEManager(self.root_ca)
        orchestrator = CertificateLifecycleOrchestrator(self.root_ca, acme)
        domain = "rotasyon.kurum.local"
        # İlk sertifikayı al
        cert1, key1 = orchestrator.bootstrap_certificate(domain)
        # Rotasyon yürüt
        cert2, key2 = orchestrator.auto_rotate_and_crypto_shred(domain)
        # Seri numaraları farklı olmalı
        self.assertNotEqual(cert1.serial_number, cert2.serial_number)
        # Eski sertifika iptal edilmiş olmalı
        self.assertIn(cert1.serial_number, self.root_ca.revocation_registry)
        # Eski anahtarın özel bileşeni imha edilmiş (crypto-shredded) olmalı
        self.assertIsNone(key1.private_key)

if __name__ == "__main__":
    unittest.main()
