# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
TLS Güvenlik Sınırları Kapsamlı Birim Testleri (test_tls_boundary.py).

Bu test paketi; HKDF anahtar türetimi, AEAD kimlik doğrulamalı şifreleme,
Record fragment sınırları (16 KB), sıra numarası senkronizasyonu,
ClientHello/ServerHello pazarlığı, Fallback-SCSV ve Sentinel Downgrade savunmaları,
Finished mesajı transkript bütünlüğü ve 0-RTT anti-replay mekanizmasını
15 bağımsız test senaryosuyla sınar.
"""

import os
import sys
import unittest
import hashlib

# Uygulama modülünü arama yoluna dahil et
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

from tls_security_boundary_engine import (
    hkdf_extract,
    hkdf_expand,
    SimulatedAEADCipher,
    TLSRecordLayer,
    TLSHandshakeEngine,
    TLS13ZeroRTTAntiReplayCache,
    TLSError,
    TLSDowngradeDetectedError,
    InsecureCipherSuiteError,
    HandshakeTranscriptIntegrityError,
    ForwardSecrecyRequiredError,
    BadRecordMACError,
    ZeroRTTReplayDetectedError,
    InvalidSequenceNumberError,
    RecordOverflowError,
    DowngradeSentinelMismatchError,
    TLS12_DOWNGRADE_SENTINEL
)

class TestTLSSecurityBoundaries(unittest.TestCase):
    """TLS 1.2 vs 1.3 Güvenlik Sınırları ve Protokol Testleri (15 Test)."""

    def setUp(self):
        """Her testten önce temiz test motorları ve anahtarlar oluştur."""
        self.key = b"0123456789abcdef0123456789abcdef" # 32 bayt test anahtarı
        self.server_engine = TLSHandshakeEngine(
            supported_versions=["TLSv1.3", "TLSv1.2"],
            allowed_ciphers=["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-AES256-GCM-SHA384"],
            require_pfs=True
        )
        self.client_engine = TLSHandshakeEngine(
            supported_versions=["TLSv1.3", "TLSv1.2"],
            allowed_ciphers=["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"],
            require_pfs=True
        )

    def test_01_hkdf_extract_and_expand(self):
        """Test 01 (RFC 5869): HKDF-Extract ve HKDF-Expand anahtar türetim doğruluğu."""
        salt = b"test_tuz_123456"
        ikm = b"girdi_anahtar_materyali"
        prk = hkdf_extract(salt, ikm)
        self.assertEqual(len(prk), 32)
        okm = hkdf_expand(prk, b"tls13_handshake_traffic", length=48)
        self.assertEqual(len(okm), 48)

    def test_02_aead_encryption_and_decryption_success(self):
        """Test 02: AEAD şifreleme ve etiket doğrulamasının başarıyla çözülmesi."""
        cipher = SimulatedAEADCipher(self.key)
        nonce = b"\x00" * 12
        aad = b"header_data"
        plaintext = b"Gizli TLS Uygulama Paketi"
        ciphertext, tag = cipher.encrypt(nonce, plaintext, aad)
        decrypted = cipher.decrypt(nonce, ciphertext, aad, tag)
        self.assertEqual(decrypted, plaintext)

    def test_03_aead_tampered_tag_rejection(self):
        """Test 03 (CWE-353): Tahrif edilmiş AEAD kimlik doğrulama etiketinin reddi."""
        cipher = SimulatedAEADCipher(self.key)
        nonce = b"\x00" * 12
        aad = b"header_data"
        ciphertext, tag = cipher.encrypt(nonce, b"Veri", aad)
        # Etiketi boz
        tampered_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
        with self.assertRaises(BadRecordMACError):
            cipher.decrypt(nonce, ciphertext, aad, tampered_tag)

    def test_04_record_max_fragment_overflow(self):
        """Test 04 (CWE-20): 16384 bayt sınırını aşan record fragment reddi."""
        record_layer = TLSRecordLayer()
        oversized_data = b"A" * 16385 # 16KB + 1 bayt
        with self.assertRaises(RecordOverflowError):
            record_layer.create_record(TLSRecordLayer.CONTENT_TYPE_APPLICATION_DATA, oversized_data)

    def test_05_record_sequence_number_tracking(self):
        """Test 05: Record katmanında sıra numaralarının sıralı ve hatasız ilerlemesi."""
        cipher = SimulatedAEADCipher(self.key)
        rl = TLSRecordLayer(aead_cipher=cipher)
        rec1 = rl.create_record(TLSRecordLayer.CONTENT_TYPE_APPLICATION_DATA, b"Mesaj 1")
        rec2 = rl.create_record(TLSRecordLayer.CONTENT_TYPE_APPLICATION_DATA, b"Mesaj 2")
        self.assertEqual(rec1["sequence_number"], 0)
        self.assertEqual(rec2["sequence_number"], 1)
        # Sırasıyla işle
        self.assertEqual(rl.process_record(rec1), b"Mesaj 1")
        self.assertEqual(rl.process_record(rec2), b"Mesaj 2")

    def test_06_record_sequence_number_desync_rejection(self):
        """Test 06 (CWE-353): Sıra numarası atlama veya paket yer değiştirme tespiti."""
        cipher = SimulatedAEADCipher(self.key)
        rl = TLSRecordLayer(aead_cipher=cipher)
        rec1 = rl.create_record(TLSRecordLayer.CONTENT_TYPE_APPLICATION_DATA, b"Mesaj 1")
        rec2 = rl.create_record(TLSRecordLayer.CONTENT_TYPE_APPLICATION_DATA, b"Mesaj 2")
        # İlk mesajı atlayıp doğrudan ikinci mesajı işlet (aradan paket çalınmış gibi)
        with self.assertRaises(InvalidSequenceNumberError):
            rl.process_record(rec2)

    def test_07_client_hello_creation(self):
        """Test 07: ClientHello yapısı, rastgele bayt uzunluğu ve şifre paketleri."""
        hello = self.client_engine.create_client_hello(["TLSv1.3"], ["TLS_AES_256_GCM_SHA384"])
        self.assertIn("client_random_hex", hello)
        self.assertEqual(len(bytes.fromhex(hello["client_random_hex"])), 32)
        self.assertEqual(hello["cipher_suites"], ["TLS_AES_256_GCM_SHA384"])

    def test_08_negotiate_tls13_success(self):
        """Test 08: En yüksek ortak sürüm olan TLS 1.3 ve güçlü AEAD şifre seçimi."""
        hello = self.client_engine.create_client_hello(["TLSv1.3", "TLSv1.2"], ["TLS_AES_256_GCM_SHA384"])
        server_reply = self.server_engine.process_client_hello_and_reply(hello)
        self.assertEqual(server_reply["server_version"], "TLSv1.3")
        self.assertEqual(server_reply["cipher_suite"], "TLS_AES_256_GCM_SHA384")

    def test_09_fallback_scsv_downgrade_detection(self):
        """Test 09 (CWE-757): TLS_FALLBACK_SCSV ile Downgrade saldırısının yakalanması."""
        # İstemci 1.3 destekleyen sunucuya 1.2 ile fallback denemesi yapıyor
        fallback_hello = {
            "supported_versions": ["TLSv1.2"],
            "cipher_suites": ["ECDHE-RSA-AES256-GCM-SHA384", "TLS_FALLBACK_SCSV"]
        }
        with self.assertRaises(TLSDowngradeDetectedError):
            self.server_engine.process_client_hello_and_reply(fallback_hello)

    def test_10_insecure_ciphers_rejection(self):
        """Test 10 (CWE-327): İstemcinin sadece zayıf/kırılmış şifreler (RC4/DES) sunması."""
        bad_hello = {
            "supported_versions": ["TLSv1.2"],
            "cipher_suites": ["TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
        }
        with self.assertRaises(InsecureCipherSuiteError):
            self.server_engine.process_client_hello_and_reply(bad_hello)

    def test_11_forward_secrecy_enforcement(self):
        """Test 11: require_pfs=True iken statik RSA anahtar değişim paketinin elenmesi."""
        pfs_server = TLSHandshakeEngine(
            supported_versions=["TLSv1.2"],
            allowed_ciphers=["TLS_RSA_WITH_AES_128_CBC_SHA"],
            require_pfs=True
        )
        hello = {
            "supported_versions": ["TLSv1.2"],
            "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"] # Statik RSA (PFS yok)
        }
        with self.assertRaises(ForwardSecrecyRequiredError):
            pfs_server.process_client_hello_and_reply(hello)

    def test_12_downgrade_sentinel_detection(self):
        """Test 12 (CWE-757): ServerRandom içindeki TLS 1.2 Downgrade Sentinel tespit kontrolü."""
        # İstemci 1.3 destekliyor, sunucu 1.2 dönüyor ve içine sentinel baytları gömülmüş
        server_random = bytearray(b"\x11" * 32)
        server_random[-8:] = TLS12_DOWNGRADE_SENTINEL
        fake_server_hello = {
            "server_version": "TLSv1.2",
            "server_random_hex": bytes(server_random).hex()
        }
        with self.assertRaises(DowngradeSentinelMismatchError):
            self.client_engine.verify_server_hello_and_downgrade_sentinel(
                fake_server_hello, client_highest_version="TLSv1.3"
            )

    def test_13_handshake_finished_verify_data_success(self):
        """Test 13: Temiz ve tahrifatsız transkript üzerinden Finished mesajı eşleşmesi."""
        client_hello = self.client_engine.create_client_hello(["TLSv1.3"], ["TLS_AES_256_GCM_SHA384"])
        server_hello = self.server_engine.process_client_hello_and_reply(client_hello)
        self.client_engine.record_handshake_message("ServerHello", server_hello)

        key = b"ortak_el_sikisma_anahtari"
        verify_data = self.client_engine.generate_finished_message(key)
        self.assertTrue(self.server_engine.verify_finished_message(key, verify_data))

    def test_14_handshake_transcript_tampering_rejection(self):
        """Test 14 (CWE-353): Araya giren saldırganın el sıkışma mesajını değiştirmesi."""
        client_hello = self.client_engine.create_client_hello(["TLSv1.3"], ["TLS_AES_256_GCM_SHA384"])
        server_hello = self.server_engine.process_client_hello_and_reply(client_hello)
        self.client_engine.record_handshake_message("ServerHello", server_hello)

        key = b"ortak_el_sikisma_anahtari"
        # Sahte verify_data
        with self.assertRaises(HandshakeTranscriptIntegrityError):
            self.server_engine.verify_finished_message(key, "deadbeef" * 8)

    def test_15_zero_rtt_anti_replay_cache(self):
        """Test 15 (CWE-294): TLS 1.3 0-RTT Erken Veri tekrar oynatma (Replay) engellemesi."""
        cache = TLS13ZeroRTTAntiReplayCache(window_seconds=10)
        ticket = "ticket_oturum_999"
        res = cache.process_early_data(ticket, "SIPARIS VER 1 ADET")
        self.assertEqual(res["status"], "ACCEPTED")
        # Aynı biletle ikinci kez istek geldiğinde Replay hatası fırlatılmalı
        with self.assertRaises(ZeroRTTReplayDetectedError):
            cache.process_early_data(ticket, "SIPARIS VER 1 ADET")

if __name__ == "__main__":
    unittest.main()
