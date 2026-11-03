# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
NIST SP 800-57 Uyumlu Anahtar Yönetimi Kapsamlı Birim Testleri (test_key_management.py).

Bu test paketi; KEK üretimi, Zarf Şifreleme (Envelope Encryption), DEK sarmalama,
Re-wrapping, Kriptoperiyot süre sınırları, anahtar durum geçişleri (Active/Deprecated/Compromised/Destroyed),
Kriptografik Sıfırlama (Zeroization / CWE-226) ve Çift Kontrol (Dual Control / Split Knowledge)
süreçlerini 15 bağımsız test senaryosuyla sınar.
"""

import os
import sys
import unittest
import datetime

# Uygulama modülünü arama yoluna dahil et
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

from key_management_engine import (
    KeyManagementService,
    EnvelopeEncryptionEngine,
    DualControlKeySplitter,
    KeyState,
    KeyManagementError,
    KeyExpiredError,
    KeyCompromisedError,
    InadequateKeyLengthError,
    KeyUsageLimitExceededError,
    EncryptedDEKIntegrityError,
    KeyAlreadyDestroyedError,
    InsufficientKeySharesError,
    KeyDeprecatedError,
    PredictableKeyError
)

class TestKeyManagementAndRotation(unittest.TestCase):
    """NIST SP 800-57 Anahtar Yönetimi ve Rotasyon Birim Testleri (15 Test)."""

    def setUp(self):
        """Her testten önce temiz KMS servisi ve motor oluştur."""
        self.kms = KeyManagementService()
        self.engine = EnvelopeEncryptionEngine(self.kms)

    def test_01_kek_generation_and_metadata(self):
        """Test 01: 256-bit KEK üretimi, ACTIVE durumu ve metaveri alanları."""
        kek = self.kms.create_kek("master_kek_01", bit_length=256, cryptoperiod_days=365)
        self.assertEqual(kek.key_id, "master_kek_01")
        self.assertEqual(kek.bit_length, 256)
        self.assertEqual(kek.state, KeyState.ACTIVE)
        self.assertIsNotNone(kek.key_material)

    def test_02_inadequate_key_length_rejection(self):
        """Test 02 (CWE-326): NIST SP 800-57 uyarınca 128 bit altı anahtar talebinin reddi."""
        with self.assertRaises(InadequateKeyLengthError):
            self.kms.create_kek("weak_kek_64", bit_length=64)

    def test_03_predictable_key_rejection(self):
        """Test 03 (CWE-321): Sıfırlardan veya sabit kalıplardan oluşan anahtar reddi."""
        with self.assertRaises(PredictableKeyError):
            self.kms.create_kek("zero_key", bit_length=256, custom_bytes=b"\x00" * 32)

    def test_04_envelope_encryption_and_decryption_success(self):
        """Test 04: Zarf şifreleme ve deşifrelemenin başarıyla tamamlanması."""
        self.kms.create_kek("kek_v1", bit_length=256)
        data = b"Gizli Veri Katmani 2026"
        envelope = self.engine.encrypt_data(data, associated_data=b"tenant_1")
        decrypted = self.engine.decrypt_data(envelope, associated_data=b"tenant_1")
        self.assertEqual(decrypted, data)

    def test_05_envelope_aad_tamper_rejection(self):
        """Test 05 (CWE-353): İlişkili veride (AAD) tahrifat yapıldığında hata üretimi."""
        self.kms.create_kek("kek_v1", bit_length=256)
        envelope = self.engine.encrypt_data(b"Veri", associated_data=b"dogru_aad")
        with self.assertRaises(EncryptedDEKIntegrityError):
            self.engine.decrypt_data(envelope, associated_data=b"sahte_aad")

    def test_06_envelope_wrapped_dek_tamper_rejection(self):
        """Test 06 (CWE-353): KEK ile sarılmış DEK etiketinin bozulmasında hata üretimi."""
        self.kms.create_kek("kek_v1", bit_length=256)
        envelope = self.engine.encrypt_data(b"Veri")
        # DEK etiketini boz
        envelope["dek_tag_hex"] = "ff" * 16
        with self.assertRaises(EncryptedDEKIntegrityError):
            self.engine.decrypt_data(envelope)

    def test_07_cryptoperiod_expiration_rejection(self):
        """Test 07 (CWE-320): Kriptoperiyodu dolmuş anahtarla işlem yapılması."""
        kek = self.kms.create_kek("kek_v1", bit_length=256, cryptoperiod_days=30)
        future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=40)
        with self.assertRaises(KeyExpiredError):
            kek.check_cryptoperiod(current_time=future_time)

    def test_08_compromised_key_blocking(self):
        """Test 08 (CWE-320): İhlal edilmiş (COMPROMISED) anahtarla tüm operasyonların kilitlenmesi."""
        self.kms.create_kek("kek_v1", bit_length=256)
        envelope = self.engine.encrypt_data(b"Hassas Kayit")
        self.kms.compromise_key("kek_v1")
        # Deşifre engellenmeli
        with self.assertRaises(KeyCompromisedError):
            self.engine.decrypt_data(envelope)

    def test_09_deprecated_key_encrypt_rejection(self):
        """Test 09 (CWE-320): DEPRECATED durumdaki KEK ile yeni veri şifrelenmesinin engellenmesi."""
        kek = self.kms.create_kek("kek_v1", bit_length=256)
        kek.state = KeyState.DEPRECATED
        with self.assertRaises(KeyDeprecatedError):
            self.engine.encrypt_data(b"Yeni Veri")

    def test_10_deprecated_key_decrypt_success(self):
        """Test 10: DEPRECATED durumdaki KEK'in geçmiş veriyi başarıyla deşifre edebilmesi."""
        self.kms.create_kek("kek_v1", bit_length=256)
        data = b"Eski Donem Arsiv Verisi"
        envelope = self.engine.encrypt_data(data)
        # KEK-2'ye rotasyon yapıldığında KEK-1 otomatik DEPRECATED olur
        self.kms.rotate_kek("kek_v2", bit_length=256)
        # DEPRECATED olan KEK-1 ile eski veriyi deşifre et
        decrypted = self.engine.decrypt_data(envelope)
        self.assertEqual(decrypted, data)

    def test_11_key_rotation_and_state_transition(self):
        """Test 11: Otomatik rollover durum geçişleri (Eski: DEPRECATED, Yeni: ACTIVE)."""
        kek1 = self.kms.create_kek("kek_1", bit_length=256)
        kek2 = self.kms.rotate_kek("kek_2", bit_length=256)
        self.assertEqual(kek1.state, KeyState.DEPRECATED)
        self.assertEqual(kek2.state, KeyState.ACTIVE)
        self.assertEqual(self.kms.get_active_kek().key_id, "kek_2")

    def test_12_re_wrapping_constant_time(self):
        """Test 12: Re-wrapping ile veriyi kopyalamadan DEK'in yeni KEK ile sarılması."""
        self.kms.create_kek("kek_1", bit_length=256)
        data = b"Milyonlarca Satirlik Buyuk Tablo Verisi"
        orig_envelope = self.engine.encrypt_data(data)
        # Rotasyon yap
        self.kms.rotate_kek("kek_2", bit_length=256)
        # Re-wrapping uygula
        re_wrapped = self.engine.re_wrap_envelope(orig_envelope)
        # Şifreli veri değişmedi (O(1) süre)
        self.assertEqual(orig_envelope["ciphertext_hex"], re_wrapped["ciphertext_hex"])
        self.assertEqual(re_wrapped["kek_id"], "kek_2")
        # Yeni KEK ile veri çözülebilir
        decrypted = self.engine.decrypt_data(re_wrapped)
        self.assertEqual(decrypted, data)

    def test_13_zeroization_crypto_shredding(self):
        """Test 13: Kriptografik Sıfırlama (Zeroization) ile anahtar materyalinin ezilmesi."""
        kek = self.kms.create_kek("kek_to_destroy", bit_length=256)
        self.assertIsNotNone(kek.key_material)
        kek.zeroize()
        self.assertIsNone(kek.key_material)
        self.assertEqual(kek.state, KeyState.DESTROYED)

    def test_14_zeroized_key_access_rejection(self):
        """Test 14 (CWE-226): İmha edilmiş (DESTROYED) anahtarla işlem yapılması."""
        self.kms.create_kek("kek_del", bit_length=256)
        self.kms.destroy_key("kek_del")
        with self.assertRaises(KeyAlreadyDestroyedError):
            self.kms.get_key("kek_del").check_cryptoperiod()

    def test_15_dual_control_split_and_combine(self):
        """Test 15 (CWE-320): Dual Control (2-of-2) anahtar parçalama ve birleştirme."""
        secret = b"KMS_ROOT_SECRET_MASTER_256BIT!!"
        share1, share2 = DualControlKeySplitter.split_secret_2_of_2(secret)
        # İki parça birleştirildiğinde sır elde edilmeli
        reconstructed = DualControlKeySplitter.combine_secret_2_of_2([share1, share2])
        self.assertEqual(reconstructed, secret)
        # Tek parça sunulduğunda hata vermeli
        with self.assertRaises(InsufficientKeySharesError):
            DualControlKeySplitter.combine_secret_2_of_2([share1])

if __name__ == "__main__":
    unittest.main()
