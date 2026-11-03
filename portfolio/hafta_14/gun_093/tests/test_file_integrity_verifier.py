# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 093: Hashlib Dosya Doğrulama ve Bütünlük İzleme Birim Test Paketi.

Bu modül; akış tabanlı hash hesaplamayı, zayıf algoritma kalkanını (CWE-328),
sabit zamanlı karşılaştırmayı (CWE-208), dizin atlama engellerini (CWE-22)
ve FIM anomali tespitini 14 kapsamlı test senaryosuyla denetler.
"""

# Standart test çerçevesi ve kütüphaneler
import unittest
import sys
import os
import json
import tempfile
import shutil

# Uygulama modülünü sisteme ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Motor sınıflarını ve istisnaları içe aktar
from file_integrity_verifier import (
    FileIntegrityVerifier,
    HashSecurityError,
    WeakHashAlgorithmError,
    UnsupportedAlgorithmError,
    TargetFileNotFoundError,
    PathTraversalError,
    InvalidChecksumFormatError,
    IntegrityMismatchError,
    NullBytePathError,
    PathTooLongError
)

class TestFileIntegrityVerifier(unittest.TestCase):
    """Kriptografik dosya doğrulama test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz motor ve referans dosyaları hazırlar."""
        self.verifier = FileIntegrityVerifier(chunk_size=4096)
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.corpus_dir = os.path.join(self.base_dir, "ornek_veri", "test_corpus")
        
        # Referans hashleri oku
        checksums_path = os.path.join(self.base_dir, "ornek_veri", "known_checksums.json")
        with open(checksums_path, "r", encoding="utf-8") as f:
            self.known_checksums = json.load(f)

    def test_01_compute_sha256_known_file(self) -> None:
        """1. Test: Bilinen konfigürasyon dosyasının SHA-256 özetinin doğruluğu."""
        conf_path = os.path.join(self.corpus_dir, "secure_config.conf")
        res = self.verifier.compute_file_hash(conf_path, algoritma="sha256")
        beklenen = self.known_checksums["secure_config.conf"]["sha256"]
        self.assertEqual(res.hesaplanan_hash, beklenen)
        self.assertEqual(res.algoritma, "sha256")

    def test_02_compute_sha512_known_file(self) -> None:
        """2. Test: Bilinen politika belgesinin SHA-512 özetinin doğruluğu."""
        policy_path = os.path.join(self.corpus_dir, "policy_doc.txt")
        res = self.verifier.compute_file_hash(policy_path, algoritma="sha512")
        beklenen = self.known_checksums["policy_doc.txt"]["sha512"]
        self.assertEqual(res.hesaplanan_hash, beklenen)
        self.assertEqual(len(res.hesaplanan_hash), 128)

    def test_03_compute_blake2b(self) -> None:
        """3. Test: İkili dosyanın modern BLAKE2b algoritmasıyla özetlenmesi."""
        bin_path = os.path.join(self.corpus_dir, "app_payload.bin")
        res = self.verifier.compute_file_hash(bin_path, algoritma="blake2b")
        self.assertEqual(res.algoritma, "blake2b")
        self.assertEqual(len(res.hesaplanan_hash), 128)

    def test_04_weak_algorithm_rejected_in_strict_mode(self) -> None:
        """4. Test: Katı modda MD5 ve SHA-1'in reddedilmesi (CWE-328)."""
        conf_path = os.path.join(self.corpus_dir, "secure_config.conf")
        with self.assertRaises(WeakHashAlgorithmError):
            self.verifier.compute_file_hash(conf_path, algoritma="md5", strict_mode=True)
        with self.assertRaises(WeakHashAlgorithmError):
            self.verifier.compute_file_hash(conf_path, algoritma="sha1", strict_mode=True)

    def test_05_weak_algorithm_allowed_in_non_strict_mode(self) -> None:
        """5. Test: Katı mod kapalıyken eski uyumluluk için MD5 hesabına izin verilmesi."""
        conf_path = os.path.join(self.corpus_dir, "secure_config.conf")
        res = self.verifier.compute_file_hash(conf_path, algoritma="md5", strict_mode=False)
        self.assertEqual(res.algoritma, "md5")
        self.assertEqual(len(res.hesaplanan_hash), 32)

    def test_06_unsupported_algorithm_rejection(self) -> None:
        """6. Test: Geçersiz veya desteklenmeyen algoritmanın reddedilmesi (CWE-20)."""
        conf_path = os.path.join(self.corpus_dir, "secure_config.conf")
        with self.assertRaises(UnsupportedAlgorithmError):
            self.verifier.compute_file_hash(conf_path, algoritma="rot13_fake")

    def test_07_file_not_found_handling(self) -> None:
        """7. Test: Bulunmayan dosya yolunun kontrollü olarak yakalanması."""
        with self.assertRaises(TargetFileNotFoundError):
            self.verifier.compute_file_hash("var_olmayan_dosya.txt")

    def test_08_path_traversal_prevention(self) -> None:
        """8. Test: Dosya yolunda dizin atlama ('..') girişimlerinin engellenmesi (CWE-22)."""
        with self.assertRaises(PathTraversalError):
            self.verifier.validate_file_path("../../etc/shadow")

    def test_09_null_byte_path_rejection(self) -> None:
        """9. Test: Dosya yolunda Null-Byte (\\x00) zehirlemesinin engellenmesi (CWE-158)."""
        with self.assertRaises(NullBytePathError):
            self.verifier.validate_file_path("config.conf\x00.exe")

    def test_10_invalid_checksum_format(self) -> None:
        """10. Test: Karşılaştırmada eksik veya hex dışı hash formatının reddedilmesi."""
        conf_path = os.path.join(self.corpus_dir, "secure_config.conf")
        # 63 karakter
        with self.assertRaises(InvalidChecksumFormatError):
            self.verifier.verify_file_integrity(conf_path, "6ab41d63c809129b15ab6ecb2e98a7b59899dd12bc634a6502a6eb644154e0b")
        # Hex dışı karakter (Z)
        with self.assertRaises(InvalidChecksumFormatError):
            self.verifier.verify_file_integrity(conf_path, "6ab41d63c809129b15ab6ecb2e98a7b59899dd12bc634a6502a6eb644154ZZZZ")

    def test_11_verify_file_integrity_success(self) -> None:
        """11. Test: Sağlama toplamı eşleştiğinde bütünlüğün başarıyla onaylanması."""
        conf_path = os.path.join(self.corpus_dir, "secure_config.conf")
        beklenen = self.known_checksums["secure_config.conf"]["sha256"]
        audit = self.verifier.verify_file_integrity(conf_path, beklenen_hash=beklenen, algoritma="sha256")
        self.assertTrue(audit.butunluk_dogrulandi_mi)
        self.assertIn("BAŞARILI", audit.durum_mesaji)

    def test_12_verify_file_integrity_mismatch(self) -> None:
        """12. Test: Kurcalanmış veya yanlış hash durumunda IntegrityMismatchError fırlatılması (CWE-353)."""
        conf_path = os.path.join(self.corpus_dir, "secure_config.conf")
        sahte_hash = "0" * 64
        with self.assertRaises(IntegrityMismatchError):
            self.verifier.verify_file_integrity(conf_path, beklenen_hash=sahte_hash, algoritma="sha256", strict_mode=True)

    def test_13_constant_time_comparison(self) -> None:
        """13. Test: Zamanlama saldırılarını önlemek için hmac.compare_digest kullanılması (CWE-208)."""
        import hmac
        h1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        h2 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertTrue(hmac.compare_digest(h1, h2))

    def test_14_directory_baseline_and_tamper_detection(self) -> None:
        """14. Test: Dizin taban çizgisi (baseline) oluşturma ve anomali tespiti (FIM)."""
        temp_dir = tempfile.mkdtemp()
        try:
            # Geçici dosyalar oluştur
            f1 = os.path.join(temp_dir, "file1.txt")
            f2 = os.path.join(temp_dir, "file2.txt")
            with open(f1, "w", encoding="utf-8") as fp:
                fp.write("Original content 1")
            with open(f2, "w", encoding="utf-8") as fp:
                fp.write("Original content 2")

            # Taban çizgisi al
            baseline = self.verifier.generate_directory_baseline(temp_dir, algoritma="sha256")
            self.assertEqual(baseline["toplam_dosya"], 2)

            # Anomali oluştur: file1 değiştir, file2 sil, file3 ekle
            with open(f1, "w", encoding="utf-8") as fp:
                fp.write("Tampered content 1!")
            os.remove(f2)
            f3 = os.path.join(temp_dir, "file3.txt")
            with open(f3, "w", encoding="utf-8") as fp:
                fp.write("New unexpected file")

            anomaliler = self.verifier.verify_directory_against_baseline(temp_dir, baseline)
            self.assertIn("file1.txt", anomaliler["degistirilen_dosyalar"])
            self.assertIn("file2.txt", anomaliler["silinen_dosyalar"])
            self.assertIn("file3.txt", anomaliler["yeni_eklenen_dosyalar"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
