# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 105: Mini Proje 14 - Kriptografik Hash Bütünlük Manifesti Test Paketi.
15 birim test ile manifest oluşturma, HMAC mühürleme, tahrifat tespiti (MODIFIED/ADDED/DELETED),
dizin geçişi (Path Traversal), zayıf hash engeli ve 9 negatif kontrol senaryosu doğrulanır.
"""

# Birim test kütüphanesi
import unittest
# JSON veri dönüştürme modülü
import json
# Sistem ve yol araçları
import sys
# Dosya ve dizin araçları
import os
import shutil

# Ana dizini modül arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Bütünlük motoru bileşenlerini içe aktar
from uygulama.hash_manifest_engine import (
    HashManifestEngine,
    safe_resolve_path,
    compute_streaming_hash,
    ManifestAuditScorecard,
    ManifestConfig,
    ManifestEngineError,
    BrokenHashAlgorithmError,
    ManifestTamperingError,
    PathTraversalError,
    SymlinkEscapeError,
    DirectoryNotFoundError,
    FileIntegrityMismatchError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    TypeValidationError
)


class TestHashManifestEngine(unittest.TestCase):
    """Bütünlük manifestosu test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce örnek test dizini ve değişkenlerini hazırla."""
        self.test_dir = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_project_tree")
        self.signing_key = "MASTER_INTEGRITY_KEY_2026"
        self.negatif_json_yolu = os.path.join(
            os.path.dirname(__file__), "..", "ornek_veri", "invalid_manifest_inputs.json"
        )

    def test_01_create_manifest_structure(self) -> None:
        """Test 1: Manifest oluşturulması ve temel alanların doğruluğu."""
        m = HashManifestEngine.create_manifest(self.test_dir, algo="sha256")
        self.assertEqual(m["algoritma"], "SHA256")
        self.assertGreaterEqual(m["toplam_dosya"], 3)
        self.assertIn("dosyalar", m)
        self.assertTrue(any(f["yol"] == "app.py" for f in m["dosyalar"]))

    def test_02_manifest_hmac_seal(self) -> None:
        """Test 2: İmzalı manifestoda geçerli HMAC-SHA256 mührünün bulunması."""
        m = HashManifestEngine.create_manifest(self.test_dir, signing_key=self.signing_key)
        self.assertIsNotNone(m["hmac_muhru"])
        self.assertEqual(len(m["hmac_muhru"]), 64)

    def test_03_verify_manifest_clean(self) -> None:
        """Test 3: Değişiklik yapılmamış temiz dizinde denetimin tam puanla geçmesi."""
        m = HashManifestEngine.create_manifest(self.test_dir, signing_key=self.signing_key)
        scorecard = HashManifestEngine.verify_manifest(self.test_dir, m, signing_key=self.signing_key)
        self.assertEqual(scorecard.verdict, "INTEGRITY_VERIFIED")
        self.assertTrue(scorecard.seal_valid)
        self.assertEqual(scorecard.modified_count, 0)
        self.assertEqual(scorecard.deleted_count, 0)
        self.assertEqual(scorecard.added_count, 0)

    def test_04_detect_modified_file(self) -> None:
        """Test 4: Bir dosyanın içeriği değiştiğinde MODIFIED olarak yakalanması."""
        m = HashManifestEngine.create_manifest(self.test_dir, signing_key=self.signing_key)
        # Manifest verisindeki bir dosyanın beklenen hashini boz
        m_bozuk = json.loads(json.dumps(m))
        m_bozuk["dosyalar"][0]["hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        scorecard = HashManifestEngine.verify_manifest(self.test_dir, m_bozuk)
        self.assertEqual(scorecard.verdict, "TAMPERING_DETECTED")
        self.assertEqual(scorecard.modified_count, 1)

    def test_05_detect_deleted_file(self) -> None:
        """Test 5: Manifestte olan ancak diskte bulunmayan dosyanın DELETED tespiti."""
        m = HashManifestEngine.create_manifest(self.test_dir)
        m_silinmis = json.loads(json.dumps(m))
        m_silinmis["dosyalar"].append({
            "yol": "olmayan_dosya.txt",
            "boyut_bayt": 10,
            "hash": "1111111111111111111111111111111111111111111111111111111111111111"
        })
        scorecard = HashManifestEngine.verify_manifest(self.test_dir, m_silinmis)
        self.assertEqual(scorecard.verdict, "TAMPERING_DETECTED")
        self.assertEqual(scorecard.deleted_count, 1)

    def test_06_detect_added_file(self) -> None:
        """Test 6: Diskte olup manifestte listelenmeyen izinsiz dosyanın ADDED tespiti."""
        m = HashManifestEngine.create_manifest(self.test_dir)
        # Manifestten bir dosyayı çıkar (Diskte kalır)
        m_eksik = json.loads(json.dumps(m))
        cikarilan = m_eksik["dosyalar"].pop()
        scorecard = HashManifestEngine.verify_manifest(self.test_dir, m_eksik)
        self.assertEqual(scorecard.verdict, "TAMPERING_DETECTED")
        self.assertGreaterEqual(scorecard.added_count, 1)

    def test_07_tampered_hmac_seal_raises_cwe353(self) -> None:
        """Test 7: Manifest HMAC mührü tahrif edildiğinde katı modda hata fırlatılması (CWE-353)."""
        m = HashManifestEngine.create_manifest(self.test_dir, signing_key=self.signing_key)
        m_sahte = json.loads(json.dumps(m))
        m_sahte["hmac_muhru"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        with self.assertRaises(ManifestTamperingError):
            HashManifestEngine.verify_manifest(self.test_dir, m_sahte, signing_key=self.signing_key, strict_mode=True)

    def test_08_broken_hash_algorithm_md5_raises_cwe328(self) -> None:
        """Test 8: Güvensiz MD5 algoritması ile manifest üretimi denemesinin engellenmesi (CWE-328)."""
        with self.assertRaises(BrokenHashAlgorithmError):
            HashManifestEngine.create_manifest(self.test_dir, algo="md5")

    def test_09_broken_hash_algorithm_sha1_raises_cwe328(self) -> None:
        """Test 9: Güvensiz SHA-1 algoritması ile manifest üretimi denemesinin engellenmesi (CWE-328)."""
        with self.assertRaises(BrokenHashAlgorithmError):
            HashManifestEngine.create_manifest(self.test_dir, algo="sha1")

    def test_10_path_traversal_in_manifest_raises_cwe22(self) -> None:
        """Test 10: Manifest içinde üst dizinlere sızma girişiminin engellenmesi (CWE-22)."""
        with self.assertRaises(PathTraversalError):
            safe_resolve_path(self.test_dir, "../../windows/system32/cmd.exe")

    def test_11_null_byte_in_path_raises_cwe158(self) -> None:
        """Test 11: Dosya yolunda Null-Byte zehirlemesi denemesinin engellenmesi (CWE-158)."""
        with self.assertRaises(NullByteInjectionError):
            safe_resolve_path(self.test_dir, "config.json\x00.bak")

    def test_12_nonexistent_root_dir_raises_cwe73(self) -> None:
        """Test 12: Olmayan kök dizin yolunda DirectoryNotFoundError fırlatılması (CWE-73)."""
        with self.assertRaises(DirectoryNotFoundError):
            HashManifestEngine.create_manifest("olmayan_hayali_dizin_12345")

    def test_13_oversized_file_raises_cwe400(self) -> None:
        """Test 13: 1 MB tavanını aşan büyük dosyanın taranmasının engellenmesi (CWE-400)."""
        temp_file = os.path.join(self.test_dir, "temp_oversized.bin")
        try:
            with open(temp_file, "wb") as f:
                f.write(b"0" * 1_200_000)  # 1.2 MB
            with self.assertRaises(PayloadLimitExceededError):
                compute_streaming_hash(temp_file, "sha256")
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_14_type_confusion_manifest_raises_cwe843(self) -> None:
        """Test 14: Manifest parametresi yerine int tipi iletildiğinde tip hatası (CWE-843)."""
        with self.assertRaises(TypeValidationError):
            HashManifestEngine.verify_manifest(self.test_dir, 123456789)  # type: ignore

    def test_15_negative_json_cases_verification(self) -> None:
        """Test 15: ornek_veri/invalid_manifest_inputs.json içindeki 9 negatif senaryonun yürütülmesi."""
        with open(self.negatif_json_yolu, "r", encoding="utf-8") as f:
            negatif_vakalar = json.load(f)

        self.assertEqual(len(negatif_vakalar), 9)

        for vaka in negatif_vakalar:
            vid = vaka["id"]
            beklenen = vaka["beklenen_hata"]

            if vid == "NEG_01_BROKEN_HASH_ALGORITHM":
                with self.assertRaises(BrokenHashAlgorithmError):
                    HashManifestEngine.create_manifest(self.test_dir, algo=vaka["algoritma"])

            elif vid == "NEG_02_HMAC_SEAL_FORGERY":
                m = HashManifestEngine.create_manifest(self.test_dir, signing_key=self.signing_key)
                m["hmac_muhru"] = vaka["sahte_muhur"]
                with self.assertRaises(ManifestTamperingError):
                    HashManifestEngine.verify_manifest(self.test_dir, m, signing_key=self.signing_key, strict_mode=True)

            elif vid == "NEG_03_PATH_TRAVERSAL_IN_MANIFEST":
                with self.assertRaises(PathTraversalError):
                    safe_resolve_path(self.test_dir, vaka["zararli_yol"])

            elif vid == "NEG_04_SYMLINK_ESCAPE_ATTEMPT":
                # Kök dizin dışına kaçış yapan sembolik bağ kontrolü
                with self.assertRaises(SymlinkEscapeError):
                    safe_resolve_path(self.test_dir, vaka["zararli_yol"])

            elif vid == "NEG_05_EMPTY_ROOT_DIRECTORY":
                with self.assertRaises(DirectoryNotFoundError):
                    HashManifestEngine.create_manifest(vaka["gecersiz_dizin"])

            elif vid == "NEG_06_CORRUPTED_FILE_HASH":
                m = HashManifestEngine.create_manifest(self.test_dir)
                m["dosyalar"][0]["hash"] = "9999999999999999999999999999999999999999999999999999999999999999"
                with self.assertRaises(FileIntegrityMismatchError):
                    HashManifestEngine.verify_manifest(self.test_dir, m, strict_mode=True)

            elif vid == "NEG_07_NULL_BYTE_PATH_INJECTION":
                with self.assertRaises(NullByteInjectionError):
                    safe_resolve_path(self.test_dir, vaka["zararli_yol"])

            elif vid == "NEG_08_OVERSIZED_FILE_READ_DOS":
                temp_big = os.path.join(self.test_dir, "temp_big_neg.bin")
                try:
                    with open(temp_big, "wb") as f:
                        f.write(b"Z" * vaka["boyut_bayt"])
                    with self.assertRaises(PayloadLimitExceededError):
                        compute_streaming_hash(temp_big, "sha256")
                finally:
                    if os.path.exists(temp_big):
                        os.remove(temp_big)

            elif vid == "NEG_09_TYPE_CONFUSION":
                with self.assertRaises(TypeValidationError):
                    HashManifestEngine.create_manifest(vaka["hatali_girdi"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
