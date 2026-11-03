# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 074: Temiz Kod, Saf Fonksiyonlar ve Modüler Güvenlik Birim Testleri
Bu test paketi, fonksiyonların saf yapısını, değişmezliğini, sözleşmelerini ve
değiştirilebilir varsayılan argüman tuzağının engellenmesini 14 test ile doğrular.
"""

# Birim test çerçevesi için standart unittest modülü içe aktarılır
import unittest
# Yol manipülasyonu için os ve sys modülleri içe aktarılır
import os
import sys

# Uygulama modülünü dinamik olarak içe aktarmak için modül yolu sys.path'e eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Doğrulanacak ana güvenlik motoru sınıfı içe aktarılır
from clean_functions_and_security_modularizer import CleanFunctionsAndSecurityModularizer


class TestCleanFunctionsAndSecurityModularizer(unittest.TestCase):
    """
    Temiz kod ve savunmacı fonksiyon pratiklerini doğrulayan test sınıfı.
    """

    def setUp(self) -> None:
        """
        Her test öncesi bağımsız bir güvenlik motoru örneği oluşturulur.
        """
        # Test izolesi için yeni motor nesnesi atanır
        self.engine = CleanFunctionsAndSecurityModularizer()

    def test_01_mutable_default_isolation(self) -> None:
        """
        Test 01: Değiştirilebilir varsayılan argüman tuzağının (CWE-670) engellendiğini doğrular.
        """
        # İlk çağrı etiket belirtilmeden yapılır
        res1 = self.engine.validate_log_and_tag("LOG_A")
        # İlk çağrının etiketlerine harici müdahale simüle edilir
        res1["tags"].append("attacker_poison")

        # İkinci çağrı yine etiket belirtilmeden yapılır
        res2 = self.engine.validate_log_and_tag("LOG_B")

        # İkinci çağrının etiketlerinde önceki çağrının enjeksiyonunun OLMADIĞI doğrulanır
        self.assertNotIn("attacker_poison", res2["tags"])
        # İkinci çağrının sadece kendi 'verified' etiketine sahip olduğu kanıtlanır
        self.assertEqual(res2["tags"], ["verified"])

    def test_02_validate_log_and_tag_valid(self) -> None:
        """
        Test 02: Dışarıdan sağlanan etiket listesinin güvenli kopyalandığını ve işlendiğini doğrular.
        """
        # Orijinal etiket listesi tanımlanır
        original_tags = ["audit", "network"]
        # Fonksiyon çağrılır
        result = self.engine.validate_log_and_tag("LOG_C", original_tags)

        # Çıktıda hem orijinal etiketlerin hem de 'verified' etiketinin yer aldığı doğrulanır
        self.assertIn("verified", result["tags"])
        self.assertIn("audit", result["tags"])
        # Orijinal listenin fonksiyon içinde yerinde (in-place) değiştirilmediği kanıtlanır
        self.assertEqual(len(original_tags), 2)

    def test_03_validate_log_and_tag_empty_raises(self) -> None:
        """
        Test 03: Boş veya yalnızca boşluktan oluşan ham log girdisinin ValueError fırlattığını doğrular.
        """
        # Boş string ile çağrıda ValueError beklenir
        with self.assertRaises(ValueError):
            self.engine.validate_log_and_tag("   ")

    def test_04_validate_log_and_tag_invalid_type_raises(self) -> None:
        """
        Test 04: String dışı bir tip (int, dict vb.) girildiğinde TypeError fırlatıldığını doğrular.
        """
        # Sayısal bir veri girildiğinde TypeError beklenir
        with self.assertRaises(TypeError):
            self.engine.validate_log_and_tag(12345)  # type: ignore

    def test_05_pure_threat_score_deterministic(self) -> None:
        """
        Test 05: Saf fonksiyonun deterministik olduğunu, aynı girdiye her seferinde aynı çıktıyı verdiğini doğrular.
        """
        # Sabit girdi faktörleri tanımlanır
        factors = {"c2": 0.8, "malware_ip": 0.6}
        # Fonksiyon ardışık 3 kez çalıştırılır
        score1 = self.engine.pure_calculate_threat_score(factors)
        score2 = self.engine.pure_calculate_threat_score(factors)
        score3 = self.engine.pure_calculate_threat_score(factors)

        # Üç sonucun da birbirine kesin olarak eşit olduğu doğrulanır
        self.assertEqual(score1, score2)
        self.assertEqual(score2, score3)
        # Beklenen matematiksel ortalama (0.7 * 100 = 70.0) doğrulanır
        self.assertEqual(score1, 70.0)

    def test_06_pure_threat_score_empty_dict(self) -> None:
        """
        Test 06: Boş faktör sözlüğü verildiğinde sonucun 0.0 olduğunu doğrular.
        """
        # Boş sözlük ile çağrılır
        score = self.engine.pure_calculate_threat_score({})
        # Sonucun 0.0 olduğu test edilir
        self.assertEqual(score, 0.0)

    def test_07_pure_threat_score_out_of_bounds_weight(self) -> None:
        """
        Test 07: 1.0'dan büyük veya 0.0'dan küçük faktör ağırlıklarında ValueError fırlatıldığını doğrular.
        """
        # 1.0'dan büyük katsayıda hata beklenir
        with self.assertRaises(ValueError):
            self.engine.pure_calculate_threat_score({"c2": 1.5})

        # 0.0'dan küçük negatif katsayıda hata beklenir
        with self.assertRaises(ValueError):
            self.engine.pure_calculate_threat_score({"c2": -0.1})

    def test_08_pure_threat_score_invalid_type(self) -> None:
        """
        Test 08: Sayısal olmayan faktör ağırlığında TypeError fırlatıldığını doğrular.
        """
        # Metin formatında ağırlık verildiğinde TypeError beklenir
        with self.assertRaises(TypeError):
            self.engine.pure_calculate_threat_score({"c2": "high"})  # type: ignore

    def test_09_srp_pipeline_valid_private_ip(self) -> None:
        """
        Test 09: SRP boru hattının özel ağ IP'sini (192.168.1.100) doğru ayrıştırdığını doğrular.
        """
        # Özel IP içeren log satırı hazırlanır
        log_line = "OCT 31 10:00:00 HOST=fw01 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP"
        # Boru hattı çalıştırılır
        record = self.engine.split_and_validate_ioc_pipeline(log_line)

        # Alanların doğruluğu test edilir
        self.assertEqual(record["source_ip"], "192.168.1.100")
        self.assertTrue(record["is_valid_ipv4"])
        self.assertEqual(record["network_zone"], "PRIVATE")

    def test_10_srp_pipeline_loopback_and_public(self) -> None:
        """
        Test 10: SRP boru hattının Loopback (127.0.0.1) ve Public (8.8.8.8) IP'leri doğru sınıflandırdığını doğrular.
        """
        # Loopback log satırı test edilir
        loopback_log = "SRC=127.0.0.1 ACTION=ALLOW"
        res_lb = self.engine.split_and_validate_ioc_pipeline(loopback_log)
        self.assertEqual(res_lb["network_zone"], "LOOPBACK")

        # Public log satırı test edilir
        public_log = "SRC=8.8.8.8 ACTION=QUERY"
        res_pub = self.engine.split_and_validate_ioc_pipeline(public_log)
        self.assertEqual(res_pub["network_zone"], "PUBLIC")

    def test_11_srp_pipeline_missing_src_raises(self) -> None:
        """
        Test 11: SRC alanı içermeyen log satırında ayrıştırıcının ValueError fırlattığını doğrular.
        """
        # SRC alanı eksik log satırı
        bad_log = "OCT 31 10:00:00 HOST=fw01 NO_SOURCE_TOKEN ACTION=DENY"
        # İstisna fırlatıldığı test edilir
        with self.assertRaises(ValueError):
            self.engine.split_and_validate_ioc_pipeline(bad_log)

    def test_12_immutable_rule_sanitizer_defensive_copy(self) -> None:
        """
        Test 12: Kural temizleyicinin derin kopya (deep copy) aldığını ve orijinal sözlüğü koruduğunu doğrular.
        """
        # Orijinal kural nesnesi tanımlanır
        original_rule = {
            "kural_id": "RULE_01",
            "aksiyon": "inspect",
            "nested_config": {"max_len": 500}
        }

        # Temizleme fonksiyonu çağrılır
        sanitized = self.engine.immutable_rule_sanitizer(original_rule)

        # Dönen nesnede aksiyonun büyük harfe ('INSPECT') dönüştürüldüğü görülür
        self.assertEqual(sanitized["aksiyon"], "INSPECT")
        # Orijinal nesnedeki aksiyonun küçük harf ('inspect') olarak korunduğu doğrulanır
        self.assertEqual(original_rule["aksiyon"], "inspect")

        # Dönen nesnenin iç yapılandırmasına müdahale edilir
        sanitized["nested_config"]["max_len"] = 9999
        # Orijinal iç yapılandırmanın değişmediği (500 kaldığı) kanıtlanır
        self.assertEqual(original_rule["nested_config"]["max_len"], 500)

    def test_13_contract_hash_lookup_valid_algorithms(self) -> None:
        """
        Test 13: Sözleşmeye dayalı hash doğrulayıcının md5, sha1 ve sha256 algoritmalarını onayladığını test eder.
        """
        # Geçerli SHA-256 hash'i
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res_sha = self.engine.contract_enforced_hash_lookup(sha256_hash, "sha256")
        self.assertEqual(res_sha["verdict"], "CONFIRMED")

        # Geçerli MD5 hash'i
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        res_md5 = self.engine.contract_enforced_hash_lookup(md5_hash, "md5")
        self.assertEqual(res_md5["verdict"], "CONFIRMED")

        # Geçerli SHA-1 hash'i
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        res_sha1 = self.engine.contract_enforced_hash_lookup(sha1_hash, "sha1")
        self.assertEqual(res_sha1["verdict"], "CONFIRMED")

    def test_14_contract_hash_lookup_violations(self) -> None:
        """
        Test 14: Desteklenmeyen algoritma, hatalı uzunluk ve hex dışı karakterlerde sözleşmenin bozulduğunu doğrular.
        """
        # Desteklenmeyen algoritma ihlali
        with self.assertRaises(ValueError):
            self.engine.contract_enforced_hash_lookup("abc", "md6")

        # Eksik karakter uzunluğu ihlali (SHA-256 için 64 beklenirken 63 gönderildi)
        short_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
        with self.assertRaises(ValueError):
            self.engine.contract_enforced_hash_lookup(short_hash, "sha256")

        # Hex dışı karakter ihlali ('z' harfi)
        invalid_hex = "d41d8cd98f00b204e9800998ecf842zz"
        with self.assertRaises(ValueError):
            self.engine.contract_enforced_hash_lookup(invalid_hex, "md5")


if __name__ == "__main__":
    # Testler detaylı çıktı (-v) ile çalıştırılır
    unittest.main()
