# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 075: Veri Yapıları Güvenlik ve Performans Birim Testleri
Bu test paketi, küme cebri ile tehdit korelasyonunu, O(1) vs O(N) arama dinamiklerini,
güvenli sözlük gezintisini ve in-place mutasyon korumasını 14 test ile doğrular.
"""

# Birim test çatısı için unittest modülü içe aktarılır
import unittest
# Yol ve modül import işlemleri için os ve sys içe aktarılır
import os
import sys

# Uygulama modülünü dinamik olarak içe aktarmak için modül yolu sys.path'e eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Doğrulanacak ana güvenlik veri yapıları motoru içe aktarılır
from security_data_structures_engine import SecurityDataStructuresEngine


class TestSecurityDataStructuresEngine(unittest.TestCase):
    """
    Siber güvenlikte listeler, sözlükler ve kümelerin doğru kullanımını denetleyen test sınıfı.
    """

    def setUp(self) -> None:
        """
        Her test öncesi izole bir motor örneği ve örnek veri setleri oluşturulur.
        """
        # Test izolesi için yeni motor nesnesi atanır
        self.engine = SecurityDataStructuresEngine()
        # Test beslemesi A tanımlanır
        self.feed_a = ["198.51.100.10", "203.0.113.5", "192.0.2.1", "8.8.8.8"]
        # Test beslemesi B tanımlanır
        self.feed_b = ["198.51.100.10", "203.0.113.5", "192.0.2.2", "1.1.1.1"]
        # Meşru IP'lerden oluşan beyaz liste tanımlanır
        self.whitelist = ["8.8.8.8", "1.1.1.1"]

    def test_01_correlate_threat_feeds_intersection_and_whitelist(self) -> None:
        """
        Test 01: Küme kesişimi ve beyaz liste farkı ile yüksek güvenilirlikli tehditlerin ayrıştırıldığını doğrular.
        """
        # Korelasyon çalıştırılır
        result = self.engine.correlate_threat_feeds(self.feed_a, self.feed_b, self.whitelist)

        # Kesişimdeki tehditler test edilir: 198.51.100.10 ve 203.0.113.5
        expected_high = ["198.51.100.10", "203.0.113.5"]
        self.assertEqual(result["high_confidence_threats"], expected_high)
        self.assertEqual(result["high_confidence_count"], 2)

    def test_02_correlate_threat_feeds_union_and_exclusive(self) -> None:
        """
        Test 02: Birleşim ve münhasır (exclusive) küme farkı sayılarının doğruluğunu sınar.
        """
        # Korelasyon çalıştırılır
        result = self.engine.correlate_threat_feeds(self.feed_a, self.feed_b, self.whitelist)

        # Feed A'ya özgü beyaz listede olmayan: 192.0.2.1
        self.assertEqual(result["exclusive_to_feed_a_count"], 1)
        # Feed B'ye özgü beyaz listede olmayan: 192.0.2.2
        self.assertEqual(result["exclusive_to_feed_b_count"], 1)
        # Bastırılan beyaz liste isabet adedi (8.8.8.8 ve 1.1.1.1) 2 olmalıdır
        self.assertEqual(result["suppressed_whitelist_count"], 2)

    def test_03_correlate_threat_feeds_null_input_raises(self) -> None:
        """
        Test 03: Beslemelerden biri None olduğunda TypeError fırlatıldığını doğrular.
        """
        # feed_a None verildiğinde TypeError beklenir
        with self.assertRaises(TypeError):
            self.engine.correlate_threat_feeds(None, self.feed_b)  # type: ignore

    def test_04_correlate_threat_feeds_malformed_ip_raises(self) -> None:
        """
        Test 04: Beslemede malforme IP olduğunda ValueError fırlatılarak kümenin zehirlenmesinin engellendiğini doğrular.
        """
        # Malforme IP içeren liste
        bad_feed = ["198.51.100.10", "999.999.999.999"]
        with self.assertRaises(ValueError):
            self.engine.correlate_threat_feeds(bad_feed, self.feed_b)

    def test_05_correlate_threat_feeds_exceeds_max_limit_raises(self) -> None:
        """
        Test 05: Koleksiyon tavanı aşıldığında OverflowError ile bellek DoS saldırısının engellendiğini test eder.
        """
        # 50001 elemanlık devasa sanal liste oluşturulur
        oversized_feed = ["192.168.1.1"] * (self.engine.MAX_COLLECTION_LIMIT + 1)
        with self.assertRaises(OverflowError):
            self.engine.correlate_threat_feeds(oversized_feed, self.feed_b)

    def test_06_safe_deep_dict_get_existing_path(self) -> None:
        """
        Test 06: Güvenli sözlük okuyucunun var olan derin yolu başarıyla okuduğunu doğrular.
        """
        nested_data = {
            "network": {
                "security": {
                    "ips_mode": "INLINE_BLOCK"
                }
            }
        }
        val = self.engine.safe_deep_dict_get(nested_data, ["network", "security", "ips_mode"])
        self.assertEqual(val, "INLINE_BLOCK")

    def test_07_safe_deep_dict_get_missing_key_returns_default(self) -> None:
        """
        Test 07: Var olmayan anahtarda KeyError fırlatılmadan varsayılan değerin güvenle döndüğünü test eder.
        """
        nested_data = {"network": {"interface": "eth0"}}
        val = self.engine.safe_deep_dict_get(
            nested_data,
            ["network", "non_existent_key"],
            default="SAFE_DEFAULT"
        )
        self.assertEqual(val, "SAFE_DEFAULT")

    def test_08_safe_deep_dict_get_none_intermediate_node(self) -> None:
        """
        Test 08: Ara düğümlerden biri None olduğunda AttributeError oluşmadan varsayılanın döndüğünü doğrular.
        """
        nested_data = {"network": None}
        val = self.engine.safe_deep_dict_get(
            nested_data,
            ["network", "security", "firewall_action"],
            default="DENY"
        )
        self.assertEqual(val, "DENY")

    def test_09_safe_deep_dict_get_invalid_data_type(self) -> None:
        """
        Test 09: Ana veri dict yerine başka bir tip verildiğinde çökmeden varsayılan değer döndüğünü test eder.
        """
        val = self.engine.safe_deep_dict_get("STRING_NOT_DICT", ["a", "b"], default=100)  # type: ignore
        self.assertEqual(val, 100)

    def test_10_defensive_filter_ioc_list_avoids_mutation_skipping(self) -> None:
        """
        Test 10: Liste üzerinde gezinirken eleman atlamayan savunmacı filtrelemenin doğruluğunu test eder.
        """
        # Ardışık iki 'BAD_' elemanı içeren liste (klasik remove() döngüsünde ikinci BAD_ atlanır)
        raw_list = ["BAD_01", "BAD_02", "GOOD_01", "BAD_03"]
        filtered = self.engine.defensive_filter_ioc_list(raw_list, "BAD_")

        # Filtrelenmiş listede hiçbir 'BAD_' kalmadığı doğrulanır
        self.assertEqual(filtered, ["GOOD_01"])
        # Orijinal listenin bozulmadığı (in-place mutasyona uğramadığı) kanıtlanır
        self.assertEqual(len(raw_list), 4)

    def test_11_defensive_filter_ioc_list_invalid_type_raises(self) -> None:
        """
        Test 11: Liste dışı parametrede TypeError fırlatıldığını doğrular.
        """
        with self.assertRaises(TypeError):
            self.engine.defensive_filter_ioc_list("NOT_A_LIST", "BAD_")  # type: ignore

    def test_12_safe_set_ingest_converts_lists_and_dicts(self) -> None:
        """
        Test 12: Kümeye eklenen unhashable list ve dict nesnelerinin güvenli tuple'a çevrilerek eklendiğini doğrular.
        """
        # Değiştirilebilir liste ve sözlük içeren karışık veri koleksiyonu
        mixed_items = [
            ["192.168.1.1", 80],
            {"port": 443, "action": "ALLOW"},
            "SIMPLE_STRING"
        ]
        res_set = self.engine.safe_set_ingest(mixed_items)

        # 3 elemanın da TypeError fırlatılmadan kümeye dahil edildiği doğrulanır
        self.assertEqual(len(res_set), 3)
        self.assertIn(("192.168.1.1", 80), res_set)

    def test_13_detect_rule_shadowing_identifies_conflicts(self) -> None:
        """
        Test 13: Kural sözlüğü oluşturulurken aynı kural adının mükerrer tanımlanmasını tespit ettiğini doğrular.
        """
        pairs = [
            ("RULE_SSH", {"port": 22}),
            ("RULE_HTTP", {"port": 80}),
            ("RULE_SSH", {"port": 2222})  # Gölgeleme yapan çakışan kural
        ]
        shadowing_report = self.engine.detect_rule_shadowing(pairs)

        # Çakışmanın tespit edildiği test edilir
        self.assertTrue(shadowing_report["has_rule_shadowing"])
        self.assertEqual(shadowing_report["conflicting_rules"], ["RULE_SSH"])
        self.assertEqual(shadowing_report["total_unique_rules"], 2)

    def test_14_benchmark_lookup_performance_set_faster(self) -> None:
        """
        Test 14: Kümelerde O(1) aramanın listelerdeki O(N) aramadan daha hızlı çalıştığını doğrular.
        """
        # 3000 elemanlık kıyaslama yapılır
        bench = self.engine.benchmark_lookup_performance(element_count=3000)

        # Küme arama süresinin liste arama süresinden küçük veya eşit olduğu test edilir
        self.assertLessEqual(bench["set_lookup_seconds"], bench["list_lookup_seconds"])
        self.assertEqual(bench["element_count"], 3000.0)


if __name__ == "__main__":
    # Testler detaylı (-v) modda koşturulur
    unittest.main()
