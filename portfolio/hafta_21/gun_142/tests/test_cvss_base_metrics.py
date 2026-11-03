# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 142 - CVSS v3.1 Taban Metrikleri Birim Test Paketi.
15 kapsamlı birim testi ile FIRST şartnamesine uygun formül doğruluğunu,
vektör sözdizimi ayrıştırmasını, yuvarlama algoritmasını ve gerçek dünya zafiyetlerini test eder.
"""

# Birim testleri için standart Python unittest kütüphanesi
import unittest
# Dosya yolları ve işletim sistemi fonksiyonları
import os
# Sistem çalışma yolu yönetimi
import sys
# JSON verisi işleme
import json

# Uygulama modülünü sys.path içerisine dahil et
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.abspath(os.path.join(current_dir, "..", "uygulama"))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

# CVSS motorunu import et
from cvss_base_engine import CvssBaseEngine, CvssBaseMetrics, CvssCalculationResult


class TestCvssBaseEngine(unittest.TestCase):
    """
    CVSS v3.1 Taban Metrik Hesaplama Motoru Test Sınıfı.
    """

    def setUp(self):
        """
        Her test öncesinde motoru ilklendirir.
        """
        self.engine = CvssBaseEngine()
        self.benchmark_path = os.path.abspath(
            os.path.join(current_dir, "..", "ornek_veri", "cvss_benchmark_vectors.json")
        )

    def test_01_parse_valid_vector(self):
        """Test 01: Geçerli bir CVSS v3.1 vektör dizesinin doğru ayrıştırıldığını doğrular."""
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        m = self.engine.parse_vector_string(v)
        self.assertEqual(m.attack_vector, "N")
        self.assertEqual(m.attack_complexity, "L")
        self.assertEqual(m.privileges_required, "N")
        self.assertEqual(m.scope, "U")
        self.assertEqual(m.confidentiality, "H")

    def test_02_parse_vector_missing_prefix(self):
        """Test 02: Hatalı sürüm öneki içeren vektörde ValueError fırlatıldığını doğrular."""
        v = "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        with self.assertRaises(ValueError) as ctx:
            self.engine.parse_vector_string(v)
        self.assertIn("Hatalı CVSS sürüm öneki", str(ctx.exception))

    def test_03_parse_vector_missing_metric(self):
        """Test 03: Zorunlu 8 metrikten birinin eksik olması durumunda hata fırlatıldığını doğrular."""
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"  # S eksik
        with self.assertRaises(ValueError) as ctx:
            self.engine.parse_vector_string(v)
        self.assertIn("Eksik zorunlu CVSS metriği tespit edildi: 'S'", str(ctx.exception))

    def test_04_parse_vector_invalid_metric_value(self):
        """Test 04: Geçersiz metrik değerlerinde (örn: AV:X) ValueError fırlatıldığını test eder."""
        v = "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        with self.assertRaises(ValueError) as ctx:
            self.engine.parse_vector_string(v)
        self.assertIn("Geçersiz AV", str(ctx.exception))

    def test_05_calculate_log4shell_max_score_10(self):
        """Test 05: Log4Shell (CVE-2021-44228) vektörünün 10.0 ve CRITICAL verdiğini doğrular."""
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        res = self.engine.calculate_from_vector(v)
        self.assertEqual(res.base_score, 10.0)
        self.assertEqual(res.severity, "CRITICAL")
        self.assertEqual(res.impact_subscore, 6.0)
        self.assertEqual(res.exploitability_subscore, 3.9)

    def test_06_calculate_regresshion_score_8_1(self):
        """Test 06: regreSSHion (CVE-2024-6387) vektörünün tam 8.1 ve HIGH verdiğini test eder."""
        v = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        res = self.engine.calculate_from_vector(v)
        self.assertEqual(res.base_score, 8.1)
        self.assertEqual(res.severity, "HIGH")

    def test_07_calculate_heartbleed_score_7_5(self):
        """Test 07: Heartbleed (CVE-2014-0160) vektörünün tam 7.5 ve HIGH verdiğini doğrular."""
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        res = self.engine.calculate_from_vector(v)
        self.assertEqual(res.base_score, 7.5)
        self.assertEqual(res.severity, "HIGH")

    def test_08_calculate_zero_impact_none_severity(self):
        """Test 08: Hiçbir güvenlik etkisi olmayan (C:N/I:N/A:N) zafiyetin 0.0 ve NONE verdiğini test eder."""
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        res = self.engine.calculate_from_vector(v)
        self.assertEqual(res.base_score, 0.0)
        self.assertEqual(res.severity, "NONE")

    def test_09_roundup_edge_cases(self):
        """Test 09: FIRST Roundup yuvarlama fonksiyonunun sınır durumlarını doğrular."""
        self.assertEqual(self.engine.roundup(4.00), 4.0)
        self.assertEqual(self.engine.roundup(4.01), 4.1)
        self.assertEqual(self.engine.roundup(4.02), 4.1)
        self.assertEqual(self.engine.roundup(9.80001), 9.9)

    def test_10_scope_changed_impact_multiplier(self):
        """Test 10: Kapsam Değiştiğinde (S:C) 1.08 katsayısının ve değişen formülün uygulandığını doğrular."""
        # Unchanged Scope
        v_u = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        res_u = self.engine.calculate_from_vector(v_u)

        # Changed Scope
        v_c = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
        res_c = self.engine.calculate_from_vector(v_c)

        self.assertGreater(res_c.base_score, res_u.base_score)
        self.assertEqual(res_u.base_score, 8.8)
        self.assertEqual(res_c.base_score, 9.9)

    def test_11_compare_vectors_scope_impact(self):
        """Test 11: İki vektör karşılaştırıldığında Scope değişim farkının doğru hesaplandığını test eder."""
        v1 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        v2 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
        comp = self.engine.compare_vectors(v1, v2)
        self.assertEqual(comp["score_diff"], 1.1)
        self.assertIn("scope", comp["changed_metrics"])

    def test_12_compare_vectors_auth_impact(self):
        """Test 12: Yetki seviyesi None'dan High'a çıktığında skorun düştüğünü test eder."""
        v_none = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
        v_high = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"  # 7.2
        comp = self.engine.compare_vectors(v_none, v_high)
        self.assertLess(comp["score2"], comp["score1"])
        self.assertEqual(comp["score1"], 9.8)
        self.assertEqual(comp["score2"], 7.2)

    def test_13_batch_evaluate_distribution(self):
        """Test 13: Toplu vektör değerlendirmesinde istatistiksel dağılımın hesaplandığını doğrular."""
        v_list = [
            {"cve_id": "CVE-1", "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},  # 10.0 (CRITICAL)
            {"cve_id": "CVE-2", "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},  # 8.1 (HIGH)
            {"cve_id": "CVE-3", "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}   # 5.9 (MEDIUM)
        ]
        report = self.engine.batch_evaluate(v_list)
        self.assertEqual(report["total_evaluated"], 3)
        self.assertEqual(report["severity_distribution"]["CRITICAL"], 1)
        self.assertEqual(report["severity_distribution"]["HIGH"], 1)
        self.assertEqual(report["severity_distribution"]["MEDIUM"], 1)

    def test_14_metric_breakdown_descriptions(self):
        """Test 14: İnsan tarafından okunabilir metrik açıklamalarının eksiksiz üretildiğini doğrular."""
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        res = self.engine.calculate_from_vector(v)
        self.assertEqual(len(res.metric_breakdown), 8)
        self.assertIn("Network", res.metric_breakdown["Attack Vector (AV)"])
        self.assertIn("High", res.metric_breakdown["Confidentiality (C)"])

    def test_15_all_benchmark_vectors_verified(self):
        """Test 15: Benchmark dosyasındaki tüm gerçek dünya vektörlerinin resmî skorlarla %100 uyuştuğunu doğrular."""
        if os.path.exists(self.benchmark_path):
            with open(self.benchmark_path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            for item in data.get("vectors", []):
                v_str = item["vector_string"]
                exp_score = item["expected_base_score"]
                exp_sev = item["expected_severity"]
                res = self.engine.calculate_from_vector(v_str)
                self.assertEqual(res.base_score, exp_score, f"Skor uyuşmazlığı: {item['cve_id']}")
                self.assertEqual(res.severity, exp_sev, f"Şiddet uyuşmazlığı: {item['cve_id']}")


if __name__ == "__main__":
    unittest.main()
