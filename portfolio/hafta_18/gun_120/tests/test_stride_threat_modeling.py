# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 18 / Gün 120: STRIDE Tehdit Modelleme ve DREAD Risk Analizi Birim Test Paketi.
15 Kapsamlı Test Senaryosu (Microsoft STRIDE & DREAD Standartları).
"""

# Birim test çerçevesi için unittest kütüphanesi
import unittest
# Test edilecek modeller ve motor sınıflarının içe aktarılması
from uygulama.stride_threat_engine import (
    STRIDEThreatEngine,
    ElementType,
    STRIDECategory,
    DREADScore,
    InvalidDREADScoreError,
    MissingDataFlowEndpointError,
    UnmitigatedThreatSecurityError
)


class TestSTRIDEThreatModeling(unittest.TestCase):
    """STRIDE Tehdit Modelleme ve DREAD Risk Değerlendirme Testleri."""

    def setUp(self) -> None:
        """Her testten önce temiz ve standart bir mimari motoru kurar."""
        # Motor ilklendirilir
        self.engine = STRIDEThreatEngine(system_name="Test Finansal Mimari")

        # Standart DFD elemanları tanımlanır
        self.ext_user = self.engine.add_element("E_USER", "Müşteri Web İstemcisi", ElementType.EXTERNAL_ENTITY, "Internet")
        self.proc_api = self.engine.add_element("P_API", "Banka API Ağ Geçidi", ElementType.PROCESS, "DMZ")
        self.store_db = self.engine.add_element("D_CORE", "Müşteri Hesap Veritabanı", ElementType.DATA_STORE, "Secure_Core")

    def test_01_element_registration_and_matrix(self) -> None:
        """TEST 01: Process (Süreç) bileşeni tüm 6 STRIDE kategorisini (S, T, R, I, D, E) türetmelidir."""
        threats = self.engine.generate_threats_for_element("P_API")
        # Süreç için 6 tehdit üretilmelidir
        self.assertEqual(len(threats), 6)
        categories = {t.category for t in threats}
        self.assertEqual(
            categories,
            {
                STRIDECategory.SPOOFING,
                STRIDECategory.TAMPERING,
                STRIDECategory.REPUDIATION,
                STRIDECategory.INFORMATION_DISCLOSURE,
                STRIDECategory.DENIAL_OF_SERVICE,
                STRIDECategory.ELEVATION_OF_PRIVILEGE
            }
        )

    def test_02_external_entity_matrix(self) -> None:
        """TEST 02: Dış Varlık (External Entity) yalnızca Spoofing ve Repudiation (S, R) tehditlerini türetmelidir."""
        threats = self.engine.generate_threats_for_element("E_USER")
        self.assertEqual(len(threats), 2)
        categories = {t.category for t in threats}
        self.assertEqual(categories, {STRIDECategory.SPOOFING, STRIDECategory.REPUDIATION})

    def test_03_data_store_matrix(self) -> None:
        """TEST 03: Veri Deposu (Data Store) Tampering, Repudiation, Info Disclosure, DoS (T, R, I, D) türetmelidir."""
        threats = self.engine.generate_threats_for_element("D_CORE")
        self.assertEqual(len(threats), 4)
        categories = {t.category for t in threats}
        self.assertEqual(
            categories,
            {
                STRIDECategory.TAMPERING,
                STRIDECategory.REPUDIATION,
                STRIDECategory.INFORMATION_DISCLOSURE,
                STRIDECategory.DENIAL_OF_SERVICE
            }
        )

    def test_04_data_flow_matrix(self) -> None:
        """TEST 04: Veri Akışı (Data Flow) Tampering, Info Disclosure ve DoS (T, I, D) tehditlerini türetmelidir."""
        flow = self.engine.add_data_flow("F_TEST", "Test Akışı", "P_API", "D_CORE", "TCP/TLS", crosses_boundary=True)
        threats = self.engine.analyze_trust_boundary_flows()
        # Sınır aşan tek akış için 3 tehdit üretilmelidir
        self.assertEqual(len(threats), 3)
        categories = {t.category for t in threats}
        self.assertEqual(categories, {STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.DENIAL_OF_SERVICE})

    def test_05_dread_calculation_critical(self) -> None:
        """TEST 05: Yüksek metrikli DREAD nesnesi (9.0) CRITICAL risk seviyesi üretmelidir."""
        dread = DREADScore(damage=9, reproducibility=9, exploitability=9, affected_users=9, discoverability=9)
        self.assertEqual(dread.calculate_risk_score(), 9.0)
        self.assertEqual(dread.get_severity(), "CRITICAL")

    def test_06_dread_calculation_low(self) -> None:
        """TEST 06: Düşük metrikli DREAD nesnesi (2.2) LOW risk seviyesi üretmelidir."""
        dread = DREADScore(damage=2, reproducibility=2, exploitability=3, affected_users=2, discoverability=2)
        self.assertEqual(dread.calculate_risk_score(), 2.2)
        self.assertEqual(dread.get_severity(), "LOW")

    def test_07_invalid_dread_score_out_of_bounds(self) -> None:
        """TEST 07: 1-10 sınırları dışındaki DREAD puanı InvalidDREADScoreError vermelidir (CWE-20)."""
        # 11 puanı sınır dışıdır
        with self.assertRaises(InvalidDREADScoreError):
            DREADScore(damage=11, reproducibility=5, exploitability=5, affected_users=5, discoverability=5)
        # 0 puanı sınır dışıdır
        with self.assertRaises(InvalidDREADScoreError):
            DREADScore(damage=0, reproducibility=5, exploitability=5, affected_users=5, discoverability=5)

    def test_08_missing_flow_endpoint_error(self) -> None:
        """TEST 08: Modelde olmayan uç noktaya veri akışı bağlamak MissingDataFlowEndpointError vermelidir (CWE-20)."""
        with self.assertRaises(MissingDataFlowEndpointError):
            self.engine.add_data_flow("F_ERR", "Hatalı Akış", "E_USER", "NON_EXISTENT_NODE", "HTTPS")

    def test_09_automatic_trust_boundary_crossing_detection(self) -> None:
        """TEST 09: Farklı güven bölgeleri arasındaki veri akışında sınır aşımı otomatik saptanmalıdır."""
        # Internet -> DMZ geçişi
        flow1 = self.engine.add_data_flow("F_EXT", "Dış İstek", "E_USER", "P_API", "HTTPS")
        self.assertTrue(flow1.crosses_trust_boundary)

        # Aynı güven bölgesinde (DMZ -> DMZ) geçiş
        p_dmz2 = self.engine.add_element("P_WAF", "Web Application Firewall", ElementType.PROCESS, "DMZ")
        flow2 = self.engine.add_data_flow("F_INTRA", "İç Akış", p_dmz2.element_id, "P_API", "HTTP")
        self.assertFalse(flow2.crosses_trust_boundary)

    def test_10_trust_boundary_threat_generation(self) -> None:
        """TEST 10: Güven sınırı aşan akışların analizi yüksek riskli DREAD skorları atamalıdır."""
        self.engine.add_data_flow("F_CRITICAL", "Sınır Aşan Akış", "E_USER", "P_API", "HTTP/ClearText")
        threats = self.engine.analyze_trust_boundary_flows()
        for t in threats:
            # Sınır aşımında skor 7.0 üzerinde olmalıdır
            self.assertGreaterEqual(t.dread.calculate_risk_score(), 7.0)

    def test_11_apply_mitigation_score_reduction(self) -> None:
        """TEST 11: Tedbir uygulandığında tehdit is_mitigated=True olmalı ve DREAD skoru düşmelidir."""
        self.engine.generate_threats_for_element("P_API")
        t_id = "THREAT-P_API-SPO"
        initial_score = self.engine.threats[t_id].dread.calculate_risk_score()

        # mTLS tedbiri uygulanır
        self.engine.apply_mitigation(t_id, "X.509 Karşılıklı TLS (mTLS) ile çift yönlü kimlik teyidi")
        self.assertTrue(self.engine.threats[t_id].is_mitigated)
        new_score = self.engine.threats[t_id].dread.calculate_risk_score()
        self.assertLess(new_score, initial_score)

    def test_12_unmitigated_critical_threat_blocks_readiness(self) -> None:
        """TEST 12: Tedbirsiz kalan kritik tehdit canlıya geçiş denetiminde hata fırlatmalıdır (CWE-1025)."""
        self.engine.generate_threats_for_element("P_API")
        # Hiçbir tedbir uygulanmadığında
        with self.assertRaises(UnmitigatedThreatSecurityError):
            self.engine.validate_security_readiness()

    def test_13_security_readiness_pass(self) -> None:
        """TEST 13: Tüm yüksek/kritik tehditler çözüldüğünde canlıya geçiş onaylanmalıdır."""
        self.engine.generate_threats_for_element("P_API")
        # Tüm tehditlere tedbir uygulanır
        for t_id, threat in list(self.engine.threats.items()):
            self.engine.apply_mitigation(t_id, "Standart Güvenlik Kalkanı")

        ready, reasons = self.engine.validate_security_readiness()
        self.assertTrue(ready)
        self.assertIn("onaylı güvenlik tedbirleri", reasons[0])

    def test_14_markdown_report_generation(self) -> None:
        """TEST 14: Markdown tehdit modelleme raporu DFD özetini ve tehdit tablosunu içermelidir."""
        self.engine.generate_threats_for_element("E_USER")
        report = self.engine.export_threat_report_markdown()
        self.assertIn("STRIDE Tehdit Modelleme Raporu", report)
        self.assertIn("DREAD Skoru", report)
        self.assertIn("THREAT-E_USER-SPO", report)

    def test_15_audit_trail_logging(self) -> None:
        """TEST 15: Tüm modelleme adımları denetim günlüğüne zaman damgalı yazılmalıdır."""
        self.engine.generate_threats_for_element("E_USER")
        self.assertGreater(len(self.engine.audit_log), 0)
        events = [rec["event"] for rec in self.engine.audit_log]
        self.assertIn("ELEMENT_ADDED", events)
        self.assertIn("THREATS_GENERATED", events)


if __name__ == "__main__":
    unittest.main()
