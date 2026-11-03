# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 122: Savunma Derinliği ve Kontrol Tipleri Birim Testleri.
15 birim test senaryosu: 7 katman modellemesi, kontrol tipleri, SPoF (CWE-1008),
katman boşluğu (CWE-653), gözetimsiz katmanlar ve çok katmanlı saldırı simülasyonu.
"""

# Standart test çerçevesi unittest içe aktarılıyor
import unittest
# Sistem yolu ve dosya işlemleri için sys ve os içe aktarılıyor
import sys
import os

# Uygulama modülünü arama yoluna dahil etmek için dizin ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
sys.path.insert(0, app_dir)

# Test edilecek motor sınıfları ve istisnalar içe aktarılıyor
from defense_in_depth_engine import (
    DefenseInDepthManager,
    DefenseLayer,
    ControlType,
    AttackCategory,
    LayerControl,
    AttackStep,
    AttackScenario,
    DefenseInDepthError,
    DefenseGapError,
    SinglePointOfFailureError,
    UnmonitoredLayerError,
    InvalidControlConfigurationError,
    DuplicateControlError
)


class TestDefenseInDepthEngine(unittest.TestCase):
    """Savunma Derinliği ve Kontrol Tipleri test sınıfı."""

    def setUp(self):
        """Her testten önce temiz bir mimari örneği oluşturur."""
        self.manager = DefenseInDepthManager(architecture_name="Kurumsal Savunma Test Mimarisi")

    def test_01_all_seven_layers_enum_representation(self):
        """7 temel savunma derinliği katmanının eksiksiz tanımlandığı doğrulanır."""
        # Toplam 7 katman olmalıdır
        self.assertEqual(len(DefenseLayer), 7)
        # Katman adları doğrulanır
        expected_layers = {
            DefenseLayer.PHYSICAL,
            DefenseLayer.PERIMETER,
            DefenseLayer.INTERNAL_NETWORK,
            DefenseLayer.HOST,
            DefenseLayer.APPLICATION,
            DefenseLayer.DATA,
            DefenseLayer.IDENTITY
        }
        self.assertEqual(set(DefenseLayer), expected_layers)

    def test_02_control_types_enum_coverage(self):
        """Tüm 5 kontrol tipinin (Önleyici, Tespit, Düzeltici, Telafi, Caydırıcı) varlığı doğrulanır."""
        self.assertEqual(len(ControlType), 5)
        self.assertIn(ControlType.PREVENTIVE, ControlType)
        self.assertIn(ControlType.DETECTIVE, ControlType)
        self.assertIn(ControlType.CORRECTIVE, ControlType)
        self.assertIn(ControlType.COMPENSATING, ControlType)
        self.assertIn(ControlType.DETERRENT, ControlType)

    def test_03_invalid_control_effectiveness_out_of_bounds(self):
        """Kontrol etkinliği 0.01 altı veya 0.99 üstü olduğunda hata vermelidir."""
        # 0.00 etkinlik geçersizdir
        c_low = LayerControl("C-01", "Etkisiz", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 0.00)
        with self.assertRaises(InvalidControlConfigurationError):
            c_low.validate()
        # 1.05 etkinlik geçersizdir
        c_high = LayerControl("C-02", "Aşırı", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 1.05)
        with self.assertRaises(InvalidControlConfigurationError):
            c_high.validate()

    def test_04_duplicate_control_registration_rejected(self):
        """Aynı ID'ye sahip iki kontrol eklenmeye çalışıldığında DuplicateControlError fırlatılmalıdır."""
        c1 = LayerControl("CTRL-DUP", "Firewall 1", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 0.85)
        c2 = LayerControl("CTRL-DUP", "Firewall 2", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 0.90)
        self.manager.add_control(c1)
        with self.assertRaises(DuplicateControlError):
            self.manager.add_control(c2)

    def test_05_layer_gap_audit_detection(self):
        """Bir katmanda hiçbir kontrol olmadığında CWE-653 Katman Boşluğu tespit edilmelidir."""
        # Yalnızca Perimeter katmanına kontrol eklenir, diğer 6 katman boştur
        c1 = LayerControl("C-FW", "Firewall", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 0.85)
        self.manager.add_control(c1)
        passed, flaws = self.manager.audit_architecture_resilience()
        self.assertFalse(passed)
        # Katman boşluğu ihlali bulunmalıdır
        self.assertTrue(any("KATMAN BOŞLUĞU (CWE-653)" in f for f in flaws))

    def test_06_unmonitored_layer_blind_spot_detection(self):
        """Önleyici kontrol varken Tespit Edici (Detective) kontrol yoksa kör nokta (Blind Spot) uyarısı verilmelidir."""
        # Sadece önleyici kontrol eklenir
        c_prev = LayerControl("C-WAF", "WAF", DefenseLayer.APPLICATION, ControlType.PREVENTIVE, 0.90)
        self.manager.add_control(c_prev)
        passed, flaws = self.manager.audit_architecture_resilience()
        self.assertTrue(any("GÖZETİMSİZ KATMAN (Blind Spot)" in f for f in flaws))

    def test_07_passive_layer_no_preventive_detection(self):
        """Sadece Tespit Edici kontrol olup Önleyici bariyer olmayan katman PASİF KATMAN olarak uyarılmalıdır."""
        # Sadece tespit kontrolü eklenir
        c_det = LayerControl("C-SIEM", "SIEM Ajanı", DefenseLayer.HOST, ControlType.DETECTIVE, 0.85)
        self.manager.add_control(c_det)
        passed, flaws = self.manager.audit_architecture_resilience()
        self.assertTrue(any("PASİF KATMAN" in f for f in flaws))

    def test_08_spof_single_point_of_failure_detection(self):
        """Bir saldırı kategorisine karşı tüm mimaride yalnızca 1 önleyici kontrol varsa SPoF (CWE-1008) uyarısı verilmelidir."""
        # SQL Injection için yalnızca WAF tanımlanır (başka hiçbir katmanda SQLi önleme yok)
        c_waf = LayerControl(
            "C-WAF-SQL", "WAF", DefenseLayer.APPLICATION, ControlType.PREVENTIVE, 0.90,
            supported_attacks=[AttackCategory.SQL_INJECTION]
        )
        self.manager.add_control(c_waf)
        passed, flaws = self.manager.audit_architecture_resilience()
        self.assertTrue(any("TEK HATA NOKTASI / SPoF (CWE-1008)" in f for f in flaws))

    def test_09_enforce_resilience_raises_defense_gap_error(self):
        """Boş katman varken enforce_resilience çağrıldığında DefenseGapError fırlatılmalıdır."""
        # Tamamen boş mimaride çalıştırma
        with self.assertRaises(DefenseGapError):
            self.manager.enforce_resilience()

    def test_10_enforce_resilience_raises_spof_error(self):
        """Tüm katmanlara genel kontrol eklenip bir saldırıda tek kontrol bırakıldığında SinglePointOfFailureError fırlatılmalıdır."""
        # Her katmana birer önleyici ve tespit kontrolü eklenir
        for layer in DefenseLayer:
            p = LayerControl(f"P-{layer.name}", f"P {layer.name}", layer, ControlType.PREVENTIVE, 0.8)
            d = LayerControl(f"D-{layer.name}", f"D {layer.name}", layer, ControlType.DETECTIVE, 0.8)
            self.manager.add_control(p)
            self.manager.add_control(d)
        # Ancak Ransomware kategorisi sadece 1 kontrolde destekleniyor olsun
        p_ransom = LayerControl(
            "P-EDR-RANSOM", "EDR Ransomware", DefenseLayer.HOST, ControlType.PREVENTIVE, 0.9,
            supported_attacks=[AttackCategory.RANSOMWARE]
        )
        self.manager.add_control(p_ransom)
        with self.assertRaises(SinglePointOfFailureError):
            self.manager.enforce_resilience()

    def test_11_successful_multi_layer_attack_interception(self):
        """Düşük kaçınma gücüne (0.4) sahip saldırı Çevre katmanındaki Firewall (%90) tarafından durdurulmalıdır."""
        fw = LayerControl(
            "C-FW-01", "Dış Firewall", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 0.90,
            supported_attacks=[AttackCategory.RANSOMWARE]
        )
        self.manager.add_control(fw)
        sc = AttackScenario(
            scenario_id="SC-01",
            name="Zayıf Fidye Yazılımı Saldırısı",
            category=AttackCategory.RANSOMWARE,
            steps=[
                AttackStep(1, DefenseLayer.PERIMETER, "Port Taraması", 0.40),
                AttackStep(2, DefenseLayer.HOST, "Payload Yürütme", 0.40)
            ]
        )
        self.manager.add_scenario(sc)
        outcome = self.manager.simulate_attack("SC-01")
        self.assertTrue(outcome.stopped)
        self.assertEqual(outcome.stopped_at_layer, DefenseLayer.PERIMETER)
        self.assertFalse(outcome.data_compromised)
        self.assertEqual(outcome.total_layers_penetrated, 0)

    def test_12_deep_attack_stopped_at_inner_layer(self):
        """Çevre ve ağı aşan gelişmiş bir saldırı, Sunucu katmanındaki EDR tarafından engellenmelidir."""
        # Çevrede zayıf kontrol (0.50 etkinlik)
        c_weak = LayerControl("C-WEAK", "Eski Firewall", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 0.50,
                              supported_attacks=[AttackCategory.RANSOMWARE])
        # Sunucuda güçlü EDR (0.95 etkinlik)
        c_edr = LayerControl("C-EDR", "Gelişmiş EDR", DefenseLayer.HOST, ControlType.PREVENTIVE, 0.95,
                             supported_attacks=[AttackCategory.RANSOMWARE])
        self.manager.add_control(c_weak)
        self.manager.add_control(c_edr)

        sc = AttackScenario(
            scenario_id="SC-DEEP",
            name="Gelişmiş Tehdit",
            category=AttackCategory.RANSOMWARE,
            steps=[
                AttackStep(1, DefenseLayer.PERIMETER, "WAF Bypass", 0.70),  # 0.70 > 0.50 -> Geçer
                AttackStep(2, DefenseLayer.HOST, "Memory Injection", 0.70)   # 0.70 < 0.95 -> EDR Durdurur
            ]
        )
        self.manager.add_scenario(sc)
        outcome = self.manager.simulate_attack("SC-DEEP")
        self.assertTrue(outcome.stopped)
        self.assertEqual(outcome.stopped_at_layer, DefenseLayer.HOST)
        self.assertEqual(outcome.total_layers_penetrated, 1)  # Perimeter delindi
        self.assertFalse(outcome.data_compromised)

    def test_13_complete_defense_breach_data_compromise(self):
        """Tüm katmanlardaki kontrolleri aşan saldırı Veri katmanına ulaşıp veri ihlali üretmelidir."""
        c1 = LayerControl("C1", "Zayıf 1", DefenseLayer.APPLICATION, ControlType.PREVENTIVE, 0.30,
                          supported_attacks=[AttackCategory.SQL_INJECTION])
        c2 = LayerControl("C2", "Zayıf 2", DefenseLayer.DATA, ControlType.PREVENTIVE, 0.40,
                          supported_attacks=[AttackCategory.SQL_INJECTION])
        self.manager.add_control(c1)
        self.manager.add_control(c2)

        sc = AttackScenario(
            scenario_id="SC-BREACH",
            name="Kritik SQLi Saldırısı",
            category=AttackCategory.SQL_INJECTION,
            steps=[
                AttackStep(1, DefenseLayer.APPLICATION, "Zero-Day SQLi", 0.90),
                AttackStep(2, DefenseLayer.DATA, "Direct DB Dump", 0.90)
            ]
        )
        self.manager.add_scenario(sc)
        outcome = self.manager.simulate_attack("SC-BREACH")
        self.assertFalse(outcome.stopped)
        self.assertTrue(outcome.data_compromised)
        self.assertEqual(outcome.total_layers_penetrated, 2)

    def test_14_detective_alarm_triggered_even_if_penetrated(self):
        """Önleyici kontrol aşılsa bile tespit kontrolü alarm üretmelidir."""
        # Zayıf önleyici kontrol (0.30)
        p = LayerControl("P-ZAYIF", "Zayıf Giriş", DefenseLayer.PERIMETER, ControlType.PREVENTIVE, 0.30,
                         supported_attacks=[AttackCategory.CREDENTIAL_STUFFING])
        # Güçlü SIEM tespit kontrolü (0.90)
        d = LayerControl("D-SIEM", "SIEM Log İzleme", DefenseLayer.PERIMETER, ControlType.DETECTIVE, 0.90)
        self.manager.add_control(p)
        self.manager.add_control(d)

        sc = AttackScenario(
            scenario_id="SC-ALARM",
            name="Kaba Kuvvet",
            category=AttackCategory.CREDENTIAL_STUFFING,
            steps=[AttackStep(1, DefenseLayer.PERIMETER, "Brute Force", 0.80)]
        )
        self.manager.add_scenario(sc)
        outcome = self.manager.simulate_attack("SC-ALARM")
        # Katman delindi ama alarm çalmalı
        res = outcome.layer_results[0]
        self.assertTrue(res.penetrated)
        self.assertTrue(res.detected)
        self.assertEqual(res.detected_by_control, "SIEM Log İzleme")

    def test_15_resilient_architecture_full_audit_and_report_generation(self):
        """Tam konfigüre edilmiş 7 katmanlı sağlam mimarinin denetimi ve rapor üretimi doğrulanır."""
        # 7 katmanın her birine en az 2 önleyici ve 1 tespit edici kontrol eklenir (tüm saldırı tipleri desteklenir)
        all_attacks = list(AttackCategory)
        for layer in DefenseLayer:
            c_prev1 = LayerControl(f"P1-{layer.name}", f"P1 {layer.name}", layer, ControlType.PREVENTIVE, 0.85, all_attacks)
            c_prev2 = LayerControl(f"P2-{layer.name}", f"P2 {layer.name}", layer, ControlType.PREVENTIVE, 0.80, all_attacks)
            c_det = LayerControl(f"D1-{layer.name}", f"D1 {layer.name}", layer, ControlType.DETECTIVE, 0.90)
            self.manager.add_control(c_prev1)
            self.manager.add_control(c_prev2)
            self.manager.add_control(c_det)

        passed, flaws = self.manager.audit_architecture_resilience()
        self.assertTrue(passed)
        self.assertEqual(len(flaws), 0)
        # enforce_resilience hata vermemelidir
        self.manager.enforce_resilience()
        # Markdown raporu üretilir
        report = self.manager.generate_defense_matrix_report()
        self.assertIn("MİMARİ SAĞLAM", report)
        self.assertIn("Fiziksel_Guvenlik", report)
        self.assertIn("Veri_ve_Depolama", report)


if __name__ == "__main__":
    unittest.main()
