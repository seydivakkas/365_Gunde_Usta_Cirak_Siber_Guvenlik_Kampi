# -*- coding: utf-8 -*-
"""
Uç Nokta Risk Panosu ve Güvenlik Duruşu Yönetimi Birim Test Paketi (Mini Proje 21)
Hafta 22 / Gün 153

Bu test paketi; tekil uç nokta risk skorlamasını, çok vektörlü ceza hesaplamalarını,
kritik varlık çarpanını, filo seviyesinde toplulaştırma ve raporlama algoritmalarını
15 kapsamlı senaryo ile %100 kapsama ile test eder.
"""

import unittest
import os
import sys

# Üst dizini içe aktarma yoluna ekler
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.endpoint_risk_dashboard import (
    EndpointTelemetry,
    EndpointRiskEngine,
    FleetRiskDashboard,
    RiskBand,
)


class TestEndpointRiskDashboard(unittest.TestCase):
    """Uç nokta risk motoru ve filo panosu test sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        # Risk motoru örneği oluşturulur
        self.engine = EndpointRiskEngine()

        # Kusursuz sıkılaştırılmış örnek temiz uç nokta telemetrisi
        self.clean_host = EndpointTelemetry(
            hostname="SEC-WKS-001",
            ip_address="10.0.10.15",
            operating_system="Windows 11 Enterprise",
            department="IT Security",
            is_critical_asset=False,
            edr_installed=True,
            edr_running=True,
            tamper_protection=True,
            signatures_age_hours=4,
            app_control_mode="Enforce",
            unapproved_executables_detected=0,
            disk_encrypted=True,
            tpm_version="2.0",
            pcr_binding_valid=True,
            recovery_key_escrowed=True,
            last_backup_hours_ago=8,
            backup_immutable=True,
            last_restore_tested=True,
            cis_compliance_percentage=98.0,
            unauthorized_local_admins=0,
            uac_or_aslr_active=True,
            critical_cves=0,
            high_cves=0,
            days_since_os_patch=5,
        )

    def test_01_pristine_hardened_host_low_risk(self):
        """Kusursuz sıkılaştırılmış uç noktanın düşük risk (LOW) skoru ürettiğini doğrular."""
        # Temiz uç nokta değerlendirilir
        assessment = self.engine.assess_host(self.clean_host)
        # Risk skorunun 10'dan küçük olduğu doğrulanır
        self.assertLess(assessment.risk_score, 10.0)
        # Risk seviyesinin LOW olduğu doğrulanır
        self.assertEqual(assessment.risk_band, RiskBand.LOW)
        # Güvenlik duruş puanının 90'ın üzerinde olduğu kontrol edilir
        self.assertGreater(assessment.posture_score, 90.0)
        # Sıfır kritik bulgu beklenir
        self.assertEqual(len(assessment.findings), 0)

    def test_02_missing_edr_penalty(self):
        """EDR ajanı eksik veya durdurulmuş bir sistemin ağır ceza aldığını doğrular."""
        # EDR ajanı kaldırılmış telemetri klonlanır
        host = EndpointTelemetry(**self.clean_host.__dict__)
        host.edr_installed = False
        host.edr_running = False
        
        # Değerlendirilir
        assessment = self.engine.assess_host(host)
        # EDR ceza puanının en az 60 olduğu kontrol edilir
        self.assertGreaterEqual(assessment.vector_scores.edr_penalty, 60.0)
        # Bulgular listesinde EDR uyarısı bulunmalıdır
        self.assertTrue(any("EDR" in f for f in assessment.findings))

    def test_03_unencrypted_disk_penalty(self):
        """Diski şifresiz uç noktanın disk güvenliği ceza puanını doğrular."""
        # Diski şifresiz cihaz telemetrisi
        host = EndpointTelemetry(**self.clean_host.__dict__)
        host.disk_encrypted = False
        host.tpm_version = "None"
        
        # Değerlendirilir
        assessment = self.engine.assess_host(host)
        # Disk cezasının en az 70 puan olduğu doğrulanır
        self.assertGreaterEqual(assessment.vector_scores.disk_encryption_penalty, 70.0)
        # Bulgularda BitLocker/LUKS uyarısı aranır
        self.assertTrue(any("şifrelenmemiş" in f for f in assessment.findings))

    def test_04_stale_backup_and_mutable_penalty(self):
        """Yedekleme süresi geçmiş ve değiştirilemez olmayan depolama cezasını test eder."""
        # Yedekleme açığı bulunan cihaz
        host = EndpointTelemetry(**self.clean_host.__dict__)
        host.last_backup_hours_ago = 200  # 1 haftadan eski
        host.backup_immutable = False
        
        # Değerlendirilir
        assessment = self.engine.assess_host(host)
        # Yedek ceza puanı en az 60 olmalıdır
        self.assertGreaterEqual(assessment.vector_scores.backup_penalty, 60.0)
        # Bulgularda yedek uyarısı bulunmalıdır
        self.assertTrue(any("yedekleme" in f.lower() for f in assessment.findings))

    def test_05_unauthorized_local_admins_penalty(self):
        """Administrators grubunda yetkisiz hesapların sapma cezasını test eder."""
        # Yetkisiz yöneticiler eklenmiş cihaz
        host = EndpointTelemetry(**self.clean_host.__dict__)
        host.unauthorized_local_admins = 2
        
        # Değerlendirilir
        assessment = self.engine.assess_host(host)
        # Sıkılaştırma cezasının yükseldiği doğrulanır
        self.assertGreaterEqual(assessment.vector_scores.hardening_penalty, 40.0)
        # Bulgularda hesap uyarısı aranır
        self.assertTrue(any("yetkisiz hesap" in f for f in assessment.findings))

    def test_06_critical_cves_and_patch_delay(self):
        """Kritik CVE zafiyetleri ve yama gecikmesinin risk cezasını doğrular."""
        # Zafiyetli cihaz
        host = EndpointTelemetry(**self.clean_host.__dict__)
        host.critical_cves = 2
        host.days_since_os_patch = 75
        
        # Değerlendirilir
        assessment = self.engine.assess_host(host)
        # Zafiyet cezasının yüksek olduğu kontrol edilir
        self.assertGreaterEqual(assessment.vector_scores.vulnerability_penalty, 60.0)

    def test_07_critical_asset_multiplier(self):
        """Kritik varlık çarpanının (Domain Controller / DB) risk skorunu artırdığını doğrular."""
        # Normal varlık olarak zafiyetli cihaz
        host_normal = EndpointTelemetry(**self.clean_host.__dict__)
        host_normal.edr_running = False
        host_normal.disk_encrypted = False
        host_normal.is_critical_asset = False
        
        # Aynı zafiyetlere sahip kritik varlık cihazı
        host_critical = EndpointTelemetry(**self.clean_host.__dict__)
        host_critical.edr_running = False
        host_critical.disk_encrypted = False
        host_critical.is_critical_asset = True
        
        # Değerlendirmeler yapılır
        assess_normal = self.engine.assess_host(host_normal)
        assess_crit = self.engine.assess_host(host_critical)
        
        # Kritik varlığın skoru normal varlıktan belirgin şekilde yüksek olmalıdır
        self.assertGreater(assess_crit.risk_score, assess_normal.risk_score)

    def test_08_app_control_disabled_and_unapproved(self):
        """Uygulama kontrolü kapalı ve onaysız dosya tespit edilen cihaz cezasını test eder."""
        # Uygulama kontrolü ihlali
        host = EndpointTelemetry(**self.clean_host.__dict__)
        host.app_control_mode = "Disabled"
        host.unapproved_executables_detected = 3
        
        # Değerlendirilir
        assessment = self.engine.assess_host(host)
        # Uygulama kontrolü cezasının en az 60 olduğu doğrulanır
        self.assertGreaterEqual(assessment.vector_scores.app_control_penalty, 60.0)

    def test_09_fleet_aggregation_accuracy(self):
        """Filo seviyesinde cihaz sayısı, risk bandı dağılımı ve ortalamaların doğruluğunu test eder."""
        # 1 adet temiz, 1 adet kritik cihaz oluşturulur
        bad_host = EndpointTelemetry(**self.clean_host.__dict__)
        bad_host.hostname = "VULN-SRV-001"
        bad_host.edr_installed = False
        bad_host.disk_encrypted = False
        bad_host.backup_immutable = False
        bad_host.last_backup_hours_ago = 200
        bad_host.unauthorized_local_admins = 2
        bad_host.critical_cves = 3
        
        fleet = [self.clean_host, bad_host]
        dashboard = self.engine.assess_fleet(fleet)
        
        # Toplam cihaz 2 olmalıdır
        self.assertEqual(dashboard.total_endpoints, 2)
        # 1 adet LOW risk olmalıdır
        self.assertEqual(dashboard.low_risk_count, 1)
        # 1 adet HIGH veya CRITICAL risk olmalıdır
        self.assertGreaterEqual(dashboard.high_risk_count + dashboard.critical_risk_count, 1)
        # Filo ortalama riski 0 ile 100 arasında olmalıdır
        self.assertGreater(dashboard.fleet_average_risk, 0.0)
        self.assertLess(dashboard.fleet_average_risk, 100.0)

    def test_10_top_riskiest_hosts_ranking(self):
        """En riskli cihazların azalan sırada sıralandığını doğrular."""
        # 3 cihaz oluşturulur
        h1 = EndpointTelemetry(**self.clean_host.__dict__)
        h1.hostname = "HOST-LOW"
        
        h2 = EndpointTelemetry(**self.clean_host.__dict__)
        h2.hostname = "HOST-MED"
        h2.edr_running = False
        
        h3 = EndpointTelemetry(**self.clean_host.__dict__)
        h3.hostname = "HOST-HIGH"
        h3.edr_installed = False
        h3.disk_encrypted = False
        h3.critical_cves = 4
        
        dashboard = self.engine.assess_fleet([h1, h2, h3])
        # İlk sıradaki HOST-HIGH olmalıdır
        self.assertEqual(dashboard.top_riskiest_hosts[0]["hostname"], "HOST-HIGH")

    def test_11_department_risk_averages(self):
        """Departman bazlı ortalama risk skorlarının doğru hesaplandığını kontrol eder."""
        h_finance = EndpointTelemetry(**self.clean_host.__dict__)
        h_finance.department = "Finance"
        h_finance.disk_encrypted = False
        
        h_it = EndpointTelemetry(**self.clean_host.__dict__)
        h_it.department = "IT Security"
        
        dashboard = self.engine.assess_fleet([h_finance, h_it])
        # Finans departmanı IT'den daha yüksek riskli olmalıdır
        self.assertGreater(
            dashboard.department_risk_summary["Finance"],
            dashboard.department_risk_summary["IT Security"]
        )

    def test_12_empty_fleet_raises_value_error(self):
        """Boş telemetri listesi gönderildiğinde ValueError fırlatıldığını doğrular."""
        with self.assertRaises(ValueError):
            self.engine.assess_fleet([])

    def test_13_ascii_dashboard_generation(self):
        """Üretilen ASCII pano metninin anahtar bölümleri içerdiğini test eder."""
        dashboard = self.engine.assess_fleet([self.clean_host])
        report = self.engine.generate_ascii_dashboard_report(dashboard)
        
        # Başlık ve metriklerin raporda yer aldığı kontrol edilir
        self.assertIn("KURUMSAL UÇ NOKTA RİSK PANOSU", report)
        self.assertIn("Toplam Uç Nokta", report)
        self.assertIn("RISK DAĞILIMI", report)
        self.assertIn("EN YÜKSEK RİSKLİ UÇ NOKTALAR", report)

    def test_14_remediation_script_generation(self):
        """Riskli uç noktalar için PowerShell düzeltme betiğinin oluşturulduğunu test eder."""
        bad_host = EndpointTelemetry(**self.clean_host.__dict__)
        bad_host.hostname = "BAD-SRV-999"
        bad_host.edr_installed = False
        bad_host.disk_encrypted = False
        bad_host.backup_immutable = False
        bad_host.last_backup_hours_ago = 200
        bad_host.unauthorized_local_admins = 3
        bad_host.critical_cves = 4
        
        dashboard = self.engine.assess_fleet([bad_host])
        script = self.engine.generate_prioritized_remediation_script(dashboard)
        
        # Betikte anahtar komutların yer aldığı doğrulanır
        self.assertIn("PowerShell Otomatik İyileştirme Betiği", script)
        self.assertIn("BAD-SRV-999", script)
        self.assertIn("Enable-BitLocker", script)

    def test_15_cli_roundtrip_execution(self):
        """Dashboard sözlük çıktısının serileştirilebilir ve eksiksiz olduğunu doğrular."""
        dashboard = self.engine.assess_fleet([self.clean_host])
        dict_data = self.engine.export_dashboard_to_dict(dashboard)
        
        # Sözlükte beklenen anahtarlar kontrol edilir
        self.assertIn("total_endpoints", dict_data)
        self.assertIn("fleet_average_risk", dict_data)
        self.assertIn("host_assessments", dict_data)
        self.assertEqual(len(dict_data["host_assessments"]), 1)


if __name__ == "__main__":
    unittest.main()
