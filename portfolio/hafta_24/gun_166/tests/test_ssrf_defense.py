# -*- coding: utf-8 -*-
"""
Gün 166: SSRF Savunma Birim Testleri (test_ssrf_defense.py)

Bu test paketi; Yerel döngü (Loopback), RFC 1918 özel ağları, Bulut Metaveri
Servisi (169.254.169.254), yasaklı şemaları (file://, gopher://), gizlenmiş IP
biçimlerini (Integer, Hex, Octal), IPv6-mapped formatlarını, Taşıyıcı NAT bloklarını,
DNS Rebinding risklerini ve HTTP Açık Yönlendirme (Open Redirect) atlatmalarını
15 kapsamlı birim test senaryosuyla doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import os  # Dosya ve dizin yolu işlemleri
import sys  # Sistem çalışma yolu yönetimi
import unittest  # Birim test çerçevesi

# Uygulama dizininin eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Test dizini
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # En başa ekle

# Test edilecek savunma motoru bileşenleri
from ssrf_defense_engine import (
    SSRFDefenseEngine,  # Merkezi motor
    MockInternalNetwork,  # Sanal iç ağ
    MockSafeHTTPClient,  # Güvenli HTTP istemcisi
    EnterpriseSSRFPolicy,  # Kurumsal politika
    SSRFRiskType  # Tehdit türleri
)


class TestSSRFDefenseEngine(unittest.TestCase):
    """SSRF ve ağ seviyesi güvenlik filtreleri için 15 fonksiyonel birim test sınıfı."""

    def setUp(self):
        """Her testten önce temiz motor, sahte ağ ve istemci hazırlanır."""
        self.engine = SSRFDefenseEngine()  # Varsayılan kurumsal motor
        self.mock_net = MockInternalNetwork()  # Sanal iç ağ
        self.client = MockSafeHTTPClient(engine=self.engine, mock_net=self.mock_net)  # İstemci

    def test_01_loopback_ip_blocked(self):
        """1. Test: 127.0.0.1 yerel döngü adresinin LOOPBACK_ACCESS riskiyle engellendiğini doğrular."""
        res = self.engine.validate_url("http://127.0.0.1:8080/admin")  # Loopback URL
        self.assertFalse(res.is_safe)  # Güvensiz bulunmalı
        self.assertEqual(res.risk_type, SSRFRiskType.LOOPBACK_ACCESS)  # Risk türü doğrulanır
        self.assertIn("Yerel döngü", res.rejection_reason)  # Reddetme gerekçesi

    def test_02_cloud_metadata_ip_blocked(self):
        """2. Test: 169.254.169.254 bulut metaveri IP'sinin engellendiğini doğrular."""
        res = self.engine.validate_url("http://169.254.169.254/latest/meta-data/")  # Metadata URL
        self.assertFalse(res.is_safe)  # Güvensiz bulunmalı
        self.assertEqual(res.risk_type, SSRFRiskType.CLOUD_METADATA_ACCESS)  # Metadata riski
        self.assertIn("Bulut Metaveri Servisi", res.rejection_reason)  # Gerekçe kontrolü

    def test_03_rfc1918_10_network_blocked(self):
        """3. Test: 10.0.0.0/8 özel ağ bloğunun PRIVATE_NETWORK_ACCESS ile engellendiğini doğrular."""
        res = self.engine.validate_url("http://10.0.0.5:5432/status")  # 10.x IP
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, SSRFRiskType.PRIVATE_NETWORK_ACCESS)  # Özel ağ türü

    def test_04_rfc1918_172_network_blocked(self):
        """4. Test: 172.16.0.0/12 özel ağ bloğunun engellendiğini doğrular."""
        res = self.engine.validate_url("http://172.20.10.1/internal-api")  # 172.20.x IP
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, SSRFRiskType.PRIVATE_NETWORK_ACCESS)  # Özel ağ türü

    def test_05_rfc1918_192_network_blocked(self):
        """5. Test: 192.168.0.0/16 ev/ofis ağ bloğunun engellendiğini doğrular."""
        res = self.engine.validate_url("http://192.168.1.1/modem-config")  # 192.168.x IP
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, SSRFRiskType.PRIVATE_NETWORK_ACCESS)  # Özel ağ türü

    def test_06_disallowed_schemes_rejected(self):
        """6. Test: file://, gopher:// gibi tehlikeli şemaların DISALLOWED_SCHEME ile reddedildiğini doğrular."""
        res_file = self.engine.validate_url("file:///etc/passwd")  # Yerel dosya şeması
        self.assertFalse(res_file.is_safe)  # Engellenmeli
        self.assertEqual(res_file.risk_type, SSRFRiskType.DISALLOWED_SCHEME)  # Şema riski
        res_gopher = self.engine.validate_url("gopher://127.0.0.1:6379/_flushall")  # Gopher protokolü
        self.assertFalse(res_gopher.is_safe)  # Engellenmeli
        self.assertEqual(res_gopher.risk_type, SSRFRiskType.DISALLOWED_SCHEME)  # Şema riski

    def test_07_obfuscated_integer_ip_blocked(self):
        """7. Test: 2130706433 tamsayı (DWORD) biçimindeki 127.0.0.1 adresinin çözülüp engellendiğini doğrular."""
        res = self.engine.validate_url("http://2130706433/admin")  # DWORD IP formatı
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.details.get("normalized_ip"), "127.0.0.1")  # Normalize edilmiş IP
        self.assertEqual(res.risk_type, SSRFRiskType.LOOPBACK_ACCESS)  # Loopback olarak saptanmalı

    def test_08_obfuscated_hex_ip_blocked(self):
        """8. Test: 0x7f000001 Onaltılık (Hex) biçimindeki 127.0.0.1 adresinin çözülüp engellendiğini doğrular."""
        res = self.engine.validate_url("http://0x7f000001/admin")  # Hex IP formatı
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.details.get("normalized_ip"), "127.0.0.1")  # Çözülen IP
        self.assertEqual(res.risk_type, SSRFRiskType.LOOPBACK_ACCESS)  # Loopback riski

    def test_09_obfuscated_octal_ip_blocked(self):
        """9. Test: 0177.0.0.1 Sekizli (Octal) biçimindeki 127.0.0.1 adresinin çözülüp engellendiğini doğrular."""
        res = self.engine.validate_url("http://0177.0.0.1/admin")  # Octal IP formatı
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.details.get("normalized_ip"), "127.0.0.1")  # Çözülen IP
        self.assertEqual(res.risk_type, SSRFRiskType.LOOPBACK_ACCESS)  # Loopback riski

    def test_10_ipv6_loopback_and_mapped_blocked(self):
        """10. Test: [::1] ve [::ffff:127.0.0.1] IPv6 loopback adreslerinin engellendiğini doğrular."""
        res_v6 = self.engine.validate_url("http://[::1]/admin")  # IPv6 loopback
        self.assertFalse(res_v6.is_safe)  # Engellenmeli
        self.assertEqual(res_v6.risk_type, SSRFRiskType.LOOPBACK_ACCESS)  # Loopback riski
        res_mapped = self.engine.validate_url("http://[::ffff:127.0.0.1]/admin")  # Mapped v4 in v6
        self.assertFalse(res_mapped.is_safe)  # Engellenmeli
        self.assertEqual(res_mapped.risk_type, SSRFRiskType.LOOPBACK_ACCESS)  # Loopback riski

    def test_11_carrier_grade_nat_cgnat_blocked(self):
        """11. Test: 100.64.0.1 (Carrier-Grade NAT) ayrılmış bloğunun engellendiğini doğrular."""
        res = self.engine.validate_url("http://100.64.0.1/internal")  # CGNAT IP
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, SSRFRiskType.LINK_LOCAL_RESERVED)  # Ayrılmış IP riski

    def test_12_safe_public_url_allowed(self):
        """12. Test: Kamu genel API'si gibi meşru bir dış URL'nin başarıyla onaylandığını doğrular."""
        # Sahte DNS resolver genel bir IP (8.8.8.8) dönecek şekilde ayarlanır
        self.engine.dns_resolver = lambda host: ["8.8.8.8"]  # Güvenli genel IP
        res = self.engine.validate_url("https://api.kamu.gov.tr/hava-durumu")  # Genel URL
        self.assertTrue(res.is_safe)  # Onaylanmalı
        self.assertIsNone(res.risk_type)  # Sıfır risk

    def test_13_safe_client_blocks_open_redirect_to_metadata(self):
        """13. Test: Güvenli istemcinin 302 yönlendirmesiyle 169.254.169.254'e gitmeyi 403 ile engellediğini doğrular."""
        # İlk URL'nin genel IP'ye çözülmesi sağlanır
        self.engine.dns_resolver = lambda host: ["93.184.216.34"]  # Genel IP
        resp = self.client.safe_fetch("https://public-service.com/redirect-to-metadata")  # Yönlendiren URL
        self.assertTrue(resp.is_blocked)  # İstemci engellemeli
        self.assertEqual(resp.status_code, 403)  # 403 Forbidden
        self.assertIn("Bulut Metaveri Servisi", resp.block_reason)  # Metadata engeli doğrulanır

    def test_14_vulnerable_client_leaks_metadata(self):
        """14. Test: Zafiyetli istemcinin hiçbir kontrol yapmadan AWS metaveri gizli anahtarını sızdırdığını doğrular."""
        resp = self.client.vulnerable_fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role")
        self.assertFalse(resp.is_blocked)  # ZAFİYET: Engellenmedi
        self.assertEqual(resp.status_code, 200)  # 200 OK döndü
        self.assertIn("SecretAccessKey", resp.body)  # Gizli AWS anahtarı sızdırıldı

    def test_15_dns_rebinding_detection(self):
        """15. Test: Alan adının iç ağdaki 127.0.0.1 IP'sine çözümlendiğinde DNS sorgusunun engellendiğini doğrular."""
        # Saldırganın kontrolündeki domain 127.0.0.1 dönüyor (DNS Rebinding simülasyonu)
        self.engine.dns_resolver = lambda host: ["127.0.0.1"]  # Zararlı DNS kaydı
        res = self.engine.validate_url("http://attacker-controlled-rebinding.com/admin")
        self.assertFalse(res.is_safe)  # Engellenmeli
        self.assertEqual(res.risk_type, SSRFRiskType.LOOPBACK_ACCESS)  # Loopback teşhisi
        self.assertIn("tehlikeli bir iç IP adresine çözümlendi", res.rejection_reason)


if __name__ == "__main__":
    unittest.main()
