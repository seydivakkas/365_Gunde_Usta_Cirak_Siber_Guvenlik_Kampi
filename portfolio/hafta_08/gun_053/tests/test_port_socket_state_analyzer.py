# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G053: Port, Soket ve Bağlantı Durumu Test Süiti.
Bu modül IANA port sınıflandırmasını, RFC 793/9293 TCP durum makinesi geçişlerini,
0.0.0.0 yetkisiz servis ifşasını (Insecure Bind Exposure), Reverse Shell tespitini,
SYN Flood ve TIME_WAIT yığılması anomalilerini ile negatif sınır kontrollerini doğrular.
Her bir kod satırı didaktik açıklamalarla zenginleştirilmiştir.
"""

import unittest  # Birim test süitini tanımlamak ve yürütmek için standart test kütüphanesi
from portfolio.hafta_08.gun_053.uygulama.port_socket_state_analyzer import (  # Uygulama modülünden sınıflar içe aktarılır
    PortClassifier,  # IANA port sınıflandırıcı bileşeni
    SocketEndpoint,  # Soket uç noktası veri yapısı
    SocketSecurityAuditor,  # Soket güvenlik denetim motoru
    SocketStateTransitionError,  # Kural dışı durum geçişi istisnası
    SocketValidationError,  # Soket doğrulama hatası istisnası
    TCPStateTransitionSimulator,  # Durum makinesi simülatörü
)  # İçe aktarma tanımı tamamlanır


class TestPortSocketStateAnalyzer(unittest.TestCase):  # Test sınıfı tanımı
    """G053 Port, Soket ve Bağlantı Durumu Test Senaryoları."""

    def setUp(self) -> None:  # Her test öncesi çalışan kurulum metodu
        """Test değişkenlerini ve güvenlik denetim motorunu hazırlar."""
        self.auditor = SocketSecurityAuditor()  # Güvenlik denetçisi nesnesi oluşturulur

    def test_port_classification_well_known(self) -> None:  # Test 1: Well-known portlar
        """Test 1: 0-1023 arasındaki portların WELL_KNOWN olarak sınıflandırıldığını doğrular."""
        res_ssh = PortClassifier.classify_port(22)  # Port 22 SSH sınıflandırılır
        self.assertEqual(res_ssh["kategori"], "WELL_KNOWN")  # Kategorinin WELL_KNOWN olduğu doğrulanır
        self.assertEqual(res_ssh["servis"], "SSH")  # Servis adının SSH olduğu teyit edilir
        res_https = PortClassifier.classify_port(443)  # Port 443 HTTPS sınıflandırılır
        self.assertEqual(res_https["kategori"], "WELL_KNOWN")  # Kategorinin WELL_KNOWN olduğu doğrulanır
        self.assertEqual(res_https["servis"], "HTTPS")  # Servis adının HTTPS olduğu teyit edilir

    def test_port_classification_registered(self) -> None:  # Test 2: Kayıtlı portlar
        """Test 2: 1024-49151 arasındaki portların REGISTERED ve hassas servis olarak tanındığını doğrular."""
        res_redis = PortClassifier.classify_port(6379)  # Port 6379 Redis sınıflandırılır
        self.assertEqual(res_redis["kategori"], "REGISTERED")  # Kategorinin REGISTERED olduğu test edilir
        self.assertEqual(res_redis["servis"], "REDIS")  # Servis adının REDIS olduğu doğrulanır
        self.assertTrue(res_redis["hassas_ic_servis_mi"])  # Hassas iç ağ servisi olduğu onaylanır
        res_pg = PortClassifier.classify_port(5432)  # Port 5432 PostgreSQL sınıflandırılır
        self.assertEqual(res_pg["servis"], "POSTGRESQL")  # PostgreSQL servisi doğrulanır
        self.assertTrue(res_pg["hassas_ic_servis_mi"])  # Veritabanı servisinin hassas olduğu onaylanır

    def test_port_classification_dynamic_ephemeral(self) -> None:  # Test 3: Ephemeral portlar
        """Test 3: 49152-65535 arasındaki portların DYNAMIC_PRIVATE (ephemeral) olduğunu doğrular."""
        res_eph = PortClassifier.classify_port(52140)  # Port 52140 sınıflandırılır
        self.assertEqual(res_eph["kategori"], "DYNAMIC_PRIVATE")  # Düşük öncelikli geçici port olduğu test edilir
        self.assertFalse(res_eph["hassas_ic_servis_mi"])  # Ephemeral portun hassas servis olmadığı doğrulanır

    def test_socket_endpoint_valid_creation(self) -> None:  # Test 4: Soket oluşturma
        """Test 4: Geçerli bir TCP soket uç noktasının özelliklerinin doğru hesaplandığını doğrular."""
        sock = SocketEndpoint(  # Parametre / ifade: sock = SocketEndpoint(
            protocol="TCP",  # Parametre / ifade: protocol="TCP",
            local_ip="0.0.0.0",  # Parametre / ifade: local_ip="0.0.0.0",
            local_port=80,  # Parametre / ifade: local_port=80,
            state="LISTEN",  # Parametre / ifade: state="LISTEN",
            pid=1500,  # Parametre / ifade: pid=1500,
            process_name="httpd.exe",  # Parametre / ifade: process_name="httpd.exe",
        )  # Web dinleme soketi oluşturulur
        self.assertTrue(sock.is_listening())  # Soketin dinleme durumunda olduğu test edilir
        self.assertTrue(sock.is_all_interfaces())  # 0.0.0.0 üzerinde olduğu doğrulanır
        self.assertFalse(sock.is_loopback_only())  # Sadece localhost olmadığı doğrulanır
        data = sock.to_dict()  # Sözlük temsili alınır
        self.assertEqual(data["yerel_soket"], "0.0.0.0:80")  # Soket dizgisinin doğruluğu teyit edilir

    def test_socket_endpoint_udp_support(self) -> None:  # Test 5: UDP soket desteği
        """Test 5: Durumsuz UDP soketlerinin NONE durumuyla güvenle modellendiğini doğrular."""
        udp_sock = SocketEndpoint(  # Parametre / ifade: udp_sock = SocketEndpoint(
            protocol="UDP",  # Parametre / ifade: protocol="UDP",
            local_ip="127.0.0.1",  # Parametre / ifade: local_ip="127.0.0.1",
            local_port=53,  # Parametre / ifade: local_port=53,
            state="NONE",  # Parametre / ifade: state="NONE",
            pid=2100,  # Parametre / ifade: pid=2100,
            process_name="dnsmasq",  # Parametre / ifade: process_name="dnsmasq",
        )  # UDP DNS soketi oluşturulur
        self.assertEqual(udp_sock.protocol, "TCP" if False else "UDP")  # Protokolün UDP olduğu teyit edilir
        self.assertTrue(udp_sock.is_listening())  # Port atanmış ve uzak port 0 ise dinleme kabul edilir
        self.assertTrue(udp_sock.is_loopback_only())  # Sadece loopback üzerinde olduğu doğrulanır

    def test_tcp_state_transition_active_open_to_established(self) -> None:  # Test 6: Aktif açılış
        """Test 6: İstemci aktif açılış geçişini (CLOSED -> SYN_SENT -> ESTABLISHED) doğrular."""
        sim = TCPStateTransitionSimulator(initial_state="CLOSED")  # Simülatör CLOSED başlatılır
        self.assertEqual(sim.current_state, "CLOSED")  # Başlangıç durumu kontrol edilir
        sim.transition_to("SYN_SENT")  # İstemci SYN gönderir
        self.assertEqual(sim.current_state, "SYN_SENT")  # Durumun SYN_SENT olduğu doğrulanır
        sim.transition_to("ESTABLISHED")  # Sunucudan SYN+ACK gelir, istemci ACK atar
        self.assertEqual(sim.current_state, "ESTABLISHED")  # Bağlantının kurulduğu doğrulanır
        self.assertEqual(sim.history, ["CLOSED", "SYN_SENT", "ESTABLISHED"])  # Tarihçe doğrulanır

    def test_tcp_state_transition_passive_open_to_established(self) -> None:  # Test 7: Pasif açılış
        """Test 7: Sunucu pasif açılış geçişini (CLOSED -> LISTEN -> SYN_RECEIVED -> ESTABLISHED) doğrular."""
        sim = TCPStateTransitionSimulator(initial_state="CLOSED")  # Simülatör başlatılır
        sim.transition_to("LISTEN")  # Sunucu soketi açıp dinlemeye başlar
        sim.transition_to("SYN_RECEIVED")  # İstemciden SYN gelir, sunucu SYN+ACK atar
        self.assertEqual(sim.current_state, "SYN_RECEIVED")  # Durum SYN_RECEIVED olmalıdır
        sim.transition_to("ESTABLISHED")  # İstemciden son ACK gelir, el sıkışma tamamlanır
        self.assertEqual(sim.current_state, "ESTABLISHED")  # Bağlantı kurulmuştur

    def test_tcp_state_transition_active_close_to_closed(self) -> None:  # Test 8: Aktif kapanış
        """Test 8: Aktif kapanış ve TIME_WAIT geçişini doğrular."""
        sim = TCPStateTransitionSimulator(initial_state="ESTABLISHED")  # ESTABLISHED ile başla
        sim.transition_to("FIN_WAIT_1")  # Uygulama FIN gönderir
        sim.transition_to("FIN_WAIT_2")  # Karşı taraf FIN'i onaylar (ACK)
        sim.transition_to("TIME_WAIT")  # Karşı taraf da FIN gönderir, son ACK iletilir
        self.assertEqual(sim.current_state, "TIME_WAIT")  # 2*MSL bekleme durumunda olduğu teyit edilir
        sim.transition_to("CLOSED")  # Zamanlayıcı dolar ve soket kapanır
        self.assertEqual(sim.current_state, "CLOSED")  # Kapalı durum doğrulanır

    def test_tcp_state_transition_invalid_rejected(self) -> None:  # Test 9: Kural dışı geçiş
        """Test 9: RFC 793 kural dışı doğrudan durum atlamalarının reddedildiğini doğrular."""
        sim = TCPStateTransitionSimulator(initial_state="LISTEN")  # Dinleme durumunda başla
        with self.assertRaises(SocketStateTransitionError):  # LISTEN'dan doğrudan ESTABLISHED'a geçilemez
            sim.transition_to("ESTABLISHED")  # SYN ve ACK adımları atlanamaz
        with self.assertRaises(SocketStateTransitionError):  # LISTEN'dan TIME_WAIT'e geçilemez
            sim.transition_to("TIME_WAIT")  # Geçersiz geçiş denenir

    def test_security_audit_insecure_bind_redis_exposure(self) -> None:  # Test 10: 0.0.0.0 Redis ifşası
        """Test 10: 0.0.0.0'a bağlanan hassas veritabanının CRITICAL_EXPOSURE olarak yakalandığını doğrular."""
        vuln_sock = SocketEndpoint(  # Parametre / ifade: vuln_sock = SocketEndpoint(
            protocol="TCP",  # Parametre / ifade: protocol="TCP",
            local_ip="0.0.0.0",  # Parametre / ifade: local_ip="0.0.0.0",
            local_port=6379,  # Parametre / ifade: local_port=6379,
            state="LISTEN",  # Parametre / ifade: state="LISTEN",
            pid=3300,  # Parametre / ifade: pid=3300,
            process_name="redis-server.exe",  # Parametre / ifade: process_name="redis-server.exe",
        )  # Dışa açık Redis soketi
        safe_sock = SocketEndpoint(  # Parametre / ifade: safe_sock = SocketEndpoint(
            protocol="TCP",  # Parametre / ifade: protocol="TCP",
            local_ip="127.0.0.1",  # Parametre / ifade: local_ip="127.0.0.1",
            local_port=5432,  # Parametre / ifade: local_port=5432,
            state="LISTEN",  # Parametre / ifade: state="LISTEN",
            pid=2400,  # Parametre / ifade: pid=2400,
            process_name="postgres.exe",  # Parametre / ifade: process_name="postgres.exe",
        )  # Güvenli localhost Postgres soketi
        report = self.auditor.audit_socket_table([vuln_sock, safe_sock])  # Denetim çalıştırılır
        self.assertGreaterEqual(report["toplam_bulgu_sayisi"], 1)  # En az 1 zafiyet bulunmalıdır
        exposure = [f for f in report["bulgular"] if f["kategori"] == "INSECURE_BIND_EXPOSURE"]  # İfşa bulguları
        self.assertEqual(len(exposure), 1)  # Tam 1 ifşa bulgusu yakalanmalıdır
        self.assertEqual(exposure[0]["servis"], "REDIS")  # Redis servisinin işaretlendiği doğrulanır
        self.assertEqual(exposure[0]["seviye"], "CRITICAL")  # Seviyenin CRITICAL olduğu teyit edilir

    def test_security_audit_reverse_shell_detection(self) -> None:  # Test 11: Reverse Shell tespiti
        """Test 11: PowerShell sürecinin şüpheli porta giden bağlantısının REVERSE_SHELL_DETECTED olarak yakalandığını doğrular."""
        rev_shell = SocketEndpoint(  # Parametre / ifade: rev_shell = SocketEndpoint(
            protocol="TCP",  # Parametre / ifade: protocol="TCP",
            local_ip="192.168.1.100",  # Parametre / ifade: local_ip="192.168.1.100",
            local_port=49500,  # Parametre / ifade: local_port=49500,
            remote_ip="198.51.100.99",  # Parametre / ifade: remote_ip="198.51.100.99",
            remote_port=4444,  # Parametre / ifade: remote_port=4444,
            state="ESTABLISHED",  # Parametre / ifade: state="ESTABLISHED",
            pid=6600,  # Parametre / ifade: pid=6600,
            process_name="powershell.exe",  # Parametre / ifade: process_name="powershell.exe",
        )  # Metasploit portuna bağlı PowerShell
        report = self.auditor.audit_socket_table([rev_shell])  # Denetle
        shell_findings = [f for f in report["bulgular"] if f["kategori"] == "REVERSE_SHELL_DETECTED"]  # Ters kabuk bulguları
        self.assertEqual(len(shell_findings), 1)  # Tam 1 kritik ters kabuk yakalanmalıdır
        self.assertEqual(shell_findings[0]["seviye"], "CRITICAL")  # Seviyenin kritik olduğu test edilir
        self.assertIn("KRİTİK GÜVENLİK İHLALİ", shell_findings[0]["aciklama"])  # Alarm açıklaması doğrulanır

    def test_security_audit_syn_flood_and_time_wait_cluster(self) -> None:  # Test 12: Anomali kümeleri
        """Test 12: Aşırı SYN_RECEIVED ve TIME_WAIT yığılmalarının anomali olarak yakalandığını doğrular."""
        syn_sockets = [  # Parametre / ifade: syn_sockets = [
            SocketEndpoint("TCP", "0.0.0.0", 80, f"10.0.0.{i}", 50000 + i, "SYN_RECEIVED") for i in range(8)  # Parametre / ifade: SocketEndpoint("TCP", "0.0.0.0", 80, f"10.0.0.{i}", 50000 + i, "SYN_RECEIVED") for i in range(8)
        ]  # 8 adet SYN_RECEIVED soketi (SYN Flood göstergesi)
        tw_sockets = [  # Parametre / ifade: tw_sockets = [
            SocketEndpoint("TCP", "192.168.1.10", 50000 + i, "93.184.216.34", 80, "TIME_WAIT") for i in range(20)  # Parametre / ifade: SocketEndpoint("TCP", "192.168.1.10", 50000 + i, "93.184.216.34", 80, "TIME_WAIT") for i in range(20)
        ]  # 20 adet TIME_WAIT soketi
        report = self.auditor.audit_socket_table(syn_sockets + tw_sockets)  # Denetle
        categories = {f["kategori"] for f in report["bulgular"]}  # Bulunan kategori kümesi
        self.assertIn("SYN_FLOOD_SUSPICION", categories)  # SYN Flood uyarısının varlığı doğrulanır
        self.assertIn("TIME_WAIT_ACCUMULATION", categories)  # TIME_WAIT yığılması uyarısının varlığı doğrulanır

    def test_negative_invalid_ports_and_negative_pid(self) -> None:  # Test 13: Negatif port/PID
        """Test 13: Negatif kontrol: Aralık dışı port (-1, 70000) ve negatif PID reddedildiğini doğrular."""
        with self.assertRaises(SocketValidationError):  # Negatif yerel port denemesi
            SocketEndpoint("TCP", "127.0.0.1", -1, "0.0.0.0", 0, "LISTEN")  # Hata beklenir
        with self.assertRaises(SocketValidationError):  # Üst sınır aşımı port denemesi
            SocketEndpoint("TCP", "127.0.0.1", 70000, "0.0.0.0", 0, "LISTEN")  # Hata beklenir
        with self.assertRaises(SocketValidationError):  # Negatif PID denemesi
            SocketEndpoint("TCP", "127.0.0.1", 8080, "0.0.0.0", 0, "LISTEN", pid=-1)  # Hata beklenir

    def test_negative_malformed_ip_and_unsupported_protocol(self) -> None:  # Test 14: Negatif IP/protokol
        """Test 14: Negatif kontrol: Geçersiz IP adresi ve desteklenmeyen protokolün reddedildiğini doğrular."""
        with self.assertRaises(SocketValidationError):  # Hatalı yerel IP
            SocketEndpoint("TCP", "999.1.2.3", 80, "0.0.0.0", 0, "LISTEN")  # Hata beklenir
        with self.assertRaises(SocketValidationError):  # Hatalı uzak IP
            SocketEndpoint("TCP", "127.0.0.1", 80, "gecersiz_ip", 443, "ESTABLISHED")  # Hata beklenir
        with self.assertRaises(SocketValidationError):  # Desteklenmeyen protokol (SCTP vb.)
            SocketEndpoint("SCTP", "127.0.0.1", 80, "0.0.0.0", 0, "LISTEN")  # Hata beklenir


if __name__ == "__main__":  # Doğrudan yürütme koşulu
    unittest.main()  # Testleri çalıştır
