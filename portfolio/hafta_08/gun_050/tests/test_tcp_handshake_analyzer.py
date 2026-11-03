# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G050: TCP Üçlü El Sıkışma ve Güvenlik Denetim Motoru Birim Testleri.
Bu test paketi RFC 793 / RFC 9293 başlık yapısını, sahte başlık sağlama toplamı matematiğini,
üç aşamalı durum makinesini (State Machine), ISN ve Ack numarası doğrulamalarını,
bağlantı sıfırlama (RST) mantığını ve kural dışı tarama anomalilerini doğrular.
"""

# Birim testi iddia ve doğrulama mekanizmaları için pytest kütüphanesi
import pytest
# Dosya ve dizin yolu çözümleme modülü
import os
# Modül arama yollarını yönetmek için sys modülü
import sys
# JSON veri ayrıştırma için json modülü
import json

# Test dosyasının bulunduğu mutlak dizini alır
current_dir = os.path.dirname(os.path.abspath(__file__))
# Uygulama kaynak kod dizini yolunu oluşturur
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
# Uygulama dizini henüz Python yolunda kayıtlı değilse listeye ekler
if app_dir not in sys.path:
    # İlk sıraya ekleyerek doğrudan import edilmesini sağlar
    sys.path.insert(0, app_dir)

# Test edilecek TCP sınıflarını ve fonksiyonlarını içe aktarır
from tcp_handshake_analyzer import (
    # Özel TCP doğrulama istisnası
    TCPValidationError,
    # TCP bayrakları yönetim sınıfı
    TCPFlags,
    # RFC 1071 sağlama toplamı hesaplayıcı
    calculate_tcp_checksum,
    # TCP paket veri modeli
    TCPPacket,
    # El sıkışma durum makinesi
    TCPHandshakeSession,
    # Kapsamlı analiz ve denetim motoru
    TCPHandshakeAnalyzer,
)


def test_tcp_flags_conversion_and_strings():
    """TCP bayraklarının sözlükten bit maskesine ve metin listesine dönüşümünü test eder."""
    # SYN ve ACK içeren bayrak sözlüğü
    f_dict = {"SYN": 1, "ACK": 1, "FIN": 0, "RST": 0}
    # Bit düzeyinde maske hesaplanır
    mask = TCPFlags.from_dict(f_dict)
    # Maskenin 0x12 (SYN=0x02 + ACK=0x10 = 0x12) olduğunu doğrular
    assert mask == 0x12
    # Maskeden metin listesi çıkarılır
    str_list = TCPFlags.to_string_list(mask)
    # Listede SYN bulunmalıdır
    assert "SYN" in str_list
    # Listede ACK bulunmalıdır
    assert "ACK" in str_list
    # Listede FIN bulunmamalıdır
    assert "FIN" not in str_list


def test_tcp_pseudo_header_checksum_calculation():
    """RFC 793 Sahte Başlık (Pseudo-Header) ve TCP sağlama toplamı hesabını test eder."""
    # Kaynak ve hedef IP tanımlanır
    src_ip = "192.168.1.10"
    # Hedef IP
    dst_ip = "192.168.1.20"
    # 20 baytlık temsili TCP başlığı
    sample_tcp = b"\x1f\x90\x00\x50\x00\x00\x03\xe8\x00\x00\x00\x00\x50\x02\xfa\xf0\x00\x00\x00\x00"
    # Sağlama toplamı hesaplanır
    chk = calculate_tcp_checksum(src_ip, dst_ip, sample_tcp)
    # Checksum 16-bitlik pozitif bir tamsayı olmalıdır
    assert isinstance(chk, int)
    # 0 ile 65535 aralığında olduğunu teyit eder
    assert 0 <= chk <= 0xFFFF


def test_tcp_packet_binary_packing_and_unpacking():
    """TCP paketinin ikili baytlara paketlenmesini ve geri açılmasını test eder."""
    # Orijinal paket nesnesi oluşturulur
    pkt = TCPPacket(
        kaynak_ip="10.0.0.1",
        hedef_ip="10.0.0.2",
        kaynak_port=12345,
        hedef_port=80,
        seq_no=987654,
        ack_no=0,
        flags=TCPFlags.SYN,
        window_size=32768,
        data_offset=5,
        payload=b"TEST_PAYLOAD",
    )
    # İkili baytlara paketlenir
    raw = pkt.to_bytes()
    # Bayt uzunluğu en az 20 bayt başlık + 12 bayt yük = 32 bayt olmalıdır
    assert len(raw) == 32
    # Baytlardan tekrar nesne oluşturulur
    unpacked = TCPPacket.from_bytes(raw, "10.0.0.1", "10.0.0.2")
    # Kaynak port doğrulanır
    assert unpacked.kaynak_port == 12345
    # Hedef port doğrulanır
    assert unpacked.hedef_port == 80
    # Sıra numarası doğrulanır
    assert unpacked.seq_no == 987654
    # Bayrak doğrulanır
    assert unpacked.flags == TCPFlags.SYN
    # Yükün eksiksiz çözüldüğü teyit edilir
    assert unpacked.payload == b"TEST_PAYLOAD"


def test_tcp_packet_field_bounds_validation():
    """Geçersiz port, sıra no ve veri ofsetlerinde TCPValidationError fırlatıldığını test eder."""
    # Geçersiz port numarası (> 65535) ile nesne oluşturulması engellenmelidir
    with pytest.raises(TCPValidationError):
        # 70000 portu ile deneme yapılır
        TCPPacket("10.0.0.1", "10.0.0.2", 70000, 80, 1000)
    # Sıfır port numarası engellenmelidir
    with pytest.raises(TCPValidationError):
        # Port 0 ile deneme yapılır
        TCPPacket("10.0.0.1", "10.0.0.2", 0, 80, 1000)
    # Negatif sıra numarası engellenmelidir
    with pytest.raises(TCPValidationError):
        # Negatif Seq no ile deneme yapılır
        TCPPacket("10.0.0.1", "10.0.0.2", 50000, 80, -5)
    # 5'ten küçük veri ofseti engellenmelidir
    with pytest.raises(TCPValidationError):
        # Veri ofseti 4 ile deneme yapılır
        TCPPacket("10.0.0.1", "10.0.0.2", 50000, 80, 1000, data_offset=4)


def test_three_way_handshake_full_success_flow():
    """Normal bir üçlü el sıkışmanın (SYN -> SYN-ACK -> ACK) baştan sona başarıyla tamamlanmasını test eder."""
    # Oturum nesnesi oluşturulur
    session = TCPHandshakeSession("10.0.0.5:50000->10.0.0.1:80")
    
    # 1. Adım: İstemci SYN gönderir (Seq = 1000, Ack = 0)
    pkt_syn = TCPPacket("10.0.0.5", "10.0.0.1", 50000, 80, seq_no=1000, ack_no=0, flags=TCPFlags.SYN)
    # Paketi işler
    res1 = session.process_packet(pkt_syn)
    # Sonuç STEP_1_SYN_SENT olmalıdır
    assert res1 == "STEP_1_SYN_SENT"
    # İstemci durumu SYN_SENT olmalıdır
    assert session.client_state == "SYN_SENT"
    # Sunucu durumu SYN_RECEIVED olmalıdır
    assert session.server_state == "SYN_RECEIVED"
    
    # 2. Adım: Sunucu SYN-ACK gönderir (Seq = 5000, Ack = 1001)
    pkt_syn_ack = TCPPacket("10.0.0.1", "10.0.0.5", 80, 50000, seq_no=5000, ack_no=1001, flags=TCPFlags.SYN | TCPFlags.ACK)
    # Paketi işler
    res2 = session.process_packet(pkt_syn_ack)
    # Sonuç STEP_2_SYN_ACK_RECEIVED olmalıdır
    assert res2 == "STEP_2_SYN_ACK_RECEIVED"
    # İstemci durumu ESTABLISHED olmalıdır
    assert session.client_state == "ESTABLISHED"
    
    # 3. Adım: İstemci ACK gönderir (Seq = 1001, Ack = 5001)
    pkt_ack = TCPPacket("10.0.0.5", "10.0.0.1", 50000, 80, seq_no=1001, ack_no=5001, flags=TCPFlags.ACK)
    # Paketi işler
    res3 = session.process_packet(pkt_ack)
    # Sonuç STEP_3_ESTABLISHED olmalıdır
    assert res3 == "STEP_3_ESTABLISHED"
    # Sunucu durumu ESTABLISHED olmalıdır
    assert session.server_state == "ESTABLISHED"
    # Oturumun tamamen kurulduğu teyit edilir
    assert session.is_established is True


def test_handshake_step_1_syn_only():
    """Yalnızca SYN paketi gönderildiğinde durumların doğru güncellendiğini test eder."""
    # Oturum başlatılır
    session = TCPHandshakeSession("TEST-SESS-01")
    # SYN paketi
    pkt = TCPPacket("1.1.1.1", "2.2.2.2", 1000, 2000, seq_no=42000, ack_no=0, flags=TCPFlags.SYN)
    # Paketi işler
    step = session.process_packet(pkt)
    # Adım 1 olmalıdır
    assert step == "STEP_1_SYN_SENT"
    # İstemci ISN değeri saklanmış olmalıdır
    assert session.client_isn == 42000
    # Oturum henüz kurulu olmamalıdır
    assert session.is_established is False


def test_handshake_step_2_ack_number_check():
    """Sunucu SYN-ACK cevabındaki Ack numarasının istemci ISN + 1 olmasını denetler."""
    # Oturum başlatılır
    session = TCPHandshakeSession("TEST-SESS-02")
    # İstemci SYN gönderir (ISN = 10000)
    session.process_packet(TCPPacket("1.1.1.1", "2.2.2.2", 1000, 2000, seq_no=10000, ack_no=0, flags=TCPFlags.SYN))
    
    # Sunucu hatalı Ack numarası (10000 yerine 9999) gönderir
    bad_syn_ack = TCPPacket("2.2.2.2", "1.1.1.1", 2000, 1000, seq_no=50000, ack_no=9999, flags=TCPFlags.SYN | TCPFlags.ACK)
    # Paketi işler
    res = session.process_packet(bad_syn_ack)
    # Sonuç INVALID_ACK_NUMBER olmalıdır
    assert res == "INVALID_ACK_NUMBER"
    # Güvenlik alarmı üretilmiş olmalıdır
    assert any("Hatalı Ack numarası" in alert for alert in session.security_alerts)


def test_handshake_step_3_ack_number_check():
    """İstemci 3. Adım ACK cevabındaki Ack numarasının sunucu ISN + 1 olmasını denetler."""
    # Oturum başlatılır
    session = TCPHandshakeSession("TEST-SESS-03")
    # 1. Adım: İstemci SYN (ISN = 100)
    session.process_packet(TCPPacket("1.1.1.1", "2.2.2.2", 1000, 2000, seq_no=100, ack_no=0, flags=TCPFlags.SYN))
    # 2. Adım: Sunucu SYN-ACK (ISN = 500, Ack = 101)
    session.process_packet(TCPPacket("2.2.2.2", "1.1.1.1", 2000, 1000, seq_no=500, ack_no=101, flags=TCPFlags.SYN | TCPFlags.ACK))
    
    # 3. Adım: İstemci yanlış Ack gönderir (Beklenen 501, gönderilen 500)
    bad_ack = TCPPacket("1.1.1.1", "2.2.2.2", 1000, 2000, seq_no=101, ack_no=500, flags=TCPFlags.ACK)
    # Paketi işler
    res = session.process_packet(bad_ack)
    # Hata durumu döner
    assert res == "INVALID_HANDSHAKE_FINAL_ACK"
    # Oturum kurulmamış olmalıdır
    assert session.is_established is False


def test_handshake_unexpected_payload_warning():
    """SYN paketinde veri yükü bulunmasının anomali alarmı tetiklediğini test eder."""
    # Oturum başlatılır
    session = TCPHandshakeSession("TEST-SESS-04")
    # Yüklü SYN paketi (RFC kuralına göre el sıkışmada veri taşınmaz)
    pkt_with_payload = TCPPacket(
        "1.1.1.1", "2.2.2.2", 1000, 2000, seq_no=1000, flags=TCPFlags.SYN, payload=b"UNEXPECTED_DATA"
    )
    # Paketi işler
    session.process_packet(pkt_with_payload)
    # Beklenmeyen veri yükü alarmı üretilmelidir
    assert any("beklenmeyen veri yükü" in alert for alert in session.security_alerts)


def test_handshake_connection_reset_rst():
    """RST paketi geldiğinde oturum durumlarının CLOSED yapıldığını test eder."""
    # Oturum başlatılır
    session = TCPHandshakeSession("TEST-SESS-05")
    # SYN paketi ile oturum açılır
    session.process_packet(TCPPacket("1.1.1.1", "2.2.2.2", 1000, 2000, seq_no=100, flags=TCPFlags.SYN))
    # RST paketi gönderilir
    rst_pkt = TCPPacket("2.2.2.2", "1.1.1.1", 2000, 1000, seq_no=0, flags=TCPFlags.RST)
    # Paketi işler
    res = session.process_packet(rst_pkt)
    # Sonuç CONNECTION_RESET olmalıdır
    assert res == "CONNECTION_RESET"
    # İstemci durumu CLOSED olmalıdır
    assert session.client_state == "CLOSED"
    # Sunucu durumu CLOSED olmalıdır
    assert session.server_state == "CLOSED"


def test_anomaly_syn_fin_contradictory_flags():
    """SYN ve FIN bayraklarının aynı anda set edilmesinin kritik anomali olarak yakalandığını test eder."""
    # Analiz motoru başlatılır
    analyzer = TCPHandshakeAnalyzer()
    # Kural dışı SYN+FIN paketi
    pkt = TCPPacket("192.168.1.50", "10.0.0.1", 40000, 80, seq_no=1000, flags=TCPFlags.SYN | TCPFlags.FIN)
    # Anomali denetimi koşulur
    analyzer.check_packet_anomalies(pkt, "ANOMALY-01")
    # Anomali tespit edilmiş olmalıdır
    assert len(analyzer.anomalies) == 1
    # Kategorisi KURAL_DISI_BAYRAK_SYN_FIN olmalıdır
    assert analyzer.anomalies[0]["kategori"] == "KURAL_DISI_BAYRAK_SYN_FIN"
    # Seviyesi KRITIK olmalıdır
    assert analyzer.anomalies[0]["seviye"] == "KRITIK"


def test_anomaly_xmas_port_scan():
    """XMAS Port Taraması (FIN+PSH+URG) bayrak kombinasyonunun yakalandığını test eder."""
    # Analiz motoru başlatılır
    analyzer = TCPHandshakeAnalyzer()
    # XMAS paketi
    pkt = TCPPacket("192.168.1.50", "10.0.0.1", 40001, 80, seq_no=2000, flags=TCPFlags.FIN | TCPFlags.PSH | TCPFlags.URG)
    # Anomali denetimi koşulur
    analyzer.check_packet_anomalies(pkt, "ANOMALY-02")
    # PORT_TARAMA_XMAS tespit edilmelidir
    assert any(a["kategori"] == "PORT_TARAMA_XMAS" for a in analyzer.anomalies)


def test_anomaly_null_port_scan():
    """NULL Port Taraması (Tüm bayraklar 0) bayrak kombinasyonunun yakalandığını test eder."""
    # Analiz motoru başlatılır
    analyzer = TCPHandshakeAnalyzer()
    # NULL paketi (flags = 0)
    pkt = TCPPacket("192.168.1.50", "10.0.0.1", 40002, 80, seq_no=3000, flags=0)
    # Anomali denetimi koşulur
    analyzer.check_packet_anomalies(pkt, "ANOMALY-03")
    # PORT_TARAMA_NULL tespit edilmelidir
    assert any(a["kategori"] == "PORT_TARAMA_NULL" for a in analyzer.anomalies)


def test_analyzer_markdown_report_generation():
    """Rapor oluşturma fonksiyonunun lisans, oturum tablosu ve bulguları eksiksiz derlediğini test eder."""
    # Analiz motoru başlatılır
    analyzer = TCPHandshakeAnalyzer()
    # Örnek JSON dosya yolu
    sample_json = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_tcp_handshake_packets.json")
    # JSON verisi yüklenir
    analyzer.load_and_analyze_json(sample_json)
    # Markdown raporu derlenir
    md = analyzer.generate_markdown_report()
    
    # Başlık doğrulaması
    assert "# 📊 TCP Üçlü El Sıkışma" in md
    # Özel lisans bildirimi doğrulaması
    assert "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR" in md
    # Oturum tablosu başlığı
    assert "## 1. TCP Oturumları ve Durum Makinesi Özeti" in md
    # Güvenlik anomalileri başlığı
    assert "## 2. Tespit Edilen Güvenlik Anomalileri" in md
    # Savunma ilkeleri başlığı
    assert "## 3. TCP Seviyesinde Savunma ve Sıkılaştırma İlkeleri" in md
