# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G051: TCP Sıralama, Akış Kontrolü ve Yeniden İletim Birim Testleri.
Bu test paketi TCP bayt akışı sıra numarası ilerleyişini, kümülatif onay mantığını,
3 yinelenen ACK (Triple Duplicate ACK) ile Hızlı Yeniden İletim (Fast Retransmit) tetiklenmesini,
sıra dışı (out-of-order) paket yakalamayı, sıfır pencere (Zero Window) akış kontrolünü
ve Blind RST oturum koparma saldırı tespitlerini doğrular.
"""

# Birim testi iddia ve doğrulama mekanizmaları için pytest kütüphanesi
import pytest
# Dosya ve dizin yolu çözümleme modülü
import os
# Modül arama yollarını yönetmek için sys modülü
import sys
# JSON veri yapılarını okuma için json modülü
import json

# Test dosyasının bulunduğu mutlak dizini alır
current_dir = os.path.dirname(os.path.abspath(__file__))
# Uygulama kaynak kod dizini yolunu oluşturur
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
# Uygulama dizini henüz Python yolunda kayıtlı değilse listeye ekler
if app_dir not in sys.path:
    # İlk sıraya ekleyerek doğrudan import edilmesini sağlar
    sys.path.insert(0, app_dir)

# Test edilecek sınıfları ve hata tiplerini içe aktarır
from tcp_sequence_retransmit_analyzer import (
    # Özel doğrulama hatası sınıfı
    TCPSequenceError,
    # TCP segment veri modeli
    TCPStreamSegment,
    # Çift yönlü akış ve sıra takip motoru
    TCPFlowTracker,
    # Kapsamlı analiz ve raporlama sınıfı
    TCPSequenceRetransmitAnalyzer,
)


def test_tcp_segment_next_seq_calculation_data():
    """Veri taşıyan segmentlerde next_seq değerinin Seq + Payload_len olduğunu test eder."""
    # 500 baytlık veri taşıyan segment oluşturulur
    seg = TCPStreamSegment(
        paket_id="TEST-SEG-01",
        kaynak_ip="10.0.0.1",
        hedef_ip="10.0.0.2",
        kaynak_port=50000,
        hedef_port=80,
        seq_no=1000,
        payload_len=500,
    )
    # Bir sonraki beklenen sıra numarası 1000 + 500 = 1500 olmalıdır
    assert seg.next_seq == 1500


def test_tcp_segment_next_seq_calculation_syn_fin():
    """SYN veya FIN bayraklı segmentlerin mantıksal 1 bayt sıra tükettiğini test eder."""
    # 0 bayt yüklü ancak SYN bayraklı kontrol segmenti
    seg_syn = TCPStreamSegment(
        paket_id="TEST-SYN-01",
        kaynak_ip="10.0.0.1",
        hedef_ip="10.0.0.2",
        kaynak_port=50000,
        hedef_port=80,
        seq_no=5000,
        flags={"SYN": 1},
        payload_len=0,
    )
    # SYN 1 bayt tükettiği için next_seq 5001 olmalıdır
    assert seg_syn.next_seq == 5001


def test_tcp_segment_field_bounds_validation():
    """Geçersiz port, negatif sıra, negatif yük ve pencere taşmalarında hata fırlatıldığını test eder."""
    # Port 0 ile segment oluşturulması engellenmelidir
    with pytest.raises(TCPSequenceError):
        # Port 0 testi
        TCPStreamSegment("P1", "10.0.0.1", "10.0.0.2", 0, 80, 1000)
    # Port 70000 ile segment oluşturulması engellenmelidir
    with pytest.raises(TCPSequenceError):
        # Port 70000 testi
        TCPStreamSegment("P2", "10.0.0.1", "10.0.0.2", 50000, 70000, 1000)
    # Negatif payload uzunluğu engellenmelidir
    with pytest.raises(TCPSequenceError):
        # -100 payload testi
        TCPStreamSegment("P3", "10.0.0.1", "10.0.0.2", 50000, 80, 1000, payload_len=-100)
    # Pencere boyutu > 65535 engellenmelidir
    with pytest.raises(TCPSequenceError):
        # 80000 window testi
        TCPStreamSegment("P4", "10.0.0.1", "10.0.0.2", 50000, 80, 1000, window_size=80000)


def test_tcp_flow_in_order_sequential_delivery():
    """Sıralı gelen segmentlerin akış motorunda doğru kümülatif sırayı ilerlettiğini test eder."""
    # Akış takip nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-01", "10.0.0.1", 50000, "10.0.0.2", 80)
    # 1. Segment: Seq 1000, Boyut 200 (1000-1199 baytları)
    seg1 = TCPStreamSegment("S1", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1000, payload_len=200)
    # İşlenir
    ev1 = flow.process_segment(seg1)
    # Türü ILK_VERI_SEGMENTI olmalıdır
    assert ev1["tur"] == "ILK_VERI_SEGMENTI"
    # Sunucunun beklediği sonraki sıra 1200 olmalıdır
    assert flow.server_expected_seq == 1200

    # 2. Segment: Tam beklenen sıradan Seq 1200, Boyut 300 (1200-1499)
    seg2 = TCPStreamSegment("S2", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1200, payload_len=300)
    # İşlenir
    ev2 = flow.process_segment(seg2)
    # Türü SIRALI_VERI olmalıdır
    assert ev2["tur"] == "SIRALI_VERI"
    # Yeni beklenen sıra 1500 olmalıdır
    assert flow.server_expected_seq == 1500


def test_tcp_flow_out_of_order_detection():
    """Arada boşluk (gap) bırakan sıra dışı paketlerin tespitini test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-02", "10.0.0.1", 50000, "10.0.0.2", 80)
    # 1. Paket: Seq 1000, Boyut 500 (Beklenen: 1500)
    flow.process_segment(TCPStreamSegment("S1", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1000, payload_len=500))
    
    # 2. Paket: Seq 2000 (1500-1999 kayboldu / gecikti!)
    seg_gap = TCPStreamSegment("S2", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=2000, payload_len=500)
    # İşlenir
    ev = flow.process_segment(seg_gap)
    # Türü SIRA_DISI_PAKET olmalıdır
    assert ev["tur"] == "SIRA_DISI_PAKET"
    # Sıra dışı listesine 1 kayıt eklenmiş olmalıdır
    assert len(flow.out_of_order_packets) == 1
    # Boşluk miktarı 500 bayt olmalıdır
    assert flow.out_of_order_packets[0]["bosluk_bayt"] == 500


def test_tcp_flow_duplicate_ack_counting():
    """Aynı ACK numarasının tekrar gelmesiyle Duplicate ACK sayacının arttığını test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-03", "10.0.0.1", 50000, "10.0.0.2", 80)
    # Sunucudan ilk ACK gelir (Ack = 2000)
    flow.process_segment(TCPStreamSegment("A1", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=5000, ack_no=2000, flags={"ACK": 1}))
    # Sayacın sıfır olduğunu doğrular
    assert flow.duplicate_ack_count == 0

    # Sunucu tekrar Ack 2000 gönderir (Dup ACK #1)
    flow.process_segment(TCPStreamSegment("A2", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=5000, ack_no=2000, flags={"ACK": 1}))
    # Sayaç 1 olmalıdır
    assert flow.duplicate_ack_count == 1

    # Sunucu tekrar Ack 2000 gönderir (Dup ACK #2)
    flow.process_segment(TCPStreamSegment("A3", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=5000, ack_no=2000, flags={"ACK": 1}))
    # Sayaç 2 olmalıdır
    assert flow.duplicate_ack_count == 2


def test_tcp_flow_fast_retransmit_trigger_3_dupacks():
    """Tam 3 adet yinelenen ACK (Triple Duplicate ACK) alındığında Hızlı Yeniden İletimin tetiklendiğini test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-04", "10.0.0.1", 50000, "10.0.0.2", 80)
    # Temel ACK (2000)
    flow.process_segment(TCPStreamSegment("A1", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=5000, ack_no=2000, flags={"ACK": 1}))
    # Dup ACK 1
    flow.process_segment(TCPStreamSegment("A2", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=5000, ack_no=2000, flags={"ACK": 1}))
    # Dup ACK 2
    flow.process_segment(TCPStreamSegment("A3", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=5000, ack_no=2000, flags={"ACK": 1}))
    # Dup ACK 3 -> Tetikleyici
    ev = flow.process_segment(TCPStreamSegment("A4", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=5000, ack_no=2000, flags={"ACK": 1}))
    # Türü HIZLI_YENIDEN_ILETIM_TETIKLENDI olmalıdır
    assert ev["tur"] == "HIZLI_YENIDEN_ILETIM_TETIKLENDI"
    # Fast retransmits listesinde 1 kayıt bulunmalıdır
    assert len(flow.fast_retransmits) == 1
    # Kayıp olarak işaretlenen sıra no 2000 olmalıdır
    assert flow.fast_retransmits[0]["kayip_seq_no"] == 2000


def test_tcp_flow_retransmission_fills_gap():
    """Kayıp paketin tekrar iletilerek boşluğun kapatıldığını ve retransmission sayıldığını test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-05", "10.0.0.1", 50000, "10.0.0.2", 80)
    # Paket 1: Seq 1000 (Beklenen: 2000)
    flow.process_segment(TCPStreamSegment("S1", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1000, payload_len=1000))
    # Paket 3: Seq 3000 (2000-2999 kayıp!)
    flow.process_segment(TCPStreamSegment("S3", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=3000, payload_len=1000))
    
    # Şimdi kayıp olan Paket 2 (Seq 2000) tekrar iletilir
    seg_retrans = TCPStreamSegment("S2_RETRANS", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=2000, payload_len=1000)
    # İşlenir
    ev = flow.process_segment(seg_retrans)
    # Türü YENIDEN_ILETIM olmalıdır
    assert ev["tur"] == "YENIDEN_ILETIM"
    # Yeniden iletim listesinde 1 kayıt bulunmalıdır
    assert len(flow.retransmissions) == 1
    # Sunucunun beklediği sıra no boşluk kapandığı için ilerlemiş olmalıdır
    assert flow.server_expected_seq == 3000


def test_tcp_flow_cumulative_ack_progress():
    """Yeni bir kümülatif ACK geldiğinde Duplicate ACK sayacının sıfırlandığını test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-06", "10.0.0.1", 50000, "10.0.0.2", 80)
    # Ack 1000
    flow.process_segment(TCPStreamSegment("A1", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=1, ack_no=1000, flags={"ACK": 1}))
    # Dup Ack 1000
    flow.process_segment(TCPStreamSegment("A2", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=1, ack_no=1000, flags={"ACK": 1}))
    # Sayaç 1'dir
    assert flow.duplicate_ack_count == 1
    # Şimdi kümülatif Ack 4000 gelir
    ev = flow.process_segment(TCPStreamSegment("A3", "10.0.0.2", "10.0.0.1", 80, 50000, seq_no=1, ack_no=4000, flags={"ACK": 1}))
    # Türü KUMULATIF_ONAY olmalıdır
    assert ev["tur"] == "KUMULATIF_ONAY"
    # Yinelenen sayaç sıfırlanmış olmalıdır
    assert flow.duplicate_ack_count == 0
    # Son ACK 4000 olmalıdır
    assert flow.last_ack_no == 4000


def test_tcp_flow_zero_window_event_and_alert():
    """Sıfır pencere (Window=0) bildiriminin akış kilitlenmesi ve güvenlik uyarısı ürettiğini test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-07", "10.0.0.1", 50000, "10.0.0.2", 80)
    # Window=0 olan segment
    zw_seg = TCPStreamSegment("ZW-01", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1000, window_size=0, flags={"ACK": 1})
    # İşlenir
    ev = flow.process_segment(zw_seg)
    # Türü ZERO_WINDOW olmalıdır
    assert ev["tur"] == "ZERO_WINDOW"
    # zero_window_events listesinde 1 kayıt bulunmalıdır
    assert len(flow.zero_window_events) == 1
    # Güvenlik alarmlarında TCP_ZERO_WINDOW_DOS_RISKI bulunmalıdır
    assert any(a["kategori"] == "TCP_ZERO_WINDOW_DOS_RISKI" for a in flow.security_alerts)


def test_tcp_flow_blind_rst_injection_detection():
    """Pencere içi geçerli sıra numarasıyla gelen sahte RST enjeksiyonunun yakalandığını test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-08", "10.0.0.1", 50000, "10.0.0.2", 80)
    # Önce meşru veri akar (Seq=1000, Boyut=1000 -> Beklenen=2000)
    flow.process_segment(TCPStreamSegment("S1", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1000, payload_len=1000))
    # Saldırgan tahmin ettiği Seq 2000 ile sahte RST paketi enjekte eder
    rst_seg = TCPStreamSegment("RST-ATTACK", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=2000, flags={"RST": 1})
    # İşlenir
    ev = flow.process_segment(rst_seg)
    # Türü GUVENLIK_ALARM_RST olmalıdır
    assert ev["tur"] == "GUVENLIK_ALARM_RST"
    # Güvenlik alarmlarında Blind RST injection bulunmalıdır
    assert any(a["kategori"] == "TCP_BLIND_RST_INJECTION_SALDIRISI" for a in flow.security_alerts)


def test_tcp_flow_spurious_duplicate_packets():
    """Yinelenen paketlerin tek başına saldırı olmadığını, retransmission listesinde izlendiğini test eder."""
    # Akış nesnesi başlatılır
    flow = TCPFlowTracker("FLOW-09", "10.0.0.1", 50000, "10.0.0.2", 80)
    # Normal veri iletimi
    flow.process_segment(TCPStreamSegment("S1", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1000, payload_len=500))
    # Rota gecikmesi sebebiyle aynı paket tekrar gelir (Spurious Retransmit)
    ev = flow.process_segment(TCPStreamSegment("S1_DUP", "10.0.0.1", "10.0.0.2", 50000, 80, seq_no=1000, payload_len=500))
    # Türü YENIDEN_ILETIM olmalıdır
    assert ev["tur"] == "YENIDEN_ILETIM"
    # Ancak bu durum bir saldırı alarmı üretmez (security_alerts boş kalmalıdır)
    assert len(flow.security_alerts) == 0


def test_analyzer_load_json_sample_stream():
    """Örnek JSON dosyasındaki 14 paketin tamamının başarıyla analiz edildiğini test eder."""
    # Analiz nesnesi oluşturulur
    analyzer = TCPSequenceRetransmitAnalyzer()
    # JSON dosya yolu
    json_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_retransmit_packets.json")
    # Yüklenir ve analiz edilir
    analyzer.load_and_analyze_json(json_path)
    
    # 1 adet akış tespit edilmiş olmalıdır
    assert len(analyzer.flows) == 1
    # Akış nesnesi alınır
    flow = list(analyzer.flows.values())[0]
    # Toplam 14 segment bulunmalıdır
    assert len(flow.segment_history) == 14
    # 1 adet yeniden iletim yakalanmış olmalıdır
    assert len(flow.retransmissions) == 1
    # 1 adet Fast Retransmit olayı tetiklenmiş olmalıdır
    assert len(flow.fast_retransmits) == 1
    # 2 adet güvenlik alarmı (Zero Window ve Blind RST) bulunmalıdır
    assert len(flow.security_alerts) == 2


def test_analyzer_markdown_report_generation():
    """Markdown raporlama fonksiyonunun lisans, tablolar ve ilkeleri eksiksiz ürettiğini test eder."""
    # Analiz nesnesi oluşturulur
    analyzer = TCPSequenceRetransmitAnalyzer()
    # JSON dosya yolu
    json_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_retransmit_packets.json")
    # Yüklenir
    analyzer.load_and_analyze_json(json_path)
    # Rapor derlenir
    md = analyzer.generate_markdown_report()
    
    # Başlık doğrulaması
    assert "# 📊 TCP Sıralama, Akış Kontrolü ve Yeniden İletim" in md
    # Lisans bildirimi doğrulaması
    assert "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR" in md
    # Bölüm 1 başlığı doğrulaması
    assert "## 1. TCP Akış Takip ve İletim İstatistikleri" in md
    # Bölüm 2 başlığı doğrulaması
    assert "## 2. Yeniden İletim (Retransmission) ve Paket Kayıp Analizi" in md
    # Bölüm 3 başlığı doğrulaması
    assert "## 3. Güvenlik Anomalileri ve Oturum Koparma Tehditleri" in md
    # Bölüm 4 başlığı doğrulaması
    assert "## 4. TCP Akış Güvenliği ve Savunma İlkeleri" in md
