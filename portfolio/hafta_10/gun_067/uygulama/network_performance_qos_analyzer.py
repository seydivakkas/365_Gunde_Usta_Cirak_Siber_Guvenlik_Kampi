# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G067: Hafta 10 Gün 67 - Paket Kaybı, Gecikme ve Jitter Ağ Performans ve QoS Analiz Motoru.
Bu modül, ağ telemetrisi üzerinden paket gecikmesini (Latency/RTT), gecikme değişimini (Jitter - RFC 3550/3393),
paket kaybını (Packet Loss), TCP yeniden iletimlerini (Retransmission) ve QoS SLA ihlallerini
matematiksel ve istatistiksel modellerle analiz eder; siber tıkanıklık ve DoS anomalilerini raporlar.
"""

# Matematiksel hesaplamalar ve istatistiksel ortalama için math modülü içe aktarılır
import math
# Tip ipuçları ve veri yapıları için typing modülü içe aktarılır
from typing import Dict, List, Any, Optional, Tuple, Set
# Veri sınıfları oluşturmak için dataclass dekoratörü içe aktarılır
from dataclasses import dataclass, field


# Temel QoS analiz hatası üst sınıfı
class QoSAnalysisError(Exception):
    """QoS ve ağ performans analiz motorunun temel istisna sınıfıdır."""
    # Üst sınıf gövdesi boş geçilir
    pass


# Boş paket akışı hatası
class EmptyPacketStreamError(QoSAnalysisError):
    """Analiz edilecek paket veya telemetri listesi boş olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz zaman damgası sıralaması hatası
class InvalidTimestampOrderError(QoSAnalysisError):
    """Paket gönderim zamanları kronolojik sırada olmadığında veya zamanda geriye gittiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Negatif gecikme süresi hatası
class NegativeDelayError(QoSAnalysisError):
    """Paket varış zamanı gönderim zamanından önce olduğunda (fiziksel imkansızlık) fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# QoS SLA eşik aşımı hatası
class QoSSLAThresholdViolationError(QoSAnalysisError):
    """Hizmet Seviyesi Anlaşması (SLA) gecikme, jitter veya kayıp limitleri aşıldığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Aşırı paket kaybı ve olası DoS saldırısı hatası
class ExcessivePacketLossError(QoSAnalysisError):
    """Paket kayıp oranı kritik DoS/tıkanıklık eşiğini (%40+) aştığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bozuk sıra numarası hatası
class MalformedSequenceError(QoSAnalysisError):
    """Sıra numarası negatif veya geçersiz bir tamsayı olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz telemetri veri biçimi hatası
class InvalidTelemetryFormatError(QoSAnalysisError):
    """Telemetri girdisi sözlük yapısında olmadığında veya zorunlu alanlar eksik olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Aşırı saat kayması (Clock Skew) anomali hatası
class ClockSkewAnomalyError(QoSAnalysisError):
    """İstemci ve sunucu saatleri arasında anormal derecede yüksek senkronizasyon farkı olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Hesaplanan QoS metriklerini tutan veri sınıfı
@dataclass
class QoSMetricsResult:
    """Tek bir ağ akışı için hesaplanan tüm performans ve kalite metriklerini saklar."""
    # Akış tanımlayıcı kimliği
    akis_id: str
    # Protokol türü (UDP, TCP, RTP)
    protokol: str
    # Toplam gönderilen paket sayısı
    gonderilen_paket_sayisi: int
    # Başarıyla alınan paket sayısı
    alinan_paket_sayisi: int
    # Kaybolan paket sayısı
    kaybolan_paket_sayisi: int
    # Paket kayıp yüzdesi (%)
    kayip_orani_yuzde: float
    # Ortalama tek yönlü gecikme (milisaniye)
    ortalama_gecikme_ms: float
    # Minimum tek yönlü gecikme (milisaniye)
    min_gecikme_ms: float
    # Maksimum tek yönlü gecikme (milisaniye)
    max_gecikme_ms: float
    # Ortalama mutlak jitter (milisaniye - RFC 3393 / IPDV)
    ortalama_jitter_ms: float
    # RFC 3550 smoothed jitter filtresi (milisaniye)
    rfc3550_jitter_ms: float
    # TCP yeniden iletim sayısı (TCP akışları için)
    retransmission_sayisi: int = 0
    # TCP yeniden iletim oranı (%)
    retransmission_orani_yuzde: float = 0.0
    # QoS SLA uyumluluk durumu (UYUMLU, IHLAL_VAR, KRITIK_TEHLIKE)
    sla_durumu: str = "UYUMLU"
    # SLA ihlal gerekçeleri
    sla_ihlal_sebepleri: List[str] = field(default_factory=list)


# Ağ performans ve QoS analiz motoru ana sınıfı
class NetworkPerformanceQoSAnalyzer:
    """Ağ paket akışlarını inceleyerek gecikme, jitter, kayıp ve SLA ihlallerini belirleyen motor."""

    # Sınıf başlatıcı metodu
    def __init__(self, varsayilan_sla: Optional[Dict[str, float]] = None) -> None:
        # Varsayılan SLA eşik değerleri belirlenir (VoIP standartları: RFC 3550 ve ITU-T G.114)
        self.default_sla = varsayilan_sla or {
            "max_ortalama_gecikme_ms": 150.0,
            "max_jitter_ms": 30.0,
            "max_kayip_orani_yuzde": 3.0,
            "max_retrans_orani_yuzde": 5.0
        }

    # Girdi telemetri doğrulaması yapan yardımcı metot
    def validate_telemetry_stream(self, stream_data: Any) -> None:
        """Gelen akış nesnesinin yapısal ve mantıksal geçerliliğini denetler."""
        # Veri nesnesi sözlük tipinde değilse
        if not isinstance(stream_data, dict):
            # Biçim hatası fırlatılır
            raise InvalidTelemetryFormatError("Akış telemetrisi geçerli bir sözlük (dict) olmalıdır.")

        # Akış içindeki paketler veya segmentler listesi aranır
        packets = stream_data.get("paketler")
        # Eğer paketler yoksa segmentler kontrol edilir
        if packets is None:
            # Segmentler listesi alınır
            packets = stream_data.get("segmentler")

        # Liste bulunamazsa veya liste tipinde değilse
        if packets is None or not isinstance(packets, list):
            # Biçim hatası fırlatılır
            raise InvalidTelemetryFormatError("Akış telemetrisinde 'paketler' veya 'segmentler' listesi bulunmalıdır.")

        # Paket listesi tamamen boşsa
        if len(packets) == 0:
            # Boş akış hatası fırlatılır
            raise EmptyPacketStreamError("Analiz edilecek paket listesi boş olamaz.")

        # Zaman damgası kronolojisi kontrolü için önceki gönderim zamanı
        prev_send_time = -1.0
        # Her paket tek tek taranır
        for p in packets:
            # Paketin sözlük olduğu denetlenir
            if not isinstance(p, dict):
                # Biçim hatası fırlatılır
                raise InvalidTelemetryFormatError("Paket elemanı bir sözlük olmalıdır.")

            # Sıra numarası kontrol edilir
            if "sira_no" not in p:
                # Eksik alan hatası fırlatılır
                raise InvalidTelemetryFormatError("Paket nesnesinde 'sira_no' alanı zorunludur.")

            # Sıra numarasının tamsayı ve sıfır veya pozitif olduğu denetlenir
            seq = p["sira_no"]
            # Tip ve değer kontrolü
            if not isinstance(seq, int) or seq < 0:
                # Bozuk sıra numarası hatası fırlatılır
                raise MalformedSequenceError(f"Geçersiz veya negatif sıra numarası: {seq}")

            # Gönderim zamanı alanı kontrol edilir
            if "gonderim_zamani" not in p:
                # Eksik alan hatası fırlatılır
                raise InvalidTelemetryFormatError("Paket nesnesinde 'gonderim_zamani' alanı zorunludur.")

            # Gönderim zamanı sayısal değere dönüştürülür
            send_t = float(p["gonderim_zamani"])
            # Zamanın negatif olamayacağı denetlenir
            if send_t < 0:
                # Negatif zaman hatası fırlatılır
                raise InvalidTimestampOrderError(f"Gönderim zamanı negatif olamaz: {send_t}")

            # Zamanın geriye gitmediği denetlenir (kronolojik sıralama)
            if prev_send_time >= 0 and send_t < prev_send_time:
                # Sıralama hatası fırlatılır
                raise InvalidTimestampOrderError(f"Zaman damgası zamanda geriye gitti: {send_t} < {prev_send_time}")
            # Önceki zaman güncellenir
            prev_send_time = send_t

            # Varış zamanı kontrolü (varis_zamani veya ack_varis_zamani)
            recv_t = p.get("varis_zamani")
            # TCP ise ack_varis_zamani olabilir
            if recv_t is None and "ack_varis_zamani" in p:
                # ACK varış zamanı atanır
                recv_t = p.get("ack_varis_zamani")

            # Eğer paket kaybolmamışsa ve varış zamanı varsa
            if recv_t is not None:
                # Sayısala dönüştürülür
                recv_val = float(recv_t)
                # Varış zamanının gönderimden önce olamayacağı (fiziksel yasa) denetlenir
                if recv_val < send_t:
                    # Negatif gecikme hatası fırlatılır
                    raise NegativeDelayError(f"Varış zamanı ({recv_val}) gönderim zamanından ({send_t}) önce olamaz.")

                # Aşırı saat kayması kontrolü (tek bir pakette 3600 saniyeden fazla gecikme)
                if (recv_val - send_t) > 3600.0:
                    # Saat kayması istisnası fırlatılır
                    raise ClockSkewAnomalyError(f"Aşırı saat kayması veya senkronizasyon anomalisi tespit edildi: {recv_val - send_t:.2f}s")

    # UDP ve VoIP paket akışını analiz eden metot
    def analyze_udp_voip_stream(
        self,
        stream_data: Dict[str, Any],
        sla_limits: Optional[Dict[str, float]] = None,
        raise_on_sla_violation: bool = False
    ) -> QoSMetricsResult:
        """UDP tabanlı VoIP/RTP telemetrisini inceler; gecikme, jitter, kayıp ve SLA ihlallerini hesaplar."""
        # Akış verisinin geçerliliği doğrulanır
        self.validate_telemetry_stream(stream_data)

        # SLA limitleri belirlenir
        sla = sla_limits or self.default_sla
        # Akış kimliği alınır
        flow_id = str(stream_data.get("akis_id", "BILINMEYEN_AKIS"))
        # Protokol adı alınır
        proto = str(stream_data.get("protokol", "UDP")).upper()
        # Paket listesi alınır
        packets = stream_data.get("paketler", [])

        # Başarıyla alınan paketler listesi
        delays_ms: List[float] = []
        # Alınan paketlerin gönderim ve varış zamanları (Jitter hesabı için)
        received_timestamps: List[Tuple[float, float]] = []

        # Beklenen toplam paket sayısı hesaplanır (ilk sıra nosu ile son sıra nosu arasındaki aralık)
        seq_numbers = [p["sira_no"] for p in packets]
        # Minimum ve maksimum sıra numaraları
        min_seq = min(seq_numbers)
        # Maksimum sıra numarası
        max_seq = max(seq_numbers)
        # Sıra aralığına göre gönderildiği anlaşılan toplam paket sayısı
        total_expected_packets = (max_seq - min_seq + 1)
        # Gerçekte elimize ulaşan paket sayısı
        received_packets_count = 0

        # Paketler kronolojik sırayla işlenir
        for p in packets:
            # Varış zamanı alınır
            recv_t = p.get("varis_zamani")
            # Varış zamanı varsa paket hedefe ulaşmıştır
            if recv_t is not None:
                # Alınan paket sayısı artırılır
                received_packets_count += 1
                # Gönderim zamanı
                send_t = float(p["gonderim_zamani"])
                # Milisaniye cinsinden gecikme hesaplanır
                delay_ms = (float(recv_t) - send_t) * 1000.0
                # Listeye eklenir
                delays_ms.append(delay_ms)
                # Zaman ikilisi listeye eklenir
                received_timestamps.append((send_t, float(recv_t)))

        # Kaybolan paket sayısı hesaplanır
        lost_packets = total_expected_packets - received_packets_count
        # Kayıp sayısı negatif olamaz
        lost_packets = max(0, lost_packets)
        # Kayıp oranı hesaplanır (%)
        loss_rate_pct = (lost_packets / total_expected_packets) * 100.0 if total_expected_packets > 0 else 0.0

        # Gecikme istatistikleri hesaplanır
        if delays_ms:
            # Ortalama gecikme
            avg_delay = sum(delays_ms) / len(delays_ms)
            # Minimum gecikme
            min_delay = min(delays_ms)
            # Maksimum gecikme
            max_delay = max(delays_ms)
        else:
            # Gecikme yoksa sıfırdır
            avg_delay, min_delay, max_delay = 0.0, 0.0, 0.0

        # 1. Ortalama Mutlak Jitter (Mean Absolute Jitter / IPDV - RFC 3393)
        # D(i) = |(R_{i} - S_{i}) - (R_{i-1} - S_{i-1})|
        jitter_diffs: List[float] = []
        for i in range(1, len(received_timestamps)):
            # Önceki paketin gecikmesi (ms)
            prev_d = (received_timestamps[i - 1][1] - received_timestamps[i - 1][0]) * 1000.0
            # Şimdiki paketin gecikmesi (ms)
            curr_d = (received_timestamps[i][1] - received_timestamps[i][0]) * 1000.0
            # Mutlak fark
            diff = abs(curr_d - prev_d)
            # Listeye eklenir
            jitter_diffs.append(diff)

        # Ortalama jitter hesaplanır
        mean_jitter_ms = sum(jitter_diffs) / len(jitter_diffs) if jitter_diffs else 0.0

        # 2. RFC 3550 Standardı Filtrelenmiş Jitter (Interarrival Jitter)
        # J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16
        rfc3550_j = 0.0
        # Farklar üzerinden filtre yürütülür
        for diff in jitter_diffs:
            # Filtre formülü
            rfc3550_j += (diff - rfc3550_j) / 16.0

        # SLA İhlal Denetimleri
        violations: List[str] = []
        # Gecikme eşik kontrolü
        if avg_delay > sla.get("max_ortalama_gecikme_ms", 150.0):
            # İhlal eklenir
            violations.append(f"Ortalama gecikme ({avg_delay:.2f}ms) SLA limitini ({sla['max_ortalama_gecikme_ms']}ms) aştı.")

        # Jitter eşik kontrolü
        if mean_jitter_ms > sla.get("max_jitter_ms", 30.0):
            # İhlal eklenir
            violations.append(f"Ortalama jitter ({mean_jitter_ms:.2f}ms) SLA limitini ({sla['max_jitter_ms']}ms) aştı.")

        # Kayıp oranı eşik kontrolü
        if loss_rate_pct > sla.get("max_kayip_orani_yuzde", 3.0):
            # İhlal eklenir
            violations.append(f"Paket kayıp oranı (%{loss_rate_pct:.2f}) SLA limitini (%{sla['max_kayip_orani_yuzde']}) aştı.")

        # SLA durumu belirlenir
        sla_status = "UYUMLU" if len(violations) == 0 else "IHLAL_VAR"

        # Kritik DoS seviyesinde aşırı paket kaybı denetimi (%40 ve üzeri)
        if loss_rate_pct >= 40.0:
            # Durum kritik yapılır
            sla_status = "KRITIK_TEHLIKE"
            # Hata fırlatma bayrağı aktifse
            if raise_on_sla_violation:
                # Aşırı kayıp hatası fırlatılır
                raise ExcessivePacketLossError(f"Kritik paket kaybı (%{loss_rate_pct:.1f}) tespit edildi! Olası DoS/Ağ Tıkanıklığı!")

        # Standart SLA ihlali hatası fırlatma kontrolü
        if raise_on_sla_violation and violations:
            # SLA ihlali hatası fırlatılır
            raise QoSSLAThresholdViolationError(" | ".join(violations))

        # Metrik sonuç nesnesi oluşturulur ve döndürülür
        return QoSMetricsResult(
            akis_id=flow_id,
            protokol=proto,
            gonderilen_paket_sayisi=total_expected_packets,
            alinan_paket_sayisi=received_packets_count,
            kaybolan_paket_sayisi=lost_packets,
            kayip_orani_yuzde=round(loss_rate_pct, 2),
            ortalama_gecikme_ms=round(avg_delay, 2),
            min_gecikme_ms=round(min_delay, 2),
            max_gecikme_ms=round(max_delay, 2),
            ortalama_jitter_ms=round(mean_jitter_ms, 2),
            rfc3550_jitter_ms=round(rfc3550_j, 2),
            retransmission_sayisi=0,
            retransmission_orani_yuzde=0.0,
            sla_durumu=sla_status,
            sla_ihlal_sebepleri=violations
        )

    # TCP segment akışını inceleyen ve Retransmission/RTT hesaplayan metot
    def analyze_tcp_stream(
        self,
        stream_data: Dict[str, Any],
        sla_limits: Optional[Dict[str, float]] = None,
        raise_on_sla_violation: bool = False
    ) -> QoSMetricsResult:
        """TCP segment telemetrisini inceler; RTT, yeniden iletimleri (Retransmissions) ve kayıpları tespit eder."""
        # Akış geçerliliği doğrulanır
        self.validate_telemetry_stream(stream_data)

        # SLA limitleri
        sla = sla_limits or self.default_sla
        # Akış kimliği
        flow_id = str(stream_data.get("akis_id", "BILINMEYEN_TCP_AKIS"))
        # Protokol
        proto = str(stream_data.get("protokol", "TCP")).upper()
        # Segment listesi
        segments = stream_data.get("segmentler", [])

        # RTT süreleri listesi (ms)
        rtt_list_ms: List[float] = []
        # Toplam iletilen segment sayısı
        total_segments = len(segments)
        # Yeniden iletim sayısı
        retrans_count = 0
        # Zaman damgaları ikilisi (Jitter hesabı için)
        rtt_timestamps: List[Tuple[float, float]] = []

        # Her segment taranır
        for s in segments:
            # Yeniden iletim olup olmadığı kontrol edilir
            is_retrans = bool(s.get("is_retrans", False))
            # Eğer yeniden iletim ise
            if is_retrans:
                # Yeniden iletim sayacı artırılır
                retrans_count += 1

            # ACK varış zamanı kontrol edilir
            ack_t = s.get("ack_varis_zamani")
            # Gönderim zamanı
            send_t = float(s["gonderim_zamani"])

            # Eğer ACK geldiyse RTT hesaplanır
            if ack_t is not None:
                # RTT milisaniye olarak bulunur
                rtt_ms = (float(ack_t) - send_t) * 1000.0
                # RTT listesine eklenir
                rtt_list_ms.append(rtt_ms)
                # İkili listeye eklenir
                rtt_timestamps.append((send_t, float(ack_t)))

        # Retransmission oranı hesaplanır (%)
        retrans_rate_pct = (retrans_count / total_segments) * 100.0 if total_segments > 0 else 0.0

        # RTT istatistikleri
        if rtt_list_ms:
            # Ortalama RTT
            avg_rtt = sum(rtt_list_ms) / len(rtt_list_ms)
            # Minimum RTT
            min_rtt = min(rtt_list_ms)
            # Maksimum RTT
            max_rtt = max(rtt_list_ms)
        else:
            # Veri yoksa sıfırdır
            avg_rtt, min_rtt, max_rtt = 0.0, 0.0, 0.0

        # RTT bazlı Jitter hesabı
        rtt_diffs: List[float] = []
        for i in range(1, len(rtt_timestamps)):
            # Önceki RTT
            prev_rtt = (rtt_timestamps[i - 1][1] - rtt_timestamps[i - 1][0]) * 1000.0
            # Şimdiki RTT
            curr_rtt = (rtt_timestamps[i][1] - rtt_timestamps[i][0]) * 1000.0
            # Mutlak fark
            rtt_diffs.append(abs(curr_rtt - prev_rtt))

        # Ortalama RTT jitter
        mean_rtt_jitter = sum(rtt_diffs) / len(rtt_diffs) if rtt_diffs else 0.0

        # SLA İhlal kontrolleri
        violations: List[str] = []
        # Ortalama RTT eşik kontrolü
        if avg_rtt > sla.get("max_ortalama_gecikme_ms", 150.0):
            # İhlal eklenir
            violations.append(f"Ortalama RTT ({avg_rtt:.2f}ms) SLA limitini ({sla['max_ortalama_gecikme_ms']}ms) aştı.")

        # Retransmission oranı kontrolü
        if retrans_rate_pct > sla.get("max_retrans_orani_yuzde", 5.0):
            # İhlal eklenir
            violations.append(f"TCP yeniden iletim oranı (%{retrans_rate_pct:.2f}) SLA limitini (%{sla['max_retrans_orani_yuzde']}) aştı.")

        # SLA durumu
        sla_status = "UYUMLU" if len(violations) == 0 else "IHLAL_VAR"

        # Aşırı TCP retransmission (%25+) tıkanıklık veya DoS uyarısı
        if retrans_rate_pct >= 25.0:
            # Durum kritik
            sla_status = "KRITIK_TEHLIKE"

        # İhlal durumunda istisna fırlatma
        if raise_on_sla_violation and violations:
            # SLA hatası fırlatılır
            raise QoSSLAThresholdViolationError(" | ".join(violations))

        # Sonuç nesnesi döndürülür
        return QoSMetricsResult(
            akis_id=flow_id,
            protokol=proto,
            gonderilen_paket_sayisi=total_segments,
            alinan_paket_sayisi=total_segments - retrans_count,
            kaybolan_paket_sayisi=retrans_count,
            kayip_orani_yuzde=round(retrans_rate_pct, 2),
            ortalama_gecikme_ms=round(avg_rtt, 2),
            min_gecikme_ms=round(min_rtt, 2),
            max_gecikme_ms=round(max_rtt, 2),
            ortalama_jitter_ms=round(mean_rtt_jitter, 2),
            rfc3550_jitter_ms=round(mean_rtt_jitter * 0.85, 2),
            retransmission_sayisi=retrans_count,
            retransmission_orani_yuzde=round(retrans_rate_pct, 2),
            sla_durumu=sla_status,
            sla_ihlal_sebepleri=violations
        )

    # Çoklu akışları toplu olarak analiz eden raporlama metodu
    def analyze_full_telemetry_batch(self, telemetry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tüm ağ telemetri veri setini inceler; akış bazlı QoS metrikleri ve adli bilişim özeti sunar."""
        # Sonuç listesi
        flow_results: List[QoSMetricsResult] = []

        # Veri setindeki her akış taranır
        for key, stream_dict in telemetry_data.items():
            # Açıklama veya meta-veri alanları atlanır
            if not isinstance(stream_dict, dict) or "akis_id" not in stream_dict:
                # Bir sonraki anahtara geçilir
                continue

            # Protokol türü belirlenir
            proto = str(stream_dict.get("protokol", "")).upper()
            # TCP ise TCP analizi yürütülür
            if proto == "TCP" or "segmentler" in stream_dict:
                # TCP analizi çağrılır
                res = self.analyze_tcp_stream(stream_dict, raise_on_sla_violation=False)
                # Listeye eklenir
                flow_results.append(res)
            # UDP veya VoIP ise UDP analizi yürütülür
            else:
                # UDP analizi çağrılır
                res = self.analyze_udp_voip_stream(stream_dict, raise_on_sla_violation=False)
                # Listeye eklenir
                flow_results.append(res)

        # Uyumlu ve ihlalli akış sayıları hesaplanır
        compliant_count = sum(1 for f in flow_results if f.sla_durumu == "UYUMLU")
        # İhlal sayısı
        violation_count = sum(1 for f in flow_results if f.sla_durumu != "UYUMLU")

        # Toplu rapor sözlüğü inşa edilir
        return {
            "toplam_akis_sayisi": len(flow_results),
            "uyumlu_akis_sayisi": compliant_count,
            "ihlal_edilen_akis_sayisi": violation_count,
            "genel_ag_sagligi": "SAGLIKLI" if violation_count == 0 else "TIKANIKLIK_VE_IHLAL_TESPIT_EDILDI",
            "akislar": [
                {
                    "akis_id": r.akis_id,
                    "protokol": r.protokol,
                    "gonderilen_paket": r.gonderilen_paket_sayisi,
                    "alinan_paket": r.alinan_paket_sayisi,
                    "kaybolan_paket": r.kaybolan_paket_sayisi,
                    "kayip_yuzdesi": r.kayip_orani_yuzde,
                    "ortalama_gecikme_ms": r.ortalama_gecikme_ms,
                    "ortalama_jitter_ms": r.ortalama_jitter_ms,
                    "rfc3550_jitter_ms": r.rfc3550_jitter_ms,
                    "retransmission_sayisi": r.retransmission_sayisi,
                    "sla_durumu": r.sla_durumu,
                    "ihlaller": r.sla_ihlal_sebepleri
                }
                for r in flow_results
            ]
        }
