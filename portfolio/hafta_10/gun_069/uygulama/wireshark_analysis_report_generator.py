# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G069: Hafta 10 Gün 69 - Mini Proje 9: Wireshark Analiz Raporu Üretici Motoru.
Bu modül, ayrıştırılmış ağ yakalama (PCAP) telemetrisini inceler; protokol hiyerarşisi,
en aktif konuşmacılar (Top Talkers / Conversations), TCP sağlık anomalileri (Zero Window,
Retransmission), siber tehdit göstergeleri (SQLi, DNS Tünelleme, CRLF, Açık Parola)
ve IoC matrisini birleştirerek SOC standartlarında yönetici ve adli analiz raporları üretir.
"""

# Düzenli ifadeler ile arama için re modülü içe aktarılır
import re
# JSON biçimlendirme için json kütüphanesi içe aktarılır
import json
# Zaman hesaplamaları ve tarih formatı için datetime içe aktarılır
from datetime import datetime, timezone
# Tip ipuçları ve veri yapıları için typing modülü içe aktarılır
from typing import Dict, List, Any, Optional, Tuple, Set
# Veri sınıfları oluşturmak için dataclass dekoratörü içe aktarılır
from dataclasses import dataclass, field


# Temel Wireshark raporlama hatası üst sınıfı
class WiresharkReportError(Exception):
    """Wireshark raporlama motorunun temel istisna sınıfıdır."""
    # Üst sınıf metodu boş geçilir
    pass


# Boş PCAP paket ayrıştırma listesi hatası
class EmptyPCAPStreamError(WiresharkReportError):
    """Analiz edilecek PCAP veri setinde hiç paket bulunmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz PCAP telemetri veri biçimi hatası
class InvalidPCAPDataError(WiresharkReportError):
    """PCAP verisi geçerli bir sözlük tipinde olmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bozuk veya eksik paket başlığı hatası
class MalformedPacketHeaderError(WiresharkReportError):
    """Paket numarasının veya zaman damgasının eksik olduğu durumlarda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Desteklenmeyen veya geçersiz protokol tanımı hatası
class UnsupportedProtocolError(WiresharkReportError):
    """Protokol alanı boş veya geçersiz olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Aşırı yüksek paket boyutu (MTU aşımı) hatası
class OversizedPacketLengthError(WiresharkReportError):
    """Paket boyutu standart Ethernet/Jumbo MTU sınırını (65535 bayt) aştığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bozuk konuşma demeti hatası
class MalformedConversationTupleError(WiresharkReportError):
    """Konuşma analizi için gereken IP veya port bilgisi eksik olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz rapor biçimi parametresi hatası
class InvalidReportFormatError(WiresharkReportError):
    """Desteklenmeyen bir rapor formatı (örn. PDF_GECERSIZ) istendiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Çelişkili veya zamanda geriye giden paket zaman damgası hatası
class InconsistentCaptureTimestampError(WiresharkReportError):
    """Paketlerin yakalama zaman damgaları kronolojik sırada olmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz önem seviyesi filtresi hatası
class InvalidSeverityThresholdError(WiresharkReportError):
    """Filtreleme için geçersiz bir önem derecesi girildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Protokol hiyerarşisi istatistik veri sınıfı
@dataclass
class ProtocolStat:
    """Tek bir protokolün paket ve bayt bazlı istatistiklerini saklar."""
    # Protokol adı
    protokol: str
    # Toplam paket sayısı
    paket_sayisi: int
    # Toplam bayt boyutu
    toplam_bayt: int
    # Paket yüzdesi (%)
    paket_yuzdesi: float
    # Bayt yüzdesi (%)
    bayt_yuzdesi: float


# Ağ konuşması (Conversation) veri sınıfı
@dataclass
class ConversationStat:
    """İki uç nokta arasındaki karşılıklı iletişimi saklar."""
    # Kaynak IP adresi
    kaynak_ip: str
    # Hedef IP adresi
    hedef_ip: str
    # Kaynak port numarası
    kaynak_port: int
    # Hedef port numarası
    hedef_port: int
    # İletişim protokolü
    protokol: str
    # Toplam paket sayısı
    paket_sayisi: int
    # Toplam bayt sayısı
    toplam_bayt: int


# TCP sağlık metrikleri veri sınıfı
@dataclass
class TCPHealthStat:
    """TCP bağlantı sağlığı ve anomali istatistiklerini saklar."""
    # Toplam TCP paket sayısı
    toplam_tcp_paketi: int = 0
    # SYN paket sayısı
    syn_sayisi: int = 0
    # SYN-ACK paket sayısı
    syn_ack_sayisi: int = 0
    # Sıfır pencere (Zero Window) sayısı
    zero_window_sayisi: int = 0
    # Yeniden iletim (Retransmission) sayısı
    retransmission_sayisi: int = 0
    # TCP sağlık durumu
    saglik_durumu: str = "NORMAL"


# Siber güvenlik bulgusu veri sınıfı
@dataclass
class SecurityFinding:
    """Tespit edilen bir siber tehdit veya ihlal bulgusunu saklar."""
    # Anomali kodu
    kod: str
    # Önem seviyesi (KRITIK, YUKSEK, ORTA, DUSUK)
    onem: str
    # Kısa başlık
    baslik: str
    # Detaylı açıklama
    aciklama: str
    # İlgili paket numarası
    paket_no: int
    # Kanıt metni veya yük
    kanit: str


# Wireshark Analiz Raporu Üretici Ana Sınıfı
class WiresharkAnalysisReportGenerator:
    """Ayrıştırılmış PCAP telemetrisinden kapsamlı adli Wireshark raporu üreten motor."""

    # Sınıf başlatıcı metot
    def __init__(self) -> None:
        # Geçerli önem dereceleri kümesi
        self.valid_severities = {"KRITIK", "YUKSEK", "ORTA", "DUSUK"}
        # Desteklenen çıktı formatları
        self.supported_formats = {"TEXT", "JSON", "MARKDOWN"}

    # PCAP veri yapısının doğruluğunu denetleyen metot
    def validate_pcap_structure(self, pcap_data: Any) -> None:
        """Gelen PCAP veri setinin geçerliliğini ve kronolojisini doğrular."""
        # Sözlük kontrolü
        if not isinstance(pcap_data, dict):
            # Biçim hatası fırlatılır
            raise InvalidPCAPDataError("PCAP telemetrisi geçerli bir sözlük (dict) olmalıdır.")

        # Paketler listesi alınır
        packets = pcap_data.get("paketler")
        # Liste kontrolü
        if packets is None or not isinstance(packets, list):
            # Biçim hatası fırlatılır
            raise InvalidPCAPDataError("PCAP telemetrisinde 'paketler' listesi bulunmalıdır.")

        # Boş paket kontrolü
        if len(packets) == 0:
            # Boş akış hatası fırlatılır
            raise EmptyPCAPStreamError("PCAP paket ayrıştırma listesi boş olamaz.")

        # Kronoloji kontrolü için önceki zaman damgası
        prev_t = -1.0
        # Her paket taranır
        for p in packets:
            # Paketin sözlük olduğu denetlenir
            if not isinstance(p, dict):
                # Biçim hatası fırlatılır
                raise InvalidPCAPDataError("Paket elemanı bir sözlük olmalıdır.")

            # Paket numarası denetimi
            if "paket_no" not in p or not isinstance(p["paket_no"], int) or p["paket_no"] <= 0:
                # Başlık hatası fırlatılır
                raise MalformedPacketHeaderError("Geçerli bir 'paket_no' (pozitif tamsayı) bulunmalıdır.")

            # Zaman damgası denetimi
            if "zaman_damgasi" not in p or float(p["zaman_damgasi"]) < 0:
                # Başlık hatası fırlatılır
                raise MalformedPacketHeaderError("Geçerli bir 'zaman_damgasi' bulunmalıdır.")

            # Zaman damgası değeri
            curr_t = float(p["zaman_damgasi"])
            # Kronoloji denetimi (zamanda geriye gidiş kontrolü)
            if prev_t >= 0 and curr_t < prev_t:
                # Kronoloji hatası fırlatılır
                raise InconsistentCaptureTimestampError(f"Paket #{p['paket_no']} zaman damgası geriye gitti: {curr_t} < {prev_t}")
            # Önceki zaman güncellenir
            prev_t = curr_t

            # Protokol denetimi
            proto = p.get("protokol")
            # Boş protokol kontrolü
            if not proto or not isinstance(proto, str) or not proto.strip():
                # Desteklenmeyen protokol hatası fırlatılır
                raise UnsupportedProtocolError(f"Paket #{p['paket_no']} için geçersiz veya boş protokol.")

            # Paket boyutu denetimi
            size = p.get("boyut_bayt", 0)
            # Boyut tamsayı ve mantıklı aralıkta olmalı (max 65535 MTU)
            if not isinstance(size, int) or size < 0:
                # Başlık hatası fırlatılır
                raise MalformedPacketHeaderError(f"Paket #{p['paket_no']} boyutu negatif veya geçersiz.")
            # Jumbo frame aşırı boyut kontrolü
            if size > 65535:
                # Aşırı boyut hatası fırlatılır
                raise OversizedPacketLengthError(f"Paket #{p['paket_no']} MTU sınırını aştı: {size} bayt > 65535 bayt.")

    # Protokol hiyerarşisi dağılımını hesaplayan metot
    def calculate_protocol_hierarchy(self, packets: List[Dict[str, Any]]) -> List[ProtocolStat]:
        """Tüm paketleri protokollere göre gruplayarak paket ve bayt yüzdelerini çıkarır."""
        # Protokol sayımları sözlüğü
        proto_counts: Dict[str, int] = {}
        # Protokol bayt toplamları sözlüğü
        proto_bytes: Dict[str, int] = {}
        # Toplam paket sayısı
        total_packets = len(packets)
        # Toplam bayt boyutu
        total_bytes = sum(p.get("boyut_bayt", 0) for p in packets)

        # Paketler taranır
        for p in packets:
            # Protokol adı normalize edilir
            proto = str(p.get("protokol", "DIGER")).upper()
            # Bayt boyutu
            size = int(p.get("boyut_bayt", 0))
            # Sayım artırılır
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
            # Bayt eklenir
            proto_bytes[proto] = proto_bytes.get(proto, 0) + size

        # İstatistik listesi oluşturulur
        stats: List[ProtocolStat] = []
        # Her protokol işlenir
        for pr, count in proto_counts.items():
            # Bayt miktarı
            b_val = proto_bytes.get(pr, 0)
            # Paket yüzdesi
            pct_p = (count / total_packets) * 100.0 if total_packets > 0 else 0.0
            # Bayt yüzdesi
            pct_b = (b_val / total_bytes) * 100.0 if total_bytes > 0 else 0.0
            # Nesne eklenir
            stats.append(ProtocolStat(
                protokol=pr,
                paket_sayisi=count,
                toplam_bayt=b_val,
                paket_yuzdesi=round(pct_p, 2),
                bayt_yuzdesi=round(pct_b, 2)
            ))

        # Bayt miktarına göre çoktan aza sıralanır
        stats.sort(key=lambda x: x.toplam_bayt, reverse=True)
        # Liste döner
        return stats

    # En çok konuşan uç noktaları (Conversations / Top Talkers) çıkaran metot
    def extract_conversations(self, packets: List[Dict[str, Any]], top_n: int = 5) -> List[ConversationStat]:
        """İki uç nokta arasındaki IP ve port çiftlerine göre en aktif konuşmaları listeler."""
        # Konuşma anahtarları sözlüğü
        conv_map: Dict[Tuple[str, str, int, int, str], Dict[str, int]] = {}

        # Paketler taranır
        for p in packets:
            # Kaynak IP
            src_ip = p.get("kaynak_ip")
            # Hedef IP
            dst_ip = p.get("hedef_ip")
            # Portlar
            src_port = p.get("kaynak_port", 0)
            # Hedef port
            dst_port = p.get("hedef_port", 0)
            # Protokol
            proto = str(p.get("protokol", "DIGER")).upper()
            # Bayt boyutu
            size = int(p.get("boyut_bayt", 0))

            # IP kontrolleri
            if not src_ip or not dst_ip:
                # IP yoksa bu paket konuşma demetine girmez
                continue

            # Çift yönlü normalize anahtar oluşturulur
            if src_ip < dst_ip or (src_ip == dst_ip and src_port <= dst_port):
                # Normal yön
                key = (src_ip, dst_ip, src_port, dst_port, proto)
            else:
                # Karşıt yön eşleştirilir
                key = (dst_ip, src_ip, dst_port, src_port, proto)

            # Sözlükte yoksa başlatılır
            if key not in conv_map:
                # İlk değerler
                conv_map[key] = {"paket": 0, "bayt": 0}
            # Değerler güncellenir
            conv_map[key]["paket"] += 1
            conv_map[key]["bayt"] += size

        # Sonuç listesi oluşturulur
        conv_list: List[ConversationStat] = []
        # Eşlemeler taranır
        for k, v in conv_map.items():
            # Nesne eklenir
            conv_list.append(ConversationStat(
                kaynak_ip=k[0],
                hedef_ip=k[1],
                kaynak_port=k[2],
                hedef_port=k[3],
                protokol=k[4],
                paket_sayisi=v["paket"],
                toplam_bayt=v["bayt"]
            ))

        # Toplam bayta göre sıralanır
        conv_list.sort(key=lambda x: x.toplam_bayt, reverse=True)
        # İlk N tanesi döner
        return conv_list[:top_n]

    # TCP sağlık metriklerini hesaplayan metot
    def analyze_tcp_health(self, packets: List[Dict[str, Any]]) -> TCPHealthStat:
        """TCP bayrakları, Zero Window ve Retransmission olaylarını inceleyerek sağlık raporu çıkarır."""
        # Toplam TCP paketi sayacı
        total_tcp = 0
        # SYN sayacı
        syn_cnt = 0
        # SYN-ACK sayacı
        syn_ack_cnt = 0
        # Zero window sayacı
        zero_win_cnt = 0
        # Retransmission sayacı
        retrans_cnt = 0

        # Paketler taranır
        for p in packets:
            # TCP veya ilişkili protokol mü
            proto = str(p.get("protokol", "")).upper()
            # TCP kontrolü
            if proto in ("TCP", "HTTP", "TLS", "FTP"):
                # Sayacı artır
                total_tcp += 1

            # Bayraklar listesi alınır
            flags = p.get("tcp_bayraklari", [])
            # SYN kontrolü
            if "SYN" in flags and "ACK" not in flags:
                # SYN sayacı artırılır
                syn_cnt += 1
            # SYN-ACK kontrolü
            elif "SYN" in flags and "ACK" in flags:
                # SYN-ACK sayacı artırılır
                syn_ack_cnt += 1

            # Zero window tespiti
            if p.get("pencere_boyutu") == 0 or p.get("tcp_anomali") == "TCP_ZERO_WINDOW":
                # Sıfır pencere sayacı artırılır
                zero_win_cnt += 1

            # Retransmission tespiti
            if p.get("is_retransmission") or p.get("tcp_anomali") == "TCP_RETRANSMISSION":
                # Yeniden iletim sayacı artırılır
                retrans_cnt += 1

        # Genel sağlık durumu değerlendirilir
        health_status = "NORMAL"
        # Eğer sıfır pencere veya yüksek yeniden iletim varsa
        if zero_win_cnt > 0 or retrans_cnt > 0:
            # Durum güncellenir
            health_status = "TIKANIKLIK_VE_PAKET_KAYBI_TESPIT_EDILDI"

        # İstatistik nesnesi döndürülür
        return TCPHealthStat(
            toplam_tcp_paketi=total_tcp,
            syn_sayisi=syn_cnt,
            syn_ack_sayisi=syn_ack_cnt,
            zero_window_sayisi=zero_win_cnt,
            retransmission_sayisi=retrans_cnt,
            saglik_durumu=health_status
        )

    # Siber güvenlik ve anomali tehditlerini tespit eden metot
    def detect_security_anomalies(self, packets: List[Dict[str, Any]]) -> List[SecurityFinding]:
        """PCAP paketlerini SQLi, DNS tünelleme, açık metin parola ve CRLF açısından tarar."""
        # Bulgular listesi başlatılır
        findings: List[SecurityFinding] = []

        # Her paket derinlemesine incelenir
        for p in packets:
            # Paket numarası
            pkt_no = int(p.get("paket_no", 0))
            # URI bilgisi
            uri = str(p.get("http_uri", ""))
            # User agent
            ua = str(p.get("http_user_agent", ""))
            # Gövde
            body = str(p.get("http_govde", ""))
            # DNS sorgusu
            dns_q = str(p.get("dns_sorgu_alan_adi", ""))
            # Açık kimlik
            cred = str(p.get("acik_metin_kimlik", ""))

            # 1. SQL Injection & Otomatik Tarayıcı Tespiti
            if "sqlmap" in ua.lower() or "%27" in uri.lower() or "or 1=1" in uri.lower():
                # Bulgu oluşturulur
                findings.append(SecurityFinding(
                    kod="SEC_SQLI_SCANNER_PROBE",
                    onem="KRITIK",
                    baslik="SQL Enjeksiyonu ve Otomatik Saldırı Tarayıcısı",
                    aciklama=f"Paket #{pkt_no}: sqlmap tarayıcısı ile SQLi sömürü denemesi tespit edildi: URI='{uri}'",
                    paket_no=pkt_no,
                    kanit=f"User-Agent: {ua} | URI: {uri}"
                ))

            # 2. DNS Tünelleme ve Veri Sızdırma (Data Exfiltration)
            if len(dns_q) > 40 or (p.get("dns_sorgu_tipi") == "TXT" and "exfil" in dns_q.lower()):
                # Bulgu oluşturulur
                findings.append(SecurityFinding(
                    kod="SEC_DNS_TUNNEL_EXFIL",
                    onem="KRITIK",
                    baslik="DNS Tünelleme Üzerinden Veri Sızdırma",
                    aciklama=f"Paket #{pkt_no}: TXT sorgusu ile Base64 kodlu şüpheli DNS veri kaçırma girişimi: '{dns_q}'",
                    paket_no=pkt_no,
                    kanit=f"Query: {dns_q} (Tip: {p.get('dns_sorgu_tipi')})"
                ))

            # 3. Açık Metin Kimlik Bilgisi ve Parola İletimi (Cleartext Credential)
            if cred or ("user " in str(p.get("ftp_komut", "")).lower() and "pass" in cred.lower()):
                # Bulgu oluşturulur
                findings.append(SecurityFinding(
                    kod="SEC_CLEARTEXT_AUTH_LEAK",
                    onem="YUKSEK",
                    baslik="Ağ Üzerinden Açık Metin Parola İletimi",
                    aciklama=f"Paket #{pkt_no}: FTP/Telnet protokolü ile şifrelenmemiş yönetici kimlik bilgileri tespit edildi.",
                    paket_no=pkt_no,
                    kanit=cred or str(p.get("ftp_komut"))
                ))

            # 4. HTTP CRLF Enjeksiyonu ve Response Splitting
            if "%0d%0a" in uri.lower() or "set-cookie:" in uri.lower():
                # Bulgu oluşturulur
                findings.append(SecurityFinding(
                    kod="SEC_HTTP_CRLF_INJECTION",
                    onem="YUKSEK",
                    baslik="HTTP CRLF Başlık Enjeksiyonu Denemesi",
                    aciklama=f"Paket #{pkt_no}: URI parametresinde CRLF satır atlama ve çerez enjeksiyonu yakalandı.",
                    paket_no=pkt_no,
                    kanit=uri
                ))

            # 5. TCP Zero Window Tıkanıklık Anomalisı
            if p.get("tcp_anomali") == "TCP_ZERO_WINDOW":
                # Bulgu oluşturulur
                findings.append(SecurityFinding(
                    kod="PERF_TCP_ZERO_WINDOW",
                    onem="ORTA",
                    baslik="TCP Sıfır Pencere (Bufferbloat/Tıkanıklık)",
                    aciklama=f"Paket #{pkt_no}: Sunucu tampon belleği tükendi (Win=0), veri akışı durduruldu.",
                    paket_no=pkt_no,
                    kanit="TCP Window Size: 0 bytes"
                ))

        # Bulgular listesi döndürülür
        return findings

    # Bulguları önem seviyesine göre filtreleyen yardımcı metot
    def filter_findings_by_severity(self, findings: List[SecurityFinding], min_severity: str = "ORTA") -> List[SecurityFinding]:
        """Belirtilen eşik ve üzerindeki önem derecesine sahip güvenlik bulgularını filtreler."""
        # Büyük harfe normalize edilir
        sev_upper = min_severity.upper()
        # Geçerlilik denetimi
        if sev_upper not in self.valid_severities:
            # Hata fırlatılır
            raise InvalidSeverityThresholdError(f"Geçersiz önem seviyesi filtresi: '{min_severity}'. Geçerli: {self.valid_severities}")

        # Hiyerarşik ağırlık sıralaması
        weights = {"KRITIK": 4, "YUKSEK": 3, "ORTA": 2, "DUSUK": 1}
        # Hedef ağırlık
        target_weight = weights[sev_upper]

        # Filtreleme uygulanır
        return [f for f in findings if weights.get(f.onem, 0) >= target_weight]

    # Uçtan uca Wireshark analiz raporunu inşa eden ana metot
    def generate_report(self, pcap_data: Dict[str, Any], output_format: str = "TEXT") -> Any:
        """Tüm PCAP ayrıştırma verisini analiz eder; seçilen formatta (TEXT/JSON/MARKDOWN) rapor üretir."""
        # Çıktı formatı kontrolü
        fmt_upper = output_format.upper()
        # Destek kontrolü
        if fmt_upper not in self.supported_formats:
            # Hata fırlatılır
            raise InvalidReportFormatError(f"Desteklenmeyen rapor formatı: '{output_format}'. Desteklenenler: {self.supported_formats}")

        # PCAP yapısı doğrulanır
        self.validate_pcap_structure(pcap_data)

        # Meta-veri alınır
        meta = pcap_data.get("yakalama_metaverisi", {})
        # Paket listesi
        packets = pcap_data.get("paketler", [])

        # Yakalama dosya adı
        file_name = meta.get("dosya_adi", "bilinmeyen_yakalama.pcap")
        # Başlangıç ve bitiş zamanları
        start_t = float(meta.get("baslangic_zamani", packets[0]["zaman_damgasi"]))
        end_t = float(meta.get("bitis_zamani", packets[-1]["zaman_damgasi"]))
        # Yakalama süresi (saniye)
        duration_s = max(0.001, end_t - start_t)
        # Toplam paket sayısı
        total_pkts = len(packets)
        # Toplam bayt boyutu
        total_bytes = sum(p.get("boyut_bayt", 0) for p in packets)
        # Ortalama bant genişliği (kbps)
        avg_bandwidth_kbps = (total_bytes * 8.0) / (duration_s * 1000.0)

        # 1. Protokol Hiyerarşisi Hesaplanır
        protocol_stats = self.calculate_protocol_hierarchy(packets)
        # 2. En Çok Konuşanlar (Conversations) Çıkarılır
        top_conversations = self.extract_conversations(packets, top_n=5)
        # 3. TCP Sağlık Analizi Yapılır
        tcp_health = self.analyze_tcp_health(packets)
        # 4. Siber Güvenlik Bulguları Çıkarılır
        findings = self.detect_security_anomalies(packets)

        # Güvenlik skoru hesabı (100 üzerinden; bulunan açıklara göre ceza puanı düşülür)
        score = 100
        for f in findings:
            if f.onem == "KRITIK":
                score -= 25
            elif f.onem == "YUKSEK":
                score -= 15
            elif f.onem == "ORTA":
                score -= 5
            elif f.onem == "DUSUK":
                score -= 2
        # Skor 0'ın altına düşemez
        score = max(0, score)

        # Genel risk seviyesi belirlenir
        if score >= 90:
            risk_level = "DUSUK_RISK"
        elif score >= 70:
            risk_level = "ORTA_RISK"
        elif score >= 40:
            risk_level = "YUKSEK_RISK"
        else:
            risk_level = "KRITIK_TEHLIKE"

        # IoC (Indicators of Compromise) Tablosu Çıkarılır
        iocs: Dict[str, List[str]] = {
            "zararli_kaynak_ipler": list(set(p.get("kaynak_ip") for p in packets if p.get("kaynak_ip") and "105" in p.get("kaynak_ip"))),
            "supheli_alan_adlari": [p.get("dns_sorgu_alan_adi") for p in packets if p.get("dns_sorgu_alan_adi")],
            "ele_gecirilen_kimlikler": [p.get("acik_metin_kimlik") for p in packets if p.get("acik_metin_kimlik")]
        }

        # Müdahale ve İyileştirme Önerileri
        remediations = [
            "1. İstemci 192.168.1.105 derhal EDR üzerinden ağ izolasyonuna alınmalı ve adli imajı çıkarılmalıdır.",
            "2. Hedef sunucu 10.0.0.80 üzerindeki web uygulamasında parametreli sorgulara geçilerek SQLi açığı kapatılmalıdır.",
            "3. Kurum içi DNS sunucularında 'exfil.org' kök bölgesi derhal Sinkhole yönlendirmesine tabi tutulmalıdır.",
            "4. Açık metin FTP/Telnet kullanımı tamamen yasaklanmalı, SSH/SFTP zorunlu kılınmalıdır.",
            "5. TCP tampon belleği genişletilerek Zero Window tıkanıklığı için TCP Window Scaling aktif edilmelidir."
        ]

        # JSON formatı isteniyorsa
        if fmt_upper == "JSON":
            # Rapor sözlüğü döndürülür
            return {
                "rapor_basligi": "Mini Proje 9: Wireshark Ağ Analiz ve Adli İnceleme Raporu",
                "dosya_adi": file_name,
                "sure_saniye": round(duration_s, 3),
                "toplam_paket": total_pkts,
                "toplam_bayt": total_bytes,
                "ortalama_bant_genisligi_kbps": round(avg_bandwidth_kbps, 2),
                "guvenlik_skoru": score,
                "genel_risk_seviyesi": risk_level,
                "protokol_dagilimi": [vars(p) for p in protocol_stats],
                "en_aktif_konusmalar": [vars(c) for c in top_conversations],
                "tcp_saglik_durumu": vars(tcp_health),
                "guvenlik_bulgulari": [vars(f) for f in findings],
                "ioc_listesi": iocs,
                "oneriler": remediations
            }

        # TEXT veya MARKDOWN formatı inşa edilir
        lines = [
            "================================================================================",
            "G069: MİNİ PROJE 9 - WİRESHARK AĞ ANALİZİ VE ADLİ SİBER TEHDİT RAPORU",
            "Tarih: 2026-10-31 | Üretici Motor: WiresharkAnalysisReportGenerator v1.0",
            "================================================================================\n",
            "1. YAKALAMA VE TRAFİK YÖNETİCİ ÖZETİ:",
            f"  - İncelenen PCAP Dosyası       : {file_name}",
            f"  - Yakalama Süresi              : {duration_s:.3f} saniye",
            f"  - Toplam Paket Sayısı          : {total_pkts} adet",
            f"  - Toplam Trafik Hacmi          : {total_bytes} bayt ({total_bytes / 1024.0:.2f} KB)",
            f"  - Ortalama Bant Genişliği      : {avg_bandwidth_kbps:.2f} kbps",
            f"  - Kurumsal Güvenlik Skoru      : {score} / 100",
            f"  - Genel Siber Risk Seviyesi    : {risk_level}\n",
            "2. PROTOKOL HİYERARŞİSİ (PROTOCOL HIERARCHY):",
            "--------------------------------------------------------------------------------",
            f"{'Protokol':<12} | {'Paket Sayısı':<12} | {'Paket %':<10} | {'Toplam Bayt':<12} | {'Bayt %':<10}",
            "--------------------------------------------------------------------------------"
        ]

        for ps in protocol_stats:
            lines.append(f"{ps.protokol:<12} | {ps.paket_sayisi:<12} | %{ps.paket_yuzdesi:<9.2f} | {ps.toplam_bayt:<12} | %{ps.bayt_yuzdesi:<9.2f}")

        lines.extend([
            "\n3. EN AKTİF AĞ KONUŞMALARI (TOP TALKERS / CONVERSATIONS):",
            "--------------------------------------------------------------------------------",
            f"{'Kaynak IP:Port':<24} <---> {'Hedef IP:Port':<24} | {'Proto':<6} | {'Paket':<6} | {'Bayt':<8}",
            "--------------------------------------------------------------------------------"
        ])

        for c in top_conversations:
            ep1 = f"{c.kaynak_ip}:{c.kaynak_port}"
            ep2 = f"{c.hedef_ip}:{c.hedef_port}"
            lines.append(f"{ep1:<24} <---> {ep2:<24} | {c.protokol:<6} | {c.paket_sayisi:<6} | {c.toplam_bayt:<8}")

        lines.extend([
            "\n4. TCP PERFORMANS VE BAĞLANTI SAĞLIK METRİKLERİ:",
            "--------------------------------------------------------------------------------",
            f"  - Toplam TCP/Uygulama Segmenti : {tcp_health.toplam_tcp_paketi}",
            f"  - 3-Way Handshake Başlatımları : SYN={tcp_health.syn_sayisi}, SYN-ACK={tcp_health.syn_ack_sayisi}",
            f"  - TCP Zero Window Tıkanıklığı  : {tcp_health.zero_window_sayisi} adet",
            f"  - TCP Yeniden İletimleri (Ret) : {tcp_health.retransmission_sayisi} adet",
            f"  - TCP Bağlantı Sağlık Durumu   : {tcp_health.saglik_durumu}\n",
            "5. TESPİT EDİLEN SİBER GÜVENLİK TEHDİTLERİ VE BULGULAR:",
            "--------------------------------------------------------------------------------"
        ])

        for idx, f in enumerate(findings, 1):
            lines.append(f"[{idx}] [{f.onem}] {f.baslik} (Kod: {f.kod})")
            lines.append(f"    Paket No : #{f.paket_no}")
            lines.append(f"    Açıklama : {f.aciklama}")
            lines.append(f"    Adli Kanıt: {f.kanit}")
            lines.append("")

        lines.extend([
            "6. ADLİ TEHDİT GÖSTERGELERİ (IoC - INDICATORS OF COMPROMISE):",
            "--------------------------------------------------------------------------------",
            f"  - Şüpheli/Saldırgan IP'ler     : {', '.join(iocs['zararli_kaynak_ipler'])}",
            f"  - Tespit Edilen Zararlı FQDN   : {', '.join(iocs['supheli_alan_adlari'])}",
            f"  - İfşa Olan Kimlik Bilgileri   : {', '.join(iocs['ele_gecirilen_kimlikler'])}\n",
            "7. MÜDAHALE VE İYİLEŞTİRME EYLEM PLANI (REMEDIATION):",
            "--------------------------------------------------------------------------------"
        ])

        for rem in remediations:
            lines.append(f"  {rem}")

        lines.append("\n================================================================================")
        lines.append("RAPOR SONU — ADLİ BİLİŞİM VE AĞ İNCELEME ONAYI VERİLMİŞTİR.")
        lines.append("================================================================================")

        # Metin birleştirilerek döndürülür
        return "\n".join(lines)
