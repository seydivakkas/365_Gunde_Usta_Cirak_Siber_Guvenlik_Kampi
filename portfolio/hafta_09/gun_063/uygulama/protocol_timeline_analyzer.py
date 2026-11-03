# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G063: Hafta 09 Mini Proje 8 - Protokol Zaman Çizelgesi Analiz Motoru (Protocol Timeline Analyzer).
Bu modül, zaman serisi paket olaylarını analiz eder, protokol akışlarını (TCP, TLS, HTTP/2, DNS)
kronolojik olarak birleştirir, gecikme (RTT, delta) metriklerini hesaplar ve zamansal anormallikleri
(Slowloris, Port Tarama, Sıra Sıçraması, Erken Veri, Zaman Gerilemesi) tespit eder.
"""

# Tarih ve saat manipülasyonu için datetime ve timezone kütüphaneleri içe aktarılır
from datetime import datetime, timezone
# Karmaşık veri yapıları ve tip denetimi için typing modülünden tipler içe aktarılır
from typing import Dict, List, Any, Optional, Tuple, Set
# Yapılandırılmış sınıflar için dataclass ve field dekoratörleri içe aktarılır
from dataclasses import dataclass, field
# Matematiksel ve istatistiksel hesaplamalar için math modülü içe aktarılır
import math
# Düzenli ifadeler ile dizgi ayrıştırma ve entropi tespiti için re modülü içe aktarılır
import re


# Temel zaman çizelgesi istisna sınıfı
class TimelineError(Exception):
    """Zaman çizelgesi motorunda oluşan tüm genel hataların üst sınıfıdır."""
    # Üst sınıf metodu boş geçilir
    pass


# Zaman sırası ihlali istisnası
class TimelineOrderError(TimelineError):
    """Kronolojik zaman sırasının bozulduğu veya geriye doğru gittiği durumlarda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Zaman damgası biçimlendirme hatası istisnası
class TimestampFormatError(TimelineError):
    """ISO-8601 veya geçerli zaman damgası ayrıştırılamadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# El sıkışma kuralı ihlali istisnası
class HandshakeViolationError(TimelineError):
    """El sıkışma tamamlanmadan veri iletildiğinde veya protokol sırası bozulduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# TCP sıra numarası anomali istisnası
class SequenceAnomalyError(TimelineError):
    """TCP sıra numaralarında açıklanamayan sıçramalar veya oturum çalma belirtisi olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Slowloris yavaş başlık iletim anomali istisnası
class SlowlorisAnomalyError(TimelineError):
    """HTTP başlıklarının bağlantıyı açık tutmak amacıyla kasıtlı yavaş iletildiği durumlarda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Hızlı port taraması anomali istisnası
class PortScanAnomalyError(TimelineError):
    """Kısa zaman aralığında birden fazla porta yönelik seri SYN paketleri tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# DNS tünelleme anomali istisnası
class DnsTunnelingAnomalyError(TimelineError):
    """Kısa sürede yüksek entropili ve uzun alt alan adı sorguları gerçekleştirildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Zorunlu alan eksikliği istisnası
class MissingEventFieldError(TimelineError):
    """Paket olay tanımında bulunması zorunlu alanlar eksik olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz durum geçişi istisnası
class IllegalStateTransitionError(TimelineError):
    """Protokol sonlu durum makinesinde geçersiz bir durum geçişi denendiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Ağ olayını modelleyen veri sınıfı
@dataclass
class NetworkEvent:
    """Tekil bir ağ paketi veya protokol olayını kronolojik meta verilerle temsil eder."""
    # Olayın benzersiz kimliği
    olay_id: str
    # Orijinal metin formatındaki zaman damgası
    zaman_damgasi_str: str
    # Unix epoch formatındaki kayan noktalı saniye değeri
    zaman_damgasi_epoch: float
    # Protokol adı (DNS, TCP, TLS, HTTP2, HTTP)
    protokol: str
    # Kaynak IP adresi
    kaynak_ip: str
    # Hedef IP adresi
    hedef_ip: str
    # Kaynak port numarası
    kaynak_port: int
    # Hedef port numarası
    hedef_port: int
    # İşlem tipi (örn: TCP_SYN, TLS_CLIENT_HELLO, DNS_QUERY)
    islem_tipi: str
    # TCP bayrakları listesi
    bayraklar: List[str] = field(default_factory=list)
    # TCP sıra numarası (varsa)
    sira_no: Optional[int] = None
    # TCP onay numarası (varsa)
    onay_no: Optional[int] = None
    # TCP pencere boyutu (varsa)
    pencere_boyutu: Optional[int] = None
    # Bayt cinsinden toplam paket boyutu
    paket_boyutu: int = 0
    # Protokole özgü ek öznitelikler sözlüğü
    detaylar: Dict[str, Any] = field(default_factory=dict)
    # Bir önceki olaya göre milisaniye cinsinden geçen süre
    delta_ms: float = 0.0


# Akış oturumunu modelleyen veri sınıfı
@dataclass
class FlowSession:
    """5-demet (5-tuple) bazında gruplanmış iki yönlü bir ağ akışını temsil eder."""
    # Akışın benzersiz kimliği (IP:Port <-> IP:Port)
    akis_id: str
    # İletişim protokolü
    protokol: str
    # Akışı başlatan istemci adresi ve portu
    istemci_soket: Tuple[str, int]
    # Hizmet veren sunucu adresi ve portu
    sunucu_soket: Tuple[str, int]
    # Akışın başladığı epoch zamanı
    baslangic_zamani: float
    # Akışın son paketinin epoch zamanı
    bitis_zamani: float
    # Akışa ait toplam paket sayısı
    paket_sayisi: int = 0
    # Akışta iletilen toplam bayt miktarı
    toplam_bayt: int = 0
    # TCP sonlu durum makinesi güncel durumu (CLOSED, SYN_SENT, SYN_RCVD, ESTABLISHED, vb.)
    tcp_durumu: str = "CLOSED"
    # El sıkışma dönüş süresi (Round Trip Time) milisaniye
    rtt_ms: Optional[float] = None
    # TLS el sıkışma durumu
    tls_el_sikisma_tamamlandi: bool = False
    # HTTP/2 aktif akım (stream) kimlikleri kümesi
    http2_akimlar: Set[int] = field(default_factory=set)


# Zaman çizelgesi anomalisini modelleyen veri sınıfı
@dataclass
class TimelineAnomaly:
    """Zaman çizelgesinde saptanan bir güvenlik veya protokol anormalliğini temsil eder."""
    # Anomali kodu / tipi
    anomali_tipi: str
    # Tehlike seviyesi (DUSUK, ORTA, YUKSEK, KRITIK)
    onem_derecesi: str
    # Anomali açıklaması ve ayrıntıları
    aciklama: str
    # Anomaliyle doğrudan ilişkili olay kimlikleri listesi
    ilgili_olaylar: List[str]
    # Anomali tespit zaman damgası
    tespit_zamani: str


# Protokol zaman çizelgesi analiz motoru ana sınıfı
class ProtocolTimelineAnalyzer:
    """Çoklu protokol paket izlerini zamana göre sıralayan, birleştiren ve anomali tarayan motor."""

    # Sınıf başlatıcı metot
    def __init__(self) -> None:
        # Bellekte tutulan ayrıştırılmış olaylar listesi başlatılır
        self.olaylar: List[NetworkEvent] = []
        # Reconstruct edilen 5-demet akış oturumları haritası
        self.akislar: Dict[str, FlowSession] = {}
        # Tespit edilen güvenlik ve protokol anomalileri listesi
        self.anomaliler: List[TimelineAnomaly] = []

    # ISO-8601 tarih dizgisini epoch saniyeye dönüştüren yardımcı metot
    @staticmethod
    def parse_iso_timestamp(ts_str: str) -> float:
        """ISO-8601 formatındaki zaman damgasını doğrular ve epoch saniyeye dönüştürür."""
        # Zaman damgasının boş veya dize olmadığını denetler
        if not isinstance(ts_str, str) or not ts_str.strip():
            # Geçersiz zaman damgası hatası fırlatılır
            raise TimestampFormatError(f"Zaman damgası boş veya geçersiz: {ts_str}")
        # Zaman damgası metnindeki boşluklar temizlenir
        ts_cleaned = ts_str.strip()
        # 'Z' zaman dilimi belirtecini Python standart '+00:00' ile ikame eder
        if ts_cleaned.endswith("Z"):
            # Z karakteri yerine UTC ofsetini yerleştirir
            ts_cleaned = ts_cleaned[:-1] + "+00:00"
        # Hata yakalama bloğu ile ayrıştırma denenir
        try:
            # Datetime modülü ile ISO formatından ayrıştırılır
            dt = datetime.fromisoformat(ts_cleaned)
            # Zaman damgasının POSIX epoch saniye değeri hesaplanır ve döndürülür
            return dt.timestamp()
        # Biçim uyuşmazlığı hatası yakalanır
        except ValueError as err:
            # Standart TimestampFormatError istisnası fırlatılır
            raise TimestampFormatError(f"Geçersiz ISO-8601 zaman formatı '{ts_str}': {err}")

    # Şannon entropi hesaplama metodu
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Verilen dizginin Şannon bilgi entropisini hesaplar (DNS tünelleme tespiti için)."""
        # Boş metin durumunda sıfır entropi döndürülür
        if not text:
            # Sıfır değerini döner
            return 0.0
        # Metindeki her bir karakterin frekansı sayılır
        probabilities = [float(text.count(c)) / len(text) for c in set(text)]
        # Entropi toplam formülü uygulanır: -sum(p * log2(p))
        return -sum(p * math.log2(p) for p in probabilities)

    # Olayları ham veri sözlüğünden içeri aktaran metot
    def load_events_from_dict(self, trace_dict: Dict[str, Any]) -> int:
        """Ham sözlük verisinden olayları okur, alan doğrulaması yapar ve motor belleğine aktarır."""
        # Girdi sözlüğünde 'olaylar' anahtarının varlığı kontrol edilir
        if "olaylar" not in trace_dict or not isinstance(trace_dict["olaylar"], list):
            # Eksik alan istisnası fırlatılır
            raise MissingEventFieldError("Girdi verisinde 'olaylar' listesi bulunamadı.")
        # Bellekteki olay listesi sıfırlanır
        self.olaylar = []
        # Tüm ham olaylar döngüye alınır
        for idx, raw_evt in enumerate(trace_dict["olaylar"]):
            # Zorunlu alanların kontrolü için küme oluşturulur
            required_fields = {"olay_id", "zaman_damgasi", "protokol", "kaynak_ip", "hedef_ip", "islem_tipi"}
            # Eksik alanlar tespit edilir
            missing = required_fields - set(raw_evt.keys())
            # Eksik alan varsa hata verilir
            if missing:
                # Eksik alan ayrıntısıyla istisna fırlatılır
                raise MissingEventFieldError(f"Olay indeksi {idx} eksik zorunlu alanlar içeriyor: {missing}")
            # Zaman damgası ayrıştırılır ve epoch saniyeye çevrilir
            epoch_time = self.parse_iso_timestamp(raw_evt["zaman_damgasi"])
            # Ağ olayı nesnesi oluşturulur
            event_obj = NetworkEvent(
                olay_id=str(raw_evt["olay_id"]),
                zaman_damgasi_str=str(raw_evt["zaman_damgasi"]),
                zaman_damgasi_epoch=epoch_time,
                protokol=str(raw_evt["protokol"]).upper(),
                kaynak_ip=str(raw_evt["kaynak_ip"]),
                hedef_ip=str(raw_evt["hedef_ip"]),
                kaynak_port=int(raw_evt.get("kaynak_port", 0)),
                hedef_port=int(raw_evt.get("hedef_port", 0)),
                islem_tipi=str(raw_evt["islem_tipi"]).upper(),
                bayraklar=raw_evt.get("bayraklar", []),
                sira_no=raw_evt.get("sira_no"),
                onay_no=raw_evt.get("onay_no"),
                pencere_boyutu=raw_evt.get("pencere_boyutu"),
                paket_boyutu=int(raw_evt.get("paket_boyutu", 0)),
                detaylar=raw_evt.get("detaylar", {})
            )
            # Olay listesine eklenir
            self.olaylar.append(event_obj)
        # Yüklenen olay sayısı döndürülür
        return len(self.olaylar)

    # Zaman çizelgesi kronolojisini doğrulayan ve sıralayan metot
    def validate_and_sort_timeline(self, enforce_strict_monotonic: bool = True) -> None:
        """Olayları zaman sırasına dizer; geriye giden negatif delta durumlarında hata fırlatır."""
        # En az bir olay olup olmadığı kontrol edilir
        if not self.olaylar:
            # Olay yoksa işlem yapılmadan çıkılır
            return
        # Sıkı kronolojik sıralama denetimi aktifse kontrol yapılır
        if enforce_strict_monotonic:
            # Mevcut liste üzerinde negatif delta kontrolü yapılır
            for i in range(1, len(self.olaylar)):
                # Önceki ve şimdiki olay zaman farkı incelenir
                diff = self.olaylar[i].zaman_damgasi_epoch - self.olaylar[i - 1].zaman_damgasi_epoch
                # Zaman geriye gitmişse negatif delta oluşmuştur
                if diff < -1e-6:
                    # Anomali listesine kaydedilir
                    self.anomaliler.append(TimelineAnomaly(
                        anomali_tipi="NEGATIF_DELTA_ZAMAN_GERILEMESI",
                        onem_derecesi="KRITIK",
                        aciklama=f"Zaman damgası geriye gitti! Olay {self.olaylar[i].olay_id} zamanı {self.olaylar[i-1].olay_id} öncesinde.",
                        ilgili_olaylar=[self.olaylar[i - 1].olay_id, self.olaylar[i].olay_id],
                        tespit_zamani=datetime.now(timezone.utc).isoformat()
                    ))
                    # Zaman sırası hatası fırlatılır
                    raise TimelineOrderError(
                        f"Kronolojik zaman hatası: Olay {self.olaylar[i].olay_id} zaman damgası önceki olaydan küçük! ({diff*1000:.2f} ms)"
                    )
        # Olaylar kesin kronolojik epoch sırasına göre sıralanır
        self.olaylar.sort(key=lambda ev: ev.zaman_damgasi_epoch)
        # Her olayın bir öncekine göre geçen delta süresi hesaplanır
        self.olaylar[0].delta_ms = 0.0
        # Geri kalan olaylar için delta hesaplanır
        for i in range(1, len(self.olaylar)):
            # Milisaniye cinsinden fark hesaplanır
            delta = (self.olaylar[i].zaman_damgasi_epoch - self.olaylar[i - 1].zaman_damgasi_epoch) * 1000.0
            # Değer olaya atanır
            self.olaylar[i].delta_ms = max(0.0, delta)

    # İki uç nokta arasındaki standart çift yönlü akış kimliğini oluşturan yardımcı metot
    @staticmethod
    def build_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        """İki yönlü trafiği tek bir oturum kimliğinde eşleştirmek için sıralı soket çifti üretir."""
        # İlk uç nokta tanımlanır
        endpoint_a = (src_ip, src_port)
        # İkinci uç nokta tanımlanır
        endpoint_b = (dst_ip, dst_port)
        # Uç noktalar leksikografik sıralanarak simetrik kimlik oluşturulur
        if endpoint_a <= endpoint_b:
            # A önde olacak şekilde birleştirilir
            return f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
        else:
            # B önde olacak şekilde birleştirilir
            return f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}"

    # Protokol akışlarını yeniden oluşturan metot
    def reconstruct_flows(self) -> Dict[str, FlowSession]:
        """Olayları 5-demet bazında gruplar, TCP/TLS/HTTP durumlarını izler ve RTT hesaplar."""
        # Akışlar sözlüğü temizlenir
        self.akislar = {}
        # Olaylar üzerinde kronolojik olarak ilerlenir
        for ev in self.olaylar:
            # DNS gibi bağlantısız olaylar için tekil akış kimliği
            flow_key = self.build_flow_id(ev.kaynak_ip, ev.kaynak_port, ev.hedef_ip, ev.hedef_port)
            # Akış henüz sözlükte yoksa yeni oturum başlatılır
            if flow_key not in self.akislar:
                # Yeni akış oturumu örneği oluşturulur
                self.akislar[flow_key] = FlowSession(
                    akis_id=flow_key,
                    protokol=ev.protokol,
                    istemci_soket=(ev.kaynak_ip, ev.kaynak_port),
                    sunucu_soket=(ev.hedef_ip, ev.hedef_port),
                    baslangic_zamani=ev.zaman_damgasi_epoch,
                    bitis_zamani=ev.zaman_damgasi_epoch,
                    paket_sayisi=0,
                    toplam_bayt=0,
                    tcp_durumu="CLOSED"
                )
            # Mevcut akış referansı alınır
            flow = self.akislar[flow_key]
            # Paket sayısı artırılır
            flow.paket_sayisi += 1
            # Bayt hacmi toplanır
            flow.toplam_bayt += ev.paket_boyutu
            # Bitiş zamanı güncellenir
            flow.bitis_zamani = ev.zaman_damgasi_epoch

            # TCP Protokolü sonlu durum makinesi ve doğrulama mantığı
            if ev.protokol == "TCP":
                # SYN paketi alındığında durum geçişi
                if ev.islem_tipi == "TCP_SYN" or "SYN" in ev.bayraklar and "ACK" not in ev.bayraklar:
                    # Durum SYN_SENT yapılır
                    flow.tcp_durumu = "SYN_SENT"
                    # SYN gidiş zamanı geçici olarak akış nesnesine saklanır
                    flow._syn_time = ev.zaman_damgasi_epoch  # type: ignore
                # SYN-ACK paketi alındığında durum geçişi
                elif ev.islem_tipi == "TCP_SYN_ACK" or ("SYN" in ev.bayraklar and "ACK" in ev.bayraklar):
                    # Durum SYN_RCVD yapılır
                    flow.tcp_durumu = "SYN_RCVD"
                    # SYN-ACK varış zamanı kaydedilir
                    flow._syn_ack_time = ev.zaman_damgasi_epoch  # type: ignore
                # ACK paketi ile el sıkışma tamamlama kontrolü
                elif ev.islem_tipi == "TCP_ACK" and flow.tcp_durumu == "SYN_RCVD":
                    # Durum ESTABLISHED yapılır
                    flow.tcp_durumu = "ESTABLISHED"
                    # El sıkışma RTT hesaplaması yapılır (SYN ile ACK arasındaki süre)
                    if hasattr(flow, "_syn_time"):
                        # Milisaniye cinsinden TCP el sıkışma RTT değeri atanır
                        flow.rtt_ms = round((ev.zaman_damgasi_epoch - flow._syn_time) * 1000.0, 3)  # type: ignore
                # FIN veya FIN-ACK paketi alındığında
                elif "FIN" in ev.bayraklar or ev.islem_tipi == "TCP_FIN_ACK":
                    # Akış henüz el sıkışmadıysa veya kapalıysa kural dışı geçiş uyarısı
                    if flow.tcp_durumu in ("CLOSED", "SYN_SENT") and flow.paket_sayisi <= 2:
                        # Anomali kaydedilir
                        self.anomaliler.append(TimelineAnomaly(
                            anomali_tipi="GECERSIZ_DURUM_GECISI",
                            onem_derecesi="YUKSEK",
                            aciklama=f"Bağlantı kurulmadan beklenmeyen FIN paketi alındı: {ev.olay_id}",
                            ilgili_olaylar=[ev.olay_id],
                            tespit_zamani=datetime.now(timezone.utc).isoformat()
                        ))
                        # Kural dışı durum geçişi hatası fırlatılır
                        raise IllegalStateTransitionError(f"Geçersiz TCP durum geçişi: {flow.tcp_durumu} üzerinde erken FIN.")
                    # Durum sonlandırmaya evrilir
                    flow.tcp_durumu = "FIN_WAIT"
                # Tamamlanmış FIN sonrası nihai ACK
                elif ev.islem_tipi == "TCP_ACK" and flow.tcp_durumu == "FIN_WAIT":
                    # Akış tamamen kapandı olarak işaretlenir
                    flow.tcp_durumu = "CLOSED"

            # TLS Protokolü Durumu
            elif ev.protokol == "TLS":
                # Sunucu el sıkışma tamamlama bayrağı
                if ev.detaylar.get("el_sikisma_tamamlandi"):
                    # TLS güvenli tünel kuruldu olarak işaretlenir
                    flow.tls_el_sikisma_tamamlandi = True

            # HTTP/2 Protokolü Akım (Stream) Takibi
            elif ev.protokol == "HTTP2":
                # Detaylardaki akım numarası alınır
                akim_id = ev.detaylar.get("akim_id")
                # Geçerli bir akım varsa kümesine eklenir
                if akim_id is not None:
                    # Kümede saklanır
                    flow.http2_akimlar.add(int(akim_id))
                # El sıkışma olmadan erken veri denetimi (TCP ESTABLISHED olmadan gelen HTTP2 verisi)
                if flow.tcp_durumu != "ESTABLISHED" and flow.tcp_durumu != "CLOSED":
                    # Anomali kaydedilir
                    self.anomaliler.append(TimelineAnomaly(
                        anomali_tipi="ERKEN_VERI_ENJEKSIYONU",
                        onem_derecesi="KRITIK",
                        aciklama=f"TCP el sıkışması tamamlanmadan HTTP/2 veri çerçevesi enjekte edildi: {ev.olay_id}",
                        ilgili_olaylar=[ev.olay_id],
                        tespit_zamani=datetime.now(timezone.utc).isoformat()
                    ))
                    # El sıkışma ihlali istisnası fırlatılır
                    raise HandshakeViolationError("TCP el sıkışması tamamlanmadan uygulama katmanı verisi alındı!")

        # Oluşturulan akışlar döndürülür
        return self.akislar

    # Zamansal güvenlik anomalilerini tespit eden motor metodu
    def detect_anomalies(self) -> List[TimelineAnomaly]:
        """Zaman çizelgesi üzerinde saldırı kalıplarını (Slowloris, Port Scan, Hijack, vb.) inceler."""
        # 1. Hızlı Port Taraması (SYN Burst) Tespiti
        # Kaynak IP bazında gönderilen SYN paketlerinin zamanları gruplanır
        syn_events_by_src: Dict[str, List[NetworkEvent]] = {}
        # Olaylar taranır
        for ev in self.olaylar:
            # TCP SYN paketi kontrolü
            if ev.protokol == "TCP" and (ev.islem_tipi == "TCP_SYN" or "SYN" in ev.bayraklar and "ACK" not in ev.bayraklar):
                # Kaynak IP listesine eklenir
                syn_events_by_src.setdefault(ev.kaynak_ip, []).append(ev)

        # Her bir kaynak IP için zaman penceresi analiz edilir
        for src_ip, syn_list in syn_events_by_src.items():
            # 5 veya daha fazla SYN paketi varsa
            if len(syn_list) >= 5:
                # İlk ve son SYN arasındaki toplam süre hesaplanır
                duration_ms = (syn_list[-1].zaman_damgasi_epoch - syn_list[0].zaman_damgasi_epoch) * 1000.0
                # Farklı hedef portların kümesi alınır
                target_ports = {e.hedef_port for e in syn_list}
                # 100 ms altında en az 4 farklı porta SYN gönderilmişse port taramasıdır
                if duration_ms < 100.0 and len(target_ports) >= 4:
                    # Anomali nesnesi oluşturulur
                    anomaly = TimelineAnomaly(
                        anomali_tipi="HIZLI_PORT_TARAMA_BURST",
                        onem_derecesi="YUKSEK",
                        aciklama=f"Kaynak {src_ip}, {duration_ms:.2f} ms içinde {len(target_ports)} farklı porta hızlı SYN gönderdi.",
                        ilgili_olaylar=[e.olay_id for e in syn_list],
                        tespit_zamani=datetime.now(timezone.utc).isoformat()
                    )
                    # Listeye eklenir
                    self.anomaliler.append(anomaly)
                    # İlgili istisna fırlatılır
                    raise PortScanAnomalyError(anomaly.aciklama)

        # 2. Slowloris Yavaş Başlık Damlatma Tespiti
        # HTTP akışlarında başlık parçaları arasındaki gecikme incelenir
        for i in range(1, len(self.olaylar)):
            # Önceki ve mevcut olay alınır
            prev_ev = self.olaylar[i - 1]
            curr_ev = self.olaylar[i]
            # İki olay da HTTP ve parça başlık ise
            if "HTTP" in curr_ev.protokol and "PARTIAL_HEADER" in curr_ev.islem_tipi:
                # İki olay arası saniye farkı hesaplanır
                delta_sec = curr_ev.zaman_damgasi_epoch - prev_ev.zaman_damgasi_epoch
                # 15 saniyeden uzun gecikmeyle damlatılıyorsa Slowloris kalıbıdır
                if delta_sec >= 15.0:
                    # Anomali nesnesi oluşturulur
                    anomaly = TimelineAnomaly(
                        anomali_tipi="SLOWLORIS_YAVAS_BASLIK_DAMLATMA",
                        onem_derecesi="YUKSEK",
                        aciklama=f"HTTP başlıkları arasında {delta_sec:.2f} saniyelik olağan dışı bekletme tespit edildi.",
                        ilgili_olaylar=[prev_ev.olay_id, curr_ev.olay_id],
                        tespit_zamani=datetime.now(timezone.utc).isoformat()
                    )
                    # Listeye eklenir
                    self.anomaliler.append(anomaly)
                    # İlgili istisna fırlatılır
                    raise SlowlorisAnomalyError(anomaly.aciklama)

        # 3. TCP Sıra Numarası Sıçraması (Session Hijacking Şüphesi)
        # Aynı akıştaki ardışık TCP paketlerinin sıra numarası sürekliliği kontrol edilir
        last_seq_by_flow: Dict[str, Tuple[int, int]] = {}  # flow_id -> (last_seq, last_payload_len)
        # Olaylar incelenir
        for ev in self.olaylar:
            # TCP paketi ve geçerli sıra numarası varsa
            if ev.protokol == "TCP" and ev.sira_no is not None:
                # Akış kimliği oluşturulur
                flow_id = self.build_flow_id(ev.kaynak_ip, ev.kaynak_port, ev.hedef_ip, ev.hedef_port)
                # Daha önce bu akışta paket görüldüyse
                if flow_id in last_seq_by_flow:
                    # Önceki sıra no ve yük boyutu alınır
                    prev_seq, prev_len = last_seq_by_flow[flow_id]
                    # Sıra numarası farkı hesaplanır
                    seq_diff = abs(ev.sira_no - prev_seq)
                    # 1.000.000'dan büyük açıklanamayan sıra sıçraması oturum çalma belirtisidir
                    if seq_diff > 1000000:
                        # Anomali nesnesi oluşturulur
                        anomaly = TimelineAnomaly(
                            anomali_tipi="TCP_SIRA_NUMARASI_SICRAMASI",
                            onem_derecesi="KRITIK",
                            aciklama=f"TCP akışında beklenmeyen sıra no sıçraması: {prev_seq} -> {ev.sira_no} (Fark: {seq_diff})",
                            ilgili_olaylar=[ev.olay_id],
                            tespit_zamani=datetime.now(timezone.utc).isoformat()
                        )
                        # Listeye eklenir
                        self.anomaliler.append(anomaly)
                        # İlgili istisna fırlatılır
                        raise SequenceAnomalyError(anomaly.aciklama)
                # Güncel sıra numarası ve paket boyutu saklanır
                last_seq_by_flow[flow_id] = (ev.sira_no, ev.paket_boyutu)

        # 4. DNS Tünelleme Patlaması (DNS Tunneling Burst) Tespiti
        # DNS sorguları zaman ve entropi açısından süzülür
        dns_queries = [e for e in self.olaylar if e.protokol == "DNS" and e.islem_tipi == "DNS_QUERY"]
        # En az 3 DNS sorgusu varsa
        if len(dns_queries) >= 3:
            # Yüksek entropili veya uzun sorguların listesi
            high_entropy_queries = []
            # Her sorgu incelenir
            for q in dns_queries:
                # Sorgu adı alınır
                q_name = q.detaylar.get("sorgu_adi", "")
                # Sorgu adının ilk alt etiketinin entropisi ölçülür
                subdomain = q_name.split(".")[0] if "." in q_name else q_name
                # Uzunluk 20 karakterden büyükse ve entropi 3.2 bit üzerindeyse şüphelidir
                if len(subdomain) >= 20 and self.calculate_entropy(subdomain) >= 3.2:
                    # Şüpheli listesine eklenir
                    high_entropy_queries.append(q)
            # 3 veya daha fazla şüpheli tünelleme sorgusu tespit edildiyse
            if len(high_entropy_queries) >= 3:
                # İlk ve son sorgu arasındaki zaman farkı kontrol edilir
                burst_window_ms = (high_entropy_queries[-1].zaman_damgasi_epoch - high_entropy_queries[0].zaman_damgasi_epoch) * 1000.0
                # 500 ms içinde seri yüksek entropili sorgu DNS tünellemedir
                if burst_window_ms <= 500.0:
                    # Anomali nesnesi oluşturulur
                    anomaly = TimelineAnomaly(
                        anomali_tipi="DNS_TUNELLEME_PATLAMASI",
                        onem_derecesi="KRITIK",
                        aciklama=f"{burst_window_ms:.2f} ms içinde {len(high_entropy_queries)} adet yüksek entropili DNS exfiltration sorgusu tespit edildi.",
                        ilgili_olaylar=[q.olay_id for q in high_entropy_queries],
                        tespit_zamani=datetime.now(timezone.utc).isoformat()
                    )
                    # Listeye eklenir
                    self.anomaliler.append(anomaly)
                    # İlgili istisna fırlatılır
                    raise DnsTunnelingAnomalyError(anomaly.aciklama)

        # Tespit edilen anomali listesi döndürülür
        return self.anomaliler

    # Olayları merdiven / zaman çizelgesi formatında metin olarak çizen metot
    def generate_ascii_timeline(self) -> str:
        """Kronolojik olayları milisaniye delta süreleri ve yön oklarıyla görselleştiren ASCII çizelgesi üretir."""
        # Çıktı satırları listesi başlatılır
        lines: List[str] = []
        # Çizelge başlığı eklenir
        lines.append("=" * 80)
        # Başlık metni
        lines.append(" " * 22 + "PROTOKOL ZAMAN CIZELGESI (TIMELINE)")
        # Çizgi eklenir
        lines.append("=" * 80)
        # Sütun başlıkları tanımlanır
        lines.append(f"{'ZAMAN (UTC)':<26} | {'DELTA':<9} | {'PROT':<6} | {'KAYNAK -> HEDEF':<25} | {'EYLEM'}")
        # Ayırıcı çizgi
        lines.append("-" * 80)

        # Tüm olaylar kronolojik sırayla formatlanır
        for ev in self.olaylar:
            # Delta metni biçimlendirilir (+XX.X ms)
            delta_str = f"+{ev.delta_ms:>6.2f}ms" if ev.delta_ms > 0 else "   0.00ms"
            # Yön göstergesi oluşturulur (IP:Port -> IP:Port)
            direction_str = f"{ev.kaynak_ip}:{ev.kaynak_port} -> {ev.hedef_ip}:{ev.hedef_port}"
            # Eylem ve detay açıklaması derlenir
            action_desc = ev.islem_tipi
            # Detaylarda yararlı özetler varsa eklenir
            if "sorgu_adi" in ev.detaylar:
                # DNS sorgu adını ekler
                action_desc += f" ({ev.detaylar['sorgu_adi']})"
            elif "cerceve_tipi" in ev.detaylar:
                # HTTP/2 çerçeve tipi ve akım kimliğini ekler
                action_desc += f" [{ev.detaylar['cerceve_tipi']} Stream:{ev.detaylar.get('akim_id')}]"
            elif ev.sira_no is not None:
                # TCP sıra numarasını ekler
                action_desc += f" [Seq:{ev.sira_no} Ack:{ev.onay_no}]"

            # Satır dizeye eklenir
            lines.append(f"{ev.zaman_damgasi_str:<26} | {delta_str:<9} | {ev.protokol:<6} | {direction_str:<25} | {action_desc}")

        # Kapanış çizgisi
        lines.append("=" * 80)
        # Tüm satırlar yeni satır karakteriyle birleştirilerek döndürülür
        return "\n".join(lines)

    # Özet adli analiz ve metrik raporu üreten metot
    def generate_summary_report(self) -> Dict[str, Any]:
        """Tüm zaman çizelgesi metriklerini, akış özetlerini ve anomali durumunu raporlar."""
        # Toplam olay sayısı
        total_events = len(self.olaylar)
        # Süre hesaplaması (en son olay - ilk olay)
        total_duration_ms = 0.0
        # Olay varsa hesaplanır
        if total_events > 1:
            # Toplam milisaniye süresi hesaplanır
            total_duration_ms = (self.olaylar[-1].zaman_damgasi_epoch - self.olaylar[0].zaman_damgasi_epoch) * 1000.0

        # Ortalama delta süresi hesaplanır
        avg_delta = sum(e.delta_ms for e in self.olaylar[1:]) / max(1, total_events - 1) if total_events > 1 else 0.0

        # Akış özetleri derlenir
        flow_summaries = []
        # Her bir akış için metrikler toplanır
        for flow in self.akislar.values():
            # Akış sözlüğü eklenir
            flow_summaries.append({
                "akis_id": flow.akis_id,
                "protokol": flow.protokol,
                "paket_sayisi": flow.paket_sayisi,
                "toplam_bayt": flow.toplam_bayt,
                "tcp_nihai_durum": flow.tcp_durumu,
                "el_sikisma_rtt_ms": flow.rtt_ms,
                "tls_el_sikisma_tamamlandi": flow.tls_el_sikisma_tamamlandi,
                "http2_akim_sayisi": len(flow.http2_akimlar)
            })

        # Nihai rapor sözlüğü inşa edilir
        return {
            "toplam_olay_sayisi": total_events,
            "toplam_akis_sayisi": len(self.akislar),
            "toplam_sure_ms": round(total_duration_ms, 3),
            "ortalama_delta_ms": round(avg_delta, 3),
            "tespit_edilen_anomali_sayisi": len(self.anomaliler),
            "guvenlik_durumu": "TEMIZ" if len(self.anomaliler) == 0 else "ANOMALI_SAPTANDI",
            "akislar": flow_summaries,
            "anomaliler": [
                {
                    "tip": a.anomali_tipi,
                    "onem": a.onem_derecesi,
                    "aciklama": a.aciklama,
                    "olaylar": a.ilgili_olaylar
                }
                for a in self.anomaliler
            ]
        }
