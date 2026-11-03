# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G065: Hafta 10 Gün 65 - Follow TCP Stream ve Yeniden Birleştirme Motoru (TCP Stream Reassembly Engine).
Bu modül, TCP segmentlerini sıralı bayt akışı haline getirir, sıra dışı (out-of-order) paketleri
arabelleğe alıp ardışık hale geldiğinde çözer, örtüşen (overlapping) saldırı girişimlerini denetler
ve Wireshark "Follow TCP Stream" formatında çift yönlü sohbet dökümü üretir.
"""

# Tip denetimi ve veri yapıları için typing modülünden tipler içe aktarılır
from typing import Dict, List, Any, Optional, Tuple, Set
# Veri sınıfları oluşturmak için dataclass ve field dekoratörleri içe aktarılır
from dataclasses import dataclass, field
# Metin ve ikili veri işlemleri için io kütüphanesi içe aktarılır
import io


# Temel TCP yeniden birleştirme istisna sınıfı
class TCPReassemblyError(Exception):
    """TCP yeniden birleştirme motorundaki tüm hataların temel sınıfıdır."""
    # Üst sınıf metodu boş geçilir
    pass


# Sıra boşluğu hatası istisnası
class SequenceGapError(TCPReassemblyError):
    """Akışta giderilemeyen bir sıra numarası boşluğu (eksik segment) olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Örtüşen yük çelişkisi hatası istisnası
class OverlappingPayloadConflictError(TCPReassemblyError):
    """Örtüşen iki segmentte aynı bayt aralığı için farklı veriler tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bozuk segment boyutu hatası istisnası
class CorruptedSegmentError(TCPReassemblyError):
    """Segmentin bildirilen boyutu ile gerçek veri uzunluğu uyuşmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Arabellek taşma hatası istisnası
class ReassemblyBufferOverflowError(TCPReassemblyError):
    """Sıra dışı segment arabelleği maksimum kapasiteyi aştığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Birleşmemiş veri kaybı hatası istisnası
class UnreassembledDataLossError(TCPReassemblyError):
    """Arabellekte birleşmemiş segmentler varken erken FIN veya RST alındığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Eksik el sıkışma hatası istisnası
class MissingHandshakeError(TCPReassemblyError):
    """SYN bayrağı ve başlangıç sıra numarası (ISN) olmadan veri iletildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Oturum uyuşmazlığı hatası istisnası
class StreamSessionMismatchError(TCPReassemblyError):
    """Akış oturumuna ait olmayan yabancı bir IP veya port segmenti enjekte edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Boş segment akışı hatası istisnası
class EmptyStreamError(TCPReassemblyError):
    """İşlenmek üzere boş bir segment listesi verildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz protokol hatası istisnası
class InvalidProtocolError(TCPReassemblyError):
    """TCP yeniden birleştiriciye UDP veya başka protokol paketi verildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Tekil bir TCP segmentini temsil eden veri sınıfı
@dataclass
class TCPSegment:
    """Tekil bir TCP paketini ve taşıdığı bayt yükünü temsil eder."""
    # Segmentin paket numarası
    paket_no: int
    # Unix epoch zaman damgası
    zaman_damgasi: float
    # Kaynak IP adresi
    kaynak_ip: str
    # Kaynak port numarası
    kaynak_port: int
    # Hedef IP adresi
    hedef_ip: str
    # Hedef port numarası
    hedef_port: int
    # TCP sıra numarası (Sequence Number)
    sira_no: int
    # TCP onay numarası (Acknowledgment Number)
    onay_no: int
    # TCP bayrakları listesi (SYN, ACK, PSH, FIN, RST)
    bayraklar: List[str]
    # Segment içindeki metinsel veri yükü
    yuk_metin: str
    # Bayt cinsinden veri yükü boyutu
    yuk_boyutu: int
    # Protokol adı (varsayılan: TCP)
    protokol: str = "TCP"


# Tek yönlü (Client->Server veya Server->Client) TCP akış birleştiricisi
class DirectionalStreamReassembler:
    """Tek bir yöndeki segmentleri sıralayan, arabelleğe alan ve birleştiren bileşen."""

    # Başlatıcı metot
    def __init__(self, direction_name: str, max_buffer_size: int = 5) -> None:
        # Yön adı ("CLIENT_TO_SERVER" veya "SERVER_TO_CLIENT")
        self.direction_name = direction_name
        # Maksimum sıra dışı arabellek kuyruk kapasitesi
        self.max_buffer_size = max_buffer_size
        # Başlangıç sıra numarası (ISN)
        self.isn: Optional[int] = None
        # Bir sonraki beklenen ardışık sıra numarası
        self.expected_seq: Optional[int] = None
        # Yeniden birleştirilmiş toplam metin dizesi
        self.reassembled_text: str = ""
        # Sıra dışı segmentlerin tutulduğu arabellek (sira_no -> TCPSegment)
        self.out_of_order_buffer: Dict[int, TCPSegment] = {}
        # Birleşen parçaların zaman ve içerik geçmişi
        self.chunks: List[Tuple[float, str]] = []
        # Yeniden iletim (retransmission / duplicate) sayısı
        self.retransmission_count: int = 0
        # Sıra dışı (out-of-order) segment sayısı
        self.out_of_order_count: int = 0
        # Örtüşen (overlapping) segment sayısı
        self.overlap_count: int = 0
        # Akışın sonlandırılma bayrağı
        self.is_terminated: bool = False

    # Yeni bir segmenti işleme alan metot
    def add_segment(self, segment: TCPSegment) -> None:
        """Yeni gelen segmenti inceler; sıradaysa ekler, sıra dışıysa arabelleğe alır."""
        # Protokol denetimi yapılır
        if segment.protokol.upper() != "TCP":
            # Geçersiz protokol hatası fırlatılır
            raise InvalidProtocolError(f"TCP dışı protokol segmenti ({segment.protokol}) birleştiriciye verilemez.")

        # Segment boyutu bütünlük denetimi (bildirilen boyut ile metin uzunluğu tutarlı olmalıdır)
        if len(segment.yuk_metin.encode("utf-8")) != segment.yuk_boyutu:
            # Bozuk segment boyutu hatası fırlatılır
            raise CorruptedSegmentError(
                f"Paket {segment.paket_no} bozuk: Bildirilen boyut ({segment.yuk_boyutu}) ile metin bayt uzunluğu ({len(segment.yuk_metin.encode('utf-8'))}) uyuşmuyor!"
            )

        # SYN paketi el sıkışması kontrolü
        if "SYN" in segment.bayraklar:
            # Başlangıç sıra numarası kaydedilir
            self.isn = segment.sira_no
            # Veri için beklenen ilk sıra numarası ISN + 1 olarak ayarlanır
            self.expected_seq = segment.sira_no + 1
            # SYN paketinde veri yükü yoksa çıkılır
            if segment.yuk_boyutu == 0:
                # İşlem tamamlanır
                return

        # ISN henüz belirlenmemişse ve segment el sıkışmasız geldiyse
        if self.expected_seq is None:
            # Başlangıç sıra numarası ilk gelen segmentin sırası olarak kabul edilir
            self.isn = segment.sira_no
            # Beklenen sıra başlangıca eşitlenir
            self.expected_seq = segment.sira_no

        # FIN veya RST sonlandırma denetimi
        if "FIN" in segment.bayraklar or "RST" in segment.bayraklar:
            # Akış sonlandırıldı olarak işaretlenir
            self.is_terminated = True
            # Arabellekte henüz birleşmemiş parça varken sonlandırıldıysa hata fırlatılır
            if self.out_of_order_buffer:
                # Birleşmemiş veri kaybı hatası fırlatılır
                raise UnreassembledDataLossError(
                    f"Arabellekte {len(self.out_of_order_buffer)} adet birleşmemiş parça varken bağlantı FIN/RST ile kesildi!"
                )

        # Veri yükü boş olan salt ACK paketleri sıra numarasını ilerletmez
        if segment.yuk_boyutu == 0:
            # İşlem bitirilir
            return

        # 1. Durum: Segment tam olarak beklenen sıra numarasındadır (In-Order)
        if segment.sira_no == self.expected_seq:
            # Veri ana akışa eklenir
            self._append_payload(segment.zaman_damgasi, segment.yuk_metin)
            # Beklenen sıra numarası veri boyutu kadar ilerletilir
            self.expected_seq += segment.yuk_boyutu
            # Arabellekte bekleyen sıra dışı paketler çözümlenmeye çalışılır
            self._flush_out_of_order_buffer()

        # 2. Durum: Segment daha önce görülen bir sıra numarasındadır (Yeniden iletim veya Örtüşme)
        elif segment.sira_no < self.expected_seq:
            # Segmentin bitiş sıra numarası hesaplanır
            seg_end = segment.sira_no + segment.yuk_boyutu
            # A) Tam kopya (Full Duplicate / Retransmission)
            if seg_end <= self.expected_seq:
                # Yeniden iletim sayacı artırılır
                self.retransmission_count += 1
                # Kopya paket yoksayılır
                return
            # B) Kısmi Örtüşme (Partial Overlap)
            else:
                # Örtüşme sayacı artırılır
                self.overlap_count += 1
                # Daha önce birleştirilmiş kısım ile yeni gelen kısım çakışma denetimine tabi tutulur
                overlap_len = self.expected_seq - segment.sira_no
                # Eski metnin örtüşen son parçası çıkarılır
                old_overlap_text = self.reassembled_text[-overlap_len:]
                # Yeni paketin örtüşen baş kısmı çıkarılır
                new_overlap_text = segment.yuk_metin[:overlap_len]
                # Örtüşen parçalar farklıysa IDS atlatma (Ptacek-Newsham) saldırısıdır!
                if old_overlap_text != new_overlap_text:
                    # Çelişkili örtüşme hatası fırlatılır
                    raise OverlappingPayloadConflictError(
                        f"Kötü niyetli örtüşen yük tespit edildi! Eski: '{old_overlap_text}' != Yeni: '{new_overlap_text}'"
                    )
                # Çakışma yoksa kalan yeni veri ana akışa eklenir
                new_data = segment.yuk_metin[overlap_len:]
                # Veri eklenir
                self._append_payload(segment.zaman_damgasi, new_data)
                # Beklenen sıra güncellenir
                self.expected_seq = seg_end
                # Arabellek kontrol edilir
                self._flush_out_of_order_buffer()

        # 3. Durum: Segment beklenen sıranın ilerisindedir (Sıra Dışı / Out-of-Order)
        else:
            # Arabellek kapasitesi denetlenir
            if len(self.out_of_order_buffer) >= self.max_buffer_size:
                # Arabellek taşma hatası fırlatılır
                raise ReassemblyBufferOverflowError(
                    f"Sıra dışı arabellek kapasitesi ({self.max_buffer_size}) aşıldı! Olası arabellek tüketim saldırısı."
                )
            # Sıra dışı sayacı artırılır
            self.out_of_order_count += 1
            # Segment arabelleğe kaydedilir
            self.out_of_order_buffer[segment.sira_no] = segment

    # Yükü metin havuzuna ve parça listesine ekleyen yardımcı metot
    def _append_payload(self, timestamp: float, text: str) -> None:
        """Metin parçasını ana akışa ekler ve zaman damgasıyla kaydeder."""
        # Ana dizeye eklenir
        self.reassembled_text += text
        # Zaman damgalı parça geçmişine eklenir
        self.chunks.append((timestamp, text))

    # Arabellekte bekleyen sıra dışı segmentleri ardışık olarak işleyen metot
    def _flush_out_of_order_buffer(self) -> None:
        """Beklenen sıra numarası geldikçe arabellekteki parçaları sırayla akışa döker."""
        # Arabellekte beklenen sıra numarası bulunduğu sürece döngü devam eder
        while self.expected_seq in self.out_of_order_buffer:
            # Beklenen segment arabellekten çekilir
            next_seg = self.out_of_order_buffer.pop(self.expected_seq)
            # Verisi ana akışa eklenir
            self._append_payload(next_seg.zaman_damgasi, next_seg.yuk_metin)
            # Beklenen sıra numarası ilerletilir
            self.expected_seq += next_seg.yuk_boyutu

    # Akışın sonlandırılmasını ve eksik sıra boşluklarını denetleyen metot
    def finalize(self) -> None:
        """Akış tamamlandığında arabellekte boşluk veya sahipsiz parça kalıp kalmadığını denetler."""
        # Arabellekte hala bekleyen çözülememiş parça varsa
        if self.out_of_order_buffer:
            # En küçük sıra numarası tespit edilir
            lowest_gap = min(self.out_of_order_buffer.keys())
            # Sıra boşluğu hatası fırlatılır
            raise SequenceGapError(
                f"Giderilemeyen sıra boşluğu: Beklenen {self.expected_seq}, arabellekteki ilk parça {lowest_gap}!"
            )


# Çift yönlü TCP sohbet oturumunu temsil eden veri sınıfı
@dataclass
class TCPStreamSession:
    """İstemci ve sunucu arasındaki iki yönlü TCP akışını ve birleştirilmiş verileri tutar."""
    # Akış numarası (Wireshark tcp.stream indeksi)
    stream_index: int
    # İstemci soket bilgisi (IP, Port)
    client_socket: Tuple[str, int]
    # Sunucu soket bilgisi (IP, Port)
    server_socket: Tuple[str, int]
    # İstemciden sunucuya giden birleştirici
    client_to_server: DirectionalStreamReassembler
    # Sunucudan istemciye gelen birleştirici
    server_to_client: DirectionalStreamReassembler
    # Toplam segment sayısı
    total_segments: int = 0
    # Başlangıç ve bitiş zamanları
    start_time: float = 0.0
    end_time: float = 0.0


# Wireshark Follow TCP Stream ana analiz ve birleştirme motoru
class FollowTCPStreamEngine:
    """Ağ paketlerini inceleyen, TCP akışlarını gruplayan ve Follow Stream formatında döken motor."""

    # Sınıf başlatıcı
    def __init__(self, max_buffer_size: int = 5) -> None:
        # Maksimum arabellek kuyruk boyutu
        self.max_buffer_size = max_buffer_size
        # Akış oturumları sözlüğü (stream_index -> TCPStreamSession)
        self.streams: Dict[int, TCPStreamSession] = {}

    # Ham sözlükten segmentleri yükleyip akışları birleştiren ana metot
    def load_stream_from_dict(self, trace_dict: Dict[str, Any], strict_handshake: bool = True) -> TCPStreamSession:
        """JSON formatındaki segment dizisini okur, oturum doğrulaması yapar ve akışı birleştirir."""
        # Segment listesinin varlığı denetlenir
        if "segmentler" not in trace_dict or not trace_dict["segmentler"]:
            # Boş akış hatası fırlatılır
            raise EmptyStreamError("Girdi verisinde işlenecek segment bulunamadı.")

        # Akış meta bilgisi alınır
        info = trace_dict.get("akis_bilgisi", {})
        # Akış indeksi belirlenir
        stream_idx = int(info.get("akis_indeksi", 0))
        # İstemci ve sunucu soketleri belirlenir
        client_sock = (str(info.get("istemci_ip", "")), int(info.get("istemci_port", 0)))
        server_sock = (str(info.get("sunucu_ip", "")), int(info.get("sunucu_port", 0)))

        # İlk segmentten soket bilgisi tamamlama (meta bilgi boşsa)
        first_seg = trace_dict["segmentler"][0]
        # İstemci IP boşsa ilk paketten alınır
        if not client_sock[0]:
            # Kaynak IP ve port istemci kabul edilir
            client_sock = (str(first_seg.get("kaynak_ip", "192.168.1.1")), int(first_seg.get("kaynak_port", 50000)))
            # Hedef IP ve port sunucu kabul edilir
            server_sock = (str(first_seg.get("hedef_ip", "10.0.0.1")), int(first_seg.get("hedef_port", 80)))

        # İki yön için bağımsız birleştiriciler oluşturulur
        c2s = DirectionalStreamReassembler("CLIENT_TO_SERVER", max_buffer_size=self.max_buffer_size)
        s2c = DirectionalStreamReassembler("SERVER_TO_CLIENT", max_buffer_size=self.max_buffer_size)

        # Yeni akış oturumu nesnesi başlatılır
        session = TCPStreamSession(
            stream_index=stream_idx,
            client_socket=client_sock,
            server_socket=server_sock,
            client_to_server=c2s,
            server_to_client=s2c,
            total_segments=len(trace_dict["segmentler"]),
            start_time=float(first_seg.get("zaman_damgasi", 0.0)),
            end_time=float(first_seg.get("zaman_damgasi", 0.0))
        )

        # El sıkışma varlığı kontrolü (strict modda)
        if strict_handshake:
            # Tüm paketlerde SYN bayrağı aranır
            has_syn = any("SYN" in s.get("bayraklar", []) for s in trace_dict["segmentler"])
            # SYN bulunamazsa el sıkışma eksik hatası verilir
            if not has_syn:
                # MissingHandshakeError fırlatılır
                raise MissingHandshakeError("Akışta TCP 3'lü el sıkışması (SYN paketi) bulunamadı!")

        # Tüm segmentler sırayla işlenir
        for raw_seg in trace_dict["segmentler"]:
            # Segment nesnesi oluşturulur
            seg_obj = TCPSegment(
                paket_no=int(raw_seg.get("paket_no", 0)),
                zaman_damgasi=float(raw_seg.get("zaman_damgasi", 0.0)),
                kaynak_ip=str(raw_seg.get("kaynak_ip", client_sock[0])),
                kaynak_port=int(raw_seg.get("kaynak_port", client_sock[1])),
                hedef_ip=str(raw_seg.get("hedef_ip", server_sock[0])),
                hedef_port=int(raw_seg.get("hedef_port", server_sock[1])),
                sira_no=int(raw_seg.get("sira_no", 0)),
                onay_no=int(raw_seg.get("onay_no", 0)),
                bayraklar=raw_seg.get("bayraklar", []),
                yuk_metin=str(raw_seg.get("yuk_metin", "")),
                yuk_boyutu=int(raw_seg.get("yuk_boyutu", len(raw_seg.get("yuk_metin", "").encode("utf-8")))),
                protokol=str(raw_seg.get("protokol", "TCP"))
            )

            # Oturum 5-demet doğrulaması: Segment bu oturuma mı ait?
            src_sock = (seg_obj.kaynak_ip, seg_obj.kaynak_port)
            dst_sock = (seg_obj.hedef_ip, seg_obj.hedef_port)

            # İstemciden sunucuya yönü kontrolü
            if src_sock == client_sock and dst_sock == server_sock:
                # İstemci birleştiricisine verilir
                c2s.add_segment(seg_obj)
            # Sunucudan istemciye yönü kontrolü
            elif src_sock == server_sock and dst_sock == client_sock:
                # Sunucu birleştiricisine verilir
                s2c.add_segment(seg_obj)
            # Başka bir IP/Port'tan paket enjekte edilmişse oturum uyuşmazlığıdır
            else:
                # StreamSessionMismatchError fırlatılır
                raise StreamSessionMismatchError(
                    f"Paket {seg_obj.paket_no} oturum uyuşmazlığı: ({src_sock} -> {dst_sock}) akışa ait değil!"
                )

            # Oturum bitiş zamanı güncellenir
            session.end_time = max(session.end_time, seg_obj.zaman_damgasi)

        # Her iki yönün de kapanış denetimi yapılır
        c2s.finalize()
        s2c.finalize()

        # Oturum havuza kaydedilir
        self.streams[stream_idx] = session
        # Oturum döndürülür
        return session

    # Wireshark Follow TCP Stream formatında metin çıktısı üreten metot
    def render_follow_stream(self, session: TCPStreamSession) -> str:
        """İstemci ve sunucu parçalarını zaman sırasıyla çift yönlü diyalog olarak basar."""
        # Çıktı satırları listesi
        lines: List[str] = []
        # Başlık çizgisi
        lines.append("=" * 80)
        # Başlık metni
        lines.append(f"WIRESHARK FOLLOW TCP STREAM (Stream Index: {session.stream_index})")
        # Soket bilgisi
        lines.append(f"İstemci: {session.client_socket[0]}:{session.client_socket[1]} <---> Sunucu: {session.server_socket[0]}:{session.server_socket[1]}")
        # Ayırıcı çizgi
        lines.append("=" * 80)

        # İstemci ve sunucu parçaları kronolojik birleştirme için tek havuzda toplanır
        all_chunks: List[Tuple[float, str, str]] = []  # (timestamp, direction, text)
        # İstemci parçaları eklenir
        for ts, txt in session.client_to_server.chunks:
            # Havuza eklenir
            all_chunks.append((ts, "CLIENT", txt))
        # Sunucu parçaları eklenir
        for ts, txt in session.server_to_client.chunks:
            # Havuza eklenir
            all_chunks.append((ts, "SERVER", txt))

        # Zaman damgasına göre sıralanır
        all_chunks.sort(key=lambda c: c[0])

        # Her parça yönüne göre biçimlendirilir
        for ts, direction, text in all_chunks:
            # İstemci yönü (Wireshark Kırmızı Metin)
            if direction == "CLIENT":
                # İstemci etiketi
                lines.append(f"[CLIENT -> SERVER ({len(text)} bayt)]")
                # Metin satırları eklenir
                lines.append(text.strip())
                # Ayırıcı
                lines.append("-" * 40)
            # Sunucu yönü (Wireshark Mavi Metin)
            else:
                # Sunucu etiketi
                lines.append(f"[SERVER -> CLIENT ({len(text)} bayt)]")
                # Metin satırları eklenir
                lines.append(text.strip())
                # Ayırıcı
                lines.append("-" * 40)

        # Kapanış çizgisi
        lines.append("=" * 80)
        # Birleştirilerek döndürülür
        return "\n".join(lines)

    # Akış istatistikleri ve anomali özet raporu üreten metot
    def generate_summary_report(self, session: TCPStreamSession) -> Dict[str, Any]:
        """Birleştirilen akışın toplam bayt hacmini, sıra dışı ve örtüşme istatistiklerini raporlar."""
        # İstemci toplam baytı
        c_bytes = len(session.client_to_server.reassembled_text.encode("utf-8"))
        # Sunucu toplam baytı
        s_bytes = len(session.server_to_client.reassembled_text.encode("utf-8"))
        # Toplam süre (ms)
        duration_ms = max(0.0, (session.end_time - session.start_time) * 1000.0)

        # Rapor sözlüğü inşa edilir
        return {
            "akis_indeksi": session.stream_index,
            "toplam_segment": session.total_segments,
            "istemci_gonderilen_bayt": c_bytes,
            "sunucu_gonderilen_bayt": s_bytes,
            "toplam_akis_bayt": c_bytes + s_bytes,
            "toplam_sure_ms": round(duration_ms, 2),
            "sira_disi_paket_sayisi": (
                session.client_to_server.out_of_order_count + session.server_to_client.out_of_order_count
            ),
            "yeniden_iletim_sayisi": (
                session.client_to_server.retransmission_count + session.server_to_client.retransmission_count
            ),
            "ortusme_sayisi": (
                session.client_to_server.overlap_count + session.server_to_client.overlap_count
            ),
            "akis_durumu": "BASARIYLA_BIRLESTIRILDI"
        }
