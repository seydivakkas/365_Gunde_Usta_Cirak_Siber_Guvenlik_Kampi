# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G051: TCP Sıralama, Akış Kontrolü ve Yeniden İletim (Retransmission) Analiz Motoru.
Bu modül TCP bayt akışı (byte-stream) sıra numaralarını, kümülatif onay (cumulative ACK) mekanizmasını,
kayar pencere (sliding window) yönetimini, 3 yinelenen ACK (Triple Duplicate ACK) ile Hızlı Yeniden İletimi
(Fast Retransmit), zaman aşımı (RTO) mantığını ve Blind RST oturum koparma saldırılarını modeller.
"""

# IP adresi biçim ve aralık denetimleri için standart ipaddress kütüphanesi
import ipaddress
# Yapılandırılmış JSON veri alışverişi için json modülü
import json
# Dosya sistemi ve dizin yolları yönetimi için os modülü
import os
# Tip ipuçları ve veri yapıları tanımlamaları için typing modülü
from typing import Dict, List, Any, Optional, Tuple


class TCPSequenceError(ValueError):
    """TCP sıra numarası, onay numarası veya pencere doğrulama hataları için özel istisna sınıfı."""
    # Özel istisna gövdesi standart miras mekanizmasıyla çalışır
    pass


class TCPStreamSegment:
    """TCP akışındaki tek bir veri veya kontrol segmentini temsil eden veri modeli."""

    def __init__(
        self,
        paket_id: str,
        kaynak_ip: str,
        hedef_ip: str,
        kaynak_port: int,
        hedef_port: int,
        seq_no: int,
        ack_no: int = 0,
        flags: Optional[Dict[str, int]] = None,
        window_size: int = 64240,
        payload_len: int = 0,
        zaman_damgasi_ms: float = 0.0,
        aciklama: str = "",
    ) -> None:
        # Kaynak port numarası denetimi (1-65535 aralığı)
        if not isinstance(kaynak_port, int) or kaynak_port <= 0 or kaynak_port > 65535:
            # Geçersiz kaynak portunda hata fırlatır
            raise TCPSequenceError(f"Geçersiz kaynak port numarası (1-65535 olmalıdır): {kaynak_port}")
        # Hedef port numarası denetimi (1-65535 aralığı)
        if not isinstance(hedef_port, int) or hedef_port <= 0 or hedef_port > 65535:
            # Geçersiz hedef portunda hata fırlatır
            raise TCPSequenceError(f"Geçersiz hedef port numarası (1-65535 olmalıdır): {hedef_port}")
        # Sıra numarası (Sequence Number) 32-bit tamsayı denetimi
        if not isinstance(seq_no, int) or seq_no < 0 or seq_no > 0xFFFFFFFF:
            # 32-bit sınır dışı veya negatif sıra numarasında hata verir
            raise TCPSequenceError(f"Sıra numarası (seq_no) 0-4294967295 aralığında olmalıdır: {seq_no}")
        # Onay numarası (Acknowledgment Number) 32-bit tamsayı denetimi
        if not isinstance(ack_no, int) or ack_no < 0 or ack_no > 0xFFFFFFFF:
            # 32-bit sınır dışı veya negatif onay numarasında hata verir
            raise TCPSequenceError(f"Onay numarası (ack_no) 0-4294967295 aralığında olmalıdır: {ack_no}")
        # Veri yükü uzunluğu denetimi (negatif olamaz)
        if not isinstance(payload_len, int) or payload_len < 0:
            # Negatif yük uzunluğunda hata fırlatır
            raise TCPSequenceError(f"Veri yükü uzunluğu (payload_len) negatif olamaz: {payload_len}")
        # Pencere boyutu denetimi (0-65535 aralığı)
        if not isinstance(window_size, int) or window_size < 0 or window_size > 65535:
            # Geçersiz pencere boyutunda hata fırlatır
            raise TCPSequenceError(f"Pencere boyutu 0-65535 aralığında olmalıdır: {window_size}")
        # Zaman damgası denetimi (sayısal olmalıdır)
        if not isinstance(zaman_damgasi_ms, (int, float)) or zaman_damgasi_ms < 0:
            # Negatif veya sayısal olmayan zaman damgasında hata fırlatır
            raise TCPSequenceError(f"Zaman damgası negatif olmayan sayısal bir değer olmalıdır: {zaman_damgasi_ms}")

        # Kaynak IP adresini doğrular
        try:
            # IPv4 adresi nesnesi oluşturur
            self.kaynak_ip: str = str(ipaddress.IPv4Address(kaynak_ip))
        # Hata durumunu yakalar
        except Exception as err:
            # Açıklayıcı IP hatası döner
            raise TCPSequenceError(f"Geçersiz kaynak IP adresi: {kaynak_ip} - Hata: {str(err)}")

        # Hedef IP adresini doğrular
        try:
            # IPv4 adresi nesnesi oluşturur
            self.hedef_ip: str = str(ipaddress.IPv4Address(hedef_ip))
        # Hata durumunu yakalar
        except Exception as err:
            # Açıklayıcı hedef IP hatası döner
            raise TCPSequenceError(f"Geçersiz hedef IP adresi: {hedef_ip} - Hata: {str(err)}")

        # Paket tanıtıcısını saklar
        self.paket_id: str = paket_id
        # Kaynak portunu saklar
        self.kaynak_port: int = kaynak_port
        # Hedef portunu saklar
        self.hedef_port: int = hedef_port
        # Sıra numarasını saklar
        self.seq_no: int = seq_no
        # Onay numarasını saklar
        self.ack_no: int = ack_no
        # Bayrak sözlüğünü saklar (varsayılan boş sözlük)
        self.flags: Dict[str, int] = flags if flags is not None else {}
        # Pencere boyutunu saklar
        self.window_size: int = window_size
        # Yük uzunluğunu saklar
        self.payload_len: int = payload_len
        # Zaman damgasını saklar
        self.zaman_damgasi_ms: float = float(zaman_damgasi_ms)
        # Didaktik açıklamayı saklar
        self.aciklama: str = aciklama

        # Bu segmentin tükettiği sonraki beklenen sıra numarasını hesaplar
        # Normal veri baytları sıra numarasını bayt sayısı kadar ilerletir
        if self.payload_len > 0:
            # Seq + Payload uzunluğu bir sonraki baytın sıra numarasıdır
            self.next_seq: int = (self.seq_no + self.payload_len) & 0xFFFFFFFF
        # SYN veya FIN bayrakları mantıksal olarak 1 bayt sıra tüketir
        elif self.flags.get("SYN", 0) or self.flags.get("FIN", 0):
            # 1 artırır
            self.next_seq = (self.seq_no + 1) & 0xFFFFFFFF
        # Salt ACK paketleri sıra numarası tüketmez
        else:
            # Sıra numarası değişmez
            self.next_seq = self.seq_no


class TCPFlowTracker:
    """İki uç arasındaki çift yönlü TCP akışını, kayar pencereyi ve yeniden iletimleri takip eden motor."""

    def __init__(self, akis_id: str, client_ip: str, client_port: int, server_ip: str, server_port: int) -> None:
        # Akış kimliği (örn. 192.168.30.15:54321 <-> 172.16.20.10:80)
        self.akis_id: str = akis_id
        # İstemci IP adresi
        self.client_ip: str = client_ip
        # İstemci portu
        self.client_port: int = client_port
        # Sunucu IP adresi
        self.server_ip: str = server_ip
        # Sunucu portu
        self.server_port: int = server_port

        # Sunucunun istemciden beklediği kesintisiz sıra numarası (Kümülatif ACK tabanı)
        self.server_expected_seq: Optional[int] = None
        # İstemcinin sunucudan beklediği kesintisiz sıra numarası
        self.client_expected_seq: Optional[int] = None

        # Alınan son onay numarası (ACK)
        self.last_ack_no: Optional[int] = None
        # Peş peşe gelen yinelenen onay (Duplicate ACK) sayacı
        self.duplicate_ack_count: int = 0
        # İstemciden görülen en yüksek sıra numarası (Yeniden iletim tespiti için)
        self.highest_seq_from_client: int = 0

        # Alınan segmentlerin tam geçmişi
        self.segment_history: List[TCPStreamSegment] = []
        # Yeniden iletilen (Retransmission) paketlerin listesi
        self.retransmissions: List[Dict[str, Any]] = []
        # Sıra dışı (Out-of-Order) gelen paketlerin listesi
        self.out_of_order_packets: List[Dict[str, Any]] = []
        # Hızlı Yeniden İletim (Fast Retransmit) olayları
        self.fast_retransmits: List[Dict[str, Any]] = []
        # Sıfır Pencere (Zero Window) olayları
        self.zero_window_events: List[Dict[str, Any]] = []
        # Güvenlik alarmları ve saldırı tespitleri listesi
        self.security_alerts: List[Dict[str, Any]] = []

    def is_client_to_server(self, segment: TCPStreamSegment) -> bool:
        """Segmentin istemciden sunucuya mı gönderildiğini belirler."""
        # Kaynak IP ve port istemciyle eşleşiyorsa ileri yöndür
        return segment.kaynak_ip == self.client_ip and segment.kaynak_port == self.client_port

    def process_segment(self, segment: TCPStreamSegment) -> Dict[str, Any]:
        """Gelen segmenti analiz eder; sıralama, onay, kayıp ve güvenlik kontrollerini yürütür."""
        # Segmenti geçmiş listesine kaydeder
        self.segment_history.append(segment)
        # Olay özetini tutacak sözlük başlatılır
        olay_bilgisi: Dict[str, Any] = {
            "paket_id": segment.paket_id,
            "tur": "NORMAL",
            "detay": "Standart akış segmenti",
        }

        # İstemciden sunucuya giden veri akışı yönü
        c2s = self.is_client_to_server(segment)

        # 1. GÜVENLİK KONTROLÜ: TCP Blind RST Enjeksiyonu Tespiti
        if segment.flags.get("RST", 0):
            # Eğer bağlantı devam ederken RST gelmişse ve Sequence aktif aralıktaysa
            if self.server_expected_seq is not None:
                # RST sıra numarasının beklenen aralıkta olup olmadığını inceler
                fark = abs(segment.seq_no - self.server_expected_seq)
                # Eğer fark makul bir pencere içindeyse oturum koparma saldırısı şüphesidir
                if fark <= 65535:
                    # Kritik güvenlik alarmı kaydeder
                    alert = {
                        "paket_id": segment.paket_id,
                        "kategori": "TCP_BLIND_RST_INJECTION_SALDIRISI",
                        "seviye": "KRITIK",
                        "kaynak": f"{segment.kaynak_ip}:{segment.kaynak_port}",
                        "mesaj": f"Pencere içi geçerli sıra numarasıyla ({segment.seq_no}) oturum koparma (RST) saldırısı tespit edildi!",
                    }
                    # Listeye ekler
                    self.security_alerts.append(alert)
                    # Olay türünü günceller
                    olay_bilgisi["tur"] = "GUVENLIK_ALARM_RST"
                    # Detayı günceller
                    olay_bilgisi["detay"] = alert["mesaj"]
                    # Segment analizini tamamlar
                    return olay_bilgisi

        # 2. AKIŞ KONTROLÜ: Sıfır Pencere (Zero Window) Tespiti
        if segment.window_size == 0 and not segment.flags.get("RST", 0):
            # Sıfır pencere olayı kaydeder
            zw_event = {
                "paket_id": segment.paket_id,
                "kaynak": f"{segment.kaynak_ip}:{segment.kaynak_port}",
                "zaman_ms": segment.zaman_damgasi_ms,
                "mesaj": "Alıcı tamponu tamamen doldu (Window=0), gönderici veri akışını durdurmalıdır.",
            }
            # Listeye ekler
            self.zero_window_events.append(zw_event)
            # Güvenlik riski: Aşırı sıfır pencere gönderimi DoS amacı taşıyabilir
            self.security_alerts.append({
                "paket_id": segment.paket_id,
                "kategori": "TCP_ZERO_WINDOW_DOS_RISKI",
                "seviye": "ORTA",
                "kaynak": f"{segment.kaynak_ip}:{segment.kaynak_port}",
                "mesaj": "Sıfır pencere bildirimi tespit edildi (İstemci/Sunucu kaynak kilitlenmesi veya DoS belirtisi)!",
            })
            # Olay türünü günceller
            olay_bilgisi["tur"] = "ZERO_WINDOW"
            # Detayı günceller
            olay_bilgisi["detay"] = zw_event["mesaj"]

        # 3. VERİ TAŞIYAN SEGMENT ANALİZİ (Payload > 0)
        if segment.payload_len > 0 and c2s:
            # İstemciden daha önce daha yüksek bir sıra numarası görülmüşse bu bir yeniden iletimdir
            is_retransmission = (self.highest_seq_from_client > 0 and segment.seq_no < self.highest_seq_from_client)
            # Gönderilen en yüksek sıra numarasını günceller
            if segment.seq_no > self.highest_seq_from_client:
                # En yüksek sırayı günceller
                self.highest_seq_from_client = segment.seq_no

            # Sunucunun beklediği ilk sıra numarası henüz atanmamışsa
            if self.server_expected_seq is None:
                # İlk sıra numarasını kabul eder
                self.server_expected_seq = segment.next_seq
                # Türü belirler
                olay_bilgisi["tur"] = "ILK_VERI_SEGMENTI"
            # Beklenen sıra numarası mevcutsa sıralama kontrollerini yapar
            else:
                # Yeniden iletim durumu (Daha önce daha yüksek Seq görülmüş veya beklenen sıradan küçük)
                if is_retransmission or segment.seq_no < self.server_expected_seq:
                    # Yeniden iletim kaydını oluşturur
                    retrans_entry = {
                        "paket_id": segment.paket_id,
                        "seq_no": segment.seq_no,
                        "beklenen_seq": self.server_expected_seq,
                        "payload_len": segment.payload_len,
                        "zaman_ms": segment.zaman_damgasi_ms,
                        "neden": "Kayıp veya geciken paketin tekrar iletimi (Fast Retransmit)",
                    }
                    # Listeye ekler
                    self.retransmissions.append(retrans_entry)
                    # Olay türünü günceller
                    olay_bilgisi["tur"] = "YENIDEN_ILETIM"
                    # Detayı günceller
                    olay_bilgisi["detay"] = f"Yeniden iletim tespit edildi (Seq={segment.seq_no} < En Yüksek={self.highest_seq_from_client})"
                    # Eğer bu paket tam beklenen boşluğu kapatıyorsa, beklenen sırayı ilerlet
                    if segment.seq_no == self.server_expected_seq:
                        # Beklenen sırayı günceller
                        self.server_expected_seq = (self.server_expected_seq + segment.payload_len) & 0xFFFFFFFF
                # Tam beklenen sırada gelen veri segmenti
                elif segment.seq_no == self.server_expected_seq:
                    # Beklenen sırayı payload kadar ileri taşır
                    self.server_expected_seq = (self.server_expected_seq + segment.payload_len) & 0xFFFFFFFF
                    # Normal akış olduğunu bildirir
                    olay_bilgisi["tur"] = "SIRALI_VERI"
                    # Detayı günceller
                    olay_bilgisi["detay"] = f"Sıralı veri alındı, yeni beklenen sıra no: {self.server_expected_seq}"
                # Beklenenden büyük sıra numarası -> SIRA DIŞI PAKET (Out-of-Order / Gap)
                elif segment.seq_no > self.server_expected_seq:
                    # Sıra dışı paket kaydını oluşturur
                    ooo_entry = {
                        "paket_id": segment.paket_id,
                        "seq_no": segment.seq_no,
                        "beklenen_seq": self.server_expected_seq,
                        "bosluk_bayt": segment.seq_no - self.server_expected_seq,
                        "zaman_ms": segment.zaman_damgasi_ms,
                    }
                    # Listeye ekler
                    self.out_of_order_packets.append(ooo_entry)
                    # Olay türünü günceller
                    olay_bilgisi["tur"] = "SIRA_DISI_PAKET"
                    # Detayı günceller
                    olay_bilgisi["detay"] = f"Sıra dışı paket alındı! Arada {ooo_entry['bosluk_bayt']} baytlık kayıp boşluk var."

        # 4. ONAY (ACK) SEGMENTİ ANALİZİ (Sunucudan istemciye dönüş)
        if segment.flags.get("ACK", 0) and not c2s:
            # İlk ACK kontrolü
            if self.last_ack_no is None:
                # Son ACK numarasını günceller
                self.last_ack_no = segment.ack_no
                # Sayacı sıfırlar
                self.duplicate_ack_count = 0
            # Aynı ACK numarası tekrar geldiğinde (Duplicate ACK)
            elif segment.ack_no == self.last_ack_no:
                # Yinelenen ACK sayacını bir artırır
                self.duplicate_ack_count += 1
                # Olay türünü belirler
                olay_bilgisi["tur"] = f"DUP_ACK_{self.duplicate_ack_count}"
                # Detayı belirler
                olay_bilgisi["detay"] = f"Yinelenen onay #{self.duplicate_ack_count} (Ack={segment.ack_no})"

                # 3. Yinelenen Onay (Triple Duplicate ACK) -> HIZLI YENİDEN İLETİM TETİKLENMESİ
                if self.duplicate_ack_count == 3:
                    # Fast Retransmit tetikleme kaydı
                    fast_event = {
                        "tetikleyen_paket_id": segment.paket_id,
                        "kayip_seq_no": segment.ack_no,
                        "zaman_ms": segment.zaman_damgasi_ms,
                        "mesaj": "3 Yinelenen ACK alındı! Hızlı Yeniden İletim (Fast Retransmit) devreye girdi.",
                    }
                    # Listeye ekler
                    self.fast_retransmits.append(fast_event)
                    # Olay türünü günceller
                    olay_bilgisi["tur"] = "HIZLI_YENIDEN_ILETIM_TETIKLENDI"
                    # Detayı günceller
                    olay_bilgisi["detay"] = fast_event["mesaj"]

            # İlerleyen yeni bir ACK geldiğinde (Kümülatif Onay)
            elif segment.ack_no > self.last_ack_no:
                # Sayacı sıfırlar (Boşluklar kapandı)
                self.duplicate_ack_count = 0
                # Yeni onay numarasını günceller
                self.last_ack_no = segment.ack_no
                # Olay türünü günceller
                olay_bilgisi["tur"] = "KUMULATIF_ONAY"
                # Detayı günceller
                olay_bilgisi["detay"] = f"Kümülatif onay ilerledi: {self.last_ack_no}"

        # Segment özetini döner
        return olay_bilgisi


class TCPSequenceRetransmitAnalyzer:
    """Tüm TCP akışlarını yöneten, raporlayan ve anomali tespiti yapan ana analiz sınıfı."""

    def __init__(self) -> None:
        # Akış takip nesnelerini tutan sözlük (Anahtar: flow_id)
        self.flows: Dict[str, TCPFlowTracker] = {}
        # Yürütülen tüm olayların listesi
        self.events: List[Dict[str, Any]] = []

    def load_and_analyze_json(self, json_path: str) -> None:
        """JSON dosyasından paket dizisini okur ve akış motoruna iletir."""
        # Dosyanın varlığını teyit eder
        if not os.path.exists(json_path):
            # Dosya yoksa hata fırlatır
            raise TCPSequenceError(f"Paket dosyası bulunamadı: {json_path}")
        # Dosyayı okur
        with open(json_path, "r", encoding="utf-8") as f:
            # JSON verisini listeye ayrıştırır
            packets_data = json.load(f)

        # Liste tip kontrolü yapar
        if not isinstance(packets_data, list):
            # Geçersiz formatta hata verir
            raise TCPSequenceError("Paketler verisi bir JSON dizisi (list) olmalıdır.")

        # Her paketi döngüyle inceler
        for p in packets_data:
            # Segment nesnesini oluşturur
            seg = TCPStreamSegment(
                paket_id=p["paket_id"],
                kaynak_ip=p["kaynak_ip"],
                hedef_ip=p["hedef_ip"],
                kaynak_port=p["kaynak_port"],
                hedef_port=p["hedef_port"],
                seq_no=p["seq_no"],
                ack_no=p.get("ack_no", 0),
                flags=p.get("flags", {}),
                window_size=p.get("window_size", 64240),
                payload_len=p.get("payload_len", 0),
                zaman_damgasi_ms=p.get("zaman_damgasi_ms", 0.0),
                aciklama=p.get("aciklama", ""),
            )

            # Akış kimliğini oluşturur (çift yönlü kanonik anahtar)
            client_ip = p["kaynak_ip"]
            client_port = p["kaynak_port"]
            server_ip = p["hedef_ip"]
            server_port = p["hedef_port"]

            # Eğer port 80 veya 443 kaynaksa, istemci karşı taraftır
            if client_port in [80, 443, 8080] and server_port not in [80, 443, 8080]:
                client_ip, server_ip = server_ip, client_ip
                client_port, server_port = server_port, client_port

            flow_key = f"{client_ip}:{client_port}<->{server_ip}:{server_port}"

            # Akış henüz sözlükte yoksa oluşturur
            if flow_key not in self.flows:
                self.flows[flow_key] = TCPFlowTracker(flow_key, client_ip, client_port, server_ip, server_port)

            # Segmenti ilgili akış nesnesine işletir
            olay = self.flows[flow_key].process_segment(seg)
            # Genel olay listesine ekler
            self.events.append(olay)

    def generate_markdown_report(self) -> str:
        """TCP sıralama, yeniden iletim ve güvenlik denetim sonuçlarını Markdown raporu olarak derler."""
        # Rapor satırlarını toplayacak liste
        lines: List[str] = []
        # Başlık ve proje adı
        lines.append("# 📊 TCP Sıralama, Akış Kontrolü ve Yeniden İletim (Retransmission) Raporu\n")
        # Lisans bildirimi
        lines.append("**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  ")
        # Telif hakkı
        lines.append("*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*\n")
        # Ayırıcı çizgi
        lines.append("---\n")

        # 1. BÖLÜM: Akış İstatistikleri ve Özet
        lines.append("## 1. TCP Akış Takip ve İletim İstatistikleri\n")
        # Tablo başlığı
        lines.append("| Akış Kimliği | Toplam Paket | Sıra Dışı Paket | Yeniden İletim | Hızlı Yeniden İletim | Sıfır Pencere |")
        # Ayırıcı
        lines.append("|---|---|---|---|---|---|")
        
        # Tüm akışları tabloya döker
        for flow_id, fl in self.flows.items():
            # Satır formatı
            satir = (
                f"| `{flow_id}` | {len(fl.segment_history)} | "
                f"**{len(fl.out_of_order_packets)}** | **{len(fl.retransmissions)}** | "
                f"**{len(fl.fast_retransmits)}** | **{len(fl.zero_window_events)}** |"
            )
            # Listeye ekler
            lines.append(satir)
        # Boşluk
        lines.append("")

        # 2. BÖLÜM: Yeniden İletim ve Hızlı Yeniden İletim Analizi
        lines.append("## 2. Yeniden İletim (Retransmission) ve Paket Kayıp Analizi\n")
        # Yeniden iletim listesi
        tum_retrans = []
        # Akışlardan toplar
        for fl in self.flows.values():
            tum_retrans.extend(fl.retransmissions)
            
        # Eğer yeniden iletim yoksa temiz bildirimi
        if not tum_retrans:
            lines.append("✅ Trafikte kayıp veya yeniden iletilen paket tespit edilmedi.\n")
        # Varsa tablo oluşturur
        else:
            lines.append("| No | Paket ID | Yeniden İletilen Seq | Beklenen Seq | Boyut (Bayt) | Zaman (ms) | Açıklama |")
            lines.append("|---|---|---|---|---|---|---|")
            for idx, r in enumerate(tum_retrans, 1):
                satir = f"| {idx} | `{r['paket_id']}` | `{r['seq_no']}` | `{r['beklenen_seq']}` | {r['payload_len']} | {r['zaman_ms']} | {r['neden']} |"
                lines.append(satir)
            lines.append("")

        # 3. BÖLÜM: Güvenlik Anomalileri ve Oturum Koparma Bulguları
        lines.append("## 3. Güvenlik Anomalileri ve Oturum Koparma Tehditleri\n")
        # Tüm güvenlik alarmlarını toplar
        tum_alarmlar = []
        for fl in self.flows.values():
            tum_alarmlar.extend(fl.security_alerts)

        # Alarm yoksa bildirim
        if not tum_alarmlar:
            lines.append("✅ **Denetim Başarılı:** TCP akışında yetkisiz RST enjeksiyonu veya kural dışı anomali saptanmadı.\n")
        # Alarm varsa tablo
        else:
            lines.append("| No | Paket ID | Kategori | Seviye | Kaynak | Tespit Edilen Güvenlik Tehdidi |")
            lines.append("|---|---|---|---|---|---|")
            for idx, a in enumerate(tum_alarmlar, 1):
                ikon = "🚨" if a["seviye"] == "KRITIK" else "⚠️"
                satir = f"| {idx} | `{a['paket_id']}` | `{a['kategori']}` | {ikon} **{a['seviye']}** | `{a['kaynak']}` | {a['mesaj']} |"
                lines.append(satir)
            lines.append("")

        # 4. BÖLÜM: Savunma ve Sıkılaştırma İlkeleri
        lines.append("## 4. TCP Akış Güvenliği ve Savunma İlkeleri\n")
        lines.append("1. **Yinelenen Paketler Tek Başına Saldırı Değildir:** Ağ gecikmesi, alternatif rotalar veya jitter sebebiyle meşru yeniden iletimler oluşabilir. Güvenlik sistemleri her yeniden iletimi DoS olarak nitelememeli, anomalileri eşik değerleri (threshold) ile izlemelidir.")
        lines.append("2. **RFC 5961 ile Blind Reset Savunması:** Güvenlik duvarları ve işletim sistemi TCP yığınları, pencere içi herhangi bir RST paketini doğrudan kabul etmemeli; tam Seq eşleşmesi aramalı veya sorgu doğrulaması (Challenge ACK) talep etmelidir.")
        lines.append("3. **Sıfır Pencere (Zero Window) Sınırlamaları:** İstemcilerin sunucu kaynaklarını kilit altında tutmasını önlemek amacıyla `tcp_retries2` ve probe zaman aşımları agresif şekilde yapılandırılmalıdır.\n")

        # Rapor metnini döner
        return "\n".join(lines)


if __name__ == "__main__":
    # Konsol başlangıç mesajı
    print("================================================================================")
    # Başlık bildirimi
    print("[+] Gün 051: TCP Sıralama, Akış Kontrolü ve Yeniden İletim Analiz Motoru Başlatılıyor...")
    # Çizgi
    print("================================================================================")

    # Örnek JSON dosya yolu
    json_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_retransmit_packets.json")
    # Yolu mutlak yapar
    json_path = os.path.abspath(json_path)

    # Analiz motoru nesnesini oluşturur
    analyzer = TCPSequenceRetransmitAnalyzer()
    # JSON dosyasını yükler ve analiz eder
    analyzer.load_and_analyze_json(json_path)

    # İncelenen akış sayısını basar
    print(f"[*] Toplam İncelenen TCP Akışı Sayısı: {len(analyzer.flows)}")
    # Her akışın istatistiğini yazar
    for flow_id, fl in analyzer.flows.items():
        print(f"    -> Akış: {flow_id}")
        print(f"       Toplam Segment: {len(fl.segment_history)} | Sıra Dışı: {len(fl.out_of_order_packets)} | Yeniden İletim: {len(fl.retransmissions)}")
        print(f"       Fast Retransmit Olayı: {len(fl.fast_retransmits)} | Sıfır Pencere: {len(fl.zero_window_events)}")
        print(f"       Güvenlik Alarmları: {len(fl.security_alerts)}")

    # Markdown raporunu üretir
    rapor_md = analyzer.generate_markdown_report()

    # Rapor dosyasının kaydedileceği konumu belirler
    cikti_yolu = os.path.join(os.path.dirname(__file__), "..", "kanit", "gercek", "tcp_siralama_ve_retransmit_raporu.txt")
    # Yolu mutlak yapar
    cikti_yolu = os.path.abspath(cikti_yolu)
    # Dizin oluşturur
    os.makedirs(os.path.dirname(cikti_yolu), exist_ok=True)
    # Raporu dosyaya yazar
    with open(cikti_yolu, "w", encoding="utf-8") as f:
        # Metni yazar
        f.write(rapor_md)

    # Kayıt bildirimini ekrana basar
    print(f"\n[+] TCP Sıralama ve Yeniden İletim Raporu Başarıyla Kaydedildi: {cikti_yolu}")
    print("================================================================================")
