# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G053: Port, Soket ve Bağlantı Durumu Analizörü.
Bu modül RFC 793/9293 standartlarına uygun TCP/UDP soket uç noktalarının modellenmesi,
IANA port aralıklarının (Well-known, Registered, Ephemeral) sınıflandırılması,
TCP durum makinesi (LISTEN, ESTABLISHED, TIME_WAIT vb.) geçiş simülasyonu,
ve 'Açık Port != Zafiyet' ilkesi doğrultusunda 0.0.0.0 hassas servis ifşası,
Reverse Shell bağlantıları ve SYN Flood / TIME_WAIT yığılması güvenlik denetimlerini yürütür.
"""

import ipaddress  # IPv4 adres geçerlilik ve yerel ağ denetimleri için standart kütüphane
from typing import Any, Dict, List, Optional, Set, Tuple  # Statik tip güvenliği ve açıklamaları için tür tanımları


class SocketAnalyzerError(Exception):  # Temel hata hiyerarşisi oluşturmak üzere özel istisna sınıfı
    """Soket analizörü modülü için genel kök istisna sınıfı."""

    pass  # Temel sınıf gövdesi


class SocketValidationError(SocketAnalyzerError):  # Doğrulama hatalarını ayırmak için türetilmiş istisna sınıfı
    """Geçersiz port numarası, IP adresi, protokol veya durum biçimlerinde fırlatılır."""

    pass  # Doğrulama sınıf gövdesi


class SocketStateTransitionError(SocketAnalyzerError):  # Geçersiz TCP durum geçişi istisnası
    """RFC 793 durum makinesine aykırı bir durum geçişi denendiğinde fırlatılır."""

    pass  # Durum geçiş sınıf gövdesi


class SocketSecurityRiskError(SocketAnalyzerError):  # Yüksek güvenlik riski veya alarm istisnası
    """Kritik ters kabuk (Reverse Shell) veya yetkisiz ifşa tespit edildiğinde fırlatılır."""

    pass  # Güvenlik risk sınıf gövdesi


def validate_ipv4_format(ip_str: str, field_name: str = "IP") -> None:  # IP sözdizimini doğrulayan yardımcı fonksiyon
    """IPv4 adresinin geçerli 4 oktet noktalı biçimde olduğunu denetler."""
    try:  # IP çözümleme deneme bloğu
        ipaddress.IPv4Address(ip_str)  # Standart kütüphane ile IPv4 adresi nesneye dönüştürülür
    except (ipaddress.AddressValueError, ValueError) as err:  # Hatalı IP formatı yakalanır
        raise SocketValidationError(f"Geçersiz IPv4 {field_name} adresi biçimi: '{ip_str}'. Hata: {err}")  # Hata fırlatılır


class PortClassifier:  # Port sınıflandırma ve servis tespiti sınıfı
    """IANA port kategorilerini ve iyi bilinen servisleri sınıflandıran yardımcı bileşen."""

    WELL_KNOWN_MAX: int = 1023  # Sistem ve ayrıcalıklı portların üst sınırı
    REGISTERED_MAX: int = 49151  # Kayıtlı kullanıcı uygulamaları portlarının üst sınırı
    DYNAMIC_MAX: int = 65535  # Dinamik ve geçici (ephemeral) portların üst sınırı

    KNOWN_SERVICES: Dict[int, str] = {  # Yaygın port numaraları ve ilişkili protokoller haritası
        20: "FTP_DATA",  # Dosya Aktarım Protokolü Veri Kanalı
        21: "FTP_CONTROL",  # FTP Kontrol ve Komut Kanalı
        22: "SSH",  # Güvenli Kabuk Protokolü
        23: "TELNET",  # Güvensiz Düz Metin Uzak Uçbirim Protokolü
        25: "SMTP",  # Basit Posta Aktarım Protokolü
        53: "DNS",  # Alan Adı Sistemi
        80: "HTTP",  # Güvensiz Köprü Metin Aktarım Protokolü
        110: "POP3",  # E-posta Alma Protokolü
        123: "NTP",  # Ağ Zaman Protokolü
        143: "IMAP",  # İnternet Mesaj Erişim Protokolü
        443: "HTTPS",  # Güvenli Köprü Metin Aktarım Protokolü (TLS/SSL)
        445: "SMB",  # Sunucu Mesaj Bloğu (Dosya/Yazıcı Paylaşımı)
        1433: "MSSQL",  # Microsoft SQL Sunucu Portu
        1521: "ORACLE",  # Oracle Veritabanı Portu
        3306: "MYSQL",  # MySQL Veritabanı Portu
        3389: "RDP",  # Uzak Masaüstü Protokolü
        4444: "METASPLOIT_DEFAULT",  # Bilinen Varsayılan Metasploit Dinleyici Portu
        5432: "POSTGRESQL",  # PostgreSQL İlişkisel Veritabanı
        6379: "REDIS",  # Redis Bellek İçi Veri Yapısı Deposu
        8080: "HTTP_ALT",  # Alternatif HTTP Web Portu
        27017: "MONGODB",  # MongoDB NoSQL Veritabanı
    }  # Servis sözlüğü sonu

    SENSITIVE_INTERNAL_SERVICES: Set[int] = {  # Dış internete açılmaması gereken iç ağ servis portları
        23,  # Telnet: Şifresiz iletişim
        445,  # SMB: Fidye yazılımları (WannaCry vb.) yayılım vektörü
        1433, 1521, 3306, 5432, 27017,  # Veritabanları
        6379,  # Redis: Yetkisiz kod yürütme riski
    }  # Hassas portlar kümesi sonu

    @classmethod  # Sınıf referansıyla çalışan sınıflandırıcı metot
    def classify_port(cls, port: int) -> Dict[str, Any]:  # Portun aralığını ve servisini belirleyen metot
        """Verilen port numarasını IANA standartlarına göre sınıflandırır."""
        if not isinstance(port, int) or port < 0 or port > cls.DYNAMIC_MAX:  # Port aralık doğrulaması
            raise SocketValidationError(f"Port numarası 0 ile {cls.DYNAMIC_MAX} arasında olmalıdır: {port}")  # Hata bildirimi

        if port <= cls.WELL_KNOWN_MAX:  # 0-1023 aralığı kontrolü
            kategori = "WELL_KNOWN"  # İyi bilinen sistem portu
            aciklama = "Sistem / Ayrıcalıklı Port (Root/Admin yetkisi gerektirir)"  # Kategori açıklaması
        elif port <= cls.REGISTERED_MAX:  # 1024-49151 aralığı kontrolü
            kategori = "REGISTERED"  # IANA kayıtlı uygulama portu
            aciklama = "Kayıtlı Uygulama Portu (Veritabanları, uygulama sunucuları)"  # Kategori açıklaması
        else:  # 49152-65535 aralığı
            kategori = "DYNAMIC_PRIVATE"  # Geçici dinamik port
            aciklama = "Dinamik / Özel / Geçici (Ephemeral) Port (İstemci giden oturumları)"  # Kategori açıklaması

        servis = cls.KNOWN_SERVICES.get(port, "UNKNOWN_SERVICE")  # Tanımlı servis adı aranır
        return {  # Sonuç sözlüğü döndürülür
            "port": port,  # Port numarası
            "kategori": kategori,  # IANA kategorisi
            "servis": servis,  # Servis adı
            "aciklama": aciklama,  # Açıklama metni
            "hassas_ic_servis_mi": port in cls.SENSITIVE_INTERNAL_SERVICES,  # Hassas servis bayrağı
        }  # Sözlük tamamlanır


class SocketEndpoint:  # Ağ soket uç noktası veri modeli sınıfı
    """
    Tek bir TCP veya UDP soket kaydını (5-tuple + PID + Durum) temsil eden sınıf.
    Biçim: (Protokol, Yerel_IP, Yerel_Port, Uzak_IP, Uzak_Port, Durum, PID, Süreç_Adı)
    """

    VALID_PROTOCOLS: Set[str] = {"TCP", "UDP"}  # Desteklenen taşıma katmanı protokolleri
    VALID_TCP_STATES: Set[str] = {  # RFC 793/9293 standart TCP bağlantı durumları
        "LISTEN",  # Sunucu gelen bağlantı isteklerini dinliyor
        "SYN_SENT",  # İstemci SYN gönderdi, yanıt bekliyor
        "SYN_RECEIVED",  # Sunucu SYN aldı, SYN+ACK gönderdi, son ACK bekliyor
        "ESTABLISHED",  # Bağlantı kuruldu, çift yönlü veri akışı aktif
        "FIN_WAIT_1",  # Kapanışı başlatan taraf FIN gönderdi, ACK bekliyor
        "FIN_WAIT_2",  # Kapanışı başlatan taraf ACK aldı, karşı tarafın FIN'ini bekliyor
        "CLOSE_WAIT",  # Pasif taraf FIN aldı, kendi uygulamasının kapatmasını bekliyor
        "CLOSING",  # Her iki taraf aynı anda FIN gönderdi
        "LAST_ACK",  # Pasif taraf da FIN gönderdi, son ACK'yı bekliyor
        "TIME_WAIT",  # 2*MSL süresince gecikmiş paketleri yakalamak için bekliyor
        "CLOSED",  # Bağlantı tamamen kapalı
        "NONE",  # Durumsuz veya UDP soketleri için durum
    }  # TCP durum kümesi sonu

    def __init__(  # Başlatıcı yapıcı metot
        self,  # Parametre / ifade: self,
        protocol: str,  # Taşıma protokolü (TCP/UDP)
        local_ip: str,  # Yerel IP adresi
        local_port: int,  # Yerel port numarası
        remote_ip: str = "0.0.0.0",  # Uzak uç IP adresi
        remote_port: int = 0,  # Uzak uç port numarası
        state: str = "NONE",  # Soket bağlantı durumu
        pid: int = 0,  # Soketi açan sürecin PID numarası
        process_name: str = "SYSTEM",  # Süreç adı
    ) -> None:  # Başlatıcı dönüş tipi
        """Soket alanlarını doğrular ve nesneyi başlatır."""
        self._validate_fields(protocol, local_ip, local_port, remote_ip, remote_port, state, pid)  # Doğrulama çağrısı
        self.protocol: str = protocol.upper()  # Protokol adı büyük harfe çevrilir
        self.local_ip: str = local_ip  # Yerel IP atanır
        self.local_port: int = local_port  # Yerel port atanır
        self.remote_ip: str = remote_ip  # Uzak IP atanır
        self.remote_port: int = remote_port  # Uzak port atanır
        self.state: str = state.upper()  # Durum büyük harfe çevrilir
        self.pid: int = pid  # PID atanır
        self.process_name: str = process_name  # Süreç adı atanır

    def _validate_fields(  # Alan doğrulama özel metodu
        self, proto: str, lip: str, lp: int, rip: str, rp: int, st: str, pid: int  # Parametre / ifade: self, proto: str, lip: str, lp: int, rip: str, rp: int, st: str, pid: int
    ) -> None:  # Doğrulama dönüş tipi
        """Soket özniteliklerinin geçerliliğini denetler."""
        if not isinstance(proto, str) or proto.upper() not in self.VALID_PROTOCOLS:  # Protokol kontrolü
            raise SocketValidationError(f"Desteklenmeyen soket protokolü (Yalnızca TCP veya UDP): {proto}")  # Hata bildirimi
        validate_ipv4_format(lip, "yerel")  # Yerel IP format doğrulaması
        validate_ipv4_format(rip, "uzak")  # Uzak IP format doğrulaması
        if not isinstance(lp, int) or lp < 0 or lp > 65535:  # Yerel port kontrolü
            raise SocketValidationError(f"Port numarası 0 ile 65535 arasında olmalıdır: {lp}")  # Hata bildirimi
        if not isinstance(rp, int) or rp < 0 or rp > 65535:  # Uzak port kontrolü
            raise SocketValidationError(f"Port numarası 0 ile 65535 arasında olmalıdır: {rp}")  # Hata bildirimi
        if not isinstance(st, str) or st.upper() not in self.VALID_TCP_STATES:  # Durum kontrolü
            raise SocketValidationError(f"Geçersiz TCP bağlantı durumu: {st}")  # Hata bildirimi
        if not isinstance(pid, int) or pid < 0:  # PID pozitif kontrolü
            raise SocketValidationError(f"PID (Süreç Kimliği) negatif olamaz: {pid}")  # Hata bildirimi

    def is_listening(self) -> bool:  # Dinleme durumu kontrol metodu
        """Soketin gelen bağlantıları dinleyip dinlemediğini sorgular."""
        return self.state == "LISTEN" or (self.protocol == "UDP" and self.local_port > 0 and self.remote_port == 0)  # Boolean dönüş

    def is_loopback_only(self) -> bool:  # Yalnızca yerel cihaz erişimi kontrol metodu
        """Soketin sadece 127.0.0.1 (Loopback) üzerinde dinleyip dinlemediğini sorgular."""
        return self.local_ip.startswith("127.")  # Loopback öneki denetimi

    def is_all_interfaces(self) -> bool:  # Tüm ağ arayüzlerine bağlı olma kontrol metodu
        """Soketin 0.0.0.0 (tüm ağ arayüzleri) üzerinden dış dünyaya açık olup olmadığını sorgular."""
        return self.local_ip == "0.0.0.0"  # 0.0.0.0 bağlama adresi denetimi

    def to_dict(self) -> Dict[str, Any]:  # Sözlük temsiline dönüştürme metodu
        """Soket bilgilerini raporlanabilir sözlük yapısına dönüştürür."""
        return {  # Rapor sözlüğü döndürülür
            "protokol": self.protocol,  # Protokol
            "yerel_soket": f"{self.local_ip}:{self.local_port}",  # Yerel adres
            "uzak_soket": f"{self.remote_ip}:{self.remote_port}",  # Uzak adres
            "durum": self.state,  # Bağlantı durumu
            "pid": self.pid,  # Süreç kimliği
            "surec_adi": self.process_name,  # Süreç adı
            "dinliyor_mu": self.is_listening(),  # Dinleme bayrağı
            "tum_arayuzlerde_mi": self.is_all_interfaces(),  # Dışa açıklık bayrağı
        }  # Sözlük sonu


class TCPStateTransitionSimulator:  # RFC 793 durum makinesi simülatörü sınıfı
    """RFC 793/9293 TCP Durum Makinesi kurallarını modelleyen ve geçişleri doğrulayan simülatör."""

    VALID_TRANSITIONS: Dict[str, Set[str]] = {  # Her durumdan geçilebilecek yasal hedef durumlar haritası
        "CLOSED": {"LISTEN", "SYN_SENT"},  # Kapalı durumdan dinlemeye veya aktif bağlantı açmaya geçilir
        "LISTEN": {"SYN_RECEIVED", "SYN_SENT", "CLOSED"},  # Dinlemeden SYN alma, eşzamanlı açılış veya kapanış
        "SYN_SENT": {"ESTABLISHED", "SYN_RECEIVED", "CLOSED"},  # SYN_SENT'ten ACK+SYN alma veya reddedilme
        "SYN_RECEIVED": {"ESTABLISHED", "FIN_WAIT_1", "CLOSED"},  # SYN_RECEIVED'ten el sıkışma tamamlama veya RST
        "ESTABLISHED": {"FIN_WAIT_1", "CLOSE_WAIT", "CLOSED"},  # Aktif veya pasif bağlantı sonlandırma başlatma
        "FIN_WAIT_1": {"FIN_WAIT_2", "CLOSING", "TIME_WAIT"},  # Kendi FIN'ine ACK alma veya eşzamanlı FIN alma
        "FIN_WAIT_2": {"TIME_WAIT", "CLOSED"},  # Karşı tarafın FIN'ini alma ve TIME_WAIT'e geçme
        "CLOSE_WAIT": {"LAST_ACK", "CLOSED"},  # Pasif tarafın uygulamayı kapatıp FIN göndermesi
        "CLOSING": {"TIME_WAIT"},  # Eşzamanlı kapanışta son ACK'yı bekleme
        "LAST_ACK": {"CLOSED"},  # Pasif tarafın son ACK'yı alıp kapanması
        "TIME_WAIT": {"CLOSED"},  # 2*MSL süresi dolunca tamamen kapanma
    }  # Geçiş haritası sonu

    def __init__(self, initial_state: str = "CLOSED") -> None:  # Başlatıcı metot
        """Simülatörü belirtilen başlangıç durumu ile başlatır."""
        if initial_state not in self.VALID_TRANSITIONS:  # Geçerli başlangıç kontrolü
            raise SocketValidationError(f"Geçersiz başlangıç TCP durumu: {initial_state}")  # Hata fırlatma
        self.current_state: str = initial_state  # Mevcut durum kaydedilir
        self.history: List[str] = [initial_state]  # Durum geçmişi başlatılır

    def transition_to(self, next_state: str) -> str:  # Durum değiştirme metodu
        """RFC 793 kurallarına göre bir sonraki duruma geçişi yürütür ve doğrular."""
        allowed = self.VALID_TRANSITIONS.get(self.current_state, set())  # İzin verilen hedef durumlar
        if next_state not in allowed:  # Eğer kural dışı geçiş deneniyorsa
            raise SocketStateTransitionError(  # Hata bildirilir
                f"Kural dışı TCP durum geçişi: '{self.current_state}' -> '{next_state}'. İzin verilenler: {sorted(list(allowed))}"  # Açıklama
            )  # İstisna fırlatılır
        self.current_state = next_state  # Yeni durum atanır
        self.history.append(next_state)  # Geçmişe eklenir
        return self.current_state  # Yeni durum döndürülür


class SocketSecurityAuditor:  # Soket güvenlik denetim ve risk analiz motoru
    """
    Soket tablosundaki güvenlik risklerini denetleyen motor.
    - 'Açık Port != Zafiyet' ilkesini uygular.
    - 0.0.0.0 üzerinde dinleyen hassas servisleri (CRITICAL_EXPOSURE) tespit eder.
    - Reverse Shell ve şüpheli dış bağlantıları (4444 vb.) tespit eder.
    - SYN Flood belirtilerini (aşırı SYN_RECEIVED) tespit eder.
    - TIME_WAIT kaynak tükenmesi riskini değerlendirir.
    """

    SUSPICIOUS_OUTBOUND_PORTS: Set[int] = {  # Siber saldırı araçlarında yaygın kullanılan dinleyici portları
        4444,  # Metasploit Default Handler Portu
        1337,  # Klasik Elite Hacker Portu
        31337,  # Back Orifice / Eski Truva Atı Portu
        6667,  # IRC Botnet Komuta Kontrol Portu
        8888,  # Sık kullanılan alternatif dinleme portu
    }  # Şüpheli portlar sonu

    COMMAND_SHELL_PROCESSES: Set[str] = {  # Ters kabuk oluşturabilecek kabuk ve yorumlayıcı süreçleri
        "cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "python.exe", "python"  # Süreç adları
    }  # Kabuk süreçleri kümesi sonu

    def audit_socket_table(self, sockets: List[SocketEndpoint]) -> Dict[str, Any]:  # Ana soket denetim metodu
        """Soket tablosundaki tüm girişleri güvenlik, yapılandırma ve anomali açısından inceler."""
        findings: List[Dict[str, Any]] = []  # Tespit edilen güvenlik bulguları listesi
        listen_count = 0  # Dinleyen soket sayacı
        established_count = 0  # Aktif oturum sayacı
        syn_received_count = 0  # SYN_RECEIVED durumundaki soket sayacı
        time_wait_count = 0  # TIME_WAIT durumundaki soket sayacı

        for s in sockets:  # Tüm soketler döngüye alınır
            if s.state == "LISTEN":  # Dinleyen soket istatistiği
                listen_count += 1  # Sayacı artır
            elif s.state == "ESTABLISHED":  # Aktif bağlantı istatistiği
                established_count += 1  # Sayacı artır
            elif s.state == "SYN_RECEIVED":  # Yarı açık el sıkışma istatistiği
                syn_received_count += 1  # Sayacı artır
            elif s.state == "TIME_WAIT":  # Kapanış bekleyen soket istatistiği
                time_wait_count += 1  # Sayacı artır

            # 1. Kontrol: 0.0.0.0 üzerinde dinleyen hassas iç servis tespiti (CRITICAL_EXPOSURE)
            if s.is_listening() and s.is_all_interfaces():  # Tüm arayüzlerde dinliyorsa
                p_info = PortClassifier.classify_port(s.local_port)  # Portu sınıflandır
                if p_info["hassas_ic_servis_mi"]:  # Eğer hassas servis ise
                    findings.append({  # Kritik bulgu ekle
                        "seviye": "CRITICAL",  # Tehdit seviyesi
                        "kategori": "INSECURE_BIND_EXPOSURE",  # Kategori
                        "soket": f"{s.local_ip}:{s.local_port}",  # Soket
                        "surec": f"{s.process_name} (PID: {s.pid})",  # Süreç
                        "servis": p_info["servis"],  # Servis adı
                        "aciklama": f"Hassas iç servis '{p_info['servis']}' (Port {s.local_port}) '0.0.0.0' adresine bağlanarak tüm ağlara yetkisiz açılmıştır!",  # Detay
                        "onerilen_onlem": f"Servisi yalnızca '127.0.0.1' üzerinde dinleyecek şekilde yapılandırın veya güvenlik duvarıyla dış erişimi engelleyin.",  # Çözüm
                    })  # Bulgu tamamlandı

            # 2. Kontrol: Şüpheli dış bağlantı ve Reverse Shell tespiti
            if s.state == "ESTABLISHED":  # Eğer bağlantı kurulu ise
                proc_lower = s.process_name.lower()  # Süreç adını küçük harfe çevir
                is_shell_proc = proc_lower in self.COMMAND_SHELL_PROCESSES  # Kabuk süreci mi kontrolü
                is_suspicious_port = s.remote_port in self.SUSPICIOUS_OUTBOUND_PORTS  # Şüpheli uzak port mu
                is_non_local_remote = not s.remote_ip.startswith("127.") and s.remote_ip != "0.0.0.0"  # Dış IP mi

                if is_shell_proc and is_suspicious_port and is_non_local_remote:  # Tüm tehdit göstergeleri birleştiğinde
                    findings.append({  # Kritik ters kabuk alarmı ekle
                        "seviye": "CRITICAL",  # Kritik alarm seviyesi
                        "kategori": "REVERSE_SHELL_DETECTED",  # Kategori
                        "soket": f"{s.local_ip}:{s.local_port} -> {s.remote_ip}:{s.remote_port}",  # Soket çifti
                        "surec": f"{s.process_name} (PID: {s.pid})",  # Süreç
                        "aciklama": f"KRİTİK GÜVENLİK İHLALİ: '{s.process_name}' kabuk süreci saldırgan IP'sine ({s.remote_ip}:{s.remote_port}) ters kabuk (Reverse Shell) açmıştır!",  # Açıklama
                        "onerilen_onlem": f"PID {s.pid} sürecini derhal sonlandırın (kill), ağ kablosunu çekin ve uç nokta adli bilişim analizi başlatın.",  # Önlem
                    })  # Alarm tamamlandı

        # 3. Kontrol: SYN Flood Göstergesi
        if syn_received_count >= 5:  # Eğer 5 veya daha fazla yarı açık el sıkışma birikmişse
            findings.append({  # Anomali uyarısı ekle
                "seviye": "HIGH",  # Yüksek seviye
                "kategori": "SYN_FLOOD_SUSPICION",  # Kategori
                "adet": syn_received_count,  # Askıda kalan soket adedi
                "aciklama": f"{syn_received_count} adet soket 'SYN_RECEIVED' durumunda bekliyor. Olası bir SYN Flood saldırısı soket tablosunu tüketiyor olabilir.",  # Açıklama
                "onerilen_onlem": "SYN Cookies (syncookies=1) korumasını aktif edin ve tcp_max_syn_backlog değerini artırın.",  # Önlem
            })  # Anomali tamamlandı

        # 4. Kontrol: TIME_WAIT Yığılması ve Ephemeral Port Tükenmesi
        if time_wait_count >= 15:  # Eğer 15 veya daha fazla TIME_WAIT birikmişse
            findings.append({  # Uyarı ekle
                "seviye": "MEDIUM",  # Orta seviye
                "kategori": "TIME_WAIT_ACCUMULATION",  # Kategori
                "adet": time_wait_count,  # TIME_WAIT soket sayısı
                "aciklama": f"{time_wait_count} soket 'TIME_WAIT' durumunda. Hızlı bağlantı açıp kapatan sistemlerde geçici port tükenmesi (exhaustion) riski.",  # Açıklama
                "onerilen_onlem": "TCP Keep-Alive kullanın, bağlantı havuzlamayı (connection pooling) devreye alın veya tcp_tw_reuse parametresini inceleyin.",  # Önlem
            })  # Uyarı tamamlandı

        crit_cnt = len([f for f in findings if f["seviye"] == "CRITICAL"])  # Kritik bulgu sayısı
        high_cnt = len([f for f in findings if f["seviye"] == "HIGH"])  # Yüksek risk bulgu sayısı
        med_cnt = len([f for f in findings if f["seviye"] == "MEDIUM"])  # Orta risk bulgu sayısı
        risk_score = (crit_cnt * 40) + (high_cnt * 20) + (med_cnt * 10)  # Toplam saldırı yüzeyi risk puanı
        risk_durumu = "CRITICAL_RISK" if risk_score >= 40 else ("HIGH_RISK" if risk_score >= 20 else ("MEDIUM_RISK" if risk_score > 0 else "SECURE"))  # Durum

        return {  # Özet denetim raporu döndürülür
            "toplam_soket_sayisi": len(sockets),  # Toplam soket
            "istatistikler": {  # İstatistik grubu
                "dinleyen_soketler_listen": listen_count,  # Listen adedi
                "aktif_baglantilar_established": established_count,  # Established adedi
                "yari_acik_syn_received": syn_received_count,  # SYN_RECEIVED adedi
                "kapanis_bekleyen_time_wait": time_wait_count,  # TIME_WAIT adedi
            },  # İstatistik sonu
            "saldiri_yuzeyi_puanı": risk_score,  # Toplam risk puanı
            "genel_guvenlik_durumu": risk_durumu,  # Genel güvenlik derecesi
            "toplam_bulgu_sayisi": len(findings),  # Bulgu sayısı
            "bulgular": findings,  # Ayrıntılı bulgu listesi
        }  # Rapor sözlüğü tamamlanır
