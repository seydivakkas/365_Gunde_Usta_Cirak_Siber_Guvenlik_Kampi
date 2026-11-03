# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G084: Mini Proje 11: Test Edilen Güvenlik Log Aracı (Tested Security Audit & Log Tool).

Bu modül, Hafta 12 boyunca edinilen dosya güvenliği (Pathlib), güvenli veri işleme (JSON/CSV),
fail-closed hata yönetimi, log enjeksiyonu önleme, hassas veri maskeleme ve pytest ile
birim testleri konularını endüstriyel standartta birleştiren nihai güvenlik log aracıdır.
"""

from collections import Counter, defaultdict  # Frekans ve grup sayimlari icin collections modulu ice aktarilir
from dataclasses import dataclass, field  # Veri modelleri olusturmak icin dataclass siniflari ice aktarilir
from enum import Enum  # Sabit durumlari tanimlamak icin Enum modulu ice aktarilir
import ipaddress  # IP adreslerinin guvenli ve standart dogrulamasi icin ipaddress modulu ice aktarilir
import json  # Yapilandirilmis JSON loglari ayrastirmak icin json modulu ice aktarilir
from pathlib import Path  # Guvenli dosya sistemi islemleri icin Path modulu ice aktarilir
import re  # Duzenli ifadelerle desen ve hassas veri tespiti icin re modulu ice aktarilir
from typing import Any, Dict, List, Optional, Set, Tuple  # Tip guvenligi icin typing modulu ice aktarilir
import uuid  # Guvenlik olaylari icin benzersiz token uretiminde uuid modulu ice aktarilir


class SecurityAlertLevel(Enum):
    """Guvenlik alarm seviyeleri."""
    LOW = "LOW"  # Dusuk seviye: bilgilendirici anomali
    MEDIUM = "MEDIUM"  # Orta seviye: supheli kullanici davranisi
    HIGH = "HIGH"  # Yuksek seviye: dogrudan saldiri girisimi
    CRITICAL = "CRITICAL"  # Kritik seviye: acil mudahale gerektiren olay (kaba kuvvet, SQLi)


class SecurityLogToolException(Exception):
    """Guvenlik log araci temel istisna sinifi."""
    pass  # Temel govde bos birakilir


class SecurityPathTraversalException(SecurityLogToolException):
    """Log dizini disina cikma girisiminde (CWE-22) firlatilir."""
    pass  # Dizin atlama istisnasi


class SymlinkViolationException(SecurityLogToolException):
    """Log dosyasinin bir sembolik bag (symlink) olmasi durumunda (CWE-59) firlatilir."""
    pass  # Sembolik bag istisnasi


class LogInjectionAttemptException(SecurityLogToolException):
    """Log satirinda CRLF veya sahte log kaydi tespit edildiginde (CWE-117) firlatilir."""
    pass  # Log enjeksiyon istisnasi


class NullByteForbiddenException(SecurityLogToolException):
    """Log akisinda null-byte (0x00) karakteri tespit edildiginde (CWE-158) firlatilir."""
    pass  # Null byte istisnasi


class LogLineLengthLimitException(SecurityLogToolException):
    """Log satiri uzunlugu maksimum siniri astiginda (CWE-400 DoS) firlatilir."""
    pass  # Satir uzunlugu asim istisnasi


class MalformedJsonLogException(SecurityLogToolException):
    """Bozuk JSON formatli log satirlarinda (CWE-20) firlatilir."""
    pass  # Bozuk json log istisnasi


class InvalidIpAddressException(SecurityLogToolException):
    """Gecersiz veya bozuk istemci IP formatinda (CWE-20) firlatilir."""
    pass  # Gecersiz IP istisnasi


class BruteForceDetectedException(SecurityLogToolException):
    """Tekil IP'den esik degeri asan basarisiz giris denemelerinde (CWE-307) firlatilir."""
    pass  # Kaba kuvvet tespit istisnasi


class SqlInjectionDetectedException(SecurityLogToolException):
    """Log istek URL veya parametresinde SQLi tespiti halinde (CWE-89) firlatilir."""
    pass  # SQL enjeksiyon istisnasi


@dataclass
class SecurityAlert:
    """Tespit edilen tekil bir guvenlik alarmi."""
    alert_id: str  # Benzersiz alarm kimligi
    alert_type: str  # Alarm turu (BRUTE_FORCE, SQL_INJECTION vb.)
    alert_level: SecurityAlertLevel  # Tehdit seviyesi
    cwe_id: str  # Ilgili CWE numarasi
    client_ip: str  # Saldiri kaynagi istemci IP adresi
    details: str  # Olayin teknik aciklamasi


@dataclass
class SecurityLogEntry:
    """Temizlenmis ve dogrulanmis yapilandirilmis log kaydi."""
    timestamp: str  # Zaman damgasi
    client_ip: str  # Dogrulanmis istemci IP adresi
    method: str  # HTTP metodu (GET, POST vb.)
    endpoint: str  # Istek yapilan ucnokta yolu
    status_code: int  # HTTP durum kodu
    user_agent: str  # Istemci tarayici / arac basligi
    raw_message: str  # Ham log mesaji
    sanitized_message: str  # Maskelenmis ve temizlenmis log mesaji
    alerts: List[SecurityAlert] = field(default_factory=list)  # Satira ait guvenlik alarmlari


@dataclass
class AuditLogSummary:
    """Log isleme ve guvenlik denetimi sonucu uretilen ozet metrik nesnesi."""
    toplam_islenen: int = 0  # Islenen toplam satir sayisi
    toplam_gecerli: int = 0  # Basariyla ayrastirilan gecerli kayit sayisi
    toplam_reddedilen: int = 0  # Hatali veya engellenen kayit sayisi
    toplam_alarm_sayisi: int = 0  # Uretilen toplam guvenlik alarmi sayisi
    ip_istatistikleri: Dict[str, int] = field(default_factory=dict)  # IP basina istek sayisi
    durum_kodu_dagilimi: Dict[int, int] = field(default_factory=dict)  # HTTP kod dagilimi
    alarmlar: List[SecurityAlert] = field(default_factory=list)  # Tespit edilen tum alarmlar


class SecureLogPathResolver:
    """
    Log dosyasi yollarini guvenli sekilde cozumleyen ve sinirlandiran bilesen.
    Path traversal (CWE-22) ve Symlink Arbitrary File Read (CWE-59) saldirilarini engeller.
    """

    @staticmethod
    def resolve_log_path(file_path: str, allowed_base_dir: Path) -> Path:
        """Dosya yolunu cozerek izin verilen dizin icerisinde kalip kalmadigini dogrular."""
        if not file_path or not isinstance(file_path, str):  # Dosya yolu bos veya metin degilse
            raise SecurityPathTraversalException("Gecersiz dosya yolu parametresi.")  # Hata firlatilir

        if "\x00" in file_path:  # Null-byte enjeksiyonu denetimi (CWE-158)
            raise NullByteForbiddenException("Dosya yolunda zararli null byte (0x00) tespit edildi.")  # Hata

        ham_yol = Path(file_path) if Path(file_path).is_absolute() else (allowed_base_dir / file_path)  # Ham yol
        if ham_yol.is_symlink():  # Sembolik bag kontrolu cozulmeden once yapilir (CWE-59)
            raise SymlinkViolationException(f"Sembolik bag erisimi guvenlik kurali geregi yasaktir: {ham_yol}")

        hedef_yol = ham_yol.resolve()  # Guvenli sekilde mutlak cozumlenir
        guvenli_kok = allowed_base_dir.resolve()  # Guvenli temel dizin mutlak olarak cozulur
        try:  # Sinir kontrolu denenir
            hedef_yol.relative_to(guvenli_kok)  # Hedef yol guvenli koke gore goreceli mi incelenir
        except ValueError:  # Eger kok dizin disina tasiyorsa ValueError uretilir
            raise SecurityPathTraversalException(
                f"Path Traversal Engellendi: '{file_path}' hedefi guvenli '{guvenli_kok}' disindadir."
            )  # Guvenlik istisnasi firlatilir

        if hedef_yol.is_symlink():  # Eger cozulmus hedef de bir sembolik bag ise
            raise SymlinkViolationException(f"Sembolik bag erisimi guvenlik kurali geregi yasaktir: {hedef_yol}")

        return hedef_yol  # Cozulmus ve dogrulanmis guvenli yol dondurulur


class LogContentSanitizer:
    """
    Log iceriklerini arindiran, Log Injection (CWE-117) ve veri sizintisini (CWE-532) onleyen bilesen.
    """

    MAX_LINE_LENGTH: int = 4096  # DoS onleme maks satır uzunlugu (CWE-400)
    ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")  # ANSI regexi
    CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}(\d{4})\b")  # Kredi karti PAN regexi
    AWS_KEY_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")  # AWS API key regexi
    BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_\.]+)")  # JWT / Bearer token regexi
    PASSWORD_PATTERN = re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*['\"]?([^'\"\s]+)['\"]?")  # Parola regexi

    @classmethod
    def sanitize_line(cls, line: str, strict: bool = False) -> str:
        """
        Log satirini inceler, CRLF enjeksiyonunu engeller ve hassas verileri maskeler.
        strict=True durumunda CRLF veya Null-byte varsa aninda istisna firlatir.
        """
        if "\x00" in line:  # Null byte kontrolu
            raise NullByteForbiddenException("Log satirinda null-byte (0x00) enjeksiyonu tespit edildi.")

        if "\r" in line or "\n" in line:  # CRLF kontrolu
            if strict:  # Kati modda dogrudan istisna firlatilir
                raise LogInjectionAttemptException("Log Injection (CRLF) saldiri girisimi tespit edildi.")
            # Normal modda CRLF boslukla degistirilerek satirin bolunmesi engellenir
            line = line.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")

        if len(line) > cls.MAX_LINE_LENGTH:  # Boyut asim kontrolu
            if strict:  # Kati modda istisna firlatilir
                raise LogLineLengthLimitException(f"Log satiri maksimum {cls.MAX_LINE_LENGTH} karakter limitini asti.")
            line = line[:cls.MAX_LINE_LENGTH] + "...[TRUNCATED]"  # Normal modda kirpilir

        # ANSI terminal kodlarini temizle
        line = cls.ANSI_ESCAPE_PATTERN.sub("", line)

        # Hassas veri maskeleme (CWE-532 / CWE-359 onlemleri)
        line = cls.CREDIT_CARD_PATTERN.sub(r"****-****-****-\1", line)  # Kredi karti maskeleme
        line = cls.AWS_KEY_PATTERN.sub(r"AKIA***REDACTED***", line)  # AWS key maskeleme
        line = cls.BEARER_PATTERN.sub(r"Bearer [REDACTED_JWT]", line)  # Bearer token maskeleme
        line = cls.PASSWORD_PATTERN.sub(r"\1=***REDACTED***", line)  # Parola maskeleme

        return line.strip()  # Arindirilmis satir dondurulur


class NetworkValidator:
    """IP adresi dogrulama ve siniflandirma bileseni (CWE-20 onlemi)."""

    @staticmethod
    def validate_ip(ip_str: str) -> str:
        """Girdi olarak verilen IP metnini standartlastirir ve gecerliligini teyit eder."""
        if not ip_str or not isinstance(ip_str, str):  # Girdi bos veya metin degilse
            raise InvalidIpAddressException("IP adresi bos olamaz.")  # Hata firlatilir
        
        ip_temiz = ip_str.strip()  # Bosluklar temizlenir
        try:  # Standart ipaddress moduluyle cozumleme denenir
            obj = ipaddress.ip_address(ip_temiz)  # IPv4 veya IPv6 nesnesine donusturulur
            return str(obj)  # Standart metin temsili dondurulur
        except ValueError:  # Donusturulemezse gecersiz format hatasi firlatilir
            raise InvalidIpAddressException(f"Gecersiz istemci IP adresi formati: '{ip_str}'")  # Hata


class ThreatDetectionEngine:
    """
    Log kayitlari uzerinde kaba kuvvet, SQLi ve supheli tarayici saldirilarini tespit eden analiz motoru.
    """

    SQL_PATTERNS = [
        re.compile(r"(?i)\bUNION\s+SELECT\b"),  # UNION SELECT kalibi
        re.compile(r"(?i)\bOR\s+1\s*=\s*1\b"),  # OR 1=1 mantiksal kalibi
        re.compile(r"--|;--"),  # SQL yorum satiri belirtecleri
        re.compile(r"(?i)\bDROP\s+TABLE\b"),  # DROP TABLE komut kalibi
    ]

    SUSPICIOUS_UA_PATTERNS = [
        re.compile(r"(?i)\bsqlmap\b"),  # sqlmap saldiri araci
        re.compile(r"(?i)\bnikto\b"),  # nikto guvenlik tarayicisi
        re.compile(r"(?i)\bnmap\b"),  # nmap ag tarayicisi
    ]

    def __init__(self, brute_force_threshold: int = 3):
        self.brute_force_threshold = brute_force_threshold  # Kaba kuvvet esik degeri (varsayilan 3)
        self.failed_attempts: Dict[str, int] = defaultdict(int)  # IP basina basarisiz giris sayaci
        self.alert_counter = 0  # Alarm sayaci sifirlanir

    def evaluate_entry(self, ip: str, endpoint: str, status_code: int, ua: str, message: str, strict: bool = False) -> List[SecurityAlert]:
        """Log girdisini analiz eder ve tespit edilen guvenlik alarmlarini listeler."""
        alarmlar: List[SecurityAlert] = []  # Tespit edilen alarmlar listesi

        # 1. SQL Injection Denetimi (CWE-89)
        birlesik_istek = f"{endpoint} {message}"  # Endpoint ve mesaj birlestirilir
        for pattern in self.SQL_PATTERNS:  # Kayitli SQL desenleri taranir
            if pattern.search(birlesik_istek):  # Eger desen bulunursa
                self.alert_counter += 1  # Sayac artirilir
                alarm = SecurityAlert(
                    alert_id=f"ALT-SQLI-{self.alert_counter:04d}",
                    alert_type="SQL_INJECTION_ATTEMPT",
                    alert_level=SecurityAlertLevel.CRITICAL,
                    cwe_id="CWE-89: SQL Injection",
                    client_ip=ip,
                    details=f"Istek icerisinde SQL Injection kaliplari yakalandi: {birlesik_istek[:80]}"
                )  # Alarm nesnesi olusturulur
                alarmlar.append(alarm)  # Listeye eklenir
                if strict:  # Kati modda istisna firlatilir
                    raise SqlInjectionDetectedException(alarm.details)  # Istisna
                break  # Ilk eslesmede donguden cikilarak tekil alarm olusturulur

        # 2. Supheli User-Agent Denetimi
        for ua_pattern in self.SUSPICIOUS_UA_PATTERNS:  # Tarayici kaliplari gezilir
            if ua_pattern.search(ua):  # Eger saldiri araci tespit edilirse
                self.alert_counter += 1  # Sayac artirilir
                alarm = SecurityAlert(
                    alert_id=f"ALT-SCANNER-{self.alert_counter:04d}",
                    alert_type="MALICIOUS_SCANNER_DETECTED",
                    alert_level=SecurityAlertLevel.HIGH,
                    cwe_id="CWE-200: Exposure of Sensitive Information to Unauthorized Actor",
                    client_ip=ip,
                    details=f"Zararli Guvenlik Tarayicisi Tespit Edildi: {ua}"
                )  # Alarm olusturulur
                alarmlar.append(alarm)  # Eklenir

        # 3. Kaba Kuvvet (Brute Force) Yetkilendirme Denetimi (CWE-307)
        if status_code in (401, 403) and ("login" in endpoint.lower() or "auth" in endpoint.lower()):  # Giris basarisizsa
            self.failed_attempts[ip] += 1  # O IP icin basarisiz deneme 1 artirilir
            if self.failed_attempts[ip] >= self.brute_force_threshold:  # Esik deger asildiysa
                self.alert_counter += 1  # Sayac artirilir
                alarm = SecurityAlert(
                    alert_id=f"ALT-BRUTE-{self.alert_counter:04d}",
                    alert_type="AUTHENTICATION_BRUTE_FORCE",
                    alert_level=SecurityAlertLevel.CRITICAL,
                    cwe_id="CWE-307: Excessive Authentication Attempts",
                    client_ip=ip,
                    details=f"IP '{ip}' tarafindan {self.failed_attempts[ip]} basarisiz giris denemesi (Esik: {self.brute_force_threshold})"
                )  # Alarm olusturulur
                alarmlar.append(alarm)  # Eklenir
                if strict:  # Kati modda istisna firlatilir
                    raise BruteForceDetectedException(alarm.details)  # Istisna

        return alarmlar  # Tespit edilen alarmlar dondurulur


class TestedSecurityLogTool:
    """
    Test Edilen Guvenlik Log Araci (Façade Pattern).
    Dosya cozumleme, log temizleme, JSON/metin ayrastirma, tehdit tespiti ve raporlama bilesenlerini yonetir.
    """
    __test__ = False  # pytest tarafindan test sinifi olarak algilanmasi engellenir

    def __init__(self, allowed_base_dir: Optional[Path] = None, brute_force_threshold: int = 3):
        # Varsayilan olarak arac calisma dizinini temel alir
        self.allowed_base_dir = allowed_base_dir or Path(__file__).resolve().parent.parent  # Temel guvenli dizin
        self.threat_engine = ThreatDetectionEngine(brute_force_threshold=brute_force_threshold)  # Tehdit motoru

    def process_log_file(self, file_path: str, strict: bool = False) -> Tuple[List[SecurityLogEntry], AuditLogSummary]:
        """
        Belirtilen log dosyasini guvenle okur, tum satirlari temizler, ayristirir ve denetim ozetini uretir.
        """
        guvenli_dosya_yolu = SecureLogPathResolver.resolve_log_path(file_path, self.allowed_base_dir)  # Yol cozulur
        
        entries: List[SecurityLogEntry] = []  # Basarili kayitlar listesi
        summary = AuditLogSummary()  # Ozet metrik nesnesi baslatilir
        ip_counts = Counter()  # IP sayaclari
        status_counts = Counter()  # Durum kodu sayaclari

        with open(guvenli_dosya_yolu, "r", encoding="utf-8") as f:  # Guvenli dosya acilir
            for satir in f:  # Satir satir okunur
                satir = satir.strip()  # Bas ve son bosluklar atilir
                if not satir:  # Bos satirlar atlanir
                    continue  # Sonraki satira gecilir
                
                summary.toplam_islenen += 1  # Islenen sayisi artirilir

                try:  # Satir isleme denenir
                    entry = self._process_single_line(satir, strict=strict)  # Tekil satir islenir
                    entries.append(entry)  # Basarili listeye eklenir
                    summary.toplam_gecerli += 1  # Gecerli sayaci artirilir
                    
                    ip_counts[entry.client_ip] += 1  # IP sayimi yapilir
                    status_counts[entry.status_code] += 1  # Durum kodu sayimi yapilir

                    if entry.alerts:  # Eger satirdan alarm geldiyse
                        summary.toplam_alarm_sayisi += len(entry.alerts)  # Alarm sayaci artirilir
                        summary.alarmlar.extend(entry.alerts)  # Ozet alarm listesine eklenir

                except Exception as e:  # Hata durumunda
                    summary.toplam_reddedilen += 1  # Reddedilen sayisi artirilir
                    if strict:  # Eger kati moddaysa hata yukari iletilir
                        raise e  # Istisna firlatilir

        summary.ip_istatistikleri = dict(ip_counts)  # Ozet sozluk doldurulur
        summary.durum_kodu_dagilimi = dict(status_counts)  # Durum kodlari atanir

        return entries, summary  # Kayitlar ve ozet dondurulur

    def _process_single_line(self, line: str, strict: bool = False) -> SecurityLogEntry:
        """Tek bir log satirini JSON veya metin olarak ayristirir ve denetler."""
        # 1. Log enjeksiyonu ve hassas veri maskeleme
        temizlenmis_satir = LogContentSanitizer.sanitize_line(line, strict=strict)  # Temizleme

        # 2. JSON log ayrastirma denemesi
        if line.startswith("{"):  # JSON adayi ise
            try:  # JSON ayrastirma denenir
                payload = json.loads(line)  # JSON nesnesine donusturulur
            except Exception as json_err:  # Ayrastirma hatasi olursa
                raise MalformedJsonLogException(f"Gecersiz JSON log sentaksi: {json_err}")  # Hata firlatilir
            
            ts = payload.get("timestamp", "1970-01-01T00:00:00Z")  # Zaman damgasi
            raw_ip = payload.get("client_ip", "")  # IP adresi
            method = payload.get("method", "GET").upper()  # Metot
            endpoint = payload.get("endpoint", "/")  # Endpoint
            status_code = int(payload.get("status_code", 200))  # Durum kodu
            ua = payload.get("user_agent", "unknown")  # User agent
            msg = payload.get("message", "")  # Mesaj

            valid_ip = NetworkValidator.validate_ip(raw_ip)  # IP dogrulanir
            sanitized_msg = LogContentSanitizer.sanitize_line(msg, strict=strict)  # Mesaj temizlenir

            # Tehdit tespiti
            alarmlar = self.threat_engine.evaluate_entry(
                ip=valid_ip, endpoint=endpoint, status_code=status_code, ua=ua, message=msg, strict=strict
            )  # Tehdit analizi

            return SecurityLogEntry(
                timestamp=ts,
                client_ip=valid_ip,
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                user_agent=ua,
                raw_message=msg,
                sanitized_message=sanitized_msg,
                alerts=alarmlar
            )  # Log kayit nesnesi dondurulur

        else:  # Standart metin logu
            valid_ip = "127.0.0.1"  # Varsayilan yerel IP atanir
            alarmlar = []  # Bos alarm listesi
            return SecurityLogEntry(
                timestamp="1970-01-01T00:00:00Z",
                client_ip=valid_ip,
                method="RAW",
                endpoint="/",
                status_code=200,
                user_agent="text_logger",
                raw_message=line,
                sanitized_message=temizlenmis_satir,
                alerts=alarmlar
            )  # Dondurulur
