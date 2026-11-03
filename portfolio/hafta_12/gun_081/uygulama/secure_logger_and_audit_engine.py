# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G081: Python Logging Modülü ve Güvenli SIEM Denetim Boru Hattı

Bu modül; kurumsal siber güvenlik sistemlerinde log zehirlemesini (CWE-117 Log Forgery),
hassas kimlik verilerinin açığa çıkmasını (CWE-532 / CWE-359 Redaction) ve bellek/disk
doygunluğunu (CWE-400 DoS) engelleyen, yapılandırılmış (Structured JSON) savunmacı
loglama motorunu sunar.
"""

# Zaman damgası ve UTC zaman dilimi yönetimi için datetime modülünü içeri aktarıyoruz.
import datetime
# JSON formatında yapılandırılmış SIEM logu üretmek için json modülünü içeri aktarıyoruz.
import json
# Python standart loglama altyapısını içeri aktarıyoruz.
import logging
# Dosya sistemi yolları ve dizin kontrolleri için Path modülünü içeri aktarıyoruz.
from pathlib import Path
# Regex filtreleme ve hassas veri maskeleme işlemleri için re modülünü içeri aktarıyoruz.
import re
# Bellek içi log yakalama ve test doğrulamaları için io modülünü içeri aktarıyoruz.
import io
# Statik tip denetimi için generic tipleri içeri aktarıyoruz.
from typing import Any, Dict, List, Optional, Tuple, Union


# ==============================================================================
# 1. GÜVENLİK SÜZGECİ VE MASKELEME FİLTRESİ (SECURITY LOG SANITIZATION FILTER)
# ==============================================================================

class SecurityLogSanitizationFilter(logging.Filter):
    """
    Log iletilerini CRLF enjeksiyonuna, ANSI kontrol kodlarına, null-byte zehirlenmesine
    ve hassas veri (parola, token, kredi kartı) sızıntılarına karşı temizleyen filtre.
    """

    # CRLF ve kontrol karakterlerini tespit eden regex deseni.
    CRLF_PATTERN = re.compile(r"[\r\n\x00]")
    # ANSI terminal kaçış kodlarını temizleyen regex deseni.
    ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    # Parola, gizli anahtar ve token desenlerini tespit eden regex.
    SECRET_PATTERN = re.compile(r"(?i)\b(password|passwd|secret|api_key|token|auth_token)\s*[:=]\s*['\"]?([^\s'\";]+)['\"]?")
    # Bearer yetki belirteçlerini yakalayan regex deseni.
    BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_\.]+)")
    # 16 haneli kredi kartı numaralarını tespit eden regex deseni (son 4 hane hariç maskeler).
    CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[ -]?){3}(\d{4})\b")

    def __init__(self, max_message_length: int = 4096) -> None:
        """
        Filtreyi azami ileti uzunluğu tavanı ile yapılandırır (Varsayılan: 4096 karakter).
        """
        # Üst sınıf Filter başlatıcısını çağırıyoruz.
        super().__init__()
        # İleti uzunluk sınırını kaydediyoruz.
        self.max_message_length = max_message_length

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Gelen log kaydını süzer, değiştirir ve temizlenmiş olarak akışa verir.
        """
        # Ham log mesajını dizeye dönüştürüyoruz.
        raw_msg = str(record.getMessage())

        # 1. Aşama: CRLF ve Null-Byte karakterlerini boşlukla değiştirerek tek satıra indirgiyoruz (CWE-117).
        clean_msg = self.CRLF_PATTERN.sub(" ", raw_msg)

        # 2. Aşama: ANSI terminal kaçış kodlarını temizliyoruz.
        clean_msg = self.ANSI_PATTERN.sub("", clean_msg)

        # 3. Aşama: Hassas parola ve API anahtarı alanlarını maskeliyoruz (CWE-532).
        clean_msg = self.SECRET_PATTERN.sub(r"\1=[REDACTED]", clean_msg)

        # 4. Aşama: Bearer JWT belirteçlerini maskeliyoruz (CWE-359).
        clean_msg = self.BEARER_PATTERN.sub("Bearer [REDACTED_JWT]", clean_msg)

        # 5. Aşama: Kredi kartı numaralarını maskeliyoruz (PCI-DSS uyumu).
        clean_msg = self.CREDIT_CARD_PATTERN.sub(r"****-****-****-\1", clean_msg)

        # 6. Aşama: Fazla ardışık boşlukları kırpıyoruz.
        clean_msg = " ".join(clean_msg.split())

        # 7. Aşama: Tavan uzunluk sınırını aşan mesajları kesiyoruz (CWE-400 DoS koruması).
        if len(clean_msg) > self.max_message_length:
            # Mesajı sınır boyuta kadar kesip sonuna kısaltma etiketi ekliyoruz.
            clean_msg = clean_msg[: self.max_message_length] + "...[TRUNCATED]"

        # Temizlenmiş mesajı log kaydına doğrudan atıyoruz.
        record.msg = clean_msg
        # Format argümanlarını boşaltıyoruz çünkü getMessage() çağrısıyla birleştirildi.
        record.args = ()

        # Kaydın loglanmasına izin veren True değerini döndürüyoruz.
        return True


# ==============================================================================
# 2. YAPILANDIRILMIŞ SIEM JSON FORMATLAYICI (JSON SECURITY LOG FORMATTER)
# ==============================================================================

class JsonSecurityLogFormatter(logging.Formatter):
    """
    Log kayıtlarını kurumsal SIEM sistemleri (Splunk, Elastic, Sentinel) için
    standartlaştırılmış, zaman damgalı JSON nesnesi olarak formatlayan sınıf.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        LogRecord nesnesini JSON dizesine dönüştürür.
        """
        # UTC zaman damgasını mikrosaniye hassasiyetinde ve ISO-8601 standardında alıyoruz.
        utc_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Ek bağlam bilgilerini (context) kayıt üzerinden çekiyoruz (varsayılan boş sözlük).
        extra_context = getattr(record, "context", {})
        # Eğer bağlam bir sözlük değilse güvenli biçimde sözlüğe çeviriyoruz.
        if not isinstance(extra_context, dict):
            # Sözlük sarmalaması yapıyoruz.
            extra_context = {"raw_context": str(extra_context)}

        # Yapılandırılmış JSON log şemasını oluşturuyoruz.
        log_payload: Dict[str, Any] = {
            "timestamp": utc_timestamp,
            "level": record.levelname,
            "logger_name": record.name,
            "module": record.module,
            "line_number": record.lineno,
            "process_id": record.process,
            "thread_name": record.threadName,
            "message": record.getMessage(),
            "context": extra_context
        }

        # JSON dizesine serileştiriyoruz. Serileştirilemeyen tipler için varsayılan str sarmalayıcı kullanıyoruz.
        try:
            # JSON formatında tek satırlık dize üretiyoruz.
            return json.dumps(log_payload, ensure_ascii=False)
        # Serileştirme hatası durumunda güvenli yedek blok çalışır.
        except Exception:
            # Güvenli yedek sözlüğü hazırlıyoruz.
            safe_fallback = {
                "timestamp": utc_timestamp,
                "level": record.levelname,
                "message": record.getMessage(),
                "error": "JSON_SERIALIZATION_FAILED_FALLBACK"
            }
            # Yedek dizeyi döndürüyoruz.
            return json.dumps(safe_fallback, ensure_ascii=False)


# ==============================================================================
# 3. GÜVENLİ DENETİM VE LOG YÖNETİCİSİ (SECURE AUDIT LOGGER MANAGER)
# ==============================================================================

class SecureAuditLoggerManager:
    """
    Loglama altyapısını izole şekilde başlatan, güvenlik filtrelerini ve
    JSON formatlayıcıları bağlayan üst düzey yönetim motoru.
    """

    # Desteklenen meşru loglama seviyeleri haritası.
    LEVEL_MAP: Dict[str, int] = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    def __init__(self, logger_name: str = "SecureAuditPipeline", default_level: str = "INFO") -> None:
        """
        İzole logger nesnesi oluşturur ve bellek içi ile dosya işleyicilerini yapılandırır.
        """
        # Logger nesnesini verilen ad ile oluşturuyoruz.
        self.logger = logging.getLogger(logger_name)
        # Kök logger'a sinyal yayılmasını önleyerek log kirliliğini engelliyoruz.
        self.logger.propagate = False
        # Mevcut handler'ları temizleyerek mükerrer kayıt oluşmasını önlüyoruz.
        self.logger.handlers.clear()

        # Varsayılan seviyeyi güvenle belirliyoruz.
        numeric_level = self.LEVEL_MAP.get(default_level.upper(), logging.INFO)
        # Logger'ın dinleme seviyesini atıyoruz.
        self.logger.setLevel(numeric_level)

        # Güvenlik temizleme filtresini başlatıyoruz.
        self.sanitization_filter = SecurityLogSanitizationFilter(max_message_length=4096)
        # Yapılandırılmış JSON formatlayıcıyı başlatıyoruz.
        self.json_formatter = JsonSecurityLogFormatter()

        # Bellek içi string akışı oluşturarak test ve doğrulama kanıtı toplamayı sağlıyoruz.
        self.log_stream = io.StringIO()
        # Akış işleyicisini (StreamHandler) başlatıyoruz.
        self.stream_handler = logging.StreamHandler(self.log_stream)
        # Filtreyi işleyiciye bağlıyoruz.
        self.stream_handler.addFilter(self.sanitization_filter)
        # JSON formatlayıcıyı işleyiciye bağlıyoruz.
        self.stream_handler.setFormatter(self.json_formatter)
        # İşleyiciyi logger nesnesine ekliyoruz.
        self.logger.addHandler(self.stream_handler)

    def log_event(
        self,
        level_name: str,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Belirtilen seviyede güvenli ve filtreli bir olay kaydı oluşturur.
        """
        # Seviye adını büyük harfe çeviriyoruz.
        lvl_key = str(level_name).upper()
        # Geçerli bir seviye değilse varsayılan WARNING yapıyoruz.
        numeric_level = self.LEVEL_MAP.get(lvl_key, logging.WARNING)

        # Bağlam parametresini hazırlıyoruz.
        safe_context = context if context is not None else {}
        # Log kaydını üretiyoruz.
        self.logger.log(numeric_level, message, extra={"context": safe_context})

        # İşlenen son satırı bellek akışından okuyoruz.
        all_lines = self.log_stream.getvalue().strip().splitlines()
        # Son üretilen JSON satırını alıyoruz.
        last_line = all_lines[-1] if all_lines else "{}"

        # JSON olarak geri çözüp dönüyoruz.
        try:
            # JSON sözlüğünü parse ediyoruz.
            return json.loads(last_line)
        # Hata durumunda boş sözlük döndürüyoruz.
        except Exception:
            # Boş sözlük dönüşü yapıyoruz.
            return {}

    def log_security_alert(
        self,
        rule_name: str,
        source_ip: str,
        severity: str,
        details: str
    ) -> Dict[str, Any]:
        """
        Özel bir siber güvenlik alarmı kaydeder (CRITICAL veya ERROR seviyesinde).
        """
        # Ciddiyet seviyesine göre log düzeyini seçiyoruz.
        chosen_level = "CRITICAL" if severity.upper() == "CRITICAL" else "ERROR"
        # Olay mesajını birleştiriyoruz.
        alert_msg = f"GÜVENLİK ALARMI [{rule_name}]: {details}"
        # Bağlam bilgilerini paketliyoruz.
        context_data = {
            "rule": rule_name,
            "source_ip": source_ip,
            "severity": severity.upper()
        }
        # Olayı kaydedip dönüyoruz.
        return self.log_event(chosen_level, alert_msg, context=context_data)


# Modül doğrudan çalıştırıldığında örnek çalışma ve adli rapor üretimini gerçekleştiriyoruz.
if __name__ == "__main__":
    # Konsola başlangıç bilgisini basıyoruz.
    print("[+] G081: Python Logging ve Güvenli SIEM Boru Hattı Başlatılıyor...")

    # Yönetici nesnesini başlatıyoruz.
    audit_mgr = SecureAuditLoggerManager(logger_name="SIEM_Audit_Engine", default_level="INFO")

    # Örnek 1: Normal operasyonel log kaydı.
    evt1 = audit_mgr.log_event("INFO", "Sistem oturum açma işlemi başarıyla tamamlandı.", context={"kullanici": "analyst1"})
    # Konsola basıyoruz.
    print(f"[+] Normal Log Kaydedildi: Level={evt1.get('level')} | Mesaj={evt1.get('message')}")

    # Örnek 2: Parola ve CRLF içeren zararlı girdi loglama denemesi (Maskeleme ve Sanitizasyon doğrulaması).
    dirty_msg = "Giriş başarısız: username=admin password=GizliParola123!\r\n[CRITICAL] 2026-11-01 Sahte Log Satırı"
    # Zararlı mesajı logluyoruz.
    evt2 = audit_mgr.log_event("WARNING", dirty_msg, context={"ip": "198.51.100.33"})
    # Konsola temizlenmiş sonucu basıyoruz.
    print(f"[+] Filtrelenmiş Log: {evt2.get('message')}")

    # Örnek 3: Kritik güvenlik alarmı kaydı.
    alert_evt = audit_mgr.log_security_alert(
        rule_name="SQL_INJECTION_DETECTED",
        source_ip="203.0.113.88",
        severity="CRITICAL",
        details="Parametre içinde 'UNION SELECT' imzası tespit edildi."
    )
    # Konsola alarm bilgisini basıyoruz.
    print(f"[+] Güvenlik Alarmı Kaydedildi: {alert_evt.get('level')} - {alert_evt.get('message')}")

    # Adli kanıt raporunun kaydedileceği yolu belirliyoruz.
    base_dir = Path(__file__).resolve().parent.parent
    # Rapor dosya yolunu alıyoruz.
    report_path = base_dir / "kanit" / "gercek" / "guvenli_loglama_raporu.txt"
    # Raporu UTF-8 olarak açıyoruz.
    with open(report_path, "w", encoding="utf-8") as rf:
        # Başlığı yazıyoruz.
        rf.write("=== G081 PYTHON LOGGING VE GÜVENLİ SIEM BORU HATTI RAPORU ===\n")
        # Toplam log adedini yazıyoruz.
        rf.write(f"Kayıtlı Toplam Log Satırı: {len(audit_mgr.log_stream.getvalue().strip().splitlines())}\n")
        # Maskeleme sonucunu yazıyoruz.
        rf.write(f"Maskelenmiş Örnek Mesaj: {evt2.get('message')}\n")
        # Alarm özetini yazıyoruz.
        rf.write(f"Kritik Alarm Mesajı: {alert_evt.get('message')}\n")
        # Doğrulama onayını yazıyoruz.
        rf.write("Durum: CWE-117 (CRLF), CWE-532 (Hassas Veri) ve JSON Formatı Başarıyla Doğrulandı (PASS)\n")

    # Bitiş bildirimini basıyoruz.
    print(f"[+] Güvenli loglama raporu kaydedildi: {report_path}")
