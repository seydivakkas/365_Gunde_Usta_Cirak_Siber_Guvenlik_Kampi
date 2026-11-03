# GÜN 081: PYTHON LOGGING MODÜLÜ — SORU VE CEVAPLAR
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## SORU 1 (G081-SC1): LOG FORGERY / LOG ENJEKSİYONU (CWE-117) VE CRLF SALDIRI MEKANİZMASI

### Soru Başlığı ve Tanımı
Log Forgery / Log Injection (CWE-117) nedir? Bir saldırgan kullanıcı adı, URL parametresi veya HTTP başlığı gibi dış girdilere Satır Başı (`\r`) ve Yeni Satır (`\n`) karakterleri enjekte ederek log dosyasına nasıl sahte denetim kayıtları ekler? Python `logging.Filter` mimarisi ile bu zafiyet nasıl kesin olarak engellenir?

### Derinlemesine Teknik Analiz
Log dosyaları varsayılan olarak satır bazlı (line-oriented) düz metin depolarıdır. Bir log işleyici her `record` için yeni bir satır oluşturur:
1. **CRLF Saldırısının Mekaniği:**
   Saldırgan bir form alanına şunu girer:
   `admin\r\n[2026-11-01 12:00:00] [INFO] [AUDIT] Kullanici basariyla oturum acti.`
   Eğer uygulama bu girdiyi sterilize etmeden doğrudan `logger.warning(f"Hatali giris: {username}")` ile loglarsa, log dosyasında iki satır oluşur:
   - Satır 1: `2026-11-01 11:59:59 [WARNING] Hatali giris: admin`
   - Satır 2: `[2026-11-01 12:00:00] [INFO] [AUDIT] Kullanici basariyla oturum acti.`
2. **Adli Bilişim ve Tehdit Avcılığına Etkisi:**
   İkinci satır meşru bir log formatına birebir benzediği için, otomatik SIEM ayrıştırıcıları veya adli analistler bu satırı gerçek bir oturum açma kabul eder. Gerçekte saldırgan başarısız bir kaba kuvvet denerken, sistemde sahte bir başarılı oturum izi bırakarak denetim zincirini tahrif eder.
3. **Filter Tabanlı Çözüm:**
   Python'un `logging.Filter` sınıfından türetilen bir ara katman filtresi, kaydın `record.msg` alanını analiz eder. `re.sub(r"[\r\n\x00]", " ", msg)` ile tüm satır sonu ve null-byte karakterlerini boşluğa dönüştürerek mesajı tek bir fiziksel satıra kilitler.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir siber güvenlik operasyon merkezinde (SOC), analistler ihlal bildirimlerini log dosyalarını `grep` ederek incelemektedir. Bir saldırgan CRLF enjeksiyonu ile loglara sahte "Zararlı yazılım temizlendi ve IP aklandı" satırları ekleyerek analistlerin olayı "çözüldü" sanmasını sağlamış ve arka planda veri hırsızlığını sürdürmüştür.

**Pratik Çözüm (Python Güvenlik Filtresi):**
```python
import logging
import re

class CrlfSanitizingFilter(logging.Filter):
    CRLF_REGEX = re.compile(r"[\r\n\x00]")

    def filter(self, record: logging.LogRecord) -> bool:
        raw_msg = str(record.getMessage())
        # Satır sonlarını boşlukla değiştirerek sahte satır üretimini imkansız kılıyoruz
        clean_msg = self.CRLF_REGEX.sub(" ", raw_msg)
        record.msg = " ".join(clean_msg.split())
        record.args = ()
        return True
```

### Ustanın Çırağa Tavsiyesi
Evladım, log dosyası senin adli mahkemedeki en kıymetli şahidindir. Bir saldırganın o şahide kendi yalanlarını fısıldamasına izin verirsen, suçu asla aydınlatamazsın. Loga yazılan her harfi tek satıra mühürleyeceksin; satır sonu karakterini (`\r\n`) kapıdan içeri sokmayacaksın.

---

## SORU 2 (G081-SC2): GÜNLÜKLERDE HASSAS VERİ SIZINTISI (CWE-532 / CWE-359) VE OTOMATİK MASKELEME

### Soru Başlığı ve Tanımı
Hassas Verilerin Günlüklere Açık Metin Olarak Yazılması (Insertion of Sensitive Information into Log File - CWE-532 / CWE-359) nedir? Parolalar, API anahtarları, Bearer JWT tokenları ve kredi kartı numaralarının (PAN) loglara sızması hangi yasal ve operasyonel felaketlere yol açar? Boru hattına entegre regex maskeleme (Redaction) nasıl uygulanır?

### Derinlemesine Teknik Analiz
1. **İfşanın Kaynakları:**
   Geliştiriciler HTTP istek gövdelerini (`request.body`), veritabanı bağlantı dizilerini (`DATABASE_URL`) veya hata istisnalarını (`repr(exc)`) doğrudan loga yazar. Bu kayıtlar diskte açık metin olarak depolanır.
2. **Yasal ve Güvenlik Sonuçları:**
   - **GDPR / KVKK İhlali:** Kullanıcıların kişisel verilerinin (PII) kontrolsüz loglanması ağır para cezalarına neden olur.
   - **PCI-DSS İhlali:** Kredi kartı numarasının (PAN) tamamının loglanması ödeme lisansının iptaline yol açar (yalnızca ilk 6 ve son 4 haneye izin verilir).
   - **Yetki Gaspı:** Log sunucusuna erişimi olan herhangi bir destek personeli veya log yedeklerini ele geçiren saldırgan, yönetici parolalarını ve API tokenlarını doğrudan ele geçirir.
3. **Otomatik Maskeleme Mekanizması:**
   Mesaj log motoruna iletildiğinde, filtreden geçirilir:
   - `password=...` veya `api_key=...` ifadeleri `[REDACTED]` ile değiştirilir.
   - `Bearer <JWT_TOKEN>` ifadesi `Bearer [REDACTED_JWT]` yapılır.
   - `4532-1122-3344-9988` numarası `****-****-****-9988` formatına indirgenir.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Büyük bir sosyal medya platformu, 2018 yılında bir yazılım hatası nedeniyle milyonlarca kullanıcının şifresini dahili log dosyalarına açık metin olarak yazmış ve bu loglar şirket içindeki binlerce çalışan tarafından görülebilir hale gelmiştir. Olay dünya çapında prestij kaybına ve soruşturmalara neden olmuştur.

**Pratik Çözüm (Regex Tabanlı Otomatik Maskeleme Filtresi):**
```python
import logging
import re

class SensitiveDataRedactor(logging.Filter):
    PATTERNS = [
        (re.compile(r"(?i)\b(password|passwd|secret|api_key|token)\s*[:=]\s*['\"]?([^\s'\";]+)['\"]?"), r"\1=[REDACTED]"),
        (re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_\.]+)"), "Bearer [REDACTED_JWT]"),
        (re.compile(r"\b(?:\d{4}[ -]?){3}(\d{4})\b"), r"****-****-****-\1")
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.getMessage())
        for pattern, replacement in self.PATTERNS:
            msg = pattern.sub(replacement, msg)
        record.msg = msg
        record.args = ()
        return True
```

### Ustanın Çırağa Tavsiyesi
Çırağım, "bu loglar sadece şirket içinde kalıyor" mazereti siber güvenlikte en büyük yalandır. İçerideki tehdit (Insider Threat), sızdırılmış bir yedek diski veya yanlış yapılandırılmış bir Elasticsearch sunucusu loglarını tüm dünyaya saçar. Loga yazdığın her şeyin yarın bir saldırganın eline geçebileceğini bilerek yaz; sırrı loga gömme!

---

## SORU 3 (G081-SC3): YAPILANDIRILMIŞ JSON LOGLAMA VE DİSK DOYGUNLUĞU (CWE-400 DoS) KORUMASI

### Soru Başlığı ve Tanımı
Düz metin (Unstructured Text) loglama yerine Yapılandırılmış JSON Loglama (Structured JSON Logging) tercih edilmesinin SIEM (Splunk, Elastic, Sentinel) analizindeki hayati rolü nedir? Loglama altyapısını disk doygunluğu (Disk Exhaustion Attack - CWE-400) ve bellek taşması saldırılarına karşı korumak için hangi tavan sınırları ve rotasyon ilkeleri uygulanmalıdır?

### Derinlemesine Teknik Analiz
1. **Düz Metin Logların Zayıflığı:**
   `2026-11-01 10:00:00 [ERROR] IP 192.168.1.5 user admin failed login`
   Bu logu SIEM'de sorgulamak için ayrıştırma motorunun karmaşık normal ifadeler (regex parsing) koşturması gerekir. Milyonlarca satırda CPU tüketimi tavan yapar ve log formatı değiştiğinde alarmlar susar.
2. **Yapılandırılmış JSON Standardı:**
   Her kayıt JSON anahtar-değer ikilisi olarak tutulur:
   `{"timestamp": "2026-11-01T10:00:00Z", "level": "ERROR", "ip": "192.168.1.5", "action": "LOGIN_FAIL"}`
   SIEM sistemleri bu JSON alanlarını doğrudan dizine (index) alır; milisaniyeler içinde analitik korelasyon, coğrafi haritalama ve otomatik karantina kuralları işletilir.
3. **Disk Doygunluğu DoS Tehdidi ve Savunması (CWE-400):**
   Saldırgan milyonlarca hata üreterek diski doldurur (`/var/log` dolar) ve sunucuyu kilitler.
   - **Tavan Mesaj Boyutu:** Mesaj başına 4096 karakter sınırı konur; aşan mesajlar kesilir (`[TRUNCATED]`).
   - **Rotasyon (`RotatingFileHandler`):** `maxBytes` (örneğin 10 MB) aşıldığında dosya arşivlenir; `backupCount` (örneğin 5) ile eski arşivler otomatik silinir.
   - **Propagasyon Engeli:** `logger.propagate = False` yapılarak kök logger'a gereksiz çift yazım engellenir.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret sitesinde Black Friday gecesi saldırganlar devasa boyutlu JSON yükleri göndererek log diskinin dolmasına neden olmuştur. Disk dolunca veritabanı yazma yapamamış ve sistem saatlerce kapalı kalarak milyonlarca liralık ciro kaybı yaşanmıştır.

**Pratik Çözüm (JSON Formatter ve Güvenli Rotasyon):**
```python
import logging
from logging.handlers import RotatingFileHandler
import json
import datetime

class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage()
        }, ensure_ascii=False)

# Rotasyonel Güvenli Dosya İşleyicisi
handler = RotatingFileHandler(
    filename="security_audit.log",
    maxBytes=10 * 1024 * 1024,  # En fazla 10 MB
    backupCount=5,              # En fazla 5 eski yedek (toplam 50 MB tavan)
    encoding="utf-8"
)
handler.setFormatter(JsonFormatter())
```

### Ustanın Çırağa Tavsiyesi
Evladım, sınırsız depolama sadece hayallerde vardır; gerçek sunucuda her diskin bir sonu vardır. Loglarınla sistemi koruyayım derken sunucunun diskini patlatıp sistemi çökertirsen, saldırganın yapamadığını kendi elinle yapmış olursun. Rotasyonunu kur, tavanını koy, verini JSON ile yapılandır!
