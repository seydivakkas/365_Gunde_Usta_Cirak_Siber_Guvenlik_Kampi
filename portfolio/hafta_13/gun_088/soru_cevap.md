# G088: Komut Çıkış Kodları ve stderr Soru ve Cevap Rehberi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

### Soru 1: İşletim Sistemlerinde Çıkış Kodlarının (Exit Codes) Standartları Nelerdir ve Güvenlik Olayı Tespitinde Nasıl Kullanılır?

#### 1. Soru Başlığı ve Tanımı
Bir sürecin işletim sistemine döndürdüğü çıkış kodunun (0-255) teknik standardı nedir ve güvenlik izleme (SIEM/EDR) sistemleri 126, 127 ve 137 gibi spesifik çıkış kodlarını bir saldırı veya arıza göstergesi olarak nasıl analiz eder?

#### 2. Derinlemesine Teknik Analiz
POSIX standartlarında her alt süreç, sonlanma durumunu üst sürece `wait()` veya `waitpid()` sistem çağrıları aracılığıyla 8 bitlik bir tamsayı olarak bildirir:
1. **0 (Başarı):** Sürecin beklenilen iş mantığını başarıyla icra ettiğini doğrular.
2. **126 (Permission Denied):** Hedef dosya dosya sisteminde mevcuttur ancak çalıştırma yetkisi (`execute bit`) bulunmamaktadır. Saldırganın yetkisiz ikili dosyaları koşturma denemesi (Privilege Escalation) veya AppLocker / SELinux engellemesi göstergesidir.
3. **127 (Command Not Found):** Kabuk, `PATH` ortam değişkenindeki dizinlerde hedef komutu bulamamıştır. Bu durum hatalı yapılandırma olabileceği gibi, saldırganın sistemde keşif (reconnaissance) yaparken var olmayan araçları aradığını ya da PATH Hijacking girişiminde bulunduğunu gösterir.
4. **128+N (Fatal Signal Termination):** Sürecin kendi rızasıyla değil, bir sinyalle zorla öldürüldüğünü gösterir:
   - **137 (128 + 9 = SIGKILL):** İşlem `kill -9` ile durdurulmuştur veya Linux OOM (Out of Memory) Killer tarafından bellek tükenmesi nedeniyle öldürülmüştür. Bu bir DoS atağının doğrudan kanıtıdır.
   - **139 (128 + 11 = SIGSEGV):** Süreç Segmentation Fault (Geçersiz Bellek Erişimi) ile çökmüştür. Genellikle Buffer Overflow (Bellek Taşması) exploit girişimlerinin en net izidir!

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Linux sunucuda çalışan web uygulaması arka planda görüntü işleme ikililerini çağırmaktadır. Saldırgan yüklediği zararlı bir dosya ile görüntü işleyiciyi Buffer Overflow exploitine tabi tutar. Geliştirici çıkış kodunu denetlemediği için işlem sessizce çöker ve saldırgan arka kapı açar.

**Pratik Çözüm (Usta Yaklaşımı):**
```python
import subprocess
import logging

def execute_security_binary(cmd_args):
    try:
        proc = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False
        )
        # Çıkış kodu adli analizi
        if proc.returncode == 0:
            return proc.stdout
        elif proc.returncode == 139:
            logging.critical(f"[ALARM - EXPLOIT ŞÜPHESİ] Süreç SIGSEGV (139) ile çöktü! Komut: {cmd_args}")
            raise SecurityExploitSuspectedException("Bellek taşması girişimi tespit edildi.")
        elif proc.returncode == 127:
            logging.error(f"[HATA] Güvenlik ikilisi sistemde bulunamadı (127): {cmd_args}")
            raise CommandNotFoundSecurityException("Güvenlik aracı eksik veya PATH manipüle edilmiş.")
        else:
            logging.warning(f"[UYARI] Süreç başarısız oldu (Kod: {proc.returncode}): {proc.stderr}")
            raise CommandExecutionFailedException(f"Çıkış kodu: {proc.returncode}")
    except subprocess.TimeoutExpired:
        logging.critical(f"[ALARM - DoS] Süreç zaman aşımına uğradı ve asılı kaldı: {cmd_args}")
        raise ProcessExecutionTimeoutException("Süreç yanıt vermiyor.")
```

#### 4. Ustanın Çırağa Tavsiyesi
Evlat, bir komut çalıştığında yalnızca "hata verdi mi vermedi mi" diye bakma. Hata kodunun numarasına bak! 139 görüyorsan bellek saldırısı altındasın, 137 görüyorsan RAM tükeniyor, 126 görüyorsan yetki sınırına çarptın. Çıkış kodu sistemin konuşma dilidir; onu dinlemeyi öğren.

---

### Soru 2: `2> /dev/null` Kullanımı Neden Sessiz Hata Yutma (CWE-390) Zafiyetidir ve Güvenli Alternatifleri Nelerdir?

#### 1. Soru Başlığı ve Tanımı
Bash betiklerinde veya cron görevlerinde stderr çıktısını `2> /dev/null` ile yok etmek neden CWE-390 kapsamında tehlikeli bir güvenlik zaafiyetidir ve hata akışları denetim izini kaybetmeden nasıl yönetilmelidir?

#### 2. Derinlemesine Teknik Analiz
`2> /dev/null` ifadesi, dosya tanımlayıcısı 2 olan standart hata akışını Unix çekirdeğinin boş aygıtına (null device) yönlendirir. Bu işlem şu kritik güvenlik zafiyetlerine yol açar:
1. **Denetim İzi Kaybı (Audit Blindness):** Bir yetkisiz erişim, sertifika hatası veya izin reddi durumu loglanmaz. SOC analistleri saldırıyı geriye dönük inceleyemez.
2. **Kör Döngüler ve Kaskad Çöküş:** Bir betik konfigürasyon dosyasını okuyamadığı halde hatayı yutar ve sonraki satırlarda hatalı verilerle işlem yaparak veri tabanını veya sistemi bozar.
3. **Gizli Saldırı İletimi:** Saldırgan sistemde gürültü çıkaran bir exploit çalıştırırken hatayı gizleyerek yöneticilerin fark etmesini engeller.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Her gece sunucu sertifikalarını yenileyen bir cronjob betiği yazılmıştır:
```bash
certbot renew 2> /dev/null
```
Sertifika yetkilisiyle ağ bağlantısı koptuğunda veya API anahtarı geçersiz kılındığında işlem hata verir; ancak `2> /dev/null` yüzünden kimse bunu görmez. 30 gün sonra tüm üretim SSL sertifikaları düşer ve şirket hizmet veremez hale gelir.

**Pratik Çözüm (Usta Yaklaşımı):**
Hata akışı asla yok edilmez; izole denetim loguna yönlendirilir ve çıkış kodu anında kontrol edilir:
```bash
#!/usr/bin/env bash
set -euo pipefail

LOG_ERR="/var/log/cert_renew_error.log"

# Hata akışı güvenli log dosyasına yönlendirilir, sessizce yutulmaz
if ! certbot renew 2>> "${LOG_ERR}"; then
    exit_status=$?
    # SIEM veya Alerting sistemine bildirim gönderilir
    logger -p local0.err -t CERT_RENEW "Kritik Hata: Sertifika yenileme başarısız (Kod: ${exit_status})"
    exit "${exit_status}"
fi
```

#### 4. Ustanın Çırağa Tavsiyesi
Asla ekrandan hata gizlemek için `2> /dev/null` kullanma! Eğer bir komutun çıktısı seni rahatsız ediyorsa, onu çöpe atmak yerine izole bir log dosyasına (`2>> /var/log/app_errors.log`) yönlendir. Bir gün sistem çöktüğünde seni kurtaracak tek şey o log dosyasıdır.

---

### Soru 3: stderr Akışında Bilgi İfşası (CWE-209 / CWE-532) Nasıl Oluşur ve Nasıl Engellenir?

#### 1. Soru Başlığı ve Tanımı
Uygulama veya betiklerin hata akışına (stderr) açık metin parola, token, bağlantı dizgisi veya dahili sistem yolları yazdırması neden kritik bir zafiyettir ve bu sızıntılar nasıl maskelenir (redaction)?

#### 2. Derinlemesine Teknik Analiz
`stderr` kanalı genellikle geliştiriciler ve sistem yöneticileri tarafından "güvenli bir iç kanal" olarak algılanır. Ancak:
- Birçok konteyner ortamında (Docker, Kubernetes), `stderr` logları merkezi log toplayıcılara (Elasticsearch, Loki, CloudWatch) aktarılır. Bu loglara geliştirici ve analist ekipleri geniş yetkilerle erişebilir.
- Web sunucularında yakalanmayan bir `stderr` çıktısı kullanıcı tarayıcısına hata sayfası olarak yansıyabilir (**CWE-209**).
- Hata akışına basılan veritabanı bağlantı dizesi (`postgresql://admin:SecretPass@10.0.0.5:5432/core_db`) saldırgana doğrudan veri tabanı kök yetkisi verir (**CWE-532**).

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Python otomasyon aracı harici API'ye bağlanırken hata aldığında istisnayı ekrana basmaktadır:
```python
raise ConnectionError(f"API bağlantısı başarısız: {request_url} Headers: {headers}")
```
`headers` sözlüğü içerisinde `Authorization: Bearer eyJhbGci...` tokenı yer almaktadır. Hata çıktısı kurumsal log sistemine düşer ve tüm şirket çalışanları tarafından görülebilir hale gelir.

**Pratik Çözüm (Usta Yaklaşımı):**
Hata mesajları loglanmadan veya stderr akışına verilmeden önce regex tabanlı katı bir maskeleme (redaction) filtresinden geçirilir:
```python
import re

class SecureErrorLogger:
    SENSITIVE_PATTERNS = [
        (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\s]+"), r"\1:***REDACTED***"),
        (re.compile(r"(?i)(bearer|token|apikey)\s*[:=]\s*[^\s]+"), r"\1:***REDACTED***"),
        (re.compile(r"(?i)(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@"), r"\1://***REDACTED***:***REDACTED***@")
    ]

    @classmethod
    def sanitize_error_message(cls, message: str) -> str:
        sanitized = message
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

# Kullanım:
try:
    connect_to_database(db_url)
except Exception as e:
    safe_error = SecureErrorLogger.sanitize_error_message(str(e))
    sys.stderr.write(f"[HATA] {safe_error}\n")
    sys.exit(1)
```

#### 4. Ustanın Çırağa Tavsiyesi
Çırak, hata mesajı yazarken asla tembellik yapıp tüm nesneyi veya değişkeni ekrana basma. Kullanıcıya veya loga sadece "ne olduğu" bilgisini ver; "içinde ne vardı" bilgisini verme. Parola, token ve gizli anahtarlar asla hata akışının mürekkebi olamaz.
