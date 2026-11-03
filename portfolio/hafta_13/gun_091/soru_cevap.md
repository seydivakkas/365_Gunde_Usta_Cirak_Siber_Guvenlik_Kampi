# GÜN 091: Mini Proje 12 — Mülakat ve Saha Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap seti yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz paylaşılamaz veya çoğaltılamaz.*

---

## SORU 1: Heterojen (Windows/Linux) Altyapılarda Merkezi Güvenlik Raporlama Mimarisi Nasıl Tasarlanmalıdır?

### 1. Soru Başlığı ve Tanımı
Bir kurumda hem Windows Server (Active Directory, IIS, MSSQL) hem de Linux (Ubuntu, RHEL, Docker/K8s) sunucuların bulunduğu heterojen bir altyapıda; işletim sistemine bağımlı olmadan çalışan, yerel betiklerle veri toplayıp merkezi bir analiz motorunda birleştiren kurumsal bir güvenlik raporlama boru hattı mimarisi nasıl kurulmalıdır?

### 2. Derinlemesine Teknik Analiz
Farklı işletim sistemleri farklı yönetim araçlarına (Windows: WMI/CIM, PowerShell, Registry; Linux: POSIX dosya sistemi `/proc`, `/sys`, `systemd`, `syslog`) sahiptir. 
Merkezi ve ölçeklenebilir bir denetim mimarisi kurmak için:
1. **İki Aşamalı Mimari (Collector-Analyzer Pattern):**
   - **Toplayıcı Katmanı (Agent/Collector):** Her işletim sisteminde kendi yerel ve doğal diliyle (Windows'ta `PowerShell`, Linux'ta `POSIX Bash`) çalışır. Dışarıdan ağır kütüphanelere bağımlı kalmadan yalnızca ham sistem telemetrisini toplar ve standart bir veri taşıma formatına (JSON) dönüştürür.
   - **Analiz ve Raporlama Katmanı (Central Reporter):** Toplanan telemetriyi platformdan bağımsız ortak bir motora (Python tabanlı `CrossPlatformSecurityReporter`) besler.
2. **Standart Veri Sözleşmesi (Data Contract):**
   - Her iki platformdan gelen telemetri de zorunlu alanlara sahip olmalıdır: `platform`, `hostname`, `zaman_damgasi_utc` (ISO-8601 Zulu), `acik_portlar`, `calisan_servisler` ve `stderr_gunlukleri`.
3. **Savunma Derinliği (Defense-in-Depth):**
   - Merkezi motor gelen veriyi "güvenilmeyen dış girdi" kabul ederek boyut sınırı (1 MB DoS koruması), naive zaman damgası reddi (CWE-613) ve regex ile hassas veri sızıntısı taramasından (CWE-532) geçirir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir banka altyapısında 500 Windows ve 1000 Linux sunucunun günlük güvenlik durumunun denetlenmesi:

```python
from cross_platform_security_reporter import CrossPlatformSecurityReporter

# 1. Merkezi raporlayıcı motorunu başlat
reporter = CrossPlatformSecurityReporter()

# 2. Gelen telemetriyi kapıda sıkı doğrulamadan geçir
validated_telemetry = reporter.validate_telemetry_payload(raw_json_string)

# 3. Zafiyet analizini ve puanlamayı yürüt (Derin tarama modu)
report = reporter.audit_telemetry(validated_telemetry, deep_scan=True)

# 4. Kurumsal SIEM (Splunk/Elastic) için JSON, yönetim için Text çıktısı üret
siem_payload = reporter.format_report(report, format_tipi="json")
management_summary = reporter.format_report(report, format_tipi="text")
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, Linux üzerinde çalışan bir Python betiğine Windows WMI kütüphaneleri yüklemeye veya Windows'a sahte Linux komutları uydurmaya kalkışma. İşletim sistemine saygı duy: Windows'ta PowerShell'in gücünden, Linux'ta Bash'in sadeliğinden yararlan. Veriyi JSON ile köprüle, analizi merkezde yap."

---

## SORU 2: Bir Sistem Denetim Aracında Dosya İzinleri (CWE-732) ve Servis Zafiyetleri (CWE-506) Nasıl Derecelendirilmeli ve Puanlanmalıdır?

### 1. Soru Başlığı ve Tanımı
Otomatik bir sistem denetim aracında (Security Auditor); Linux'ta `/etc/shadow` dosyasının yanlışlıkla `0644` (world-readable) yapılması ile Windows'ta yetkisiz bir kripto madencilik servisinin (`CryptoMinerSvc`) çalışması arasındaki risk farkı nedir? Bu bulgular kurumsal bir güvenlik puanlama modelinde (Scoring Model) nasıl ağırlıklandırılmalıdır?

### 2. Derinlemesine Teknik Analiz
Siber güvenlik denetimlerinde her bulgu eşit risk teşkil etmez:
- **Linux `/etc/shadow` Dosyasının 0644 Olması (CWE-732 / CRITICAL):**
  - Normalde yalnızca `root:root` tarafından `0640` veya `0000` izinleriyle okunabilen bu dosya, kullanıcıların parola tuzlarını ve özetlerini (SHA-512 / yescrypt hashes) saklar.
  - Eğer `0644` (dünya tarafından okunabilir) olursa, sistemdeki en düşük yetkili kullanıcı veya bir web servisi kullanıcısı (örn. `www-data`) bu dosyayı okuyup John the Ripper veya Hashcat ile kırarak anında `root` parolasını ele geçirebilir. Bu **doğrudan tam yetki yükseltme (Privilege Escalation)** açığıdır.
  - Puan Kesintisi: -40 Puan (Kritik).
- **Windows'ta Şüpheli / Kripto Madenci Servisi (CWE-506 / CRITICAL):**
  - Sistemde çalışan `CryptoMinerSvc` gibi servisler, sistemin zaten daha önceden ele geçirildiğini (Compromised) ve içeride kötü amaçlı kod yürütüldüğünü gösterir.
  - Bu durum hem işlemci kaynaklarını tüketerek hizmet reddine (DoS) yol açar, hem de arkasında bir komuta kontrol (C2) bağlantısı barındırabilir.
  - Puan Kesintisi: -35 Puan (Kritik).
- **Ağ Portları (SMB 445 ve Redis 6379 - HIGH):**
  - SMB dışarıya açıksa fidye yazılımları için giriş kapısıdır (-15 Puan).
  - Redis şifresiz dışarıya açıksa RCE riski taşır (-15 Puan).

Puanlama modeli 100 taban puanından kesintiler yapılarak $S = \max(0, 100 - \sum P_i)$ formülüyle hesaplanır. Puan $\ge 85$ ise GÜVENLİ, $50-84$ arası RİSKLİ, $<50$ ise KRİTİK olarak etiketlenir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Denetim motorunda ceza puanı ve risk eşiği mantığı:

```python
def calculate_system_verdict(findings):
    total_penalty = sum(f.puan_kesintisi for f in findings)
    final_score = max(0, 100 - total_penalty)
    
    # En az bir kritik bulgu varsa doğrudan KRİTİK ilan et
    has_critical = any(f.onem_derecesi == "CRITICAL" for f in findings)
    
    if has_critical or final_score < 50:
        verdict = "KRİTİK"
    elif final_score < 85:
        verdict = "RİSKLİ"
    else:
        verdict = "GÜVENLİ"
        
    return final_score, verdict
```

### 4. Ustanın Çırağa Tavsiyesi
"Evlat, yönetim paneline rapor sunarken '100 üzerinden 90 aldık, çok iyiyiz' demek yetmez. Eğer geriye kalan 10 puanlık açık `/etc/shadow` dosyasının okunabilmesi ise, o 90 puan sahte bir zaferdir. Skorlama modellerinde kritik zafiyetler (Critical Findings) veto hakkına sahip olmalı ve skoru doğrudan kırmızıya boyamalıdır."

---

## SORU 3: Rapor Çıktı Dosyalarında Dizin Atlama (Path Traversal - CWE-22) ve Bilgi Sızıntısı (CWE-532) Savunması

### 1. Soru Başlığı ve Tanımı
Bir CLI güvenlik aracı kullanıcıdan `--output-file <dosya_yolu>` parametresi aldığında ve betiklerin `stderr` çıktısını rapora dahil ettiğinde ortaya çıkabilecek iki ölümcül zafiyet (CWE-22 ve CWE-532) nelerdir? Bu zafiyetler kod seviyesinde nasıl engellenir?

### 2. Derinlemesine Teknik Analiz
1. **Dizin Atlama (Path Traversal - CWE-22):**
   - Kullanıcı veya aracı çağıran harici bir betik `--output-file ../../../etc/cron.d/root_job` parametresi verebilir.
   - Eğer CLI aracı root yetkisiyle veya servis hesabı ile çalışıyorsa, rapor içeriğini sistemin kritik bir dosyası üzerine yazarak **Yetkisiz Dosya Ezme (Arbitrary File Overwrite)** veya cron mekanizması üzerinden **Kod Çalıştırma (RCE)** sağlayabilir.
   - Savunma: Yol içerisinde `..` karakter dizilimi kesinlikle yasaklanmalı, `os.path.abspath` ve `os.path.realpath` kontrolleriyle hedef yolun izin verilen kök dizin sınırları içinde kaldığı teyit edilmelidir.
2. **Log/Stderr Bilgi Sızıntısı (CWE-532 / CWE-209):**
   - Sistem komutları veya veri toplayıcı betikler hata yaptığında stderr akışına veritabanı bağlantı parolalarını (`password=Secret123`), kimlik belirteçlerini veya yetkili dosya yollarını yazabilir.
   - Bu akış olduğu gibi rapora basılırsa, düşük yetkili rapor okuyucuları sistem parolalarını öğrenir.
   - Savunma: Düzenli ifadeler (Regex) ile `password=`, `token=`, `secret=` kalıpları taranmalı; ya girdi reddedilmeli ya da hassas veriler `[REDACTED_CREDENTIAL]` şeklinde maskelenmelidir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
```python
import os
import re

SENSITIVE_PATTERN = re.compile(
    r"(password|token|secret|api[_-]?key)\s*[:=]\s*([^\s;,\'\"]+)",
    re.IGNORECASE
)

def sanitize_and_validate_report_path(output_path: str, allowed_dir: str = "./reports") -> str:
    """Path traversal engelleyici."""
    if ".." in output_path:
        raise PermissionError("Güvenlik İhlali: Dizin atlama ('..') tespit edildi!")
    
    base_abs = os.path.abspath(allowed_dir)
    target_abs = os.path.abspath(os.path.join(allowed_dir, output_path))
    
    if not target_abs.startswith(base_abs):
        raise PermissionError("Güvenlik İhlali: İzin verilen kök dizin dışına çıkılamaz!")
        
    return target_abs

def mask_sensitive_logs(log_text: str) -> str:
    """Hassas kimlik bilgilerini maskeleyici."""
    return SENSITIVE_PATTERN.sub(r"\1=[GİZLENDİ_HASSAS_VERİ]", log_text)
```

### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, güvenlik aracı yazarken kendin bir güvenlik açığı haline gelmeyeceksin. Bir güvenlik raporlayıcısının görevi açıkları kapatmaktır; saldırgana sistem dosyalarını ezme hakkı vermek veya parolaları rapor sayfalarına serpmek değil. Her zaman kapıyı çift kilitle: yolu sınırla, veriyi maskele."
