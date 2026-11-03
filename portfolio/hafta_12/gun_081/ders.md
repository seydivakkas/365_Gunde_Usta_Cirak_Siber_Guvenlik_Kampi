# GÜN 081: PYTHON LOGGING MODÜLÜ — GÜVENLİ SIEM DENETİM BORU HATTI
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞİ: LOGLAR BİR GÜVENLİK SİSTEMİNİN KARA KUTUSUDUR

Evladım, bir siber saldırı gerçekleştiğinde sistemin ne kadar güçlü şifrelendiği veya kaç satır kod yazdığın ikinci planda kalır. Olay Müdahale (Incident Response) ve Adli Bilişim (Digital Forensics) ekiplerinin elindeki tek gerçek dayanak **log kayıtlarıdır**.

Acemiler kod yazarken ekrana `print("Hata oluştu")` veya `print(f"Kullanıcı {user} giriş yaptı")` basarak işi çözdüğünü zanneder. Oysa kurumsal güvenlikte `print()` kullanmak intihardır:
- `print()` çıktısının bir ciddiyet seviyesi (Severity Level: DEBUG, INFO, WARNING, ERROR, CRITICAL) yoktur.
- `print()` zaman damgası (Timestamp), süreç numarası (PID), iş parçacığı (Thread) veya çağıran modül bilgisi üretmez.
- `print()` doğrudan standart çıktıya (stdout) yazar; dosya rotasyonu, ağ soketine aktarım veya SIEM entegrasyonu sunamaz.
- En tehlikelisi: `print()` hiçbir girdi filtresi barındırmaz. Kullanıcının girdiği parolayı, kredi kartını veya CRLF saldırı dizisini olduğu gibi basar!

Bugünkü dersimizde; Python'un standart `logging` modülünü kurumsal bir **Savunmacı SIEM Denetim Boru Hattına** dönüştüreceğiz. **Log Enjeksiyonunu (CWE-117)**, **Hassas Veri İfşasını (CWE-532 / CWE-359)** ve **Disk Doygunluğu DoS (CWE-400)** tehditlerini mimari seviyede engelleyeceğiz.

---

## 2. LOG FORGERY / LOG ENJEKSİYONU (CWE-117): SAHTE TARİH YAZANLAR

### 2.1. Saldırının Doğası
Bir web servisinde veya güvenlik aracında kullanıcı giriş logu şöyle tutuluyor olsun:
```python
logger.info(f"Kullanici girisi: {username}")
```
Saldırgan `username` alanına şu değeri girdiğinde ne olur?
```text
guest\r\n[2026-11-01 12:00:00] [AUDIT] [INFO] Admin kullanicisi sisteme yetkili giris yapti.
```
Eğer sistem ham mesajı log dosyasına yazarsa; düz metin log dosyasında **iki ayrı satır** oluşur:
```text
2026-11-01 11:59:59 [INFO] Kullanici girisi: guest
2026-11-01 12:00:00 [AUDIT] [INFO] Admin kullanicisi sisteme yetkili giris yapti.
```
Adli analist veya SIEM aracı ikinci satırı meşru bir yönetici oturumu zanneder. Gerçekte saldırgan `guest` yetkisiyle sistemi istismar ederken, loglarda sahte bir iz bırakarak suçunu gizler veya başka bir hesabı hedef gösterir.

### 2.2. Ustanın Savunma Reçetesi
Loglama hattına giren her mesaj, bir `logging.Filter` tarafından taranmalı; `\r`, `\n` ve `\x00` karakterleri tespit edildiğinde anında boşluk ile değiştirilerek **tek bir satıra indirgenmelidir**.

---

## 3. HASSAS VERİ İFŞASI VE OTOMATİK MASKELEME (CWE-532 / CWE-359)

### 3.1. Günlüklere Parola ve Token Sızması
Geliştiriciler hata ayıklarken genellikle tüm istek nesnesini veya hata metnini loga yazar:
```python
logger.error(f"Baglanti basarisiz: {db_connection_url}")
# ÇIKTI: postgresql://admin:GizliP@ss99@db.local/soc
```
Bu log dosyası yedeklendiğinde, merkezi log sunucusuna (Splunk/ELK) aktarıldığında veya stajyer bir analist tarafından incelendiğinde; parolanın tüm organizasyona ifşa olmasına yol açar.

### 3.2. Savunmacı Regex Maskeleme (Redaction Filter)
Log filtresi, mesaj içindeki belirli hassas kalıpları yayınlanmadan önce yakalar ve maskeler:
- **Parolalar ve API Anahtarları:** `password=***` -> `password=[REDACTED]`
- **Bearer Yetki Belirteçleri:** `Bearer eyJ...` -> `Bearer [REDACTED_JWT]`
- **Kredi Kartı Numaraları (PCI-DSS):** `4532-1122-3344-9988` -> `****-****-****-9988`

---

## 4. YAPILANDIRILMIŞ JSON LOGLAMA VE SIEM ENTEGRASYONU

### 4.1. Düz Metin (Plain Text) vs Yapılandırılmış JSON
Geleneksel loglar düz metindir:
`2026-11-01 14:00:00 - User admin login failed from 192.168.1.1`
Bu formatı bir SIEM aracında (Splunk, Elastic) sorgulamak regex gerektirir, yavaştır ve formattaki en ufak bir virgül değişikliğinde analiz kuralları çöker.

### 4.2. JSON Security Log Standardı
Modern güvenlik mimarisi her log satırını katı bir JSON nesnesi olarak üretir:
```json
{
  "timestamp": "2026-11-01T04:00:00.123456Z",
  "level": "CRITICAL",
  "logger_name": "SIEM_Audit_Engine",
  "module": "auth_service",
  "line_number": 88,
  "process_id": 1420,
  "message": "GÜVENLİK ALARMI [SQL_INJECTION]: Parametre içinde 'UNION SELECT' tespit edildi.",
  "context": {
    "source_ip": "203.0.113.88",
    "rule": "SQL_INJECTION"
  }
}
```
Bu sayede SIEM motoru tek bir mikro-saniyede `level: "CRITICAL" AND context.source_ip: "203.0.113.88"` sorgusunu çalıştırarak otomatik IP bloklama kuralını tetikleyebilir.

---

## 5. DİSK DOYGUNLUĞU VE TAVAN SINIRLARI (CWE-400 DoS)

Bir saldırgan sisteme yüz binlerce devasa log üretecek istek göndererek sunucunun disk alanını doldurabilir (Disk Exhaustion Attack). Disk dolduğunda işletim sistemi kilitlenir, veritabanları çöker ve tüm güvenlik mekanizmaları devre dışı kalır.

**Savunmacı Önlemler:**
1. **İleti Tavan Sınırı (`max_message_length`):** Tek bir log iletisi 4096 karakteri aşamaz; aşan kısım `...[TRUNCATED]` ile kesilir.
2. **Rotasyonel Dosya İşleyicisi (`RotatingFileHandler`):** Log dosyaları belirli bir boyuta (ör. 10 MB) ulaştığında döndürülür (`maxBytes=10*1024*1024`), eski dosyalar sıkıştırılır ve en fazla belirlenen sayıda (`backupCount=5`) yedek tutulur.
3. **Propagasyon İzolasyonu (`logger.propagate = False`):** Özel güvenlik logger'larının root logger'a sinyal göndermesi engellenerek log döngüsü (loop) ve mükerrer disk yazımı önlenir.

---

## 6. ÖZET VE USTADAN ÇIRAĞA TAVSİYELER

1. **`print()` Kullanan Çırak Ustalaşamaz:** Üretim kodunda `print()` bir ayıptır. Her zaman ciddiyet seviyesi olan yapılandırılmış `logging` kullan.
2. **Log Dosyan Mahkemedeki Şahidindir:** O şahidin kafasını CRLF ile karıştırmalarına izin verme. Her satır steril, tek ve net olmalıdır.
3. **Sırları Günlüğüne Yazma:** Kullanıcının parolası, tokenı veya kredi kartı senin log dosyanda açık metin geziyorsa; sen koruyucu değil, saldırganın işbirlikçisi olursun. Maskeleme filtresi zorunludur.
4. **JSON Düşün:** Logu insanın okuması için değil, SIEM motorunun milisaniyede analiz etmesi için yapılandırılmış JSON olarak üret.
