# GÜN 080: HATA YÖNETİMİ VE ÖZEL DURUMLAR — SAVUNMACI İSTİSNA MİMARİSİ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞİ: İSTİSNALAR SİSTEMİN AYNASIDIR

Evladım, acemi yazılımcılar hata yönetimini (exception handling) sadece programın aniden kapanmasını ("crash" etmesini) önleyen bir yama mekanizması olarak görür. Kodun etrafına rastgele `try...except Exception: pass` blokları örer, uygulamanın çalışmaya devam etmesini bir başarı zannederler.

Oysa siber güvenlik dünyasında bir ustanın bildiği en temel hakikat şudur: **Kötü tasarlanmış bir hata yönetimi, açık bırakılmış bir güvenlik kapısından çok daha tehlikelidir.**

Bir saldırgan bir sisteme sızmak istediğinde, sistemin normal çalışan yollarından ziyade **beklenmeyen girdilerle hata üreten çatlaklarını** arar. Hata anında sisteminin nasıl davrandığı, senin güvenlik felsefeni belirler:
- Bir istisna oluştuğunda sistemin kapıyı açık mı bırakıyor (Fail-Open), yoksa kilitleyip içeri kimseyi almıyor mu (Fail-Closed)?
- Hata mesajında saldırgana veritabanının yapısını, dosya yollarını ve Python kütüphane sürümlerini mi hediye ediyorsun (CWE-209), yoksa adli bir olay referans kodu verip iç sırlarını gizliyor musun?
- Hata loglarına yazarken saldırganın enjekte ettiği yeni satır karakterleriyle sahte log üretmesine (CWE-117) göz mü yumuyorsun?

Bugün seninle; siber güvenlik araçlarında kurumsal düzeyde bir **Hata Yönetimi ve Özel Durum (Custom Exception)** mimarisi kuracak, fail-closed prensibini kodun her hücresine işleyeceğiz.

---

## 2. FAİL-CLOSED VE FAİL-OPEN DİNAMİĞİ: SESSİZ YUTMANIN FELAKETİ

### 2.1. "Pokemon Exception Handling" Tuzağı
Yazılım dünyasında `except: pass` veya `except Exception: pass` kalıbına halk arasında "Pokemon Exception Handling" (Hepsini Yakala!) denir.
Şu ölümcül kod parçasına dikkatle bak:
```python
# KÖTÜ VE GÜVENSİZ KOD ÖRNEĞİ:
def check_user_permission(user_token):
    try:
        claims = verify_jwt_signature(user_token)
        return claims.get("is_admin", False)
    except Exception:
        # Hata oldu ama program çökmesin diye sessizce geçiştiriliyor!
        pass
    return True  # YA DA YANLIŞLIKLA GEÇİRİLEN DEFAULT DEĞER!
```
Eğer doğrulama fonksiyonu ağ kopması, bellek yetersizliği veya bozuk imza nedeniyle istisna fırlatırsa; bu kod fail-open çalışırsa saldırgan sahte tokenla içeri sızar.

### 2.2. Fail-Closed İlkesi
Savunmacı güvenlikte kural kesindir:
**"Bir güvenlik kontrolü sırasında en ufak bir şüphe, belirsizlik veya istisna meydana gelirse; varsayılan karar daima ERİŞİMİ REDDETMEK (DENY) olmalıdır."**

```python
# GÜVENLİ VE SAVUNMACI KOD:
def check_user_permission_secure(user_token):
    # Varsayılan durum: Kesin ret (Fail-Closed)
    access_granted = False
    try:
        claims = verify_jwt_signature(user_token)
        access_granted = bool(claims.get("is_admin", False))
    except (JwtSignatureError, TokenExpiredError) as auth_err:
        # Bilinen yetki hatası: Adli kayda al ve reddet
        log_security_warning(auth_err)
        raise AuthenticationFailureException("Geçersiz kimlik belirteci.") from auth_err
    except Exception as unexpected_err:
        # Bilinmeyen her türlü hata: En kötü senaryo kabul edilir
        log_critical_forensic(unexpected_err)
        raise SecurityException("Sistem güvenliği nedeniyle istek reddedildi.") from unexpected_err
    finally:
        # Eğer bir kilit açıldıysa mutlaka kapatılır
        release_locks()
    
    return access_granted
```

---

## 3. BİLGİ İFŞASI VE YIĞIN İZİ SIZINTILARI (CWE-209)

### 3.1. Stack Trace Saldırgana Ne Anlatır?
Bir web uygulamasında veya REST API'de işlenmemiş bir hata oluştuğunda, ekrana basılan şu çıktı saldırgan için bir altın madenidir:
```text
Traceback (most recent call last):
  File "/var/www/internal_soc_api/v2/auth.py", line 84, in execute_query
    conn = psycopg2.connect("dbname=soc_db user=postgres host=10.0.0.50 password=...")
psycopg2.OperationalError: could not connect to server: Connection refused
```
Bu çıktı sayesinde saldırgan:
1. Uygulamanın Python ve `psycopg2` kullandığını öğrenir.
2. Dahili dosya sisteminin `/var/www/internal_soc_api/v2/` yolunda olduğunu anlar.
3. Dahili veritabanı IP'sinin `10.0.0.50`, kullanıcı adının `postgres`, veritabanı adının `soc_db` olduğunu öğrenir!

### 3.2. Çözüm: İki Katmanlı Hata İletişimi
Savunmacı sistemlerde hatalar ikiye ayrılır:
1. **Dış İstemciye (Public User):** Yalnızca genel ve steril bir mesaj ile benzersiz bir **Olay Referans Numarası (Incident ID)** verilir (`SEC-ERR-A4F12C`). Asla iç mimari detayı verilmez.
2. **İç Adli Loglara (Private Forensic SIEM):** Ayrıştırılmış, sterilize edilmiş ve zaman damgalı ayrıntılı teknik log kaydedilir. Analist veya mühendis sorun olduğunda destek biletindeki `SEC-ERR-A4F12C` kodunu SIEM'de aratarak gerçek kök nedeni bulur.

---

## 4. ÖZEL GÜVENLİK İSTİSNA HİYERARŞİSİ (SECURITY EXCEPTION HIERARCHY)

Standart Python istisnaları (`ValueError`, `TypeError`, `KeyError`) genel amaçlıdır. Bir siber güvenlik mimarisinde güvenlik olaylarını operasyonel hatalardan ayırt edebilmek için **özel bir istisna hiyerarşisi** kurulmalıdır:

```
                      +-------------------------------+
                      |       SecurityException       |
                      |  - incident_id                |
                      |  - timestamp                  |
                      |  - context_details            |
                      +-------------------------------+
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
         v                            v                            v
[AuthenticationFailure]     [AuthorizationDenied]       [InputSanitization]
(Kimlik Doğrulama)          (Yetki / RBAC İhlali)       (XSS, SQLi, Payload)
         |                            |
         v                            v
[RateLimitExceeded]         [SecurityResourceException]
(Brute-Force / DoS)         (Kilit / Temizlik Hatası)
```

Bu hiyerarşi sayesinde kodun üst katmanlarında şu ayrımı yapabilirsin:
```python
try:
    gateway.process(request)
except AuthenticationFailureException:
    # 401 Unauthorized üret, SIEM'e düşük seviye auth alarmı yaz
except AuthorizationDeniedException:
    # 403 Forbidden üret, SIEM'e orta seviye yetki alarmı yaz
except InputSanitizationException:
    # 400 Bad Request üret, WAF kurallarını güncelle
except SecurityException:
    # Genel güvenlik ihlali, IP'yi izlemeye al
except Exception:
    # 500 İç Sunucu Hatası, ama fail-closed!
```

---

## 5. DETERMINİSTİK KAYNAK TEMİZLİĞİ VE CONTEXT MANAGERS

Hata yönetiminin en kritik ayaklarından biri **kaynak sızıntılarının (Resource Leaks)** önlenmesidir. Bir dosya kilidi, veritabanı oturumu veya ağ soketi işlem sırasında hata oluştuğunda açık kalırsa; sistem kaynak tükenmesi (Denial of Service - DoS) krizine sürüklenir.

Python'un `try...finally` veya `with` (Context Manager) mekanizması ile kaynak temizliği deterministik (kesin) hale getirilir:

```python
class SecureResourceContext:
    def __enter__(self):
        self.acquire_lock()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # İstisna olsa da olmasa da kilit serbest bırakılır!
        self.release_lock()
        # exc_type varsa False dönerek istisnanın yukarı fırlatılmasını sağlarız
        return False
```

---

## 6. LOG FORGERY / LOG ENJEKSİYONU (CWE-117)

Saldırganlar hata mesajlarına kasıtlı olarak yeni satır (`\r\n`) veya terminal kaçış dizileri (`\x1b[...]`) enjekte ederek log dosyalarını tahrif eder:
```text
Hata: KullaniciBulunamadi\r\n[INFO] 2026-11-01 Admin kullanicisi basariyla sisteme girdi.
```
Log okuyucu bu kaydı iki ayrı satır gibi görür ve adli bilişim analisti yanıltılır. Savunmacı hata işleyici, loga yazmadan önce tüm mesajları `re.sub(r'[\r\n\x1b\x00]', ' ', msg)` filtresinden geçirmelidir.

---

## 7. ÖZET VE USTADAN ÇIRAĞA TAVSİYELER

1. **Sessizliği Terk Et:** `except: pass` yazan bir el, sistemin idam fermanını imzalayan eldir. Hata varsa yakala, logla ve fail-closed durdur.
2. **Müşteriye Sır Verme:** Kullanıcıya "Hata oluştu, kodunuz: SEC-ERR-X" de. Dosya yollarını ve yığın izini yalnızca kendi güvenli loglarında sakla.
3. **Kendi Dilini Konuş:** Güvenlik katmanında generic hatalar yerine kendi `SecurityException` hiyerarşini kullan; alarm yönetimini kristal berraklığına kavuştur.
4. **Temizliği Şansa Bırakma:** Her açılan kaynağın arkasında bir `finally` veya `with` bekçisi olsun.
