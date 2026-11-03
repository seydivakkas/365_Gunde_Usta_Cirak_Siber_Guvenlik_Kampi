# GÜN 080: HATA YÖNETİMİ VE ÖZEL DURUMLAR — SORU VE CEVAPLAR
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## SORU 1 (G080-SC1): FAİL-CLOSED VS FAİL-OPEN HATA YÖNETİMİ VE SESSİZ İSTİSNA YUTMA TEHLİKESİ

### Soru Başlığı ve Tanımı
Siber güvenlik yazılımlarında "Fail-Closed" (Hata Anında Kapalı Kal) ve "Fail-Open" (Hata Anında Açık Kal) yaklaşımları ne anlama gelir? Yazılımcıların sıkça başvurduğu `except: pass` veya genel `except Exception: pass` gibi sessiz hata yutma kalıpları kimlik doğrulama ve yetkilendirme mekanizmalarında nasıl ölümcül güvenlik zafiyetlerine yol açar?

### Derinlemesine Teknik Analiz
1. **Fail-Open (Güvensiz Yaklaşım):** Bir güvenlik kontrolü veya erişim kararı verilirken bir hata oluştuğunda, sistemin kullanıcı deneyimini bozmamak veya akışı tıkamamak adına işlemi geçerli kabul etmesidir.
2. **Fail-Closed (Savunmacı Yaklaşım):** Bir güvenlik denetimi sırasında beklenmeyen, öngörülemeyen veya tanımsız en ufak bir durum oluştuğunda, sistemin varsayılan olarak **ERİŞİMİ REDDETMESİ** ve işlemi derhal sonlandırmasıdır.
3. **Sessiz Hata Yutmanın Mekaniği:**
   Geliştirici bir yetkilendirme fonksiyonunda veritabanı veya imza denetimini `try` içine alır. `except Exception: pass` dediğinde, arka planda meydana gelen bir bellek hatası, veritabanı zaman aşımı veya kriptografik imza bozukluğu sessizce görmezden gelinir. Fonksiyon varsayılan olarak `return True` veya `access = True` döndürürse, saldırgan manipüle ettiği sahte belirteçle sisteme yönetici olarak sızmış olur.
4. **Savunmacı Standart:**
   Güvenlik bloklarında varsayılan değişken durumu daima `is_authorized = False` olarak başlatılmalı, yalnızca ve sadece tüm kontroller başarıyla geçildiğinde `is_authorized = True` yapılmalıdır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankacılık API'sinde iki faktörlü kimlik doğrulama (2FA) servisi SMS sağlayıcısına HTTP isteği atarken ağ zaman aşımı (Timeout) oluşmuştur. Yazılımcı bu hatayı `except Exception: pass` ile yakalayıp 2FA adımını "geçilmiş" saydığı için, saldırganlar SMS kodunu girmeksizin kullanıcı hesaplarını boşaltmıştır.

**Pratik Çözüm (Fail-Closed Güvenlik Deseni):**
```python
def verify_2fa_token_secure(user_id: str, submitted_code: str) -> bool:
    # Kural 1: Varsayılan durum kesinlikle RED (Fail-Closed)
    token_verified = False
    try:
        # Kriptografik doğrulama veya harici servis çağrısı
        token_verified = validate_totp(user_id, submitted_code)
    except (TotpValidationError, NetworkTimeoutError) as known_err:
        # Bilinen hata: Adli kayda al, kullanıcıya güvenli mesaj ver
        log_security_alert(user_id, known_err)
        raise AuthenticationFailureException("Doğrulama kodu geçersiz veya zaman aşımına uğradı.") from known_err
    except Exception as unexpected_err:
        # Bilinmeyen her türlü hata: En kötü senaryo varsayılır
        log_critical_forensic(user_id, unexpected_err)
        raise SecurityException("Güvenlik servis arızası nedeniyle işlem durduruldu.") from unexpected_err
    
    # Kural 2: Asla belirsiz boolean döndürme
    return bool(token_verified)
```

### Ustanın Çırağa Tavsiyesi
Evladım, kodun içinde bir `pass` gördüğümde tüylerim diken diken olur. Hata sana sisteminin feryadıdır; "burada anormal bir şey oldu" demektir. Sen o feryadı elinle susturursan, yarın saldırganın kahkahasını dinlersin. Hata varsa yakala, fail-closed durdur ve kaydını adli deftere yaz.

---

## SORU 2 (G080-SC2): YIĞIN İZİ (STACK TRACE) BİLGİ İFŞASI (CWE-209) VE ADLİ REFERANS KODU MİMARİSİ

### Soru Başlığı ve Tanımı
Yığın İzi Bilgi İfşası (Information Exposure Through an Error Message - CWE-209) nedir? Web servislerinin ve API'lerin istemciye döndürdüğü ham hata metinleri veya Python Traceback çıktıları saldırganlar için nasıl bir istihbarat (reconnaissance) kaynağı oluşturur? İki katmanlı hata yanıtı ve Olay Referans Kodu (Incident ID) mimarisi bu tehdidi nasıl ortadan kaldırır?

### Derinlemesine Teknik Analiz
1. **Traceback Çıktısının Anatomisi:**
   İşlenmemiş bir istisna ekrana basıldığında Python şunları döker:
   - Sunucunun mutlak dosya yolları (`/home/deploy/production_api/auth/jwt_verifier.py`)
   - İşletim sistemi kullanıcı adı ve dizin yapısı
   - Hatanın oluştuğu tam satır numarası ve kod blokları
   - Kullanılan harici kütüphanelerin isimleri ve tam sürümleri
   - Bazen SQL sorguları, çevre değişkenleri veya parametre değerleri
2. **Saldırgan Açısından Keşif Kolaylığı:**
   Saldırgan bu bilgiyi aldığında, kullanılan kütüphane sürümüne ait bilinen CVE zafiyetlerini (1-day exploits) araştırır, hedefli SQL enjeksiyonu veya yerel dosya dahil etme (LFI) saldırılarını doğrudan dosya yollarına göre kurgular.
3. **İki Katmanlı Çözüm Mimarisi:**
   - **İstemci Katmanı (Public Layer):** İstemciye asla teknik terim, dosya yolu veya yığın izi dönülmez. Sadece steril bir mesaj ve benzersiz bir kimlik iletilir: `"İşleminiz güvenlik nedeniyle tamamlanamadı. Destek Kodu: SEC-ERR-88A1F9"`.
   - **Adli Denetim Katmanı (Private Forensic Layer):** Sunucu tarafındaki güvenli SIEM veya şifreli log dosyasında `SEC-ERR-88A1F9` kodu altında tam traceback, istemci IP'si, oturum parametreleri ve zaman damgası saklanır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-devlet portalında kullanıcı girdi alanına tek tırnak (`'`) girdiğinde sunucu ham veritabanı sürücü hatasını ekrana basmıştır. Saldırgan hatadan Oracle veritabanı sürümünü ve tablo sütun isimlerini görerek dakikalar içinde kör SQL enjeksiyonu (Blind SQLi) exploitini tamamlamıştır.

**Pratik Çözüm (Python Güvenli Hata Formatlayıcı):**
```python
import uuid
import datetime

def build_sanitized_client_error(exception_obj: Exception) -> dict:
    # 1. Benzersiz olay referans kodu üret
    incident_id = f"SEC-ERR-{uuid.uuid4().hex[:8].upper()}"
    
    # 2. İç sisteme (SIEM/Log) ayrıntılı adli kaydı yaz
    internal_log = {
        "incident_id": incident_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "raw_error": str(exception_obj),
        "exception_type": type(exception_obj).__name__
    }
    secure_siem_logger.critical(internal_log)
    
    # 3. İstemciye steril, bilgi ifşa etmeyen yanıt dön
    return {
        "durum": "HATA",
        "olay_kodu": incident_id,
        "mesaj": f"Güvenlik politikası nedeniyle isteğiniz reddedildi. İletişim referansı: {incident_id}"
    }
```

### Ustanın Çırağa Tavsiyesi
Çırağım, düşmanına asla bedava istihbarat verme. Müşteriye "Dosya açılamadı çünkü C:/app/secret.key bulunamadı" demek, hırsıza evin anahtarının hangi paspasın altında olduğunu söylemektir. Müşteriye referans kodunu ver, gerisini kendi adli günlüğünde sakla.

---

## SORU 3 (G080-SC3): DETERMINİSTİK KAYNAK TEMİZLİĞİ VE LOG ZEHİRLEMESİ (CWE-117) SAVUNMASI

### Soru Başlığı ve Tanımı
İşlem sırasında beklenmeyen bir hata meydana geldiğinde dosya tanıtıcılarının (file descriptors), kilitlerin (mutex/lock) veya ağ bağlantılarının açık kalması (Resource Leakage DoS) nasıl önlenir? Hata mesajlarına kötü niyetli kullanıcılar tarafından enjekte edilen satır başı (`\r\n`) karakterleri ile sahte log üretimi (Log Forgery - CWE-117) nasıl engellenir?

### Derinlemesine Teknik Analiz
1. **Kaynak Sızıntısı ve DoS Tehdidi:**
   İşletim sistemleri her süreç için sınırlı sayıda açık dosya tanıtıcısına (`ulimit -n`) ve kilit mekanizmasına izin verir. Bir fonksiyon kritik bir dosyayı açıp kilitledikten sonra hata verip `close()` veya `release()` satırına ulaşamazsa, bu kaynak kilitli kalır. Saldırgan sürekli kasıtlı hata tetikleyerek sistemin tüm kaynak havuzunu tüketir (Resource Exhaustion DoS).
   - **Çözüm:** Python'un `with` (Context Manager) protokolü (`__enter__` ve `__exit__`) ya da `try...finally` blokları. `finally` bloğu, hata fırlatılsın veya fırlatılmasın **mutlaka** çalıştırılır.
2. **Log Forgery / Log Zehirlenmesi (CWE-117):**
   Saldırgan bir parametreye şunu gönderir:
   `"GecersizGirdi\r\n[2026-11-01 12:00:00] [AUDIT] Admin kullanicisi sisteme yetkili giris yapti."`
   Eğer hata işleyici bu mesajı doğrudan log dosyasına yazarsa, SIEM veya adli analist bu sahte satırı meşru bir yönetici girişi zanneder ve saldırganın izi örtülür.
   - **Çözüm:** Loga yazılacak her hata metni `re.sub(r"[\r\n\x1b\x00]", " ", message)` süzgecinden geçirilmelidir.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir SOC orkestrasyon betiği, şüpheli IP'leri güvenlik duvarına yazarken veritabanı kilitlenme hatası almıştır. `finally` bloğu olmadığı için veritabanı tablosu kilitli kalmış, sonraki tüm otomatik engelleme kuralları durmuş ve kurumsal ağ saldırıya açık hale gelmiştir.

**Pratik Çözüm (Deterministik Bağlam ve Log Temizliği):**
```python
import re

class SecureLockManager:
    def __init__(self, lock_name: str):
        self.lock_name = lock_name
        self.acquired = False

    def __enter__(self):
        self.acquired = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Hata fırlatılsa bile kilit kesin olarak bırakılır
        self.acquired = False
        return False  # İstisnayı bastırmadan yukarı iletir

def sanitize_for_logging(message: str) -> str:
    # CRLF, ANSI kaçış kodları ve null-byte karakterlerini boşlukla değiştir
    clean = re.sub(r"[\r\n\x1b\x00]", " ", str(message))
    return " ".join(clean.split())
```

### Ustanın Çırağa Tavsiyesi
Evladım, iyi bir usta geride çöp bırakmaz. İşlem yarıda kalsa da, elektrik kesilse de, kodun en can alıcı yerinde patlasa da o kilit açılacak, o dosya kapanacak! Ve unutma; log defterin senin mahkeme tutanağındır. O tutanağa saldırganın kalem oynatmasına asla izin vermeyeceksin.
