# GÜN 074: FONKSİYONLAR VE TEMİZ KOD (FUNCTIONS, CLEAN CODE & DEFENSIVE MODULARITY)
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞ DERSİ: SİBER GÜVENLİKTE KOD TEMİZLİĞİ BİR ESTETİK DEĞİL, BİR SAVUNMA KALKANIDIR

Evlat, siber güvenlik dünyasına yeni adım atan çıraklar genellikle şöyle düşünür: *"Kodum çalışıyorsa ve saldırıyı engelliyorsa ne kadar karmaşık, spagetti veya uzun olduğu önemli değildir."* Bu, bir güvenlik mühendisinin düşebileceği en ölümcül yanılgıdır.

Siber savunma araçlarında karmaşıklık, güvenlik açıklarının kuluçka merkezidir. 300 satırlık monolitik bir log ayrıştırıcı fonksiyonu düşün: İçinde hem ağ soketi okuyor, hem regex ile IP ayıklıyor, hem veritabanına bağlanıyor, hem de tehdit skoru hesaplıyor. Bu fonksiyonun içinde bir mantıksal açık çıktığında, onu birim testle yakalayamazsın. Hangi satırın hangi yan etkiyi ürettiğini izleyemezsin.

Temiz kod (Clean Code) ve fonksiyonel disiplin; kodumuzu küçük, tek bir işi mükemmel yapan, girdi-çıktı sözleşmesi katı olarak tanımlanmış, dış dünyada kontrolsüz yan etki bırakmayan yapı taşlarına bölmektir. Bir güvenlik aracı ne kadar modüler ve temiz yazılmışsa, saldırganın o aracı atlatabileceği kör noktalar o kadar sıfıra yaklaşır.

---

## 2. DEĞİŞTİRİLEBİLİR VARSAYILAN ARGÜMAN TUZAĞI (MUTABLE DEFAULT ARGUMENT TRAP - CWE-670)

Python'da fonksiyonlar birinci sınıf nesnelerdir (first-class citizens) ve fonksiyon tanımlandığı anda (derleme/yükleme zamanında) argümanların varsayılan değerleri bir kez bellekte oluşturulur. Eğer varsayılan argüman olarak değiştirilebilir (mutable) bir veri tipi (`list`, `dict`, `set`) kullanılırsa, o nesne tüm fonksiyon çağrıları arasında **ortak paylaşılan tek bir bellek adresine** işaret eder.

### Güvensiz Anti-Pattern (Kritik Çok Kiracılı Veri Sızıntısı):
```python
# ❌ KESİNLİKLE YASAK / ÇOK TEHLİKELİ
def audit_security_event(raw_event: str, tags: list = []):
    tags.append("audited")
    return {"event": raw_event, "tags": tags}

# Birinci çağrı (Müşteri A):
res_a = audit_security_event("LOGIN_FAIL_USER_ALICE")
# res_a['tags'] -> ['audited']

# İkinci çağrı (Müşteri B - etiket belirtmiyor):
res_b = audit_security_event("LOGIN_FAIL_USER_BOB")
# Eğer Müşteri A kendi çağrısına özel gizli bir etiket eklediyse:
res_a['tags'].append("TENANT_A_CONFIDENTIAL_IP")

# Üçüncü çağrı (Müşteri C):
res_c = audit_security_event("LOGIN_FAIL_USER_CHARLIE")
# res_c['tags'] -> ['audited', 'TENANT_A_CONFIDENTIAL_IP', 'audited']
# 💥 FELAKET: Müşteri A'nın gizli verisi Müşteri C'ye sızdı! (CWE-670 / CWE-200)
```

### Savunmacı ve Güvenli Tasarım (None İle Güvenli Başlatma):
```python
# ✅ USTANIN YÖNTEMİ: None ve Yerel İzole Liste
def audit_security_event(raw_event: str, tags: list[str] | None = None) -> dict:
    # 1. Varsayılan durum bağımsız yerel kapsamda çözülür
    if tags is None:
        resolved_tags = []
    else:
        # Dışarıdan liste geldiyse bile referansını bozmamak için kopyası alınır
        resolved_tags = list(tags)
        
    resolved_tags.append("audited")
    return {"event": raw_event, "tags": resolved_tags}
```

Bu yöntemle her çağrı kendi izole bellek alanında yaşar; bellek sızıntısı ve çapraz kiracı kirlenmesi donanımsal düzeyde engellenir.

---

## 3. SAF FONKSİYONLAR (PURE FUNCTIONS): DETERMINİZM VE SIFIR YAN ETKİ

Bir fonksiyonun **Saf (Pure)** kabul edilebilmesi için iki temel şartı sağlaması gerekir:
1. **Determinizm:** Aynı girdiler verildiğinde daima ve istisnasız olarak aynı çıktıyı üretmelidir.
2. **Sıfır Yan Etki (No Side-Effects):** Fonksiyon kapsamı dışındaki hiçbir değişkeni (global değişkenler, dosya sistemi, ağ soketi, veritabanı veya parametre olarak gelen nesneler) değiştirmemelidir.

### Neden Siber Güvenlikte Saf Fonksiyonlar Hayatidir?
- **Paralel ve Dağıtık Tehdit Puanlama:** Bir SIEM veya IPS sistemi saniyede 100.000 log işlerken çoklu iş parçacığı (multi-threading) veya çoklu işlemci (multiprocessing) kullanır. Saf fonksiyonlar paylaşılan durum (shared state) veya yarış durumu (race condition) üretmediği için kilit mekanizmalarına (mutex/lock) ihtiyaç duymadan paralel koşturulabilir.
- **Tekrarlanabilir Adli Bilişim (Digital Forensics):** Bir olayın adli analizinde kullanılan skorlama algoritması saf ise, olaydan 2 yıl sonra bile aynı log verildiğinde mahkemeye sunulabilecek birebir aynı adli puanı üretir.

```python
# ✅ SAF TEHDİT SKORLAMA FONKSİYONU
def pure_calculate_threat_score(factors: dict[str, float]) -> float:
    """
    Saf Fonksiyon: Global durum yok, I/O yok, girdi mutasyonu yok.
    """
    if not factors:
        return 0.0
    total = sum(factors.values())
    return round((total / len(factors)) * 100.0, 2)
```

---

## 4. TEK SORUMLULUK İLKESİ (SINGLE RESPONSIBILITY PRINCIPLE - SRP) VE MODÜLER BORU HATLARI

Bir fonksiyon yalnızca **tek bir işi** yapmalı ve o işi eksiksiz yapmalıdır. Bir fonksiyonun birden fazla nedeni değiştirmek için gerekçesi varsa, o fonksiyon bölünmelidir.

Güvenlik boru hattında monolitik yapıyı kırmak için uyguladığımız SRP mimarisi:

```
split_and_validate_ioc_pipeline(raw_log)
  │
  ├── 1. _extract_ip_token(raw_log)       --> Sadece metinden IP dizesini çeker.
  ├── 2. _validate_ipv4_format(ip_str)    --> Sadece IPv4 sözdizimini doğrular.
  ├── 3. _classify_ip_zone(ip_str)        --> Sadece ağ bölgesini sınıflandırır.
  └── 4. _build_security_audit_record()   --> Sadece nihai denetim sözlüğünü kurar.
```

### SRP'nin Güvenlik Kazanımı:
Eğer saldırgan geçersiz bir IP enjekte ederse, hata `_validate_ipv4_format` adımında izole edilir. Ağ sınıflandırma algoritması hiç çağrılmaz. Kodun hangi noktasında neyin bozulduğunu 0.001 saniyede kesin olarak tespit edebilirsiniz.

---

## 5. DEĞİŞMEZLİK (IMMUTABILITY) VE SAVUNMACI KOPYALAMA (DEFENSIVE COPYING)

Python'da sözlükler (`dict`) referans yoluyla fonksiyona iletilir. Eğer bir fonksiyon aldığı parametre üzerinde `rule["status"] = "ACTIVE"` gibi bir değişiklik yaparsa, çağıran yerdeki orijinal kural tablosu da değişir. Bu durum, arka planda çalışan güvenlik politikalarının dinamik olarak bozulmasına (Policy Corruption) yol açar.

### Savunmacı Kopyalama Deseni:
```python
import copy

def immutable_rule_sanitizer(rule_def: dict) -> dict:
    """
    Orijinal nesneyi asla değiştirmez; derin kopya alarak normalize eder.
    """
    # Derin savunmacı kopya (Deep Defensive Copy)
    sanitized_rule = copy.deepcopy(rule_def)
    
    # Normalizasyon yalnızca yeni kopya üzerinde icra edilir
    sanitized_rule["aksiyon"] = sanitized_rule["aksiyon"].upper()
    sanitized_rule["is_sanitized"] = True
    
    return sanitized_rule
```

---

## 6. SÖZLEŞMEYE DAYALI TASARIM (DESIGN BY CONTRACT - DbC)

Sözleşmeye dayalı tasarımda bir fonksiyon, çağıran taraf ile imzalanmış yasal bir sözleşme gibi davranır:
1. **Ön Koşullar (Preconditions):** Fonksiyon çalışmaya başlamadan önce girdilerin sağlaması gereken asgari güvenlik şartlarıdır. Şart sağlanmazsa fonksiyon derhal istisna fırlatır (Fail-Fast).
2. **Son Koşullar (Postconditions):** Fonksiyon tamamlandığında ürettiği çıktının sağlamayı taahhüt ettiği güvenlik nitelikleridir.
3. **Değişmezler (Invariants):** Fonksiyonun icrası boyunca sistemin değişmemesi garanti edilen çekirdek durumudur.

### Hash Arama Motorunda DbC Örneği:
- **Ön Koşul 1:** Algoritma yalnızca `{"md5", "sha1", "sha256"}` kümesinde olmalıdır.
- **Ön Koşul 2:** Hash dizesi sadece onaltılık (hexadecimal) karakterler içermelidir.
- **Ön Koşul 3:** Dize uzunluğu tam olarak algoritmanın bit uzunluğuna uymalıdır (MD5=32, SHA1=40, SHA256=64).
- **Son Koşul:** Dönen kararın (`verdict`) kesinlikle `{"CONFIRMED", "UNVERIFIED", "REJECTED"}` kümesinde olduğu garanti edilir.

---

## 7. USTANIN ÇIRAĞA ÖĞÜTLERİ VE ALTIN KURALLAR

1. **Hiçbir Zaman Değiştirilebilir Nesneyi Varsayılan Yapma:** Fonksiyon imzasında asla `tags=[]` veya `config={}` yazma. Her zaman `None` kullan ve içeride yeni liste oluştur.
2. **Fonksiyon Boyunu 30 Satırın Altında Tut:** Bir güvenlik fonksiyonu ekrana sığmıyorsa ve kaydırma çubuğu gerektiriyorsa, içinde gizli bir güvenlik açığı barındırma olasılığı %80'dir.
3. **Tip İpuçlarını (Type Annotations) Eksiksiz Yaz:** `def inspect(data: bytes, timeout: int = 5) -> SecurityVerdict:` şeklinde tip sözleşmesini açık tut.
4. **Girdi Sözlüklerini Asla Yerinde (In-Place) Değiştirme:** Çağıranın kural tablosunu bozarsan, bütün güvenlik duvarı felç olur. Savunmacı kopyalama (`copy.deepcopy`) kullan.
5. **Önce Hata Durumlarını Ele Al (Guard Clauses):** İç içe 5 kat `if` açmak yerine, geçersiz durumlarda hemen `raise` veya `return` ile çık. Kodun okunabilirliği güvenliğin temelidir.
