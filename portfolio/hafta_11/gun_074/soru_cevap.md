# GÜN 074: FONKSİYONLAR VE TEMİZ KOD — SORU & CEVAP VE TEKNİK ANALİZ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

### G074-SC1: Değiştirilebilir Varsayılan Argüman Tuzağı (CWE-670) ve Çok Kiracılı (Multi-Tenant) Güvenlik Sistemlerinde Çapraz Veri Sızıntısı

#### Soru Başlığı ve Tanımı
Python'da bir fonksiyon tanımlanırken `def audit_log(event, metadata={}):` veya `def tag_packet(pkt, flags=[]):` şeklinde değiştirilebilir (mutable) bir veri yapısının varsayılan değer olarak atanması ne gibi bir mekanik çalışma üretir? Çok kullanıcılı bir SaaS güvenlik platformunda veya merkezi bir SIEM ayrıştırıcısında bu durum nasıl kritik bir veri sızıntısına (CWE-670: Use of Inherently Dangerous Function / CWE-200: Exposure of Sensitive Information) yol açar?

#### Derinlemesine Teknik Analiz
Python yorumlayıcısı bir fonksiyon tanımıyla (`def` ifadesiyle) karşılaştığında, o fonksiyon için bir fonksiyon nesnesi (`function object`) oluşturur. Fonksiyonun varsayılan argümanları (default arguments), fonksiyon **her çağrıldığında yeniden hesaplanmaz**; fonksiyon ilk tanımlandığı anda (modül yükleme / parse aşamasında) bir kez oluşturulur ve fonksiyon nesnesinin `__defaults__` (veya keyword-only ise `__kwdefaults__`) niteliğinde bir tuple olarak saklanır.

Eğer bu varsayılan nesne değiştirilebilir (`list`, `dict`, `set`) bir tip ise:
1. İlk kullanıcı fonksiyonu varsayılan parametre ile çağırdığında bu ortak bellek alanına işaret eden referansı alır.
2. Fonksiyon gövdesi içinde bu nesneye bir eleman eklendiğinde (`flags.append(...)`), doğrudan `__defaults__` içindeki paylaşılan tek nesne mutate edilir (değiştirilir).
3. İkinci bir kullanıcı veya tamamen bağımsız bir oturum fonksiyonu çağırdığında, boş bir liste yerine ilk çağrının değiştirdiği listeyi devralır.

**Siber Güvenlik Açısından Sonuç:**
Çok kiracılı (multi-tenant) bir bulut güvenlik duvarında, A firmasının incelenen paketine eklenen `"TENANT_A_INTERNAL_IP: 10.200.1.5"` etiketi, hemen ardından gelen B firmasının paket analiz sonucuna sızar. Bu durum yetkisiz bilgi ifşası (Information Disclosure), oturum zehirlenmesi ve erişim kontrolü atlatma açıklarına zemin hazırlar.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir MSSP (Managed Security Service Provider) firması, müşterilerinden gelen olayları zenginleştiren bir Python mikroservisi çalıştırmaktadır. Kod şu şekilde yazılmıştır:

```python
# GÜVENSİZ KOD:
def enrich_alert(alert_id: str, tags: list = []):
    tags.append(f"processed_at_{time.time()}")
    return {"id": alert_id, "tags": tags}
```

Servis birkaç saat çalıştıktan sonra, Banka X'e ait bir güvenlik alarmı raporunda Hastane Y'nin gizli hasta veritabanı IP etiketleri görünmüş ve regülasyon denetçileri sistemi derhal durdurmuştur.

**Savunmacı ve Güvenli Tasarım Çözümü:**
Varsayılan argüman olarak her zaman değişmez (`immutable`) olan `None` değeri kullanılmalı, fonksiyon gövdesinde ise koruma kontrolü (`guard clause`) ile yeni ve izole bir nesne örneği oluşturulmalıdır:

```python
# GÜVENLİ VE SAVUNMACI KOD:
def enrich_alert(alert_id: str, tags: list[str] | None = None) -> dict:
    # 1. Varsayılan durum bağımsız olarak başlatılır
    if tags is None:
        resolved_tags: list[str] = []
    else:
        # Çağıranın referansını korumak için kopyalama yapılır
        resolved_tags = list(tags)
        
    resolved_tags.append(f"processed_at_{time.time()}")
    return {"id": alert_id, "tags": resolved_tags}
```

Bu modelde her çağrı kendine ait taze bir liste oluşturur; çapraz kiracı bellek kirlenmesi imkansız hale gelir.

#### Ustanın Çırağa Tavsiyesi
> "Evlat, fonksiyon imzasında gördüğün her `[]` ve `{}` pimi çekilmiş bir el bombasıdır! Fonksiyon parametresine asla ama asla mutable nesne yazmayacaksın. Kural basittir: İmzaya `None` yaz, gövdede `if tags is None: tags = []` de. Bu iki satırlık alışkanlık seni yüz binlerce dolarlık veri sızıntısı davalarından ve itibar kaybından kurtarır!"

---

### G074-SC2: Saf Fonksiyonların (Pure Functions) Siber Tehdit Puanlaması ve Adli Bilişimdeki Hayati Önemi

#### Soru Başlığı ve Tanımı
Fonksiyonel programlamanın temel kavramlarından biri olan "Saf Fonksiyon" (Pure Function) nedir? Bir tehdit puanlama motorunda veya adli bilişim (digital forensics) kanıt inceleme hattında saf fonksiyon kullanmak; determinizm, yarış durumları (race conditions) ve adli tekrar üretilebilirlik (reproducibility) açısından ne tür güvenlik garantileri sağlar?

#### Derinlemesine Teknik Analiz
Bir fonksiyonun matematiksel anlamda "Saf" (Pure) sayılabilmesi için şu iki temel şartı eksiksiz karşılaması zorunludur:
1. **Aynı Girdiye Daima Aynı Çıktı (Determinizm):** Fonksiyon, gizli bir dış durumdan (`global` değişkenler, sistem saati, rastgele sayı üreteci, ortam değişkenleri) beslenmez. Girdileri $X$ ise, çıktı daima $f(X)$ olur.
2. **Sıfır Yan Etki (No Side-Effects):** Fonksiyon kendi kapsamı dışındaki hiçbir varlığı değiştirmez. Dosya yazmaz, ağ soketine veri göndermez, veritabanını güncellemez ve kendisine argüman olarak iletilen nesnelerin bellekteki durumunu mutasyona uğratmaz.

**Siber Güvenlikteki Üç Büyük Kazanımı:**

1. **Adli Bilişimde Yasal Kanıt Güvencesi (Forensic Reproducibility):** Bir siber saldırı sonrası toplanan loglar mahkemeye sunulduğunda, savunma makamı analistin raporuna itiraz edebilir. Eğer tehdit skoru hesaplayıcı fonksiyon saf ise, olaydan aylar sonra bağımsız bir bilirkişi aynı logları aynı fonksiyona verdiğinde kuruşu kuruşuna aynı tehdit skorunu elde eder. Sistem saati veya ortam değişkeni gibi yan etkiler adli kanıtın geçerliliğini zedeleyemez.
2. **Yarış Durumlarının (Race Conditions) Önlenmesi:** Yüksek hacimli paket analizlerinde (saniyede yüz binlerce ağ akışı) fonksiyonlar birden fazla thread veya worker process tarafından paralel koşturulur. Saf fonksiyonlar paylaşılan bir durumu (shared state) okuyup yazmadığı için bellek kilitleme mekanizmalarına (`threading.Lock`) ihtiyaç duymaz. Kilit çekişmesi (lock contention) ve deadlock riskleri ortadan kalkar.
3. **Önbellekleme ve Performans (Memoization):** Fonksiyon saf olduğu için, belirli bir IP veya dosya karmasının sonucu bellekte güvenle önbelleklenebilir. Girdi aynı kaldığı sürece hesaplama tekrar yapılmadan $O(1)$ sürede sonuç döndürülür.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir SIEM analisti, IP itibar puanını hesaplayan bir fonksiyon yazmıştır:

```python
# GÜVENSİZ VE YAN ETKİLİ (IMPURE) KOD:
global_multiplier = 1.2

def calculate_ip_risk(ip_reputation: dict) -> float:
    global global_multiplier
    # Yan etki 1: Dışarıdaki global çarpanı dinamik değiştiriyor!
    if ip_reputation.get("is_tor"):
        global_multiplier += 0.5
    # Yan etki 2: Parametre olarak gelen sözlüğü mutasyona uğratıyor!
    ip_reputation["calculated"] = True
    return ip_reputation["score"] * global_multiplier
```

Bu fonksiyon çoklu thread ile çalıştırıldığında `global_multiplier` kontrolsüz şekilde şişmiş, masum Google DNS IP'si dahi bir süre sonra 999.0 risk puanı alarak tüm iç ağın internet erişimini kesmiştir.

**Savunmacı ve Saf Fonksiyon Çözümü:**
```python
# GÜVENLİ VE SAF (PURE) FONKSİYON:
def pure_calculate_ip_risk(reputation_factors: dict[str, float]) -> float:
    """
    Saf Fonksiyon: Global durum yok, girdi mutasyonu yok, deterministik hesaplama.
    """
    if not reputation_factors:
        return 0.0
    
    # Girdi üzerinde değişiklik yapılmaz, yerel ağırlık hesabı yapılır
    weights = {"c2": 0.4, "tor": 0.3, "spam": 0.3}
    weighted_score = sum(
        reputation_factors.get(k, 0.0) * w for k, w in weights.items()
    )
    return round(weighted_score * 100.0, 2)
```

#### Ustanın Çırağa Tavsiyesi
> "Çırak! Bir güvenlik fonksiyonunun içine 'global' kelimesini yazıyorsan, kendi ayağına kurşun sıkıyorsun demektir. Güvenlik yazılımında matematik gibi olacaksın: $2 + 2$ her zaman 4 eder, dün de 4'tü, yarın da 4 olacak, arkadan rüzgar esse de 4 olacak! Fonksiyonun saf olsun ki, mahkeme salonunda savcıya rapor verirken başın dik dursun!"

---

### G074-SC3: Sözleşmeye Dayalı Tasarım (Design by Contract - DbC) ile Giriş ve Karar Bütünlüğünün Korunması

#### Soru Başlığı ve Tanımı
Sözleşmeye Dayalı Tasarım (Design by Contract - DbC) prensibi; Ön Koşullar (Preconditions), Son Koşullar (Postconditions) ve Değişmezler (Invariants) kavramları üzerine kuruludur. Siber tehdit istihbaratı (IoC) veya kriptografik özet (hash) doğrulama süreçlerinde DbC mimarisi, mantıksal enjeksiyon ve güvenlik kararı bozulmalarına karşı nasıl bir savunma sağlar?

#### Derinlemesine Teknik Analiz
Geleneksel yazılım geliştirmede fonksiyonlar girdilerin makul ölçüde doğru olduğunu varsayar ve sadece ana iş mantığına odaklanır. Savunmacı siber güvenlik yazılımlarında ise her fonksiyon çağıran taraf ile bir **güvenlik sözleşmesi** imzalar:

1. **Ön Koşullar (Preconditions - Giriş Güvenliği):** Fonksiyonun çalışmayı kabul etmesi için girdinin sağlaması gereken katı teknik şartlardır.
   - Örnek: `algorithm` parametresi kesinlikle `{"md5", "sha1", "sha256"}` kümesinde olmalıdır.
   - Örnek: `hash_str` yalnızca geçerli hex karakterlerden (`[0-9a-f]`) oluşmalı ve uzunluğu algoritmanın beklenen karakter uzunluğuna (SHA-256 için 64) tam eşit olmalıdır.
   - Bu koşullar sağlanmazsa fonksiyon hiçbir iş yapmadan derhal (Fail-Fast) istisna fırlatır. Böylece malforme verinin sistemin daha derin katmanlarına sızması sınırda engellenir.
2. **Son Koşullar (Postconditions - Karar Bütünlüğü):** Fonksiyonun işini bitirdiğinde çağıran tarafa teslim etmeyi taahhüt ettiği güvenlik garantileridir.
   - Örnek: Fonksiyonun döndürdüğü `verdict` alanı rastgele veya beklenmeyen bir metin olamaz; kesinlikle `{"CONFIRMED", "UNVERIFIED", "REJECTED"}` kümesinde yer almalıdır.
   - Eğer dahili bir algoritma hatası veya beklenmeyen bir durum sebebiyle karar bu kümenin dışına çıkarsa, fonksiyon yanlış veya bozuk bir kararı sisteme yaymak yerine son koşul denetiminde patlar ve alarm üretir.
3. **Değişmezler (Invariants - Durum Bütünlüğü):** Fonksiyonun çalışması öncesinde ve sonrasında sistemin veya nesnenin korumayı taahhüt ettiği değişmez kurallardır (örneğin kural sayacının asla negatif olamaması).

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir Tehdit Avcılığı (Threat Hunting) platformunda, analistler dosya hash'lerini girerek virüs veritabanında arama yapmaktadır. Bir saldırgan web arayüzünden `sha256` seçip hash alanına 500 baytlık bir SQL Injection / buffer payload'u göndermiştir. Ayrıştırıcı fonksiyon ön koşul denetimi yapmadığı için bu payload doğrudan arka uçtaki C kütüphanesine veya SQL sorgusuna geçmiş ve bellek taşması / enjeksiyon gerçekleşmiştir.

**DbC ile Korunan Savunmacı Fonksiyon:**
```python
class ThreatIntelligenceLookup:
    ALLOWED_ALGOS = {"md5": 32, "sha1": 40, "sha256": 64}
    VALID_VERDICTS = {"CONFIRMED", "UNVERIFIED", "REJECTED"}
    
    def lookup_hash(self, hash_str: str, algo: str = "sha256") -> dict:
        algo_clean = algo.lower().strip()
        
        # [ÖN KOŞUL 1]: Algoritma yetki denetimi
        if algo_clean not in self.ALLOWED_ALGOS:
            raise ValueError(f"Sözleşme İhlali: Geçersiz algoritma {algo}")
            
        # [ÖN KOŞUL 2]: Tip ve uzunluk sözleşmesi
        expected_len = self.ALLOWED_ALGOS[algo_clean]
        hash_clean = hash_str.lower().strip()
        if len(hash_clean) != expected_len:
            raise ValueError(f"Sözleşme İhlali: {algo_clean} için beklenen uzunluk {expected_len}")
            
        # [ÖN KOŞUL 3]: Karakter kümesi sözleşmesi
        if not all(c in "0123456789abcdef" for c in hash_clean):
            raise ValueError("Sözleşme İhlali: Hexadecimal olmayan zararlı girdi!")
            
        # İş mantığı çalışır...
        verdict = self._internal_db_query(hash_clean)
        
        # [SON KOŞUL]: Üretilen güvenlik kararının doğrulanması
        if verdict not in self.VALID_VERDICTS:
            raise SystemError(f"Sözleşme İhlali: Fonksiyon geçersiz bir karar üretti: {verdict}")
            
        return {"hash": hash_clean, "verdict": verdict}
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, güvenlik yazılımında 'varsaymak' intihardır. Her fonksiyon bir kale kapısıdır. Kapıdan giren her parametrenin pasaportunu (ön koşullarını) sınırda kontrol edeceksin. Kapıdan çıkan her kararın da kurumun mührünü (son koşullarını) taşıdığını garanti edeceksin. Sözleşmeye uymayanı içeri de sokmayacaksın, dışarı da bırakmayacaksın!"
