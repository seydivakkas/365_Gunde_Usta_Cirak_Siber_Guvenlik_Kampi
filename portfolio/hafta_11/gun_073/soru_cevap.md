# GÜN 073: KOŞULLAR VE DÖNGÜLER — SORU & CEVAP VE TEKNİK ANALİZ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

### G073-SC1: Python'da `for ... else` ve `while ... else` Mantığı ile Savunmacı (Fail-Closed) Güvenlik Doğrulaması

#### Soru Başlığı ve Tanımı
Geleneksel programlama dillerinde döngü yapıları (`for`, `while`) yalnızca koşul sağlandığı sürece iterasyon gerçekleştirirken, Python'da döngülerin opsiyonel bir `else` bloğu bulunmaktadır. Bir siber güvenlik kural motorunda veya tehdit istihbaratı (IoC) tarayıcısında `for ... else` yapısı ne anlama gelir ve bu yapı "Varsayılan Olarak Engelle" (Fail-Closed) ilkesi doğrultusunda güvenli akış inşasında nasıl bir rol oynar?

#### Derinlemesine Teknik Analiz
Python'da bir `for` veya `while` döngüsüne bağlı `else` bloğu, döngü bir `break` ifadesi ile **kesintiye uğramadan** normal akışıyla tükenip bittiğinde (yani iterable nesne tükendiğinde veya while koşulu `False` olduğunda) çalışır. Eğer döngü gövdesi içerisinden bir `break` ile erken çıkış yapılırsa, `else` bloğu tamamen atlanır.

Siber savunma mimarisinde bu mekanizma şu iki kritik desende hayati bir garanti sunar:

1. **Tehdit Arama ve Temiz Onayı (Certify Clean):** Bir paket veya log akışında zararlı imza (IoC) aranıyorsa, bulunan ilk tehditte `break` çalıştırılarak alarm üretilir. Eğer döngü tüm akışı tarayıp hiçbir imza ile eşleşmeden tamamlarsa, `else` bloğu devreye girer. Bu blok, "Tüm veri seti başarıyla tarandı ve hiçbir zararlı desen bulunamadı" durumunu açıkça ve bayrak (flag) değişkenlerine (`found = False`) gerek kalmadan, doğrudan dilin çalışma mantığıyla güvenceye alır.
2. **Güvenlik Duvarı Kural Eşleşmesi ve Varsayılan Düşürme (Default Deny / Fail-Closed):** Gelen bir ağ paketi öncelik sırasına göre sıralanmış kurallar (`rules`) boyunca test edilir. Herhangi bir kural ile eşleşme sağlandığında paket için ilgili aksiyon (`ALLOW` / `DROP`) belirlenir ve döngü `break` edilir. Eğer kurallar kümesinde hiçbir eşleşme bulunamazsa (yani döngü `break` olmadan tükenirse), döngünün `else` bloğu çalışır ve paketi otomatik olarak varsayılan katı politikaya (`DENY` / `DROP`) yönlendirir. Bu, yapılandırma hataları veya eksik kurallar durumunda sistemin asla "açıkta" (fail-open) kalmamasını donanımsal düzeyde sağlar.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurumun Ağ Saldırı Tespit Sistemi (NIDS), gelen her HTTP isteğini bilinen 10.000 SQL Injection deseni ile test etmektedir. Yazılımcı `matched = False` bayrağı kullanarak kod yazmış, fakat döngü içindeki karmaşık `try/except` blokları sırasında beklenmeyen bir `continue` veya exception atlaması sebebiyle bayrak güncellenememiş ve saldırı içeren paket ağdan içeri sızmıştır.

Bunun yerine savunmacı `for ... else` yapısı ile mimari kurulur:

```python
def inspect_payload_against_signatures(payload: str, signatures: list[str]) -> dict:
    """
    Tüm imzaları ardışık olarak denetler; eşleşme anında alarm verir,
    tamamlandığında ise 'else' bloğu ile güvenli olduğunu onaylar.
    """
    for sig in signatures:
        if sig in payload:
            # Zararlı içerik tespit edildi, akış derhal kırılır
            return {"status": "BLOCKED", "matched_signature": sig}
    else:
        # Döngü kesintiye uğramadan bitti, kesinlikle temiz
        return {"status": "ALLOWED", "matched_signature": None}
```

Bu çözümde hiçbir aracı durum bayrağına (`flag`) ihtiyaç duyulmaz; döngü kendi durumunu (`exhaustion`) kendisi yönetir.

#### Ustanın Çırağa Tavsiyesi
> "Evlat, güvenlik yazılımında bayrak değişkenleri (flag variables) ne kadar çoğalırsa, insan hatası ve mantıksal yarış durumu (race condition) o kadar artar. Python'ın `for ... else` yapısı, çırakların ilk başta ters anladığı ('break olunca else çalışır sanılan') ama ustaların fail-closed güvenlik mimarilerinde imza gibi kullandığı bir mücevherdir. Kural motorlarında eşleşmeyen her durumun varsayılan olarak `DENY` düşmesini döngünün `else` bloğuna emanet et; böylece kurallar tükense dahi kapı daima kapalı kalır!"

---

### G073-SC2: Döngülerde Hizmet Dışı Bırakma (DoS / CWE-835) Tehdidi ve Sıkıştırma İşaretçi Döngülerinin Savunması

#### Soru Başlığı ve Tanımı
Ağ protokolü ayrıştırıcılarında (örn. DNS isim çözümleme, TAR/ZIP arşiv açma veya BGP yönlendirme tabloları) işaretçi (pointer/offset) atlama döngüleri sıkça kullanılır. Kötü niyetli bir saldırgan tarafından hazırlanan döngüsel (cyclic) bir paket başlığı yazılımı nasıl sonsuz döngüye (CWE-835: Loop with Unreachable Exit Condition / CPU DoS) sokabilir ve savunmacı programlamada bu durum hangi tekniklerle engellenir?

#### Derinlemesine Teknik Analiz
DNS (RFC 1035) mesajlarında alan adı sıkıştırması (Name Compression) kullanılır. Bir etiket (label) iki baytlık bir işaretçi (`0xC000` maskesi) içerdiğinde, çözümleyici bu işaretçinin gösterdiği bellek ofsetine atlayarak alan adının geri kalanını oradan okur.

Saldırgan şu yapıda kötü niyetli bir DNS paketi hazırlar:
- Ofset `0x20`: Ofset `0x30`'u işaret eden bir sıkıştırma işaretçisi (`0xC030`).
- Ofset `0x30`: Tekrar ofset `0x20`'yi işaret eden bir sıkıştırma işaretçisi (`0xC020`).

Savunmasız bir ayrıştırıcı aşağıdaki gibi naif bir `while` döngüsü çalıştırır:
```python
# GÜVENSİZ: Sonsuz döngü ve %100 CPU tükenmesi (CWE-835)
offset = start_offset
while offset != 0:
    offset = read_pointer(packet_bytes, offset)
```
Bu döngü $0x20 \to 0x30 \to 0x20 \to 0x30 \dots$ şeklinde sonsuza kadar döner. İş parçacığı (thread) tek çekirdeği %100 yük altına sokar, bellek taşabilir veya ayrıştırıcı servis tamamen çöker.

**Savunmacı Programlama Çözümü (İkili Bariyer İlkesi):**
1. **Ziyaret Edilen Ofsetler Kümesi (`visited_offsets = set()`):** Döngü her atlama yaptığında hedef ofset `visited_offsets` kümesinde aranır. $O(1)$ karmaşıklıkla yapılan bu aramada ofset daha önce görülmüşse döngüsel işaretçi saldırısı (`CYCLIC_POINTER_LOOP`) anında tespit edilir ve işlem iptal edilir.
2. **Sert İterasyon Sınırı (`max_iterations = 1000`):** Saldırgan ardışık olarak binlerce meşru işaretçi zincirleyerek CPU süresini tüketmeye çalışabilir. Döngü sayacı belirlenen üst sınırı aştığında (`EXCEEDED_MAX_ITERATIONS`) işlem zorla durdurulur.
3. **Sınır Dışı Bellek Denetimi (Out-of-Bounds Check):** İşaretçinin gösterdiği ofsetin paket boyutundan (`len(data)`) küçük olduğu her iterasyonda doğrulanır.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir SOC merkezinde çalışan log ve paket ayrıştırıcı motor, bilinmeyen bir kaynaktan gelen malforme DNS paketlerini ayrıştırırken çökmüş ve arka plandaki tüm kuyruk kilitlenmiştir. Yapılan kök neden analizinde saldırganın 64 baytlık küçük bir UDP paketi ile bellek içi döngüsel işaretçi enjekte ettiği saptanmıştır.

Savunmacı motor implementasyonu:

```python
def safe_parse_pointer_chain(data: bytes, initial_offset: int, max_depth: int = 64) -> list[int]:
    """
    Ziyaret kümesi ve derinlik limiti ile döngüsel DoS saldırılarını engelleyen güvenli ayrıştırıcı.
    """
    visited = set()
    chain = []
    curr = initial_offset
    
    for _ in range(max_depth):
        if curr in visited:
            raise ValueError(f"Döngüsel işaretçi (cyclic loop) tespit edildi! Ofset: {curr}")
        if curr < 0 or curr >= len(data):
            raise IndexError("Paket sınırları dışına taşan işaretçi!")
        if curr == 0:  # Sonlandırıcı bayt
            break
            
        visited.add(curr)
        chain.append(curr)
        curr = data[curr] # Bir sonraki ofset
    else:
        raise OverflowError("Maksimum atlama derinliği aşıldı; DoS girişimi şüphesi!")
        
    return chain
```

#### Ustanın Çırağa Tavsiyesi
> "Çırak! Ağdan veya kullanıcıdan gelen hiçbir girdiye güvenerek ucu açık `while True` döngüsü başlatma. Her `while` döngüsünün arkasına mutlaka bir 'bekçi sayacı' (`iteration_counter`), ziyaret kümesi (`visited_set`) ve sert bir zaman/adım aşımı sınırı (`timeout / max_iterations`) koyacaksın. Bir saldırgan için en tatlı zafiyet, tek bir 50 baytlık paketle senin koca sunucunun CPU'sunu %100'e kitlemektir!"

---

### G073-SC3: Mantıksal Kısa Devre (Short-Circuit) Operatörleri ve Güvenlik Duvarı Kural Motorlarında Yan Etki (Side-Effect) Riskleri

#### Soru Başlığı ve Tanımı
Python'da mantıksal `and` ile `or` operatörleri kısa devre (short-circuit evaluation) mantığıyla çalışır. Çok katmanlı bir yetkilendirme veya paket denetim kural motorunda kısa devre değerlendirmesi performans açısından ne gibi avantajlar sağlar? Yan etki (side-effect) içeren fonksiyon çağrılarıyla birleştiğinde ne tür kritik güvenlik açıklarına yol açabilir?

#### Derinlemesine Teknik Analiz
Kısa devre değerlendirmesinde Python şu kuralı uygular:
- `A and B`: Eğer `A` ifadesi `False` ise, `B` ifadesi **asla çalıştırılmaz ve değerlendirilmez**, çünkü sonuç kesin olarak `False` olacaktır.
- `A or B`: Eğer `A` ifadesi `True` ise, `B` ifadesi **asla çalıştırılmaz ve değerlendirilmez**, çünkü sonuç kesin olarak `True` olacaktır.

**Güvenlik ve Performans Avantajı:**
Kural motorlarında kurallar maliyet ve seçicilik sırasına göre dizilmelidir:
1. Ucuz ve hızlı kontroller: Port numarası kontrolü (`packet.port == 443`), protokol kontrolü.
2. Pahalı kontroller: Regex analizi, bellek içi imza araması.
3. Çok pahalı kontroller: Veritabanı sorgusu, dış tehdit istihbaratı API çağrısı, şifreleme/hashing kontrolü.

`if is_port_matching(pkt) and verify_crypto_signature(pkt):` yazıldığında, port eşleşmiyorsa ikinci fonksiyon (ağır kriptografik doğrulama) hiç çağrılmaz. Bu, sistemin saniyede yüz binlerce paketi CPU darboğazına girmeden incelemesini sağlar.

**Yan Etki (Side-Effect) ve Güvenlik Zaafı:**
Eğer değerlendirilen ikinci fonksiyonda durum güncelleyen, log yazan, sayaç artıran veya oturum yenileyen bir yan etki (side-effect) bulunuyorsa, kısa devre mekanizması bu fonksiyonun çalışmasını engelleyebilir:

```python
# TEHLİKELİ MANTIK TASARIMI
if user.is_authenticated and log_access_attempt(user) and user.has_permission("ADMIN"):
    grant_access()
```
Eğer `user.is_authenticated` `False` ise, `log_access_attempt(user)` fonksiyonu **asla çalıştırılmaz**. Sonuç olarak SOC merkezinin denetim izinde (audit trail) bu başarısız yetkisiz giriş denemesi hiçbir zaman kaydedilmez; saldırgan iz bırakmadan parola denemeleri yapabilir!

Aynı şekilde `or` ifadesinde:
```python
# YETKİ AŞIMI / ATLATMA RİSKİ
if is_whitelisted_ip(ip) or check_mfa_token(token):
    allow_privileged_action()
```
Beyaz listedeki IP doğrulaması `True` döndüğünde MFA fonksiyonu çalıştırılmaz. IP sahteciliği (IP spoofing) yapabilen veya iç ağa sızmış bir saldırgan MFA bariyere takılmadan içeri geçer.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir API Gateway'de hız sınırlama (rate limiting) ve token geçerliliği tek bir koşul satırında test edilmektedir. Yazılımcı `if validate_token(t) and decrement_rate_limit(ip):` yazmıştır. Geçersiz token ile gelen milyonlarca istek ilk şartta `False` ürettiği için `decrement_rate_limit` çalışmamış, saldırganın IP'si sayaçlara takılmadan dakikalarca API'ye brute-force token tahmin isteği yağdırmıştır.

**Güvenli Tasarım Kuralı:**
Durum değiştiren veya log üreten operasyonlar mantıksal karşılaştırma ifadelerinin içine gömülmemeli, bağımsız adımlar olarak işletilmelidir:

```python
# GÜVENLİ TASARIM: Yan etkiler koşul satırından ayrıştırılmıştır
def process_request(ip: str, token: str) -> bool:
    # 1. Adım: Denetim ve sayaç yan etkileri kayıtsız şartsız yürütülür
    record_request_metric(ip)
    
    # 2. Adım: Hız sınırı bağımsız kontrol edilir
    if is_rate_limited(ip):
        log_security_alert("RATE_LIMIT_EXCEEDED", ip)
        return False
        
    # 3. Adım: Doğrulama kısa devre olmadan veya yan etkisiz saf fonksiyonlarla yapılır
    is_valid_token = check_token_signature_pure(token)
    if not is_valid_token:
        log_security_alert("INVALID_TOKEN", ip)
        return False
        
    return True
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, koşul satırları saf (pure) matematiksel sorgulamalar için vardır; orada veritabanı yazılmaz, log düşülmez, sayaç artırılmaz! Kısa devre optimizasyonu CPU'nu kurtarır ama içine gizli bir yan etki saklarsan güvenlik denetimini felç eder. Mantıksal `and`/`or` zincirinde önce en ucuz sorguyu başa koy, yan etkili kodları ise her zaman koşulun dışına, bağımsız bir satıra al!"
