# GÜN 082: PYTEST İLE BİRİM TESTLERİ — SORU VE CEVAPLAR
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## SORU 1 (G082-SC1): PYTEST PARAMETRİZASYONU VE SALDIRI MATRİSLERİ

### Soru Başlığı ve Tanımı
`pytest` çatısındaki `@pytest.mark.parametrize` mekanizması nedir? Siber güvenlik otomasyonunda ve savunmacı kod testlerinde, tek tek onlarca test fonksiyonu yazmak veya döngü kurmak yerine parametrik saldırı matrisi oluşturmanın mimari ve operasyonel üstünlükleri nelerdir?

### Derinlemesine Teknik Analiz
1. **Döngü Tabanlı Testin Tehlikesi:**
   Geliştirici bir test içinde `for payload in attack_payloads:` döngüsü kurup her birini `assert` ettiğinde; eğer 2. payload'da test patlarsa, döngü kırılır ve kalan 98 payload hiç test edilemez. Geliştirici sadece 1 hata görür, sistemin diğer 98 varyasyona karşı nasıl davrandığı karanlıkta kalır.
2. **`@pytest.mark.parametrize` Mekaniği:**
   `pytest`, parametre listesindeki her bir girdiyi bağımsız birer test senaryosu (test case) olarak ele alır:
   - Her senaryo için test motoru sıfırdan izole bir çağrı yığını oluşturur.
   - Biri başarısız olduğunda diğerleri koşmaya devam eder.
   - Rapor ekranında hangi girdinin (`[Kisa1!]`, `[Abc!1]`, `[11Karakter!]`) geçtiği ve hangisinin kaldığı net olarak listelenir.
3. **Güvenlik Matrisi Kapsamı:**
   Özellikle enjeksiyon (XSS, SQLi), parola karmaşıklığı veya alan adı doğrulama kurallarında; farklı karakter sınıflarının (büyük harf eksik, sembol eksik, boş girdi, aşırı uzun girdi) tek bir fonksiyon çatısı altında kapsamlı taranmasını sağlar.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir web uygulaması güvenlik duvarında (WAF), HTTP isteklerini süzen bir kural motoru geliştirilmiştir. Analist 20 farklı SQL Injection atlatma (bypass) tekniğini test etmek istemektedir.

**Pratik Çözüm (Parametrik pytest Matrisi):**
```python
import pytest

@pytest.mark.security
@pytest.mark.parametrize(
    "sqli_vector",
    [
        ("' OR 1=1 --"),
        ("' UNION SELECT null, username, password FROM users --"),
        ("admin' #"),
        ("1' AND SLEEP(5) --"),
        ("1; EXEC xp_cmdshell('calc') --")
    ]
)
def test_waf_sqli_detection_matrix(waf_engine, sqli_vector):
    # Her bir saldırı vektörünün WAF tarafından engellendiğini bağımsız doğruluyoruz
    with pytest.raises(SecurityViolationException, match="SQL_INJECTION_DETECTED"):
        waf_engine.inspect_query(sqli_vector)
```

### Ustanın Çırağa Tavsiyesi
Evladım, saldırgan tek bir kapıdan vurmaz; elindeki yüzlerce anahtarı sırayla dener. Sen de savunmanı test ederken tek bir örnekle yetinemezsin. Parametrize senin çok namlulu test tüfeğindir; tek tetiğe basarsın, sistemin tüm açıklarını aynı anda tararsın.

---

## SORU 2 (G082-SC2): PYTEST FİKSTÜRLERİ (FIXTURES) VE DURUM KİRLİLİĞİ (STATE POLLUTION)

### Soru Başlığı ve Tanımı
pytest fikstürleri (`@pytest.fixture`) nedir? Birim testlerde testlerin birbirinin çalışma alanına ve bellek durumuna müdahale etmesi (State Pollution / Leaky State) nasıl yanıltıcı başarılı (False Positive) veya hatalı başarısız (False Negative) sonuçlar üretir? Fikstürler bu durumu nasıl deterministik olarak engeller?

### Derinlemesine Teknik Analiz
1. **Durum Kirliliği (State Pollution) Tehlikesi:**
   Testler aynı küresel nesneyi (singleton, veritabanı bağlantısı veya sayaç sözlüğü) paylaştığında, önceki testin yaptığı değişiklikler sonraki testin başlangıç koşulunu bozar:
   - Örnek: Test 1, `198.51.100.1` IP'sinden 4 başarısız istek atar.
   - Test 2, aynı IP'den 1 istek atıp hız sınırını aşmadığını test etmek ister. Ancak önceki testten kalan sayaç yüzünden sistem anında kilitlenir ve Test 2 haksız yere patlar.
   - Ya da tam tersi: Bir test oturum açar, sonraki test yetkisiz girişi test ederken önceki testin açık oturumu yüzünden geçmemesi gereken test geçebilir (False Positive).
2. **pytest Fixture Çözümü:**
   `@pytest.fixture`, test fonksiyonuna parametre olarak enjekte edilen izole fabrikalardır:
   - Varsayılan olarak her test fonksiyonu çağrıldığında fikstür baştan sıfır olarak üretilir (`scope="function"`).
   - Test bittiğinde `yield` sonrasındaki kod çalışarak ortamı (açık dosyalar, geçici dizinler, bellek sayaçları) tertemiz siler.
   - Testler arasında hiçbir bellek artığı veya yan etki (side-effect) aktarılmaz.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir API geçidinde IP başına hız sınırlayıcı (Rate Limiter) test edilmektedir. Fikstür kullanılmadığında testler rastgele sıralandığında (pytest-random-order) testlerin bazen geçip bazen kaldığı (flaky test) gözlenmiştir.

**Pratik Çözüm (İzole Fixture ile Deterministik Test):**
```python
import pytest

@pytest.fixture
def clean_rate_limiter():
    # Her test için bağımsız ve sıfır sayaçlı hız sınırlayıcı başlat
    limiter = RateLimiter(max_requests=5)
    yield limiter
    # Test bitiminde temizlik garantisi
    limiter.reset_all_counters()

def test_single_request_allowed(clean_rate_limiter):
    assert clean_rate_limiter.allow_request("10.0.0.1") is True

def test_burst_request_blocked(clean_rate_limiter):
    for _ in range(5):
        clean_rate_limiter.allow_request("10.0.0.1")
    assert clean_rate_limiter.allow_request("10.0.0.1") is False
```

### Ustanın Çırağa Tavsiyesi
Çırağım, temiz olmayan laboratuvarda yapılan deneyin sonucu geçersizdir. Bir önceki deneyden kalan kimyasal tüpte dururken yeni deney yaparsan patlarsın. Testlerinin her biri steril bir ameliyathanede doğmalı, işini bitirince ardında tek bir çöp bırakmamalıdır.

---

## SORU 3 (G082-SC3): SINIR DEĞER ANALİZİ VE `pytest.raises` İLE HATA DOĞRULAMA

### Soru Başlığı ve Tanımı
Siber güvenlik kurallarında Sınır Değer Analizi (Boundary Value Analysis - BVA) neden en kritik test metodolojisidir? Bir fonksiyonun hata fırlattığını doğrulamak için `pytest.raises` kullanırken sadece istisna sınıfını değil, hata mesajını (`match`) regex ile denetlemenin bilgi ifşası (CWE-209) ve güvenlik açısından önemi nedir?

### Derinlemesine Teknik Analiz
1. **Sınır Değerlerin Kırılganlığı:**
   Geliştiriciler mantıksal operatörlerde en sık `<` ile `<=` veya `>` ile `>=` farkında hata yapar (Off-by-One Error).
   - Örneğin tehdit puanı `0-100` aralığında olmalıdır. Kritik sınırlar:
     - Alt sınır: `-1` (Yasak), `0` (Geçerli), `1` (Geçerli).
     - Aralık geçişi: `39` (LOW), `40` (MEDIUM), `69` (MEDIUM), `70` (HIGH), `89` (HIGH), `90` (CRITICAL).
     - Üst sınır: `99` (Geçerli), `100` (Geçerli), `101` (Yasak).
   - Saldırganlar güvenlik duvarı kurallarında, port filtrelerinde veya tampon boyutlarında daima bu sınır noktalarını hedefler.
2. **`pytest.raises` ve `match` Önemi:**
   Eğer sadece `with pytest.raises(PolicyViolationException):` yazarsan; fonksiyon bambaşka bir sebepten (örneğin tip hatasından veya beklenmeyen bir çökmeden) o istisnayı fırlatsa bile test "başarılı" sayılır.
   `match="Parola uzunluğu 12-64"` parametresi eklendiğinde; `pytest` fırlatılan istisnanın mesajını regex ile tarar. Böylece:
   - İstisnanın tam olarak beklenen güvenlik kontrolü tarafından üretildiği kesinleşir.
   - Hata mesajının dış istemciye dahili dosya yolları veya hassas sırlar sızdırmadığı doğrulanır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir güvenlik duvarı yazılımında port kontrolü `port < 65535` olarak kodlanmış, `<= 65535` unutulmuştur. Sonuç olarak 65535 portu (meşru bir port) geçersiz sayılarak sistem yöneticisinin hayati bir servisi engellenmiş ve servis kesintisi yaşanmıştır.

**Pratik Çözüm (Sınır Değer Testi ve Mesaj Kontrolü):**
```python
import pytest

@pytest.mark.parametrize("valid_boundary_port", [1, 80, 443, 65535])
def test_firewall_valid_boundary_ports(valid_boundary_port):
    assert evaluate_port(valid_boundary_port) is True

@pytest.mark.parametrize("invalid_boundary_port", [-1, 0, 65536, 70000])
def test_firewall_invalid_boundary_ports(invalid_boundary_port):
    with pytest.raises(PolicyViolationException, match="Hedef port 1-65535 aralığında"):
        evaluate_port(invalid_boundary_port)
```

### Ustanın Çırağa Tavsiyesi
Evladım, surun ortası kalın ve sağlamdır; düşman surun ortasına değil, surun bittiği köşe taşlarına vurur. Sınır değerleri senin köşe taşlarındır. 0 ile 1, 65535 ile 65536 arasındaki o tek bir adımı sağlam örmezsen, tüm sur yerle bir olur. Sınırlarını santim santim test et.
