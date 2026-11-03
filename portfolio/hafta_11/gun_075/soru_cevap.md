# GÜN 075: LİSTELER, SÖZLÜKLER VE KÜMELER — SORU & CEVAP VE TEKNİK ANALİZ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

### G075-SC1: Zaman Karmaşıklığı ($O(1)$ vs $O(N)$) ve Yüksek Hacimli Ağ Denetiminde Hizmet Dışı Bırakma (CPU DoS)

#### Soru Başlığı ve Tanımı
Bir Saldırı Engelleme Sistemi (IPS) veya güvenlik duvarı betiğinde 100.000 zararlı IP içeren bir karaliste bulunmaktadır. Bu listenin Python'da bir liste (`list`) veri yapısında tutulması ile bir küme (`set`) veri yapısında tutulması arasındaki algoritmik karmaşıklık farkı nedir? Saniyede on binlerce paketin geçtiği bir hatta liste kullanmak neden doğrudan bir DoS (Denial of Service) ve paket kaybı açığı doğurur?

#### Derinlemesine Teknik Analiz
Python'da bir veri yapısında `item in collection` sorgusunun çalıştırılması, koleksiyonun bellekteki organizasyon biçimine bağlı olarak dramatik ölçüde farklı iki algoritma işletir:

1. **Liste (`list`) Veri Yapısı — $O(N)$ Doğrusal Karmaşıklık:**
   Python listeleri dinamik dizilerdir (contiguous array of pointers). Bir elemanın listede olup olmadığını test etmek için yorumlayıcı 0. indeksten başlar ve aranan elemanı bulana veya listenin sonuna gelene kadar her bir elemanı sırayla (`==`) karşılaştırır.
   - Ortalama arama maliyeti: $N / 2$ karşılaştırma.
   - En kötü durum maliyeti (eleman listede yoksa): $N$ adet karşılaştırma adımıdır.
   - $N = 100.000$ olduğunda, karalistede olmayan her masum paket için işlemci tam 100.000 döngü tüketir! Saniyede 10.000 paket gelen bir hatta saniyede $10.000 \times 100.000 = 1.000.000.000$ (1 milyar) karşılaştırma işlemi yapılır. Bu, modern bir CPU çekirdeğini anında %100 yük altına sokar.

2. **Küme (`set`) Veri Yapısı — Ortalama $O(1)$ Sabit Zaman Karmaşıklığı:**
   Python kümeleri, açık adresleme (open addressing) ve SipHash tabanlı karma tablosu (hash table) olarak uygulanmıştır. Bir eleman sorgulandığında:
   - Elemanın hash değeri hesaplanır: $\text{hash}(item)$.
   - Hash değeri dizin tablosunun boyutuna göre modüler olarak indekslenir: $\text{index} = \text{hash} \pmod{\text{size}}$.
   - Doğrudan o bellek adresindeki kova (bucket) okunur.
   - Koleksiyonda 10 eleman da olsa, 10.000.000 eleman da olsa arama süresi mikrosaniyelerin altındadır ($\approx 0.40 \ \mu s$).

**Siber Güvenlik Açısından Sonuç:**
Ağ seviyesinde gecikme (latency) kritik olduğunda, $O(N)$ karmaşıklığa sahip bir liste ayrıştırıcı kuyruğunun (queue buffer) taşmasına ve gelen meşru paketlerin işletim sistemi tarafından düşürülmesine (packet drop) yol açar. Saldırgan arka planda yoğun trafik üreterek güvenlik motorunun CPU'sunu tüketir ve araya gizlediği asıl saldırı paketinin incelenmeden geçmesini sağlar.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret sitesinin API Gateway'inde şüpheli IP'ler bir Python listesinde tutulmaktadır:

```python
# GÜVENSİZ VE YAVAŞ UYGULAMA (O(N) CPU Tükenmesi):
banned_ips_list = ["198.51.100.1", "198.51.100.2", ...] # 250.000 kayıt

def inspect_traffic(client_ip: str) -> bool:
    if client_ip in banned_ips_list: # Her istekte 250.000 adım!
        return False
    return True
```

Kara Cuma (Black Friday) indiriminde saniyede 15.000 meşru istek gelmiş; API Gateway CPU'su %100'e kilitlenmiş ve müşteriler saatlerce "504 Gateway Timeout" hatası almıştır.

**Savunmacı ve Yüksek Performanslı Çözüm:**
Veri yapısı tek bir satırda kümeye (`set`) dönüştürülür:

```python
# GÜVENLİ VE $O(1)$ SABİT ZAMANLI UYGULAMA:
banned_ips_set = set(banned_ips_list) # O(1) arama için karma tablosu

def inspect_traffic(client_ip: str) -> bool:
    # 250.000 kayıt olsa dahi tek bir hash adımında çözülür
    if client_ip in banned_ips_set:
        return False
    return True
```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, siber güvenlikte algoritma bilgisi kurşun geçirmez yelek gibidir. Bir IP'yi, bir dosya hash'ini veya bir portu listede aratıyorsan, kendi sunucuna bilerek DoS saldırısı yapıyorsun demektir. Hatırlayacaksın: Sıra ve indeks önemliyse `list`, varlık ve hız önemliyse daima `set` kullanacaksın!"

---

### G075-SC2: Küme Cebri ile Çok Kaynaklı Tehdit İstihbaratında Yanlış Pozitiflerin (False Positive) Bastırılması

#### Soru Başlığı ve Tanımı
Siber Tehdit İstihbaratı (Cyber Threat Intelligence - CTI) süreçlerinde birden fazla kaynaktan (örn. OTX, MISP, AbuseIPDB) toplanan yüz binlerce gösterge (IoC) neden doğrudan güvenlik duvarına blok kuralı olarak yazılamaz? Küme cebri (kesişim, fark, birleşim) kullanılarak yüksek güvenilirlikli tehdit kümesi ve sıfır yanlış pozitif (False Positive) filtresi nasıl inşa edilir?

#### Derinlemesine Teknik Analiz
Açık kaynaklı veya ticari tehdit beslemeleri (Threat Feeds) "gürültülü" (noisy) veriler içerir. Çoğu zaman bir güvenlik araştırmacısının tarama sunucusu, içerik dağıtım ağı (CDN) IP'si veya genel DNS sunucusu (8.8.8.8, 1.1.1.1) bir saldırgan tarafından istismar edildiği için tehdit listesine girer.

Eğer bir güvenlik ekibi bu beslemelerden gelen verileri doğrudan `iptables` veya güvenlik duvarına yazarsa:
1. Kurumun meşru dış DNS çözümlemesi çöker.
2. İş ortakları veya bulut servisleri engellenir.
3. Yanlış alarm yorgunluğu (Alert Fatigue) sebebiyle SOC analistleri gerçek alarmları gözden kaçırır.

**Küme Cebri Modeli (Set Theoretic Formulation):**

- $S_A$: A istihbarat beslemesinden gelen IP kümesi.
- $S_B$: B istihbarat beslemesinden gelen IP kümesi.
- $W$: Kurumun meşru ve dokunulmaz beyaz liste (whitelist) IP kümesi.

1. **Yüksek Güvenilirlikli Tehditler (Kesişim):**
   Bir IP adresinin tek bir beslemede görülmesi geçici bir tarama veya yanlış pozitif olabilir. Ancak bağımsız iki beslemenin ikisinde birden raporlanması saldırı güvenilirliğini logaritmik olarak artırır:
   $$T_{ortak} = S_A \cap S_B$$
2. **Beyaz Liste Temizliği (Fark):**
   Ortak tehditler kümesinde yer alsa dahi, beyaz listedeki IP'lerin derhal düşürülmesi gerekir:
   $$T_{aktif} = T_{ortak} \setminus W = (S_A \cap S_B) - W$$
3. **Bastırılan Yanlış Pozitif Tespiti:**
   Tehdit listelerine karışmış beyaz liste adreslerinin raporlanarak CTI yöneticisine bildirilmesi:
   $$W_{baski} = (S_A \cup S_B) \cap W$$

Bu işlemler Python'ın yerel küme metotları (`intersection`, `difference`, `union`) ile optimize C seviyesinde milisaniyeler içinde icra edilir.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir telekom operatörünün SOC birimi, MISP ve OTX beslemelerinden gelen IP'leri doğrudan sınırdaki BGP yönlendiricisine kara delik (Blackhole) kuralı olarak enjekte etmiştir. OTX beslemesine kimliği belirsiz bir kullanıcı tarafından Google DNS adresi (`8.8.8.8`) enjekte edilmiş ve ülke genelinde 2 milyon abonenin internet erişimi 40 dakika boyunca kesilmiştir.

**Küme Cebri İle Güvenli Boru Hattı:**
```python
def generate_safe_firewall_blocklist(
    feed_otx: set[str],
    feed_misp: set[str],
    corporate_whitelist: set[str]
) -> set[str]:
    # 1. Adım: Yalnızca her iki bağımsız kaynakça onaylanan tehditler alınır
    correlated_threats = feed_otx & feed_misp
    
    # 2. Adım: Beyaz liste kayıtsız şartsız düşürülür
    safe_blocklist = correlated_threats - corporate_whitelist
    
    # 3. Adım: Beyaz listeye çarpan şüpheli durumlar denetime yazılır
    suppressed = (feed_otx | feed_misp) & corporate_whitelist
    if suppressed:
        log_security_audit(f"DİKKAT: Tehdit beslemesinde beyaz liste IP'si bastırıldı: {suppressed}")
        
    return safe_blocklist
```

#### Ustanın Çırağa Tavsiyesi
> "Çırak! İstihbarat ham bir bilgidir; filtrelenmemiş istihbarat ise zehirdir. Tek bir kaynaktan gelen veriye körü körüne inanıp güvenlik duvarının kurallarını değiştirmeyeceksin. En az iki bağımsız gözün gördüğünü (kesişim) alacak, kendi şirketinin can damarlarını (beyaz liste farkı) koruyacaksın. Küme cebri, istihbaratı operasyonel güce dönüştüren filtredir!"

---

### G075-SC3: İterasyon Sırasında Liste Üzerinde In-Place Değişiklik Yapma Tuzağı ve Güvenlik Filtrelerinin Atlatılması (Bypass)

#### Soru Başlığı ve Tanımı
Python'da bir liste üzerinde `for item in ioc_list:` döngüsü yürütülürken, döngü gövdesi içinde `ioc_list.remove(item)` veya `del` ile eleman silinmesi durumunda neden "eleman atlama" (skipping elements) hatası ortaya çıkar? Bir içerik filtreleme (content filtering) veya zararlı imza temizleme betiğinde bu mantık hatası nasıl bir güvenlik zafiyetine (WAF/IPS Bypass) yol açar?

#### Derinlemesine Teknik Analiz
Python yorumlayıcısı bir liste üzerinde `for` döngüsü çalıştırdığında, dahili bir tamsayı sayaç (indeks işaretçisi) tutar. İteratör her adımda bu sayacı 1 artırır (`index += 1`) ve listenin o indeksteki elemanını döngü gövdesine iletir.

Eğer döngü gövdesi içindeyken listenin kendisinden bir eleman silinirse (`list.remove()`):
1. Silinen elemandan sonraki tüm elemanlar bellekte bir basamak sola kayar (0'a doğru yaklaşır).
2. Ancak döngünün iç indeksi bir sonraki adıma (`index + 1`) ilerlemeye devam eder.
3. Sonuç olarak, silinen elemanın hemen arkasında duran ve sola kayan eleman **asla denetlenemez ve atlanır!**

**Güvenlik Zafiyeti Simülasyonu:**
Bir log akışında ardışık iki adet zararlı parametre (`MAL_01` ve `MAL_02`) olduğunu varsayalım:
- `i = 0`: İnceleme `MAL_01` üzerinde yapılır. Zararlı bulunur ve `list.remove("MAL_01")` ile silinir.
- Listenin yeni durumu: `MAL_02` artık 0. indekse kaymıştır.
- Döngü bir sonraki adıma geçer: `i = 1`.
- Ancak 1. indekste artık masum eleman (`CLEAN_01`) bulunmaktadır!
- **Sonuç:** `MAL_02` hiçbir denetime takılmadan listede kalır ve sistemden içeri sızar!

Saldırganlar bu çalışma mantığını bildiklerinde, zararlı isteklerini ardışık olarak paketler veya çift zararlı başlık göndererek güvenlik filtrelerinin ikinci yükü atlamasını sağlarlar.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir Web Uygulama Güvenlik Duvarı (WAF) ters vekil (reverse proxy) katmanında, gelen HTTP istek başlıklarındaki bilinen zararlı başlıkları temizleyen bir Python eklentisi yazılmıştır:

```python
# GÜVENSİZ KOD (Bypass Açığı İçeren Mantık):
headers_list = ["X-Attacker-1", "X-Attacker-2", "User-Agent", "Accept"]

for header in headers_list:
    if header.startswith("X-Attacker"):
        headers_list.remove(header) # Sola kayma sebebiyle X-Attacker-2 ATLANIR!
```

Saldırgan sunucuya `X-Attacker-1: test` ve hemen ardından `X-Attacker-2: command_injection` başlıklarını göndermiş; WAF birinci başlığı silmiş ancak ikinci başlığı atladığı için zararlı komut doğrudan arka uç web sunucusuna iletilmiştir.

**Savunmacı ve Güvenli Tasarım Çözümleri:**

1. **Yol (En Temiz ve Hızlı): List Comprehension (Yeni Liste Üretimi):**
   ```python
   # Orijinal listeye dokunulmaz, yeni temiz liste oluşturulur
   clean_headers = [h for h in headers_list if not h.startswith("X-Attacker")]
   ```
2. **Yol: Listenin Kopyası Üzerinde İterasyon Yapmak:**
   ```python
   # Döngü kopya liste üzerinde dönerken silme orijinal listeden yapılır
   for header in list(headers_list):
       if header.startswith("X-Attacker"):
           headers_list.remove(header)
   ```

#### Ustanın Çırağa Tavsiyesi
> "Evlat, bindiğin dalı kesmeyeceksin! Üzerinde yürüdüğün listenin altından halıyı çekersen (eleman silersen), ayağın tökezler ve arkandaki saldırganı görmezden gelirsin. Bir koleksiyonu temizleyeceksen, ya list comprehension ile pırıl pırıl yeni bir liste doğuracaksın, ya da kopyasının üzerinde yürüyüp gerçeğini temizleyeceksin. Güvenlik kodunda tek bir eleman bile atlanamaz!"
