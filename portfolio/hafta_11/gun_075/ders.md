# GÜN 075: LİSTELER, SÖZLÜKLER VE KÜMELER (DATA STRUCTURES IN CYBER SECURITY)
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞ DERSİ: VERİ YAPISI SEÇİMİ BİR PERFORMANS TERCİHİ DEĞİL, BİR GÜVENLİK SINIRIDIR

Evlat, siber güvenlikte "küçük" hatalar yoktur; küçük görünen mimari dikkatsizliklerin büyük felaketlere yol açtığı anlar vardır. Bir güvenlik aracı yazdığında, bellekte tuttuğun veriyi hangi yapıda sakladığın (`list`, `dict` veya `set`), yazılımının bir siber saldırı altında ayakta kalıp kalmayacağını belirler.

Bir saniyede ağ kartından 50.000 paket geçtiğini ve kurumun 1.000.000 adet zararlı IP içeren bir tehdit istihbaratı (IoC) beslemesine sahip olduğunu hayal et. Eğer bu IP'leri bir Python listesinde (`list`) tutar ve her gelen paket için `if ip in blacklist_list:` sorgusu atarsan, her sorgu için ortalama 500.000 karşılaştırma ($O(N)$) yaparsın. CPU anında %100'e kilitlenir, ayrıştırıcı kuyruğu taşar, ağ paketleri düşmeye başlar ve saldırgan senin güvenlik duvarını kör ederek içeri sızar.

Oysa o IP'leri bir kümede (`set`) veya sözlükte (`dict`) tutsaydın, arka plandaki karma tablosu (hash table) sayesinde arama süren koleksiyonda kaç milyon eleman olursa olsun sabit zaman $O(1)$ olacaktı! Veri yapıları teorisi, savunmacı bir mühendisin donanım kaynaklarını saldırgana karşı kalkan yapma sanatıdır.

---

## 2. ZAMAN KARMAŞIKLIĞI: $O(1)$ KÜME ARAMASI VS $O(N)$ LİSTE TARAMASI

Python'da temel koleksiyonların eleman varlık denetimi (`in` operatörü) şu karmaşıklık kurallarına tabidir:

| Veri Yapısı | Arama Karmaşıklığı (Ortalama) | Arama Karmaşıklığı (En Kötü) | Bellek Kullanımı | Temel Mekanizma |
| :--- | :---: | :---: | :---: | :---: |
| **Liste (`list`)** | $O(N)$ (Doğrusal) | $O(N)$ | Düşük (Kompakt dizi) | Baştan sona tek tek eleman karşılaştırması |
| **Küme (`set`)** | $O(1)$ (Sabit Zaman) | $O(N)$ (Aşırı Çakışma) | Orta / Yüksek | SipHash tabanlı açık adresleme karma tablosu |
| **Sözlük (`dict`)** | $O(1)$ (Sabit Zaman) | $O(N)$ (Aşırı Çakışma) | Orta / Yüksek | Birleşik seyrek ve yoğun karma tablosu |

### Mikro-Kıyaslama Analizi:
5.000 elemanlı bir koleksiyonda yapılan arama testinde:
- Liste arama süresi: $\approx 45.20 \ \mu s$
- Küme arama süresi: $\approx 0.40 \ \mu s$
- **Hız Farkı:** Küme araması listeye göre **113 kat daha hızlıdır!** Koleksiyon boyutu 1.000.000 elemana çıktığında bu fark binlerce kata ulaşır.

---

## 3. KÜME CEBRİ (SET ALGEBRA) İLE TEHDİT İSTİHBARATI KORELASYONU

Siber savunma merkezlerinde (SOC) tek bir tehdit beslemesine güvenilmez; birden fazla istihbarat kaynağı (OTX, MISP, AbuseIPDB, kurum içi honeypot'lar) toplanır. Bu beslemelerin korelasyonu küme cebri işlemleri ile hatasız olarak çözülür:

### 1. Kesişim (Intersection `&`): Yüksek Güvenilirlikli Tehditler
Farklı bağımsız iki veya daha fazla istihbarat kaynağının her ikisinde de raporlanan IP'ler, saldırının doğruluğu konusunda en yüksek güveni sunar:
$$\text{Ortak Tehditler} = \text{FeedA} \cap \text{FeedB}$$

### 2. Fark (Difference `-`): Yanlış Pozitifleri (False Positive) Bastırma
Tehdit listeleri bazen meşru altyapıları (örn. Google DNS `8.8.8.8`, Cloudflare `1.1.1.1` veya şirket ağ geçidi) yanlışlıkla engelleyebilir. Kurum beyaz listesi (`whitelist`) küme farkı ile anında ayıklanır:
$$\text{Aktif Blok Listesi} = (\text{FeedA} \cap \text{FeedB}) \setminus \text{Beyaz Liste}$$

### 3. Birleşim (Union `|`): Kapsamlı Tehdit Şemsiyesi
Tüm kaynaklardan gelen tekil zararlı adreslerin konsolide edilmesi:
$$\text{Toplam Tekil Tehditler} = (\text{FeedA} \cup \text{FeedB}) \setminus \text{Beyaz Liste}$$

### 4. Simetrik Fark (Symmetric Difference `^`): Besleme Anomalisi Analizi
Yalnızca tek bir kaynakta görülen, diğer kaynak tarafından teyit edilmemiş şüpheli anomaliler.

---

## 4. SÖZLÜK GÜVENLİĞİ VE `KeyError` KAYNAKLI HİZMET DIŞI BIRAKMA (DoS)

Python sözlüklerinde en sık yapılan hata, anahtarın varlığından emin olmadan köşeli parantez ile doğrudan okumadır:

```python
# ❌ ÇÖKME VE DoS RİSKİ:
sensor_mode = packet_payload["headers"]["security_mode"]
# Eğer saldırgan "security_mode" başlığını göndermezse:
# KeyError fırlatılır -> Tüm iş parçacığı çöker -> Trafik akışı durur!
```

### Savunmacı Çözüm: Güvenli Derin Gezinti (`safe_deep_dict_get`)
İç içe sözlüklerde ara düğümlerden biri `None` veya sözlük dışı bir tip olduğunda, standart `.get()` zincirleri bile `AttributeError: 'NoneType' object has no attribute 'get'` hatası üretebilir.

```python
# ✅ USTANIN DERİN GEZİNTİ YÖNTEMİ:
def safe_deep_dict_get(data: dict, key_path: list[str], default: Any = None) -> Any:
    current = data
    for step in key_path:
        if not isinstance(current, dict):
            return default
        current = current.get(step)
        if current is None:
            return default
    return current
```

---

## 5. PYTHON'DA KARMA ÇAKIŞMA SALDIRILARI (HASH COLLISION DoS / CWE-407)

Sözlükler ve kümeler karma tablosu kullandığı için, teorik olarak bir saldırgan aynı hash değerini üreten binlerce özel anahtar (hash collision) hazırlayıp sisteme HTTP başlığı veya JSON parametresi olarak gönderebilir.
Eğer tüm anahtarlar aynı bucket'a düşerse, karma tablosu $O(1)$ yerine $O(N)$ bağlı liste aramasına dönüşür ve tek bir küçük istek sunucunun CPU'sunu saatlerce %100'e kilitler (HashDoS).

### Python'ın Savunma Mekanizması: SipHash ve `PYTHONHASHSEED`
Python 3.3 sürümünden itibaren, dahili string hashleme algoritması olarak **SipHash-2-4** standardı getirilmiştir. Yorumlayıcı her başladığında rastgele 128 bitlik bir tohum (seed) belirler (`PYTHONHASHSEED`). Bu sayede dışarıdaki bir saldırgan, hedef Python sürecinin iç hash tablosunda hangi anahtarların çakışacağını matematiksel olarak tahmin edemez.

---

## 6. LİSTE İTERASYONUNDA YERİNDE (IN-PLACE) SİLME TUZAĞI

Bir güvenlik mühendisinin düşebileceği en sinsi mantık hatalarından biri, üzerinde `for` döngüsü çalıştırdığı bir listeden eleman silmektir (`list.remove()` veya `del`):

```python
# ❌ SİNSİ MANTIK HATASI (GİZLİ SALDIRI ATLATMASI):
bad_iocs = ["MAL_01", "MAL_02", "CLEAN_01", "MAL_03"]

for ioc in bad_iocs:
    if ioc.startswith("MAL_"):
        bad_iocs.remove(ioc)

# Sonuç: bad_iocs -> ['MAL_02', 'CLEAN_01']
# 💥 FELAKET: "MAL_02" ASLA İNCELENMEDİ VE LİSTEDE KALDI!
```
**Neden Oldu?** `MAL_01` silindiğinde liste sola kayar. İteratör 1. indekse geçtiğinde, sola kayıp 0. indekse gelen `MAL_02` atlanır! Saldırgan bu hatayı bilerek zararlı payload'un tespit edilmeden ağdan geçmesini sağlar.

### Savunmacı Çözüm: List Comprehension ile Yeni Liste Üretimi
```python
# ✅ GÜVENLİ VE ATLAMAYAN FİLTRELEME:
filtered_iocs = [ioc for ioc in bad_iocs if not ioc.startswith("MAL_")]
# Sonuç: ['CLEAN_01'] -> Hiçbir zararlı kaçamaz!
```

---

## 7. USTANIN ÇIRAĞA ÖĞÜTLERİ VE ALTIN KURALLAR

1. **Arama Yapacaksan Kümeyi (`set`), Sıra Koruyacaksan Listeyi (`list`) Seç:** Tehdit IP'si, dosya hash'i veya port sorgulamasında asla liste kullanma. Milyonlarca satırlık veriyi kümeye emanet et.
2. **Koleksiyon Boyutuna Daima Tavan Koy (Memory Ceiling):** Dışarıdan veri çeken bir koleksiyona sınır koymazsan (`MAX_LIMIT`), saldırgan 10 GB bellek tükettirip sunucunu Out-Of-Memory (OOM-Killer) ile düşürür.
3. **Asla Döngü İçinde Listeden Eleman Silme:** List comprehension kullan, orijinal listeyi bozmadan taze ve filtrelenmiş liste üret.
4. **Sözlükten Asla Doğrudan `data[key]` İle Veri Alma:** Derin gezinti fonksiyonları ve `.get(key, default)` kullanarak sistemini KeyError kaynaklı çökmelerden koru.
5. **Kural Sözlüklerinde Mükerrer Anahtarları Denetle (Rule Shadowing):** Aynı isimde iki kural tanımlanırsa ikincisi birincisini ezer. Kural tablolarını yüklerken çift anahtar kontrolü yap.
