<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 073: Koşullar, Kontrol Akışı ve Savunmacı Döngüler

## Ustanın Girişi: Kontrol Akışı Savunmanın Omurgasıdır

Evlat, dinle. Bir siber güvenlik aracını alelade bir Python scriptinden ayıran en temel unsur, yazdığın kodun **karar verme mantığı (control flow)** ve **döngü güvenliğidir (loop safety)**.

Çoğu acemi programcı koşulları yalnızca `if a == b:` şeklinde basit karşılaştırmalar sanır; döngüleri ise sonsuza kadar dönebilecek `while True:` bloklarıyla yazar. Oysa bir saldırganın en sevdiği hedeflerden biri, güvenlik yazılımının döngülerini kilitlemek ve CPU'yu %100'e vurarak sistemi çökertmektir (Denial of Service - DoS).

Bir paket ayrıştırıcının (packet parser) içine öyle bir DNS paketi yerleştirirler ki, içindeki iki gösterici (pointer) birbirini gösterir: $A \to B \to A$. Eğer döngünün içinde savunmacı bir tavan (circuit breaker) ve ziyaret kümesi yoksa, o parser sonsuza kadar o iki bayt arasında döner, bellek kilitlenir, sunucu düşer ve saldırgan arkada cirit atar.

Bugün, koşullu dallanmanın derinliklerine inecek; kısa devre (short-circuit) değerlendirmesini, `None` ile `False` arasındaki kritik farkı, `for ... else` ile zararlı tarama zarafetini ve sonsuz döngü tuzaklarına karşı çelik zırh örmeyi öğreneceksin.

---

## 1. Mantıksal Değerlendirme ve "Fail-Closed" İlkesi

Siber güvenlikte erişim denetimi (ACL) ve güvenlik duvarı kuralları yazılırken iki temel felsefe vardır:
- **Fail-Open (Kusurlu Açık):** Bir hata olursa veya hiçbir kural eşleşmezse trafiğe izin ver. (Felakettir!)
- **Fail-Closed (Kusurlu Kapalı / Varsayılan Engelleme):** Eğer kural açıkça izin vermiyorsa, sistem koşulsuz olarak kapıyı kilitler (`default_action = "DENY"`).

### A. Kısa Devre (Short-Circuit) Değerlendirmesi
Python'da mantıksal `and` ve `or` işleçleri soldan sağa değerlendirilir ve sonuç kesinleştiği anda durur:
```python
if is_admin and check_ldap_directory(user):
```
Eğer `is_admin` değeri `False` ise, Python `check_ldap_directory` fonksiyonunu **asla çağırmaz**. Bu sadece bir performans optimizasyonu değildir; pahalı veritabanı sorgularını ve ağ çağrılarını gereksiz yere tetiklemeyi önleyen bir DoS kalkanıdır.

### B. `None` ile `False` Arasındaki Ölümcül Fark
Python'da `if not permission:` dendiğinde hem `permission = False` hem de `permission = None` aynı şekilde davranır. Ancak erişim denetiminde:
- `False` = Açıkça reddedilmiş, erişim yetkisi yok demektir.
- `None` = Veritabanında kullanıcı bulunamadı veya bağlantı koptu (yokluk/hata) demektir.

Bu ikisini birbirine karıştırmak, sistem hatası anında yanlış yetkilendirme kararlarına yol açar. Bu yüzden kritik koşullarda daima katı eşitlik (`is not None`) aranmalıdır.

---

## 2. Savunmacı Döngüler ve Sonsuz Döngü (Anti-DoS) Koruması

Ağ protokollerinde (örneğin DNS isim sıkıştırma - RFC 1035) veya dosya formatlarında (ELF/PE başlıkları), verinin boyutunu küçültmek için göstericiler (pointers) kullanılır. Bir etki alanı adı tekrarlanmak yerine önceki ofsete bir göstericiyle işaret edilir.

### Saldırganın Silahı: Döngüsel Gösterici (Pointer Cycle)
Saldırgan yapay bir paket üretir:
- Ofset 10, Ofset 20'yi gösterir.
- Ofset 20, Ofset 10'u gösterir.

Normal bir `while offset != -1:` döngüsü bu paketi açmaya kalktığında sonsuz döngüye (CWE-835) girer.

### Ustanın Savunma Kalkanı:
```python
visited_offsets = set()
iteration_count = 0

while curr_offset != -1:
    iteration_count += 1
    if iteration_count > max_iterations: # 1. Kalkan: Adım Tavanı
        raise ControlFlowSecurityError("Yineleme tavanı aşıldı! DoS koruması.")
    if curr_offset in visited_offsets:   # 2. Kalkan: Döngüsel Atıf Tespiti
        raise ControlFlowSecurityError("Pointer Cycle tespit edildi!")
    visited_offsets.add(curr_offset)
    curr_offset = get_next_offset(curr_offset)
```

---

## 3. Python'ın Gizli Silahı: `for ... else` ile Tehdit Avcılığı

Birçok dilde bir listede arama yaparken bir bayrak değişkeni (`found = False`) tanımlanır. Python'da ise döngülerin `else` bloğu vardır. Bu blok, döngü `break` ile kırılmadan **doğal olarak tamamlandığında** çalışır:

```python
for artifact in stream:
    if artifact.is_malware():
        trigger_incident_response(artifact)
        break # Zararlı bulundu, döngüyü kır!
else:
    # Döngü break görmeden bitti -> Tüm akış temiz demektir!
    certify_clean_stream()
```
Bu zarif yapı, ara bayrak değişkeni ihtiyacını ortadan kaldırır ve kodun adli okunabilirliğini zirveye taşır.

---

## 4. Kayan Pencere Hız Sınırlayıcı (Rate Limiting)

Kaba kuvvet (Brute Force) saldırılarını tespit ederken zaman faktörünü döngüyle modellemek gerekir. Her başarısız denemeyi bir zaman damgası listesinde tutarız. Gelen her yeni olayda, pencerenin dışındaki eski olayları liste kavrama (list comprehension) ile süzeriz:

$$\text{Geçerli Olaylar} = \{ t \in \text{Olaylar} \mid T_{\text{şimdi}} - t \le W \}$$

Eğer geçerli olay sayısı belirlenen eşiği ($\text{threshold}$) aşarsa, IP adresi anında karantinaya alınır.

---

## Ustanın Çırağa Öğüdü

Evlat, döngü yazmak araba sürmeye benzer; gaza basmayı (döngüyü başlatmayı) herkes bilir ama usta şoför daima ayağını fren pedalının (döngü tavanı ve break koşulu) üzerinde tutar. Sonsuz döngüye giren bir güvenlik yazılımı, nöbet kulübesinde uyuyakalan askere benzer; düşman içeri girerken o kendi rüyasında kaybolmuştur. Döngülerine daima sınır koy!
