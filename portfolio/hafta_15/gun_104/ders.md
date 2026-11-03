# GÜN 104: AEAD VE NONCE YENİDEN KULLANIMI
**Aşama 05 — Kriptografi Temelleri ve Uygulamaları (Hafta 15 / Gün 104)**  
*Eğitmen / Usta: Seydi Eryılmaz (@seydivakkas)*

---

## 1. USTANIN DERS GİRİŞİ: "KRİPTOGRAFİNİN ÖLÜMCÜL GÜNAHI: NONCE TEKRARI"

Evladım, kriptografi tarihinde öyle hatalar vardır ki, milyar dolarlık sistemleri tek bir matematiksel denklemle yerle bir eder. Bu hataların en meşhuru, en tehlikelisi ve affedilmezi **Nonce (Number Used Once) Yeniden Kullanımıdır (CWE-323)**.

İngilizcede *"Nonce"* kelimesi *"Number used once"* (Yalnızca bir kez kullanılan sayı) ifadesinin kısaltmasıdır. Adı üstünde: **BİR KEZ KULLANILAN SAYI**. Eğer bir kriptografik protokolde aynı gizli anahtar ile aynı Nonce değerini ikinci kez kullanırsan, matematik affetmez. Akış şifrelerinin (Stream Ciphers) ve sayaç modlarının (AES-CTR, AES-GCM, ChaCha20-Poly1305) tüm gizlilik zırhı o anda buharlaşır!

Bugünkü dersimizde; AEAD kavramını, ilişkili açık verinin (AAD) protokollerdeki kritik yerini, aynı Nonce kullanıldığında anahtar akışının nasıl kendi kendini yok ettiğini (Two-Time Pad felaketi), Antoine Joux'nun meşhur "Forbidden Attack" saldırısını ve SIV (Synthetic IV) deterministik savunma mimarisini en derin teknik katmanlarıyla inceleyeceğiz.

---

## 2. AEAD VE İLİŞKİLİ DOĞRULANMIŞ VERİ (AAD) MİMARİSİ

Geçmişte mühendisler şifreleme ve bütünlüğü ayrı ayrı uygulamaya çalıştılar:
1. **Encrypt-and-MAC:** $C = E(P), T = \text{MAC}(P)$ -> SSH'ın eski sürümlerinde kullanıldı, MAC düz metinden alındığı için bilgi sızdırabilir!
2. **MAC-then-Encrypt:** $T = \text{MAC}(P), C = E(P \parallel T)$ -> SSL/TLS 1.0 ve 1.2'de kullanıldı, Dolgu Oracle (Padding Oracle / Lucky Thirteen) saldırılarına yol açtı!
3. **Encrypt-then-MAC (EtM):** $C = E(P), T = \text{MAC}(C)$ -> En güvenli yöntemdir; şifreli metin deşifre edilmeden önce etiket doğrulanır.

Modern dünyada bu tartışmalara son veren standart **AEAD (Authenticated Encryption with Associated Data - RFC 5116)** oldu.

### 2.1. AAD (Associated Authenticated Data) Nedir ve Neden Hayatidir?
Bir ağ paketinde veya API isteğinde bazı verilerin gizlenmemesi (şifrelenmemesi) gerekir. Örneğin:
- IP paket başlıkları (Kaynak IP, Hedef IP, Port numarası) yönlendiriciler (routers) tarafından okunabilmelidir.
- Bir veritabanı kaydında `kullanici_id` veya `olusturma_tarihi` indeksleme için açık kalmalıdır.

İşte bu açık veriye **AAD** denir. AAD şifrelenmez; ancak kimlik doğrulama etiketinin (Authentication Tag) hesaplamasına dahil edilir:

$$C = \text{CTR\_Encrypt}(K, \text{Nonce}, P)$$
$$T = \text{MAC}(K, \text{Nonce} \parallel C \parallel AAD \parallel \text{Lengths})$$

Eğer bir saldırgan ağ üzerinden geçerken paketin hedef IP'sini veya kullanıcının `rol=user` değerini `rol=admin` olarak değiştirirse (`CWE-345`), alıcı şifreyi çözmeden önce etiketi kontrol eder ve uyuşmazlığı tespit ederek paketi çöpe atar (`AuthenticationTagMismatchError`).

---

## 3. TWO-TIME PAD FELAKETİ: MATEMATİKSEL İPTAL

CTR tabanlı tüm şifreleme modlarında (AES-GCM ve ChaCha20 dahil), şifreleme işlemi düz metin ile üretilen bir **anahtar akışının (Keystream $K_s$)** XOR'lanmasından ibarettir:

$$K_s = \text{AES}_K(\text{Nonce} \parallel \text{Counter})$$

Şimdi bir sistemin aynı $(K, \text{Nonce})$ çiftini kullanarak iki farklı mesajı ($P_1$ ve $P_2$) şifrelediğini düşünelim:

$$C_1 = P_1 \oplus K_s$$
$$C_2 = P_2 \oplus K_s$$

Ağ trafiğini dinleyen bir saldırgan, $C_1$ ve $C_2$ paketlerini yakalar ve ikisini birbiriyle XOR'lar:

$$C_1 \oplus C_2 = (P_1 \oplus K_s) \oplus (P_2 \oplus K_s)$$

XOR işleminin değişme ve birleşme özellikleri gereğince:

$$C_1 \oplus C_2 = P_1 \oplus P_2 \oplus (K_s \oplus K_s)$$

Bir sayının kendisiyle XOR'u sıfırdır ($X \oplus X = 0$):

$$C_1 \oplus C_2 = P_1 \oplus P_2 \oplus 0 = P_1 \oplus P_2$$

**DEHŞET VERİCİ GERÇEK:**
Gizli anahtar akışı $K_s$ tamamen yok olmuştur! Saldırganın elinde artık doğrudan **iki düz metnin birbirine XOR'lanmış hali** vardır.

### 3.1. Düz Metinler Nasıl Kurtarılır? (Crib Dragging)
Saldırgan $P_1 \oplus P_2$ sonucuna sahiptir. İnsan dillerinde (Türkçe, İngilizce) ve protokollerde belirli kalıplar ("GET /", "user_id=", "HTTP/1.1", "{" gibi) son derece yaygındır.
- Saldırgan tahmin ettiği bir kelimeyi (Crib) $P_1 \oplus P_2$ üzerinde bayt bayt kaydırarak XOR'lar:
  $$(P_1 \oplus P_2) \oplus \text{Crib}$$
- Eğer Crib $P_1$'in doğru bir parçasıysa, çıkan sonuç $P_2$'nin anlamlı harflerini verir!
- Saldırgan $P_2$'deki anlamlı kelimeleri tamamladıkça $P_1$ açığa çıkar; domino taşları gibi her iki mesaj da gizli anahtara hiç ihtiyaç duyulmadan tamamen okunur!

---

## 4. AES-GCM VE FORBIDDEN ATTACK: BÜTÜNLÜĞÜN DE ÇÖKMESİ

Durum sadece gizlilik sızıntısıyla kalmaz. 2006 yılında Antoine Joux tarafından keşfedilen ve 2016 yılında yüz binlerce HTTPS sunucusunda tespit edilen **"Forbidden Attack"** şunu kanıtlamıştır:

AES-GCM modunda Nonce tekrar ettiğinde:
1. Saldırgan sadece düz metinleri çözmekle kalmaz;
2. GHASH kimlik doğrulama polinomunun köklerini bularak gizli **GHASH kimlik doğrulama anahtarını ($H$)** matematiksel olarak hesaplayabilir!
3. $H$ anahtarını ele geçiren saldırgan, artık kurban adına geçerli kimlik doğrulama etiketleri (Tag) üretebilir. Yani araya girip istediği sahte paketleri enjekte edebilir ve sistem bunları meşru zanneder!

---

## 5. NONCE TEKRARINI ENGELLEME STRATEJİLERİ

### 5.1. Durum Bilgili Nonce Takibi (Stateful Nonce Tracking)
Sistem belleğinde veya Redis/Memcached gibi yüksek hızlı bir dağıtık önbellekte, her anahtar için kullanılan Nonce değerleri kaydedilmelidir. Eğer bir şifreleme isteği aynı Nonce ile gelirse işlem anında engellenmelidir (`CWE-323`).

### 5.2. Doğum Günü Paradoksu ve 96-Bit Nonce Riski
Eğer 96-bitlik Nonce'ları `secrets.token_bytes(12)` ile rastgele üretiyorsanız, Doğum Günü Paradoksu gereği yaklaşık $2^{48}$ ($2.8 \times 10^{14}$) adet mesajdan sonra iki Nonce'un tesadüfen aynı üretilme ihtimali %50'ye ulaşır. Bu nedenle:
- Yüksek trafikli sistemlerde anahtar belirli aralıklarla (örneğin her 1 milyon mesajda bir) rotasyona tabi tutulmalıdır.
- Ya da 192-bit Nonce kullanan **XChaCha20-Poly1305** algoritması tercih edilmelidir.

### 5.3. SIV (Synthetic IV - RFC 5297) Deterministik AEAD
Eğer sisteminiz durum bilgisi tutamıyorsa (stateless mikroservisler) veya rastgele sayı üreticinizin bozulmasından endişe ediyorsanız, **SIV (AES-GCM-SIV)** mimarisi kullanılır:
$$\text{Synthetic Nonce} = \text{HMAC}(K, P \parallel AAD)[:12]$$
Burada Nonce rastgele üretilmez; şifrelenecek verinin ve AAD'nin kriptografik özetinden türetilir.
- Eğer aynı mesaj tekrar şifrelenirse aynı Nonce oluşur; ancak düz metin aynı olduğu için Two-Time Pad sızıntısı oluşmaz ($P_1 \oplus P_1 = 0$).
- Farklı bir mesaj şifrelendiğinde ise Nonce tamamen farklı üretilir!

---

## 6. USTADAN ÇIRAĞA TAVSİYELER

1. **Nonce Asla Sabit Olamaz:** Kodunda `nonce = b"000000000000"` gibi statik tanımlamalar gördüğün yerde sistemi durdur.
2. **CTR ve GCM'de Nonce Kutsaldır:** Bir anahtarla bir Nonce yalnızca BİR KEZ kullanılabilir.
3. **Şüphedeysen SIV Kullan:** Nonce yönetiminin riskli olduğu dağıtık ortamlarda AES-GCM-SIV mimarisini tercih et.
4. **AAD'yi Boş Bırakma:** Paket başlıklarını, kullanıcı yetkilerini ve zaman damgalarını AAD'ye bağla ki aktarım sırasında kurcalanamasın.
