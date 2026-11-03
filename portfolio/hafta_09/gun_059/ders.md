# G059: HTTPS ve TLS El Sıkışması (TLS Handshake) — Usta Dersi

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Giriş: Açık Metin HTTP'den Kriptografik HTTPS Kalesine

Evlat, düne kadar HTTP isteklerinin nasıl metin tabanlı olarak aktığını, GET ve POST gibi yöntemlerin arkasındaki mantığı ve durumsuzluk (statelessness) prensibini inceledik. Ancak çıplak bir HTTP bağlantısı, internetin vahşi coğrafyasında tamamen korunmasızdır. Bir istemci açık metin bir HTTP paketi gönderdiğinde, bu veri yerel kablosuz ağdan (Wi-Fi), kurumsal yönlendiricilerden, internet servis sağlayıcılarının omurgalarından ve denizaltı fiber optik kablolarından geçer. 

Araya giren herhangi bir gözlemci veya saldırgan (adversary):
1. **Gizlilik İhlali (Eavesdropping):** Kullanıcı oturum çerezlerini, parolaları, kredi kartı bilgilerini ve URL parametrelerini açıkça okuyabilir.
2. **Bütünlük İhlali (Tampering):** Ağ akışındaki HTML/JS kodlarını modifiye ederek tarayıcıya zararlı betikler (malvertising, cryptomining, phishing) enjekte edebilir.
3. **Kimlik Sahteciliği (Spoofing / Impersonation):** DNS zehirlemesi veya ARP zehirlemesiyle istemciyi sahte bir sunucuya yönlendirip orijinal servis gibi davranabilir.

İşte **HTTPS (HTTP Secure - RFC 2818)**, bu üç temel zafiyete karşı HTTP protokolünün doğrudan **TLS (Transport Layer Security)** katmanı üzerinde çalıştırılmasıyla doğmuştur. HTTPS, ayrı bir uygulama katmanı protokolü değildir; HTTP'nin şifreli ve kimlik doğrulamalı bir TLS tüneli içerisine sarılmış (encapsulated) halidir. Standart varsayılan portu **443**'tür.

---

## 2. TLS Protokol Mimarisi ve Kayıt Katmanı (Record Layer)

TLS protokolü tek parçalı bir blok değildir. İki ana katmandan ve bu katmanlar üzerinde çalışan dört alt protokolden oluşur:

```
+-------------------------------------------------------------------------+
|                  UYGULAMA KATMANI (HTTP, gRPC, WebSocket)              |
+-------------------------------------------------------------------------+
|  Handshake Protocol  | Alert Protocol | ChangeCipherSpec | Application  |
|  (El Sıkışma - 22)   |  (Alarm - 21)  |  (Geçiş - 20)    |  Data (23)   |
+-------------------------------------------------------------------------+
|                  TLS KAYIT KATMANI (TLS RECORD LAYER)                   |
|           5 Bayt Başlık: [Content-Type] [Version] [Length]              |
+-------------------------------------------------------------------------+
|                  AKTARIM KATMANI (TCP - Port 443)                       |
+-------------------------------------------------------------------------+
```

### 2.1. TLS Record Layer Başlığı (5 Bayt)

Her TLS paketi, TCP segmentinin başında yer alan sabit **5 baytlık** bir Record Layer başlığı ile başlar:
- **Bayt 0 - Content-Type (1 bayt):** Paketin hangi TLS alt protokolüne ait olduğunu bildirir:
  - `0x14` (20): `ChangeCipherSpec` (Şifreleme parametrelerinin devreye girdiğini belirtir; TLS 1.3'te middlebox uyumluluğu haricinde kaldırılmıştır).
  - `0x15` (21): `Alert` (Hata veya kapatma bildirimleri: `close_notify`, `bad_record_mac`, `handshake_failure`).
  - `0x16` (22): `Handshake` (Oturum açma ve anahtar mutabakatı mesajları: ClientHello, ServerHello, Certificate vb.).
  - `0x17` (23): `ApplicationData` (Asıl şifrelenmiş HTTP yükü).
- **Bayt 1-2 - Protocol Version (2 bayt):** Tarihi nedenlerle geriye dönük uyumluluk sürümüdür (`0x0303` = TLS 1.2). TLS 1.3 paketlerinde dahi, ağdaki eski güvenlik duvarları (middleboxes) bağlantıyı koparmasın diye bu alana `0x0303` yazılır; asıl TLS 1.3 sürümü uzantılar (extensions) içinde bildirilir.
- **Bayt 3-4 - Length (2 bayt big-endian):** Kendisinden sonra gelen şifrelenmiş veya açık el sıkışma gövdesinin bayt cinsinden uzunluğudur. RFC 5246'ya göre maksimum **16384 bayt (16 KB)** olabilir.

---

## 3. Klasik TLS 1.2 El Sıkışması ve Gecikme Bedeli (2-RTT)

TLS 1.2 (RFC 5246), günümüzde halen birçok kurumsal sistemde varlığını sürdüren ancak mimari olarak 2 tam gidiş-dönüş süresine (**2-RTT**) ihtiyaç duyan bir protokoldür.

### Adım Adım TLS 1.2 Akışı:
1. **TCP 3-Way Handshake (1 RTT):**
   - İstemci `SYN` gönderir -> Sunucu `SYN+ACK` döner -> İstemci `ACK` gönderir.
2. **TLS El Sıkışması 1. Gidiş-Dönüşü (1. RTT):**
   - **ClientHello (İstemci -> Sunucu):**
     - İstemcinin desteklediği en yüksek TLS sürümü.
     - 32 bayt `Client Random` (Pre-Master Secret hesaplamasında tuz görevi görür).
     - Desteklenen Şifreleme Paketleri (Cipher Suites) listesi (öncelik sırasına göre).
     - Desteklenen Uzantılar (Extensions): `SNI` (hangi sunucu adına bağlanıldığı), Eliptik Eğriler vb.
   - **ServerHello (Sunucu -> İstemci):**
     - Sunucunun seçtiği TLS sürümü ve Şifreleme Paketi.
     - 32 bayt `Server Random`.
     - Oturum Kimliği (`Session ID`).
   - **Certificate (Sunucu -> İstemci):** Sunucunun X.509 dijital sertifika zinciri.
   - **ServerKeyExchange (Sunucu -> İstemci):** Eğer Diffie-Hellman (DHE/ECDHE) kullanılıyorsa, sunucunun geçici açık anahtar parametreleri ve bu parametrelerin sunucu özel anahtarıyla imzalanmış hali.
   - **ServerHelloDone (Sunucu -> İstemci):** Sunucunun karşılama turunu bitirdiğini haber verir.
3. **TLS El Sıkışması 2. Gidiş-Dönüşü (2. RTT):**
   - **ClientKeyExchange (İstemci -> Sunucu):** İstemcinin geçici Diffie-Hellman açık anahtarı.
   - **[ChangeCipherSpec] & Finished (İstemci -> Sunucu):** İstemci, anahtarları türettiğini ve bundan sonraki paketlerin şifreli olacağını bildirir; el sıkışma özetini (Finished) iletir.
   - **[ChangeCipherSpec] & Finished (Sunucu -> İstemci):** Sunucu da oturum anahtarlarını teyit eder ve Finished paketini yollar.
4. **Veri Aktarımı (Application Data):**
   - Artık ilk HTTP `GET /index.html` isteği şifreli olarak gönderilebilir!

> **Usta Notu:** Fark ettiğin üzere, TCP (1 RTT) + TLS 1.2 (2 RTT) toplamda **3-RTT** gecikme demektir. Bir mobil kullanıcı için bu durum, sayfanın yüklenmesinden önce yüzlerce milisaniyelik kör bir bekleme süresi yaratır!

---

## 4. Modern Devrim: TLS 1.3 ve 1-RTT Mimarisi

2018 yılında yayımlanan **RFC 8446 (TLS 1.3)**, kriptografi dünyasında son yirmi yılın en köklü temizliğini yapmıştır. TLS 1.3 iki ana felsefeyle tasarlanmıştır:
1. **Daha Hızlı (1-RTT ve 0-RTT):** El sıkışma süresi tek bir gidiş-dönüşe indirilmiştir.
2. **Daha Güvenli (Kriptografik Budama):** Tarihi, güvensiz, kırılmış veya zayıf olan tüm algoritmalar protokolden tamamen kazınmıştır.

### 4.1. TLS 1.3 Nasıl 1-RTT'ye İndi?
TLS 1.3'te istemci, sunucunun hangi eliptik eğriyi destekleyeceğini tahmin eder (günümüzde internet trafiğinin %99'u `X25519` veya `secp256r1` kullanır). İstemci, daha ilk `ClientHello` paketinin içerisine `key_share` uzantısıyla kendi geçici (ephemeral) açık anahtarını koyar!

Sunucu `ServerHello` döndüğünde, kendi `key_share` anahtarını da aynı pakette geri verir. **Böylece 1. gidiş-dönüşün sonunda her iki taraf da ortak gizli anahtarı (Master Secret) hesaplamış olur!** Sunucu, sertifikasını ve el sıkışma Finished mesajını dahi şifreleyerek aynı pakette gönderir. İstemci 2. paketi aldığı anda hemen şifreli HTTP verisini basabilir!

### 4.2. TLS 1.3'ten Kazınan Güvensiz Algoritmalar:
- **Statik RSA Anahtar Değişimi:** Kesinlikle yasaklandı! Yalnızca geçici eliptik eğriler (`ECDHE`) veya sonlu alan Diffie-Hellman (`DHE`) zorunlu kılındı. Bu sayede **Kusursuz İletme Gizliliği (Perfect Forward Secrecy - PFS)** tavizsiz standart haline geldi.
- **CBC Modu Blok Şifreleme:** Lucky Thirteen, POODLE ve dolgu kahini (padding oracle) saldırılarına kapı araladığı için kaldırıldı. Yalnızca modern **AEAD (Authenticated Encryption with Associated Data)** modları (AES-GCM, ChaCha20-Poly1305, AES-CCM) kabul edilir.
- **RC4, 3DES, MD5, SHA-1:** Tamamen tedavülden kaldırıldı.
- **TLS Seviyesinde Sıkıştırma:** CRIME saldırısına yol açtığı için protokolden silindi.
- **Yeniden Müzakere (Renegotiation):** DoS ve MitM enjeksiyon riskleri nedeniyle kaldırıldı.

---

## 5. İleri Düzey Güvenlik Tehdit Modeli ve Saldırı Vektörleri

Bir güvenlik uzmanı olarak el sıkışma trafiğini incelerken aşağıdaki zaafiyet desenlerini ezbere bilmelisin:

### 5.1. Sürüm Düşürme (Downgrade) Saldırıları ve RFC 8446 Koruması
Saldırganlar, istemci ile sunucu arasına girerek (MitM), istemcinin gönderdiği `ClientHello` paketindeki TLS sürümünü değiştirip sunucuya "Bu istemci sadece eski TLS 1.2 (veya TLS 1.0) destekliyor" yalanını söyleyebilir. Amaç, modern korumaları bypass edip eski protokol açıklarını (POODLE, FREAK) sömürmektir.

**RFC 8446 Sentinel Çözümü:**
Eğer bir sunucu TLS 1.3 destekliyorsa ancak müzakere sonucunda istemciye TLS 1.2 ile yanıt veriyorsa, sunucu `ServerHello.random` alanının son 8 baytına şu sihirli değeri yazmak **zorundadır**:
$$\text{DOWNGRD\x01} \quad (0x444f574e47524401)$$
Eğer TLS 1.1 veya altına düşüyorsa:
$$\text{DOWNGRD\x02} \quad (0x444f574e47524402)$$
İstemci, kendisinin TLS 1.3 desteklediğini bildiği halde sunucu yanıtında bu sentinel baytlarını görürse, araya bir saldırganın girdiğini anlar ve bağlantıyı derhal bir **TLS Alert** ile sonlandırır!

### 5.2. CRIME Saldırısı (CVE-2012-4929) ve Sıkıştırma Tuzağı
TLS seviyesinde DEFLATE veri sıkıştırması açıldığında, saldırgan gizli bir çerezi (Session Cookie) yan kanal boyut analiziyle (Side-Channel Length Analysis) bayt bayt çalabilir. DEFLATE, ardışık benzer dizgileri sıkıştırıp paket boyutunu küçülttüğü için, saldırgan doğru harfi tahmin ettiğinde TLS paketinin boyutu 1 bayt kısalır. Bu sebeple TLS sıkıştırması **asla ve asla açılmamalıdır (yalnızca Null 0x00 kabul edilir)**.

### 5.3. SNI Sızıntısı ve ECH (Encrypted Client Hello)
Klasik TLS 1.3'te dahi, istemcinin bağlandığı alan adı (`SNI`) ilk pakette açık metin gider. Bu durum internet servis sağlayıcılarının ve sansür sistemlerinin hangi siteye girdiğinizi görmesine yol açar. Modern standart olan **ECH (Encrypted Client Hello)**, DNS üzerinden alınan açık anahtarla SNI alanını da şifreleyerek bu açığı kapatmaktadır.

### 5.4. 0-RTT Erken Veri ve Tekrar (Replay) Saldırısı
TLS 1.3'ün sunduğu 0-RTT özelliği, daha önce bağlanılmış bir sunucuya ilk pakette HTTP verisi gönderme lüksü tanır. Ancak ağdaki bir dinleyici bu 0-RTT paketini yakalayıp sunucuya tekrar tekrar basabilir! Bu yüzden 0-RTT yüklerinde asla durumu değiştiren istekler (`POST /para-transferi`) taşınmamalı, yalnızca idempotent ve güvenli istekler (`GET /index.html`) kabul edilmelidir.

---

## 6. Usta-Çırak Öğütleri ve Sektörel Pratik

1. **Sunucu Yapılandırmasında:** Nginx, Apache veya Envoy kullanırken `ssl_protocols TLSv1.2 TLSv1.3;` haricindeki tüm protokolleri (SSLv2, SSLv3, TLSv1, TLSv1.1) kapatacaksın.
2. **Şifreleme Paketlerinde:** Asla statik RSA içeren paketleri kabul etmeyeceksin; `ECDHE` şarttır.
3. **Wireshark İncelemesinde:** Port 443 trafiğini dinlerken `tls.handshake.type == 1` filtresiyle `ClientHello`, `tls.handshake.type == 2` ile `ServerHello` mesajlarını izleyeceksin.
4. **Sertifika Doğrulamasında:** İstemci tarafında `verify=False` veya `InsecureSkipVerify: true` parametresi yazan geliştiriciyi derhal uyaracaksın; bu parametre tüm HTTPS kalesini tek satırda yerle bir eder!

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Bu ders notu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
