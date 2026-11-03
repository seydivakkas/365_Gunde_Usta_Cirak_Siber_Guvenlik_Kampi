# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 110: TLS Güvenlik Sınırları — Soru ve Cevaplar

---

## Soru 1: TLS 1.2 vs TLS 1.3 Mimarisi ve Perfect Forward Secrecy (PFS) Zorunluluğu

### 1. Soru Başlığı ve Tanımı
TLS 1.2 (RFC 5246) ile TLS 1.3 (RFC 8446) arasındaki temel mimari güvenlik sınırları nelerdir? TLS 1.3 protokolünde Statik RSA anahtar değişiminin tamamen yasaklanmasının ve Ephemeral Diffie-Hellman (ECDHE/DHE) ile İleriye Dönük Gizliliğin (Perfect Forward Secrecy - PFS / CWE-327) zorunlu kılınmasının teknik gerekçeleri nelerdir?

### 2. Derinlemesine Teknik Analiz
TLS 1.2'ye kadar olan protokol sürümlerinde anahtar değişimi için iki ana yöntem kullanılıyordu:
1. **Statik RSA Anahtar Değişimi (`TLS_RSA_WITH_*`):** İstemci 48 baytlık bir `Pre-Master Secret` üretir, bunu sunucunun sertifikasındaki genel anahtar (`Public Key`) ile şifreler ve sunucuya gönderir. Sunucu kendi özel anahtarıyla (`Private Key`) bunu çözer ve her iki taraf `Master Secret`'ı türetir.
2. **Geçici Diffie-Hellman (ECDHE / Ephemeral Diffie-Hellman):** Her iki taraf el sıkışma anında anlık, geçici (ephemeral) anahtar çiftleri üretir ve Diffie-Hellman matematiksel prensibiyle ortak sır türetilir. Sunucunun sertifikası yalnızca bu değişimi imzalamak için kullanılır.

**Statik RSA'nın Ölümcül Kusuru (PFS Eksikliği / CWE-327):**
Statik RSA'da oturum anahtarını koruyan tek şey, sunucunun diskinde duran RSA özel anahtarıdır.
- Eğer bir istihbarat teşkilatı veya saldırgan, bir şirketin şifreli TLS trafiğini 5 yıl boyunca ağ üzerinden kaydedip saklarsa (**Harvest Now, Decrypt Later**);
- 5 yıl sonra şirketin sunucusu emekliye ayrıldığında veya özel anahtar bir şekilde sızdığında (örn. Heartbleed zafiyeti veya bir çalışanın diski satmasıyla);
- Saldırgan geriye dönük olarak son 5 yılda kaydedilmiş tüm TLS oturumlarının `Pre-Master Secret`'ını tek tek çözer ve geçmişe dönük milyonlarca kullanıcının bankacılık şifrelerini, e-postalarını ve gizli verilerini açığa çıkarır!

**TLS 1.3'ün Güvenlik Sınırı Çözümü:**
TLS 1.3, statik RSA anahtar değişimini, CBC modunu ve zayıf algoritmaları tamamen protokol standardından kazımıştır:
- Yalnızca **ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)** ve **DHE** anahtar değişimine izin verilir.
- Her el sıkışmada geçici anahtarlar üretilir ve oturum bittiğinde bellekten silinir.
- Sunucunun anahtarı daha sonra ele geçirilse bile, geçmişteki geçici anahtarlar artık var olmadığı için eski oturumların deşifre edilmesi matematiksel olarak imkansızdır (Perfect Forward Secrecy garantisi).
- Ayrıca tüm şifreleme paketleri zorunlu olarak **AEAD** (AES-GCM, ChaCha20-Poly1305) olmak zorundadır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir telekom operatörünün eski fatura ödeme portalında TLS 1.2 üzerinde `TLS_RSA_WITH_AES_128_CBC_SHA` şifre paketi aktif bırakılmıştır. Şirketin sunucu odasından çalınan eski bir yedek teybindeki RSA özel anahtarı APT grubu tarafından ele geçirilmiş ve siber saldırganlar son 2 yıl boyunca pasif dinlemeyle kaydettikleri 40 milyon abonenin kredi kartı ödeme paketlerini topluca deşifre etmiştir.

**Pratik Çözüm:**
Sunucu TLS yapılandırmasında statik RSA paketleri devre dışı bırakılmalı, TLS 1.3 önceliklendirilmeli ve TLS 1.2 için yalnızca ECDHE zorunlu tutulmalıdır:
```nginx
# Güvenli Nginx Yapılandırması (Yalnızca TLS 1.3 ve Güçlü TLS 1.2 PFS)
ssl_protocols TLSv1.3 TLSv1.2;
ssl_prefer_server_ciphers off; # TLS 1.3'te istemci şifre önceliği
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_ecdh_curve X25519:secp384r1:prime256v1;
```

### 4. Ustanın Çırağa Tavsiyesi
Çırak! Bugünü korumak marifet değildir; usta bir güvenlik mühendisi bugünün verisini gelecekteki hırsızlardan da koruyandır. Statik RSA kullanmak, evin tüm kilitlerini açan tek bir anahtarı çekmecede unutmaya benzer. Her misafire anlık, kendini imha eden geçici anahtarlar ver (ECDHE); çekmecen kırılsa bile geçmişte kimin ne konuştuğunu felek bile çözemesin!

---

## Soru 2: Sürüm Düşürme (Downgrade Dance) Saldırıları ve Savunma Kalkanları

### 1. Soru Başlığı ve Tanımı
TLS el sıkışmasında sürüm düşürme (Downgrade Dance) saldırısı (CWE-757) nedir ve aradaki bir saldırgan (MitM) bu saldırıyı nasıl organize eder? **TLS_FALLBACK_SCSV (RFC 7507)** ve RFC 8446 **Downgrade Sentinel** baytları bu saldırıları el sıkışma aşamasında nasıl imkansız hale getirir?

### 2. Derinlemesine Teknik Analiz
Tarihsel olarak web tarayıcıları, internetteki eski veya kötü yapılandırılmış web sunucularıyla el sıkışırken "uyumluluk" sağlamak adına esnek davranırdı:
1. Tarayıcı önce TLS 1.2 ile bağlanmayı denerdi.
2. Eğer bağlantı koparsa veya TCP Reset gelirse, tarayıcı "sunucu eski herhalde" diyerek otomatik olarak TLS 1.0 ile yeniden denerdi.
3. O da koparsa SSL 3.0 ile denerdi (**Downgrade Dance**).

**Saldırganın İstismarı (CWE-757):**
Araya giren bir saldırgan (MitM), istemcinin TLS 1.2/1.3 el sıkışma paketlerini bozar veya TCP RST atarak bağlantıyı düşürür. Tarayıcı otomatik olarak SSL 3.0 seviyesine inene kadar saldırgan bu sabote işlemini sürdürür. Sonunda hem modern istemci hem de modern sunucu SSL 3.0 ile el sıkışır ve saldırgan bilinen **POODLE** (Padding Oracle On Downgraded Legacy Encryption) zafiyetini kullanarak oturum çerezlerini deşifre eder!

**Savunma Kalkanı 1: TLS_FALLBACK_SCSV (RFC 7507):**
Tarayıcı bir sürüm düşürme (fallback) durumuna girdiğinde, şifre paketleri listesine yapay bir değer ekler: `TLS_FALLBACK_SCSV (0x5600)`.
- Bu değer bir şifre algoritması değil, bir alarm sinyalidir.
- Sunucu `ClientHello` içinde bu sinyali gördüğünde şu denetimi yapar:
  $$\text{Eğer } \text{ClientVersion} < \text{ServerHighestVersion} \implies \text{ABORT (inappropriate\_fallback)}$$
- Sunucu, istemcinin teklif ettiği sürümden daha yüksek bir sürümü destekliyorsa araya girildiğini anlar ve el sıkışmayı derhal öldürür.

**Savunma Kalkanı 2: RFC 8446 Downgrade Sentinel:**
TLS 1.3 destekleyen bir sunucu, istemciyle TLS 1.2 müzakere etmek zorunda kaldığında, `ServerHello` içerisindeki 32 baytlık rastgele sayının (`server_random`) son 8 baytını özel bir sihirli sabitle ezer:
$$\text{ServerRandom}[24..31] = \texttt{444F574E47524401} \quad (\text{"DOWNGRD\x01"})$$
- Eğer istemci TLS 1.3 destekliyorsa ve sunucu ona TLS 1.2 döndüyse, istemci `server_random`'ın sonuna bakar.
- Bu sihirli diziyi gördüğü an anlar ki: Sunucu aslında TLS 1.3 biliyor! Demek ki istemcinin `ClientHello`'sundaki TLS 1.3 teklifi aradaki saldırgan tarafından silinmiştir!
- İstemci bağlantıyı anında `illegal_parameter` fatal alert ile keser.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Kurumsal bir Wi-Fi ağında (otelde veya havalimanında) araya giren siber saldırgan, şirket çalışanlarının VPN bağlantılarını düşürmek için el sıkışma paketlerine RST enjekte ederek istemcileri eski protokollere zorlamaktadır.

**Pratik Çözüm:**
Uygulama ve sunucu kütüphanelerinde Fallback-SCSV ve Sentinel kontrolleri zorunlu kılınmalıdır:
```python
# Sunucu tarafında Fallback-SCSV kontrol mekanizması
if "TLS_FALLBACK_SCSV" in client_ciphers:
    if server_highest_version > client_offered_version:
        raise TLSDowngradeDetectedError(
            "CWE-757: TLS_FALLBACK_SCSV sinyali alındı; araya girme ve sürüm düşürme saldırısı tespit edildi!"
        )
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, siber alemde "eskiyle de uyumlu olsun, kimseyi üzmeyelim" demek, hırsıza arka kapıyı açık bırakmaktır. Bir protokol eskidiyse (SSL 3.0, TLS 1.0, TLS 1.1) onu sisteminden söküp atacaksın. Uyumluluk adına taviz veren her sistem, gün gelir o tavizin bedelini veri sızıntısıyla öder!

---

## Soru 3: Transkript Bütünlüğü, Record Sıra Numaraları ve 0-RTT Replay Tehdidi

### 1. Soru Başlığı ve Tanımı
TLS el sıkışmasında **Transcript-Hash ve Finished Mesajı** el sıkışma bütünlüğünü (CWE-353) nasıl temin eder? TLS Record katmanındaki **Sıra Numarası (Sequence Number)** hangi saldırıları önler? TLS 1.3'ün getirdiği **0-RTT Erken Veri (Early Data)** özelliği neden Replay saldırılarına (CWE-294) açıktır ve nasıl korunmalıdır?

### 2. Derinlemesine Teknik Analiz
**1. Transkript Bütünlüğü (Transcript-Hash):**
Bir saldırgan `ClientHello` paketindeki güçlü şifre paketlerini silip yerine daha zayıf paketler yazsa ne olur?
El sıkışmanın en sonunda her iki taraf bir `Finished` mesajı üretir:
$$\text{VerifyData} = \text{HMAC}(\text{HandshakeSecret}, \text{SHA-256}(\text{ClientHello} \parallel \text{ServerHello} \parallel \dots))$$
Aradaki saldırgan şifre paketlerini değiştirmişse, istemcinin gönderdiği `ClientHello` ile sunucunun aldığı `ClientHello` farklı baytlardan oluşacaktır. Bu durumda iki tarafın transkript özetleri uyuşmaz, `Finished` doğrulaması başarısız olur ve bağlantı tek bir uygulama baytı bile iletilmeden kopar (CWE-353 koruması).

**2. Record Sıra Numarası (Sequence Number):**
TLS Record katmanında her paket için 64-bitlik bir monontonik sayaç ($0, 1, 2, \dots$) tutulur.
- Bu numara paketin açık başlığında iletilmez; AEAD kimlik doğrulama etiketi hesaplanırken ilişkili veri (AAD) veya Nonce olarak dahil edilir.
- **Engellenen Saldırılar:**
  - **Paket Çalma (Packet Drop):** Saldırgan aradan 3. paketi düşürürse, alıcı 4. paketi aldığında sayaç uyuşmazlığından AEAD etiketi geçersiz çıkar.
  - **Paket Sıralama Bozma (Reordering):** Saldırgan paketlerin sırasını değiştirirse şifre çözülemez.
  - **Oynatma (Replay):** Eski bir şifreli paketi tekrar ağa bassa bile alıcının sayacı ilerlemiş olduğu için paket anında `bad_record_mac` ile çöpe atılır.

**3. TLS 1.3 0-RTT Erken Veri ve Replay Tehlikesi (CWE-294):**
TLS 1.3, önceden bağlanılmış bir sunucuya el sıkışmayı beklemeden ilk pakette veri gönderme (0-RTT) imkanı sağlar.
- **Tehdit:** 0-RTT paketi eski bir oturum biletine (`resumption_master_secret`) dayandığı için ve henüz sunucu rastgeleliği (`server_random`) el sıkışmasında üretilmediği için bu paket statiktir. Ağdaki bir saldırgan bu paketi yakalayıp sunucuya 100 defa gönderebilir!
- Eğer bu paket `POST /api/transfer?amount=1000TL` ise, kullanıcının hesabından 100 defa para transferi gerçekleşir!
- **Savunma:**
  1. **HTTP Kuralı (RFC 8446 Section 8):** 0-RTT içinde ASLA durumu değiştiren non-idempotent (POST/PUT/DELETE) istekler iletilmemelidir; yalnızca güvenli GET isteklerine izin verilmelidir.
  2. **Anti-Replay Cache:** Sunucu, işlediği 0-RTT bilet kimliklerini (ticket identifiers) ve zaman damgalarını kayan bir pencerede saklamalı; aynı bilet ikinci kez gelirse isteği reddetmeli veya 1-RTT el sıkışması tamamlanana kadar bekletmelidir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir online oyun sunucusu, oyuncuların yeniden bağlanma süresini sıfırlamak için TLS 1.3 0-RTT erken verisini etkinleştirmiş ve oyun içi eşya satın alma API'sini (`POST /buy_item`) 0-RTT ile kabul etmiştir. Bir oyuncu ağ paketini yakalayıp 1000 kez sunucuya replay ederek tek bir ödeme ile 1000 adet zırh elde etmiştir.

**Pratik Çözüm:**
Sunucu yazılımında 0-RTT yalnızca güvenli GET isteklerine sınırlandırılmalı ve anti-replay önbelleği işletilmelidir:
```python
# TLS 1.3 0-RTT Güvenlik Doğrulaması
def handle_incoming_request(request, is_0rtt_early_data: bool, replay_cache):
    if is_0rtt_early_data:
        # 1. Kural: Yalnızca idempotent GET isteklerine izin ver
        if request.method != "GET":
            raise TLSError("0-RTT Erken Veri içinde güvensiz durum değiştiren istek yasaktır!")
        # 2. Kural: Anti-Replay kontrolü
        replay_cache.process_early_data(request.ticket_id, request.body)
    # İsteği işle
    return execute_request(request)
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat! Hız, güvenliğin düşmanı olmamalıdır. 0-RTT sana web sayfalarını göz açıp kapayıncaya kadar açma hızını verir ama tedbirini almazsan o hız seni uçurumdan aşağı yuvarlar. Finansal veya kritik işlemlerde 1-RTT'nin 50 milisaniyelik el sıkışma bedelini seve seve ödeyeceksin; güvenliğin bedeli bir göz kırpma süresidir, faturası ise bir ömür sürer!
