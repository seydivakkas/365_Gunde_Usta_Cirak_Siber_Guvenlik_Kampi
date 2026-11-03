# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 110: TLS Güvenlik Sınırları (Transport Layer Security Boundaries)

## Usta-Çırak Başlangıç Hasbihali
**Usta:** Evlat, dün seninle dijital sertifikaların tüm yaşam evrelerini inceledik. Bir sertifikanın olması, elinde mühürlü bir kimlik kartı taşımak gibidir. Ancak o kimlik kartıyla iki yabancının (istemci ve sunucu) internetin güvensiz, dinlenen ve saldırgan kaynayan caddelerinde birbirine güvenerek gizli bir tünel açması, **TLS (Transport Layer Security)** protokolünün görevidir.

**Çırak:** Hocam, tarayıcıda kilit simgesini (HTTPS) gördüğümüzde verilerimizin tamamen güvende olduğunu düşünürüz. Ancak protokolün "güvenlik sınırları" derken tam olarak neyi kastediyoruz? Nerede başlar bu güvenlik, nerede biter?

**Usta:** Kilit simgesi sadece bir vitrindir evlat. Eğer altyapıda 1990'lardan kalma köhne bir şifreleme algoritması (örn. RC4, 3DES veya CBC modu) kullanılıyorsa, o kilit paslı bir tenekeden ibarettir! TLS protokolü, el sıkışma (Handshake) katmanından veri iletim (Record) katmanına kadar milimetrik hesaplanmış matematiksel sınırlarla örülüdür. Bugün seninle TLS 1.2'den TLS 1.3'e geçerken internetin hangi tarihi zafiyetleri tarihe gömdüğünü, Downgrade saldırılarının nasıl püskürtüldüğünü ve transkript bütünlüğünün nasıl sağlandığını adım adım inceleyeceğiz.

---

## 1. TLS Protokol Mimarisi ve İki Katmanlı Güvenlik Sınırı

TLS protokolü tek bir monolitik blok değildir; iki ana katmandan oluşur:

```
+----------------------------------------------------------------------------------+
| 1. ÜST KATMAN: EL SIKIŞMA VE YÖNETİM PROTOKOLLERİ                                |
|    - Handshake Protocol (RFC 8446): Sürüm, şifre paketi, anahtar değişimi        |
|    - Alert Protocol: Hata ve uyarı bildirimleri (Fatal / Warning)                |
|    - ChangeCipherSpec Protocol (TLS 1.2 mirası, TLS 1.3'te uyumluluk için dummy) |
+----------------------------------------------------------------------------------+
                                        |
                                        v
+----------------------------------------------------------------------------------+
| 2. ALT KATMAN: TLS RECORD PROTOKOLÜ (VERİ TAŞIMA VE ŞİFRELEME)                   |
|    - Çerçeveleme: [Content Type (1B) | Version (2B) | Length (2B) | Fragment]    |
|    - Simetrik Şifreleme ve AEAD Kimlik Doğrulama (Auth Tag)                      |
|    - Sıra Numarası (Sequence Number): Paket kaybı, kayması ve replay savunması   |
+----------------------------------------------------------------------------------+
```

### 1.1 Record Katmanı Güvenlik Sınırları (RFC 8446 Section 5)
1. **Azami Fragment Boyutu (16 KB Sınırı):** Bir TLS record fragment'ı en fazla $2^{14} = 16384$ bayt olabilir (CWE-20 taşma koruması). Daha büyük paketler arabellek taşması ve DoS riski nedeniyle anında reddedilir.
2. **Sıra Numarası (Sequence Number):** Her TLS oturumunda gönderilen ve alınan paketler için sıfırdan başlayan 64-bitlik bir monontonik sayaç tutulur. Bu sayaç açıkça ağda iletilmez; AEAD şifrelemede Nonce veya AAD içine gömülür. Böylece saldırgan aradan paket çalsa (`packet drop`) veya sırayı kaydırsa (`reordering`), alıcı taraf sıra numarası uyuşmazlığından bağlantıyı `bad_record_mac` fatal alert ile sonlandırır (CWE-353).
3. **AEAD Zorunluluğu:** Eski TLS sürümlerindeki **MAC-then-Encrypt** yaklaşımı (CBC modu), Lucky 13 ve POODLE gibi dolgu kehaneti (Padding Oracle) saldırılarına kapı aralamıştı. Modern TLS (özellikle TLS 1.3), yalnızca ilişkili verili kimlik doğrulamalı şifrelemeye (**AEAD - Authenticated Encryption with Associated Data**) izin verir (AES-GCM, ChaCha20-Poly1305).

---

## 2. TLS 1.2 vs TLS 1.3: Kriptografik Devrim ve Tasfiye Edilen Zafiyetler

IETF, 2018 yılında yayınladığı **RFC 8446 (TLS 1.3)** ile protokolün 20 yıllık kamburlarını tek bir hamlede kesip atmıştır.

| Güvenlik Özelliği | TLS 1.2 (RFC 5246) | TLS 1.3 (RFC 8446) | Güvenlik Gerekçesi (CWE) |
| :--- | :--- | :--- | :--- |
| **Statik RSA Anahtar Değişimi** | Desteklenir (Tehlikeli) | **Tamamen Yasaklandı** | Statik RSA'da sunucunun özel anahtarı ele geçerse geçmişteki tüm şifreli trafik çözülür (PFS yok / CWE-327). |
| **İleriye Dönük Gizlilik (PFS)** | İsteğe Bağlı (ECDHE/DHE) | **ZORUNLU (Yalnızca Ephemeral)** | Her oturumda geçici anahtarlar üretilir; sunucu anahtarı sızsa bile eski trafik çözülemez. |
| **Blok Şifreleme Modu** | CBC (HMAC ile) ve GCM | **Yalnızca AEAD** | CBC dolgu kehaneti (POODLE / Lucky 13) zafiyetlerini tamamen yok etmek için. |
| **Eski Algoritmalar** | RC4, 3DES, MD5, SHA-1 serbestti | **Tümü Yasaklandı** | Kırılmış algoritmaların (CWE-327) seçilmesini engellemek. |
| **El Sıkışma Gecikmesi** | 2-RTT (2 Gidiş-Dönüş) | **1-RTT (0-RTT Early Data seçeneği)** | Hız ve performans artışı; el sıkışma mesajlarının şifrelenmesi. |
| **Sertifika Gizliliği** | Düz metin olarak iletilir | **Handshake içinde Şifrelenir** | Ağ dinleyicilerinin hangi servise bağlanıldığını görmesini engellemek. |

---

## 3. Sürüm Düşürme Saldırıları ve Savunma Kalkanları (Downgrade Attacks)

Bir istemci ve sunucu her ikisi de TLS 1.3 desteklese bile, aradaki aktif bir saldırgan (MitM) el sıkışma paketlerini tahrif ederek tarafları zayıf bir sürüme (örn. TLS 1.0 veya SSL 3.0) düşürmeye çalışabilir. Buna tarihte **Downgrade Dance** adı verilmiştir (saldırgan sunucuyu POODLE zafiyetine zorlamak için bunu yapardı).

Modern TLS iki çelik kalkanla bu saldırıyı engeller:

### 3.1 TLS_FALLBACK_SCSV (RFC 7507)
Eğer bir istemci modern bir el sıkışma denerken ağ hatası alır ve uyumluluk adına daha eski bir sürümle yeniden denerse (Fallback), şifre paketleri listesine özel bir sinyal bayrağı ekler: `TLS_FALLBACK_SCSV (0x5600)`.
- Sunucu bu sinyali gördüğünde derhal kendi desteklediği en yüksek sürümü kontrol eder.
- Eğer sunucu istemcinin teklif ettiği sürümden daha yüksek bir sürümü (örn. TLS 1.3) destekliyorsa, aradaki saldırganın istemciyi kasten düşürdüğünü anlar!
- El sıkışmayı derhal `inappropriate_fallback` fatal alert ile sonlandırır (CWE-757 Savunması).

### 3.2 RFC 8446 Downgrade Sentinel Baytları
TLS 1.3 destekleyen bir sunucu, istemcinin `ClientHello` mesajına yanıt olarak TLS 1.2 sürümünü müzakere etmek zorunda kalırsa, `ServerHello` içerisindeki 32 baytlık rastgele değerin (`server_random`) son 8 baytını özel bir sihirli sabitle ezer:
$$\text{ServerRandom}[24..31] = \texttt{444F574E47524401} \quad (\text{"DOWNGRD\x01"})$$
Eğer istemci TLS 1.3 destekliyorsa, gelen `server_random` içindeki bu son 8 baytı kontrol eder. İstemci "ben 1.3 biliyorum ama sunucu 1.2 döndü ve içine bu sentinel'i koymuş; demek ki sunucu da aslında 1.3 biliyor ama aradaki saldırgan benim ClientHello'mu tahrif edip 1.3 teklifimi silmiş!" der ve bağlantıyı derhal keser (CWE-757 Savunması).

---

## 4. Transkript Bütünlüğü: Transcript-Hash ve Finished Mesajı (CWE-353)

El sıkışma sırasında saldırgan istemcinin sunduğu şifre paketleri listesinden güçlü olanları silip sadece zayıf olanları bıraksa ne olur?

İşte bu noktada **Transcript-Hash ve Finished Mesajı** devreye girer:
1. İstemci ve sunucu, el sıkışmanın ilk baytından son baytına kadar gönderilen ve alınan tüm mesajları sırasıyla bir özete ekler:
   $$\text{Transcript-Hash} = \text{SHA-256}(\text{ClientHello} \parallel \text{ServerHello} \parallel \text{EncryptedExtensions} \parallel \dots)$$
2. El sıkışmanın sonunda her iki taraf bir `Finished` mesajı gönderir. Bu mesaj, türetilen el sıkışma anahtarı (`handshake_traffic_secret`) kullanılarak transkript özetinin HMAC'idir:
   $$\text{VerifyData} = \text{HMAC}(\text{BaseKey}, \text{Transcript-Hash})$$
3. Eğer aradaki saldırgan tek bir biti bile değiştirmişse (örn. bir şifre paketini silmişse), sunucu ve istemcinin transkript özetleri birbirinden farklı çıkar.
4. `Finished` mesajındaki `VerifyData` doğrulaması başarısız olur ve bağlantı tek bir uygulama baytı bile iletilmeden `decrypt_error` fatal alert ile kapatılır!

---

## 5. TLS 1.3 0-RTT Erken Veri ve Tekrar Oynatma (Replay) Sınırı (CWE-294)

TLS 1.3, daha önce bağlanılmış bir sunucuya el sıkışma tamamlanmadan ilk pakette veri gönderme imkanı sunar (**0-RTT Early Data**). Bu, web sayfalarının açılışını olağanüstü hızlandırır.
- **Güvenlik Riski (CWE-294):** 0-RTT verileri Perfect Forward Secrecy taşımaz ve ağdaki pasif bir saldırgan bu paketi kopyalayıp sunucuya tekrar tekrar gönderebilir (Replay Saldırısı)!
- **Kritik Kural:** 0-RTT asla para transferi, sipariş onaylama veya şifre değiştirme gibi durumu değiştiren (non-idempotent) HTTP POST isteklerinde kullanılmamalıdır! Yalnızca güvenli GET isteklerinde kullanılabilir.
- **Sunucu Savunması:** Sunucu, işlediği 0-RTT biletlerini kayan bir zaman penceresinde tutan bir **Anti-Replay Cache** (tekrar oynatma engelleme önbelleği) barındırmalıdır.

---

## Ustanın Çırağa Öğüdü
Evlat! TLS güvenliği bir ayar dosyasına `ssl_protocols TLSv1.2 TLSv1.3;` yazıp unutulacak bir iş değildir. 
1. Asla statik RSA anahtar değişimine izin verme; her zaman Ephemeral Diffie-Hellman (PFS) kullan.
2. Zayıf şifreleri (RC4, 3DES, CBC) sisteminden kökünden kazı.
3. Downgrade saldırılarına karşı Fallback-SCSV ve Sentinel kontrollerini eksiksiz kıl. Unutma; en güçlü kale, kapısını ardına kadar açık unutan bir bekçi kadar savunmasızdır!
