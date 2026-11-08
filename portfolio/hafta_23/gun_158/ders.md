# Hafta 23 / Gün 158: Oturum Yönetimi ve Süresi

## Usta-Çırak / Hoca Dersi Notları

> **Usta:** *"Evladım, dün seninle oturum belirtecinin tarayıcıda nasıl taşınacağını (Cookies & Bayraklar) konuştuk. Bugün ise o belirtecin sunucu tarafındaki kalbini, yani 'Oturum Yönetimi ve Yaşam Döngüsü'nü (Session Management & Lifecycle) inşa edeceğiz. Bir oturum açıldığı andan kapandığı ana kadar sürekli denetlenmelidir. Eğer bir kullanıcı bilgisayarının başından kalkıp çay almaya gittiğinde oturumu açık kalıyorsa veya şifresini değiştirdiği halde eski oturumları kapanmıyorsa, o sistemde güvenlikten bahsedilemez!"*
>
> **Çırak:** *"Ustamm, bir oturumun yaşam döngüsünde 'Boşta Kalma Süresi' (Idle Timeout) ile 'Mutlak Süre' (Absolute Timeout) neden ayrı ayrı tanımlanır? Oturum sabitleme (Session Fixation) atağı nasıl çalışır?"*
>
> **Usta:** *"Bak evlat, boşta kalma süresi (örn. 15 dakika), ekran başında olmayan kullanıcıyı korur; kahve almaya giden memurun masasına oturan kötü niyetli biri işlem yapamaz. Mutlak süre ise (örn. 8 saat), kullanıcı ne kadar aktif olursa olsun günün sonunda oturumu zorla kapatır; böylece çalınan bir oturum belirteci sonsuza kadar kullanılamaz (Stolen Token Lifetime Bound). Oturum sabitleme ise saldırganın önceden bildiği bir oturum kimliğini kurbana kabul ettirip, kurban giriş yaptıktan sonra aynı kimlikle sisteme sızmasıdır. Bunu önlemenin tek yolu: Kimlik doğrulandığı an ve yetki değiştiği an eski oturumu çöpe atıp sıfırdan yeni ID üretmektir!"*

---

## 1. Oturum Yönetiminin Temel Sütunları

Oturum yönetimi; kimliği doğrulanmış bir kullanıcının durumunu (State) istekler arasında güvenle takip eden mekanizmadır. OWASP ve NIST SP 800-63B standartlarına göre sağlam bir oturum yönetimi şu kurallara dayanır:

```
+----------------------------------------------------------------------------------------------------+
|                               OTURUM YÖNETİMİ GÜVENLİK SÜTUNLARI                                   |
+----------------------------------------------------------------------------------------------------+
| 1. Kriptografik Rastgelelik  | secrets.token_hex(32) ile en az 128-bit (ideal 256-bit) entropi.    |
| 2. Boşta Kalma Zaman Aşımı   | 15-30 dakika inaktivite sonrası sunucu tarafında oturumu sonlandırma|
| 3. Mutlak Zaman Aşımı        | Kullanıcı aktif olsa bile 8-12 saat sonra oturumu zorla kapatma.   |
| 4. Oturum Sabitleme Kalkanı  | Login veya Yetki Değişiminde (Privilege Escalation) ID'yi yenileme. |
| 5. Eşzamanlı Oturum Limiti   | Kullanıcı başına maks 2-3 aktif oturum (Aşımda FIFO ile tasfiye).   |
| 6. Bağlam ve Cihaz Doğrulama | User-Agent ve IP uyuşmazlığında potansiyel hırsızlığı askıya alma.  |
| 7. Sunucu Taraflı İptal      | Logout anında bellekten/Redis'ten silme (Client silmesi yetmez!).   |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Derinlemesine Güvenlik Mekanizmaları

### 1. Kriptografik Olarak Güvenli Oturum Kimliği (CSPRNG & Entropi)
- **Hata:** Oturum ID'sini `md5(username + time())` veya `random.randint()` ile üretmek. Bu değerler tahmin edilebilirdir (Predictable).
- **Standart:** Python `secrets.token_hex(32)` veya `secrets.token_urlsafe(32)` kullanılır. Bu fonksiyon işletim sisteminin kriptografik entropi havuzundan (`/dev/urandom` veya Windows CryptGenRandom) beslenir. 32 bayt hex (64 karakter) yaklaşık 256 bit Shannon entropisi sağlar; kaba kuvvetle tahmin edilmesi trilyonlarca yıl sürer.

### 2. İki Kademeli Zaman Aşımı Mimarisi
- **Boşta Kalma Zaman Aşımı (Idle Timeout):** `now - last_activity_epoch > 900 sn (15 dk)`. Her geçerli HTTP isteğinde `last_activity_epoch` güncellenir. Kullanıcı 15 dakika boyunca istek atmazsa oturum `EXPIRED_IDLE` olur.
- **Mutlak Oturum Zaman Aşımı (Absolute Timeout):** `now - created_at_epoch > 28800 sn (8 saat)`. Kullanıcı hiç durmadan her saniye tıklasa bile, oturum açıldığı andan itibaren 8 saat geçtiğinde `EXPIRED_ABSOLUTE` olur ve kullanıcı login ekranına yönlendirilir. Bu sayede sızdırılmış belirteçlerin geçerlilik penceresi sınırlandırılır.

### 3. Oturum Sabitleme (Session Fixation) ve Dinamik Rotasyon
- **Saldırı Senaryosu:** Saldırgan web sitesine gider ve henüz giriş yapmamışken `SID=12345` oturumunu alır. Kurbana `https://banka.com/?sid=12345` linkini atar. Kurban giriş yapar (Login). Eğer sunucu oturum kimliğini yenilemezse, saldırgan da elindeki `12345` kimliği ile sisteme girdiğinde kurbanın hesabına erişir!
- **Kusursuz Savunma:**
  1. Kullanıcı başarıyla kimlik doğruladığında (Login),
  2. Kullanıcı rolü yükseldiğinde (Örn: Normal kullanıcıdan Yönetici ekranına geçiş),
  3. Periyodik olarak (Örn: Her 30 dakikada bir),
  Mevcut oturum kimliği **sunucu tarafında derhal iptal edilmeli (`REVOKED`)** ve istemciye yepyeni bir oturum kimliği tahsis edilmelidir (`regenerate_session_id`).

### 4. Bağlam Bağlama (Context Binding) ve Oturum Kaçırma (Hijacking) Tespiti
- Oturum oluşturulduğu an istemcinin `User-Agent` başlığı ve kaynak `IP adresi` oturum nesnesine mühürlenir.
- Bir oturum belirteci XSS veya ağ dinlemesi ile çalındığında, saldırgan genellikle farklı bir tarayıcı (örneğin cURL, Python betiği veya farklı bir işletim sistemi) ve farklı bir IP adresi üzerinden bağlanır.
- Motorumuz gelen her istekte bu bağlamı doğrular; bariz bir User-Agent veya IP sapması tespit ettiğinde oturumu derhal `SUSPENDED_HIJACK_RISK` durumuna alarak erişimi keser.

### 5. Sunucu Taraflı İptal (Server-Side Revocation)
- **Büyük Yanılgı:** Yalnızca tarayıcıdaki çerezi silmek (`Max-Age=0`). Eğer sunucu veritabanında/önbelleğinde o oturumu silmezse, tarayıcı geçmişinden veya proxy loglarından o çerezi bulan biri oturumu kullanmaya devam edebilir.
- **Doğru Uygulama:** Logout butonuna basıldığı an, sunucu oturum tablosundan oturum kimliğini tamamen siler veya durumunu `REVOKED` yapar. Ayrıca şifre değiştirildiğinde `terminate_all_user_sessions` ile kullanıcının telefon, tablet ve PC'deki tüm oturumları tek tuşla sonlandırılmalıdır.

---

## 3. Geliştirilen SessionManagerEngine Mimarisi

Bugün geliştirdiğimiz motor, oturumların durum makinesini (State Machine) şu akışla yönetir:

```
[ GİRİŞ ] ---> ACTIVE ---> (İstekler: last_activity güncellenir)
                 |
                 +---> İnaktivite > 15 dk  ---> [ EXPIRED_IDLE ]
                 |
                 +---> Toplam Süre > 8 saat ---> [ EXPIRED_ABSOLUTE ]
                 |
                 +---> User-Agent Uyuşmazlığı -> [ SUSPENDED_HIJACK ]
                 |
                 +---> Logout / İptal      ---> [ REVOKED ]
                 |
                 +---> 30 dk Doldu / Yetki  ---> [ ROTATED ] (Yeni ID)
```

Motor, bellek sızıntısını önlemek için `clean_expired_sessions` çöp toplayıcı (Garbage Collector) fonksiyonu ile süresi biten oturumları otomatik tasfiye eder.

---

## Özet ve Ustanın Altın Kuralı

> *"Evladım, oturum yönetiminde altın kural şudur: Oturumu istemci değil, sunucu yönetir! İstemci sadece bir belirteç (token) taşır. O belirtecin ne zaman öleceğine, ne zaman yenileneceğine ve ne zaman iptal edileceğine yalnızca sunucundaki sıkı güvenlik politikası karar vermelidir!"*
