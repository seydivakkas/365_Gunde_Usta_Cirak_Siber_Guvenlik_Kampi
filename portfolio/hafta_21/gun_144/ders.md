# Gün 144: Kerberos v5 Temel Bilet Akışı — Usta-Çırak Dersi

**Modül:** Hafta 21 / Gün 144 (Excel Satır 148)  
**Konu:** Kerberos v5 Temel Bilet Akışı, KDC Biletleme Yaşam Döngüsü ve Saldırı/Savunma Mekanizmaları  
**Standartlar:** RFC 4120 (Kerberos v5), RFC 3962 (AES Encryption for Kerberos), NIST SP 800-63B, MITRE ATT&CK T1558  
**Usta:** Seydi Eryılmaz (@seydivakkas)  

---

## 1. Ustanın Giriş Dersi: "Ağda Parola Uçurma, Bilet Takas Et!"

> **Usta:** "Yaklaş çırak! Ağ güvenliğinde en büyük zafiyet nedir bilir misin? İstemcinin her erişmek istediği sunucuya kendi parolasını veya hash değerini göndermesidir. Eğer her sunucuya parolanı verirsen, o sunuculardan biri ele geçirildiğinde senin tüm kimliğin rehin düşer.
>
> İşte 1980'lerin sonunda MIT'de geliştirilen ve bugün tüm kurumsal Active Directory dünyasının kalbinde atan **Kerberos**, tam olarak bu sorunu kökünden çözmek için tasarlandı. Yunan mitolojisindeki üç başlı muhafız köpeğinden (Cerberus) adını alır. Çünkü sistemde üç bağımsız taraf vardır:
> 1. **İstemci (Client)**
> 2. **Hedef Servis (Application Server)**
> 3. **Anahtar Dağıtım Merkezi (Key Distribution Center - KDC)**
>
> Kerberos'ta istemci asla hedef sunucuya parolasını göndermez. Bunun yerine KDC'den aldığı kriptografik 'biletleri' (Tickets) ve 'kanıtlayıcıları' (Authenticators) takas eder. Şimdi arkana yaslan, bu üç başlı bilet çarkının dişlilerini tek tek sökeceğiz."

---

## 2. KDC Anatomisi ve Kerberos 3 Aşamalı Bilet Akışı (RFC 4120)

Kerberos v5 kimlik doğrulama süreci üç temel aşamadan oluşur:

```text
  +------------------+         KDC (Key Distribution Center)        +-------------------+
  |                  |    +--------------------------------------+   |                   |
  |  İSTEMCİ (Client)|    | Authentication Service (AS)          |   |  UYGULAMA SUNUCUSU|
  |                  |    | [KRBTGT Anahtarı ile TGT İmzalar]    |   |  (Target Service) |
  +--------+---------+    +------------------+-------------------+   +---------+---------+",
           |                                 |                                 |
           |  1. AS-REQ (Kullanıcı + PA-ENC) |                                 |
           |────────────────────────────────>|                                 |
           |  2. AS-REP [TGT (krbtgt anahtarlı)                               |
           |             + Oturum Anahtarı K_c_t]                              |
           |<────────────────────────────────|                                 |
           |                                                                   |
           |             +---------------------------------------+             |
           |             | Ticket Granting Service (TGS)         |             |
           |             | [Hedef SPN Anahtarı ile ST Şifreler]  |             |
           |             +----------------───+───────────────────+             |
           |                                 |                                 |
           |  3. TGS-REQ [TGT + Authenticator|                                 |
           |             + Hedef SPN]        |                                 |
           |────────────────────────────────>|                                 |
           |  4. TGS-REP [Servis Bileti (ST) |                                 |
           |             + Oturum Anahtarı K_c_s]                              |
           |<────────────────────────────────|                                 |
           |                                                                   |
           |  5. AP-REQ [Servis Bileti + Authenticator (K_c_s)]                |
           |──────────────────────────────────────────────────────────────────>|
           |  6. AP-REP [Karşılıklı Doğrulama - Mutual Authentication]         |
           |<──────────────────────────────────────────────────────────────────|
```

---

### Aşama 1: Authentication Service (AS) Takası (Oturum Açma)

1. **AS-REQ (Authentication Service Request):**
   - İstemci kullanıcı adını (`canan@KURUM.LOCAL`) ve talep ettiği bilet türünü KDC'ye bildirir.
   - **Pre-Authentication (Ön Kimlik Doğrulama - PA-ENC-TIMESTAMP):** İstemci, anlık zaman damgasını kendi parolasından türetilen gizli anahtarla şifreler.
   - **Neden Önemlidir?** KDC, gelen zaman damgasını kullanıcının veritabanındaki anahtarıyla çözer. Eğer çözülemezse veya istemci saati DC saatinden 300 saniyeden fazla sapmışsa (`CLOCK_SKEW`), isteği reddeder. Bu, saldırganların parolasız bilet istemesini engeller.
2. **AS-REP (Authentication Service Response):**
   - KDC iki kritik veri paketi döner:
     - **TGT (Ticket Granting Ticket):** Yalnızca etki alanının `krbtgt` hesabı tarafından bilinen gizli simetrik anahtarla şifrelenmiştir. İstemci bu paketin içini okuyamaz ve değiştiremez.
     - **İstemci-KDC Oturum Anahtarı ($K_{c,t}$):** İstemcinin parola anahtarıyla şifrelenmiştir; istemci bunu çözerek RAM belleğinde saklar.

---

### Aşama 2: Ticket Granting Service (TGS) Takası (Servis Bileti İsteme)

1. **TGS-REQ (Ticket Granting Service Request):**
   - İstemci ağdaki bir kaynağa (örn. dosya sunucusu `cifs/fs01.kurum.local`) bağlanmak ister.
   - İstemci KDC'ye üç parça veri sunar:
     - Daha önce aldığı **TGT** bileti.
     - **Authenticator (Kanıtlayıcı):** $K_{c,t}$ oturum anahtarıyla şifrelenmiş anlık zaman damgası ve istemci adı.
     - Hedef servisin **SPN** (Service Principal Name) kaydı.
2. **TGS-REP (Ticket Granting Service Response):**
   - KDC önce TGT'yi kendi `krbtgt` anahtarıyla çözer; biletin geçerli ve süresinin dolmamış olduğunu doğrular.
   - Ardından Authenticator'ı $K_{c,t}$ ile çözer; zaman damgası sapmasını ve daha önce kullanılıp kullanılmadığını (Replay Cache) denetler.
   - Her şey yolundaysa hedef servisin parola anahtarıyla şifrelenmiş **Servis Biletini (ST/TGS)** ve istemci ile servis arasında kullanılacak yeni oturum anahtarını ($K_{c,s}$) üretir.

---

### Aşama 3: Application (AP) Takası (Uygulama Erişimi)

1. **AP-REQ (Application Request):**
   - İstemci hedef sunucuya doğrudan bağlanır.
   - TGS Servis Biletini ve $K_{c,s}$ oturum anahtarıyla şifrelenmiş yeni bir **Authenticator** gönderir.
2. **Hedef Sunucu Doğrulaması:**
   - Hedef sunucu, bileti kendi özel servis anahtarıyla çözer.
   - Bilet içindeki PAC (Privilege Attribute Certificate) yapısını inceler. PAC içinde istemcinin kullanıcı SID'si ve üye olduğu güvenlik grupları yer alır.
   - Sunucu PAC imzasını (Server Signature) kontrol eder.
3. **AP-REP (Karşılıklı Doğrulama - Mutual Auth):**
   - Hedef sunucu, istemcinin gönderdiği zaman damgasını $K_{c,s}$ ile şifreleyip geri dönerek kendisinin de gerçek sunucu olduğunu istemciye kanıtlar (DNS zehirlemesi ve Man-in-the-Middle savunması).

---

## 3. PAC (Privilege Attribute Certificate) ve HMAC Mimarisi

Standart Kerberos RFC 4120'de biletler yalnızca kullanıcının kim olduğunu (`Principal`) doğrular; kullanıcının hangi yetkilere sahip olduğunu söylemez.

Microsoft, Active Directory için Kerberos protokolüne **PAC (Privilege Attribute Certificate)** uzantısını eklemiştir:
- **Kullanıcı SID ve Grup RID Listesi:** Kullanıcının Domain Users, Domain Admins gibi üyelikleri biletin içine gömülür.
- **Server Signature:** Biletin hedef servis anahtarı ile üretilen HMAC-SHA256 imzasıdır.
- **KDC Signature:** KDC'nin kendi `krbtgt` anahtarı ile sunucu imzasını mühürlediği ikinci imzadır.

Bu çift imza yapısı sayesinde:
- Bir kullanıcı biletin içindeki grup listesini değiştirip kendini yönetici yapmaya kalkarsa sunucu imzası bozulur.
- Bir sunucu yöneticisi kendi servis anahtarıyla yetkileri şişirmeye çalışırsa KDC imzası bozulur.

---

## 4. Kerberos Saldırı Vektörleri ve Tespit Yöntemleri

| Saldırı Adı | MITRE ID | Mekanizma | Motorumuzun Tespit Mantığı |
|-------------|----------|-----------|----------------------------|
| **AS-REP Roasting** | T1558.004 | `DONT_REQ_PREAUTH` bayrağı açık hesaplar için şifresiz AS-REQ çekilip çevrimdışı kırılır | `PREAUTH_VULNERABILITY`: Ön kimlik doğrulaması kapatılmış hesapları anında bayraklar |
| **Kerberoasting** | T1558.003 | Servis biletleri (TGS) zayıf RC4 şifrelemeyle talep edilip çevrimdışı parola kırılır | `CIPHER_SUITE_DOWNGRADE`: RC4 ve DES taleplerini anında engeller, AES zorlar |
| **Golden Ticket** | T1558.001 | Çalınan `krbtgt` anahtarıyla sahte TGT üretilip 10 yıl geçerli kılınır | `GOLDEN_TICKET_DETECTED`: KDC anahtarıyla uyuşmayan sahte biletleri yakalar |
| **Silver Ticket** | T1558.002 | Servis anahtarıyla KDC'ye hiç gitmeden sahte Servis Bileti üretilir | `SILVER_TICKET_DETECTED`: Hedef sunucunun anahtarıyla bilet şifresini çözüp doğrular |
| **Yeniden Oynatma** | T1550 | Ağdan yakalanan bilet ve kanıtlayıcı tekrar gönderilir | `REPLAY_ATTACK_DETECTED`: Zaman damgası ve cusec değerini Replay Cache'te denetler |
| **Saat Sapması** | CWE-384 | Sahte biletleri geçersiz kılınan pencerelerde çalıştırma girişimi | `CLOCK_SKEW`: DC ile istemci arasındaki fark 300 saniyeyi aştığında reddeder |

---

## 5. Ustanın Çırağa Öğütleri

> "Çırak, kulağına küpe olsun:
> 1. **Saat her şeydir:** Bir etki alanında NTP senkronizasyonu çökerse Kerberos durur, Kerberos durursa kimse oturum açamaz. Saat sapmasını asla 5 dakikanın üzerine çıkarma.
> 2. **RC4'e veda et:** Active Directory ortamında RC4 şifreleme açık kaldığı sürece ağındaki her servis hesabı Kerberoasting ile kırılmaya mahkumdur. GPO ile yalnızca AES-128 ve AES-256 zorlaması yap.
> 3. **Ön kimlik doğrulamayı kapatma:** Bir yazılımcı gelip 'eski servisimiz bağlanamıyor, Kerberos Pre-Auth kutucuğunu kaldırır mısınız' dediğinde, ona 'kapının kilidini sökelim mi' diye sor. `DONT_REQ_PREAUTH` bayrağı AS-REP Roasting'e davetiyedir!"
