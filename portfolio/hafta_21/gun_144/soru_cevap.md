# Gün 144: Kerberos Temel Bilet Akışı — Soru & Cevap

Bu belgede RFC 4120 Kerberos v5 bilet yaşam döngüsü, kanıtlayıcılar (Authenticators), Replay Cache, PAC HMAC doğrulaması, saat senkronizasyonu ve sahte bilet saldırılarına (Golden & Silver Ticket) karşı kurumsal savunma pratikleri usta-çırak diyaloguyla derinlemesine incelenmiştir.

---

### Soru 1: Kerberos Kanıtlayıcı (Authenticator), Saat Sapması (Clock Skew) ve Replay Cache Savunması

#### 1. Soru Başlığı ve Tanımı
**Yeniden Oynatma Saldırıları ve Kanıtlayıcı Bütünlüğü:** Bir saldırgan ağ trafiğini dinleyerek (sniffing) geçerli bir TGS-REQ veya AP-REQ isteğini ele geçirirse, bu isteği hedef sunucuya tekrar göndererek oturum açabilir mi? Kerberos'taki Kanıtlayıcı (Authenticator), 300 saniyelik saat sapması (clock skew) sınırı ve Replay Cache önbelleği bu saldırıyı nasıl engeller?

#### 2. Derinlemesine Teknik Analiz
Kerberos protokolünde biletler tek başlarına kimlik doğrulama için yeterli değildir; çünkü bilet çalınabilir. Bu nedenle her biletin yanında bir **Authenticator (Kanıtlayıcı)** sunulması zorunludur:
1. **Kanıtlayıcının Rolü:** Kanıtlayıcı; istemcinin adı (`client_name`), ait olduğu etki alanı (`realm`), isteğin oluşturulduğu anlık zaman damgası (`timestamp`) ve mikrosaniye (`cusec`) değerini içerir. En kritik nokta, Kanıtlayıcının yalnızca istemci ile KDC (veya servis) arasında paylaşılan **simetrik oturum anahtarıyla (Session Key)** şifrelenmesidir. Saldırgan ağdan paketi yakalasa bile oturum anahtarını bilmediği için kanıtlayıcının içindeki zaman damgasını güncelleyemez.
2. **Saat Sapması Eşiği (MaxClockSkew = 300 Saniye):** KDC ve uygulama sunucuları, gelen kanıtlayıcıdaki zaman damgası ile kendi sistem saatlerini karşılaştırır. Eğer aradaki fark 300 saniyeden (5 dakika) fazlaysa paket `KRB_AP_ERR_SKEW` hatasıyla anında çöpe atılır. Bu mekanizma, saldırganın yakaladığı paketi saatler veya günler sonra kullanmasını imkansız kılar.
3. **Replay Cache (Yeniden Oynatma Önbelleği):** Peki saldırgan paketi yakaladığı ilk 300 saniye içinde tekrar gönderirse ne olur? İşte burada **Replay Cache** devreye girer. Sunucular ve KDC, son 5 dakika içinde işledikleri tüm kanıtlayıcıların `(İstemci Adı, Zaman Damgası, Mikrosaniye)` üçlüsünü RAM'deki Replay Cache tablosunda tutar. Aynı kanıtlayıcı ikinci kez geldiğinde sunucu bunu daha önce gördüğünü anlar ve `KRB_AP_ERR_REPEAT` koduyla isteği engeller.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir üretim tesisinde PLC yönetim sunucusuna bağlanan mühendis iş istasyonunun ağ trafiği, ARP zehirlemesi yapan bir saldırgan tarafından dinlenmiştir. Saldırgan yakaladığı AP-REQ paketini 2 dakika sonra kendi bilgisayarından replay etmeye çalışmıştır.

**Pratik Çözüm ve Sertleştirme:**
1. **NTP Senkronizasyonunun Sağlanması:** Tüm DC, üye sunucu ve istemcilerde saat kaymasını önlemek için kurumsal NTP hiyerarşisi yapılandırılmalıdır:
   ```powershell
   # DC üzerinde güvenilir harici saat kaynağı yapılandırma
   w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update
   # İstemci saatini DC ile zorunlu senkronize etme
   w32tm /resync /rediscover
   ```
2. **Replay Cache Denetimi:** Linux tabanlı Kerberos servislerinde (MIT Kerberos / Heimdal) `KRB5RCACHETYPE` ortam değişkeni bellek veya dosya tabanlı replay cache olarak aktif tutulmalı (`none` yapılmamalıdır).
3. **Kerberos Olay Günlükleri:** Windows Olay Günlüklerinde Olay Kimliği 4769 (Başarısız Servis Bileti Talebi - Hata Kodu `0x25` = Replay Attack) SIEM üzerinden alarm kuralına bağlanmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, unutma: Bilet pasaport ise, kanıtlayıcı o pasaportu taşıyan kişinin anlık canlı yüz taramasıdır. Bilet tek başına kapıyı açamaz; oturum anahtarıyla mühürlenmiş taze bir kanıtlayıcı şarttır. Ağında NTP çökerse Kerberos çöker; saatine sahip çıkamayan sistem yöneticisi, kimliğine de sahip çıkamaz."

---

### Soru 2: PAC (Privilege Attribute Certificate) Doğrulama Mimarisi ve Çift İmza Zorunluluğu

#### 1. Soru Başlığı ve Tanımı
**PAC Çift İmza Yapısı ve Yetki Yükseltme Savunması:** Microsoft Kerberos genişletmesi olan PAC (Privilege Attribute Certificate) neden hem Sunucu İmzası (Server Signature) hem de KDC İmzası (KDC Signature) ile çift mühürlenir? Hedef servislerin PAC doğrulamasını yapmaması ortamda nasıl bir güvenlik açığı doğurur?

#### 2. Derinlemesine Teknik Analiz
Kerberos standartlarında bilet kullanıcı yetkilerini taşımaz; yetkilendirme hedef sunucuya bırakılmıştır. Ancak Active Directory'de etki alanı çapında merkezi yetki yönetimi için PAC yapısı biletin içine eklenmiştir:
1. **PAC İçeriği:** Kullanıcının güvenlik tanımlayıcısı (`user_sid`), üye olduğu tüm grupların SID listesi (`group_sids`), parola son değiştirilme tarihi ve hesap kısıtlamaları biletin içine yazılır.
2. **Neden Çift İmza (Dual Signature)?**
   - **Sunucu İmzası (Server Signature):** Biletin hedef servisi tarafından bilinen servis parola anahtarıyla hesaplanan HMAC özetidir. Hedef sunucu bileti açtığında, bilet içeriğinin istemci tarafından değiştirilmediğini (örneğin araya girip grup listesine Domain Admins eklenmediğini) bu imzayla teyit eder.
   - **KDC İmzası (KDC Signature):** Yalnızca etki alanı denetleyicisi tarafından bilinen `krbtgt` anahtarıyla hesaplanan HMAC özetidir. Bu imza, Sunucu İmzasının bizzat KDC tarafından üretildiğini garanti eder. Eğer KDC imzası olmasaydı, kendi sunucusunda yerel yönetici (Local Admin) olan bir saldırgan, kendi servis anahtarıyla sahte bir PAC üretip Sunucu İmzasını basarak kendini Domain Admin ilan edebilirdi!
3. **PAC Doğrulama Süreci (PAC Validation):** Hedef sunucu kritik bir işlem öncesinde KDC'ye `KerbVerifyPACSignature` RPC çağrısı yaparak biletin KDC imzasını doğrulatabilir. Eğer sunucu PAC imzasını kontrol etmezse (veya eski MS14-068 zafiyetinde olduğu gibi geçersiz imzaları KDC reddetmezse), standart bir kullanıcı saniyeler içinde Domain Admin haklarına yükselir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurumsal sızma testinde saldırgan, ele geçirdiği düşük yetkili bir IIS web servis hesabını kullanarak bilet oluşturmuş, PAC içine `Enterprise Admins (RID 519)` eklemiş ve hedef dosya sunucusuna yönetici haklarıyla erişmeye çalışmıştır.

**Pratik Çözüm ve Sertleştirme:**
1. **PAC İmzalarının Zorunlu Kılınması (CVE-2022-37967 Yamaları):**
   - Microsoft'un güncel Kerberos PAC imzası zorunluluğu registry üzerinden denetlenmelidir:
     ```powershell
     # PAC İmzası Alt Düzey Zorlaması (Tam Zorlama Modu)
     Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "PacSignatureValidationLevel" -Value 3 -Type DWord
     ```
2. **Kerberos AES-256 Zorlaması:** PAC imzalarında zayıf MD5 veya HMAC-MD5 algoritmalarının kullanımını engellemek için RC4 tamamen devre dışı bırakılmalıdır.
3. **SIEM İzleme:** Olay Kimliği 4624 (Oturum Açma) altındaki Grup Üyelikleri (Group Membership) bilgisi ile etki alanındaki gerçek grup üyelikleri anomali tespit motorlarıyla karşılaştırılmalıdır.

#### 4. Ustanın Çırağa Tavsiyesi
> "Çırak, PAC dediğin şey kullanıcının yetki cüzdanıdır. Cüzdanın içine herkes 'ben cumhurbaşkanıyım' diye bir kartvizit koyabilir. Ama o kartvizitin altında hem sarayın (KDC) mührü hem de gittiğin kapının (Servis) onayı yoksa kapıdaki nöbetçi o kişiyi içeri almaz. Çift imzayı asla gevşetme!"

---

### Soru 3: Golden Ticket vs Silver Ticket: Kriptografik Ayrım ve SIEM Tespit Stratejileri

#### 1. Soru Başlığı ve Tanımı
**Bilet Sahteciliği Ayrımı:** Active Directory ortamlarında icra edilen Golden Ticket ile Silver Ticket saldırıları arasındaki kriptografik anahtar, bilet türü, KDC etkileşimi ve adli bilişim (forensics) tespit yöntemleri açısından temel farklar nelerdir?

#### 2. Derinlemesine Teknik Analiz
İki saldırı da Kerberos bilet sahteciliğine dayanır ancak hedefleri ve mimari ayak izleri tamamen farklıdır:

| Kriter | Golden Ticket (Altın Bilet) | Silver Ticket (Gümüş Bilet) |
|--------|----------------------------|-----------------------------|
| **Kullanılan Anahtar** | `krbtgt` hesabının parola özeti (NTLM veya AES-256) | Hedef servisin (SPN) kendi parola özeti |
| **Üretilen Bilet Türü** | TGT (Ticket Granting Ticket) | TGS Servis Bileti (Service Ticket) |
| **Kapsam ve Yetki** | Tüm orman / etki alanı (Forest-wide tam hakimiyet) | Yalnızca ilgili tek bir servis (Örn: Sadece SQL veya CIFS) |
| **KDC ile İletişim** | **Sıfır İletişim (TGT için):** TGT saldırganın cebinde üretilir, ancak TGS isterken KDC'ye gider. | **Tamamen KDC Dışı:** KDC'ye hiçbir paket gitmez; doğrudan hedef sunucuya gidilir! |
| **Kalıcılık Süresi** | Varsayılan 10 yıl olarak ayarlanabilir | Servis parolası değişene kadar geçerlidir |
| **PAC Doğrulaması** | KDC imzası mevcuttur (çünkü saldırgan `krbtgt` anahtarına sahiptir) | KDC imzası yoktur veya sahtedir (KDC PAC doğrulaması yapılırsa yakalanır) |

**Adli Bilişim ve Tespit Kriterleri:**
1. **Silver Ticket Tespiti:** KDC'de Olay Kimliği 4769 (TGS İstendi) kaydı **oluşmadan**, hedef sunucuda Olay Kimliği 4624 (Başarılı Oturum Açma) görülmesi en kesin Silver Ticket kanıtıdır! Bilet KDC'den geçmemiştir.
2. **Golden Ticket Tespiti:** Bilet ömrünün (Ticket Lifetime) kurumsal GPO politikasındaki 10 saati aşması (örn. 10 yıl), şifreleme türünün RC4 olması veya biletin düzenlenme anında KDC Olay Kimliği 4768 (TGT Verildi) kaydının bulunmamasıdır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir finans kurumunda saldırgan, SQL servis hesabının parolasını kırarak Silver Ticket üretmiş ve doğrudan veritabanına bağlanarak müşteri tablolarını çekmiştir. DC günlüklerinde hiçbir şüpheli hareket görülmemiştir.

**Pratik Çözüm ve Savunma:**
1. **krbtgt ve Servis Parola Rotasyonu:**
   - Golden Ticket için: `krbtgt` parolasının kontrollü çift sıfırlanması.
   - Silver Ticket için: Hedef servis hesabının parolasının sıfırlanması veya **gMSA** mimarisine geçiş.
2. **SIEM Korelasyon Kuralı (KDC Olmayan Oturumlar):**
   ```text
   KURAL: "Hedef Sunucuda Event 4624 (LogonType=3, Kerberos) VAR"
   VE 
   "KDC üzerinde aynı kullanıcı/zaman için Event 4769 YOK"
   -> ALARM: "Olası Silver Ticket Saldırısı Tespit Edildi!"
   ```
3. **Kerberos Full PAC Validation:** Hedef sunucularda PAC doğrulamasının KDC üzerinden zorunlu kılınması.

#### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, Golden Ticket tüm kalenin anahtarını kopyalamaktır; kralın mührü elindedir. Silver Ticket ise sarayın aşçısının kapı anahtarını çalmaktır; sadece mutfağa girersin ama kralın haberi bile olmaz. KDC günlüklerine bakıp 'ortam temiz' diyen güvenlik uzmanı, mutfakta ziyafet çeken Silver Ticket saldırganını asla göremez!"
