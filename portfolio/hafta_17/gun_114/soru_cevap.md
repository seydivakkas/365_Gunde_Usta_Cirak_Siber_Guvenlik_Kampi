# Hafta 17 / Gün 114: MFA Yöntemleri ve Oltalama Direnci — Derin Teknik Soru & Cevap

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Pedagojik Format:** Usta-Çırak Derin Teknik Mülakat ve Saha Deneyimi  

---

## Soru 1: Ters Vekil (AiTM / Evilginx2) Oltalama Saldırılarının Çalışma Prensibi ve TOTP / SMS Yöntemlerinin Neden Başarısız Olduğu

### 1. Soru Başlığı ve Tanımı
Geleneksel oltalama (phishing) saldırıları sadece statik form kopyalamaktan ibaretken, modern **Ters Vekil (Adversary-in-the-Middle — AiTM)** saldırıları nasıl çalışır? Neden RFC 6238 TOTP (Google Authenticator) ve SMS tabanlı çok faktörlü doğrulama yöntemleri bu saldırı modeli karşısında tamamen etkisiz kalmaktadır?

### 2. Derinlemesine Teknik Analiz
Statik oltalama sayfalarında saldırgan kullanıcının parolasını kaydeder ancak kurban MFA kullandığında saldırgan gerçek sunucuya zamanında giriş yapamaz. AiTM araçları (örneğin Evilginx2, Modlishka) ise bir **ters vekil (Reverse Proxy)** olarak konumlanır:

1. Saldırgan kurbanı inandırıcı görünen sahte bir alan adına çeker (Örn. `https://login.microsoft.security-update-portal.com`).
2. Kurban sayfayı açtığında, ters vekil gerçek sunucuya (`https://login.microsoftonline.com`) bağlanarak orijinal giriş sayfasını, CSS'leri, logoları ve JS kodlarını gerçek zamanlı olarak çeker ve kurbana yansıtır.
3. Kurban kullanıcı adını ve parolasını girdiğinde, vekil sunucu bu verileri yakalar ve aynı anda gerçek sunucuya POST eder.
4. Gerçek sunucu MFA kodu talep ettiğinde (SMS veya TOTP), ters vekil bu ekranı kurbana iletir.
5. Kurban telefonundaki TOTP uygulamasından 6 haneli kodu (`492 108`) sahte forma girer.
6. Ters vekil bu 6 haneli kodu 1-2 saniye içinde gerçek sunucuya iletir.
7. **Kritik Kırılma Noktası:** RFC 6238 TOTP algoritması, sadece $HMAC(K, \lfloor \text{Time}/30 \rfloor)$ fonksiyonuna dayanır. Bu kodun içinde web sitesinin alan adı, IP adresi veya menşei (Origin) hakkında **hiçbir veri yoktur**. Kod sadece paylaşımlı gizli anahtar ve zamandan türetilmiştir.
8. Gerçek sunucu gelen 6 haneli kodun matematiksel olarak doğru olduğunu görür ve oturum kimliğini kanıtlayan `Set-Cookie` (Session Cookie / OAuth Access & Refresh Token) başlıklarını döner.
9. Ters vekil bu oturum çerezlerini yakalar, diske kaydeder ve kurbanı meşru bir sayfaya yönlendirir. Saldırgan artık kurbanın hiçbir parolasına veya telefonuna ihtiyaç duymadan doğrudan oturum çereziyle sisteme girer (Session Hijacking).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Uluslararası bir finans şirketinin üst düzey yöneticisine sahte bir "OneDrive Belge Paylaşımı" e-postası gelir. Yönetici linke tıklar, şirket portalına benzeyen sayfada parolasını ve Microsoft Authenticator TOTP kodunu girer. Yönetici girişin başarılı olduğunu düşünürken, saldırganlar Evilginx2 konsolundan yöneticinin `ESTSAUTH` ve `ESTSAUTHPERSISTENT` çerezlerini çalarak şirketin iç yazışmalarına ve bütçe raporlarına tam erişim sağlar.

**Pratik Çözüm:**
Şirket içindeki tüm kullanıcılar için TOTP ve SMS tabanlı kimlik doğrulama politikası kaldırılmalı; FIDO2 / WebAuthn tabanlı **Donanım Güvenlik Anahtarları (Hardware Security Keys / Passkeys)** veya Windows Hello for Business zorunlu kılınmalıdır:
```powershell
# Microsoft Entra ID (Azure AD) Koşullu Erişim Politikası (Conditional Access)
# Kimlik doğrulama gücü: "Phishing-resistant MFA" (FIDO2 / Certificate-Based) zorunlu tutulmalıdır.
Set-AzureADMSConditionalAccessPolicy -GrantControls @{
    BuiltInControls = @("mfa")
    AuthenticationStrength = "fido2-phishing-resistant"
}
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, bir güvenlik mekanizması tasarlarken saldırganın araya vekil (proxy) koyabileceğini varsayacaksın. Eğer doğrulamada istemcinin bulunduğu yer (menşe) matematiksel olarak kanıtlanmıyorsa, o 6 haneli kod posta güvercini gibidir; havada avlanır ve düşmanın kalesine iner. TOTP'ye güvenip 'biz hacklenmeyiz' deme!"

---

## Soru 2: FIDO2 / WebAuthn Mimarisinde Kriptografik Menşe Bağlama (Cryptographic Origin Binding) ve CWE-346 Zafiyetinin Önlenmesi

### 1. Soru Başlığı ve Tanımı
FIDO2 / WebAuthn standardı hangi matematiksel ve protokoler mekanizmayla Ters Vekil (AiTM) oltalama saldırılarını tamamen engeller? Tarayıcı, donanım anahtarı (Authenticator) ve Güvenen Taraf (Relying Party — RP) arasındaki **Kriptografik Menşe Bağlama (Cryptographic Origin Binding)** süreci **CWE-346: Origin Validation Error** zafiyetini nasıl bertaraf eder?

### 2. Derinlemesine Teknik Analiz
WebAuthn standardı, kimlik doğrulama sorumluluğunu kullanıcının dikkatinden alıp tarayıcı motorunun TLS katmanına ve donanım anahtarına devreder. Süreç şu adımlarla işler:

1. **Meydan Okuma (Challenge - CWE-294 Önleme):**  
   Sunucu 32-baytlık kriptografik güvenli rastgele bir değer üretir ($Challenge$).
2. **İstemci Verisi (clientDataJSON Üretimi):**  
   Tarayıcının `navigator.credentials.get()` API'si çağrıldığında, tarayıcı arka planda `clientDataJSON` nesnesini oluşturur:
   ```json
   {
     "type": "webauthn.get",
     "challenge": "d8f3b2...a19c",
     "origin": "https://mevzuat.siber.local"
   }
   ```
   **Buradaki kritik nokta:** Tarayıcı `origin` değerini kullanıcının girdiğinden değil, o anda bağlı olduğu **gerçek TLS sertifikasının ve adres çubuğunun etki alanından** alır. Kullanıcı sahte bir sitedeyse (`https://phishing-site.com`), tarayıcı `origin` alanına zorunlu olarak `https://phishing-site.com` yazar.
3. **Donanım İmzası (Authenticator Assertion):**  
   Donanım güvenlik anahtarı (YubiKey / TPM) şu bayt dizisini özel anahtarıyla ($d$) imzalar:
   $$\text{İmzalanan Veri} = \text{authenticatorData} \parallel \text{SHA-256}(\text{clientDataJSON})$$
4. **Sunucu Doğrulaması (CWE-346 Savunması):**  
   Sunucu kendisine iletilen `clientDataJSON` nesnesini inceler:
   - Sunucunun beklediği menşe: `https://mevzuat.siber.local`
   - Donanım anahtarının imzaladığı menşe: `https://phishing-site.com`
   - Sunucu: $\text{submitted\_origin} \neq \text{expected\_origin}$ tespit eder.
   - Doğrulama **CWE-346 PhishingOriginMismatchError** ile reddedilir!

Saldırgan vekil sunucu araya girip `clientDataJSON` içindeki menşei değiştirmeye çalışırsa ne olur? O zaman da `SHA-256(clientDataJSON)` özeti değişeceği için donanım anahtarının asimetrik dijital imzası **CWE-347** ile geçersiz kalır! Saldırgan için hiçbir kaçış yolu yoktur.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir devlet kurumunda kritik altyapı operatörleri, sahte bir SMS ile "Zorunlu Güvenlik Güncellemesi" linkine (`https://portal-ebys-destek.com`) yönlendirilir. Kullanıcılar dizüstü bilgisayarlarına takılı YubiKey donanım anahtarlarının altın temas noktasına dokunurlar.

**Sistem Savunma Analizi:**
YubiKey, tarayıcının bulunduğu `https://portal-ebys-destek.com` menşeini imzalar. Sahte proxy bu imzayı gerçek `https://ebys.gov.tr` sunucusuna ilettiğinde, gerçek sunucunun WebAuthn doğrulayıcısı:
```python
if client_data["origin"] != "https://ebys.gov.tr":
    raise PhishingOriginMismatchError("CWE-346: Oltalama sahte menşei engellendi!")
```
kontrolünü çalıştırır ve oturum isteğini çöpe atar. Operatörler oltalama linkine tıklamış ve anahtara dokunmuş olsalar dahi sıfır sızıntı gerçekleşir!

### 4. Ustanın Çırağa Tavsiyesi
> "İşte asimetrik kriptografinin zarafeti buradadır çırağım. Parola kullanıcının beynindedir, çalınabilir. TOTP ekrandadır, kopyalanabilir. Ama FIDO2 imzası doğrudan tarayıcının TLS oturumuyla donanım çipine kenetlenmiştir. Düşman araya girse bile menşe farkı saldırganın boynuna kement gibi dolanır."

---

## Soru 3: MFA Fatigue (MFA Yorgunluğu / Push Spamming) Saldırıları, Uber Vakası ve Sayı Eşleştirme (Number Matching) / FIDO2 Geçiş Stratejileri

### 1. Soru Başlığı ve Tanımı
Mobil Push bildirimleri (Authenticator Push Approval) neden son yılların en tehlikeli saldırı vektörlerinden biri olan **MFA Fatigue (Onay Bıkkınlığı — CWE-307)** saldırılarına yol açmıştır? 2022 yılındaki meşhur Uber siber sızıntısında bu açık nasıl kullanılmıştır ve savunma tarafında **Sayı Eşleştirme (Number Matching)** ile **FIDO2** stratejileri nasıl uygulanmalıdır?

### 2. Derinlemesine Teknik Analiz
Mobil Push tabanlı MFA mekanizmasında kullanıcıya telefondan basit bir ekran gelir: *"Giriş yapmaya çalışan siz misiniz? [EVET / REDDET]"*.

Saldırgan kurbanın parolasını sızdırdığında veya kaba kuvvetle ele geçirdiğinde:
1. Gece yarısı saat 03:00'te her 10 saniyede bir giriş isteği tetikler.
2. Kurbanın telefonuna art arda onlarca push bildirimi yağar (MFA Spamming / Fatigue).
3. Saldırgan aynı anda WhatsApp veya Telegram üzerinden kurbana IT Destek personeli taklidi yaparak mesaj atar: *"Sistemimizde arıza var, telefonunuzdaki onay bildirimini kabul ederseniz bildirimler duracaktır."*
4. Uykulu veya bıkmış kullanıcı sonunda *"Yeter artık"* diyerek **EVET (Onayla)** butonuna basar.
5. Saldırgan sisteme tam yetkiyle giriş yapar (CWE-307 / CWE-287).

Bu açık, push onayının kullanıcının bilişsel dikkatine (cognitive attention) dayanmasından ve hiçbir bağlamsal doğrulama içermemesinden kaynaklanır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo (2022 Uber İhlali):** Lapsus$ hacker grubu, harici bir Uber sözleşmeli çalışanının parolasını ele geçirdi. Ardından çalışanın telefonuna saatlerce push onayı gönderdi. Çalışan sürekli gelen bildirimleri durdurmak için sonunda onayla butonuna bastı. Saldırganlar iç ağa sızdı, AWS ve Google Cloud anahtarlarını, Slack mesajlarını ve HackerOne açık raporlarını ele geçirdi.

**Pratik Savunma Çözümleri:**
1. **Sayı Eşleştirme (Number Matching / Contextual Push):**  
   Kullanıcıya sadece "Onayla" butonu gösterilmez. Web ekranında 2 basamaklı rastgele bir sayı gösterilir (Örn. `74`). Kullanıcının cep telefonundaki Authenticator uygulamasına bu sayıyı klavyeden girmesi zorunlu tutulur. Böylece sahte ve uzaktan tetiklenen saldırılarda kurban web ekranındaki sayıyı görmediği için onaylayamaz.
2. **İstek Hız Limiti ve Otomatik Kilitleme (Rate Limiting — CWE-307):**  
   Kısa sürede 3'ten fazla reddedilen veya cevapsız kalan push isteğinde hesap otomatik olarak 30 dakika kilitlenmeli ve SOC ekibine alarm üretilmelidir.
3. **Nihai Çözüm (FIDO2 / Passkeys):**  
   Push bildirimleri tamamen devre dışı bırakılarak kullanıcının fiziksel olarak cihazın başında olduğunu ve menşei doğrulayan FIDO2 anahtarları zorunlu hale getirilmelidir.

```python
# Sayı Eşleştirme ve MFA Fatigue Engelleme Mantığı
class PushMFAManager:
    def __init__(self, max_spam_limit=3):
        self.max_spam_limit = max_spam_limit
        self.pending_challenges = {}

    def trigger_push_request(self, user_id):
        # Aşırı istek denetimi (CWE-307)
        if self.get_unanswered_count(user_id) >= self.max_spam_limit:
            self.lock_account_and_alert_soc(user_id)
            raise MFAFatigueError("Aşırı push isteği engellendi! Hesap donduruldu.")

        # Sayı eşleştirme için 2 basamaklı rastgele kod üretimi
        match_number = secrets.randbelow(90) + 10
        self.pending_challenges[user_id] = match_number
        return match_number
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, bir güvenlik kontrolü insanı bıktıracak veya dalgınlığına gelecek şekilde tasarlanmışsa, o kontrol saldırganın müttefikidir. Kullanıcıya sadece 'Evet/Hayır' soran tembel sistemler kurma. Güvenlik, niyetin ve bilincin teyididir. Sayı eşleştirmeyi standart kıl, ama nihai hedefin daima donanım tabanlı FIDO2 olsun."
