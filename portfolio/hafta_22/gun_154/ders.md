# Gün 154: Aşama 6 Kalite Özeti ve Kabulü — Uç Nokta ve Kimlik Güvenliği

## Usta-Çırak / Hoca Dersi Notu

Çırağım, gözlerini aç ve geriye dönüp katettiğimiz yola bir bak! 
Bugün, tam 28 günlük devasa bir maratonun, **Aşama 6: Uç Nokta ve Kimlik Güvenliği (Endpoint and IAM)** döneminin taç giyme günüdür.

Gün 127'de başladık; bir kullanıcının Active Directory'de ilk oluşturulduğu andan parola hashleme algoritmalarına (Argon2id, PBKDF2), çok faktörlü kimlik doğrulamadan (FIDO2, WebAuthn) Kerberos biletleme mekanizmasına ve ayrıcalıklı erişim yönetimine (PAM / PIM) kadar kimliğin her atomunu işledik. Ardından uç noktaya indik; EDR ajanlarının telemetri motorlarından çekirdek seviyesinde Seccomp/Sandbox izolasyonuna, BitLocker ve TPM 2.0 PCR ölçüm zincirlerinden WORM yedekleme ve CIS yapılandırma sapmasına kadar savunma derinliğinin (Defense-in-Depth) çelik zırhını ördük. Dün ise tüm bu parçaları Mini Proje 21'de kurumsal bir uç nokta risk panosuna bağladık.

Bugün konumuz bir veda değil, resmi bir **Kalite Güvence ve Kabul (Quality Gate & Acceptance)** sınavıdır. Bir siber güvenlik mimarının en büyük erdemi, kurduğu sistemleri en acımasız denetim kriterleriyle test edebilmesidir.

---

### 1. Modern Sıfır Güven (Zero Trust) Neden Kimlik ve Uç Noktanın Kesişimidir?

NIST SP 800-207 Sıfır Güven Mimarisi (ZTA) şu temel aksiyom üzerine kuruludur:
$$\text{Erişim Kararı} = f(\text{Doğrulanmış Kimlik Güveni}, \text{Doğrulanmış Uç Nokta Sağlığı}, \text{Bağlam})$$

Klasik ağ perimeter güvenliği ölmüştür! Güvenlik duvarının ardında olmak artık "güvenilir" olmak anlamına gelmez.
* İstediğin kadar güçlü bir MFA kullan (`FIDO2`), eğer kullanıcının oturum açtığı dizüstü bilgisayarda EDR yoksa ve LSASS bellek koruması (`RunAsPPL`) kapalıysa, saldırgan belleğe sızar, oturum çerezlerini veya biletleri çalar (`Pass-the-Ticket / Token Theft`).
* İstediğin kadar güçlü bir EDR kur, eğer Active Directory'de kalıcı Domain Admin hesapları (`Standing Privilege`) cirit atıyorsa ve ayrılan personelin hesapları günlerce açık kalıyorsa, saldırgan meşru kimlik bilgileriyle sıfır alarm üreterek etki alanını ele geçirir (`Living off the Land`).

İşte bu yüzden Aşama 6, **Kimlik (IAM)** ve **Uç Nokta (Endpoint)** dünyalarını birbirinden ayrılmaz iki ikiz kardeş olarak ele almıştır.

---

### 2. Aşama 6'nın 6 Resmi Kalite Kapısı (Quality Gates)

Geliştirdiğimiz `Stage6QualityEngine`, kurumsal bir altyapıyı 6 bağımsız kapıdan geçirir:

```
+---------------------------------------------------------------------------------+
|                   AŞAMA 6 KALİTE GÜVENCE KAPILARI (QUALITY GATES)               |
+---------------------------------------------------------------------------------+
| KAPI 1: Kimlik Doğrulama & Hijyen | MFA zorunlu, Argon2id, NTLMv1 ve RC4 kapalı |
| KAPI 2: En Az Ayrıcalık & JML     | RBAC/ABAC matrisi, Leaver <24h SLA, gMSA   |
| KAPI 3: Ayrıcalıklı Erişim (PAM)  | Kalıcı Domain Admin = 0, JIT <4h, Oturum Kayıt|
| KAPI 4: Görünürlük & Anti-Tamper  | EDR %100 kapsama, Tamper Protection aktif   |
| KAPI 5: Donanım Kökü & Sandbox    | TPM 2.0 PCR mühürlü BitLocker, WDAC, RunAsPPL|
| KAPI 6: Dayanıklılık & Sapma      | 3-2-1-1-0 WORM yedek, Tatbikat <30g, Self-Heal|
+---------------------------------------------------------------------------------+
```

#### Kapı Eşikleri ve Kabul Mantığı:
* Her bir kapının asgari geçme notu **85.0 / 100.0** puandır.
* Genel Aşama 6 Kabul Eşiği **90.0 / 100.0** puandır.
* **Veto Kuralı (Hard Stop):** Tek bir kapı dahi başarısız olursa (`FAIL`), genel puan 90'ın üzerinde çıksa bile nihai kabul verilmez; sistem `HOLD / REJECT` durumuna düşer. Siber güvenlikte zincir, en zayıf halkası kadar güçlüdür!

---

### 3. Aşama 6 Boyunca Kazanılan Kritik Yetkinlikler Özeti

| Hafta | Kapsanan Temel Konular | Üretilen Mini Proje / Başarı |
| :---: | :--- | :--- |
| **Hafta 19** | IAM Temelleri, AuthN vs AuthZ, Modern Parola Hashleme, MFA, Kerberos Akışları, Active Directory Dizin Servisleri. | Mini Proje 18: Kimlik Doğrulama ve Token Akışı |
| **Hafta 20** | Yetkilendirme Modelleri (RBAC/ABAC), Ayrıcalıklı Erişim Yönetimi (PAM), JIT Yetki, gMSA, JML Yaşam Döngüsü. | Mini Proje 19: PAM ve JIT Yetki Simülatörü |
| **Hafta 21** | Sıfır Güven Kimlik, AD Saldırı Yüzeyi (Kerberoasting, Pass-the-Hash), AD CS Sertifika Güvenliği, Güvenlik Grupları. | Mini Proje 20: IAM Politika Matrisi |
| **Hafta 22** | Uç Nokta Savunması: EDR Telemetrisi, Sandbox/AppContainer, BitLocker/TPM 2.0, WORM Yedekleme, CIS Sapması. | Mini Proje 21: Uç Nokta Risk Panosu (ESPM) |

---

### 4. Aşama 7'ye Bakış: Web Uygulama ve API Güvenliği

Evlat! Aşama 6'yı başarıyla tamamlayıp sertifikamızı aldığımıza göre artık kale kapılarının dışına, internete açık olan vitrinimize odaklanacağız: **Aşama 7: Web Güvenliği (Web Application & API Security)**.
* OWASP Top 10 zafiyetleri (SQL Injection, XSS, SSRF, CSRF, IDOR).
* Modern API güvenliği (REST, GraphQL, JWT manipülasyonları, Rate Limiting).
* Web Uygulama Güvenlik Duvarları (WAF) ve DevSecOps boru hatları.

Kimliğini ve uç noktasını sağlama almayan bir mimar web güvenliğine geçerse, bastığı zemin çöker. Sen ise artık sağlam bir zemin üzerindesin!

---

### 5. Ustanın Çırağa Öğüdü

Evlat! Kalite bir tesadüf değildir; sürekli ve tavizsiz bir disiplindir. 
Bir sistemin "çalışıyor" olması, onun "güvenli" olduğu anlamına gelmez. Güvenlik, sistemin sadece normal şartlarda değil, en sofistike saldırı altında ve en kritik personel ayrıldığında dahi dimdik ayakta kalabilmesidir. Aşama 6'da kazandığın bu kimlik ve uç nokta vizyonu, seni sektördeki alelade teknisyenlerden ayırıp gerçek bir güvenlik mimarı yapacak temel taşıdır. Başını dik tut; Aşama 6 resmi olarak tamamlanmıştır!
