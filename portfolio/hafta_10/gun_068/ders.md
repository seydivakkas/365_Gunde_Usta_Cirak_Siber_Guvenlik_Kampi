# Hafta 10 Gün 68: Ağ Günlükleri ve Kişisel Veri (Usta-Çırak Dersi)

> **Usta Notu:**  
> *"Evlat, bir güvenlik analistinin en büyük ikilemi şudur: Tehdidi yakalamak için olabildiğince çok veri toplamak zorundasın; ancak topladığın her veri parçası, içinde kişisel bir kimlik, parola veya kredi kartı taşıyorsa şirketi milyonlarca liralık KVKK/GDPR cezasıyla karşı karşıya bırakabilir! Acemi analist 'Ben güvenlikçiyim, her şeyi açık kaydederim' der; kanunun kılıcı boynuna inince şaşırır. Usta analist ise adli kanıt değerini (Forensic Value) bir gram bile zedelemeden, IP'yi alt ağında maskeleyen, oturum çerezini buharlaştıran, e-postayı sözde-anonimleştiren (Pseudonymization) ve sistemi hem siber saldırılara hem de yasal denetimlere karşı zırh gibi koruyan kişidir!"*

---

## 1. Ağ Günlüklerinde Kişisel Veri (PII) ve Yasal Çerçeve

Siber güvenlik ekipleri; SIEM, IDS/IPS, WAF ve EDR sistemlerine ağ trafiği günlüklerini (PCAP, NetFlow, Zeek/Bro, Web Access Logs, Syslog) durmaksızın aktarır. Ancak bu günlükler doğrudan veya dolaylı olarak gerçek kişileri tanımlayan veriler (PII - Personally Identifiable Information) barındırır.

### 1.1 Yasal Standartlar ve Kararlar
1. **GDPR (Genel Veri Koruma Tüzüğü - Madde 4 ve Recital 30):**
   - Avrupa Adalet Divanı'nın *Breyer v. Bundesrepublik Deutschland (C-582/14)* kararı uyarınca **dinamik IP adresleri dahi kişisel veridir**; çünkü internet servis sağlayıcısı (ISS) elindeki loglarla eşleştirildiğinde gerçek kişiye ulaşılabilir.
2. **KVKK (6698 Sayılı Kişisel Verilerin Korunması Kanunu):**
   - IP adresi, MAC adresi, kullanıcı adı, telefon numarası ve e-posta kimliği doğrudan veya dolaylı kimlik belirleyici veri kabul edilir.
3. **PCI-DSS (Ödeme Kartı Sektörü Veri Güvenliği Standardı - Madde 3.4):**
   - Kredi kartının 16 haneli birincil hesap numarası (PAN) günlüklerde asla açık (cleartext) saklanamaz. En fazla ilk 6 ve son 4 hane açık bırakılabilir; CVV/CVC güvenlik kodu ise **asla ve hiçbir koşulda** kaydedilemez!

---

## 2. Ağ Katmanlarında Gizlenen PII Envanteri

| Protokol / Katman | Günlükte Yakalanan Alan | PII Niteliği | Maskeleme / Arındırma Yöntemi |
|---|---|---|---|
| **Ağ Katmanı (L3)** | `src_ip`, `dst_ip` | Bireysel Cihaz / Kullanıcı Konumu | Subnet Truncation (`/24`), Salted HMAC-SHA256 |
| **Veri Bağı (L2)** | `src_mac`, `dst_mac` | Donanım Kimliği, BSSID Wi-Fi | Üretici OUI Korumalı Maskeleme (`00:1A:2B:XX:XX:XX`) |
| **Uygulama (HTTP)** | `Authorization: Bearer <JWT>` | Kimlik Doğrulama / Oturum Jetonu | `Bearer [REDACTED_TOKEN]` |
| **Uygulama (HTTP)** | `Cookie: session_id=...` | Kullanıcı Oturum Kimliği | `[REDACTED_SESSION_COOKIE]` |
| **Uygulama (HTTP)** | URI Query (`?email=...&tckn=...`) | Kullanıcı Kimlik ve İletişim Bilgisi | Regex Parametre Sanitization (`a***z@kurum.com`) |
| **Uygulama (HTTP)** | JSON/Form Body (`kart_no`, `tel`) | Finansal ve Biyometrik/Kişisel Veri | PCI-DSS İlk 4/Son 4 Maskeleme, Telefon Redaksiyonu |
| **Uygulama (DNS)** | DNS Query FQDN | Bireyin İlgi Alanı, Ziyaret Alışkanlığı | Dahili Hostname Maskeleme, Sinkhole Kayıtları |
| **Sistem (Syslog)** | Kullanıcı Giriş Logları | Kullanıcı Adı, E-posta, IP | Regex Tabanlı Serbest Metin Maskeleme |

---

## 3. Anonimleştirme ve Sözde-Anonimleştirme (Pseudonymization) Teknikleri

Verinin tamamen yok edilmesi adli bilişim incelemelerini (Forensic Investigation) imkansız kılar. Saldırganın IP'sini tamamen silerseniz hangi sunuculara sıçradığını göremezsiniz. Bu yüzden mühendislik dengesi kurulmalıdır:

### 3.1 Alt Ağ Maskeleme (Subnet Truncation)
- Bir kurum içindeki veya dışındaki IP adresinin son okteti sıfırlanır:
  $$\text{IPv4: } 192.168.1.145 \longrightarrow 192.168.1.0/24$$
- Bu sayede analist trafiğin hangi departmandan veya hangi IP bloğundan geldiğini anlar; fakat o bloktaki tek bir bireyi doğrudan hedef alamaz.

### 3.2 Tuzlu Kriptografik Özetleme (Salted HMAC-SHA256)
- IP adresleri gizli bir tuz (Salt) anahtarı ile şifrelenir:
  $$\text{Sözde-Kimlik} = \text{HMAC-SHA256}(\text{IP}, \text{Salt})[:12]$$
- **Korelasyon Üstünlüğü:** Aynı IP adresi loglarda her geçtiğinde aynı `IP_PSEUDO_3a8f9c12b0e4` hash'ini üretir. SOC analisti saldırganın 10 farklı sunucuya yaptığı hareketleri uçtan uca takip edebilir; ancak saldırganın gerçek IP'sini çözmek için yalnızca CISO'da bulunan gizli tuz anahtarına ihtiyaç duyar.
- **Tuz Rotasyonu (Salt Rotation):** Tuz anahtarı periyodik olarak (örneğin 30 günde bir) değiştirilerek gökkuşağı tabloları (Rainbow Tables) ile hash kırma saldırıları engellenir.

---

## 4. Log Saklama Süreleri (Data Retention) ve Yaşam Döngüsü

- **5651 Sayılı Kanun (Türkiye):** İnternet toplu kullanım sağlayıcıları ve ISS'ler için trafik loglarının 2 yıl (730 gün) boyunca zaman damgalı saklanması zorunludur.
- **GDPR Saklama Sınırı (Storage Limitation - Madde 5(1)(e)):** Veriler işleme amacının gerektirdiğinden daha uzun süre saklanamaz. Amacı tamamlanan ve yasal süresi dolan telemetri güvenli biçimde imha edilmeli veya tamamen geri döndürülemez biçimde anonimleştirilmelidir.

---

## 5. Ustanın Çırağa Öğüdü
Çırak! Ağ günlükleri kurumun kara kutusudur. Uçak düştüğünde o kara kutu hayat kurtarır. Ancak kara kutunun içine yolcuların cüzdanlarını, kimlik kartlarını açık saçık koyarsan hırsızlara davetiye çıkarırsın. Gerçek bir usta, log boru hattını (pipeline) öyle kurar ki; SIEM ekranına düşen hiçbir pakette ham parola, açık kart veya açık TCKN bulunmaz. Güvenlik, gizlilikten ödün vermeden güvenliği sağlamaktır!
