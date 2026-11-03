# GÜN 124: Secrets Yönetimi ve Çevre Değişkenleri Mimarisi

## 1. Usta-Çırak Açılış Konuşması

**Usta:** Evlat, tarihin en büyük veri sızıntılarını incelediğinde ne görürsün bilir misin? Milyon dolarlık güvenlik duvarları, yapay zekalı EDR'lar, sıfır güven mimarileri... Ve sonra bir bakarsın, bir stajyer veya dikkatsiz bir kıdemli mühendis GitHub'a bir `commit` atmış; içinde AWS kök anahtarı, Stripe canlı gizli anahtarı veya üretim veritabanı şifresi açıkça yazıyor! Saldırganlar özel tarama botlarıyla GitHub'a düşen bir anahtarı **20 saniyede** yakalayıp hesabı boşaltıyor!

Siber güvenlikte buna **CWE-798 (Use of Hard-coded Credentials)** zafiyeti denir. Ve bu açık, tarihin en utanç verici ama en yaygın güvenlik felaketidir.

**Çırak:** Hocam, peki geliştiriciler "Biz koda yazmıyoruz, `.env` dosyasına koyup çevre değişkenlerinden (environment variables) okuyoruz" diyorlar. Bu yeterince güvenli değil midir?

**Usta:** Aferin evlat, 12-Faktör Uygulama (The Twelve-Factor App) metodolojisi konfigürasyonun çevre değişkenlerinde saklanmasını önerir. Bu, koda yazmaktan bin kat iyidir; **ancak modern bir bulut ve konteyner ortamında asla tek başına yeterli değildir!**
Neden mi?
1. Bir Docker konteynerinde `docker inspect <container_id>` diyen biri tüm `.env` değişkenlerini açık metin okur!
2. Linux üzerinde sunucuya sızan bir saldırgan `/proc/<PID>/environ` dosyasını okuyarak uygulamanın tüm secret'larını çeker.
3. Uygulama bir hata verip çöktüğünde (crash / stack trace), çevre değişkenleri doğrudan hata loglarına veya Sentry gibi harici izleme platformlarına sızar (**CWE-532 Zafiyeti**)!
4. Çevre değişkenlerinde anahtar rotasyonu (rotation) yapmak için tüm sunucuları veya konteynerleri yeniden başlatman gerekir; bu da kesintiye (downtime) yol açar.

İşte bu yüzden kurumsal dünyada standart: **Merkezi Secrets Kasaları (Secret Vaults - örn: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)** mimarisidir!

---

## 2. Kurumsal Secret Vault Mimarisi ve İlkeleri

Bir Secret Vault şu 5 temel güvenlik prensibiyle çalışır:

| Prensip | Açıklama | Motordaki Karşılığı |
|---|---|---|
| **1. Zarflı Şifreleme (Envelope Encryption)** | Gizli veriler diskte asla düz metin durmaz. Veri Şifreleme Anahtarı (DEK) ile şifrelenir, DEK ise Kasa Ana Anahtarı (Master Key) ve PBKDF2/HMAC ile kilitlenir. | `CryptoVaultHelper.encrypt()` |
| **2. En Az Yetki ve Rol Kısıtı (PoLP)** | Bir secret'a her servis erişemez. Yalnızca yetkilendirilmiş roller (örn: `payment_service`) anahtarı çekebilir. | `SecretAccessDeniedError` (CWE-285) |
| **3. Süreli Yaşam Döngüsü (TTL & Expiration)** | Statik, ömür boyu geçerli şifre devri bitmiştir. Her secret'ın bir TTL süresi vardır; süresi dolan anahtar kilitlenir. | `SecretExpiredError` (CWE-613) |
| **4. Otomatik Rotasyon (Secret Rotation)** | Anahtarlar 30, 60 veya 90 günde bir otomatik versiyonlanır. Eski anahtar bir süre rotasyonda kalır, yeni sürüm devreye girer. | `vault.rotate_secret()` |
| **5. Derhal İptal (Revocation)** | Sızıntı şüphesinde tek bir komutla anahtar kasadan iptal edilir; tüm oturumlar anında düşer. | `vault.revoke_secret()` |

---

## 3. CWE-798 Tespiti: Shannon Entropisi ve Regex Analizi

Bir anahtarın kodda unutulmasını engellemek için CI/CD boru hattına statik güvenlik tarayıcısı koyarız. Tarayıcı iki yöntem kullanır:
1. **İmza Tabanlı Regex Taraması:**
   - AWS: `AKIA[0-9A-Z]{16}`
   - GitHub Token: `ghp_[A-Za-z0-9_]{36}`
   - Stripe Secret: `sk_live_[0-9a-zA-Z]{24}`
   - Private Key: `-----BEGIN (RSA|EC) PRIVATE KEY-----`
2. **Shannon Entropi Analizi:**
   Rastgele üretilmiş kriptografik anahtarlar yüksek bilgi yoğunluğuna (entropi) sahiptir:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   Normal İngilizce veya Türkçe kod metinlerinin entropisi 2.5 - 3.5 arasındayken; base64, hex veya karmaşık şifrelerin entropisi **4.2 ve üzerine** çıkar! Tarayıcımız bu sıçramayı gördüğü anda derlemeyi kırar!

---

## 4. CWE-532: Log Maskeleme ve Sanitizasyon

Bir geliştirici debug yaparken yanlışlıkla:
`logger.info(f"Kullanıcı ödeme isteği: token={stripe_token}")` yazabilir.
Bu log ElasticSearch'e veya Splunk'a gittiğinde tüm operasyon ekibi anahtarı görür.

Motorumuzda uyguladığımız **Log Maskeleme (Log Sanitization / Redaction)** filtresi, loglar diske veya ağa yazılmadan önce hem kasadaki aktif secret değerlerini hem de bilinen regex kalıplarını bularak `[REDACTED_SECRET]` ile sansürler.

---

## 5. Uygulama Mimarisi

Bugün geliştirdiğimiz `secrets_management_engine.py`:
1. `SecretVaultManager` ile merkezi anahtar deposunu yönetir, PBKDF2 ve HMAC tabanlı zarflı şifreleme uygular.
2. Rol bazlı erişim denetimi (CWE-285) ve TTL denetimi (CWE-613) sağlar.
3. Otomatik versiyon rotasyonu ve acil durum iptali (Revocation) gerçekleştirir.
4. `SecretScanner` ile hem regex kalıplarını hem de Shannon entropisini tarayarak kod içi hardcoded secret'ları yakalar (CWE-798).
5. `mask_log_message` ile loglardaki gizli verileri temizler (CWE-532).

Evlat, bu dersi iyi belle: Şifreyi koda yazan mühendis hırsıza anahtarı paspasın üstüne bırakan ev sahibidir. Anahtarlarını daima kasada, kasayı ise çelik zırhın ardında tutacaksın!
