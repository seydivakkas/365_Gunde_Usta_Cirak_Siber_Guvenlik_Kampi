# Gün 166: SSRF Kavramı ve Savunma — Usta-Çırak Derinlemesine Teknik Rehberi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Bu doküman ve kodlar yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, dağıtılamaz.

---

## 1. Usta Girişi: "Sunucuyu Truva Atına Dönüştürmek"

Evlat, modern web uygulamalarında istemciden bir URL alıp sunucu tarafında o URL'ye istek göndermek çok yaygın bir mimari modeldir.
Örnek verelim:
- Kullanıcı profil resmi için bir resim URL'si girer (Avatar fetching).
- Bir e-fatura veya rapor oluşturucu harici bir web sayfasını PDF'e dönüştürür (HTML-to-PDF).
- Bir webhook servisi, dışarıdaki bir uç noktaya bildirim yollar.

İşte tam bu noktada zafiyet pusuda bekler evlat!
Eğer sen istemciden gelen bu URL'yi körlemesine alıp `requests.get(user_url)` veya `curl` ile çağırırsan, saldırgan senin sunucunu **kendi vekil sunucusuna (Proxy / Truva Atı)** dönüştürür!
Bu zafiyetin adı **Sunucu Taraflı İstek Sahteciliği (Server-Side Request Forgery - SSRF / CWE-918)**'dir.

Neden bu kadar tehlikelidir bilir misin?
Çünkü senin web sunucun internete açıktır ama aynı zamanda şirketin **güvenli iç ağına (Intranet), veritabanlarına ve bulut metaveri servislerine** doğrudan bağlıdır! Saldırgan internetten erişemediği `10.0.0.5` veritabanına veya `169.254.169.254` bulut metaveri motoruna senin sunucun üzerinden elini kolunu sallayarak erişir!

---

## 2. SSRF Saldırı Hedefleri ve İstismar Senaryoları

### 2.1 Hedef 1: Yerel Döngü (Loopback: 127.0.0.1, localhost)
Web sunucuları genellikle sadece `localhost` üzerinde dinleyen yönetim panellerine (Admin Console, Redis 6379, Elasticsearch 9200, Memcached 11211) sahiptir. Saldırgan dışarıdan bu portlara bağlanamaz çünkü güvenlik duvarı (Firewall) dış erişimi engeller.
Fakat SSRF ile istek bizzat sunucunun içinden çıktığı için güvenlik duvarını tamamen atlatır:
```http
POST /api/fetch-avatar HTTP/1.1
Host: kurum.internal

{"url": "http://127.0.0.1:8080/admin/delete-database"}
```

### 2.2 Hedef 2: Bulut Metaveri Servisi (Cloud Metadata: 169.254.169.254)
Evlat, 2019 yılındaki meşhur Capital One sızıntısını hatırla! 100 milyondan fazla müşterinin verisi tek bir SSRF açığıyla çalındı. Nasıl mı?
AWS EC2, Google Cloud Compute Engine ve Azure sanal makineleri, sunucunun kimliğini doğrulamak için sabit bir bağlantı-yerel IP kullanır: `http://169.254.169.254/`.
Saldırgan şu URL'yi gönderir:
```http
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
```
Sunucu bu isteği yapar ve AWS geçici IAM erişim anahtarlarını (`AccessKeyId`, `SecretAccessKey`, `Token`) saldırgana geri döndürür. Saldırgan bu anahtarlarla tüm kurumsal AWS bulut hesabını ele geçirir!

### 2.3 Hedef 3: Protokol İstismarı (Protocol Smuggling)
Geliştirici HTTP beklerken saldırgan başka bir şema iletir:
- `file:///etc/passwd` veya `file:///c:/windows/win.ini`: Sunucunun yerel dosyalarını okur (LFI benzeri etki).
- `gopher://127.0.0.1:6379/_flushall`: Gopher protokolüyle ham TCP baytları göndererek iç ağdaki Redis veya veritabanı sunucularına komut enjekte eder.
- `dict://127.0.0.1:11211/stat`: Memcached durum bilgilerini çeker.

---

## 3. Gelişmiş Atlatma (Bypass) Teknikleri: Saldırganın Çantası

Geliştiriciler genellikle `if "127.0.0.1" in url:` veya `if "localhost" in url:` gibi ilkel kara listeler (Blacklist) yazarlar. Saldırgan bunu saniyeler içinde aşar:

### 3.1 IP Biçimini Gizleme (Obfuscation)
1. **Tamsayı (DWORD) Formatı:** `127.0.0.1` adresinin matematiksel tamsayı karşılığı `2130706433`'tür.
   `http://2130706433/` -> İşletim sistemi bunu doğrudan `127.0.0.1` olarak çözer!
2. **Onaltılık (Hexadecimal) Format:** `0x7f.0x0.0x0.0x1` veya `0x7f000001`
3. **Sekizli (Octal) Format:** `0177.0.0.1` (Önündeki sıfır octal tabanı temsil eder).
4. **Kısaltılmış Format:** `127.1` (A.B formatında B = 1, yani 127.0.0.1).
5. **IPv6 Karşılıkları:** `[::1]` veya IPv4-mapped IPv6 `[::ffff:127.0.0.1]`.

### 3.2 DNS Tabanlı Atlatmalar ve DNS Rebinding (TOCTOU)
Saldırgan kendi alan adını (`spoof.evil.com`) kurar ve DNS kaydını `127.0.0.1` yapar. Geliştirici domain kontrolü yaparsa domain temiz görünür ama çözülen IP iç ağdır!
Daha da sinsisi: **DNS Rebinding**.
Saldırganın DNS sunucusu ilk sorguda (senin kontrol anında) TTL=0 ile genel bir IP (`8.8.8.8`) döner. Kontrol geçer.
Fakat milisaniyeler sonra `requests.get()` asıl HTTP isteğini atarken DNS sunucusu bu kez `169.254.169.254` döner! Buna **Time-of-Check to Time-of-Use (TOCTOU)** denir!

### 3.3 HTTP Açık Yönlendirme (Open Redirect) Zinciri
Geliştirici sadece `https://public-service.com` alan adına izin verir.
Ancak `public-service.com` üzerinde bir açık yönlendirme (Open Redirect) açığı vardır:
`https://public-service.com/redirect?to=http://169.254.169.254/`
Geliştiricinin HTTP istemcisi ilk URL'yi onaylar; ancak `302 Found` başlığını körlemesine takip ederek metaveri IP'sine balıklama dalar!

---

## 4. Kurumsal Çok Katmanlı Savunma Mimarisi (Defense-in-Depth)

Evlat, SSRF'e karşı tek bir regex veya basit if-else kalkanı yetmez. Savunma katman katman örülmelidir:

### 4.1 Katman 1: Katı Şema İzin Listesi (Scheme Allowlist)
Yalnızca `http` ve `https` protokollerine izin verilir. `file`, `gopher`, `dict`, `ftp` derhal reddedilir.

### 4.2 Katman 2: URL Ayrıştırma ve IP Normalizasyonu
URL'deki host dizesi ayrıştırılır. Tamsayı, Hex, Octal ve IPv6-mapped desenleri tespit edilerek standart IPv4/IPv6 formatına çevrilir.

### 4.3 Katman 3: DNS Çözümlemesi ve Kapsamlı IP Filtresi (Pre-Request Inspection)
Host adının DNS sorgusu yapılır (`socket.getaddrinfo`). Dönen TÜM IP adresleri incelenir:
- `ip.is_loopback` (127.0.0.0/8, ::1) -> YASAK!
- `ip.is_private` (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) -> YASAK!
- `ip == 169.254.169.254` (Bulut Metaveri) -> YASAK!
- `ip.is_link_local` (169.254.0.0/16, fe80::/10) -> YASAK!
- `ip in 100.64.0.0/10` (CGNAT) -> YASAK!
- `ip.is_unspecified` (0.0.0.0) -> YASAK!

### 4.4 Katman 4: IP Sabitleme (IP Pinning) ile DNS Rebinding Engeli
DNS sorgusuyla doğrulanan IP adresi HTTP soketine doğrudan verilir (Pinning). İkinci bir DNS sorgusu yapılması engellenir.

### 4.5 Katman 5: Güvenli Yönlendirme Denetimi (Redirect Re-Validation)
HTTP istemcisi `301`, `302`, `307`, `308` yönlendirmelerini körlemesine takip etmez!
Dönen `Location` başlığındaki yeni hedef, sıfırdan Katman 1'den başlayarak tüm SSRF filtrelerinden geçirilir.

### 4.6 Katman 6: Altyapı ve Ağ Seviyesi İzolasyonu
- Sunucuların işletim sistemi seviyesinde (`iptables` / Windows Defender Firewall) `169.254.169.254` ve iç ağ alt ağlarına doğrudan çıkışı (egress) engellenmelidir.
- AWS ortamlarında **IMDSv2** zorunlu kılınmalı; `X-aws-ec2-metadata-token` oturum başlığı şartı ve `Hop-Limit=1` ile SSRF geçişleri altyapıdan kilitlenmelidir.

---

## 5. Çırağa Öğütler ve Saha Deneyimi
Evlat, dışarıdan URL alan her fonksiyon bir saatli bombadır. Asla "Kullanıcı sadece resim linki verir canım" deme. Ağ seviyesinde izole etmediğin, DNS çözümlemesini denetlemediğin ve yönlendirmeleri körlemesine takip ettiğin her sistem bir gün sana bulut anahtarlarını çaldırarak bedel ödetir!
