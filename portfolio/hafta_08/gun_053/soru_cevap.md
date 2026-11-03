<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 53: Port, Soket ve Bağlantı Durumu — Soru Bankası ve Usta-Çırak Mülakatı

---

## Soru 1 (G053-SC1): Temel Mekanizma ve Güvenlik Önemi

### Soru
Port, socket ve bağlantı durumu bağlamında: Temel mekanizmayı ve "Açık port doğrudan zafiyet anlamına gelmez" ilkesinin siber güvenlik açısından taşıdığı kritik önemi açıklayınız.

### Usta Cevabı
Port, Taşıma Katmanında (Transport Layer) çalışan 16-bitlik ($0-65535$) bir adresleme mekanizmasıdır; gelen paketlerin işletim sisteminde çalışan doğru sürece yönlendirilmesini (demultiplexing) sağlar. Soket ise bu iletişimin uç noktasıdır ve `(Protokol, Yerel IP, Yerel Port, Uzak IP, Uzak Port)` 5'li demeti (5-tuple) ile tanımlanır.

"Açık port tek başına bir zafiyet değildir" prensibi modern siber güvenliğin en temel taşlarındandır. Bir sistemde portun `LISTEN` durumunda olması, orada meşru bir ağ servisinin (örneğin HTTPS için 443, SSH için 22) gelen istekleri beklediğini gösterir. Zafiyet; portun açık olması değil, o kapının arkasında çalışan servisin:
1. Kimlik doğrulamasız olması (örn. parolasız Redis veya MongoDB),
2. Bilinen kritik güvenlik açıklarına (CVE) sahip güncellenmemiş eski bir yazılım olması,
3. Yanlış ağ arayüzüne (`0.0.0.0` - tüm internet) bağlanarak (bind) iç ağa özel kalması gereken verilerin dış dünyaya açılmasıdır.

Port sadece bir geçittir; saldırı yüzeyini genişletir ancak zafiyetin kendisi daima servis mimarisi, kimlik doğrulama ve yapılandırma katmanındadır.

### Kritik Güvenlik / Mühendislik Noktası
0-1023 arasındaki Well-known portlar Unix/Linux mimarisinde yalnızca `root` (veya `CAP_NET_BIND_SERVICE`) yetkisiyle açılabilir. Eğer 1024'ten küçük bir portu dinleyen bir web servisinde (örn. port 80 Apache/Nginx) uzaktan kod yürütme (RCE) zafiyeti oluşursa ve servis yetki düşürme (privilege dropping - `www-data` kullanıcısına geçiş) yapmamışsa, saldırgan doğrudan en yüksek sistem yetkisini (`root`) ele geçirir.

### Çırak İçin Pratik Çıkarım
Bir güvenlik taraması (Nmap) yaptığında raporuna sadece "Port 80 açık, sistem tehlikede" yazma. Portun arkasında hangi yazılımın ve sürümün çalıştığını, kimlik doğrulamanın bulunup bulunmadığını ve servisin hangi IP arayüzüne bağlandığını araştırmadan zafiyet hükmü verme.

---

## Soru 2 (G053-SC2): Bağımsız Laboratuvar Tasarımı ve Kontroller

### Soru
Port, socket ve bağlantı durumu bağımsız laboratuvarının girdisi, işleme adımları, beklenen gözlenebilir sonucu ve negatif kontrolü nedir?

### Usta Cevabı
G053 laboratuvarı harici üçüncü taraf araçlara veya önceki günün kodlarına bağımlı olmaksızın kendi başına çalışan yerel bir soket denetim ve durum doğrulama laboratuvarıdır:
- **Girdi:** 
  1. Gerçekçi işletim sistemi soket tablosu simülasyonu (`ornek_veri/sample_socket_table.json`): Meşru dinleyiciler (Nginx 443, SSH 22), güvenli yerel veritabanı (Postgres 127.0.0.1:5432), tehlikeli şekilde dışa açılmış servis (Redis 0.0.0.0:6379), meşru giden HTTPS oturumu (Chrome), ve ters kabuk (PowerShell -> 4444).
  2. 8 adet kural dışı ve sınır aşımı negatif kontrol senaryosu (`ornek_veri/invalid_socket_inputs.json`).
- **İşlem:**
  1. `PortClassifier.classify_port`: IANA standartlarına göre 0-1023 (Well-known), 1024-49151 (Registered) ve 49152-65535 (Dynamic/Ephemeral) aralıklarını sınıflandırma ve hassas servis tespiti.
  2. `SocketEndpoint`: Soket uç noktasının 5-tuple yapısını oluşturma, `is_listening()`, `is_loopback_only()`, `is_all_interfaces()` özelliklerini denetleme.
  3. `TCPStateTransitionSimulator`: RFC 793/9293 kurallarına göre durum makinesi geçişlerini (CLOSED -> LISTEN -> SYN_RECEIVED -> ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT -> CLOSED) yürütme ve kural dışı atlamaları engelleme.
  4. `SocketSecurityAuditor.audit_socket_table`: Soket tablosunu tarayarak `0.0.0.0` hassas servis ifşasını (`INSECURE_BIND_EXPOSURE`), Reverse Shell bağlantılarını (`REVERSE_SHELL_DETECTED`), SYN Flood yığılmasını (`SYN_FLOOD_SUSPICION`) ve TIME_WAIT tükenmesini (`TIME_WAIT_ACCUMULATION`) puanlama.
- **Beklenen Sonuç:** 14 birim testin 0.01 saniyenin altında `PASS` alması; Redis'in `0.0.0.0` ifşasının ve PowerShell port 4444 ters kabuğunun `CRITICAL` seviyesinde yakalanması; RFC 793 durum geçişlerinin hatasız simüle edilmesi.
- **Negatif Kontrol:** Negatif port (-1), port taşması (70000), geçersiz TCP durumu (`INVALID_STATE_XYZ`), hatalı IP formatı (`300.1.2.3`), negatif PID ve desteklenmeyen protokoller verildiğinde sistemin sessiz kalmayıp `SocketValidationError` fırlatması (8/8 başarı).

### Kritik Güvenlik / Mühendislik Noktası
RFC 793 durum makinesinde `LISTEN` durumundan doğrudan `ESTABLISHED` durumuna geçilemez; arada mutlaka `SYN_RECEIVED` adımı bulunmalıdır. Aynı şekilde aktif kapanışta `FIN_WAIT_2` durumundan doğrudan `CLOSED` durumuna geçilemez; soket mutlaka $2 \times \text{MSL}$ süresince `TIME_WAIT` durumunda beklemelidir. Bu durum kurallarına uymayan bir uygulama çekirdek seviyesinde soket kilitlenmelerine veya veri karışmalarına sebep olur.

### Çırak İçin Pratik Çıkarım
Kendi bilgisayarında PowerShell'i açıp `Get-NetTCPConnection -State Listen` veya Linux'ta `ss -tulpn` çalıştır. Dinleyen portların karşısında `0.0.0.0` mı yoksa `127.0.0.1` mi yazdığına dikkat et. Eğer veritabanın `0.0.0.0`'da dinliyorsa, aynı Wi-Fi ağındaki herkes senin veritabanına bağlanabilir demektir.

---

## Soru 3 (G053-SC3): Tehdit Modeli, Tespit ve Savunma Kontrolleri

### Soru
"Port, socket ve bağlantı durumu" bağlamında siber güvenlik riskleri nasıl oluşur, ağ ve uç nokta düzeyinde hangi sinyallerle tespit edilir ve hangi kontrollerle önlenir?

### Usta Cevabı
- **Risk Oluşumu:** 
  1. **Yetkisiz Dış İfşa (Insecure Bind):** Geliştiricilerin iç ağ servislerini (Redis, MongoDB, Elasticsearch, Telnet) `0.0.0.0` adresine bağlaması sonucu saldırganların internet üzerinden doğrudan erişim sağlayarak kimlik doğrulamasız RCE elde etmesi.
  2. **Reverse Shell (Ters Kabuk İhlali):** Saldırganın içeriye sızdıktan sonra güvenlik duvarının giden (outbound) kurallarının gevşek olmasından faydalanarak `powershell.exe` veya `/bin/sh` üzerinden dışarıdaki dinleyiciye (örn. port 4444) oturum açması.
  3. **SYN Flood ve TIME_WAIT Tükenmesi:** Yüzlerce soketin `SYN_RECEIVED` veya `TIME_WAIT` durumunda birikerek işletim sisteminin soket ve dosya tanımlayıcı (file descriptor) limitlerini tüketmesi ve DoS oluşması.
- **Tespit Sinyalleri:**
  1. `netstat -ano` veya `ss -tunaep` çıktısında `powershell.exe`, `cmd.exe` veya `bash` süreçlerinin dış IP'lere `ESTABLISHED` soket tutması.
  2. Kritik veritabanı portlarının (3306, 5432, 6379, 27017) `0.0.0.0` veya `:::` üzerinde dinlemede olması.
  3. Tek bir portta 5'ten fazla soketin `SYN_RECEIVED` durumunda asılı kalması (SYN Flood sinyali).
  4. Saniyede yüzlerce yeni `TIME_WAIT` soketinin açılıp kapanması (ephemeral port tükenmesi sinyali).
- **Savunma Kontrolleri:**
  1. **Strict Localhost Binding:** Tüm iç servisler yapılandırma dosyalarında kesinlikle `bind 127.0.0.1` olarak tanımlanmalıdır.
  2. **Egress (Çıkış) Filtrelemesi:** Güvenlik duvarlarında sunucuların internete gelişigüzel portlardan çıkması engellenmeli; yalnızca belirli hedeflere ve portlara (80, 443, 53) giden trafiğe izin verilmelidir. Böylece 4444 veya 1337 gibi portlara ters kabuk açılamaz.
  3. **En Az Yetki İlkesi (Least Privilege):** Web ve ağ servisleri asla `root` veya `Administrator` yetkisiyle çalıştırılmamalıdır.
  4. **TCP Parametre Optimizasyonu:** Çekirdekte `net.ipv4.tcp_syncookies = 1`, `net.ipv4.tcp_tw_reuse = 1` ve `net.ipv4.ip_local_port_range = 1024 65535` ayarları yapılarak kaynak tükenmesi önlenmelidir.

### Kritik Güvenlik / Mühendislik Noktası
Egress filtrelemesi (giden trafik kısıtlaması) siber savunmada en çok ihmal edilen ancak en etkili güvenlik kontrolüdür. Bir sunucu saldırgan tarafından ele geçirilse bile, eğer o sunucunun dışarıdaki rastgele IP ve portlara TCP bağlantısı kurması güvenlik duvarında engellenmişse, saldırgan ters kabuk (Reverse Shell) elde edemez ve sızıntı büyümeden durdurulur.

### Çırak İçin Pratik Çıkarım
Bir sunucu kurduğunda işin bitmiş sayılmaz. Son adım olarak `ss -tulpn` çalıştır; dış dünyaya açılmaması gereken tek bir port bile `0.0.0.0` görüyorsan o sunucuyu canlı ortama alma. Güvenlik, kapıları kapatma sanatıdır.
