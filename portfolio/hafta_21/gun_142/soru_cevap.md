<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 142: CVSS Temel Metrikleri — Usta-Çırak Soru & Cevap

Bu belgede, FIRST CVSS v3.1 standardında zafiyet puanlaması yapılırken analistlerin en çok zorlandığı Scope (Kapsam) değişimi, Attack Complexity (Saldırı Karmaşıklığı) nüansları ve Privileges Required (Yetki Düzeyi) etkileri 3 derinlemesine soru altında incelenmiştir.

---

## Soru 1: Scope (Kapsam) Değişimi (`S:U` vs `S:C`) ve Puan Üzerindeki Çarpan Etkisi

### 1. Soru Başlığı ve Tanımı
CVSS v3.1 standardında Kapsam Değişimi (`Scope: Changed - S:C`) tam olarak hangi güvenlik sınırının aşılması anlamına gelir ve matematiksel formülde neden 1.08 çarpanı ve üstel kuvvet ($(\text{ISS} - 0.02)^{15}$) kullanılır?

### 2. Derinlemesine Teknik Analiz
Geleneksel CVSS v2 standardında en çok eleştirilen konu, sanallaştırma ve konteyner teknolojilerinin ortaya çıkardığı çok katmanlı sınır ihlallerini yansıtamamasıydı. Bir web uygulamasındaki açık yalnızca o web sitesini etkileyebileceği gibi, web uygulamasındaki bir açık kullanılarak sunucudaki hipervizör veya kullanıcıların tarayıcı oturumları da ele geçirilebilirdi.

CVSS v3.1'de **Yetkilendirme Kapsamı (Authorization Scope)** kavramı getirildi:
- **Savunmasız Bileşen (Vulnerable Component):** Zafiyeti barındıran yazılım veya donanım (örn: misafir VM içindeki bir sürücü).
- **Etkilenen Bileşen (Impacted Component):** Zafiyetin sonucundan zarar gören yazılım veya donanım (örn: ana hipervizör ESXi veya KVM).

Eğer bu iki bileşenin yetkilendirme otoritesi farklıysa, yani savunmasız bileşendeki bir açık başka bir otorite alanındaki kaynakları etkiliyorsa **Scope Changed (`S:C`)** gerçekleşir:
1. **VM Escape (Hipervizör İhlali):** Misafir sanal makineden ana fiziksel sunucuya sıçrama.
2. **Konteyner Kaçışı (Container Breakout):** Docker/K8s konteynerinden ana çekirdeğe sıçrama (örn: `runc` CVE-2024-21626 Leaky Vessels).
3. **Cross-Site Scripting (XSS):** Web sunucusundaki açık üzerinden kurbanın tarayıcı bağlamında kod çalıştırma (Sunucu otoritesinden İstemci tarayıcı otoritesine geçiş).
4. **Log4Shell (CVE-2021-44228):** Java kütüphanesindeki zafiyet üzerinden tüm işletim sisteminin tam kontrolünü ele geçirme.

**Matematiksel Formül Etkisi:**
Scope Unchanged olduğunda etki katsayısı `6.42 * ISS` iken, Scope Changed olduğunda karmaşık polinom devreye girer:
$$\text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$$
Ve nihai formülde **1.08 çarpanı** uygulanır. Örneğin aynı etki değerlerine sahip bir açıkta `S:U` iken skor 8.8 çıkarken, `S:C` yapıldığında skor **9.9 (Kritik)** seviyesine fırlar!

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir bulut sağlayıcısında (Cloud Provider) kiralanan sanal sunucuda (VPS) QEMU aygıt öykünme sürücüsünde bir bellek taşması zafiyeti keşfedilir.
- Eğer analist bu açığı `S:U` (Scope Unchanged) olarak puanlarsa: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` -> Skor: **7.8 (Yüksek)**.
- Ancak bu açık kullanılarak diğer müşterilerin verilerini barındıran ana sunucu (Host OS) ele geçirilebildiği için gerçekte `S:C` (Scope Changed) mevcuttur.

**Doğru Değerlendirme:**
Vektör `S:C` olarak düzeltildiğinde:
`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` -> Skor: **8.8 (Yüksek)** ve çoklu kiracı ortamında doğrudan acil yamalanma zorunluluğu doğar.

### 4. Ustanın Çırağa Tavsiyesi
> "Gözünü dört aç evlat! Bir zafiyet analizinde 'Kapsam değişti mi?' sorusunu sorarken kendine şu soruyu sor: 'Kurban kim?' Zafiyeti barındıran yazılım ile zarar gören sistem aynı yetki dairesinde mi, yoksa saldırgan bir duvarı yıkıp komşu daireye mi geçti? Eğer bir duvar yıkıldıysa, `S:C` bayrağını çekeceksin!"

---

## Soru 2: Attack Complexity (`AC:L` vs `AC:H`) ve regreSSHion Örneği

### 1. Soru Başlığı ve Tanımı
CVSS v3.1'de Saldırı Karmaşıklığı (Attack Complexity) metriğinde Düşük (`AC:L`) ve Yüksek (`AC:H`) arasındaki teknik fark nedir ve 2024 yılında keşfedilen `regreSSHion` (CVE-2024-6387) zafiyetinde skor neden 9.8 yerine 8.1 olarak hesaplanmıştır?

### 2. Derinlemesine Teknik Analiz
FIRST CVSS v3.1 şartnamesine göre **Attack Complexity (AC)**, saldırının hedef sisteme ulaştıktan sonra başarıya ulaşması için gereken koşulların saldırganın kontrolünde olup olmadığını ölçer:

- **Low (`AC:L` - Katsayı 0.77):** Saldırgan saldırıyı başlattığı her seferinde başarı garantidir. Hedef sistemde özel bir bellek düzeni, yarış durumu (race condition) veya karmaşık şifreleme anahtarı tahmini gerekmez. Örneğin Log4Shell veya basit bir SQL Enjeksiyonu `AC:L`'dir.
- **High (`AC:H` - Katsayı 0.44):** Saldırının başarılı olması için saldırganın kontrol edemediği dış etkenlerin denk gelmesi gerekir:
  1. **Yarış Durumu (Race Condition):** İki sürecin veya sinyal işleyicisinin mikrosaniye düzeyinde çakışması gerekir.
  2. **ASLR / Bellek Düzeni Korumaları:** Saldırganın yüz binlerce kez bellek adresini denemesi (brute-force) veya hedef sistemin hafızayı belirli bir düzende tutması gerekir.
  3. **Ağ Ortamı / Man-in-the-Middle (MitM):** Saldırganın ağda aktif olarak araya girmesi ve trafiği manipüle etmesi zorunludur.

**`regreSSHion` (CVE-2024-6387) Vakası:**
OpenSSH sunucusunda `SIGALRM` sinyal işleyicisinde bir yarış durumu zafiyeti keşfedildi. Saldırgan uzaktan kimlik doğrulamadan root yetkisi elde edebiliyordu (`AV:N/PR:N/UI:N/C:H/I:H/A:H`).
İlk bakışta bu açık 9.8 (Kritik) gibi görünüyordu. Ancak:
- Yarış durumunu tutturabilmek ve ASLR korumasını atlatabilmek için ortalama **10.000 bağlantı denemesi** ve 32-bit x86 sistemlerde bile yaklaşık **6-8 saat kesintisiz saldırı trafiği** gerekiyordu. 64-bit sistemlerde ise bu süre haftalar alıyordu.
- Dolayısıyla saldırı karmaşıklığı **`AC:H`** olarak sınıflandırıldı.
- `AC:H` (0.44 katsayısı), İstismar Edilebilirlik skorunu 3.9'dan **2.2**'ye düşürdü ve nihai skor **8.1 (High)** olarak tescillendi.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kurumun SOC analisti, `regreSSHion` zafiyetinin CVSS puanını 9.8 zannederek tüm sunucuları mesai saatinde anında kapatmaya karar verir. Ancak tecrübeli güvenlik mimarı vektörü inceler:
`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` -> 8.1.
Saldırının gerçekleşebilmesi için tek bir IP'den saatlerce on binlerce SSH bağlantısı açılması gerektiğini bilir.

**Pratik Çözüm:**
Sistemleri kapatmak yerine güvenlik duvarında (nftables/fail2ban) rate-limiting kuralı devreye sokulur:
```bash
nft add rule inet filter input tcp dport 22 ct state new limit rate over 10/minute drop
```
Saldırganın yarış durumunu tetiklemesi imkansız hale getirilir; sistemler çalışmaya devam ederken gece planlı bakımda OpenSSH paketi güncellenir.

### 4. Ustanın Çırağa Tavsiyesi
> "Evlat, `AC:L` ile `AC:H` arasındaki farkı bilmeyen analist paniğe kapılır. Bir açık uzaktan kod çalıştırıyor (RCE) diye hemen dünyanın sonu gelmiş sanma. Eğer `AC:H` ise, saldırganın o açığı sömürebilmek için binlerce kez kapıyı çalması gerekir. Sen o sırada kapıya nöbetçi (rate-limiting veya IPS) dikersen, saldırgan içeri giremeden yorulur!"

---

## Soru 3: Privileges Required (`PR`) ve Yetki Önkoşulunun Risk Skoru Üzerindeki Dramatik Düşüşü

### 1. Soru Başlığı ve Tanımı
Bir zafiyetin istismar edilebilmesi için kimlik doğrulama gerekmesi (`PR:L` veya `PR:H`), CVSS skorunu neden 9.8 gibi kritik bir seviyeden 7.2 veya 6.5 seviyelerine düşürür ve sıfır güven (Zero Trust) mimarilerinde bu durum nasıl yorumlanmalıdır?

### 2. Derinlemesine Teknik Analiz
CVSS v3.1'de **Privileges Required (PR)** metriği, saldırganın açığı tetiklemeden önce hedef sistemde sahip olması gereken yetki düzeyini ölçer:

- `PR:N (None = 0.85)`: Saldırgan tamamen anonimdir, hiçbir kullanıcı adı veya parolaya ihtiyacı yoktur (En yüksek risk).
- `PR:L (Low = 0.62)`: Saldırganın temel bir kullanıcı hesabı olmalıdır (Örn: standart e-posta kullanıcısı veya kısıtlı Linux kabuğu).
- `PR:H (High = 0.27)`: Saldırganın zaten yönetici, DBA veya root yetkisine sahip olması gerekir.

**Matematiksel Kıyaslama:**
İki zafiyet düşünelim, diğer tüm metrikleri birebir aynı olsun (`AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H`):
1. Durum 1 (`PR:N` - Anonim):
   $$\text{Exploitability} = 8.22 \times 0.85 \times 0.77 \times 0.85 \times 0.85 = 3.89$$
   $$\text{Base Score} = \text{Roundup}(5.9 + 3.89) = \mathbf{9.8 \ (CRITICAL)}$$
2. Durum 2 (`PR:H` - Yönetici Yetkisi Gerekiyor):
   $$\text{Exploitability} = 8.22 \times 0.85 \times 0.77 \times 0.27 \times 0.85 = 1.23$$
   $$\text{Base Score} = \text{Roundup}(5.9 + 1.23) = \mathbf{7.2 \ (HIGH)}$$

Fark **2.6 puan** gibi devasa bir düşüştür! Zafiyet Kritik kategorisinden Yüksek kategorisine iner. Çünkü saldırganın önce o yönetici şifresini bulması gerekmektedir.

**Sıfır Güven (Zero Trust) Bakış Açısı:**
Geleneksel çevre güvenliğinde `PR:L` açıkları daha az önemsenirdi çünkü "kullanıcılar zaten bizim çalışanlarımız" varsayımı yapılırdı.
Ancak Zero Trust mimarisinde **"Her kimlik potansiyel olarak ele geçirilmiş sayılır (Assume Breach)"**. Bu nedenle bir saldırgan oltalama (phishing) ile standart bir kullanıcı hesabı elde ettiğinde, `PR:L` olan zafiyetleri kullanarak dikey yetki yükseltme (privilege escalation) yapar.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Linux sunucusunda `sudo` paketinde `Baron Samedit` (CVE-2021-3156) bellek taşması zafiyeti mevcuttur.
- Vektör: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` -> Skor: **7.8 (Yüksek)**.
Zafiyet yerel bir kullanıcının anında root olmasını sağlar. Ancak zafiyet `PR:L` gerektirdiği için dışarıdaki bir anonim saldırgan doğrudan saldıramaz.

**Pratik Çözüm:**
Güvenlik ekibi dışa açık servislere (AV:N/PR:N) anında acil yama uygularken, `sudo` zafiyetini iç tehdit ve yanal hareket (lateral movement) senaryoları için PAM çok faktörlü kimlik doğrulama (MFA) ve auditd kurallarıyla izole eder, ardından planlı yama uygular.

### 4. Ustanın Çırağa Tavsiyesi
> "Çırak, formüle bakıp aldanma! Kağıt üzerinde `PR:L` bir açığın skoru 7.8 diye onu önemsiz görme. Eğer içerideki bir stajyerin şifresi zayıfsa veya bir çalışan zararlı bir makro çalıştırdıysa, o `PR:L` açığı saniyeler içinde bütün şirketi felç edecek bir rootkit'e dönüşür. Formül dışarıdaki tehlikeyi tartar, ama sen içerideki düşmanı da asla unutmayacaksın!"
