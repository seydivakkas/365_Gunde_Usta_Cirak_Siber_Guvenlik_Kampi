# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 112: Mini Proje 15 — İmzalı Yapılandırma Konsepti — Soru ve Cevaplar

---

## Soru 1: RFC 8785 JSON Kanonikleştirme (JCS) ve Tahrifat Koruması

### 1. Soru Başlığı ve Tanımı
Kriptografik olarak imzalanmış yapılandırma dosyalarında **RFC 8785 JSON Canonicalization Scheme (JCS)** standardı neden zorunludur? JSON formatındaki sözlük anahtarı sıralaması, boşluklar ve sayısal gösterimler kriptografik özet (Hash) üretimini nasıl bozar ve bu durum tahrifat korumasını (Tamper-Evidence / CWE-353) nasıl etkiler?

### 2. Derinlemesine Teknik Analiz
JSON (JavaScript Object Notation), insan tarafından okunabilir veri değişimi için tasarlanmış esnek bir dildir. Ancak bu esneklik, kriptografik bütünlük kontrolleri için ciddi bir zafiyet kaynağıdır:
1. **Sözlük Anahtar Sırasının Belirsizliği:** JSON standardı (RFC 8259) gereği nesne anahtarlarının belirli bir sırada olması zorunlu değildir.
   - Nesne 1: `{"port": 443, "service": "https"}`
   - Nesne 2: `{"service": "https", "port": 443}`
   Bu iki nesne anlamsal (semantik) olarak tamamen özdeştir; ancak ham bayt dizileri farklı olduğu için SHA-256 özetleri tamamen farklı çıkar!
2. **Boşluk ve Satır Sonu Farklılıkları:** Windows ortamında üretilen bir JSON dosyası `\r\n` (CRLF) satır sonu kullanırken, Linux ortamında `\n` (LF) kullanılır. Bir dosya Git üzerinden çekildiğinde veya bir editörle açılıp kaydedildiğinde boşluklar değişebilir.
3. **Kriptografik İmzanın Çöküşü:** İmza, verinin SHA-256 özeti üzerine atılır. Eğer veri kanonikleştirilmezse, içerik değişmediği halde sistem doğrulayıcısı `InvalidSignatureError` verir ve sistem kilitlenir. Ya da tersine, tahrif edilen alanlar sahte eşleşmeler üretebilir.

**RFC 8785 (JCS) Çözümü:**
- **Sözlük Anahtarları:** Tüm anahtarlar UTF-16 kod noktalarına göre alfabetik olarak sıralanır (`sort_keys=True`).
- **Boşlukların Temizlenmesi:** Ayraçlar arasındaki tüm boşluklar kaldırılır (`separators=(',', ':')`).
- **Karakter Kodlama:** Kesinlikle UTF-8 zorunludur.
Bu sayede bir nesne hangi platformda, hangi dille üretilirse üretilsin tek bir deterministik bayt dizisi üretir:
$$\text{JCS}(\text{Config}) \implies \text{Tek ve Değişmez Bayt Dizisi} \implies \text{Kusursuz SHA-256 Özeti}$$

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Kubernetes operatörü, güvenlik ilkelerini (Security Policy) merkezi bir yönetim sunucusundan JSON formatında çekmektedir. Yönetim sunucusu Python ile, istemci pod ise Go dili ile yazılmıştır. Python'ın varsayılan JSON serileştiricisi Go'nun varsayılan anahtar sıralamasıyla uyuşmadığı için her dağıtımda imza doğrulama hatası alınmış, mühendisler bu sorunu çözmek için imza kontrolünü tamamen devre dışı bırakmış ve küme saldırılara açık hale gelmiştir.

**Pratik Çözüm:**
RFC 8785 standart fonksiyonu hem imzalayıcıda hem de doğrulayıcıda zorunlu kılınmalıdır:
```python
def canonicalize_json(data: Any) -> bytes:
    """RFC 8785 standartlarına tam uyumlu deterministik JSON bayt dizisi üretir."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    ).encode('utf-8')
```

### 4. Ustanın Çırağa Tavsiyesi
Çırak! İki terazi farklı tartıyorsa problem ağırlıkta değil, terazinin kalibrasyonundadır. Kriptografide her karakter bir bit fırtınası koparır. Kanonikleştirme yapmadan imza atan geliştirici, rüzgarlı havada kuma imza atan adama benzer; ilk esintide imza silinir gider. RFC 8785 senin kalibrasyon standardındır; veriyi önce hizaya sokacaksın, sonra mührünü basacaksın!

---

## Soru 2: Yapılandırma Güvenliğinde Geri Alma (Rollback) Saldırıları ve Epoch Savunması

### 1. Soru Başlığı ve Tanımı
Bir yapılandırma yönetim sisteminde **Geri Alma (Rollback / Downgrade) Saldırısı (CWE-294)** nedir? Saldırgan daha önce meşru yetkililer tarafından imzalanmış eski bir konfigürasyon dosyasını sisteme sunduğunda asimetrik imza neden tek başına bu saldırıyı engelleyemez? **Monotonik Epoch Sayacı** bu zafiyeti nasıl kesin olarak çözer?

### 2. Derinlemesine Teknik Analiz
Bir saldırganın yeni bir yapılandırmayı tahrif edemediğini varsayalım; çünkü dijital imza anahtarına sahip değildir. Ancak saldırgan sistemin arşivinden 6 ay önceki eski bir yapılandırma dosyasını bulur:
- 6 ay önceki konfigürasyonda eski bir zafiyetli protokol (örn. TLS 1.0 veya zayıf bir şifreleme algoritması) aktiftir.
- Üstelik bu eski dosya o dönem kurumun yetkili güvenlik mimarı tarafından yasal olarak imzalanmıştır!
- Saldırgan sunucuya sızıp güncel dosyanın yerine bu eski meşru dosyayı yerleştirir.
- Sistem açılırken imza kontrolü yapar: İmza geçerlidir, güvenilen otoriteye aittir, içerik tahrif edilmemiştir!
- Sistem açılır ve saldırgan bilinen eski zafiyeti istismar eder. Buna **Rollback Saldırısı (CWE-294)** denir.

**Monotonik Epoch Sayacı Savunması:**
Asimetrik imza yalnızca "bu veriyi yetkili kişi yazdı mı ve veri bozuldu mu?" sorusuna yanıt verir; "bu veri bugünün taze verisi mi?" sorusuna yanıt veremez!

Bu yüzden zarfın içerisine **Monotonik Epoch Sayacı** entegre edilir:
1. Her yeni konfigürasyon yayınlandığında `epoch` değeri kesin olarak artırılır ($E_{n+1} > E_n$).
2. Sistem doğrulayıcısı güvenli yerel belleğinde en son kabul ettiği epoch değerini saklar (`current_system_epoch`).
3. Doğrulama kuralı:
   $$\text{Eğer } \text{Config.Epoch} < \text{System.CurrentEpoch} \implies \text{REJECT (Rollback Attack Detected!)}$$
4. Buna ek olarak bir `expires_at` (son geçerlilik tarihi / CWE-298) konularak belirli bir süreden eski konfigürasyonların tamamen geçersiz sayılması sağlanır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir endüstriyel SCADA ağında güvenlik politikası güncellenmiş ve uzaktan bakım portu (RDP 3389) kapatılmıştır. Bir siber saldırgan, 1 yıl önce imzalanmış eski konfigürasyon yedeğini sisteme yüklemiş; epoch denetimi olmadığı için sistem eski kurallara dönmüş ve saldırgan açık kalan porttan kontrol sistemine sızmıştır.

**Pratik Çözüm:**
Doğrulayıcıda epoch kontrolü tavizsiz işletilmelidir:
```python
def verify_anti_rollback(incoming_epoch: int, system_epoch: int) -> None:
    if incoming_epoch < system_epoch:
        raise RollbackAttackDetectedError(
            f"CWE-294: Geri alma saldırısı engellendi! Sistem epoch: {system_epoch}, sunulan epoch: {incoming_epoch}"
        )
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat! Dünün doğrusu bugünün tuzağı olabilir. Geçmişte imzalanmış bir ferman, bugünün kanunlarını hükümsüz kılıyorsa orada düzen çöker. İmzanın yanına mutlaka zamanın mührünü ve epoch sayacını koyacaksın; saati geriye sarmak isteyen hiçbir sahtekara geçit vermeyeceksin!

---

## Soru 3: Çift İmza (Dual Signing) ve "Fail-Safe Shutdown" Prensibi

### 1. Soru Başlığı ve Tanımı
Kritik altyapılarda **Çift İmza (Dual Signing / M-of-N Yetkilendirme / CWE-285)** neden bir zorunluluktur? Yapılandırma doğrulama sürecinde herhangi bir imza, tahrifat veya zaman anomalisi tespit edildiğinde sistemin sergilemesi gereken **"Fail-Safe Shutdown"** prensibi nedir? Neden asla esnek veya izin verici (permissive) varsayılan ayarlara dönülmemelidir?

### 2. Derinlemesine Teknik Analiz
**1. Dual Signing (Çift İmza ve Yetki Ayrımı / CWE-285):**
Kurumsal sistemlerde en tehlikeli tehdit içeriden gelen tehdittir (Malicious Insider veya hesabı ele geçirilmiş sistem yöneticisi).
- Eğer tek bir imza yeterli olursa, hesabı çalınan bir sistem yöneticisi tüm firewall kurallarını tek başına değiştirebilir.
- **Dual Signing Kuralı:** Zarf üzerinde bağımsız iki farklı roldeki uzmanın asimetrik imzası aranır:
  - Rol 1: Güvenlik Mimarı (SecOps Lead) -> Kuralın güvenlik standartlarına uygunluğunu onaylar.
  - Rol 2: Altyapı Direktörü (Infra Director) -> Kuralın operasyonel kesintiye yol açmayacağını onaylar.
- Doğrulayıcı, zarf içindeki imzaların genel anahtarlarını kontrol eder ve farklı yetkililerden en az $M$ (örn. 2) geçerli imza bulunmadıkça konfigürasyonu reddeder.

**2. Fail-Safe Shutdown Prensibi (Asla Fail-Open Olma!):**
Bir yazılım sistemi açılışta `config.json` dosyasını okurken imza hatası (`ConfigTamperingError`) alırsa ne yapmalıdır?
- **Yanlış ve Ölümcül Davranış (Fail-Open / Permissive Fallback):** "Konfigürasyon bozulmuş, müşteriler mağdur olmasın diye varsayılan ayarlarla açılıyorum."
  - Bu durumda saldırgan kasten dosyayı bozar, sistem varsayılan (ve genellikle korumasız) ayarlarla açılır ve saldırgan kaleyi fetheder!
- **Doğru Güvenlik Davranışı (Fail-Safe / Fail-Closed):**
  - "Konfigürasyon bütünlüğü doğrulanamadı. Sistem güvenli bir durumda değildir."
  - Servis derhal açılışı durdurur (`sys.exit(1)`), ağ bağlantılarını keser, SIEM sistemine yüksek öncelikli alarm gönderir ve insan müdahalesi gelene kadar kilitli kalır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir bulut erişim güvenlik aracında (CASB), imza doğrulama hatası alındığında yazılım "güvenlik duvarını devre dışı bırakıp tüm trafiğe izin vererek" açılacak şekilde kodlanmıştır. Tehdit aktörü sunucudaki konfigürasyon dosyasının sonuna tek bir boşluk ekleyerek imza kontrolünü düşürmüş ve güvenlik duvarı kendini kapatınca kurumun tüm iç ağına sızmıştır.

**Pratik Çözüm:**
Uygulama açılış döngüsünde istisnasız güvenli kapatma uygulanmalıdır:
```python
def bootstrap_application():
    try:
        config = verifier.verify_and_load(envelope)
        initialize_services(config)
    except SignedConfigError as e:
        # Asla varsayılan ayarlarla açılma!
        logger.critical(f"GÜVENLİK İHLALİ: Yapılandırma doğrulanamadı: {e}")
        alert_siem_system(event="CONFIG_VERIFICATION_FAILURE", error=str(e))
        sys.exit("FAIL-SAFE: Güvenlik bütünlüğü bozulduğu için sistem durduruldu.")
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat! Şüphe duyduğun yerde duracaksın; gözün görmediği, aklın onaylamadığı bir emirle savaşa girilmez. Bir konfigürasyonun mührü kırılmışsa "idare edelim" diyemezsin. Çalışmayan bir sistem veri kaybettirmez ama tahrif edilmiş ayarlarla çalışan bir sistem tüm şirketi batırır. Güvenlikte tereddüt anında kapıyı kapatacak, kilidi vuracak ve ustanın gelmesini bekleyeceksin!
