# GÜN 33: DOSYA HASH VE KRİPTOGRAFİK BÜTÜNLÜK
## Usta-Çırak / Hoca Dersi Notları

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, dağıtılamaz, ticari amaçla kullanılamaz.
```

---

### 1. Giriş ve Temel Pedagojik Yaklaşım: Çırağa Öğüt
Evlat, siber güvenliğin kutsal üçlüsü olan **CIA Triad**'ın (Gizlilik, Bütünlük, Erişilebilirlik) ortasındaki o "Bütünlük" (Integrity) harfi, modern sistemlerin ayakta kalmasını sağlayan görünmez omurgadır. 

Bir işletim sisteminde veya ağda bir dosyanın içeriğinin değişip değişmediğini, aktarım sırasında bozulup bozulmadığını ya da bir saldırgan tarafından tahrif edilip edilmediğini nasıl anlarsın? Dosyayı satır satır gözünle mi okuyacaksın? 10 Gigabaytlık bir veri tabanı yedeğini ya da bir sistem çekirdeğini (kernel) nasıl karşılaştıracaksın?

İşte burada devreye **Kriptografik Özetleme Fonksiyonları (Cryptographic Hash Functions)** girer. 

Bugün seninle şu altın kuralı öğreneceğiz:
> **"SHA-256 gibi özetler dosya değişimini saptar; fakat hash tek başına bir dosyanın güvenilir olduğunu asla söylemez!"**

Bu iki kavramı (Bütünlük ile Güvenilirlik) birbirine karıştıran sözde güvenlikçiler, bir zararlının SHA-256 özetini alıp "Bakın hash değeri var, demek ki dosya sağlam" diyebilecek kadar büyük gafletlere düşebilirler. Bugün bu yanılgıyı sonsuza dek hafızandan sileceğiz.

---

### 2. Kriptografik Özet Fonksiyonlarının Matematiksel Özellikleri

Kriptografik özet fonksiyonu, herhangi bir uzunluktaki girdiyi (ister 1 baytlık bir harf, ister terabaytlarca disk imajı) alıp sabit uzunlukta (fixed-size) benzersiz bir onaltılık dizgiye dönüştüren matematiksel bir algoritmadır.

Bir fonksiyonun "kriptografik" sayılabilmesi için şu üç temel niteliğe sahip olması şarttır:
1. **Tek Yönlülük (One-Way Property / Pre-Image Resistance):**
   Verilen bir \( h \) özet değerinden yola çıkarak, \( H(m) = h \) eşitliğini sağlayan orijinal \( m \) girdisini hesaplamak pratikte imkânsız olmalıdır. Yani özetten orijinal dosyaya geri dönüş yoktur.
2. **İkinci Ön Görüntü Direnci (Second Pre-Image Resistance):**
   Verilen belirli bir \( m_1 \) girdisi için, \( H(m_1) = H(m_2) \) olacak şekilde farklı bir \( m_2 \) girdisi bulmak hesaplama açısından imkânsız olmalıdır. Saldırgan meşru bir dosyanın yerine aynı özeti veren sahte bir dosya koyamamalıdır.
3. **Çarpışma Direnci (Collision Resistance):**
   Hiçbir kısıtlama olmaksızın, \( H(m_1) = H(m_2) \) olan rastgele iki farklı \( m_1 \) ve \( m_2 \) girdisi bulmak imkânsız olmalıdır.

#### Neden MD5 ve SHA-1 Tarihe Karıştı?
- **MD5 (128 bit):** 2004 yılında Çinli araştırmacı Xiaoyun Wang ve ekibi tarafından pratik çarpışma saldırılarıyla delinmiştir. 2012 yılında Flame casus yazılımı, Microsoft'un MD5 tabanlı kod imzalama sertifikasını taklit ederek Windows Update üzerinden yayılmıştır. Bugün güvenlik doğrulamalarında **kesinlikle yasaktır**.
- **SHA-1 (160 bit):** 2017 yılında Google ve CWI araştırmacıları tarafından **SHAttered** saldırısıyla iki farklı PDF dosyasına aynı SHA-1 özetini üreterek kırılmıştır.
- **SHA-256 (SHA-2 Ailesi - 256 bit):** Günümüzün endüstri standardıdır. Olası kombinasyon sayısı \( 2^{256} \) olup evrendeki gözlemlenebilir atom sayısından fazladır.

---

### 3. Çığ Etkisi (Avalanche Effect) Nedir?

Kriptografik algoritmaların en büyüleyici özelliği **Çığ Etkisidir**. Girdide yapılan en ufak bir değişiklik (örneğin sadece 1 bitin 0'dan 1'e çevrilmesi veya tek bir virgülün silinmesi), algoritmanın iç tur karıştırma matrislerinde öyle bir domino etkisi yaratır ki, ortaya çıkan 256 bitlik özetin yaklaşık **%50'si tamamen rastgele ve tahmin edilemez şekilde değişir**.

Laboratuvarımızda geliştirdiğimiz örnekte gördüğümüz gibi:
- Orijinal dosya (`config.json`): `"debug_mode": false` -> SHA-256: `2cf886ce37d1c9fdf227bd875fc638c83938da29d65c074a562c30e79136474f`
- Tahrif edilmiş dosya (`tampered_config.json`): `"debug_mode": true` -> SHA-256: `91a7743b52a28d0b1f2f9ac03d848dca744ee0b9fe8d9f62608de3870e363d3c`
- **Fark:** 256 bitin tam **122 biti (%47.66)** tamamen değişti!

Bu özellik sayesinde saldırgan tek bir biti bile değiştirse, özetin ilk birkaç hanesine bakarak dahi tahrifatı anında yakalarız.

---

### 4. Bütünlük (Integrity) vs Güvenilirlik (Trustworthiness): G033-SC1 Analizi

Çırak, bu ayrım mülakatlarda da adli bilişim incelemelerinde de hayat kurtarır:

| Kriter | Dosya Hash / Bütünlük (Integrity) | Dosya Güvenilirliği (Trustworthiness) |
| :--- | :--- | :--- |
| **Cevapladığı Soru** | "Bu dosya dün bildiğim dosya ile birebir aynı mı? Yolda bozuldu mu?" | "Bu dosya zararsız mı? Bir casus yazılım veya fidye virüsü içeriyor mu?" |
| **Kapsamı** | Yalnızca matematiksel kimlik ve değişmezlik. | Kodun amacı, güvenliği ve niyet analizi. |
| **Zararlı Yazılımda Durum** | Bir Ransomware veya Backdoor da geçerli, tutarlı bir SHA-256 üretir. | EDR, AV ve analist tarafından BLOKLANIR. |
| **Doğrulama Yöntemi** | SHA-256 özet karşılaştırması (FIM). | Dijital İmza (Authenticode), Kod İmzalama Sertifikası, Tehdit İstihbaratı (VirusTotal), Davranışsal Analiz. |

**Özetle:** Bir dosyanın SHA-256 hash'inin biliniyor olması, onun "güvenli" veya "temiz" olduğunu kanıtlamaz. Yalnızca elimizdeki referans kopyayla eşleştiğini gösterir.

---

### 5. Dosya Bütünlüğü İzleme (File Integrity Monitoring - FIM)

Kurumsal savunmada sunuculardaki kritik sistem dosyalarını korumak için **FIM** ajanları (Tripwire, OSSEC, Wazuh, AIDE) kullanılır.
FIM mekanizması 3 temel adımdan oluşur:
1. **Taban Çizgisi Oluşturma (Baseline Creation):** Temiz sistem kurulumunda (Golden Image) tüm kritik sistem dosyalarının (`/etc/`, `C:\Windows\System32\`, web kök dizini) SHA-256 özetleri, dosya boyutları ve izinleri bir manifestoda saklanır.
2. **Periyodik Tarama ve Karşılaştırma:** Ajan düzenli aralıklarla diskteki fiili dosyaları okuyup hash'ler ve taban çizgisiyle karşılaştırır:
   - **INTEGRITY_COMPROMISED:** Dosya mevcut ama hash farklı (Yetkisiz değişiklik).
   - **FILE_MISSING:** Taban çizgisindeki dosya diskte yok (Silinmiş).
   - **NEW_UNAUTHORIZED_FILE:** Diskte taban çizgisinde olmayan yabancı dosya var (Webshell, backdoor vb.).
3. **Alarm ve Olay Müdahalesi:** Uyuşmazlık anında SOC merkezine SIEM üzerinden alarm iletilir.

---

### 6. Terminal ve Komut Satırı Pratikleri

- **Windows PowerShell:**
  ```powershell
  Get-FileHash -Path .\config.json -Algorithm SHA256
  Get-FileHash -Path .\config.json -Algorithm MD5
  ```
- **Windows Klasik Komut Satırı:**
  ```cmd
  certutil -hashfile config.json SHA256
  ```
- **Linux Terminal:**
  ```bash
  sha256sum config.json
  # Birden fazla dosyanın bütünlüğünü topluca denetleme:
  sha256sum * > manifest.txt
  sha256sum -c manifest.txt
  ```

---

### Resmî Kaynaklar
- Microsoft Learn: [Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- NIST FIPS 180-4: [Secure Hash Standard (SHS)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- MITRE ATT&CK: [T1565.001 - Data Manipulation: Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/)
