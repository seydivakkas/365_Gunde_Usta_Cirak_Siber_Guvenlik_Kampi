# Gün 126: Soru & Cevap — Aşama 5 Kalite Özeti ve Kabul

---

### Soru 1: Kriptografik Geçiş Standartları (NIST SP 800-131A / SP 800-57) kapsamında neden MD5, SHA-1 ve 1024-bit RSA gibi eski mekanizmalar derhal terk edilmelidir ve kurumsal sistemlerde kriptografik çeviklik (Cryptographic Agility) nasıl sağlanır?

#### 1. Soru Başlığı ve Tanımı
NIST SP 800-131A standardı, zaman içerisinde matematiksel veya donanımsal gelişmelerle zayıflayan kriptografik algoritmaların ve yetersiz anahtar boyutlarının tedavülden kaldırılmasını (deprecation) düzenler. MD5 ve SHA-1'in çarpışma direnci yok olmuş, 1024-bit RSA ise hesaplama maliyeti açısından süper bilgisayarlar ve bulut kümleri tarafından kırılabilir seviyeye inmiştir (CWE-327 / CWE-326).

#### 2. Derinlemesine Teknik Analiz
1. **Çarpışma Saldırıları (Collision Attacks):**
   - MD5 için 2004'te Wang ve ekibi tarafından pratik çarpışma yöntemleri bulunmuş; 2012'de Flame zararlısı Microsoft Terminal Server sertifikasını MD5 çarpışması ile taklit etmiştir.
   - SHA-1 için 2017'de Google ve CWI Amsterdam tarafından gerçekleştirilen SHAttered saldırısı ile aynı özete sahip iki farklı PDF dokümanı üretilmiştir.
2. **Faktörlere Ayırma Gücü (Factorization):**
   - 1024-bit RSA anahtarlarının çarpanlarına ayrılması NFS (Number Field Sieve) algoritmaları ve modern GPU/ASIC kümeleriyle teorik sınırdan pratik sınıra inmiştir. Güvenlik eşiği asgari 2048-bit (112-bit güvenlik seviyesi), tavsiye edilen 3072 veya 4096-bit (128/192-bit güvenlik) seviyesidir.
3. **Kriptografik Çeviklik (Crypto Agility):**
   - Uygulama kodlarında algoritmalar (`AES`, `SHA-256`, `Ed25519`) sabit kodlanmamalı (hardcoded); yapılandırma servisleri veya soyut arayüzler (Crypto Provider Abstraction) üzerinden dinamik olarak değiştirilebilir olmalıdır. Böylece kuantum sonrası (PQC - Post-Quantum Cryptography) algoritmalar çıktığında kod tabanını yeniden yazmaya gerek kalmaz.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir ödeme kuruluşu, POS cihazları ile ana sunucu arasındaki oturum anahtarlarını 1024-bit RSA ile takas etmekte ve işlem kayıtlarını SHA-1 ile imzalamaktadır. PCI-DSS ve BDDK denetçileri bu durumu tespit etmiş ve şirkete 30 gün içinde düzeltme, aksi halde lisans askıya alma uyarısı vermiştir.
**Pratik Çözüm:**
Sistem mimarisi katmanında eski algoritmaları engelleyen bir kalite kapısı (Quality Gate) konulur:
```python
BANNED_ALGOS = {"MD5", "SHA1", "SHA-1", "DES", "3DES", "RC4"}
def validate_crypto_spec(component):
    if component.algorithm.upper() in BANNED_ALGOS:
        raise InsecureCryptographicAlgorithmError(f"Yasaklı algoritma: {component.algorithm} (CWE-327)")
    if "RSA" in component.algorithm.upper() and component.key_bits < 2048:
        raise WeakKeyLengthError(f"Yetersiz anahtar: {component.key_bits} bit < 2048 bit (CWE-326)")
```
Sistem TLS 1.3 ve RSA-4096 / Ed25519 standardına geçirilerek PCI-DSS uyumu sağlanmıştır.

#### 4. Ustanın Çırağa Tavsiyesi
Asla "Bu algoritma 10 yıldır sorunsuz çalışıyor, dokunmayalım" deme. Kriptografide bayat ekmek yenmez; bayat algoritma sistemi zehirler. Kodunu öyle bir tasarla ki, yarın sabah NIST "SHA-256 yerine Kyber/Dilithium kullanacaksınız" dediğinde tek bir konfigürasyon satırıyla tüm sistem güncellenebilsin.

---

### Soru 2: Saltzer-Schroeder ilkelerinden "Tam Aracılık" (Complete Mediation) ve "Varsayılan Ret" (Fail-Safe Defaults) prensiplerinin modern mikroservis ve API mimarilerindeki izdüşümü nedir?

#### 1. Soru Başlığı ve Tanımı
Saltzer ve Schroeder'in 1975 tarihli çalışmasında yer alan iki altın kural; her erişim isteğinin istisnasız denetlenmesini (Complete Mediation) ve açıkça izin verilmemiş her şeyin doğası gereği reddedilmesini (Fail-Safe Defaults / Default-Deny) emreder (CWE-1188 / CWE-285).

#### 2. Derinlemesine Teknik Analiz
1. **Tam Aracılık (Complete Mediation):**
   - Geleneksel monolitik sistemlerde kullanıcı kapıda bir kez doğrulanır ve içerideki tüm modüllere güvenilirdi (Perimeter Security / Kale Modeli).
   - Modern Sıfır Güven (Zero-Trust) ve mikroservis mimarilerinde iç ağ kavramı yoktur. Servisler arası iletişimde (Service-to-Service mTLS, JWT, DPoP) her bir API çağrısı, her mikroservis sınırında yeniden doğrulanmalı ve yetkilendirilmelidir. Önbellekte tutulan yetkiler (caching) kısa süreli (TTL) olmalı ve iptal listeleri (revocation lists) gerçek zamanlı sorgulanmalıdır.
2. **Varsayılan Ret (Fail-Safe Defaults / Default-Deny):**
   - Güvenlik duvarlarında (Firewall), API ağ geçitlerinde (API Gateway) ve RBAC/ABAC motorlarında temel mantık şudur: Kural listesinin en altında görünmez bir kural vardır: `DENY ALL`.
   - Eğer gelen istek tanımlı kurallardan hiçbiriyle tam olarak eşleşmiyorsa, sistem "belki gerekebilir" demez; derhal `DENY` kararı verir. Bu prensip, unutulmuş veya yanlış yapılandırılmış uç noktaların (Shadow APIs) saldırganlarca sömürülmesini engeller.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir sağlık kuruluşu mikroservis mimarisine geçmiş; ancak performans kaygısıyla mikroservisler arasındaki iletişimi şifresiz ve yetkilendirmesiz bırakmıştır. Bir saldırgan web sunucusundaki basit bir SSRF zafiyeti üzerinden iç ağa geçmiş ve `Complete Mediation` uygulanmadığı için hasta veritabanı mikroservisine hiçbir kimlik bilgisi sunmadan doğrudan sorgu atarak 500.000 hastanın tahlil sonuçlarını çalmıştır.
**Pratik Çözüm:**
Her mikroservis kapısına bir PEP (Policy Enforcement Point) konulur ve varsayılan ret uygulanır:
```python
def authorize(token, resource, action):
    # 1. Oturum geçerli mi?
    if not token or token.is_expired():
        return AccessResult(decision="DENY", reason="Geçersiz oturum")
    # 2. İzin listesi eşleşiyor mu?
    if f"{resource}:{action}" in token.permissions:
        return AccessResult(decision="PERMIT")
    # 3. Saltzer-Schroeder Default-Deny
    return AccessResult(decision="DENY", reason="Saltzer-Schroeder Varsayılan Ret (Default-Deny)")
```

#### 4. Ustanın Çırağa Tavsiyesi
İç ağındaki hiçbir sunucuya kendi öz kardeşin gibi güvenme. İç ağda dolaşan her paketi, internetin en karanlık köşesinden geliyormuş gibi sorgula. Kapıyı herkese açık bırakıp sadece hırsızlara kapatmaya çalışma; kapıyı herkese kilitle, sadece anahtarı olan dostu içeri al.

---

### Soru 3: Bir güvenlik mimarisi denetiminde "Quality Gate" (Kalite Kapısı) nasıl kurgulanmalı ve "Hard Blocker" mekanizmaları neden CI/CD süreçlerine entegre edilmelidir?

#### 1. Soru Başlığı ve Tanımı
Kalite Kapısı (Quality Gate), bir yazılımın veya güvenlik mimarisinin geliştirme aşamasından üretim (production) ortamına geçmeden önce karşılamak zorunda olduğu asgari güvenlik ve kalite eşikleridir. "Hard Blocker" ise, genel puan ne kadar yüksek olursa olsun, varlığı halinde süreci derhal ve tartışmasız durduran kritik zafiyetlerdir (Showstopper).

#### 2. Derinlemesine Teknik Analiz
Yazılım güvenliğinde en büyük yanılgı ortalama puandır:
- Bir mimari; şifreleme, hız, ölçeklenebilirlik ve dokümantasyon alanlarında 100 üzerinden 95 puan alabilir.
- Ancak sistemde tek bir "Default-Allow" (CWE-1188) veya "Fail-Open" (CWE-636) açığı varsa, o sistemin gerçek güvenlik değeri sıfırdır; çünkü saldırgan güçlü olan %95'i değil, çöken %5'lik aralık kapıyı kullanır.
Bu nedenle Aşama 5 Kalite Denetçimiz şu kuralı işletir:
```python
critical_cwe_blockers = {"CWE-327", "CWE-1188", "CWE-636"}
has_blocker = any(cwe in critical_cwe_blockers for cwe in detected_cwes)
if score >= 85.0 and not has_blocker:
    decision = STAGE_5_ACCEPTED_PASS
else:
    decision = STAGE_5_HOLD_REMEDIATION_REQUIRED
```

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir telekomünikasyon şirketi, yeni faturalandırma yazılımını canlıya alacaktır. Proje yöneticisi "Testlerimizin %98'i başarılı, canlıya çıkalım" der. Ancak kalan %2'lik başarısız test, veritabanı kesintisinde kimlik doğrulamanın Fail-Open davrandığını (CWE-636) göstermektedir. CI/CD hattında Hard Blocker kuralı olmadığı için yazılım canlıya alınır. İki hafta sonra veritabanı bakımında kısa süreli bir kesinti yaşanır ve bu sırada binlerce yetkisiz kullanıcı ücretsiz olarak hatlarına sınırsız internet tanımlar.
**Pratik Çözüm:**
CI/CD işlem hattına otomatik kalite denetleyicisi konulur:
```bash
python uygulama/stage5_cli.py audit ornek_veri/sample_crypto_architecture_spec.json
if [ $? -ne 0 ]; then
    echo "[!] AŞAMA 5 KALİTE KAPISI AŞILAMADI: CANLIYA ALIM DURDURULDU!"
    exit 1
fi
```

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Proje yöneticileri teslim tarihlerine bakar, pazarlamacılar yeni özelliklere bakar; ama günün sonunda bir sızıntı olduğunda savcı da hakim de güvenlik mimarına bakar. "Çoğu yer iyiydi" savunması seni kurtarmaz. Hard Blocker'ların arkasında dimdik dur; güvenliği asla takvime kurban etme!
