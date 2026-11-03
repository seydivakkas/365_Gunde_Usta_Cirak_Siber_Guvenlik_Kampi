# GÜN 104: SORU & CEVAP VE TEKNİK MÜLAKAT DOSYASI
**Aşama 05 — Kriptografi Temelleri ve Uygulamaları**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.*

---

### SORU 1: Akış Şifrelerinde ve CTR Tabanlı AEAD Modlarında Nonce Yeniden Kullanımı (Two-Time Pad) Neden Gizli Anahtarı Tamamen Devre Dışı Bırakır ve Crib-Dragging Yöntemiyle Düz Metinler Nasıl Kurtarılır?

#### 1. Soru Başlığı ve Tanımı
CTR ve akış şifresi (AES-GCM, ChaCha20) mimarilerinde aynı (Anahtar, Nonce) çiftinin iki farklı düz metin için kullanılması durumunda oluşan $C_1 \oplus C_2 = P_1 \oplus P_2$ zafiyeti (CWE-323); anahtar akışının (keystream) matematiksel iptali ve saldırganların anahtara ihtiyaç duymaksızın metinleri kurtarma tekniği olan Crib-Dragging'in teknik analizi.

#### 2. Derinlemesine Teknik Analiz
CTR modunda ve modern akış şifrelerinde şifreleme işlemi, blok şifrenin artan bir sayaç ile işletilmesi sonucu üretilen sözde-rastgele bir anahtar akışının ($K_s$) düz metinle bit düzeyinde XOR'lanmasıdır:
$$C = P \oplus K_s, \quad K_s = \text{PRF}_K(\text{Nonce} \parallel \text{Counter})$$

Eğer aynı gizli anahtar $K$ ve aynı Nonce değeri iki farklı mesaj ($P_1$ ve $P_2$) için kullanılırsa, PRF (Pseudo-Random Function) deterministik olduğu için **tıpatıp aynı anahtar akışı $K_s$** üretilir:
$$C_1 = P_1 \oplus K_s$$
$$C_2 = P_2 \oplus K_s$$

Ağ üzerinden bu iki şifreli paketi yakalayan pasif bir dinleyici (eavesdropper), şifreli metinleri birbiriyle XOR'lar:
$$C_1 \oplus C_2 = (P_1 \oplus K_s) \oplus (P_2 \oplus K_s)$$
XOR cebirinde değişme ve birleşme kuralları ile $X \oplus X = 0$ ve $X \oplus 0 = X$ özellikleri geçerlidir:
$$C_1 \oplus C_2 = P_1 \oplus P_2 \oplus (K_s \oplus K_s) = P_1 \oplus P_2 \oplus 0 = P_1 \oplus P_2$$

**Matematiksel Sonuç:**
Gizli anahtar $K$ ve üretilen tüm anahtar akışı $K_s$ denklemden tamamen silinmiştir! Saldırganın elinde artık doğrudan iki düz metnin birbirine XOR'lanmış değeri ($M_{xor} = P_1 \oplus P_2$) vardır.

**Crib-Dragging Kurtarma Tekniği:**
İnsan dillerinde ve protokollerde sözcük yapıları yüksek oranda tahmin edilebilirdir (Örn: HTTP protokolünde "GET /index", JSON formatında "{\"status\":", bankacılıkta "ACCOUNT_NO=").
1. Saldırgan olası bir kelimeyi (Crib $W$) varsayar.
2. Bu kelimeyi $M_{xor}$ dizisi üzerinde sırayla her pozisyona ($i$) yerleştirerek XOR'lar:
   $$R_i = M_{xor}[i : i + |W|] \oplus W$$
3. Eğer $W$ tahmini $P_1$'in o pozisyondaki gerçek içeriğiyse, $R_i$ doğrudan $P_2$'nin o pozisyondaki anlamlı metnini verir!
4. Anlamlı harfler ortaya çıktıkça saldırgan bir metinden diğerine atlayarak (cross-decryption) her iki mesajın tamamını dakikalar içinde deşifre eder.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir mobil mesajlaşma uygulaması, uçtan uca şifreleme için AES-CTR kullanmaktadır. Ancak uygulama istemcisi yeniden başlatıldığında (reboot) Nonce sayacını sıfırdan (`000000000000`) başlatmaktadır. Ağ trafiğini kaydeden bir saldırgan, telefon her açıldığında gönderilen ilk mesajların şifreli metinlerini toplayarak $C_1 \oplus C_2$ analizi ile kullanıcıların özel sohbetlerini anahtarı kırmadan okur.

**Pratik Çözüm:**
Sistemde durum bilgili Nonce takip önbelleği (Stateful Nonce Tracker) kurulmalı, her mesajda CSPRNG ile 96-bit benzersiz Nonce üretilmeli ve tekrar denemeleri engellenmelidir:
```python
import secrets
from uygulama.aead_nonce_engine import AEADNonceEngine, GLOBAL_NONCE_TRACKER

# Kriptografik güvenli rastgele Nonce ile AEAD şifreleme
rastgele_nonce = secrets.token_bytes(12)  # 96-bit
sonuc = AEADNonceEngine.encrypt_aead(
    plaintext="Kullanıcı Özel Mesajı",
    key=oturum_anahtari,
    nonce=rastgele_nonce,
    tracker=GLOBAL_NONCE_TRACKER  # Nonce tekrarında CWE-323 fırlatır
)
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, akış şifresi kullanırken Nonce'u hafife almak, bankanın çelik kasasının şifresini kapının önüne megafonla bağırmaya benzer! Bir kez üretilen rastgele bir sayıyı ikinci kez üretirsen, matematiksel olarak anahtarın hiçbir hükmü kalmaz. Nonce'u asla sabit tutma, asla cihaz yeniden başladığında sıfırlanan bir değişkene bağlama; daima işletim sisteminin kriptografik entropi havuzuna güven!"

---

### SORU 2: AES-GCM Modunda Nonce Tekrarı Durumunda Ortaya Çıkan "Forbidden Attack" (Antoine Joux) Nedir ve Bütünlük Etiketi Nasıl Sahtelenir?

#### 1. Soru Başlığı ve Tanımı
NIST SP 800-38D standardı AES-GCM (Galois/Counter Mode) mimarisinde aynı Nonce'un tekrar kullanılması halinde gerçekleşen "Forbidden Attack"; GHASH kimlik doğrulama polinomunun çözülerek kimlik doğrulama anahtarı $H$'nin elde edilmesi ve yetkisiz şifreli paket sahteciliği (CWE-353) riskinin analizi.

#### 2. Derinlemesine Teknik Analiz
AES-GCM modu iki bileşenden oluşur:
1. Şifreleme için **AES-CTR** modu.
2. Kimlik doğrulama etiketi üretimi için $GF(2^{128})$ Galois Alanı üzerinde çalışan **GHASH** fonksiyonu.

GHASH fonksiyonu, şifreli metin bloklarını ($C_1, C_2, \dots, C_m$) ve AAD bloklarını bir polinomun katsayıları olarak değerlendirir. Polinomun değişkeni ise gizli kimlik doğrulama anahtarı $H = \text{AES}_K(0^{128})$'dir:
$$g(H) = AAD_1 \cdot H^m + \dots + C_1 \cdot H^2 + C_2 \cdot H + L$$
Son etiket $T$ ise bu polinom sonucunun $J_0$ sayaç bloğunun şifresiyle XOR'lanmasıdır:
$$T = g(H) \oplus \text{AES}_K(J_0)$$

Buradaki kritik zafiyet şudur: **$J_0$ sayaç bloğu doğrudan Nonce'tan türetilir.**
Eğer saldırgan aynı Nonce ile şifrelenmiş iki farklı mesaj ve bunların etiketlerini ($T_1, T_2$) elde ederse:
$$T_1 \oplus T_2 = g_1(H) \oplus \text{AES}_K(J_0) \oplus g_2(H) \oplus \text{AES}_K(J_0)$$
$$\text{AES}_K(J_0) \text{ terimleri birbirini yok eder: } T_1 \oplus T_2 = g_1(H) \oplus g_2(H)$$

Bu eşitlik, $GF(2^{128})$ sonlu alanı üzerinde derecesi mesaj blok sayısına eşit olan bir polinom denklemine dönüşür:
$$P(H) = g_1(H) \oplus g_2(H) \oplus (T_1 \oplus T_2) = 0$$

Antoine Joux tarafından 2006 yılında kanıtlandığı üzere, sonlu alanlar üzerinde polinom köklerini bulmak (örneğin Berlekamp algoritması ile) son derece hızlıdır. Saldırgan bu denklemi çözerek gizli **$H$ anahtarını** doğrudan ele geçirir!

**Saldırının Yıkıcı Sonucu:**
$H$ anahtarını ele geçiren saldırgan:
- Artık kurban adına geçerli kimlik doğrulama etiketleri (Tag) üretebilir.
- Araya girme (Man-in-the-Middle) pozisyonunda şifreli paketleri değiştirebilir, içeriğine zararlı kodlar ekleyebilir ve alıcının sistemi bunu meşru bir paket olarak kabul eder.
- Yani AES-GCM'de Nonce tekrarı **hem gizliliği hem de bütünlüğü tamamen yok eder!**

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** 2016 yılında güvenlik araştırmacıları Böck, Zauner, Devlin, Somorovsky ve Jovanovic, internet üzerindeki HTTPS sunucularını taradıklarında 184.000'den fazla TLS sunucusunun aynı AES-GCM Nonce'unu tekrar tekrar kullandığını tespit ettiler ("Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS"). Araştırmacılar aktif bir saldırganın bu sunuculardan geçen HTTPS trafiğine zararlı JavaScript enjekte edebileceğini kanıtladılar.

**Pratik Çözüm:**
Yüksek hızlı ağ donanımlarında Nonce üretimi rastgele sayı yerine 64-bitlik tekil bir sayaç (monotonic counter) ile deterministik olarak artırılmalı ve sayaç dolduğunda oturum anahtarı derhal yenilenmelidir (Rekeying):
```python
# Monotonik artan sayaç ile Nonce garantisi
def generate_deterministic_nonce(session_id: bytes, counter: int) -> bytes:
    # 4 bayt oturum kimliği + 8 bayt kesinlikle artan sayaç (96 bit)
    return session_id[:4] + counter.to_bytes(8, byteorder="big")
```

#### 4. Ustanın Çırağa Tavsiyesi
"Evladım, AES-GCM kriptografinin yarış arabasıdır; çok hızlıdır ama virajı kaçırırsan uçurumdan yuvarlanırsın! Nonce'u bir kez bile tekrar edersen sadece içeriği okutmakla kalmazsın, sistemin imza mührünü ($H$) saldırganın eline teslim edersin. GCM kullanıyorsan ya donanımsal monotonik sayaç kullanacaksın ya da anahtarını sık sık rotasyona sokacaksın!"

---

### SORU 3: SIV (Synthetic IV) Mimarisi ve Nonce-Misuse Resistant AEAD (RFC 5297 / RFC 8452) Nedir ve Dağıtık Sistemlerde Nonce Çakışmalarını Nasıl Önler?

#### 1. Soru Başlığı ve Tanımı
Dağıtık mikroservis mimarilerinde ve durum bilgisi tutamayan (stateless) ortamlarda rastgele Nonce üretiminin yarattığı Doğum Günü Paradoksu çakışma riskleri; Synthetic IV (SIV) standardının çalışma mekanizması ve "Nonce-Misuse Resistance" (Kötüye Kullanıma Dirençli AEAD) mimarisi.

#### 2. Derinlemesine Teknik Analiz
Standart AEAD modlarında (AES-GCM, ChaCha20-Poly1305), rastgele 96-bit Nonce kullanıldığında Doğum Günü Paradoksu matematiksel bir sınır koyar. $N = 2^{96}$ olası Nonce uzayında, çakışma ihtimalinin %50'ye ulaşması için gereken mesaj sayısı:
$$M \approx \sqrt{2^{96}} = 2^{48} \approx 2.8 \times 10^{14}$$
Bulut ölçeğinde saniyede yüz binlerce paket işleyen dağıtık mikroservis kümelerinde veya sanal makinelerin bellek durumlarının geri yüklendiği (VM snapshot rollback) durumlarda, rastgele sayı üreteçleri aynı tohumu (seed) alarak aynı Nonce'ları üretebilir.

**SIV (Synthetic IV) Çözümü (RFC 5297 / RFC 8452):**
SIV mimarisi, şifreleme öncesinde **deterministik bir başlangıç vektörü (Synthetic IV)** türetir:
1. **Adım 1 (Vektör Türetimi):** Düz metin $P$ ve ilişkili açık veri $AAD$, gizli bir kimlik doğrulama anahtarı $K_{mac}$ ile işlenir:
   $$SIV = \text{PRF}_{K_{mac}}(P \parallel AAD)$$
2. **Adım 2 (Şifreleme):** Türetilen $SIV$, AES-CTR modunun başlangıç Nonce'u olarak kullanılır:
   $$C = \text{AES-CTR}_{K_{enc}}(SIV, P)$$
3. **Adım 3 (Paketleme):** Çıktı olarak $(SIV, C)$ iletilir.

**SIV Modunun Sağladığı Eşsiz Güvenlik Garantisi:**
- **Farklı Mesajlar:** Eğer iki mesaj birbirinden farklıysa ($P_1 \neq P_2$), PRF fonksiyonunun kriptografik özellikleri gereği türetilen $SIV_1$ ve $SIV_2$ birbirinden tamamen bağımsız ve rastgeledir. Asla Nonce çakışması yaşanmaz!
- **Aynı Mesajın Tekrarı:** Eğer aynı mesaj ve aynı AAD kasıtlı veya kazara ikinci kez şifrelenirse, aynı $SIV$ ve dolayısıyla tıpatıp aynı şifreli metin $C$ üretilir. Ancak $P_1 = P_2$ olduğu için:
  $$C_1 \oplus C_2 = P_1 \oplus P_2 = P_1 \oplus P_1 = 0$$
  Saldırgan sadece aynı mesajın tekrar yollandığını anlar (deterministik şifreleme); ancak **asla Two-Time Pad anahtar sızıntısı veya etiket sahteciliği yapamaz!**

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir Kubernetes kümesinde yüzlerce pod aynı simetrik anahtarla log kayıtlarını şifreleyerek merkezi depoya göndermektedir. Podlar yeniden başlatıldığında CSPRNG tohumları benzer kalabildiği için Nonce çakışmaları yaşanmakta ve güvenlik denetiminde CWE-323 tespit edilmektedir.

**Pratik Çözüm:**
Küme haberleşmesi `AES-GCM-SIV` (RFC 8452) standardına geçirilmelidir. Podlar durum bilgisi tutmak zorunda kalmadan, verinin kendi kriptografik özetinden türetilen Synthetic IV ile şifreleme yapar:
```python
from uygulama.aead_nonce_engine import AEADNonceEngine

# SIV Deterministik Güvenli Mod
res = AEADNonceEngine.encrypt_aead(
    plaintext="LOG_EVENT_CRITICAL_DATABASE_FAIL",
    key=kume_anahtari,
    associated_data="node_id=worker_04;ts=179302200",
    use_siv=True  # Synthetic IV aktiftir
)
# Nonce rastgele değil, veriye bağlı türetildiğinden çakışma riski sıfırdır
```

#### 4. Ustanın Çırağa Tavsiyesi
"Çırağım, bulut sistemlerinde ve mikroservislerde 'ben rastgele sayı üretiyorum, nasılsa çakışmaz' demek kumardır. Binlerce sunucunun aynı anda çalıştığı yerde doğum günü paradoksu seni mutlaka yakalar. Eğer durum bilgisi tutamıyorsan ve Nonce sayacını senkronize edemiyorsan, mimarini SIV (Synthetic IV) zırhıyla koru. SIV, kriptografın emniyet kemeridir!"
