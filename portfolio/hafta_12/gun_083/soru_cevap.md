# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 083: Soru-Cevap ve Güvenlik Senaryoları

---

### Soru 1: Git Diff Analizinde Trojan Source (CVE-2021-42574) Saldırısı ve Savunma Mekanizmaları

#### Soru Başlığı ve Tanımı
Trojan Source saldırısı nedir; çift yönlü (Bidirectional - Bidi) Unicode kontrol karakterleri kaynak kod incelemesi (Code Review) yapan güvenlik uzmanlarını ve geliştiricileri nasıl yanıltır? Git diff denetim motoru bu tehdidi derleme öncesinde nasıl engeller?

#### Derinlemesine Teknik Analiz
Çoğu modern metin editörü ve web tabanlı Git arayüzü (GitHub, GitLab), Arapça ve İbranice gibi sağdan sola (RTL) yazılan diller ile İngilizce/Türkçe gibi soldan sağa (LTR) yazılan dilleri bir arada desteklemek için **Unicode Çift Yönlü Algoritmasını (Unicode Bidirectional Algorithm - Bidi)** uygular.

Saldırganlar bu algoritmada metnin yönünü zorla değiştiren görünmez kontrol karakterlerini koda enjekte eder:
1. `U+202E` (Right-to-Left Override - RLO)
2. `U+2066` (Left-to-Right Isolate - LRI)
3. `U+2067` (Right-to-Left Isolate - RLI)
4. `U+2068` (First Strong Isolate - FSI)
5. `U+2069` (Pop Directional Isolate - PDI)

Bu karakterler kaynak kodun dosya içerisindeki bayt sırasını değiştirmez; ancak editörün ekranında render edilen satırın sırasını görsel olarak tersyüz eder. Örneğin bir if koşulunun gövdesi insan gözüne yorum satırı gibi gösterilebilir veya yetkisiz bir kullanıcı admin olarak yetkilendirildiği halde ekranda "user" okunabilir. Derleyici (Python, C, Rust) ise bayt sırasını okuduğu için zararlı mantığı çalıştırır.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir açık kaynak kütüphaneye "yetkilendirme kontrolü iyileştirmesi" adı altında bir pull request (PR) gelir. İnceleyen mühendis görsel diff ekranında şu satırı görür:
```python
# check if user is admin: if isAdmin == False: return
```
Mühendis bu kodun zararsız bir yorum satırı olduğunu düşünerek PR'ı onaylar. Oysa satırın arkasında `\u202E` karakteri bulunmaktadır ve yorum satırının kapatılıp Python tarafından `if isAdmin == True:` bloğunun işletilmesini sağlayan bir saldırı gömülüdür.

**Pratik Çözüm:**
CI/CD hattında çalışan `GitCommitDiffAuditor`, commit edilen diff içerisindeki tüm eklenen satırlarda ve commit mesajlarında Bidi kontrol karakterlerini tarar (`TrojanSourceDetector`). Bu kümedeki herhangi bir karakter tespit edildiğinde işlem anında `TrojanSourceAttackException` fırlatarak pipeline'ı kırar ve commit'i `REJECT` kararıyla reddeder.

#### Ustanın Çırağa Tavsiyesi
"Çırağım, gözünün gördüğüne değil, baytın söylediğine inanacaksın. Bir kod incelemesinde 'yorum satırı' sandığın şey arkada bir bayt illüzyonu olabilir. Editöründe 'Render Whitespace and Control Characters' seçeneğini daima açık tut ve CI/CD hattına mutlaka Trojan Source dedektörü yerleştir."

---

### Soru 2: Hardcoded Sırların Tespiti: Regex vs. Shannon Entropisi Karşılaştırması

#### Soru Başlığı ve Tanımı
Git commit incelemesinde açık metin sırları (parola, API anahtarı, token) tespit ederken düzenli ifadeler (Regex) ile Shannon Bilgi Entropisi (Entropy) yöntemleri arasındaki farklar, avantajlar ve yanlış pozitif (false positive) yönetim stratejileri nelerdir?

#### Derinlemesine Teknik Analiz
Commit diff taramasında iki temel yaklaşım kullanılır:

1. **Desen Eşleştirme (Regex):**
   - **Avantaj:** Bilinen sağlayıcıların (AWS, GitHub, Google, Slack, Stripe) anahtarları sabit önekler (prefix) ve uzunluklarla başlar (örn. AWS: `AKIA[0-9A-Z]{16}`, GitHub: `ghp_[a-zA-Z0-9]{36}`). Yanlış pozitif oranı düşüktür.
   - **Dezavantaj:** Geliştiricinin kendi ürettiği rastgele veritabanı parolalarını, dahili mikroservis gizli anahtarlarını veya özel şifreleme tuzlarını yakalayamaz.

2. **Shannon Entropisi Analizi ($H = -\sum p_i \log_2 p_i$):**
   - **Avantaj:** Bir metindeki karakterlerin rastgelelik ve öngörülemezlik derecesini matematiksel olarak ölçer. Düz metinlerde İngilizce/Türkçe harf tekrarları nedeniyle entropi $2.0 - 3.2$ bit/karakter arasındayken, kriptografik rastgelelikle üretilmiş parolalar $4.3 - 5.5$ bit/karakter seviyesine çıkar. Bu sayede hiçbir desene uymayan gizli şifreler bile yakalanır.
   - **Dezavantaj:** UUID'ler, uzun hash değerleri (SHA-256) ve base64 ile kodlanmış zararsız ikili veriler yüksek entropi vererek yanlış pozitif üretebilir.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir fintech firmasında bir geliştirici test ortamı için yazdığı microservice'in içine gizli bir salt değeri gömmüştür:
```python
PASSWORD_SALT = "s7K9#mQ2$vL8!pZ4@wX1%yR3^bN6&cT5"
```
Bu değer hiçbir bilinen bulut sağlayıcı formatında değildir, dolayısıyla standart regex tarayıcıları bu satırı atlar.

**Pratik Çözüm:**
`GitCommitDiffAuditor`, hibrit bir yaklaşım uygular:
1. Önce bilinen sağlayıcıları yüksek hassasiyetli regex ile yakalar.
2. Ardından eklenen satırlardaki 16 karakterden uzun string literallerini ayıklar ve `ShannonEntropyCalculator` ile inceler. Entropi $4.3$ eşik değerini aşıyorsa `HighEntropySecretException` veya `HIGH` seviye bulgu üretir.
3. Yanlış pozitifleri azaltmak için bilinen dosya uzantıları (örn: `.lock`, `.svg`, `.map`, font dosyaları) diff ayrıştırıcı düzeyinde beyaz listeye alınır.

#### Ustanın Çırağa Tavsiyesi
"Evladım, regex seni dünkü bilinen tehlikelerden korur; matematik ve entropi ise yarın karşılaşacağın bilinmeyen sırlardan korur. İkisini birleştirmeyen güvenlikçi, bir gözünü kapatıp nişan alan avcıya benzer."

---

### Soru 3: Kazara Commit Edilen Bir Gizli Anahtarın Doğru Müdahale Prosedürü

#### Soru Başlığı ve Tanımı
Bir geliştirici AWS veya GitHub API anahtarını içeren bir commit'i GitHub'a push ettiğinde, anahtarı koddan silip yeni bir commit atmak neden güvenliği sağlamaz? Git DAG (Directed Acyclic Graph) yapısı açısından doğru adli bilişim ve olay müdahale (Incident Response) adımları nelerdir?

#### Derinlemesine Teknik Analiz
Git, dosyaların sadece anlık halini değil, her commit nesnesini ve bu nesnenin işaret ettiği ağaç (tree) ve veri bloğu (blob) hashlerini kriptografik olarak birbirine bağlayan bir DAG yapısıdır.
Geliştirici anahtarı dosyadan silip `git commit -m "anahtar temizlendi"` ve `git push` yaptığında:
1. Yeni commit dosyanın anahtarsız halini gösterir;
2. Ancak önceki commit nesnesi (`commit abc1234`) ve onun altındaki dosya blob'u Git geçmişinde sapasağlam durur;
3. Herhangi biri `git checkout HEAD~1`, `git log -p` veya GitHub'ın commit geçmişi URL'si üzerinden anahtara doğrudan erişebilir;
4. İnternetteki saldırgan botlar GitHub Event API'sini dinleyerek saniyeler içinde bu geçmişi klonlayıp anahtarı çeker.

#### Gerçek Dünya Senaryosu ve Pratik Çözüm
Geliştirici `AKIA...` ile başlayan AWS Root/Admin anahtarını yanlışlıkla public repoya göndermiştir. 3 dakika sonra hatasını fark edip satırı silmiş ve commit atmıştır. Ancak 7 dakika sonra AWS hesabında yüzlerce pahalı GPU makinesinin kripto madenciliği için açıldığı tespit edilmiştir.

**Doğru Müdahale Prosedürü (Adım Adım):**
1. **İPTAL VE DEĞİŞTİRME (REVOCATION - ANINDA):** Koda veya Git geçmişine dokunmadan önce ilk saniyede AWS konsoluna girilip anahtar devre dışı bırakılır (Deactivate / Delete) ve yeni anahtar üretilir. Sızan anahtar artık geçersizdir.
2. **ERİŞİM VE LOG ANALİZİ (FORENSICS):** AWS CloudTrail logları taranarak bu anahtar ile son dakikalarda hangi API çağrılarının yapıldığı, hangi kaynakların oluşturulduğu adli olarak incelenir ve yetkisiz kaynaklar sonlandırılır.
3. **GİT GEÇMİŞİNİ YENİDEN YAZMA (HISTORY REWRITE):**
   - Reponun tüm geçmişinden o dosya ve gizli anahtar bloğu `git-filter-repo` aracıyla kazınır:
     ```bash
     git-filter-repo --replace-text expressions.txt
     ```
   - Eski gevşek nesneler (loose objects) temizlenir:
     ```bash
     git reflog expire --expire=now --all
     git gc --prune=now --aggressive
     ```
   - Uzak sunucuya zorla itilir (`git push origin --force --all`).
4. **KÖK NEDEN ÖNLEMİ:** `GitCommitDiffAuditor` kütüphanesi yerel geliştirici makinesine `pre-commit` kancası olarak entegre edilerek gelecekteki sızıntılar daha bilgisayardan çıkmadan durdurulur.

#### Ustanın Çırağa Tavsiyesi
"Çırağım, namludan çıkan kurşun ile push edilen API anahtarı geri dönmez. İlk işin Git geçmişini silmeye çalışmak değil, anahtarın can damarını buluttan kesmektir. Unutma: Geçmişi temizlemek kozmetiktir, anahtarı iptal etmek hayattır!"
