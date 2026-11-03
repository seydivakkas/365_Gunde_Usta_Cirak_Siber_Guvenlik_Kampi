# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 083: Git Commit ve Değişiklik İncelemesi (Git Commit & Diff Auditing)

## Usta-Çırak Açılış Hasbihali

Evladım, çırağım;
Yazılım güvenliğinde en büyük zafiyetler ve en maliyetli veri sızıntıları, sistemler üretime çıktıktan sonra değil; bir geliştiricinin klavyesinden çıkan tek bir dikkatsiz `git commit` ve `git push` komutuyla başlar. 

Birçok acemi geliştirici Git'i yalnızca kod yedekleme ve sürüm takip aracı zanneder. Oysa bir güvenlik mühendisi ve siber savunmacı için Git; adli bilişim (forensics), kod denetimi (code review), sızıntı önleme (DLP) ve tedarik zinciri güvenliğinin (supply chain security) en kritik cephesidir. Bir repoya yanlışlıkla atılan bir AWS anahtarını daha sonra `git rm` veya yeni bir commit ile silmek o anahtarı temizlemez; Git'in DAG (Directed Acyclic Graph) yapısındaki commit geçmişinde sonsuza dek saklı kalır ve botlar dakikalar içinde o anahtarı kullanarak bulut altyapınızı ele geçirir.

Bugünkü dersimizde seninle bir Git commit nesnesinin kalbine inecek, Unified Diff formatını karakter karakter ayrıştıracak, Trojan Source (Bidi) görsel aldatmaca saldırılarını ve yüksek Shannon entropisine sahip gizli anahtarları otomatik olarak yakalayan bağımsız bir denetim motoru inşa edeceğiz.

---

## 1. Unified Diff Formatının Anatomisi

Git, iki sürüm veya commit arasındaki farkı hesaplarken **Unified Diff** standardını kullanır. Güvenlik analizini doğru yapabilmek için diff akışındaki her işaretin teknik anlamını bilmek zorundasın:

1. **Commit Üstbilgileri (Metadata):**
   - `commit <hash>`: 40 karakterlik SHA-1 veya 64 karakterlik SHA-256 nesne kimliği.
   - `Author: <isim> <eposta>`: Commiti yazan kişinin beyan ettiği kimlik (dikkat: imzalanmamışsa sahteciliğe [spoofing] açıktır).
   - `Date: <zaman>`: ISO veya standart RFC zaman damgası.

2. **Dosya Başlıkları (File Headers):**
   - `diff --git a/path b/path`: Karşılaştırılan dosya yolları.
   - `index a1b2c3d..e4f5g6h 100644`: Dosyanın Git blob hashleri ve POSIX izin modu (100644 normal dosya, 100755 çalıştırılabilir dosya).
   - `--- a/path`: Orijinal (eski) dosya referansı.
   - `+++ b/path`: Hedef (yeni) dosya referansı.

3. **Hunk (Parça) Başlığı (Hunk Header):**
   - Biçim: `@@ -eski_baslangic,eski_adet +yeni_baslangic,yeni_adet @@`
   - Örnek: `@@ -10,8 +10,12 @@` ifadesi; eski dosyada 10. satırdan itibaren 8 satırlık bir bloğun, yeni dosyada 10. satırdan itibaren 12 satırlık bir bloğa dönüştüğünü gösterir.

4. **Satır Değişiklik Göstergeleri:**
   - `+`: Yeni sürümde eklenen satır (Güvenlik taramalarının 1 numaralı hedefi).
   - `-`: Eski sürümden silinen satır (Zafiyet giderilmiş mi veya güvenlik kontrolleri kaldırılmış mı kontrolü).
   - ` ` (boşluk): Bağlam (context) satırı; kodun etrafındaki değişmeyen yapıyı gösterir.

---

## 2. Commit Taramasında Temel Güvenlik Riskleri

### A. Açık Metin Kimlik Bilgileri (Hardcoded Credentials - CWE-798 / CWE-312)
Geliştiriciler yerel test yaparken API anahtarlarını, veritabanı parolalarını veya JWT tokenlarını koda gömerler. "Nasılsa sonra temizlerim" düşüncesi en büyük felakettir.
- **AWS Access Key ID:** `AKIA[0-9A-Z]{16}`
- **GitHub Personal Access Token:** `ghp_[a-zA-Z0-9]{36}`
- **SSH / RSA Özel Anahtarları:** `-----BEGIN RSA PRIVATE KEY-----`

### B. Trojan Source ve Unicode Bidi Saldırıları (CVE-2021-42574)
Bu saldırı türünde saldırgan, koda insan gözüyle okunduğunda zararsız görünen ancak derleyici veya yorumlayıcı tarafından bambaşka sırada işletilen çift yönlü Unicode kontrol karakterleri (Right-to-Left Override `\u202E`, Left-to-Right Isolate `\u2066` vb.) enjekte eder.
Gözden geçiren güvenlik uzmanı "bu satır bir yorum satırı" veya "bu bir yetki kontrolü" zannederken, derleyici kodu bambaşka çalıştırır. Bir diff motoru, bu görünmez kontrol karakterlerini derhal yakalamak zorundadır.

### C. Shannon Entropisi ile Bilinmeyen Parolaların Tespiti
Bilinen desenlere (regex) uymayan rastgele şifreler, tuzlar (salt) ve karmaşık anahtarlar nasıl tespit edilir? Claude Shannon'ın 1948 tarihli bilgi teorisiyle:
$$H = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$
- Düz bir İngilizce/Türkçe metin veya standart değişken adı genellikle $2.0 - 3.5$ bit/karakter entropiye sahiptir.
- Rastgele üretilmiş 32 karakterlik bir parola veya base64 anahtar $4.3 - 5.5$ bit/karakter civarında yüksek bir entropiye ulaşır.
Motorumuz string literallerinin entropisini ölçerek kural dışı sırları da yakalar.

### D. DoS ve Diff Bombaları (CWE-400)
Saldırganlar CI/CD denetim motorlarını çökertmek için milyonlarca satırlık devasa diff dosyaları veya null-byte enjeksiyonları (`\x00`) gönderebilir. Ayrıştırıcımız bayt ve satır sınırları koyarak fail-closed mimariyle çalışır.

---

## 3. Ustanın Öğütleri ve CI/CD Entegrasyonu

1. **Pre-commit Kancalarını (Git Hooks) Zorunlu Tut:** Güvenlik denetimi kod sunucuya gitmeden önce geliştiricinin yerel makinesinde çalışmalıdır (`.git/hooks/pre-commit`).
2. **Geçmişi Temizlemeyi Öğren:** Eğer bir anahtar commit edilmişse, repoyu anında dondur, anahtarı bulut sağlayıcıdan iptal et (revoke) ve `git-filter-repo` veya BFG Repo-Cleaner ile geçmişi tamamen yeniden yaz.
3. **İmzalı Commit Kullan (GPG / SSH Signing):** Kimlik sahteciliğini önlemek için geliştiricilerin commitlerini GPG veya SSH anahtarlarıyla imzalamasını (`git commit -S`) zorunlu kıl.
