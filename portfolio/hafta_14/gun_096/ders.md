# Gün 096: Güvenli Betik Kullanım Belgeleri ve Dokümantasyon Mimarisi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu ders notu yalnızca görüntüleme ve kişisel eğitim amacıyla paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya ticari amaçla kullanılamaz.*

---

## 1. Usta Girişi: "Belgelenmemiş Parametre, Potansiyel Bir Arka Kapıdır!"

Evlat, siber güvenlik dünyasında bir betik (script) sadece çalışan bir kod yığını değildir. O betik gece yarısı bir fidye yazılımı saldırısı anında nöbetçi SOC analistinin elindeki silahtır. Veya bankanın CI/CD dağıtım hattında sistemi tarayan otomatik denetçidir.

Şimdi şu felaket senaryosunu düşün:
Bir güvenlik mühendisi logları temizlemek veya veritabanını taramak için bir betik yazar. Kodun içine test yaparken `--purge-original` veya `--skip-auth` gibi tehlikeli bir parametre ekler; ancak bunu kullanım kılavuzunda veya `--help` çıktısında **belgelemez**.
Aradan aylar geçer. Başka bir operatör veya otomatik SOAR senaryosu bu betiği çalıştırırken yanlışlıkla veya kötü niyetli bir saldırganın parametre enjeksiyonuyla bu gizli bayrak tetiklenir. Tüm adli delil logları silinir!

İşte bu yüzden siber güvenlik mühendisliğinde temel bir kural vardır:
**"Belgelenmemiş parametre bir arka kapıdır (Backdoor) veya güvensiz varsayılan başlatmadır (CWE-1188: Insecure Default Initialization of Resource)."**

Bir güvenlik aracının değeri, sadece ne kadar iyi çalıştığıyla değil; ne kadar güvenli, eksiksiz ve doğrulanabilir belgelendiğiyle ölçülür.

---

## 2. Güvenli Bir Betik Belgesinde Bulunması Zorunlu 5 Kritik Unsur

Sıradan bir yazılım kılavuzu sadece *"şu komutu yazın, çalışır"* der. Oysa **Güvenlik Odaklı Bir Operatör Kılavuzu (Security Runbook)** şu 5 unsuru eksiksiz içermek zorundadır:

### 1. Yetki Seviyesi ve En Az Yetki Prensibi (Least Privilege - CWE-250)
- Betik hangi kullanıcı yetkisiyle çalışmalıdır?
- Betik `root`, `sudo` veya `Administrator` gerektiriyor mu? Eğer gerektirmiyorsa, belgede açıkça **"Bu betik kesinlikle root yetkisiyle ÇALIŞTIRILMAMALIDIR"** uyarısı yer almalıdır. Yetki aşımı (Privilege Creep) en büyük sistem açığıdır.

### 2. Tehdit Modeli ve Savunulan CWE Kodları
- Bu araç hangi saldırıları önlemektedir? (Örn: CWE-532 Log Sızıntısı, CWE-88 Komut Enjeksiyonu, CWE-22 Path Traversal). Operatör aracın güvenlik kapsamını net bilmelidir.

### 3. Girdi Parametreleri ve Tip/Sınır Güvenliği
- Her parametrenin tipi, zorunlu olup olmadığı ve kabul ettiği güvenli değer aralığı belirtilmelidir.
- Dosya yollarında Path Traversal koruması var mı? Boyut tavanı nedir?

### 4. Yıkıcı Yan Etkiler ve Güvenlik Uyarıları (Safety Warnings)
- Aracın yaptığı işlemler geri alınabilir mi? Dosya siliyor mu, ağ trafiğini kesiyor mu, veritabanına yazıyor mu? Yıkıcı parametreler (`--purge`, `--force`) kalın uyarı kutularıyla (`> [!WARNING]`) vurgulanmalıdır.

### 5. Standart Çıkış Kodları Sözlüğü (POSIX Exit Codes)
- Otomasyon araçları (SOAR, Bash, Ansible, Jenkins) betiğin ekrana ne yazdığına değil, **hangi çıkış koduyla bittiğine** bakar.
- `0`: Tam Başarılı.
- `1`: Güvenlik Engeli / Tehdit Tespit Edildi / Uyarı.
- `2`: Girdi / Parametre / Dosya Hatası.
Çıkış kodları belgelenmezse, otomasyon zincirleri güvenlik ihlallerini sessizce gözden kaçırır.

---

## 3. Security Documentation as Code ve Statik Linter Denetimi

Belge yazmak yetmez evlat; belgenin kodla **senkronize olduğunu otomatik olarak doğrulamak** gerekir. Buna **Documentation as Code** denir.

Geliştirdiğimiz `SecurityDocLinter` motoru şu kontrolleri statik olarak yapar:
1. **Kod Ayrıştırma:** Kaynak Python betiğini açar, `argparse.add_argument()` çağrılarını tespit eder.
2. **Kıyaslama:** Kodda bulunan tüm CLI parametrelerini (`-i`, `--input-file`, `--purge-original`) dokümantasyon şemasındaki parametrelerle karşılaştırır.
3. **Eksiklik Tespiti:** Eğer kodda var olan bir parametre belgede yoksa, linter `UndocumentedArgumentError` (CWE-1188) fırlatarak derlemeyi veya CI/CD boru hattını anında durdurur.
4. **Lisans Bütünlüğü:** Kaynak kodun başında zorunlu kurumsal **"ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR"** başlığı yoksa `MissingLicenseHeaderError` fırlatır.

---

## 4. Çok Formatlı Belge Üretimi: Bir Kez Yaz, Her Yerde Kullan

Güvenlik şeması tek bir yapılandırılmış kaynakta (`JSON`) tutulur ve `DocGenerator` motoru tarafından ihtiyaç duyulan formatlara derlenir:

| Format | Hedef Kitle ve Kullanım Alanı |
| :--- | :--- |
| **Markdown (RUNBOOK.md)** | SOC analistleri, GitHub/GitLab wiki sayfaları, kurumsal denetim raporları. |
| **CLI Help Text (`--help`)** | Terminal operatörleri için hızlı, renkli ve kompakt yönlendirme. |
| **Man Page (ROFF)** | Linux/Unix sistem entegrasyonu (`man log_sanitizer_tool` çağrıları). |
| **JSON Schema** | SOAR platformları, Ansible modülleri ve CI/CD pipeline otomasyonları. |

---

## 5. Ustanın Çırağa Öğütleri

1. **"Nasıl Çalıştırırım" Değil, "Nasıl Güvenli Çalıştırırım":** Bir kullanım kılavuzu sadece başarı yolunu (happy path) anlatmaz. Hangi durumlarda sistemin hata vereceğini, hangi parametrenin riskli olduğunu ve acil durumda ne yapılması gerektiğini anlatır.
2. **Çıkış Kodları Bir Sözleşmedir (Contract):** Bir betiğin çıkış kodunu kafana göre değiştiremezsin. Çıkış kodu, betiğin diğer güvenlik sistemlerine verdiği yemindir.
3. **Belgesiz Kod Canlıya Çıkamaz:** Bir kodu yazıp testi geçsen bile, eksiksiz bir güvenlik kullanım belgesi ve linter onayı olmadan o kod asla canlı sisteme (production) alınamaz.
