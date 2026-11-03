# GÜN 096: Güvenli Betik Kullanım Belgeleri — Mülakat ve Uzmanlık Soru-Cevap Seti

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu soru-cevap dokümanı DevSecOps, güvenlik mühendisliği ve operasyonel otomasyon mülakatlarına hazırlık için pedagojik olarak yapılandırılmıştır.*

---

## SORU 1: Güvenlik Betiklerinde Belgelenmemiş Parametrelerin (Undocumented Arguments - CWE-1188) Doğurduğu Tehditler

### 1. Soru Başlığı ve Tanımı
Bir güvenlik aracında veya sistem betiğinde, kaynak kodda tanımlı olduğu halde resmi kullanım belgesinde (`--help` veya `README`) yer verilmeyen "gizli / belgelenmemiş parametreler" (Undocumented CLI Arguments) siber güvenlik açısından neden yüksek riskli bir zafiyet (CWE-1188 / CWE-16) olarak değerlendirilir?

### 2. Derinlemesine Teknik Analiz
Geliştiriciler genellikle hata ayıklama (debug), hızlı test veya acil durum müdahalesi amacıyla betiklere parametre eklerler (örneğin: `--skip-ssl-verify`, `--debug-auth`, `--disable-integrity`, `--force-purge`). Bu parametreler dokümantasyonda gizlenir veya unutulur.

Bu durum şu teknik felaketlere yol açar:
1. **İç Tehdit ve Arka Kapı İstismarı (Backdoor Potential):** Saldırganlar veya içerideki kötü niyetli aktörler betiğin kaynak kodunu (veya `strings` / tersine mühendislik ile ikili dosyasını) incelediklerinde bu gizli parametreleri keşfederler. Normalde yetki gerektiren bir işlemi `--bypass` parametresiyle aşabilirler.
2. **Yanlış Yapılandırma ve Veri Kaybı (CWE-16):** Operatör veya otomasyon betiği, parametrenin varsayılan davranışını veya yan etkilerini bilmediği için üretim ortamında yıkıcı bir işlemi (örneğin log veya tablo silinmesi) tetikleyebilir.
3. **Güvensiz Başlatma (CWE-1188):** Belgelenmeyen parametrelerin varsayılan değerleri genellikle güvensizdir (örneğin kimlik doğrulamayı kapatan bayraklar).

Bu nedenle kurumsal DevSecOps standartlarında, kaynak kod ile dokümantasyon arasında birebir eşleşme zorunludur. Kodda var olan her bayrak, kabul ettiği değerler, güvenlik riskleri ve yetki gereksinimleriyle belgelenmek zorundadır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurumda ağ envanterini toplayan bir güvenlik betiği kullanılmaktadır. Geliştirici test amacıyla betiğe `--allow-remote-cmd` parametresi eklemiş ve belgelememiştir. Bir saldırgan ağ üzerinde komut enjeksiyonu denerken bu bayrağın varlığını fark etmiş ve uzaktan kod yürütme (RCE) elde etmiştir.

**Pratik Çözüm:**
CI/CD boru hattına `SecurityDocLinter` entegre edilmiştir. Kaynak koddaki `add_argument` listesi ile JSON güvenlik şeması kıyaslanmakta; şemada yer almayan herhangi bir parametre tespit edildiğinde derleme anında durdurulmaktadır:
```python
# CI/CD güvenlik kapısı
report = SecurityDocLinter.lint("script.py", doc_schema)
if not report["status"] == "PASS":
    sys.exit(1) # Dağıtım iptal edilir
```

### 4. Ustanın Çırağa Tavsiyesi
Çırak, "kimse görmez, ben biliyorum" diyerek koda gizli parametre koyma. Unutma; senin yazdığın her satır kod, eninde sonunda bir güvenlik denetçisinin veya saldırganın eline geçer. Koda koyduğun her seçeneği resmi belgeye yaz; yazamayacağın kadar tehlikeliyse o seçeneği doğrudan koddan temizle.

---

## SORU 2: SOAR ve Güvenlik Otomasyonunda Çıkış Kodları (Exit Codes) Sözleşmesi ve Sessiz Hata İhlalleri

### 1. Soru Başlığı ve Tanımı
Güvenlik betiklerinde standart POSIX çıkış kodlarının (Exit Codes: 0, 1, 2) belgelenmesi ve doğru uygulanması neden bir seçenek değil, güvenlik sözleşmesidir? Çıkış kodu disiplini olmayan betikler SOAR veya SIEM orkestrasyonunda nasıl bir "sessiz güvenlik ihlaline" yol açar?

### 2. Derinlemesine Teknik Analiz
Unix/Linux ve Windows işletim sistemlerinde her süreç tamamlandığında işletim sistemine bir tamsayı çıkış kodu (Exit Status) döner:
- `0`: Standart POSIX uyarınca **BAŞARILI (SUCCESS)** demektir.
- Sıfırdan farklı değerler (`1`, `2`, `127` vb.): **HATA, TEHLİKE veya GÜVENLİK ENGELİ** anlamına gelir.

SOAR (Security Orchestration, Automation and Response) platformları ve Bash/CI betikleri, çalıştırdıkları güvenlik araçlarının ekrana bastığı metinleri (stdout) değil, doğrudan bu çıkış kodunu (`$?` veya `$LASTEXITCODE`) denetler:
```bash
python malware_scanner.py /incoming/file.bin
if [ $? -eq 0 ]; then
    transfer_file_to_production
fi
```
Eğer kötü amaçlı yazılım tarayıcısı (malware_scanner) virüs bulduğunda veya dosya bozuk olduğunda bile `sys.exit(0)` ile çıkarsa, otomasyon boru hattı dosyanın temiz olduğunu varsayar ve virüslü dosyayı doğrudan üretim sunucusuna kopyalar!

Bu nedenle çıkış kodları kullanım belgesinde net bir sözlük olarak tanımlanmalıdır:
- `0`: Temiz / İşlem Başarılı.
- `1`: Tehdit Tespit Edildi / Güvenlik Kuralı İhlali / İptal.
- `2`: Girdi Hatası / Dosya Bulunamadı / Sentaks Hatası.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret firmasında her gece müşteri veritabanı yedeğinin kriptografik bütünlüğü denetlenmektedir. Bütünlük denetleme betiği hash tutmadığında ekrana `[HATA] Hash uyuşmuyor` yazdırmakta ancak `return 0` ile sonlanmaktadır. Jenkins otomasyonu çıkış kodu `0` olduğu için yedeği onaylamış; felaket anında geri yükleme yapılmak istendiğinde yedeklerin tahrif edilmiş olduğu ortaya çıkmıştır.

**Pratik Çözüm:**
Betik ve belgesi güncellenmiş; bütünlük uyuşmazlığında çıkış kodu `1`, girdi hatasında `2` olarak standartlaştırılmış ve belgeye işlenmiştir:
```python
if hash_mismatch:
    sys.stderr.write("[KRİTİK] Bütünlük ihlali!\n")
    sys.exit(1) # Otomasyon hattı hemen alarm üretir ve durur
```

### 4. Ustanın Çırağa Tavsiyesi
Evlat, ekrana kırmızı renkli hata mesajı basmak operatörü bilgilendirir ama otomasyonu bilgilendirmez. Otomasyon robottur; sadece sıfır ve sıfır olmayanı anlar. Çıkış kodların bir sözleşmedir; o sözleşmeyi ihlal edersen sistem sessizce çöker.

---

## SORU 3: "Documentation as Code" ve CI/CD Güvenlik Kapılarında Statik Belge Doğrulaması

### 1. Soru Başlığı ve Tanımı
"Documentation as Code" (Kod Olarak Belgeleme) metodolojisi nedir? Güvenlik betiklerinin geliştirme yaşam döngüsünde (SDLC) Markdown, CLI `--help` ve Man-Page çıktılarının tek bir şemadan üretilmesi ve linter ile test edilmesi kurumsal güvenlik operasyonlarına ne kazandırır?

### 2. Derinlemesine Teknik Analiz
Geleneksel yazılım süreçlerinde belgeler genellikle Word dosyalarında, Confluence sayfalarında veya unutulmuş wiki'lerde saklanır. Kod geliştikçe belgeler güncellenmez; 6 ay sonra belgedeki parametrelerle kodun kabul ettiği parametreler birbirini tutmaz hale gelir (Documentation Drift).

"Documentation as Code" yaklaşımında:
1. **Tek Doğruluk Kaynağı (Single Source of Truth):** Betiğin güvenlik gereksinimleri, yetki seviyesi ve parametreleri yapılandırılmış bir veri modelinde (JSON/YAML) tutulur.
2. **Otomatik Çok Formatlı Derleme:** Bu şemadan operatörün okuyacağı `RUNBOOK.md`, terminal operatörünün göreceği `--help`, Linux sistem yöneticisinin okuyacağı `man` sayfası otomatik derlenir. Asla manuel kopyala-yapıştır yapılmaz.
3. **Statik Kod Analizi (AST Linting):** Python'un `ast` modülü veya gelişmiş regex motorları ile betiğin kaynak kodu taranır; kod ile şemanın tutarlılığı matematiksel kesinlikle denetlenir.
4. **CI/CD Güvenlik Kapısı:** Kod deposuna (Git) her commit atıldığında linter çalışır. Eğer geliştirici yeni bir parametre ekleyip belgelemediyse veya güvenlik uyarısını yazmadıysa build kırılır ve kod ana dala (main branch) birleştirilemez.

Bu yaklaşım, güvenlik araçlarının her zaman denetlenebilir, standart ve şeffaf kalmasını sağlar.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
50 güvenlik analistinin çalıştığı bir siber savunma merkezinde, farklı analistler tarafından yazılmış 200'den fazla Python aracı bulunmaktadır. Araçların çoğunun yardım metni yoktur veya eski sürümlerden kalmadır. Yeni başlayan analistler betikleri yanlış yetkiyle çalıştırarak logları bozmaktadır.

**Pratik Çözüm:**
Kurum genelinde `SecurityScriptDoc` standardı zorunlu kılınmıştır. Her araca bir JSON şeması eklenmiş; `DocGenerator` ile tüm araçların standart `--help` ve `RUNBOOK.md` sayfaları CI/CD aşamasında otomatik üretilmiştir. `SecurityDocLinter` sayesinde belgesi eksik hiçbir betiğin kod deposuna kabul edilmemesi sağlanmıştır.

### 4. Ustanın Çırağa Tavsiyesi
Kod değişir evlat; canlıdır, gelişir. Ama belgeyi koddan ayrı tutarsan belge ölür, geride sadece yanıltıcı bir hayalet kalır. Belgeyi kodun bir parçası yap, onu da kod gibi test et ve doğrula. Usta mühendisin bıraktığı belge, kendisi şirketten ayrılsa bile arkasındakilere ışık tutar.
