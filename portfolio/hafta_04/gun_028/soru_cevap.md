# Hafta 04 — Gün 028: Soru & Cevap ve Senaryo Analizleri

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## Senaryo 1 (G028-SC1): Komut Satırı Çalışma Defteri Temel Mekanizması ve Güvenlik Önemi

### Senaryo Analizi ve Kapsam
Siber güvenlik operasyonlarında (SOC, Olay Müdahalesi / DFIR, Sistem Sıkılaştırma), analistlerin işletim sistemi üzerinde yürüttüğü incelemelerin rastgele ve belgelenmemiş olması kabul edilemez. Bir sistemin mevcut durumuna (kullanıcılar, süreçler, açık portlar, disk doluluğu, ortam değişkenleri) dair gözlemler, denetlenebilir ve yeniden üretilebilir (reproducible) olmalıdır. Bu senaryonun kapsamı; komut satırı çalışma defteri mekanizmasının adli geçerliliğini, gözlemlerin standartlaştırılmış komut dizileriyle nasıl belgelenmesi gerektiğini ve bu sürecin kurumsal güvenlik denetimlerindeki vazgeçilmez yerini incelemektir.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Yeniden Üretilebilirlik İlkesi (Principle of Reproducibility):** Bir analistin elde ettiği güvenlik bulgusu (örn: şüpheli bir dinleme portu veya yetkisiz ortam değişkeni), başka bir analist veya denetçi tarafından aynı komut çalıştırıldığında aynı kriterlerle gözlemlenebilmelidir.
2. **Kriptografik Bütünlük Mühürlemesi (SHA-256):** Terminal çıktıları metin tabanlı olduğu için sonradan değiştirilme (tampering) riski taşır. Komut kimliği, komut dizgisi, ham çıktı ve yürütme zaman damgası birleştirilerek SHA-256 kriptografik özeti hesaplanır. Bu sayede defterin bütünlüğü garanti altına alınır.
3. **Durum Değiştirmeyen Keşif (Idempotent / Read-Only Reconnaissance):** Denetim komutları kesinlikle sistem durumunu değiştirmemeli (state mutation yapmamalı), dosya oluşturup silmemeli veya servis ayarlarını tahrif etmemelidir. Salt-okunur (read-only) güvenlik politikası, denetimin sistemi bozmasını önler.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Denetim ve Defter Çalıştırma:**
  ```bash
  python portfolio/hafta_04/gun_028/uygulama/command_line_notebook_engine.py --catalog portfolio/hafta_04/gun_028/ornek_veri/safe_command_catalog.json --audit
  ```
- **Kanıt Dosyası:** `kanit/gercek/komut_ve_cikis.txt` dosyasında doğrulanmıştır. 12 adet salt-okunur komutun tamamı sırayla incelenmiş, her biri için tekil SHA-256 özeti üretilmiş ve `%100` başarıyla doğrulanmıştır.
- **Detaylı Defter Çıktısı:** `kanit/gercek/calisma_defteri_ornek.md` dosyasında 380 satırlık eksiksiz çalışma defteri üretilmiştir.

### Savunma Kontrolleri ve Alınacak Dersler
- Sistem yöneticileri ve analistler, rastgele komut geçmişi (`.bash_history`) yerine yapılandırılmış çalışma defterleri kullanmalıdır.
- Komut çıktıları merkezi SIEM sistemine kriptografik özetleriyle aktarılmalıdır.

---

## Senaryo 2 (G028-SC2): Bağımsız Laboratuvar Doğrulaması: 10+ Salt-Okunur Komut Defteri ve Negatif Kontrol

### Senaryo Analizi ve Kapsam
Bu senaryoda bağımsız bir laboratuvar deneyi kurgulanmıştır: Kontrollü bir girdi olarak 12 adet salt-okunur komut içeren JSON kataloğu (`safe_command_catalog.json`) verilmiş; sistem bu komutları güvenlik kapısından geçirerek açıklamalı bir Markdown çalışma defterine dönüştürmüştür. Ardından negatif kontrol amacıyla 8 adet yıkıcı ve yetkisiz komut içeren veri kümesi (`prohibited_commands_test.json`) sisteme verilmiş ve motorun bu komutları istisnasız engellediği adli olarak doğrulanmıştır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Asgari 10 Komut Şartı ve Kapsam:** Laboratuvarda 12 komut incelenmiştir: `whoami`, `id`, `hostname`, `uname -a`, `uptime`, `ps aux`, `df -h`, `free -m`, `ss -tulpn`, `ip addr`, `env`, `ls -ld /tmp`. Her komut MITRE ATT&CK keşif teknikleriyle (T1033, T1082, T1057, T1049 vb.) eşleştirilmiştir.
2. **Çift Kademeli Güvenlik Kapısı (Command Safety Gate):**
   - **Kademe 1 (Kara Liste RegEx):** `rm -rf`, `del /f /s /q`, `mkfs`, `dd`, `kill -9 1`, `chmod 777`, `useradd`, `curl | bash` kalıpları taranır (CWE-78, CWE-250, CWE-494).
   - **Kademe 2 (Beyaz Liste Kök Komut):** Yalnızca onaylanmış 16 salt-okunur ikili dosya adına izin verilir.
3. **Negatif Kontrol Doğrulaması:** Yıkıcı bir komut tespit edildiğinde yürütme derhal durdurulur, `SecurityPolicyViolationError` fırlatılır ve olay `BLOCKED` statüsüyle güvenlik günlüğüne işlenir.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
1. **Açıklamalı Markdown Defteri Üretimi:**
   `python command_line_notebook_engine.py --catalog safe_command_catalog.json --generate-notebook calisma_defteri_ornek.md --audit`
   *(Çıktı: `12 komut işlendi, %100 başarı, calisma_defteri_ornek.md oluşturuldu.`)*
2. **Negatif Kontrol Testi (Yıkıcı Komutlar):**
   `python command_line_notebook_engine.py --test-prohibited prohibited_commands_test.json`
   *(Çıktı: `Toplam Test Edilen Zararlı Komut: 8, Başarıyla Engellenen: 8, Sonuç: TAM BAŞARILI (PASS).`)*
- **Kanıt Dosyaları:**
  - `kanit/gercek/guvenlik_engelleme_kaydi.txt` (Engellenen 8 yıkıcı komutun dökümü).
  - `kanit/gercek/calisma_defteri_ornek.md` (380 satırlık nihai çalışma defteri).
  - `kanit/gercek/test_sonuclari.txt` (14/14 birim test PASS).

### Savunma Kontrolleri ve Alınacak Dersler
- Yıkıcı komutlar üretim sistemlerinde doğrudan engellenmeli, sistem yöneticilerine bile çift onay mekanizması getirilmelidir.
- Otomasyon araçları `shell=True` yerine kesinlikle güvenli parametre ayrıştırması kullanmalıdır.

---

## Senaryo 3 (G028-SC3): Risk Oluşumu, Tespiti ve Önleyici Savunma Kontrolleri

### Senaryo Analizi ve Kapsam
Komut satırı çalışma defterleri bağlamında güvenlik riskleri; denetim araçlarının yetkisiz kişilerce kötüye kullanılması, gereksiz ayrıcalıklı hesaplarla çalıştırılması (CWE-250), sistem çıktılarında hassas verilerin (parolalar, API anahtarları) açık metin olarak ifşa olması veya yanlış yapılandırılmış servislerin istismar edilmesiyle ortaya çıkar. Bu senaryo, bu risklerin nasıl oluştuğunu, fark analiziyle nasıl tespit edildiğini ve en az ayrıcalık prensibiyle nasıl önlendiğini ortaya koyar.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Risk Nasıl Oluşur?**
   - **Gereksiz İzinler ve Root/SYSTEM Bağımlılığı:** Bir analist veya betik basit bir `hostname` veya `uptime` komutunu `sudo` ile çalıştırdığında, olası bir enjeksiyon açığı tüm sistemi ele geçirme riskine yol açar.
   - **Hassas Veri İfşası (Information Disclosure):** `env` veya `ps aux` gibi komutlar çalıştırıldığında, ortam değişkenlerinde veya komut satırı argümanlarında unutulmuş veritabanı şifreleri açığa çıkabilir.
   - **Yanlış Servis ve Yapılandırma:** Sistemde gereksiz servislerin (FTP, Telnet) açık kalması saldırganların hedefi haline gelir.
2. **Nasıl Tespit Edilir?**
   - **Envanter ve Fark Raporu:** Sistemden periyodik olarak alınan komut satırı çalışma defterleri bir önceki referans (baseline) defter ile karşılaştırılır (Differential Analysis).
   - Yeni açılmış bir dinleme soketi (`ss -tulpn` farkı), yeni eklenmiş bir ortam değişkeni (`env` farkı) veya beklenmeyen bir süreç (`ps aux` farkı) anında alarm üretir.
3. **Hangi Kontrollerle Önlenir?**
   - **En Az Ayrıcalık (Least Privilege):** Denetim komutları kesinlikle kısıtlı (unprivileged) bir kullanıcı hesabıyla (`secops_auditor`) yürütülmelidir.
   - **Çıktı Maskeleme (Data Masking / Redaction):** `env` çıktısındaki `*KEY*`, `*SECRET*`, `*PASSWORD*` alanları çalışma defterine yazılmadan önce maskelenmelidir.
   - **Geri Alınabilir Yapılandırma:** Yapılan tüm sistem değişiklikleri ve denetim kayıtları versiyon kontrol sisteminde (Git) saklanmalıdır.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Fark ve Risk Analizi:**
  Geliştirilen motor, her komut kaydı için düzenli ifade desen denetimi (`pattern_matched`) yaparak beklenmeyen çıktı formatlarını derhal tespit eder (`kanit/gercek/calisma_defteri_ornek.md`).
- **Bütünlük İhlal Tespiti:** Kriptografik SHA-256 mühürleri sayesinde defter üzerinde yapılacak en ufak yetkisiz değişiklik anında yakalanır.

### Savunma Kontrolleri ve Alınacak Dersler
- Güvenlik denetimleri asla körlemesine yapılmamalı; sistem gözlemleri adli standartlarda arşivlenmelidir.
- Savunma stratejisinde "keşif yeteneği", saldırganın keşif yeteneğinden her zaman bir adım önde ve daha disiplinli olmalıdır.
