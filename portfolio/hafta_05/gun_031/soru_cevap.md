# Hafta 05 — Gün 031: Soru & Cevap ve Senaryo Analizleri

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## Senaryo 1 (G031-SC1): Process Explorer ve Süreç Ağacı Temel Mekanizması ve Güvenlik Önemi

### Senaryo Analizi ve Kapsam
Windows işletim sistemlerinde görev yöneticisi (Task Manager) süreçleri düz bir listede gösterir; bu durum süreçlerin birbirleriyle olan ebeveyn-çocuk ilişkilerini gizler. Sysinternals Process Explorer ise süreçleri PPID (Parent Process ID) ve PID ilişkilerine göre hiyerarşik bir ağaç grafı (Process Tree) olarak görselleştirir. Ancak güvenlik analistlerinin en sık düştüğü yanılgı, karmaşık her süreç ağacını zararlı zannetmektir. Bu senaryonun kapsamı; süreç soyağacının adli önemini açıklamak, meşru karmaşık ağaçlar (Google Chrome çoklu süreçleri) ile saldırı zincirleri (Ofis belgesinden komut kabuğu başlatma) arasındaki bağlamsal ayrımı ortaya koymaktır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **PPID-PID Yürütme Zinciri:**
   - Bir süreç başlatıldığında ebeveyninin PID'sini (PPID) miras alır. Bu hiyerarşi adli incelemede bir saldırının başlangıç noktasını (Initial Access) ve sonraki aşamalarını (Execution / Lateral Movement) takip etmeyi sağlar.
2. **G031-SC1 Prensibi (Meşru Karmaşık Ağaçlar vs Saldırı Zincirleri):**
   - **Meşru Karmaşık Ağaç:** Google Chrome veya Microsoft Edge gibi modern tarayıcılar, sekmeleri ve eklentileri sandbox ortamında izole etmek için onlarca çocuk süreç başlatır (`--type=gpu-process`, `--type=renderer`). Bu ağaç karmaşık görünse de dijital imzası geçerlidir (`Google LLC`), çalıştırıldığı dizin meşrudur (`C:\Program Files\`) ve beklenen bir davranıştır.
   - **Saldırı Zinciri:** Bir kelime işlemci (`winword.exe`) veya elektronik tablo (`excel.exe`) bir komut kabuğu (`cmd.exe` veya `powershell.exe`) başlattığında bu durum olağan dışıdır. MITRE ATT&CK **T1204.002 (Malicious File)** ve **T1059 (Command and Scripting Interpreter)** teknikleriyle eşleşir ve derhal müdahale gerektirir.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Süreç Ağacı ve Güvenlik Denetimi:**
  ```bash
  python portfolio/hafta_05/gun_031/uygulama/process_tree_explorer_analyzer.py --inventory portfolio/hafta_05/gun_031/ornek_veri/sample_process_inventory.json --tree --audit
  ```
- **Kanıt Dosyası:** `kanit/gercek/komut_ve_cikis.txt` dosyasında doğrulanmıştır. Chrome'un meşru 4 süreçlik alt ağacı anomali üretmezken (`test_12`); Word uygulamasından başlatılan `cmd.exe -> powershell.exe -> svchost.exe` zinciri kritik anomali olarak izole edilmiştir.
- **Birim Test:** `test_12_legitimate_complex_process_tree_chrome` ile meşru Chrome ağacının sıfır false-positive ürettiği kanıtlanmıştır.

### Savunma Kontrolleri ve Alınacak Dersler
- Mavi takım analistleri yalnızca çocuk sürecin varlığına değil; ebeveynin kimliğine, komut satırı argümanlarına ve ikili dosya yoluna birlikte bakmalıdır.
- EDR kurallarında "Ofis uygulamalarından kabuk türemesini engelleyen" ASR (Attack Surface Reduction) kuralları zorunlu tutulmalıdır.

---

## Senaryo 2 (G031-SC2): Bağımsız Laboratuvar Doğrulaması: Süreç Ağacı Şemalaştırma ve Negatif Kontrol

### Senaryo Analizi ve Kapsam
Bu senaryoda bağımsız bir laboratuvar deneyi kurgulanmıştır: Kontrollü bir girdi olarak 16 süreç içeren `sample_process_inventory.json` dosyası alınmış; süreç hiyerarşisi (kök süreçler: System PID 4, ebeveyn-çocuk bağları) taranarak ASCII ağaç formatında şemalaştırılmıştır. Ardından negatif kontrol amacıyla döngüsel ebeveyn-çocuk ilişkisi (Cycle), negatif PID, boş süreç adı ve mükerrer PID içeren 4 adet bozuk vaka (`corrupted_process_tree_test.json`) sisteme verilmiş ve motorun bu hatalı girdileri istisnasız reddettiği doğrulanmıştır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Süreç Ağacı Şemalaştırma (Tree Rendering):**
   - Kök süreçler (`System`, `explorer.exe`) tespit edilir.
   - Her bir düğüm için bağlantı kolları (`├──`, `└──`) ve derinlik ofsetleri hesaplanır.
   - Anomali taşıyan süreçler kırmızı ünlem etiketiyle (`[! TEHDİT]`) işaretlenir.
2. **Döngüsel Süreç Tespiti (Cycle Detection - DFS):**
   - Bellek tahrifatı veya kötü niyetli manipülasyonlar sonucu oluşan Süreç A -> Süreç B -> Süreç A döngüleri, sonsuz özyinelemeye (stack overflow) neden olur.
   - `ProcessValidator`, derinlik öncelikli arama (DFS) algoritması ile ziyaret edilen PID kümesini takip ederek döngüyü anında tespit eder (`CIRCULAR_PROCESS_LOOP`).
3. **Negatif Kontrol Kapsamı:**
   - Negatif PID (-99) -> `INVALID_PID`
   - Boş süreç adı -> `MISSING_PROCESS_NAME`
   - Mükerrer PID (200) -> `DUPLICATE_PID_DETECTED`
   - Döngüsel ilişki -> `CIRCULAR_PROCESS_LOOP`

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
1. **ASCII Süreç Ağacı Üretimi:**
   `python process_tree_explorer_analyzer.py --inventory sample_process_inventory.json --tree`
   *(Çıktı: `16 süreçlik hiyerarşik ASCII ağacı üretildi, kanit/gercek/surec_agaci_semasi.txt kaydedildi.`)*
2. **Negatif Kontrol Testi:**
   `python process_tree_explorer_analyzer.py --test-corrupted corrupted_process_tree_test.json`
   *(Çıktı: `Toplam Test Edilen Hatalı Vaka: 4, Başarıyla Reddedilen: 4, Sonuç: TAM BAŞARILI (PASS).`)*
- **Kanıt Dosyaları:**
  - `kanit/gercek/surec_agaci_semasi.txt` (ASCII süreç ağacı dökümü).
  - `kanit/gercek/negatif_kontrol_sonuclari.txt` (Döngü ve hata ret kayıtları).
  - `kanit/gercek/test_sonuclari.txt` (14/14 birim test PASS).

### Savunma Kontrolleri ve Alınacak Dersler
- Süreç tabloları analiz edilmeden önce biçimsel veri doğrulaması yapılmalı; adli yazılımların döngüsel veri enjeksiyonlarıyla çökmesi (DoS) önlenmelidir.
- Ağaç yapısı tehdit modellemede analistin bilişsel yükünü azaltır.

---

## Senaryo 3 (G031-SC3): Risk Oluşumu, Tespiti ve Önleyici Savunma Kontrolleri

### Senaryo Analizi ve Kapsam
Süreç ağacı bağlamında güvenlik riskleri; saldırganların meşru süreç adlarını taklit etmesi (Masquerading - T1036.005), ebeveyn süreç aldatmacası (PPID Spoofing), geçici dizinlerden (`AppData\Local\Temp`) sistem ikilisi çalıştırma ve kodlanmış komutlarla (PowerShell Obfuscation) EDR/AV çözümlerini atlatma girişimleriyle ortaya çıkar. Bu senaryo, bu risklerin nasıl oluştuğunu, kural tabanlı motorla nasıl yakalandığını ve en az ayrıcalık ile uygulama beyaz listeleme (AppLocker/WDAC) sayesinde nasıl engellendiğini inceler.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Risk Nasıl Oluşur?**
   - **Süreç Taklidi (Masquerading):** Saldırgan zararlı aracına `svchost.exe` veya `lsass.exe` adını verir. Sıradan görev yöneticisinde bu ad meşru sanılır.
   - **Şüpheli Çalışma Yolu:** Meşru `svchost.exe` yalnızca `System32` altındadır. Saldırgan ise kullanıcı haklarıyla `C:\Users\...\AppData\Local\Temp\` altına yazar ve çalıştırır.
   - **İmzasız Sistem Dosyası:** Microsoft sistem ikilileri Microsoft tarafından dijital olarak imzalanmıştır. Sahte süreçler imzasızdır (`is_verified_signature: False`).
2. **Nasıl Tespit Edilir?**
   - **Ağaç ve Ebeveyn Analizi:** `svchost.exe`'nin ebeveyninin `services.exe` olup olmadığı denetlenir (`INVALID_PARENT_FOR_SVCHOST`).
   - **Dizin ve İmza Kontrolü:** `Temp` dizinindeki sistem adları ve imzasız kritik süreçler motor tarafından otomatik `CRITICAL` risk olarak işaretlenir.
3. **Hangi Kontrollerle Önlenir?**
   - **Uygulama Denetimi (AppLocker / WDAC):** `C:\Users\` ve `Temp` dizinlerinden herhangi bir ikili dosyanın çalıştırılması doğrudan engellenmelidir.
   - **ASR Kuralları (Attack Surface Reduction):** Ofis yazılımlarının alt süreç türetmesi çekirdek seviyesinde bloke edilmelidir.
   - **En Az Ayrıcalık (Least Privilege):** Kullanıcı hesapları yerel yönetici yapılmamalıdır.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Anomali ve İhlal Tespiti:**
  Geliştirilen denetim aracı, `sample_process_inventory.json` üzerinde yaptığı analizde 5 adet kritik güvenlik anomalisi yakalamıştır (`kanit/gercek/komut_ve_cikis.txt`):
  1. `OFFICE_SPAWNED_SHELL` (Word -> cmd.exe)
  2. `ENCODED_POWERSHELL_EXECUTION` (PowerShell Base64)
  3. `INVALID_PARENT_FOR_SVCHOST` (PowerShell -> svchost.exe)
  4. `SUSPICIOUS_SYSTEM_BINARY_PATH` (Temp dizininde svchost)
  5. `UNSIGNED_CRITICAL_PROCESS` (İmzasız svchost.exe)

### Savunma Kontrolleri ve Alınacak Dersler
- Düz süreç listesi güvenlik analizi için yetersizdir; süreç ağacı ve ebeveyn doğrulaması zorunludur.
- Süreç ismi tek başına güven vermez; imza ve dosya yolu ayrılmaz bir bütündür.
