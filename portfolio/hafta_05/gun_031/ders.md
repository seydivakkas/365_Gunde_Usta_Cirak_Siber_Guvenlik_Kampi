# Hafta 05 — Gün 031: Process Explorer ve Süreç Ağacı Güvenlik Mimarisi

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## 1. Giriş ve Felsefi Temel

### Usta ile Çırak Arasında Bir Tehdit Avı Sohbeti
*Çırak:* "Ustam, standart Windows Görev Yöneticisi'ni (Task Manager) açtığımda yüzlerce süreç alt alta düz bir liste halinde akıyor. `svchost.exe` adında 70 tane süreç görüyorum, hepsi de 'Windows Hizmet Ana Bilgisayarı' yazıyor. Bir saldırgan kendi kötücül yazılımının adını `svchost.exe` koysa, bunu düz listede nasıl ayırt edeceğiz?"

*Usta:* "Evlat, düz liste gözü kör eder! Süreçler işletim sisteminde havadan zembille inmez; her sürecin onu doğuran bir **ebeveyni (Parent Process)** vardır. İşte bu yüzden efsanevi Windows çekirdek mimarı Mark Russinovich, **Sysinternals Process Explorer** aracını geliştirdi. Process Explorer bize süreçleri düz bir liste olarak değil, bir **soyağacı (Process Tree)** olarak gösterir."

"Fakat çırak, bir tehdit avcısının (Threat Hunter) aklından çıkarmaması gereken en kritik ilke şudur: **Ebeveyn-çocuk süreç ilişkisi yürütme zincirine ipucu sağlar fakat meşru yazılımlar da karmaşık süreç ağacı üretir.** Örneğin Google Chrome veya VS Code açtığında arkada onlarca çocuk süreç başlatır; bu durum bir saldırı değildir. Ancak bir Word belgesi (`winword.exe`) arkasından `cmd.exe` veya `powershell.exe` başlatıyorsa, orada kıyamet kopuyor demektir! Bugün bu yürütme zincirlerini adli düzeyde ayrıştırmayı öğreneceksin."

---

## 2. Süreç Ağacı Anatomisi ve PPID-PID Mekanizması

İşletim sisteminde çalışan her sürece benzersiz bir **PID (Process Identifier)** atanır. Bir süreç başka bir süreci başlattığında (örneğin `CreateProcess` API çağrısıyla), yeni doğan sürece başlatan sürecin PID'si **PPID (Parent Process Identifier)** olarak işlenir.

```
+-------------------------------------------------------------------+
|               STANDART ÇEKİRDEK SÜREÇ SOYAĞACI (BOOT BASELINE)    |
+---------------------------------+---------------------------------+
| System (PID 4)                  | Windows Çekirdeği (ntoskrnl.exe)|
|   └── smss.exe (PID 340)        | Oturum Yöneticisi Alt Sistemi   |
|         ├── csrss.exe (PID 450) | İstemci/Sunucu Çalışma Zamanı   |
|         └── wininit.exe (PID 520)| Windows Başlatma Süreci        |
|               ├── services.exe  | Hizmet Denetim Yöneticisi (SCM) |
|               │     └── svchost | Windows Servis Konteynerleri    |
|               ├── lsass.exe     | Yerel Güvenlik Otoritesi        |
|               └── explorer.exe  | Kullanıcı Masaüstü Kabuğu       |
+---------------------------------+---------------------------------+
```

### Kritik Güvenlik Kuralları:
1. `services.exe` tekil olmalı ve `wininit.exe` altından çıkmalıdır.
2. `svchost.exe` süreçlerinin istisnasız tamamı `services.exe` tarafından başlatılmalıdır.
3. `lsass.exe` tekil olmalı ve asla kullanıcı masaüstü kabuğundan (`explorer.exe`) başlatılmamalıdır.

---

## 3. Bağlamsal Ayrım Sanatı (G031-SC1)

> **Mavi Takım İlkesi (G031-SC1):**  
> *"Ebeveyn-çocuk süreç ilişkisi yürütme zincirine ipucu sağlar fakat meşru yazılımlar da karmaşık süreç ağacı üretir."*

### Meşru Karmaşık Ağaç: Google Chrome & Modern Tarayıcılar
Modern web tarayıcıları, güvenlik ve kararlılık için çoklu süreç mimarisi (multi-process architecture) kullanır:
- `chrome.exe (PID 2100)`: Tarayıcı ana arayüzü ve sekme yöneticisi.
- `├── chrome.exe (PID 2110)`: GPU hızlandırma süreci (`--type=gpu-process`).
- `├── chrome.exe (PID 2120)`: Web sitesi render motoru (`--type=renderer`, izole sandbox).
- `└── chrome.exe (PID 2130)`: Ağ ve uzantı yardımcı süreci (`--type=utility`).
Bu ağaç karmaşıktır, onlarca PID barındırır fakat dijital imzası (`Google LLC`) geçerlidir ve ikili dosya yolu `C:\Program Files\` altındadır. Bu bir **yanlış alarm (False Positive)** oluşturmamalıdır.

### Zararlı Yürütme Zinciri: Ofis Belgesinden Kabuk Başlatma (Malicious Macro)
- `explorer.exe (PID 1040)` -> Kullanıcı faturayı açtı:
- `└── winword.exe (PID 3100)` -> Word belgesi yüklendi.
- `      └── cmd.exe (PID 3150)` -> **ALARM! (T1204.002 / T1059)** Word neden komut satırı açsın?
- `            └── powershell.exe -enc ... (PID 3160)` -> Base64 kodlanmış payload.
- `                  └── svchost.exe (PID 4050)` -> C2 sunucusuna bağlanan sahte servis!

---

## 4. Süreç Taklidi (Masquerading - T1036.005) ve Dijital İmza

Saldırganlar güvenlik araçlarını atlatmak için meşru Windows süreç adlarını taklit eder (Masquerading):
1. **Yanlış Ebeveyn:** Bir `svchost.exe` süreci `services.exe` yerine `cmd.exe` veya `powershell.exe` tarafından başlatılmışsa doğrudan zararlıdır.
2. **Şüpheli Dizin Yolu:** Meşru `svchost.exe` yalnızca `C:\Windows\System32\` dizininde bulunur. Eğer bir süreç `C:\Users\<Kullanıcı>\AppData\Local\Temp\svchost.exe` konumundan çalışıyorsa bu bir truva atıdır (Trojan).
3. **Dijital İmza Yokluğu:** Microsoft'un sistem ikilileri Microsoft tarafından imzalanmıştır. Process Explorer veya analiz motorumuzda `is_verified_signature: False` çıkan bir sistem süreci kırmızı alarmdır.

---

## 5. Süreç Ağacını Şemalaştırma ve Döngü Denetimi (G031-SC2)

Süreç ağacının doğru şemalaştırılması için iki şart vardır:
1. **Hiyerarşik ASCII Görselleştirme:** Ağaç dalları (`├──`, `└──`) ile ebeveyn-çocuk bağları net biçimde gösterilmeli; anomali taşıyan düğümler anında işaretlenmelidir.
2. **Döngüsel Bağımlılık Tespiti (Cycle Detection):** Zararlı yazılımlar veya bozuk bellek yapıları EPROCESS tablosunu tahrif ederek Süreç A'nın ebeveynini Süreç B, Süreç B'nin ebeveynini Süreç A yapabilir (Sonsuz döngü). Geliştirdiğimiz motor bu döngüleri tespit ederek `CIRCULAR_PROCESS_LOOP` hatası ile reddeder (G031-SC2 negatif kontrol).

---

## 6. Geliştirilen Analiz Aracının Satır Satır Analizi

`process_tree_explorer_analyzer.py` aracımız şu modüllerden oluşur:
- **`ProcessValidator`:** Negatif PID, boş ad, mükerrer PID ve DFS tabanlı döngü denetimini icra eder.
- **`ProcessTreeBuilder`:** Düz süreç sözlüklerini `ProcessTreeNode` nesnelerine dönüştürür ve PPID haritası üzerinden kök-çocuk ilişkilerini kurar.
- **`ProcessAnomalyDetector`:** Ofis kabuk başlatmalarını (`OFFICE_SPAWNED_SHELL`), sahte ebeveynleri (`INVALID_PARENT_FOR_SVCHOST`), Temp dizinlerini ve imzasız sistem ikililerini yakalar.
- **`generate_ascii_tree()`:** Standart adli süreç ağacı dökümünü üretir.

---

## 7. Çırağa Tavsiyeler, Mavi Takım Kontrolleri ve Gelecek Güne Köprü

1. **Process Explorer'da Renk Kodlarını Öğren:** Pembe (Servisler), Mavi (Standart kullanıcı süreçleri), Yeşil (Yeni başlayan süreçler), Kırmızı (Kapanan süreçler).
2. **Verify Signatures Özelliğini Aç:** Process Explorer'da `Options -> Verify Signatures` ve `Check VirusTotal.com` seçeneklerini daima aktif tut.
3. **Gelecek Güne Köprü (Gün 032):** Süreçlerin nasıl çalıştığını ve gizlendiğini gördük. Peki bu süreçler sistem yeniden başladığında nasıl otomatik olarak tekrar ayağa kalkar? Yarın, Windows kalıcılık mekanizmalarının temeli olan **Windows Kayıt Defteri (Registry) Run ve RunOnce Anahtarlarını** inceleyeceğiz!
