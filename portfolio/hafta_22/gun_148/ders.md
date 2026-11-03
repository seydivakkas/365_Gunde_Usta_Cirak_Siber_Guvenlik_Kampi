# Gün 148: EDR, Antivirüs (AV) ve Uç Nokta Telemetri Güvenliği

**Hafta 22: Usta-Çırak Derinlemesine Teknik Dersi**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Özel Lisans — Tüm Hakları Saklıdır.*

---

## 🧭 Bölüm 1: Giriş ve Geleneksel AV'nin Çöküşü (Usta Dersi)

> **Usta:** Evlat, bundan 15-20 yıl önce güvenlik sektörü çok saftı. Bir zararlı yazılım çıkardı, antivirüs şirketi o dosyanın MD5 veya SHA-256 özetini (hash) alır, veri tabanına eklerdi. Antivirüs de diski tarar, hash eşleşirse "Virüs buldum!" diye sevinirdi.
>
> **Çırak:** Usta, peki saldırgan o dosyanın sonuna tek bir anlamsız boşluk veya 1 bayt eklese ne olurdu?
>
> **Usta:** İşte o zaman hash tamamen değişirdi! Buna **Polimorfizm (Polymorphism)** diyoruz. Dahası, günümüzde gelişmiş saldırganlar (APT grupları) diske **hiçbir dosya yazmıyorlar**. Kod doğrudan belleğe (RAM) enjekte ediliyor, PowerShell veya WMI gibi meşru işletim sistemi araçları üzerinden çalıştırılıyor (**Fileless Malware / Living-off-the-Land**).
>
> İşte bu yüzden geleneksel Antivirüs (AV) artık kapıdaki tabeladan ibarettir. Modern savunmanın kalbi **EDR (Endpoint Detection and Response - Uç Nokta Tespit ve Müdahale)** sistemleridir. EDR dosyanın ne olduğuna değil, **işletim sistemi çekirdeğinde ne yaptığına (telemetriye)** bakar!

---

## 🏛️ Bölüm 2: AV vs EDR Karşılaştırmalı Mimarisi

```text
+-----------------------------------------------------------------------------------+
|               GELENEKSEL ANTİVİRÜS (AV) vs MODERN EDR FARKI                       |
+---------------------------------------------------+-------------------------------+
| GELENEKSEL AV (Statik & Reaktif)                  | MODERN EDR (Dinamik & Davranışsal)
+---------------------------------------------------+-------------------------------+
| - Dosya tabanlıdır (Diskte dosya arar).           | - Telemetri ve süreç tabanlıdır (RAM/Kernel).
| - Hash (MD5/SHA256) ve imza eşleşmesine bakar.   | - Davranış anomalilerini ve soy ağacını izler.
| - Dosyasız (Fileless) saldırılarda KÖRDÜR.        | - Bellek enjeksiyonunu ve LOLBAS'ı yakalar.
| - Yalnızca bilinen eski tehditleri durdurur.      | - Sıfır gün (0-day) ve APT zincirini yakalar.
| - Müdahale yeteneği: Dosyayı sil / karantinaya al.| - Müdahale: Süreci öldür, makineyi ağdan izole et.
+---------------------------------------------------+-------------------------------+
```

---

## 🔬 Bölüm 3: Çekirdek (Kernel) Telemetrisi Nasıl Toplanır?

Bir EDR ajanının işletim sisteminde olan biteni kaçırmaması için Windows çekirdeğine (Kernel Mode) sürücü seviyesinde entegre olması gerekir:

1. **Kernel Callbacks (Çekirdek Bildirim Rutinleri):**
   - `PsSetCreateProcessNotifyRoutineEx`: Sistemde her yeni süreç başladığında veya kapandığında EDR sürücüsüne anında bildirim gider (Parent PID, Image Path, Command Line).
   - `PsSetCreateThreadNotifyRoutine`: Yeni bir iş parçacığı (thread) açıldığında tetiklenir (Çapraz enjeksiyon tespiti).
   - `ObRegisterCallbacks`: Süreç ve iş parçacığı tanıtıcıları (Handles) açılırken araya girer. Örneğin bir süreç `lsass.exe` için `PROCESS_VM_READ` hakkı istediğinde EDR bu tanıtıcıyı bloke eder!
2. **Minifilter Dosya Sürücüleri (File System Minifilters):**
   - Diskte oluşturulan, değiştirilen veya şifrelenen her dosya G/Ç (I/O) isteği filtreden geçer (Fidye yazılımı tespiti).
3. **ETW ve ETW-TI (Event Tracing for Windows - Threat Intelligence):**
   - Windows çekirdeğinin doğrudan güvenlik olaylarını (bellek ayırma, DLL yükleme, APICall) akıttığı yüksek performanslı telemetri kanalıdır.
4. **Linux Dünyasında Karşılığı: eBPF (Extended Berkeley Packet Filter):**
   - Linux çekirdeğine modül yazmadan, güvenli sanal makine ortamında sistem çağrılarını (syscalls) ve ağ paketlerini mikrosaniyeler seviyesinde izleme standardıdır.

---

## 🌲 Bölüm 4: Süreç Soy Ağacı (Process Lineage) ve LOLBAS Tespiti

Saldırganlar kurumsal sistemlere kendi derlenmiş `.exe` dosyalarını sokmak yerine, Windows'un meşru ikili dosyalarını (**LOLBAS - Living-off-the-Land Binaries and Scripts**) silah olarak kullanırlar.

### Tipik Bir Saldırı Soy Ağacı:
```text
explorer.exe (Kullanıcı Arayüzü)
   │
   └── WINWORD.EXE (Kullanıcı oltalama e-postasındaki Word belgesini açar)
          │
          └── powershell.exe (Zararlı VBA makrosu gizlice PowerShell başlatır - ANOMALİ!)
                 │
                 ├── cmd.exe /c whoami (Sistem keşfi yapar)
                 └── procdump.exe -ma lsass.exe (Bellekten parola çalar - KRİTİK ALARM!)
```

**EDR'ın Bakış Açısı:**
- `powershell.exe` tek başına meşru bir araçtır.
- Ancak `powershell.exe`'nin ebeveyninin (Parent Process) `WINWORD.EXE` veya `EXCEL.EXE` olması **asla normal değildir**!
- EDR süreç soy ağacına bakar: *"Word bir metin editörüdür, neden PowerShell başlatsın?"* der ve o süreci çekirdek seviyesinde sonlandırır (`KILL_PROCESS`).

---

## 💉 Bölüm 5: Bellek Enjeksiyonu (Process Injection) ve Gizleme

Gelişmiş zararlı yazılımlar diske dosya bırakmaz, doğrudan meşru bir Windows sürecinin (örn. `svchost.exe`, `explorer.exe`, `notepad.exe`) belleğine kendi kodunu aşılar:

1. **DLL Injection & CreateRemoteThread:**
   - Saldırgan hedef süreci `OpenProcess` ile açar, `VirtualAllocEx` ile hedef bellekte yer açar, `WriteProcessMemory` ile kabuk kodunu (shellcode) yazar ve `CreateRemoteThread` ile yeni bir iş parçacığı başlatır.
2. **Process Hollowing (Süreç Oyma):**
   - Meşru bir süreç askıya alınmış (`CREATE_SUSPENDED`) halde başlatılır, orijinal kodu bellekten sökülür (`ZwUnmapViewOfSection`), yerine zararlı kod yazılır ve süreç uyandırılır (`ResumeThread`).
3. **EDR Tespiti:**
   - EDR, bir sürecin başka bir sürecin belleğine yazma hakkı almasını veya bellek alanının hem yazılabilir hem çalıştırılabilir (`PAGE_EXECUTE_READWRITE - RWX`) olmasını şüpheli bulur ve engeller.

---

## 🛑 Bölüm 6: Otonom Müdahale (Response Actions)

Bir tehdit tespit edildiğinde EDR yalnızca log atmaz, otomatik aksiyon alır:
1. **Kill Process (Süreç Ağacını Öldürme):** Zararlı süreci ve başlattığı tüm alt süreçleri (Child Processes) derhal sonlandırır.
2. **Quarantine File (Dosya Karantinaya Alma):** İlgili çalıştırılabilir dosyayı şifreleyerek özel karantina dizinine taşır.
3. **Host Isolation (Ağ İzolasyonu):** En kritik müdahaledir. Eğer uç noktada C2 bağlantısı veya LSASS dökümü yakalanırsa, EDR makinenin tüm yerel ağ ve internet erişimini keser; yalnızca SOC analistinin uzaktan konsol bağlantısına izin verir. Böylece saldırganın diğer sunuculara sıçraması (Lateral Movement) anında durdurulur!

---

## 🎓 Usta Öğüdü ve Altın Kural

> **"Evlat, dosyanın adına veya uzantısına bakan aldanır. Saldırgan dosyanın adını `svchost.exe` yapar, imzasını siler, kodunu şifreler. Ama belleğe girdiğinde CPU komutunu işletmek ve sistem çağrısı yapmak zorundadır. EDR telemetrisi gerçeğin tek aynasıdır!"**
