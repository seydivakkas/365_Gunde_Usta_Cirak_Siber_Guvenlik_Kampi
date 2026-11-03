# Gün 149: Uygulama İzinleri ve Sandbox Güvenlik Mimarisi
**Hoca Dersi — Usta-Çırak Derinlemesine Teknik Eğitim Modülü**

---

## 1. Giriş ve Temel Felsefe: Neden Sandbox?

Evlat, siber güvenliğin en kadim ve en acı tecrübelerle sabitlenmiş kuralı şudur: **"Yazdığın ya da çalıştırdığın hiçbir üçüncü taraf koda, tarayıcı eklentisine ya da kullanıcı girdisine sonsuz güvenemezsin."**

Klasik monolitik işletim sistemi mimarilerinde bir uygulama çalıştırıldığında, o uygulamayı başlatan kullanıcının tüm yetkilerini devralırdı. Yani Ahmet kullanıcısı standart bir kullanıcı olsa bile; indirdiği bir PDF görüntüleyici veya tarayıcı exploited edildiğinde, saldırgan Ahmet'in okuyabildiği tüm dosyalara (`/home/ahmet` veya `C:\Users\Ahmet`), ağ kartına, hafızadaki diğer süreçlere ve işletim sistemi çekirdeğine doğrudan erişim sağlardı.

İşte **Sandbox (Korumalı Alan / Kum Havuzu)** mimarisi bu "varsayılan güven" gafletini ortadan kaldırmak için doğmuştur. Bir uygulamayı sandbox içine almak; onu sanal bir zindana hapsetmek, etrafına katmanlı duvarlar örmek ve yalnızca çalışması için hayati derecede zorunlu olan sistem kaynaklarına izin vermektir. 

Bu derste; modern işletim sistemlerinin (Linux ve Windows) çekirdek seviyesindeki izolasyon primitiflerini, sistem çağrısı filtrelerini (Seccomp-BPF), Linux yeteneklerini (Capabilities), Windows Zorunlu Bütünlük Seviyelerini (MIC & AppContainer) ve kum havuzundan kaçış (Sandbox Escape) vektörlerini en ince ayrıntısına kadar inceleyeceğiz.

---

## 2. Linux Çekirdek İzolasyon Primitifleri

Linux üzerinde "sandbox" veya "konteyner" dediğimiz yapılar sihirli bir kutu değildir; çekirdeğin sunduğu 4 temel mekanizmanın bir araya gelmesidir:
1. **Namespaces (Ad Alanları):** Sürecin neyi görebildiğini sınırlar (görünürlük izolasyonu).
2. **Control Groups (cgroups v2):** Sürecin ne kadar kaynak tüketebileceğini sınırlar (kaynak izolasyonu).
3. **Linux Capabilities (Yetenekler):** Root yetkisini 40+ parçaya bölerek gereksiz yetkileri düşürür (ayrıcalık izolasyonu).
4. **Seccomp-BPF (Secure Computing Mode):** Sürecin çekirdeğe hangi sistem çağrılarını yapabileceğini sınırlar (sistem çağrısı izolasyonu).

```
+------------------------------------------------------------------------------------+
|                         GÜVENİLMEYEN SÜREÇ (UNTRUSTED PROCESS)                      |
+------------------------------------------------------------------------------------+
       |                                      |                                  |
       v (Görünürlük)                         v (Kaynak)                         v (Sistem Çağrısı)
+-----------------------+              +-----------------------+          +-----------------------+
|   LINUX NAMESPACES    |              |       CGROUPS v2      |          |      SECCOMP-BPF      |
| * PID (İzole süreçler)|              | * pids.max (Fork Bomb)|          | * Allowlist (Minimal) |
| * Mount (Kök / tmpfs) |              | * memory.max (OOM)    |          | * Blocked: ptrace,    |
| * Net (Loopback/None) |              | * cpu.max (Throttling)|          |   bpf, mount, reboot  |
+-----------------------+              +-----------------------+          +-----------------------+
                                              |
                                              v
                              +-------------------------------+
                              |    LINUX KERNEL (RING 0)      |
                              +-------------------------------+
```

### 2.1. Seccomp ve Seccomp-BPF (Berkeley Packet Filter)
Linux'ta bir uygulama çekirdekten dosya açmasını, ağ soketi oluşturmasını veya bellek tahsis etmesini istemek için **Sistem Çağrısı (System Call - Syscall)** yapar. x86_64 mimarisinde yaklaşık 350-400 sistem çağrısı bulunur. Oysa basit bir HTTP servisinin veya JavaScript yorumlayıcısının çalışması için yalnızca 40-50 çağrı yeterlidir.

Geriye kalan ~300 sistem çağrısı (`bpf`, `ptrace`, `mount`, `kexec_load`, `pivot_root`, `reboot` vb.), saldırganların çekirdek açığı tetiklemek veya sandbox dışına kaçmak için kullandığı cephaneliktir.

* **Seccomp Modu:** `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` çağrıldığında süreç yalnızca 4 çağrıya izin verir: `read`, `write`, `_exit`, `sigreturn`. Diğer herhangi bir çağrıda süreç çekirdek tarafından `SIGKILL` ile katledilir. Bu mod çok kısıtlıdır.
* **Seccomp-BPF (Filtre Modu):** `SECCOMP_MODE_FILTER` ile çekirdeğe bir BPF programı yüklenir. Çekirdek, sürecin her sistem çağrısında bu BPF talimatlarını koşturur ve şu aksiyonlardan birini üretir:
  1. `SECCOMP_RET_ALLOW`: Çağrıya izin ver.
  2. `SECCOMP_RET_KILL_PROCESS`: Bütün süreci ve iş parçacıklarını anında öldür.
  3. `SECCOMP_RET_ERRNO`: Çağrıyı çalıştırmadan `errno` (örn: `EPERM` - Operation not permitted) döndür.
  4. `SECCOMP_RET_LOG`: Denetim için syslog/auditd'ye yaz ama çalışmasına izin ver.
  5. `SECCOMP_RET_TRAP`: `SIGSYS` sinyali üreterek hata ayıklayıcıya yönlendir.

> [!CRITICAL]
> **Ustanın Altın Kuralı (Default Deny):** Bir seccomp filtresinde asla ve kata varsayılan eylemi `ALLOW` yapıp sadece bildiğin tehlikeli çağrıları engellemeye çalışma (Denylist mantığı). Saldırganlar yeni çekirdek sürümlerindeki bilinmeyen çağrıları (`io_uring`, `open_by_handle_at`, `process_madvise`) kullanarak filtreni deler geçer. Her zaman varsayılan eylemi `SECCOMP_RET_ERRNO` veya `SECCOMP_RET_KILL` yapıp, yalnızca testlerle doğruladığın çağrıları `ALLOW` listesine ekle!

### 2.2. Linux Capabilities (Ayrıcalık Bölümleme)
Klasik UNIX modelinde yetkilendirme ikiliydi: Ya normal kullanıcısın (UID != 0) hiçbir şey yapamazsın, ya da `root`sun (UID == 0) tanrısal yetkilere sahipsin. 

Linux çekirdeği bu sorunu çözmek için `Capabilities` mekanizmasını getirdi. Root yetkileri 40'tan fazla bağımsız yeteneğe bölündü:
* `CAP_CHOWN`: Dosya sahipliği değiştirme.
* `CAP_NET_BIND_SERVICE`: 1024'ün altındaki portlara bağlanabilme (örn: 80, 443).
* `CAP_SYS_ADMIN`: **"Konteyner Katili"**. Çekirdeğin en geniş ve en tehlikeli yeteneğidir. Dosya sistemi bağlama (`mount`), namespace değiştirme, IPC manipülasyonu gibi fiili root yetkilerini içerir.
* `CAP_SYS_PTRACE`: Diğer süreçlerin belleğini denetleme ve `ptrace` ile kod enjekte etme.
* `CAP_NET_RAW`: Ham paket soketleri (`SOCK_RAW`) açarak ağ kartı üzerinden ARP/IP zehirleme ve paket dinleme.

Korumalı bir sandbox çalıştırılırken kural basittir: **Tüm yetenekleri düşür (`--cap-drop=ALL`), sadece mutlak gerekli olanı (örneğin sadece port bağlayacaksa `CAP_NET_BIND_SERVICE`) damlalıkla ver.**

---

## 3. Windows İzolasyon Mimarisi: MIC ve AppContainer

Windows dünyasında güvenlik nesne tabanlıdır (Securable Objects) ve Güvenlik Tanımlayıcıları (Security Descriptors) ile yönetilir. Ancak Windows Vista ile birlikte kum havuzu güvenliği için iki devrimsel katman eklenmiştir:

### 3.1. Zorunlu Bütünlük Kontrolü (Mandatory Integrity Control - MIC)
Windows'ta her sürecin ve her güvenli nesnenin (dosya, kayıt defteri anahtarı, adlandırılmış boru hattı) bir **Bütünlük Seviyesi (Integrity Level)** vardır:
1. `UNTRUSTED` (Güvensiz / 0x0000): Sıfır yetki.
2. `LOW` (Düşük / 0x1000): Internet Explorer Korumalı Mod, Chromium render süreçleri.
3. `MEDIUM` (Orta / 0x2000): Standart kullanıcı olarak çalışan programlar.
4. `HIGH` (Yüksek / 0x3000): "Yönetici Olarak Çalıştır" (Elevated Admin) süreçleri.
5. `SYSTEM` (Sistem / 0x4000): İşletim sistemi servisleri.

**Bütünlük Kuralı (No Write Up):**
Daha düşük bütünlük seviyesine sahip bir süreç, kendisinden daha yüksek bütünlük seviyesindeki hiçbir nesneye **yazamaz**, değiştiremez ve `CreateRemoteThread` gibi API'lerle o sürecin belleğine kod enjekte edemez. Örneğin Low Integrity çalışan bir tarayıcı render süreci, Medium Integrity olan Windows Gezgini'ne veya masaüstü dosyalarına asla yazamaz.

### 3.2. Windows AppContainer İzolasyonu
Windows 8 ile tanıtılan **AppContainer**, Windows'un en gelişmiş süreç izolasyon sandboxing teknolojisidir. Modern UWP uygulamaları ve Chromium tabanlı tarayıcılar bu mekanizmayı kullanır:
* **Özel Güvenlik Kimliği (Package SID):** Her AppContainer süreci benzersiz bir paket SID'sine (`S-1-15-2-...`) sahiptir.
* **Yetenek Tabanlı İzinler:** Uygulamanın mikrofon, kamera veya internete erişmesi için açıkça Capability SID verilmesi gerekir (örn: `internetClient`, `privateNetworkClientServer`).
* **Sıfır Dosya Sistemi Erişimi:** AppContainer süreçleri varsayılan olarak `C:\Users` veya `C:\Windows` altına yazamaz; yalnızca kendilerine özel ayrılmış `AppData\Local\Packages\...` klasörüne erişebilirler.

---

## 4. Sandbox Kaçış (Escape) Vektörleri ve Savunma Stratejileri

Saldırganlar sandbox içine sızmayı başardıklarında doğrudan ana makineye zıplamak (Escape to Host) için şu yöntemlere başvururlar:

| Saldırı Vektörü | MITRE Tekniği | Saldırı Yöntemi | Savunma ve Sertleştirme Çözümü |
|---|---|---|---|
| **Konteyner `--privileged` Suistimali** | T1611 | Konteynere tüm yeteneklerin verilmesi ve `/dev` altındaki ana disk bloklarına (`/dev/sda1`) doğrudan yazılarak host diskinin ele geçirilmesi. | Asla `--privileged` kullanılmamalıdır. Yetenekler `--cap-drop=ALL` ile sıfırlanmalıdır. |
| **Docker Soket Bağlantısı** | T1611 | Host `/var/run/docker.sock` dosyasının sandbox içine bağlanmasıyla içeriden Docker API çağrılıp host root'u mount eden yeni konteyner açılması. | Docker soketi kesinlikle sandbox içine mount edilmemeli, `maskedPaths` ile gizlenmelidir. |
| **ptrace Bellek Enjeksiyonu** | T1055.008 | Seccomp filtresinde `ptrace` engellenmediğinde aynı UID'deki host süreçlerine bağlanıp kötü amaçlı shellcode enjekte edilmesi. | Seccomp profilinde `ptrace`, `process_vm_readv` ve `process_vm_writev` çağrıları `SCMP_ACT_KILL` ile katledilmelidir. |
| **Kök Dosya Sistemi Kalıcılığı** | T1547 | Kök dosya sistemi yazılabilir bırakıldığında paylaşılan kütüphanelerin (`.so`, `.dll`) veya başlangıç betiklerinin değiştirilmesi. | Kök dosya sistemi `--read-only` bağlanmalı; geçici veriler için bellek tabanlı `tmpfs` (`noexec, nosuid, nodev`) verilmelidir. |
| **Fork Bomb ve DoS** | T1499 | Sınırsız süreç çatallanmasıyla ana makinenin PID tablosunun kilitlenmesi ve sistemin çökertilmesi. | cgroups v2 `pids.max` (örn: 32 veya 64) ile süreç sayısı sert bir tavanla sınırlandırılmalıdır. |

---

## 5. Usta-Çırak Uygulama Notları ve Özet

Evlat, bugün geliştirdiğimiz `app_sandbox_engine.py` motoru ve 15 birim testimiz; bir sandbox profilinin kağıt üzerinde güvenli görünüp görünmediğini değil, çekirdek seviyesinde gerçekten su geçirmez olup olmadığını denetler.

Unutma: **En iyi sandbox, saldırganın varlığından bile şüphelenmediği ama kılını kıpırdattığı anda çekirdek tarafından imha edildiği sandboxtur.**
