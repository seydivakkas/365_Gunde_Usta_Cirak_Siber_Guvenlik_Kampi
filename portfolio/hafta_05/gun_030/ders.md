# Hafta 05 — Gün 030: Linux journalctl ve Günlük Dizinleri Güvenlik Mimarisi

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## 1. Giriş ve Felsefi Temel

### Usta ile Çırak Arasında Bir Sohbet
*Çırak:* "Ustam, dün Windows Event Viewer dünyasını inceledik ve ikili EVTX kayıtlarını bağlamsal olarak ayrıştırdık. Bugün Linux sunucusuna geçtiğimde eski yöneticilerin bana söylediği ilk şey `/var/log/syslog` veya `/var/log/messages` dosyalarını `tail -f` ile izlemekti. Ancak modern Linux dağıtımlarında `journalctl` diye bir komut var. Neden düz metin loglardan vazgeçilip ikili (binary) bir journal yapısına geçildi?"

*Usta:* "Evlat, 1980'lerden kalan geleneksel Syslog mimarisi düz metin dosyaları kullanırdı. Düz metin dosyaların iki ölümcül zaafı vardır: Birincisi, sisteme sızan bir saldırgan bir metin düzenleyiciyle (`nano`, `sed`) log satırlarını tahrif edebilir veya silebilir. İkincisi, saniyede on binlerce olayın aktığı devasa bulut sistemlerinde düz metin aramak çok yavaştır."

"`systemd-journald`, işte bu sorunları çözmek için doğdu. Olayları ikili (binary), indekslenmiş ve kriptografik Forward Secure Sealing (FSS) ile mühürlenebilir biçimde saklar. Fakat çırak, bir sistem yöneticisinin yapacağı en ölümcül hata, journal yapılandırmasını varsayılan 'geçici (volatile)' modda bırakmaktır. Eğer günlükler kalıcı diske yazılmazsa, saldırgan sunucuyu yeniden başlattığı (`reboot`) anda tüm adli izler yok olur! Ayrıca çoklu sunucu denetiminde saat dilimini (timezone) hesaba katmazsan, olayların kronolojisini tamamen ters yorumlarsın. Bugün bu hayati mekanizmaları inceleyeceğiz!"

---

## 2. systemd-journald Anatomisi ve Günlük Dizinleri

Geleneksel Linux sistemlerinde loglar `/var/log/` altında düz metin olarak birikirken, modern systemd tabanlı sistemlerde `systemd-journald` servisi merkezi bir toplayıcı olarak çalışır.

```
+-------------------------------------------------------------------+
|               GÜNLÜK TOPLAMA VE DEPOLAMA HİYERARŞİSİ              |
+---------------------------------+---------------------------------+
| /var/log/journal/<machine-id>/  | KALICI (PERSISTENT) DEPOLAMA    |
| - system.journal                | Diske yazılır; sistem yeniden   |
| - user-1000.journal             | başlasa dahi adli kayıtlar kalır|
+---------------------------------+---------------------------------+
| /run/log/journal/<machine-id>/  | GEÇİCİ (VOLATILE) DEPOLAMA      |
| - system.journal (RAM tmpfs)    | Yalnızca bellekte tutulur!      |
|                                 | Yeniden başlatmada SİLİNİR!     |
+---------------------------------+---------------------------------+
| /var/log/auth.log / secure      | Kimlik doğrulama & sudo logları |
+---------------------------------+---------------------------------+
| /var/log/syslog / messages      | Genel sistem ve çekirdek logları|
+---------------------------------+---------------------------------+
```

### Temel Yapılandırma Dosyası: `/etc/systemd/journald.conf`
Bu dosya günlüğün nasıl saklanacağını ve sınırlarını belirler:
- `Storage=persistent`: Günlüklerin `/var/log/journal/` dizininde kalıcı olarak saklanmasını garanti eder.
- `Storage=volatile`: Günlükleri yalnızca RAM üzerinde (`/run/log/journal/`) tutar. (Yüksek risk!)
- `Compress=yes`: Log dosyalarını zstd/lz4 ile sıkıştırır.
- `Seal=yes`: Kriptografik FSS anahtarıyla günlük bloklarını mühürler; geçmişe dönük tahrifatı imkansız kılar.
- `SystemMaxUse=4G`: Günlüklerin diski doldurarak DoS oluşturmasını engeller.

---

## 3. Kalıcılık ve Geçicilik Riski (G030-SC1 & G030-SC3)

> **Mavi Takım İlkesi (G030-SC1):**  
> *"Geçici bellekte tutulan günlükler, saldırganın ilk yeniden başlatmasında (reboot) silinir. Bu durum CWE-778 (Insufficient Logging) zaafiyetidir."*

Bir olay müdahalesi (DFIR) uzmanı bir sunucuyu incelerken ilk olarak `/var/log/journal` dizininin varlığını ve `journald.conf` içindeki `Storage` parametresini kontrol etmelidir. Eğer sistem geçici depolamadaysa:
1. Saldırgan sisteme sızar.
2. Yetkisiz servis kurar veya verileri sızdırır.
3. `reboot` komutu vererek çekirdeği yeniden başlatır.
4. Bellekteki tüm journal kayıtları silinir ve analist hiçbir adli kanıt bulamaz.

Bu risk, laboratuvarımızda `VOLATILE_STORAGE_RISK` negatif kontrolü ile modellenmiş ve motor tarafından engellenmesi sağlanmıştır.

---

## 4. Zaman Dilimi ve Çoklu Sunucu Olay Korelasyonu (G030-SC1)

Adli araştırmalarda en büyük tuzaklardan biri **Yerel Saat Dilimi (Timezone Discrepancy)** farkıdır:
- Sunucu A (İstanbul): `+03:00` saat dilimindedir.
- Sunucu B (Londra): `+00:00` (UTC) saat dilimindedir.
- Sunucu C (New York): `-05:00` (EST) saat dilimindedir.

Eğer her sunucunun logu yerel saatle incelenirse, İstanbul'daki `11:15` olayı Londra'daki `08:15` olayından 3 saat sonra gerçekleşmiş gibi algılanır. Oysa ikisi **aynı anda** meydana gelmiştir!

```
[Sunucu A (Yerel Saat)]: 2026-10-27T11:15:30+03:00  (İstanbul)
[Sunucu B (Yerel Saat)]: 2026-10-27T08:15:30+00:00  (UTC / Londra)
                         ||
             [UTC NORMALİZASYONU GEREKLİ]
                         ||
[Sunucu A (UTC)]: 2026-10-27T08:15:30Z  ==> AYNI SANİYE!
[Sunucu B (UTC)]: 2026-10-27T08:15:30Z  ==> Olaylar Tam Eşzamanlı!
```

Bu sebeple adli soruşturmalarda daima:
```bash
journalctl --utc
```
komutu kullanılarak çıktılar küresel UTC standardına zorlanmalıdır.

---

## 5. journalctl ile Pratik Adli Filtreleme (G030-SC2)

`journalctl`, güçlü filtreleme yetenekleriyle adli araştırmayı hızlandırır:

```bash
# 1. Yalnızca belirli bir servisin (sshd) loglarını çekme:
journalctl -u sshd.service

# 2. Öncelik seviyesine göre filtreleme (Hata, Kritik, Acil):
journalctl -p err..emerg

# 3. UTC zaman penceresi belirleme:
journalctl --utc --since "2026-10-27 08:00:00" --until "2026-10-27 09:00:00"

# 4. Yalnızca mevcut önyükleme (boot) oturumunu dökme:
journalctl -b 0

# 5. Programatik analiz için JSON formatında dışa aktarma:
journalctl -u sshd.service -o json
```

---

## 6. Geliştirilen Denetim Aracının Satır Satır Analizi

Geliştirdiğimiz `linux_journalctl_log_auditor.py` aracı şu bileşenlere sahiptir:
- **`LinuxJournalValidator`:** Syslog öncelik seviyesini (0-7), ISO 8601 tarih formatını ve `storage_location` kalıcılığını denetler. Geçici bellek kayıtlarını `VOLATILE_STORAGE_RISK` ile tespit eder.
- **`LinuxJournalctlAuditor`:**
  - `load_journald_conf()`: `/etc/systemd/journald.conf` dosyasını ayrıştırıp Storage modunu doğrular.
  - `filter_entries()`: Birim (unit), öncelik (priority) ve metin desenine göre filtreleme yapar (G030-SC2).
  - `generate_audit_report()`: UTC ve Yerel Saat bilgilerini yan yana koyarak zaman korelasyonunu ortaya koyar.
  - `SHA-256 Mühürleme`: Her log kaydı için adli bütünlük özeti çıkarır.

---

## 7. Çırağa Tavsiyeler, Mavi Takım Kontrolleri ve Gelecek Güne Köprü

1. **Storage=persistent Şarttır:** Yeni kurulan her Linux sunucusunda `/etc/systemd/journald.conf` dosyasını açıp `Storage=persistent` yap ve `systemctl restart systemd-journald` çalıştır.
2. **NTP Senkronizasyonunu Doğrula:** `timedatectl status` ile sistem saatinin `NTP service: active` olduğunu doğrula. Saat kayması log korelasyonunu imkansız kılar.
3. **Gelecek Güne Köprü (Gün 031):** Yarın, logların yalnızca yerel makinede kalmayıp ağ üzerinden merkezi log sunucusuna nasıl aktarıldığını gösteren **Syslog ve rsyslog protokolleri ile uzaktan log iletimini** inceleyeceğiz!
