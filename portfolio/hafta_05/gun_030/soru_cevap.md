# Hafta 05 — Gün 030: Soru & Cevap ve Senaryo Analizleri

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## Senaryo 1 (G030-SC1): Linux journalctl ve Günlük Dizinleri Temel Mekanizması ve Güvenlik Önemi

### Senaryo Analizi ve Kapsam
Linux işletim sistemlerinde `systemd-journald` servisi, çekirdek mesajlarından (`/dev/kmsg`) kullanıcı süreçlerine ve systemd servislerine kadar tüm sistem olaylarını toplayan merkezi günlük motorudur. Ancak journal kayıtlarının güvenliği ve adli geçerliliği doğrudan iki temel faktöre bağlıdır: Depolamanın kalıcı (persistent) olup olmadığı ve saat dilimi (timezone) yönetimi. Bu senaryonun kapsamı; kalıcı ve geçici depolama arasındaki farkları, saat dilimi uyuşmazlığının adli korelasyonu nasıl bozduğunu ve `journalctl` aracının güvenlik mimarisindeki rolünü açıklamaktır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Kalıcı (Persistent) vs Geçici (Volatile) Depolama:**
   - `/run/log/journal/`: Günlükler RAM tabanlı geçici dosya sisteminde tutulur (`Storage=volatile`). Sunucu yeniden başlatıldığında (`reboot`) tüm günlükler kaybolur (CWE-778 Yetersiz Günlükleme zaafiyeti).
   - `/var/log/journal/`: Günlükler kalıcı disk alanında tutulur (`Storage=persistent`). Sistem çökmesi veya yeniden başlatma sonrasında olaylar korunur.
2. **Saat Dilimi (Timezone) ve Olay Korelasyonu:**
   - Farklı coğrafi bölgelerdeki veya farklı saat dilimlerine (`+03:00`, `+00:00`, `-05:00`) ayarlanmış sunucuların logları incelenirken yerel saatler yanıltıcıdır.
   - İki ayrı sunucuda aynı anda meydana gelen bir olay, yerel saat farkı nedeniyle kronolojik olarak saatler sonra gerçekleşmiş gibi algılanabilir. Bu sebeple adli analizde zorunlu olarak `journalctl --utc` ile UTC zaman standardı kullanılmalıdır.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Adli Denetim ve Zaman Dilimi Korelasyonu:**
  ```bash
  python portfolio/hafta_05/gun_030/uygulama/linux_journalctl_log_auditor.py --logs portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json --conf portfolio/hafta_05/gun_030/ornek_veri/sample_journald_conf_baseline.ini --audit
  ```
- **Kanıt Dosyası:** `kanit/gercek/komut_ve_cikis.txt` dosyasında doğrulanmıştır. Her kayıt için UTC zamanı (`time_utc`) ve yerel saat (`time_local`) karşılaştırmalı olarak listelenmiş, `Storage=persistent` yapılandırması teyit edilmiştir.
- **Birim Test:** `test_12_timezone_correlation_utc_and_local` ile UTC ve yerel saat ofsetlerinin doğruluğu sınanmıştır.

### Savunma Kontrolleri ve Alınacak Dersler
- `/etc/systemd/journald.conf` dosyasında `Storage=persistent` açıkça tanımlanmalı, sistemin geçici belleğe düşmesi önlenmelidir.
- Tüm kurumsal sunucularda NTP (Network Time Protocol) veya `chrony` ile saat senkronizasyonu zorunlu tutulmalıdır.

---

## Senaryo 2 (G030-SC2): Bağımsız Laboratuvar Doğrulaması: Günlük Filtreleme, Saat Bilgisi ve Negatif Kontrol

### Senaryo Analizi ve Kapsam
Bu senaryoda bağımsız bir laboratuvar deneyi kurgulanmıştır: Kontrollü bir girdi olarak bir test sunucusunun journal çıktısını temsil eden `sample_journal_logs.json` dosyası alınmış; sistem günlüğü üzerinde belirli bir birim (`sshd.service`) filtrelenmiş ve UTC/Yerel saat bilgileri not edilmiştir. Ardından negatif kontrol amacıyla eksik mesaj, geçersiz öncelik seviyesi ve geçici bellek (`/run/log/journal`) kullanan 4 adet bozuk kayıt (`corrupted_journal_test.json`) sisteme verilmiş ve motorun bu girdileri adli olarak reddettiği doğrulanmıştır.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Filtreleme İşlemi (Filtering):**
   - Güvenlik analistleri milyonlarca log satırı arasından belirli bir servisin (`-u sshd.service`) veya önceliğin (`-p err`) kayıtlarını hızla ayıklamalıdır.
   - Laboratuvarda `sshd.service` filtresi uygulanmış; başarılı anahtar kabulü (`Accepted publickey`) ve yetkisiz kaba kuvvet denemesi (`Failed password for invalid user admin`) izole edilmiştir.
2. **Saat Bilgisinin Not Edilmesi:**
   - Olay 1 (SSH Başarılı Giriş): UTC `2026-10-27T08:15:35Z` | Yerel `2026-10-27T11:15:35+03:00`.
   - Olay 2 (SSH Başarısız Giriş): UTC `2026-10-27T08:15:42Z` | Yerel `2026-10-27T11:15:42+03:00`.
3. **Negatif Kontrol Doğrulaması:**
   - Boş mesaj -> `MISSING_MESSAGE`
   - Geçersiz öncelik (99) -> `INVALID_PRIORITY_LEVEL`
   - Bozuk zaman damgası -> `MALFORMED_TIMESTAMP`
   - Geçici bellek kullanımı -> `VOLATILE_STORAGE_RISK`

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
1. **Birim Filtreleme ve Saat İncelemesi:**
   `python linux_journalctl_log_auditor.py --logs sample_journal_logs.json --conf sample_journald_conf_baseline.ini --unit sshd --audit`
   *(Çıktı: `sshd birimine ait 2 olay filtrelendi, UTC ve yerel saatleri kaydedildi.`)*
2. **Negatif Kontrol Testi:**
   `python linux_journalctl_log_auditor.py --test-corrupted corrupted_journal_test.json`
   *(Çıktı: `Toplam Test Edilen Hatalı Kayıt: 4, Başarıyla Reddedilen: 4, Sonuç: TAM BAŞARILI (PASS).`)*
- **Kanıt Dosyaları:**
  - `kanit/gercek/journal_filtreleme_ve_zaman_kaydi.txt` (sshd filtreleme ve saat dökümü).
  - `kanit/gercek/negatif_kontrol_sonuclari.txt` (Bozuk kayıtların reddedilme izi).
  - `kanit/gercek/test_sonuclari.txt` (14/14 birim test PASS).

### Savunma Kontrolleri ve Alınacak Dersler
- Log filtreleme kuralları oluşturulurken `journalctl`'in regex ve birim filtrelerinden yararlanılmalı, gereksiz log kalabalığı ayıklanmalıdır.
- Adli raporlarda ham zaman damgası ve dönüştürülmüş UTC zamanı birlikte yer almalıdır.

---

## Senaryo 3 (G030-SC3): Risk Oluşumu, Tespiti ve Önleyici Savunma Kontrolleri

### Senaryo Analizi ve Kapsam
Linux journalctl ve günlük dizinleri bağlamında güvenlik riskleri; günlüklerin geçici bellekte tutulması (volatile storage), yetkisiz kullanıcıların `systemd-journal` grubuna eklenerek tüm sistem loglarını okuması (Information Disclosure), log alanının sınırlandırılmaması nedeniyle diskin dolması (Log Flooding DoS) ve FSS mühürleme eksikliği ile logların tahrif edilmesi sonucu ortaya çıkar. Bu senaryo, bu risklerin oluşumunu, fark analizini ve alınacak önleyici kontrolleri ortaya koyar.

### Teknik Açıklama ve Güvenlik Mekanizması
1. **Risk Nasıl Oluşur?**
   - **Yetkisiz Erişim (CWE-284):** Bir kullanıcının `/var/log/journal/` dosyalarını okuyabilmesi için `systemd-journal` veya `adm` grubuna dahil olması gerekir. Sıradan kullanıcılara bu grubun verilmesi, parola veya API sızıntılarını okuyabilmelerine yol açar.
   - **Log Flooding DoS (CWE-400):** Kötü niyetli bir süreç saniyede binlerce sahte log üreterek disk alanını tüketebilir.
   - **Tahrifat Riski:** FSS (Forward Secure Sealing) mühürlemesi kapalıysa (`Seal=no`), root yetkisini ele geçiren saldırgan geçmişe dönük ikili journal dosyalarını manipüle edebilir.
2. **Nasıl Tespit Edilir?**
   - **Fark Raporu ve Yapılandırma Denetimi:** `journald.conf` dosyası taranarak `Storage`, `SystemMaxUse`, `RateLimitBurst` ve `Seal` parametreleri kontrol edilir.
   - Geliştirilen `linux_journalctl_log_auditor.py` aracı, yapılandırma ve günlük dosyalarını denetleyerek ihlalleri anında raporlar.
3. **Hangi Kontrollerle Önlenir?**
   - **En Az Ayrıcalık (Least Privilege):** `systemd-journal` grubuna yalnızca yetkili sistem denetçileri eklenmelidir.
   - **Kalıcı Depolama ve Kota Sınırları:** `Storage=persistent`, `SystemMaxUse=4G`, `SystemKeepFree=1G` ayarları yapılmalıdır.
   - **Hız Sınırlaması (Rate Limiting):** `RateLimitIntervalSec=30s` ve `RateLimitBurst=10000` ile log taşması saldırıları engellenmelidir.
   - **Uzaktan İletim (systemd-journal-remote):** Loglar ağ üzerinden merkezi bir SIEM havuzuna şifreli TLS ile aktarılmalıdır.

### Komutlar, Kanıtlar ve Laboratuvar Doğrulaması
- **Yapılandırma Denetimi:** `sample_journald_conf_baseline.ini` dosyasında `Storage=persistent` ve `Seal=yes` parametrelerinin varlığı teyit edilmiştir (`test_08`).
- **Geçici Depolama Alarmı:** `/run/log/journal` kullanan girdiler motor tarafından `VOLATILE_STORAGE_RISK` koduyla reddedilmiştir (`test_05`).

### Savunma Kontrolleri ve Alınacak Dersler
- Bir Linux sunucusunun adli güvenliği, `journald.conf` dosyasının doğru sertleştirilmesine doğrudan bağlıdır.
- Log dosyaları yerel diskle sınırlı tutulmamalı; merkezi log sunucusuna yedeklenmelidir.
