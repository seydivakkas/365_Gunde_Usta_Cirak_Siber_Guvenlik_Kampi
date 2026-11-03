# Hafta 04 — Gün 028: Mini Proje 3 — Komut Satırı Çalışma Defteri (Runbook Engine)

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, dağıtılamaz, ticari olarak kullanılamaz.*

---

## 1. Giriş ve Felsefi Temel

### Usta ile Çırak Arasında Bir Hafta Sonu Sohbeti
*Çırak:* "Ustam, geride bıraktığımız haftada PowerShell'den Bash'e, Linux izinlerinden (rwx) ortam değişkenlerine ve paket yöneticilerine kadar işletim sisteminin kalbine indik. Fakat sahada bir olaya müdahale ederken (DFIR) veya bir sunucuyu güvenlik denetiminden geçirirken onlarca komut yazıyoruz. Bazen hangi komutun ne çıktı verdiğini, ne zaman çalıştırıldığını ve o çıktının sonradan değiştirilip değiştirilmediğini kanıtlamak çok güç oluyor. Bir analist bu süreci nasıl profesyonelce yönetmelidir?"

*Usta:* "Evlat, adli bilişim ve siber güvenlik denetiminin altın kuralı şudur: **'Belgelenmemiş ve yeniden üretilemeyen bir gözlem, mahkemede de denetimde de yok hükmündedir.'** Bir sisteme bağlandığında ilk yapacağın şey kontrolsüzce komut yazmak değil, ayak izini en aza indiren **salt-okunur (read-only)** bir keşif yürütmektir."

"Düşün ki bir sistem yöneticisi veya güvenlik mühendisi sunucuda sorun ararken yanlışlıkla sistemi çökertecek veya veriyi bozacak bir komut çalıştırdı (`rm -rf` veya yetkisiz servis sonlandırma). Bu durum müdahaleyi bir felakete çevirir. İşte bu yüzden biz bugün 4. Haftanın tacı olan **Mini Proje 3'ü** inşa ediyoruz: Yıkıcı komutları güvenlik kapısında filtreleyen, yalnızca izin verilen salt-okunur komutları çalıştıran, her bir çıktıyı kriptografik SHA-256 özetiyle mühürleyen ve denetlenebilir bir **Markdown Çalışma Defteri (Runbook)** üreten otonom motoru kodlayacağız!"

---

## 2. Salt-Okunur Komut Güvenliği ve Komut Enjeksiyonu Tehditleri

Siber güvenlikte keşif (reconnaissance) ve denetim (auditing) aşaması, MITRE ATT&CK matrisinde **Discovery (Taktik TA0007)** altında sınıflandırılır. Bu aşamada temel hedef sistemin durumunu değiştirmeden envanter çıkarmaktır.

```
+-----------------------------------------------------------------------+
|                 GÜVENLİ DENETİM AKIŞI (READ-ONLY)                    |
|  - Durum Değişikliği (State Mutation) YOK!                            |
|  - Dosya Yazma / Silme YOK!                                          |
|  - Çekirdek Parametrelerine Müdahale YOK!                            |
|  - Yalnızca Bilgi Toplama ve Kriptografik Kayıt VAR!                  |
+-----------------------------------------------------------------------+
```

### Karşılaşılan Temel Tehdit Standartları:
1. **CWE-78 (OS Command Injection):** Kullanıcı veya analist girdilerinin filtrelenmeden doğrudan `shell=True` ile kabuğa aktarılması durumunda araya zararlı komutların enjekte edilmesi.
2. **CWE-250 (Execution with Unnecessary Privileges):** Salt-okunur basit bir keşif komutunun (örn: `hostname`) gereksiz yere `root/SYSTEM` yetkileriyle ve yıkıcı parametrelerle koşturulması.
3. **CWE-494 (Download of Code Without Integrity Check):** `curl ... | bash` gibi harici kaynaklardan doğrulanmamış kodların doğrudan belleğe veya kabuğa aktarılması.
4. **CWE-276 (Incorrect Default Permissions):** Geçici dizinlerde (`/tmp`) izinlerin yanlış yapılandırılması sonucu yerel kullanıcıların komut çıktılarını tahrif edebilmesi.

---

## 3. İşletim Sistemi Gözlem Defteri (Runbook) Anatomisi

Profesyonel bir güvenlik çalışma defteri (Security Runbook / Notebook) şu temel bileşenlerden oluşmalıdır:

1. **Yürütme Üstverileri (Metadata):** Tarih/saat damgası (ISO 8601 UTC), yürütme ortamı (Canlı/Mock), toplam komut sayısı, başarılı/başarısız çıkış kodları.
2. **Komut İndeksi:** Her komutun benzersiz kimliği (`CMD-01`), kategorisi, MITRE ATT&CK tekniği ve ilk 8 karakterlik kriptografik hash'i.
3. **Ayrıntılı Gözlem Kartları:**
   - Komut sözdizimi ve hedef platform.
   - Güvenlik gerekçesi ve tehdit modeli.
   - Ham terminal çıktısı (`stdout` / `stderr`).
   - Düzenli ifade (RegEx) desen eşleşme doğrulaması.
   - **Kriptografik Bütünlük Damgası (SHA-256):** `hashlib.sha256(f"{id}:{cmd}:{output}:{time}".encode())`. Bu sayede defterdeki çıktının sonradan manipüle edilmediği matematiksel olarak ispatlanır.
4. **Negatif Kontrol ve Engelleme Günlüğü:** Filtreye takılan yıkıcı komut denemelerinin engellendiğini kanıtlayan adli kayıt.

---

## 4. En Az 10 Kritik Keşif Komutunun Didaktik Analizi

Mini projemizde kurumsal standart gereği en az 10 (projemizde 12) salt-okunur komut incelenmiştir:

| Komut | Kategori | MITRE ATT&CK | Güvenlik Önemi ve Sistem Karşılığı |
| :--- | :--- | :--- | :--- |
| `whoami` | Kimlik | T1033 | Oturumu açan kullanıcının adını verir; beklenmedik yetki durumunu açığa çıkarır. |
| `id` | Kimlik | T1033 | UID, GID ve ikincil grup üyeliklerini döker; `sudo` yetkilerini doğrular. |
| `hostname` | Sistem | T1082 | Makinenin etki alanı (domain) rolünü ve ağ adını gösterir. |
| `uname -a` | Sistem | T1082 | Çekirdek sürümünü (kernel) listeler; çekirdek zafiyetleri (Dirty Pipe vb.) için şarttır. |
| `uptime` | Sistem | T1082 | Sistemin ne kadar süredir açık olduğunu ve CPU yük ortalamasını sunar. |
| `ps aux` | Süreç | T1057 | Çalışan tüm süreçleri, PID'leri ve komut satırı argümanlarını döker; ters kabukları yakalar. |
| `df -h` | Depolama | T1083 | Disk bağlama noktalarını ve doluluk oranlarını gösterir; log şişirme DoS'unu tespit eder. |
| `free -m` | Bellek | T1499 | RAM ve Swap tüketimini verir; bellek sızıntılarını ve tükenme risklerini gösterir. |
| `ss -tulpn` | Ağ | T1049 | Dinleyen TCP/UDP soketlerini ve portları döker; yetkisiz arka kapı portlarını açığa çıkarır. |
| `ip addr` | Ağ | T1016 | Ağ arayüzlerini ve IP adreslerini listeler; gizli VPN/tünel adaptörlerini tespit eder. |
| `env` | Ortam | T1082 | Tanımlı ortam değişkenlerini dökümler; açık metin parola ve PATH sızıntılarını yakalar. |
| `ls -ld /tmp`| Dosya | T1083 | `/tmp` dizin izinlerini ve sticky bit (`t`) durumunu kontrol eder. |

---

## 5. Güvenlik Duvarı ve Negatif Kontrol Mimarisi

*Usta der ki:* "Bir güvenlik aracını güçlü kılan, sadece doğru komutları çalıştırması değil; yanlış ve yıkıcı bir komut geldiğinde onu **anında durdurabilmesidir**."

Motorumuz iki aşamalı bir güvenlik kapısı (`CommandSafetyValidator`) içerir:
1. **Yıkıcı Desen Taraması (Blacklist Regex):** `rm -rf`, `del /f /s /q`, `mkfs`, `dd`, `kill -9 1`, `chmod 777`, `useradd` ve borulama (`| bash`) desenlerini tespit eder.
2. **Kök Komut Beyaz Listesi (Whitelist):** Komutun ilk kelimesi (binary adı), önceden onaylanmış 16 güvenli salt-okunur araçtan biri olmak zorundadır. Aksi takdirde işlem engellenir ve `SecurityPolicyViolationError` fırlatılır.

---

## 6. Geliştirilen Defter Motorunun Satır Satır Analizi

`command_line_notebook_engine.py` modülü şu nesnel tasarım üzerine kuruludur:
- **`SecurityPolicyViolationError`:** İhlal anında komut ve risk türünü taşıyan yapılandırılmış hata sınıfı.
- **`CommandSafetyValidator`:** Bağımsız, statik ve test edilebilir komut süzgeci.
- **`CommandLineNotebookEngine`:**
  - `load_catalog()`: JSON kataloğunu belleğe alır.
  - `execute_command_entry()`: Komutu doğrular, canlı veya deterministik mock modunda çalıştırır, SHA-256 özetini çıkarır.
  - `generate_markdown_notebook()`: 380 satırlık eksiksiz, profesyonel Markdown runbook üretir.
  - `test_prohibited_commands_pipeline()`: 8 tehlikeli senaryoyu negatif kontrol olarak sınar.

---

## 7. Çırağa Tavsiyeler, Haftalık Kapanış ve Gelecek Güne Köprü

1. **Hafta 04 Kazanımları:** İşletim sisteminin iç mekanizmalarını (PowerShell, Bash, Dosya İzinleri, Kullanıcılar, PATH, Paket Yöneticileri ve Komut Satırı Defteri) başarıyla tamamladın.
2. **Savunmacı Disiplini:** Hangi komutu yazarsan yaz, önce çıktısının ne getireceğini ve sistemde kalıcı bir hasar bırakıp bırakmayacağını hesapla.
3. **Aşama 02 Hafta 05'e Köprü (Gün 029):** Yarın yepyeni bir haftaya başlıyoruz: **Ağ Güvenliği Temelleri!** OSI modeli, TCP/IP yığını, IP paket başlıkları ve Wireshark ile paket analizi dünyasına adım atacağız. Hazır ol çırak, ağın derinlikleri bizi bekliyor!
