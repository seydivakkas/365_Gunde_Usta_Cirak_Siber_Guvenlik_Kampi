# GÜN 091: Mini Proje 12 — Çok Platformlu Sistem Raporu — Usta-Çırak Siber Güvenlik Dersi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz çoğaltılamaz, dağıtılamaz veya ticari projelerde kullanılamaz.*

---

## 1. Ustanın Giriş Dersi: Hafta 13'ün Büyük Sentezi — "Tek Bir Platformu Bilen, Hiçbir Platformu Bilmez"

Evlat, Hafta 13 boyunca seninle muazzam bir yolculuk yaptık:
1. **Gün 086:** PowerShell betik parametrelerini, `[CmdletBinding()]` yapısını ve komut enjeksiyonu kalkanlarını inceledik.
2. **Gün 087:** Bash betik iskeletini, katı mod `set -euo pipefail` kurallarını ve quoting (tırnaklama) prensiplerini ele aldık.
3. **Gün 088:** Komut çıkış kodlarını (Exit Codes 0, 1, 2) ve stderr üzerinden kimlik bilgisi sızmasını (CWE-209/532) önlemeyi öğrendik.
4. **Gün 089:** Python `argparse` ile POSIX uyumlu, alt komutlu ve karşılıklı dışlayan seçeneklere sahip kurumsal CLI mimarisini tasarladık.
5. **Gün 090:** Adli bilişimde zamanın kalbini oluşturan UTC standardını, Unix Epoch ve 64-bit Windows FileTime dönüşümlerini ve saat sapmasını (Clock Skew) inceledik.

Bugün, yani **Hafta 13'ün Bitirme Projesinde (Capstone)**, öğrendiğin bu 5 temel taşı bir araya getirerek gerçek dünyada çalışan, kurumsal düzeyde **Çok Platformlu (Heterojen) Bir Sistem Güvenlik ve Uyum Raporlayıcısı** inşa edeceksin.

Gerçek dünyada hiçbir büyük kurumsal altyapı yalnızca Windows veya yalnızca Linux'tan ibaret değildir. Active Directory etki alanında Windows sunucular çalışırken, mikroservisler ve veritabanları Linux konteynerlerinde barınır. Bir güvenlik mühendisi her iki dünyayı da anadili gibi konuşabilmeli, her iki taraftan telemetri toplayıp tek bir potada eritebilmelidir.

---

## 2. Çok Platformlu Güvenlik Denetim Mimarisi

Geliştirdiğimiz mimari üç katmandan oluşur:

### A. Yerel Veri Toplayıcılar (Native Telemetry Collectors):
- **Windows:** PowerShell tabanlı `windows_collector.ps1` betiği WMI/CIM, `Get-NetTCPConnection` ve `Get-NetFirewallProfile` kullanarak sistem durumunu doğrudan `[PSCustomObject]` JSON olarak derler.
- **Linux:** POSIX Bash tabanlı `linux_collector.sh` betiği katı modda (`set -euo pipefail`, safe IFS) `/proc`, `/etc/shadow`, `systemctl` ve dinleme portlarını okur.

### B. Çekirdek Güvenlik ve Normalizasyon Motoru (`CrossPlatformSecurityReporter`):
- **Zaman Standardizasyonu:** Gelen tüm telemetrilerin zaman damgaları ISO-8601 UTC Zulu standardında doğrulanır; naive zaman damgaları reddedilir (CWE-613).
- **Bilgi Sızıntısı Kalkanı (CWE-532):** Betiklerin stderr veya log akışında açık parola, API anahtarı veya veritabanı bağlantı dizesi tespit edilirse sistem alarm verir.
- **DoS ve Bellek Koruması (CWE-400):** 1 MB üzerindeki şişirilmiş telemetri paketleri kapıda reddedilir.
- **Dizin Atlama Engeli (CWE-22):** Raporların kaydedileceği dosya yollarında `..` dizin atlama karakterleri engellenir.

### C. Zafiyet Analiz ve Puanlama Kuralları:
Sistem bulunan zafiyetlerin önem derecesine göre ceza puanı keserek 100 üzerinden bir güvenlik skoru üretir:
- **Port 445 (SMB):** Dışarıya veya geniş ağa açıksa (-15 Puan | Ransomware / Lateral Movement riski).
- **Port 3389 (RDP):** Ağda korunmasız dinlemedeyse (-10 Puan | Brute-force riski).
- **Port 6379 (Redis):** Dış dünyaya açıksa (-15 Puan | Kimlik doğrulamasız RCE riski).
- **Windows Güvenlik Duvarı:** PublicProfile kapalıysa (-20 Puan | CWE-276).
- **Windows Kripto Madenci / Zararlı Servis:** Şüpheli servis (-35 Puan | CWE-506).
- **Linux `/etc/shadow` İzinleri:** 0644 veya world-readable ise (-40 Puan | CWE-732 Kritik).
- **Linux Sudoers NOPASSWD:** Parolasız root yetkisi verilmişse (-20 Puan | CWE-250).

---

## 3. Komut Satırı Arayüzü (CLI) ve POSIX Çıkış Kodları

Geliştirdiğimiz `reporter_cli.py` komut satırı aracı GNU/POSIX standartlarına tam uyum sağlar:
- `0`: Raporlama ve telemetri analizi başarıyla tamamlandı.
- `1`: Dosya bulunamadı veya çalışma zamanı giriş/çıkış hatası.
- `2`: Geçersiz parametre, karşılıklı dışlayan seçenek ihlali (`--fast` ve `--deep` bir arada) veya güvenlik kuralı ihlali (Path Traversal vb.).

Örnek Kullanım:
```bash
# Windows telemetrisi hızlı tarama ve yapısal konsol çıktısı
python reporter_cli.py --telemetry-file sample_windows_telemetry.json --fast

# Linux telemetrisi derinlemesine tarama ve JSON formatında SIEM çıktısı
python reporter_cli.py --telemetry-file sample_linux_telemetry.json --deep --format json
```

---

## 4. Çırağa Öğütler ve Hafta 13 Kapanış Mesajı

Evlat, bu projeyle birlikte sadece tekil betikler yazan bir kodlayıcı olmaktan çıktın; altyapıları uçtan uca denetleyen, farklı işletim sistemlerini konuşturan ve kurumsal standartlara sadık bir güvenlik mühendisi olma yolunda dev bir adım attın.

Unutma:
1. **Asla Platform Fanatizmi Yapma:** Bir güvenlik mühendisi için Windows da Linux da sadece birer operasyon alanıdır. Her ikisinin de zafiyet vektörlerini ve mimari yapılarını bilmek zorundasın.
2. **Güvenlik Çıktılarını Standartlaştır:** SIEM ve SOAR platformları JSON ve yapısal loglarla beslenir. Yazdığın aracın `--format json` seçeneği, onu binlerce sunuculuk bir kurumsal orkestrasyonun parçası haline getiren anahtardır.
3. **Girdiyi Her Seviyede Doğrula:** Bir betikten diğerine veri aktarırken "nasıl olsa benim betiğim üretti" diyerek doğrulamayı atlama. Savunma derinliği (Defense-in-Depth) ilkesi bunu emreder.
