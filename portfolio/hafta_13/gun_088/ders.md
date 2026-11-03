# G088: Komut Çıkış Kodları, Standart Hata (stderr) ve Güvenli Hata Yönetimi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## Ustanın Giriş Dersi: Başarı Sessizdir, Hatalar Konuşur

Evlat, siber güvenlikte ve sistem mühendisliğinde acemi ile ustayı ayıran en keskin çizgi, hatalara nasıl yaklaşıldığıdır. Acemi bir betik yazarı yalnızca "kodun çalıştığı" mutlu senaryoya (happy path) odaklanır. Bir komut hata verdiğinde ekranda çıkan kırmızı yazılardan rahatsız olur ve hemen şu ilkel refleksi gösterir:
```bash
komut 2> /dev/null
```
İşte bu satır, bir güvenlik operasyonunda (SOC) kör uçuş başlatmaktır! Saldırgan arka planda kimlik doğrulamayı kırmış, yetkisiz dosyalara erişmeye çalışmış veya bellek taşması tetiklemiş olabilir; fakat sen `2> /dev/null` diyerek işletim sisteminin sana attığı imdat çığlığını çöpe atmışsındır. Bu ölümcül zafiyetin adı literatürde **CWE-390: Detection of Error Condition Without Action (Sessiz Hata Yutma)** olarak geçer.

Bir de madalyonun diğer yüzü vardır: Hata mesajlarında aşırı geveze olmak!
```bash
echo "Veritabanı bağlantısı koptu. Parola: $DB_PASSWORD" >&2
```
Bu kez de hata akışına açık metin parola veya API anahtarı basılmıştır (**CWE-209 / CWE-532**). Saldırgan veya yetkisiz bir kullanıcı yalnızca stderr loglarını okuyarak tüm sistemi ele geçirebilir.

Usta der ki: **"Bir sürecin çıkış kodu onun adli sicilidir, stderr ise olay yeri incelemesidir. Çıkış kodunu yok sayan sistemini kör eder, stderr'e parola yazan anahtarı hırsıza verir."**

---

## 1. POSIX ve Windows Çıkış Kodları (Exit Codes) Anatomisi

Her işletim sistemi süreci (process) sonlandığında kendisini başlatan ebeveyn sürece (parent process) 1 baytlık (0-255 arası) bir sayı fırlatır:

| Çıkış Kodu | Standart Anlamı | Güvenlik / Teşhis Değeri |
| :---: | :--- | :--- |
| **0** | **Başarı (Success)** | İşlem hatasız ve kurallara uygun tamamlandı. |
| **1** | **Genel Hata (General Error)** | Sıradan mantık hatası veya yakalanan genel istisna. |
| **2** | **Kabuk Dahili Hata (Shell Misuse)** | Sözdizimi hatası veya yanlış dahili komut kullanımı. |
| **126** | **Çalıştırma İzni Yok (Permission Denied)** | Hedef ikili dosya mevcut ama yürütme biti (`+x`) eksik. Yetki aşımı veya izin ihlali göstergesi. |
| **127** | **Komut Bulunamadı (Command Not Found)** | Komut `PATH` üzerinde yok. PATH Manipülasyonu (PATH Hijacking) veya eksik bağımlılık. |
| **128+N** | **Ölümcül Sinyal (Fatal Signal N)** | Süreç harici bir işletim sistemi sinyali ile zorla öldürüldü. |
| **130** | `128 + 2 (SIGINT)` | Kullanıcı klavyeden `Ctrl+C` ile süreci kesti. |
| **137** | `128 + 9 (SIGKILL)` | Süreç `kill -9` veya Linux OOM (Out-of-Memory) Killer tarafından katledildi. DoS belirtisi! |
| **143** | `128 + 15 (SIGTERM)` | Standart sonlandırma isteği ile kapatıldı. |

---

## 2. Dosya Tanımlayıcıları: stdout (1) vs stderr (2)

Unix/Linux ve Windows mimarisinde süreçler dış dünyaya 3 standart kanal üzerinden bağlanır:
- **0 (stdin):** Standart Girdi
- **1 (stdout):** Standart Çıktı (İşin asıl sonucu, JSON, boru hattı verisi)
- **2 (stderr):** Standart Hata (Tanı, log, uyarı, istisna dökümü)

### Neden İki Ayrı Kanal Vardır?
Çünkü boru hattında (`pipe |`) veri akışı ile arıza teşhisinin birbirine karışmaması gerekir:
```bash
veri_uret | filtrele > sonuc.json
```
Eğer `veri_uret` hata mesajını da `stdout` kanalına bassaydı, `filtrele` komutu ve JSON ayrıştırıcı çökerdi. Hatalar daima `stderr` (2) kanalına aktarılmalı, ekranda görünmeli veya izole bir log dosyasına (`2> error.log`) yazılmalıdır.

---

## 3. Boru Hattında Hata Gizleme ve `PIPESTATUS`

Bash kabuğunda acemilerin düştüğü en büyük tuzak boru hattı başarısızlıklarıdır:
```bash
cat /non_existent_file | grep "admin"
echo $? # Çıktı: 1 (cat çöktü ama grep aradığını bulamadığı için 1 döndü)
```
Ya da daha kötüsü:
```bash
cat /non_existent_file | wc -l
echo $? # Çıktı: 0! (cat çöktü ama wc -l başarılı çalıştığı için çıkış kodu 0 oldu!)
```
Gördün mü çırak? İlk komut dosya bulamadığı için çöktü, ama ikinci komut 0 satır saydığı için tüm hattın çıkış kodu `0` (BAŞARILI) sayıldı! Sistem çöktü ama farkında değilsin!

### Savunma: `set -o pipefail` ve `${PIPESTATUS[@]}`
```bash
set -o pipefail # Boru hattındaki herhangi bir hata tüm hattı çökertir

cat /non_existent_file | wc -l
pipe_durumu=("${PIPESTATUS[@]}")
echo "Hattın durumları: ${pipe_durumu[*]}"
# Çıktı: 1 0 (İlk komut 1 ile çöktü, ikincisi 0)
```

---

## 4. Python ile Güvenli Süreç Yürütme: `subprocess.run`

Python içerisinden dış komut çalıştırırken `os.system()` kullanmak tarihe gömülmüştür. Usta standartı `subprocess.run` kullanmaktır:

```python
import subprocess

result = subprocess.run(
    ["/usr/bin/security_tool", "--target", "corp.internal"],
    capture_output=True,  # stdout ve stderr'i ayrı ayrı topla
    text=True,            # Bayt yerine string olarak çöz
    timeout=5.0,          # 5 saniye sonra asılı kalırsa kes (DoS koruması)
    check=False           # Hata kodunu manuel ve adli olarak incele
)

if result.returncode != 0:
    print(f"[ALARM] Komut başarısız oldu (Exit: {result.returncode})")
    print(f"[STDERR] {result.stderr.strip()}")
```

---

## Ustanın Altın Kuralları
1. **Asla `2> /dev/null` ile hata yutma:** Hata varsa ya logla ya da betiği güvenle durdur.
2. **Boru hatlarına daima `pipefail` tak:** Ara komutların başarısızlığı gizlenmesin.
3. **stderr loglarına parola basma:** Parola, token, bağlantı URI'si hata mesajlarında maskelenmelidir (`***REDACTED***`).
4. **Çıkış kodunu deterministik yap:** Parametre hatasına 1, dosya yoksa 2, ağ çöktüyse 3 ver; rastgele `exit 1` saçma.
