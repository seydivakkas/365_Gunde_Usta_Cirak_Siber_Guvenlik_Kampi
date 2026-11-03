# HOCA DERSI STANDARDI: "Usta-Çırak / Sıfırdan Uzmanlığa Siber Güvenlik Akademisi"

**Sürüm:** 2.0 (Radikal Yenilenme)  
**Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.  
**Temel İlke:** Fabrikasyon, ruhsuz ve tekrar eden yapay JSON denetleyicileri YASAKTIR. Her gün, karşısına 0 bilgiyle oturan bir öğrenciyi adım adım dünyanın en yetkin siber güvenlik uzmanlarından biri yapacak bir **Hoca / Usta Dersi** olarak işlenir.

---

## 🏛️ Pedagojik Felsefe ve Anlatım Dili

1. **Öğretmen / Hoca Dili:**
   - Didaktik, samimi, derin, merak uyandıran, ezberletmeyen ve mantığını kavratan bir üslup.
   - Soyut kavramlar asla havada bırakılmaz; somut zihinsel modeller (Mental Models), analojiler ve gerçek hayattan yaşanmış siber olaylar (vakalar) ile zihne kazınır.
2. **Sıfır Noktasından Başlama İlkesi:**
   - Öğrencinin hiçbir ön bilgiye sahip olmadığı varsayılır. Bit, bayt, bellek, IP, port, soket, çekirdek (kernel), yetki ve işlem kavramları kristal berraklığında anlatılır.
3. **Mühendislik ve Sahicilik Standardı:**
   - Öğrencinin kendi terminalini (PowerShell, Bash, CMD, Python) açıp **bizzat yazacağı, çalıştıracağı ve sonucunu kendi gözleriyle göreceği** yaşayan laboratuvarlar kurulur.
   - Konu hangi aracı ve dili gerektiriyorsa o kullanılır:
     - PowerShell günlerinde: Gerçek `.ps1` güvenlik betikleri ve cmdlet'ler.
     - Linux kabuk günlerinde: Gerçek `.sh` Bash betikleri ve boru hatları.
     - İzin günlerinde: Gerçek dosya sistemi, umask, ACL, chmod/chown pratikleri.
     - Günlük analizinde: Gerçek Event Log (`Get-WinEvent`), Syslog, `journalctl` akışları.
     - Ağ günlerinde: Gerçek soket programlama, paket analizi, Wireshark akışları.
     - Yazılım güvenliği / DevSecOps günlerinde: Gerçek Python, C veya ilgili diller.

---

## 📋 Zorunlu 7 Aşamalı Günlük Ders Mimarisi (`ders.md`)

Her günün `ders.md` içeriği istisnasız şu 7 ana başlığı eksiksiz barındıracaktır:

### 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)
- "Bugün masamızda ne var? Bu konuyu neden öğreniyoruz?"
- Bu bilginin gerçek dünyada bir siber güvenlik uzmanının (SOC Analisti, Sızma Testi Uzmanı, DFIR Olay Müdahale Uzmanı, Güvenlik Mimarı) masasında nasıl karşımıza çıktığı.
- Konuyu kafada somutlaştıran güçlü analojiler.

### 2. Sıfırdan Başlayan Kristal Netliğinde Teori (Under the Hood)
- Sistemin arka planında donanım, işletim sistemi çekirdeği veya ağ protokolü seviyesinde ne dönüyor?
- Matematiksel, mantıksal veya mimari temel.

### 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)
- **Saldırgan (Black/Red Hat):** Bu mekanizmayı nasıl deler, zafiyetten nasıl faydalanır, saldırı nasıl gerçekleşir?
- **Savunmacı (Blue/Purple Hat):** Biz bu saldırıyı sistemde nasıl tespit ederiz, hangi loglara bakarız ve sistemi nasıl sertleştiririz?

### 4. Hocayla Birlikte Canlı Laboratuvar (Adım Adım Terminal Rehberi)
- Öğrencinin kendi bilgisayarında çalıştıracağı adım adım terminal komutları ve kodları.
- Kodların satır satır ne işe yaradığı, beklenen ekran çıktıları ve açıklamaları.

### 5. Hocanın "Ölümcül Hatalar ve Mülakat Tuzakları" Notu
- Sektöre yeni başlayanların en çok düştüğü yanılgılar.
- Teknik iş mülakatlarında sorulan püf noktaları.
- Canlı üretim ortamlarında yapılan felaket hatalar.

### 6. Günün Pratik Görevi (Hands-on Challenge & Walkthrough)
- Excel'deki `LABORATUVAR` sekmesinde tanımlanan somut senaryo görevi.
- Öğrencinin görevi nasıl çözeceğinin adım adım analizi ve hocanın çözümü.

### 7. Hocanın Soru Odası (Kapsamlı Soru-Cevap)
- Excel `SORU BANKASI` sekmesinde o gün için belirlenmiş 3 sorunun, hocanın üslubuyla derinlemesine, teknik gerekçeli, felsefi ve doyurucu yanıtları.

---

## 🧪 Uygulama ve Test Standardı (`uygulama/` & `tests/`)

1. **Sahici Kod:** Uygulama klasöründeki kodlar, konunun özünü yaşayan gerçek bir araç, simülasyon veya laboratuvar yardımcısıdır.
2. **Pozitif ve Negatif Testler:** `tests/` klasöründeki birim testler, öğrenilen güvenlik prensibinin hem doğru çalıştığını (pozitif kontrol) hem de güvenlik ihlali/tahrifat durumunda başarısız olduğunu (negatif kontrol) kanıtlar.
3. **Gerçek Çıktı Kanıtı:** `kanit/gercek/` klasöründe yerel terminalde gerçekten çalıştırılmış komut ve test çıktıları (`komut_ve_cikis.txt`, `test_sonuclari.txt`) yer alır.
4. **Temsilî Mimari Şeması:** `kanit/temsili/` klasöründe konunun zihinsel haritasını ve mimari akışını gösteren ASCII/metin diyagramı yer alır.

---

## 🔒 Lisans ve Etik Sözleşmesi
- Her dosyanın başında: "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)" hükümleri yer alır.
- Açık kaynak (MIT, GPL, Apache vb.) lisanslar KULLANILMAZ.
