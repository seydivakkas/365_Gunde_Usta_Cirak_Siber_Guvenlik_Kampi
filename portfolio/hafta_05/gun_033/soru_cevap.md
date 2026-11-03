# GÜN 33: DOSYA HASH VE BÜTÜNLÜK — SORU-CEVAP BANKASI

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu soru-cevap ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, çoğaltılamaz, ticari amaçla kullanılamaz.
```

---

## SORU 1 (G033-SC1)

### Temel Kavram ve Güvenlik Mekanizması
Kriptografik özet fonksiyonları (özellikle NIST onaylı SHA-256), herhangi bir boyuttaki veriyi sabit 256 bitlik (64 onaltılık karakter) matematiksel bir parmak izine dönüştürür. Bu fonksiyonlar tek yönlüdür (pre-image resistant) ve çığ etkisine (avalanche effect) tabidir; yani girdideki en ufak bir bayt değişimi çıktıda tamamen farklı bir özet değeri üretir.

Güvenlik mekanizması açısından özetler, dosyanın yetkisizce değiştirilip değiştirilmediğini (bütünlük / integrity) saptamak için kusursuz bir denetim sağlar. Ancak siber güvenlikte en çok karıştırılan iki kavram "bütünlük" ile "güvenilirliktir". Bir dosyanın geçerli bir SHA-256 özetine sahip olması veya bu özetin bilinmesi, o dosyanın zararsız veya güvenilir olduğu anlamına gelmez. Bilinen en tehlikeli fidye yazılımları, casus yazılımlar veya arka kapılar da mükemmel ve matematiksel olarak geçerli bir SHA-256 özetine sahiptir. Kriptografik hash yalnızca "bu dosya beklenen referans dosya ile aynı mı?" sorusuna yanıt verir; "bu dosya sisteme zarar verir mi?" sorusuna değil. Dosyanın güvenilirliği; kod imzalama (code signing), geçerli dijital sertifikalar (Authenticode), EDR davranış analizi ve tehdit istihbaratı (VirusTotal vb.) ile belirlenir.

---

### Soru ve Didaktik Çözüm
**Soru:**
Dosya hash ve bütünlük: Temel mekanizmayı ve güvenlik önemini açıklayınız.

**Didaktik Çözüm:**
SHA-256 gibi özetler dosya değişimini saptar; hash tek başına bir dosyanın güvenilir olduğunu söylemez.
1. **Dosya Değişimini Saptama (Bütünlük):** Taban çizgisi (baseline) ile karşılaştırıldığında özet fonksiyonu, dosya içeriğinde tek bir bit dahi değiştirilse (Çığ Etkisi sayesinde) farklı bir çıktı üreterek yetkisiz müdahaleyi anında açığa çıkarır.
2. **Güvenilirlik Sınırı:** Hash bir güvenlik garantisi veya temizlik belgesi değildir. Bir saldırganın sisteme bıraktığı zararlı bir ikili de tutarlı bir hash üretir. Güvenilirlik tespiti için dijital imza doğrulaması ve itibar analizi zorunludur.

---

### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizması:**
  - PowerShell ile dosyanın kriptografik özetini hesaplayın:
    ```powershell
    Get-FileHash -Path "C:\Windows\System32\cmd.exe" -Algorithm SHA256
    ```
  - Dosyanın yalnızca hash'ine değil, Microsoft dijital imzasına da bakın:
    ```powershell
    Get-AuthenticodeSignature -FilePath "C:\Windows\System32\cmd.exe"
    ```
- **Savunma Kontrolü:**
  - Güvenilmeyen veya imzasız yazılımların çalıştırılmasını engellemek için AppLocker veya Windows Defender Application Control (WDAC) politikalarını devreye alın.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Çırak, internetten indirdiğin bir aracın web sitesinde yazan SHA-256 hash'i ile indirdiğin dosyanın hash'ini karşılaştırdığında neyi kanıtlamış olursun? Dosyanın indirme sırasında bozulmadığını veya yolda araya giren biri tarafından değiştirilmediğini kanıtlarsın. Peki web sitesinin kendisi ele geçirilmiş ve oraya saldırgan kendi zararlısının hash'ini koymuşsa? İşte o zaman hash tutar ama makineni saldırgana teslim edersin. Hash bütünlüktür, güvenilirlik değil!"

---

## SORU 2 (G033-SC2)

### Temel Kavram ve Güvenlik Mekanizması
Bir dosya bütünlüğü izleme (FIM) motoru; girdi olarak verilen dosyaları okumalı, sabit bloklar halinde akış (streaming) üzerinden kriptografik özetlerini çıkarmalı ve bunları yetkili bir taban çizgisi (baseline) ile kıyaslamalıdır. Laboratuvar ortamı bağımsız olmalı, kontrollü girdilerle çalışmalı ve bozuk veriler (geçersiz hex, yanlış uzunluk, eksik alanlar) verildiğinde çökmeyerek negatif kontrolleri tescillemelidir.

---

### Soru ve Didaktik Çözüm
**Soru:**
Dosya hash ve bütünlük: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

**Didaktik Çözüm:**
Bağımsız laboratuvar çalışmasının 4 temel bileşeni şunlardır:
1. **Girdi (Input):** Kendi test ortamımızda üretilen kontrollü veri seti: Yetkili konfigürasyon (`config.json`), tek bir parametresi değiştirilmiş tahrifatlı dosya (`tampered_config.json`), güvenlik politikası metni (`security_policy.txt`) ve yetkili taban çizgisi manifestosu (`sample_baseline_manifest.json`). Önceki günlerden hiçbir veri veya dosya devralınmaz.
2. **İşlem (Process):** `FileIntegrityHashChecker` motoru tarafından dosyaların 64 KB'lık bloklar halinde okunarak SHA-256 ve MD5 özetlerinin çıkarılması, orijinal ile tahrif edilmiş dosya arasındaki bit düzeyindeki Hamming mesafesinin (Çığ Etkisi) hesaplanması ve diskteki dosyaların taban çizgisiyle karşılaştırılması.
3. **Beklenen Sonuç (Expected Output):** Orijinal `config.json` ile `tampered_config.json` arasında 122 bitlik (%47.66) değişimle Çığ Etkisinin kanıtlanması; değiştirilen dosya için `INTEGRITY_COMPROMISED` (CRITICAL), diskte olmayan dosya için `FILE_MISSING` (HIGH), fazladan eklenen dosya için `NEW_UNAUTHORIZED_FILE` (MEDIUM) alarmlarının üretilmesi.
4. **Negatif Kontrol (Negative Control):** Geçersiz hex içeren (`zzzz...`), 64 karakterden kısa/uzun, eksik yollu veya sözlük olmayan kayıtları barındıran `corrupted_hash_test_cases.json` dosyasının sisteme verilmesi; uygulamanın çökmeksizin tüm hatalı kayıtları `corrupted_records` listesine alması ve 14/14 testin başarıyla PASS vermesi.

---

### Savunma ve Tespit Kılavuzu
- **Test ve Doğrulama Adımları:**
  - Birim testleri koşturarak hem matematiksel hash doğruluğunu hem negatif kontrolleri doğrulayın:
    ```bash
    python -m unittest portfolio/hafta_05/gun_033/tests/test_file_integrity_hash_checker.py -v
    ```
  - Bütünlük denetim motorunu çalıştırarak ASCII raporunu inceleyin:
    ```bash
    python portfolio/hafta_05/gun_033/uygulama/file_integrity_hash_checker.py
    ```

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Bir dosyanın hash'ini hesaplarken asla dosyanın tamamını tek seferde RAM'e yükleme (`f.read()`). Yarın karşına 50 GB'lık bir bellek dökümü veya disk imajı çıktığında uygulaman bellek yetersizliğinden çöker. Her zaman 64 KB'lık akış (chunked streaming) bloklarıyla çalış."

---

## SORU 3 (G033-SC3)

### Temel Kavram ve Güvenlik Mekanizması
'Dosya hash ve bütünlük' bağlamında kurumsal güvenlik riski; sistem konfigürasyonlarının, ikili dosyaların veya web uygulaması kaynak kodlarının yetkisizce değiştirilmesi ve bu değişikliğin fark edilememesinden kaynaklanır. Risk; aşırı geniş dosya izinleri (Everyone: Full Control), denetimsiz yönetimsel hesaplar ve periyodik bütünlük kontrolü (FIM) yapılmamasından doğar.

---

### Soru ve Didaktik Çözüm
**Soru:**
'Dosya hash ve bütünlük' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

**Didaktik Çözüm:**
1. **Risk Nasıl Oluşur?:**
   - **Gereksiz İzin:** Kritik sistem dizinlerine (`/etc/`, `C:\Windows\System32\`, `C:\inetpub\wwwroot\`) standart kullanıcılara veya web servis hesaplarına yazma yetkisi verilmesi.
   - **Yetkisiz Değişiklik:** Saldırganın web sunucusuna bir web shell bırakması veya konfigürasyondaki güvenlik parametresini (`debug_mode=true` veya `firewall=disabled`) tahrif etmesi.
   - **Körlük:** Bütünlük izleme mekanizması olmadığı için sistemin aylarca bu tahrif edilmiş durumla çalışması.
2. **Nasıl Tespit Edilir?:**
   - **Dosya Bütünlüğü İzleme (FIM):** Bilinen temiz altın imajın (Golden Image) SHA-256 taban çizgisi ile üretim ortamındaki dosyaların periyodik fark raporu (diff) alınır.
   - **Anomali Alarmları:** Hash eşleşmeyen (`INTEGRITY_COMPROMISED`) veya yeni eklenen (`NEW_UNAUTHORIZED_FILE`) dosyalar SOC merkezinde gerçek zamanlı uyarı üretir.
3. **Hangi Kontrolle Önlenir?:**
   - **En Az Ayrıcalık (Least Privilege):** Dosya sistemi ACL izinleri sıkılaştırılır; yalnızca `SYSTEM` veya `TrustedInstaller` yazma hakkına sahip olur.
   - **Salt Okunur Dosya Sistemleri ve İmmutability:** Mümkün olan üretim ortamlarında (Docker konteynerleri, sunucu konfigürasyonları) dosya sistemi salt okunur (`read-only`) bağlanır.
   - **Geri Alınabilir Yapılandırma:** Yapılandırma dosyaları Git/IaC reposunda versiyonlanır; tahrifat anında otomatik olarak temiz sürüme geri dönülür (Self-healing).

---

### Savunma ve Tespit Kılavuzu
- **Linux Taban Çizgisi Oluşturma ve Doğrulama Komutları:**
  ```bash
  # Kritik dizinlerin hash taban çizgisini oluşturma:
  find /etc/ -type f -exec sha256sum {} + > /var/log/fim_baseline.sha256
  # Bütünlüğü periyodik olarak kontrol etme:
  sha256sum -c /var/log/fim_baseline.sha256 | grep -v 'OK$'
  ```
- **Önleme:**
  Kritik dosyaların `chattr +i <dosya>` (immutable) ile root dahil silinmesi veya değiştirilmesi engellenir.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Saldırganlar sisteme girdikten sonra çoğu zaman logları temizlemeye veya konfigürasyonu gevşetmeye çalışırlar. Eğer senin FIM sistemin o dosyanın hash'inin değiştiğini 1 saniye içinde yakalarsa, saldırganın tüm operasyonu açığa çıkar. Taban çizgini koru, bütünlüğünü koru!"
