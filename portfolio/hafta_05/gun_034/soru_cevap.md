# GÜN 34: DOSYA TÜRLERİ, METADATA VE MIME — SORU-CEVAP BANKASI

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu soru-cevap ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, çoğaltılamaz, ticari amaçla kullanılamaz.
```

---

## SORU 1 (G034-SC1)

### Temel Kavram ve Güvenlik Mekanizması
Bir işletim sisteminde dosyanın kullanıcı arayüzünde görünen adı ve uzantısı (`.pdf`, `.jpg`, `.txt`), dosyanın gerçek biçimini tanımlamak için yalnızca yüzeysel bir etikettir. Dosyaların fiziksel ve mantıksal gerçek kimliği; dosyanın başlangıç ofsetinde (offset 0) yer alan ve **Sihirli Baytlar (Magic Bytes / File Signatures)** olarak adlandırılan değişmez bayt dizilimleri ve IANA tarafından tanımlanmış **MIME (Multipurpose Internet Mail Extensions)** türleri ile belirlenir.

Güvenlik mekanizması açısından dosya uzantısına güvenmek ölümcül bir güvenlik zafiyetidir. Saldırganlar çift uzantı (`fatura.pdf.exe`) veya uzantı değiştirme (`malware.jpg` içine Windows PE ikilisi koyma) yöntemleriyle güvenlik filtrelerini, e-posta ağ geçitlerini ve son kullanıcıları aldatırlar (MITRE T1036). 

Bununla birlikte dosya metadata'sı (zaman damgaları MACB, dosya boyutu, yazar bilgileri, EXIF verileri) "veri hakkındaki veri"dir. Bu üstverilerin birçoğu (özellikle dosya oluşturulma ve değiştirilme tarihleri) saldırganlar tarafından adli bilişim analistlerini aldatmak amacıyla kolayca tahrif edilebilir (Timestomping - MITRE T1070.006). Dolayısıyla bir dosya analiz edilirken yüzeysel uzantıya veya kolayca manipüle edilebilen metadata'ya değil, dosya başlığındaki sihirli baytların derinlemesine incelenmesine (Deep Content Inspection) dayanılmalıdır.

---

### Soru ve Didaktik Çözüm
**Soru:**
Dosya türleri, metadata ve MIME: Temel mekanizmayı ve güvenlik önemini açıklayınız.

**Didaktik Çözüm:**
Dosya adı uzantısından bağımsız olarak imza ve MIME gibi metadata içerir; bazı bilgiler kolayca değiştirilebilir.
1. **İmza ve MIME Bağımsızlığı:** Bir dosyanın sonuna `.pdf` yazılması onun PDF olduğunu kanıtlamaz. Gerçek kimlik dosya başlığındaki sihirli baytlarda (Örn: PDF için `%PDF-`, PE için `MZ`, PNG için `\x89PNG`) saklıdır.
2. **Metadata'nın Değiştirilebilirliği:** Dosya uzantısı, MIME bildirim başlığı (`Content-Type`) ve dosya sistemi zaman damgaları (Timestomping) saldırgan tarafından saniyeler içinde manipüle edilebilir. Güvenlik doğrulaması bu yüzeysel katmanlara değil, dosyanın fiziksel başlık baytlarına dayanmalıdır.

---

### Savunma ve Tespit Kılavuzu
- **Tespit Mekanizması:**
  - Linux ortamında dosyanın gerçek biçimini ve MIME türünü öğrenmek için:
    ```bash
    file -b --mime-type supheli_dosya.pdf
    ```
  - Hex dump alarak ilk baytları incelemek için:
    ```bash
    head -c 16 supheli_dosya.pdf | xxd -p
    ```
- **Savunma Kontrolü:**
  - Web yükleme modüllerinde ve e-posta sunucularında uzantı kontrolünün yanı sıra sunucu taraflı "Magic Bytes Whitelist" doğrulamasını zorunlu kılın.

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Çırak, bir adli bilişim vakasında sana 'kullanıcı yalnızca bir resim dosyası indirdi' dediklerinde hemen dur. Dosyanın uzantısına değil, ilk iki baytına bak. Eğer orada `4D 5A` görüyorsan, o bir resim değil, çalıştırılabilir bir Windows ikilisidir. Gözünle gördüğün uzantıya değil, hex editörün sana söylediği gerçeğe inan!"

---

## SORU 2 (G034-SC2)

### Temel Kavram ve Güvenlik Mekanizması
Bağımsız bir dosya türü ve metadata analiz laboratuvarı; kontrollü girdi dosyaları üzerinden yürütülmeli, dosya başlık baytlarını okumalı, iddia edilen uzantı ile tespit edilen sihirli baytları karşılaştırmalı, uyuşmazlıkları (Mismatch) ve çift uzantıları ortaya çıkarmalıdır. Ayrıca negatif kontrollerle bozuk ve eksik metadata şemalarını güvenle reddedebilmelidir.

---

### Soru ve Didaktik Çözüm
**Soru:**
Dosya türleri, metadata ve MIME: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

**Didaktik Çözüm:**
Bağımsız laboratuvar çalışmasının 4 temel bileşeni şunlardır:
1. **Girdi (Input):** Kendi test ortamımızda üretilen, hem meşru biçimleri (`sample_document.pdf`, `sample_image.png`, `sample_archive.zip`, `sample_text.txt`) hem de güvenlik anomalilerini (`fake_invoice.pdf` -> PE executable, `disguised_photo.jpg` -> ELF binary, `urgent_bill.pdf.exe` -> double extension) içeren kontrollü dosya havuzu ve envanter manifestosu (`sample_file_type_inventory.json`). Önceki günlerin dosyaları kesinlikle devralınmaz.
2. **İşlem (Process):** `FileMetadataMimeAnalyzer` motoru tarafından dosyaların ilk 32 baytının okunması, `SIGNATURE_DATABASE` ile sihirli bayt eşleştirmesi yapılması, çift uzantı ve uzantı-imza çelişkisi analizinin işletilmesi.
3. **Beklenen Sonuç (Expected Output):** Meşru dosyaların `CLEAN` olarak raporlanması; `fake_invoice.pdf` ve `disguised_photo.jpg` için `CRITICAL` seviyesinde `is_mismatch=True` uyarısı üretilmesi; `urgent_bill.pdf.exe` için `is_double_extension=True` (HIGH) tespit edilmesi ve ASCII özet tablosunun oluşturulması.
4. **Negatif Kontrol (Negative Control):** Eksik alanlı, boşluktan ibaret isimli, sözlük olmayan kayıtlar içeren `corrupted_metadata_test_cases.json` dosyasının sisteme verilmesi; motorun çökmeksizin hataları `corrupted_records` günlüğüne işlemesi, 0 baytlık boş dosyanın güvenle işlenmesi ve 14/14 testin başarıyla PASS vermesi.

---

### Savunma ve Tespit Kılavuzu
- **Test ve Doğrulama Adımları:**
  - Birim testleri koşturarak imza tespiti ve negatif kontrolleri doğrulayın:
    ```bash
    python -m unittest portfolio/hafta_05/gun_034/tests/test_file_metadata_mime_analyzer.py -v
    ```
  - Analizciyi çalıştırarak terminal denetim tablosunu inceleyin:
    ```bash
    python portfolio/hafta_05/gun_034/uygulama/file_metadata_mime_analyzer.py
    ```

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Sistemine 0 baytlık boş bir dosya geldiğinde uygulamanın patlamaması gerekir (`len(header) == 0`). İstisnaları (edge-cases) yönetemeyen kod, kurumsal ağda çalıştırılamaz. Negatif kontrol işte bu yüzden profesyonelliğin imzasıdır."

---

## SORU 3 (G034-SC3)

### Temel Kavram ve Güvenlik Mekanizması
'Dosya türleri, metadata ve MIME' bağlamında kurumsal güvenlik riski; sistemlerin gelen dosyalara yalnızca dosya adı uzantısına veya istemci tarafından bildirilen HTTP `Content-Type` başlığına güvenerek izin vermesinden (Weak File Upload Validation) ve kullanıcıların dosya simgelerine aldanarak zararlıları çalıştırmasından doğar.

---

### Soru ve Didaktik Çözüm
**Soru:**
'Dosya türleri, metadata ve MIME' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

**Didaktik Çözüm:**
1. **Risk Nasıl Oluşur?:**
   - **Yüzeysel Doğrulama:** Web uygulaması veya dosya aktarım servisi yalnızca dosya uzantısını kontrol eder (`filename.endswith('.jpg')`). Saldırgan bir PHP web shell veya Windows PE ikilisini `.jpg` uzantısıyla yükler.
   - **Kullanıcı Aldatması:** Çift uzantı (`.pdf.exe`) veya RTLO karakterleriyle zararlı dosya masum bir doküman gibi gösterilerek oltalama (phishing) yoluyla kurbana çalıştırılır.
   - **Timestomping:** Saldırgan zararlı dosyanın tarihini 5 yıl geriye çekerek adli bilişim taramalarından gizlenir.
2. **Nasıl Tespit Edilir?:**
   - **Fark Raporu ve İmza Denetimi:** Ağ geçitlerinde veya dosya sunucularında periyodik olarak uzantı ile dosya başlığı karşılaştırılır; uyuşmayan ikililer (`Extension Mismatch`) SOC merkezine iletilir.
   - **EDR Dosya Oluşturma Olayları:** Sysmon Olay Kimliği 11 (FileCreate) izlenerek çift uzantılı dosyaların indirilmesi anında alarm üretilir.
3. **Hangi Kontrolle Önlenir?:**
   - **Sihirli Bayt Doğrulaması:** Dosyalar içeri alınırken sunucu tarafında ilk 16 bayt okunur; uzantı ve MIME türü bu baytlara göre yeniden atanır.
   - **En Az Ayrıcalık ve İnfaz Engelleme:** Yükleme yapılan dizinlerde (Örn: `/uploads/`, `C:\inetpub\uploads\`) komut yürütme (Execute) izinleri tamamen kaldırılır (`noexec`).
   - **Geri Alınabilir Yapılandırma:** Windows Grup İlkesi (GPO) üzerinden "Bilinen dosya türleri için uzantıları gizle" seçeneği zorunlu olarak kapatılır (Uzantılar her zaman görünür olmalıdır).

---

### Savunma ve Tespit Kılavuzu
- **Windows GPO ile Uzantıları Görünür Kılma:**
  ```powershell
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
  ```
- **Web Sunucu IIS/Nginx Sıkılaştırma:**
  Yükleme klasörlerinde PHP/ASPx yürütmeyi engelleme:
  ```nginx
  location /uploads/ {
      location ~ \.(php|phar|phtml)$ {
          deny all;
      }
  }
  ```

---

### Usta-Çırak İpuçları ve Laboratuvar Notu
*Usta der ki:* "Dosya yükleme fonksiyonu bir web sitesinin en tehlikeli kapısıdır. O kapıya sadece uzantı kontrolü koymak, kapıya kilit takıp anahtarı paspasın altına koymaya benzer. İçeri giren her baytı koklayacaksın!"
