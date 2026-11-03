# GÜN 34: DOSYA TÜRLERİ, METADATA VE MIME — TEKNİK RAPOR VE DEĞERLENDİRME

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu rapor ve değerlendirme içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, çoğaltılamaz, ticari amaçla kullanılamaz.
```

---

## 1. GÖREV VE PEDAGOJİK HEDEF ÖZETİ
- **Gün:** 34 (G034)
- **Hafta:** 05 | **Aşama:** 02 (Sistem ve Ağ Güvenliği Temelleri)
- **Konu:** Dosya türleri, metadata ve MIME (File types, metadata, and MIME)
- **Standart Kaynak:** `standart_gun.md §3–12`
- **Resmî Kaynak:** [Microsoft Learn: Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- **Öğrenme Çıktısı:**
  1. Dosya adı uzantısının yüzeysel bir etiket olduğunu ve gerçek kimliği temsil etmediğini kavrama.
  2. Sihirli Baytlar (Magic Bytes / File Signatures) ve MIME türleri arasındaki ilişkiyi analiz etme.
  3. "Dosya adı uzantısından bağımsız olarak imza ve MIME gibi metadata içerir; bazı bilgiler kolayca değiştirilebilir" (G034-SC1) ilkesini temellendirme.
  4. Uzantı-İmza Uyuşmazlığı (Extension Mismatch - MITRE T1036.008), Çift Uzantı (Double Extension - MITRE T1036.007) ve Timestomping risklerini tespit eden bir denetim motoru (`FileMetadataMimeAnalyzer`) geliştirme.

---

## 2. DÖRT BİLEŞENLİ DEĞERLENDİRME RUBRİĞİ (100 / 100)

| Rubrik Kriteri | Taban Puan | Alınan Puan | Açıklama ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 0 – 20 | **20** | `soru_cevap.md` içinde G034-SC1, SC2 ve SC3 soruları tam teknik derinlikle, 4 zorunlu alt başlık (Temel Kavram, Soru/Didaktik Çözüm, Savunma/Tespit, Usta-Çırak İpuçları) eksiksiz uygulanarak hazırlanmıştır. |
| **Gerçek Uygulama / Simülasyon** | 0 – 40 | **40** | `file_metadata_mime_analyzer.py` aracı bağımsız ve sıfırdan geliştirilmiştir. Çalıştırılabilir her bir kod satırı didaktik açıklamalarla zenginleştirilmiş; sihirli bayt eşleştirme, çift uzantı kontrolü, uyuşmazlık analizi ve metadata motoru eksiksiz kodlanmıştır. |
| **Doğrulanabilir Kanıt** | 0 – 25 | **25** | `kanit/gercek/` altında 14/14 birim test çıktısı (`test_sonuclari.txt`), CLI yürütme dökümü (`komut_ve_cikis.txt`), ASCII denetim çıktısı (`metadata_ve_mime_denetim_raporu.txt`) ve bozuk veri reddini belgeleyen `negatif_kontrol_sonuclari.txt` doğrulanmıştır. `kanit/temsili/` altında etiketli mimari şema yer almaktadır. |
| **Teknik Raporlama** | 0 – 15 | **15** | Rapor; dosya imzası analiz sonuçlarını, MITRE ATT&CK eşleşmelerini ve kurumsal savunma önlemlerini net bir şekilde ortaya koymaktadır. |
| **TOPLAM PUAN** | **100** | **100** | **SONUÇ: YETERLİ / PASS (TAM BAŞARI)** |

---

## 3. LABORATUVAR VE DENETİM BULGULARI ÖZETİ

`sample_file_type_inventory.json` dosyasında yer alan 7 dosya başlık baytları düzeyinde incelenmiş ve aşağıdaki bulgular elde edilmiştir:

1. **Uzantı - İmza Uyuşmazlığı (Extension Mismatch) — CRITICAL:**
   - **Dosya:** `fake_invoice.pdf` | İddia Edilen Uzantı: `.pdf`
   - **Tespit Edilen Biçim:** `Windows PE Executable` (`4D 5A` - MZ) | MIME: `application/x-dosexec`
   - **Risk:** Kullanıcıya masum PDF faturası gibi sunulan ancak çalıştırıldığında Windows PE ikilisi olarak yürütülecek zararlı yazılım (Phishing / Extension Spoofing - T1036.008).
2. **Platform Yanıltması ve İkili Gizleme — CRITICAL:**
   - **Dosya:** `disguised_photo.jpg` | İddia Edilen Uzantı: `.jpg`
   - **Tespit Edilen Biçim:** `Linux ELF Executable` (`7F 45 4C 46`) | MIME: `application/x-executable`
   - **Risk:** Web sunucusuna resim olarak yüklenen Linux çalıştırılabilir ikilisi.
3. **Çift Uzantı Saldırısı (Double Extension) — HIGH:**
   - **Dosya:** `urgent_bill.pdf.exe` | İddia Edilen Uzantı: `.pdf.exe`
   - **Tespit Edilen Biçim:** `Windows PE Executable`
   - **Risk:** Windows Gezgini'nin uzantı gizleme zaafını istismar ederek kullanıcıyı kandırmayı hedefleyen Truva Atı (T1036.007).
4. **Meşru Biçimler — CLEAN:**
   - `sample_document.pdf` (%PDF-), `sample_image.png` (\x89PNG), `sample_archive.zip` (PK), `sample_text.txt` tam uyumlu ve temiz bulunmuştur.

---

## 4. NEGATİF KONTROL VE HATA DAYANIKLILIĞI

`corrupted_metadata_test_cases.json` dosyasındaki 6 bozuk kayıt (eksik dosya adı, eksik yol, boşluktan ibaret isimler, sözlük olmayan tipler) `validate_manifest_entry` fonksiyonu tarafından güvenle yakalanmış, sistemin çökmesi engellenmiş ve tüm hatalar `corrupted_records` günlüğüne işlenmiştir. Ayrıca 0 baytlık boş dosya (`empty_zero_byte.bin`) `Empty File` olarak başarıyla işlenmiştir. 14 birim testin tamamı 0.132 saniyede başarıyla sonuçlanmıştır.

---

## 5. SONUÇ VE BİR SONRAKİ ADIM
Gün 34 çalışmaları; bağımsızlık kuralına tam riayetle, Usta-Çırak pedagojisine uygun şekilde, her satırı açıklamalı kod ve testlerle başarıyla tamamlanmıştır.

- **Sonraki Gün:** Gün 35 (G035 - Hafta 05)
- **Hazırlık:** Gün 34'ün yedeklenmesi, manifest dosyasının üretilmesi ve Excel çizelgesinin güncellenmesi.
