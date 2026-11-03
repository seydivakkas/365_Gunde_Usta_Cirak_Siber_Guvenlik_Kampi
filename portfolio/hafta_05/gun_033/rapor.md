# GÜN 33: DOSYA HASH VE BÜTÜNLÜK — TEKNİK RAPOR VE DEĞERLENDİRME

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
- **Gün:** 33 (G033)
- **Hafta:** 05 | **Aşama:** 02 (Sistem ve Ağ Güvenliği Temelleri)
- **Konu:** Dosya hash ve bütünlük (File hashing and integrity)
- **Standart Kaynak:** `standart_gun.md §3–12`
- **Resmî Kaynak:** [Microsoft Learn: Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- **Öğrenme Çıktısı:**
  1. Kriptografik özet fonksiyonlarının (SHA-256, MD5) tek yönlülük, ikinci ön görüntü direnci ve çarpışma direnci matematiksel temellerini kavrama.
  2. Girdideki 1 bitlik değişikliğin özet bitlerinin yaklaşık %50'sini değiştirdiği Çığ Etkisini (Avalanche Effect) Hamming mesafesiyle kanıtlama.
  3. "Hash dosya değişimini saptar; fakat hash tek başına bir dosyanın güvenilir olduğunu söylemez" (G033-SC1) ilkesini analiz etme.
  4. Dosya Bütünlüğü İzleme (FIM) motoru ile taban çizgisi oluşturma, tahrif edilmiş dosyaları (`INTEGRITY_COMPROMISED`), silinmiş dosyaları (`FILE_MISSING`) ve yeni yetkisiz dosyaları (`NEW_UNAUTHORIZED_FILE`) otomatik tespit edebilme.

---

## 2. DÖRT BİLEŞENLİ DEĞERLENDİRME RUBRİĞİ (100 / 100)

| Rubrik Kriteri | Taban Puan | Alınan Puan | Açıklama ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 0 – 20 | **20** | `soru_cevap.md` içinde G033-SC1, SC2 ve SC3 soruları tam teknik derinlikle, 4 zorunlu alt başlık (Temel Kavram, Soru/Didaktik Çözüm, Savunma/Tespit, Usta-Çırak İpuçları) eksiksiz uygulanarak hazırlanmıştır. |
| **Gerçek Uygulama / Simülasyon** | 0 – 40 | **40** | `file_integrity_hash_checker.py` aracı bağımsız ve sıfırdan geliştirilmiştir. Çalıştırılabilir her bir kod satırı didaktik açıklamalarla zenginleştirilmiş; 64 KB akışlı hash hesaplama, çığ etkisi ölçümü, taban çizgisi doğrulama ve güvenilirlik analiz motoru eksiksiz kodlanmıştır. |
| **Doğrulanabilir Kanıt** | 0 – 25 | **25** | `kanit/gercek/` altında 14/14 birim test çıktısı (`test_sonuclari.txt`), CLI yürütme dökümü (`komut_ve_cikis.txt`), ASCII denetim çıktısı (`butunluk_denetim_raporu.txt`) ve bozuk veri reddini belgeleyen `negatif_kontrol_sonuclari.txt` doğrulanmıştır. `kanit/temsili/` altında etiketli mimari şema yer almaktadır. |
| **Teknik Raporlama** | 0 – 15 | **15** | Rapor; matematiksel çığ etkisini, FIM denetim sonuçlarını, MITRE ATT&CK eşleşmelerini ve savunma stratejilerini net bir şekilde ortaya koymaktadır. |
| **TOPLAM PUAN** | **100** | **100** | **SONUÇ: YETERLİ / PASS (TAM BAŞARI)** |

---

## 3. LABORATUVAR VE MATEMATİKSEL İSPAT SONUÇLARI

### A. Çığ Etkisi (Avalanche Effect) İspatı
- **Orijinal Dosya:** `config.json` (`"debug_mode": false`) -> SHA-256: `2cf886ce37d1c9fdf227bd875fc638c83938da29d65c074a562c30e79136474f`
- **Tahrif Edilmiş Dosya:** `tampered_config.json` (`"debug_mode": true`) -> SHA-256: `91a7743b52a28d0b1f2f9ac03d848dca744ee0b9fe8d9f62608de3870e363d3c`
- **Fark Analizi:** 256 bitlik özet çıktısında tam **122 bit** değişmiştir (%47.66). Bu oran kriptografik fonksiyonların ideal hedefi olan %50 bandı içindedir.

### B. Bütünlük Denetim Bulguları (FIM)
`sample_baseline_manifest.json` taban çizgisi baz alınarak yapılan denetimde:
1. `tampered_config.json` dosyasında hash uyuşmazlığı saptanmış ve `INTEGRITY_COMPROMISED` (CRITICAL) alarmı üretilmiştir.
2. Taban çizgisinde olmayan yetkisiz `malicious_payload.sh` tespit edilmiş ve `NEW_UNAUTHORIZED_FILE` (MEDIUM) olarak işaretlenmiştir.
3. Test senaryolarında silinen dosyalar için `FILE_MISSING` (HIGH) üretildiği doğrulanmıştır.

---

## 4. NEGATİF KONTROL VE HATA DAYANIKLILIĞI

`corrupted_hash_test_cases.json` dosyasında yer alan 7 bozuk kayıt (geçersiz onaltılık karakter içeren hash'ler, 64 karakterden kısa/uzun hash'ler, eksik alanlar ve liste formatında olmayan yapılar) `validate_baseline_entry` ve `validate_hash_format` fonksiyonları tarafından güvenle yakalanmış, sistemin çökmesi engellenmiş ve tüm hatalar `corrupted_records` listesine işlenmiştir. 14 birim testin tamamı 0.058 saniyede başarıyla sonuçlanmıştır.

---

## 5. SONUÇ VE BİR SONRAKİ ADIM
Gün 33 çalışmaları; bağımsızlık kuralına tam riayetle, Usta-Çırak pedagojisine uygun şekilde, her satırı açıklamalı kod ve testlerle başarıyla tamamlanmıştır.

- **Sonraki Gün:** Gün 34 (G034 - Hafta 05)
- **Hazırlık:** Gün 33'ün yedeklenmesi, manifest dosyasının üretilmesi ve Excel çizelgesinin güncellenmesi.
