# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 100 Değerlendirme Raporu: Entropi ve Rastgelelik Prensipleri

## 1. Genel Bilgiler
- **Eğitim Günü:** Gün 100 (Dalya Günü!)
- **Hafta:** Hafta 15 / Aşama 05
- **Konu Başlığı:** Entropi ve rastgelelik
- **Değerlendirme Tarihi:** 02.11.2026
- **Uygulama Modülü:** `portfolio/hafta_15/gun_100/uygulama/entropy_randomness_engine.py`
- **CLI Modülü:** `portfolio/hafta_15/gun_100/uygulama/entropy_cli.py`
- **Test Paketi:** `portfolio/hafta_15/gun_100/tests/test_entropy_randomness.py`

---

## 2. Puanlama ve Değerlendirme Rubriği (100 Tam Puan)

| Değerlendirme Kriteri | Taban / Tavan Puan | Alınan Puan | Açıklama ve Gerekçe |
|---|---|---|---|
| **1. Mimari Prensipler ve Standartlar** | 20 | **20** | Saf standart kütüphane ile NIST SP 800-22 ve NIST SP 800-90B uyumlu modüler mimari, CLI arayüzü, POSIX çıkış kodları (0, 1, 2) ve bağımsız gün kuralına tam uyum. |
| **2. Kod Güvenliği ve Kriptografik Tasarım** | 40 | **40** | Shannon ve Min-Entropi hesaplayıcı, Ki-Kare testi, Monobit frekans testi, CSPRNG (secrets/os.urandom) anahtar üretimi, zayıf PRNG (CWE-338) ve tahmin edilebilir tohum (CWE-337) engellemesi. |
| **3. Test, Dayanıklılık ve Hata Yönetimi** | 25 | **25** | 15/15 birim testi (0.003s) ve 9/9 negatif kontrol senaryosu %100 başarıyla tamamlandı. Null-Byte (CWE-158) ve 1 MB DoS sınırı (CWE-400) uygulandı. |
| **4. Dokümantasyon ve Lisans Bütünlüğü** | 15 | **15** | Kurumsal Özel Lisans başlığı, didaktik Türkçe satır içi açıklamalar, kapsamlı ders notu ve soru-cevap modülleri tam. |
| **TOPLAM SKOR** | **100** | **100** | **DURUM: YETERLİ / PASS (Kriptografik Entropi Standartlarına Tam Uyum)** |

---

## 3. Kanıt Zinciri ve Doğrulama Dosyaları

Tüm kanıtlar yerel ortamda gerçek zamanlı üretilmiş ve `kanit/` dizininde arşivlenmiştir:

1. **Birim Test Çıktıları:**
   - Dosya: `kanit/gercek/test_sonuclari.txt`
   - Kapsam: 15 test senaryosu, 0.003 saniye yürütme süresi, `Ran 15 tests ... OK`.
2. **Negatif Kontrol Çıktıları:**
   - Dosya: `kanit/gercek/negatif_kontrol_sonuclari.txt`
   - Kapsam: 9 adet negatif senaryo (CWE-338, CWE-331, CWE-337, CWE-334, CWE-20, CWE-400, CWE-158, CWE-1284, CWE-843), 9/9 BAŞARILI.
3. **Entropi Analiz Raporu:**
   - Dosya: `kanit/gercek/entropi_analiz_raporu.txt`
   - Kapsam: CSPRNG akışı (7.98 bit/bayt, p=0.85, PASS) ve düşük entropili akış (0.0 bit/bayt, FAIL) matematiksel karşılaştırma karnesi.
4. **CLI Komut ve Çıkış Kayıtları:**
   - Dosya: `kanit/gercek/komut_ve_cikis.txt`
   - Kapsam: `-g`, `--compare-prng`, `-s`, `--json` parametreleri ve standart çıkış kodları doğrulaması.
5. **Temsili Mimari İllüstrasyonu:**
   - Dosya: `kanit/temsili/entropi_rastgelelik_mimarisi.txt`
   - Kapsam: Zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığı ile Entropi ve Rastgelelik Mimarisi.

---

## 4. 100. Gün Dalya Değerlendirmesi

Müfredatın 100. günü başarıyla mühürlenmiştir. Kriptografinin temeli olan belirsizlik ve entropi kavramı; Shannon, Min-Entropi ve NIST istatistiksel testleriyle matematiksel olarak modellenmiş, yazılımda zayıf PRNG kullanımının yıkıcı sonuçları pratik deneylerle doğrulanmıştır.
