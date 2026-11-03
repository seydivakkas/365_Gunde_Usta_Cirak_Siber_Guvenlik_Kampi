# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 101 Değerlendirme Raporu: Hash Fonksiyonları ve Çakışma Dinamikleri

## 1. Genel Bilgiler
- **Eğitim Günü:** Gün 101
- **Hafta:** Hafta 15 / Aşama 05
- **Konu Başlığı:** Hash fonksiyonları ve çakışma
- **Değerlendirme Tarihi:** 02.11.2026
- **Uygulama Modülü:** `portfolio/hafta_15/gun_101/uygulama/hash_collision_engine.py`
- **CLI Modülü:** `portfolio/hafta_15/gun_101/uygulama/hash_cli.py`
- **Test Paketi:** `portfolio/hafta_15/gun_101/tests/test_hash_collision.py`

---

## 2. Puanlama ve Değerlendirme Rubriği (100 Tam Puan)

| Değerlendirme Kriteri | Taban / Tavan Puan | Alınan Puan | Açıklama ve Gerekçe |
|---|---|---|---|
| **1. Mimari Prensipler ve Standartlar** | 20 | **20** | Saf standart kütüphane ile NIST FIPS 180-4 ve RFC 7693 uyumlu modüler mimari, CLI arayüzü, POSIX standart çıkış kodları (0, 1, 2) ve bağımsız gün kuralına tam uyum. |
| **2. Kod Güvenliği ve Kriptografik Tasarım** | 40 | **40** | SHA-256, SHA-512, BLAKE2b desteği, Çığ Etkisi hesaplayıcı, Doğum Günü çakışma simülasyonu, kırılmış MD5/SHA-1 engellemesi (CWE-328) ve sabit zamanlı doğrulama (CWE-208). |
| **3. Test, Dayanıklılık ve Hata Yönetimi** | 25 | **25** | 15/15 birim testi (0.003s) ve 9/9 negatif kontrol senaryosu %100 başarıyla tamamlandı. Null-Byte (CWE-158) ve 1 MB DoS sınırı (CWE-400) uygulandı. |
| **4. Dokümantasyon ve Lisans Bütünlüğü** | 15 | **15** | Kurumsal Özel Lisans başlığı, didaktik Türkçe satır içi açıklamalar, kapsamlı ders notu ve soru-cevap modülleri tam. |
| **TOPLAM SKOR** | **100** | **100** | **DURUM: YETERLİ / PASS (Kriptografik Hash Standartlarına Tam Uyum)** |

---

## 3. Kanıt Zinciri ve Doğrulama Dosyaları

Tüm kanıtlar yerel ortamda gerçek zamanlı üretilmiş ve `kanit/` dizininde arşivlenmiştir:

1. **Birim Test Çıktıları:**
   - Dosya: `kanit/gercek/test_sonuclari.txt`
   - Kapsam: 15 test senaryosu, 0.003 saniye yürütme süresi, `Ran 15 tests ... OK`.
2. **Negatif Kontrol Çıktıları:**
   - Dosya: `kanit/gercek/negatif_kontrol_sonuclari.txt`
   - Kapsam: 9 adet negatif senaryo (CWE-328, CWE-327, CWE-208, CWE-400, CWE-158, CWE-1284, CWE-20, CWE-843), 9/9 BAŞARILI.
3. **Hash Çakışma Analiz Raporu:**
   - Dosya: `kanit/gercek/hash_cakisma_analiz_raporu.txt`
   - Kapsam: NIST FIPS 180-4 'abc' referans vektörü, %49.61 çığ etkisi ölçümü ve 16-bit Doğum Günü çakışma simülasyonu karnesi.
4. **CLI Komut ve Çıkış Kayıtları:**
   - Dosya: `kanit/gercek/komut_ve_cikis.txt`
   - Kapsam: `-s`, `-a`, `--avalanche`, `--birthday-sim`, `--verify` parametreleri ve standart çıkış kodları doğrulaması.
5. **Temsili Mimari İllüstrasyonu:**
   - Dosya: `kanit/temsili/hash_cakisma_mimarisi.txt`
   - Kapsam: Zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığı ile Hash ve Çakışma Mimarisi.

---

## 4. Kapanış Değerlendirmesi

Gün 101, hash fonksiyonlarının kriptografik güvenliğini ve zayıf algoritmaların (MD5, SHA-1) neden terk edilmesi gerektiğini matematiksel ve deneysel kanıtlarla ortaya koymuştur. Bir sonraki gün ele alınacak olan parola saklama, salt ve pepper konularına kusursuz bir temel hazırlanmıştır.
