# Hafta 05 — Gün 031: Değerlendirme ve Sonuç Raporu

> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> **Özel Lisans — Tüm Hakları Saklıdır**  
> *Bu rapor eğitim ve değerlendirme amaçlı hazırlanmıştır. İzinsiz kopyalanamaz veya dağıtılamaz.*

---

## 1. Genel Bilgiler
- **Eğitim Programı:** Siber Güvenlik 365 Gün Standart ve Müfredat Paketi
- **Aşama:** Aşama 02 — Sistem ve Ağ Güvenliği Temelleri
- **Hafta:** Hafta 05 — Olay Günlükleri, Kayıt Defteri ve Temel Ağ Analizi
- **Gün:** Gün 031 — Process Explorer ve Süreç Ağacı
- **Değerlendirme Tarihi:** 2026-10-27
- **Sonuç:** **YETERLİ / PASS (100 / 100)**

---

## 2. Puanlama Tablosu

| Kriter | Açıklama | Taban Puan | Alınan Puan | Durum |
| :--- | :--- | :---: | :---: | :---: |
| **Kriter 1: Teorik Altyapı ve Kavramsal Yetkinlik** | Process Explorer felsefesi, PPID-PID hiyerarşisi, meşru karmaşık ağaçlar ile saldırı zincirlerinin ayrımı (G031-SC1), süreç taklidi (Masquerading T1036) ve döngü tespiti teorisi eksiksiz incelenmiştir. | 20 | **20** | Mükemmel |
| **Kriter 2: Pratik Uygulama ve Kod Kalitesi** | `process_tree_explorer_analyzer.py` aracı bağımsız, standart kütüphane odaklı, DFS tabanlı döngü denetçisi, hiyerarşik ASCII ağaç çizicisi ve 5 farklı anomali dedektörü ile yazılmış; tüm satırları didaktik açıklamalarla donatılmıştır. | 40 | **40** | Mükemmel |
| **Kriter 3: Güvenlik Senaryoları ve Doğrulama** | G031-SC1 (Chrome meşru ağacı vs Word zararlı zinciri), G031-SC2 (izinli sistemde süreç ağacı şemalaştırma, negatif kontrolde 4 bozuk vakanın reddedilmesi) ve G031-SC3 (süreç taklidi, imzasız ikili ve Temp dizini tespiti) 14 birim test ile %100 doğrulanmıştır. | 25 | **25** | Mükemmel |
| **Kriter 4: Dokümantasyon, Raporlama ve Standart Uyumu** | Usta-çırak üslubu, 4 başlıklı senaryo formatı, özel lisans damgası, temsilî kanıt banner'ı, UTF-8 kodlama ve JSON veri bütünlüğü kurumsal standartta tamamlanmıştır. | 15 | **15** | Mükemmel |
| **TOPLAM** | **Genel Değerlendirme ve Başarı Skoru** | **100** | **100** | **YETERLİ (PASS)** |

---

## 3. Laboratuvar ve Test İstatistiği
- **Toplam Birim Test:** 14
- **Başarılı Test (PASS):** 14 (%100.0)
- **Başarısız / Hatalı Test:** 0 (%0.0)
- **Çalışma Süresi:** 0.190 saniye
- **İncelenen Süreç Sayısı:** 16 süreç (Kök süreçler: System, explorer; Çocuk süreçler: Chrome sekmeleri, svchost'lar, saldırı zinciri).
- **Tespit Edilen Anomaliler:** 5 adet (Ofis kabuk başlatma, Base64 PowerShell, geçersiz ebeveyn, Temp dizininde sistem ikilisi, imzasız sistem süreci).
- **Negatif Kontrol Kapsamı:** 4 adet bozuk veya döngüsel vaka (döngüsel PPID döngüsü, negatif PID, boş süreç adı, mükerrer PID) %100 başarıyla reddedilmiştir.

---

## 4. Çıkarılan Temel Sonuçlar ve Mühendislik Kazanımları
1. **Soyağacı Zorunluluğu:** Süreçleri düz bir liste olarak incelemek yanıltıcıdır; ebeveyn-çocuk bağı kurulmadan saldırı zinciri anlaşılamaz.
2. **Meşru Karmaşık Ağaçlar:** Modern tarayıcılar (Chrome) gibi yazılımların çoklu süreç mimarisi doğru anlaşılmalı, yanlış alarm (false-positive) üretilmemelidir.
3. **Süreç Taklidi (Masquerading):** Bir sürecin adı `svchost.exe` olsa bile ebeveyni, çalışma yolu ve dijital imzası doğrulanmadıkça güvenilir sayılamaz.
