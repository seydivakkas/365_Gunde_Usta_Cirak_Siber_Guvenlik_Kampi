<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 001 DEĞERLENDİRME VE UYGULAMA RAPORU
## Konu: Siber Güvenlik Nedir ve Neyi Korur? — CIA Üçlüsü ve Temel İlkeler

---

### 1. Beş Satırlık Standart Yönetici Özeti
- **Tarih ve Saat:** 2026-10-26 16:35:00 UTC+03:00
- **Çalışma Ortamı:** Windows 11 Enterprise | Python 3.14 (Standard Library) | PowerShell 7
- **Kısıtlar ve Kapsam:** Dış ağ/IP taraması yapılmamıştır; sentetik yerel okul not verisi kullanılmıştır.
- **Uygulanan Mekanizma:** Rol Tabanlı Erişim (RBAC), SHA-256 Kriptografik Bütünlük, Servis Durumu Doğrulama.
- **Nihai Karar ve Puan:** PASS — 100 / 100 (Eksiksiz Pozitif ve Negatif Kontrol Başarısı)

---

### 2. Kalite Kapısı Puanlama Cetveli (100 Puan Üzerinden)

| Değerlendirme Bileşeni | Tam Puan | Alınan Puan | Durum | Doğrulama Kanıtı |
| :--- | :---: | :---: | :---: | :--- |
| **Soru-Cevap / Anlatım Derinliği** | 20 | 20 | EKSİKSİZ | `ders.md` 7 bölüm + `soru_cevap.md` 4'lü yapı |
| **Uygulama ve Kodlama Kalitesi** | 40 | 40 | EKSİKSİZ | `cia_triad_lab.py` tam çalışır bağımsız kod |
| **Doğrulanabilir Gerçek Kanıt** | 25 | 25 | EKSİKSİZ | `kanit/gercek/` komut çıktısı ve 10/10 test kanıtı |
| **Raporlama ve Kalite Kontrol** | 15 | 15 | EKSİKSİZ | Pozitif/negatif kontrol, sınırlar, 5 satır özet |
| **TOPLAM SKOR** | **100** | **100** | **PASS** | **Kalite Kapısı Aşılmıştır (≥80)** |

---

### 3. Laboratuvar Doğrulama Metrikleri

| Metrik Adı | Ölçülen Değer | Durum |
| :--- | :--- | :--- |
| **Toplam Birim/Entegrasyon Testi** | 10 Test | BAŞARILI |
| **Hata / Başarısızlık / Atlama** | 0 / 0 / 0 | KUSURSUZ |
| **Test Tamamlanma Süresi** | 0.050 saniye | HIZLI / OPTİMİZE |
| **Pozitif Kontroller** | 3/3 (Öğretmen okuma, Öğrenci kendi notu, Sağlam hash) | DOĞRULANDI |
| **Negatif Kontroller** | 4/4 (Misafir engeli, ID'siz öğrenci engeli, Tahrifat tespiti, DoS tespiti) | DOĞRULANDI |

---

### 4. Pozitif ve Negatif Kontrol İncelemesi

#### A. Pozitif Kontroller
1. **Öğretmen Yetkisi:** `SchoolSystemSecurityManager.read_grades("OGRETMEN")` fonksiyonu 5 öğrenci kaydının tamamını başarıyla döndürmüştür.
2. **Öğrenci Kendi Kaydı:** Öğrenci Ali Yılmaz (ID: 101) sorgulandığında sadece kendi not satırı (Vize: 45, Final: 55) dönmüş, diğer öğrencilerin verileri gizlenmiştir.
3. **Bütünlük Doğrulaması:** Dosya SHA-256 özeti referans güvenli özetle tam eşleşmiştir (`2e5462450ae63eab2d21a315636aa3e9a9a82ed85406ec624bc4cff195dc4c2f`).

#### B. Negatif Kontroller (Hata ve Saldırı Engelleme)
1. **Yetkisiz Misafir Engeli:** Misafir kullanıcının kütük okuma isteği `ConfidentialityViolationError` fırlatarak 0. satırda bloke edilmiştir.
2. **Tahrifat Tespiti (Çığ Etkisi):** Ali'nin notu 45'ten 95'e çıkarıldığında SHA-256 özeti baştan aşağı değişmiş (`5e15d0354f3b287b84c153a0f616c93f0b3998d07618cd9aaa2334b09258ae43`), `IntegrityViolationError` üretilerek sistem alarm vermiştir.
3. **Hizmet Kesintisi / Kilit Tespiti:** Sistem kilitlendiğinde yapılan okuma denemesi `AvailabilityViolationError` ile düşürülmüştür.

---

### 5. Güvenlik Sınırları ve Etik Beyanı
Bu laboratuvarda kullanılan tüm veriler, senaryolar ve kodlar izole yerel ortamda üretilmiş sentetik varlıklardır. Hiçbir gerçek kişisel veri (KVKK kapsamı) veya üçüncü taraf ağ hedef alınmamıştır.

**Sonuç:** Gün 001 hedefleri tam başarıyla yerine getirilmiştir.
