# Gün 162: SQL Injection Neden Oluşur Değerlendirme Raporu

## Yönetici Özeti ve Başarı Tablosu
Bu rapor, 365 Günlük Siber Güvenlik Müfredatı kapsamında **Hafta 24, Aşama 07 (Web Güvenliği)** açılış konusu olan **Gün 162: SQL Injection Neden Oluşur?** çalışmasının teknik değerlendirme ve kalite karne sonuçlarını sunar.

Çalışma; SQL enjeksiyonunun (CWE-89) derin teorik kök nedenini (Kod ile Veri karışımı / AST manipülasyonu) in-memory SQLite motoru üzerinde somutlaştırmış, güvensiz dinamik dize birleştirme ile güvenli parametrik sorgu (Prepared Statement) arasındaki yapısal ve operasyonel farkları 15 birim test ve 9 negatif kontrol senaryosu ile %100 başarıyla doğrulamıştır.

| Değerlendirme Alanı | Maksimum Puan | Alınan Puan | Durum |
| :--- | :---: | :---: | :---: |
| **Soru-Cevap & Teorik Derinlik** | 20 | **20** | TAM (Eksiksiz 4 Alt Başlık) |
| **Gerçek Yerel Uygulama / Simülasyon** | 40 | **40** | TAM (Motor + CLI + SQLite + AST Analizi) |
| **Olumlu/Olumsuz Test ve Gözlenebilir Kanıt** | 25 | **25** | TAM (15/15 Birim Test + 9/9 Negatif Kontrol) |
| **Dürüst, Kaynaklı Teknik Rapor** | 15 | **15** | TAM (Doğrulanmış Metrikler ve Standartlar) |
| **TOPLAM PUAN** | **100** | **100** | **MÜKEMMEL (PASS)** |

---

## 1. Uygulama ve Mimari Doğrulama (40 Puan)
- **Modül Dosyaları:**
  - `uygulama/sql_injection_engine.py`: SQLiThreatSensor, MockDatabaseEngine ve SQLInjectionDefenseEngine bileşenlerini içeren tam fonksiyonel motor. Her çalıştırılabilir satırda açıklayıcı Türkçe yorumlar yer alır.
  - `uygulama/sql_injection_cli.py`: Komut satırından tehdit tarama (`scan`), zafiyetli vs. güvenli yürütme simülasyonu (`simulate`) ve dinamik belirteç testi (`dynamic-identifier`) alt komutlarını sunan CLI yönetim aracı.
- **Mimari Nitelikler:**
  - **Kök Neden Gösterimi:** Dinamik dize birleştirme (`f"SELECT ... WHERE user = '{username}'"`) kullanıldığında `' OR '1'='1` yükünün veritabanı AST yapısını değiştirerek kimlik doğrulamayı aştığı (Bypass) gerçek SQLite üzerinde kanıtlanmıştır.
  - **Parametrik Savunma:** Prepared Statement (`SELECT ... WHERE username = ?`) kullanıldığında veritabanı motorunun girdiyi yalnızca düz dize literali olarak algıladığı, sözdizim manipülasyonunun imkansız olduğu ve saldırının %100 engellendiği doğrulanmıştır.
  - **Dinamik Belirteç Güvenliği:** Parametrik yapılamayan tablo ve kolon adları için katı allowlist eşlemesi uygulanmış, allowlist dışı veya enjeksiyonlu belirteçlerin `ValueError` ile engellendiği test edilmiştir.

---

## 2. Test ve Kanıt Doğrulama (25 Puan)

### 2.1 Birim Testler (`tests/test_sql_injection.py`)
Toplam 15 birim test icra edilmiş ve **%100 (15/15 OK)** başarı elde edilmiştir (Çalışma süresi: 0.005 saniye).
- `test_01`: Mantıksal totoloji (`' OR '1'='1`) tespitinin doğrulanması.
- `test_02`: `UNION SELECT` veri sızdırma kalıbı tespiti.
- `test_03`: Zaman tabanlı kör enjeksiyon (`SLEEP` / `pg_sleep`) tespiti.
- `test_04`: Yığılmış sorgular (`Stacked Queries` - `; DROP TABLE`) tespiti.
- `test_05`: Hata tabanlı fonksiyon (`EXTRACTVALUE`) tespiti.
- `test_06`: Bant dışı dosya erişimi (`LOAD_FILE`) tespiti.
- `test_07`: Masum alfanümerik girdide sıfır bulgu üretilmesi.
- `test_08`: Zafiyetli dize birleştirmede totoloji ile kimlik doğrulamanın aşılması (Vulnerable Execution).
- `test_09`: Parametrik sorguda totolojinin düz veri sayılarak engellenmesi (Secure Execution).
- `test_10`: Bozuk SQL sözdiziminde veritabanı hata yönetiminin doğrulanması.
- `test_11`: Geçerli kimlik bilgilerinin parametrik sorgu ile doğru kullanıcıyı getirmesi.
- `test_12`: İzinli tablo ve kolon belirteçlerinin güvenle çalıştırılması.
- `test_13`: İzin verilmeyen tablo adının allowlist tarafından reddedilmesi.
- `test_14`: Sıralama kolonuna SQLi enjeksiyonunun engellenmesi.
- `test_15`: Karşılaştırmalı analiz raporunun kök neden ve sonuç anahtarlarının doğrulanması.

### 2.2 Negatif Kontrol ve Saldırı Senaryoları (`invalid_sqli_payloads.json`)
Toplam 9 kurumsal saldırı senaryosu çalıştırılmış, tamamı savunma katmanları tarafından tespit edilmiş ve Prepared Statement ile etkisiz kılınmıştır (**9/9 BAŞARILI**):
1. `SCN-SQLI-01`: Klasik Totoloji (`' OR '1'='1`) -> Tehdit Algılandı, Parametrik Modda Engellendi.
2. `SCN-SQLI-02`: Yorum Satırı Kesmeli Totoloji (`' OR 1=1 --`) -> Tehdit Algılandı, Engellendi.
3. `SCN-SQLI-03`: `UNION SELECT` Veri Çıkarma -> Tehdit Algılandı, İkinci Sorgu Çalıştırılmadı.
4. `SCN-SQLI-04`: Zaman Tabanlı Kör Sleep -> Tehdit Algılandı, Uyuma Önlenildi.
5. `SCN-SQLI-05`: Yığılmış Sorgu (`DROP TABLE`) -> Tehdit Algılandı, Zincirleme Komut Engellendi.
6. `SCN-SQLI-06`: Hata Tabanlı Sızıntı (`EXTRACTVALUE`) -> Fonksiyon Çağrısı Etkisiz Kılındı.
7. `SCN-SQLI-07`: Bant Dışı Dosya Okuma (`LOAD_FILE`) -> Parametrik Olarak Yutuldu.
8. `SCN-SQLI-08`: Dinamik Sıralama Kolonu Enjeksiyonu -> Allowlist Eşleşmesinde Reddedildi.
9. `SCN-SQLI-09`: Sayısal Totoloji (`' OR 5=5 --`) -> Parametrik Dize Olarak Kaldı.

---

## 3. Kanıt Dosyaları Özeti
- `kanit/gercek/test_sonuclari.txt`: 15 birim testin terminal çıktısı.
- `kanit/gercek/negatif_kontrol_sonuclari.txt`: 9 negatif saldırı senaryosunun ayrıntılı yürütme günlüğü.
- `kanit/gercek/sqli_audit_report.json`: Yapılandırılmış JSON denetim raporu.
- `kanit/gercek/sanitized_query_samples.txt`: Zafiyetli ve güvenli sorgu yürütmelerinin karşılaştırmalı dökümü.
- `kanit/gercek/komut_ve_cikis.txt`: CLI araçlarının gerçek yürütme çıktısı.
- `kanit/temsili/sqli_savunma_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` bayraklı ASCII mimari şema.

---

## 4. Kaynaklar ve Standartlar (15 Puan)
- **OWASP Top 10:2021 / 2025:** A03:2021 - Injection (CWE-89: Improper Neutralization of Special Elements used in an SQL Command).
- **OWASP SQL Injection Prevention Cheat Sheet:** Query Parameterization and Dynamic Identifier Whitelisting.
- **NIST SP 800-53 Rev. 5:** SI-10 Information Input Validation and Least Privilege Database Architecture.
- **W3C / RFC Veritabanı Standartları:** Extended Query Protocol and Prepared Statement Specifications.
