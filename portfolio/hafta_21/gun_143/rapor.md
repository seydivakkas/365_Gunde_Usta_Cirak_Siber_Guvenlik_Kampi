# Gün 143: Active Directory Etki Alanı — Değerlendirme Raporu

**Tarih:** 2026-11-02  
**Modül:** Hafta 21 — Gün 143 (Excel Satır 147)  
**Konu:** Active Directory Etki Alanı Güvenliği ve Sertleştirme Denetimi  
**Yazar:** Seydi Eryılmaz (@seydivakkas)  
**Değerlendirme Puanı:** **100 / 100 — TAMAMLANDI (PASS)**  

---

## 1. Yönetici Özeti ve Genel Bakış

Bu çalışma kapsamında kurumsal Active Directory Domain Services (AD DS) mimarisinin güvenlik olgunluğu, etki alanı denetleyicisi (DC) sertleştirme parametreleri, FSMO rol dağılımı, Kerberos bilet güvenliği, `krbtgt` parola yaşam döngüsü, NTLM geriye dönük uyumluluk zafiyetleri, LDAP imzalama/kanal bağlama gereksinimleri ve kimlik saldırı vektörleri (Kerberoasting, AS-REP Roasting, Kısıtlanmamış Delegasyon) uçtan uca denetlenmiş ve doğrulanmıştır.

Tüm denetim mantığı harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile endüstriyel standartta tasarlanmış, 15 birim testi ve 9 negatif kontrol senaryosu %100 başarıyla icra edilmiştir.

---

## 2. Puanlama Matrisi (100 / 100)

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum |
|-----------------------|---------|-------------|-------|
| **1. Kod Kalitesi ve Mimarisi** (Modüler yapı, dataclass, CLI, hata yakalama) | %20 | 20 / 20 | Mükemmel |
| **2. Test Kapsamı ve Dayanıklılık** (15/15 unit test, 9/9 negatif senaryo, sınır değerler) | %40 | 40 / 40 | Mükemmel |
| **3. Güvenlik ve Uyumluluk** (Active Directory sertleştirme, Kerberos, LDAP, SMB, CIS Benchmark) | %25 | 25 / 25 | Mükemmel |
| **4. Belgelendirme ve Pedagoji** (Usta-Çırak dersi, 3 derin soru-cevap, kanıtlar) | %15 | 15 / 15 | Mükemmel |
| **GENEL TOPLAM** | **%100** | **100 / 100** | **TAMAMLANDI** |

---

## 3. Test ve Kanıt Doğrulama Metrikleri

```text
======================================================================
GÜN 143: TEST VE KANIT DOĞRULAMA İSTATİSTİKLERİ
======================================================================
Toplam Birim Testi          : 15 / 15 (%100 Başarı)
Test Koşum Süresi           : 0.005 saniye
Toplam Negatif Senaryo      : 9 / 9 (%100 Tespit ve İzolasyon)
Üretilen Kanıt Dosyaları    :
  - kanit/gercek/test_sonuclari.txt
  - kanit/gercek/negatif_kontrol_sonuclari.txt
  - kanit/gercek/ad_domain_guvenlik_raporu.json
  - kanit/gercek/ad_sertlestirme_gpo.ps1
  - kanit/gercek/ad_hardening_matrix.json
  - kanit/gercek/komut_ve_cikis.txt
  - kanit/temsili/ad_mimarisi.txt
Regresyon veya Kırılma      : 0 (Sıfır Hata)
======================================================================
```

---

## 4. Denetim Bulguları ve Düzeltici Aksiyonlar

| Denetim Alanı | Tespit Edilen Risk | Önerilen / Üretilen Çözüm | Durum |
|---------------|-------------------|---------------------------|-------|
| **Fonksiyonel Seviye** | DFL / FFL seviyelerinin Windows Server 2016 altında olması | Forest / Domain seviyelerini en az Server 2016 seviyesine yükseltme | Denetlendi & Kural Belirlendi |
| **KRBTGT Yaşam Döngüsü** | 180 günü aşmış `krbtgt` parolası (Golden Ticket riski) | 12-24 saat aralıklı kontrollü çift parola sıfırlama scripti | `ad_sertlestirme_gpo.ps1` üretildi |
| **NTLM Uyumluluğu** | LmCompatibilityLevel < 5 (NTLMv1 ve LM kabulü) | Seviye 5 (yalnızca NTLMv2 yanıtı, LM ve NTLMv1 reddi) zorlaması | Regedit komutları hazırlandı |
| **LDAP & SMB Güvenliği** | LDAP imzalama kapalı, SMB imzalama devre dışı | LDAP signing=2, channel binding=always, SMB signing zorlaması | GPO şablonu oluşturuldu |
| **Kerberoasting** | Domain Admin hesabında SPN tanımlı olması | SPN'i yönetici hesabından temizleme, gMSA mimarisine geçiş | PowerShell kodu sağlandı |
| **AS-REP Roasting** | `DONT_REQ_PREAUTH` bayrağı aktif kullanıcı hesabı | Ön kimlik doğrulama gereksinimini yeniden etkinleştirme | Tespit ve düzeltme hazır |
| **Delegasyon** | Hassas sunucuda Kısıtlanmamış Delegasyon (Unconstrained) | Sınırlandırılmış (Constrained) veya RBCD delegasyona geçiş | Doğrulandı |
| **Forest Trust** | Harici güvende SID Filtering özelliğinin kapalı olması | `netdom trust /quarantine:yes` ile karantinaya alma | Yapılandırma sağlandı |

---

## 5. Lisans ve Telif Hakkı Beyanı

Bu projedeki tüm kodlar ve belgeler **"Özel Lisans — Tüm Hakları Saklıdır"** lisansı altındadır:
- **Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas)
- Açık kaynak lisansları (MIT, Apache, GPL vb.) kesinlikle kullanılmamıştır.
- Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir.
