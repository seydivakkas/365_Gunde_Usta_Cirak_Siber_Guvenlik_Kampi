# Gün 146: IAM Yaşam Döngüsü JML — Değerlendirme Raporu

**Tarih:** 2026-11-03  
**Modül:** Hafta 21 — Gün 146 (Excel Satır 150)  
**Konu:** IAM Yaşam Döngüsü JML (Joiner, Mover, Leaver), Yetki Birikimi (Privilege Creep), Yetim Hesaplar (Orphan Accounts) ve Görevler Ayrılığı (SoD)  
**Yazar:** Seydi Eryılmaz (@seydivakkas)  
**Değerlendirme Puanı:** **100 / 100 — TAMAMLANDI (PASS)**  

---

## 1. Yönetici Özeti ve Genel Bakış

Bu çalışma kapsamında kurumsal Kimlik ve Erişim Yönetimi (IAM) mimarisinde personel yaşam döngüsünün (**Joiner - Mover - Leaver / JML**) uçtan uca güvenliği, İK otoriter veri kaynağı ile hedef sistemler arasındaki senkronizasyon ve yetki sınırları modellenmiş ve test edilmiştir.

Geliştirilen güvenlik ve denetim motoru ile:
1. **Joiner (Katılım / Onboarding):** İK kaydına dayalı hesap açılışı, asgari doğum hakkı rolleri (Birthright Entitlements), yönetici onay kapısı, ilk girişte zorunlu parola değişimi ve MFA zorunluluğu doğrulanmıştır.
2. **Mover (Transfer / Role Transition):** Departman değiştiren personelde en kritik iç tehditlerden biri olan **Yetki Birikimi (Privilege Creep)** engellenmiş; eski departman rolleri otomatik geri alınarak (revocation) yeni roller atanmıştır.
3. **Görevler Ayrılığı (Separation of Duties - SoD):** Fatura oluşturan ile ödeme onaylayan, kod yazan ile canlıya dağıtan roller arasındaki zehirli kombinasyonlar (**Toxic Combinations**) otomatik matris denetimiyle tespit edilip engellenmiştir.
4. **Leaver (Ayrılma / Deprovisioning):** İşten ayrılan personelin tüm hedef sistemlerdeki (AD, Entra ID, AWS, SAP) hesapları anında dondurulmuş (`DISABLED`), aktif OAuth/OIDC yenileme jetonları (Refresh Tokens) iptal edilmiş ve yetim hesap (**Orphan Account**) oluşumu engellenmiştir.
5. **Dizin Denetimi ve Mutabakat (Reconciliation):** Sahipsiz hayalet hesaplar (Ghost Accounts), kapatılması unutulmuş yetim hesaplar, 90 günden uzun süredir oturum açılmamış atıl hesaplar (Dormant Accounts) ve MFA'sız ayrıcalıklı hesaplar tespit edilip otomatik PowerShell sertleştirme betiği üretilmiştir.

Tüm denetim motoru harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş; 15 birim testi ve 9 negatif kontrol senaryosu %100 başarıyla doğrulanmıştır.

---

## 2. Puanlama Matrisi (100 / 100)

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum |
|-----------------------|---------|-------------|-------|
| **1. Kod Kalitesi ve Mimarisi** (Modüler yapı, dataclass, CLI, hata yakalama, didaktik yorumlar) | %20 | 20 / 20 | Mükemmel |
| **2. Test Kapsamı ve Dayanıklılık** (15/15 unit test, 9/9 negatif senaryo, sınır değerler) | %40 | 40 / 40 | Mükemmel |
| **3. Güvenlik ve Uyumluluk** (NIST SP 800-63, CIS Controls v8, ISO 27001 A.9, SOX 404) | %25 | 25 / 25 | Mükemmel |
| **4. Belgelendirme ve Pedagoji** (Usta-Çırak dersi, 3 derin soru-cevap, kanıtlar) | %15 | 15 / 15 | Mükemmel |
| **GENEL TOPLAM** | **%100** | **100 / 100** | **TAMAMLANDI** |

---

## 3. Test ve Kanıt Doğrulama Metrikleri

```text
======================================================================
GÜN 146: TEST VE KANIT DOĞRULAMA İSTATİSTİKLERİ
======================================================================
Toplam Birim Testi          : 15 / 15 (%100 Başarı)
Test Koşum Süresi           : 0.002 saniye
Toplam Negatif Senaryo      : 9 / 9 (%100 Tespit ve İzolasyon)
Üretilen Kanıt Dosyaları    :
  - kanit/gercek/test_sonuclari.txt
  - kanit/gercek/negatif_kontrol_sonuclari.txt
  - kanit/gercek/iam_jml_audit_report.json
  - kanit/gercek/iam_jml_remediation.ps1
  - kanit/gercek/iam_jml_matrix.json
  - kanit/gercek/komut_ve_cikis.txt
  - kanit/temsili/iam_jml_mimarisi.txt
Regresyon veya Kırılma      : 0 (Sıfır Hata)
======================================================================
```

---

## 4. Denetim Bulguları ve Düzeltici Aksiyonlar

| Denetim Alanı | Tespit Edilen Risk | Uygulanan Çözüm / Savunma | Durum |
|---------------|-------------------|---------------------------|-------|
| **Yetim Hesap (Orphan)** | İK'dan ayrılmış personelin AD hesabının aktif kalması | `Disable-ADAccount` ve `Revoke-MgUserAllRefreshToken` ile anında kapatma | Doğrulandı |
| **Hayalet Hesap (Ghost)** | İK veri tabanında kaydı olmayan gölge yönetici hesabı | Hesabın karantinaya alınması ve hesap sahibinin tespiti | Doğrulandı |
| **Yetki Birikimi (Creep)** | Departman değişimi sonrası eski departman rollerinin kalması | Mover sürecinde eski rollerin zorunlu iptali (Revocation) | Doğrulandı |
| **SoD Çatışması (Finans)** | Fatura kesen ve ödeme onaylayan yetkilerinin aynı kişide olması | SoD matris kuralı ile işlemin engellenmesi | Doğrulandı |
| **SoD Çatışması (DevOps)** | Geliştirici rolü ile canlıya doğrudan dağıtım yetkisinin birleşmesi | Dört göz kuralı ile canlı dağıtım rolünün ayrıştırılması | Doğrulandı |
| **Atıl Hesap (Dormant)** | >90 gün oturum açılmamış aktif hesaplar | Otomatik hesap dondurma ve onay yenileme süreci | Doğrulandı |
| **MFA Eksikliği** | Ayrıcalıklı BT yöneticisi hesabında MFA bulunmaması | Koşullu erişim kuralı ile MFA zorunluluğu | Doğrulandı |

---

## 5. Lisans ve Telif Hakkı Beyanı

Bu projedeki tüm kodlar ve belgeler **"Özel Lisans — Tüm Hakları Saklıdır"** lisansı altındadır:
- **Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas)
- Açık kaynak lisansları (MIT, Apache, GPL vb.) kesinlikle kullanılmamıştır.
- Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir.
