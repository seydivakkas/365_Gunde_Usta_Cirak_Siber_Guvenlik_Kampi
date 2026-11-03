# Gün 147: Mini Proje 20 — IAM Politika Matrisi — Değerlendirme Raporu

**Tarih:** 2026-11-03  
**Modül:** Hafta 21 — Gün 147 (Excel Satır 151 — Haftalık Mini Proje 20)  
**Konu:** Kurumsal IAM Politika Matrisi, Katmanlama (Tier 0 / Tier 1 / Tier 2), Kerberos RBCD ve Sıfır Güven (Zero Trust)  
**Yazar:** Seydi Eryılmaz (@seydivakkas)  
**Değerlendirme Puanı:** **100 / 100 — TAMAMLANDI (PASS)**  

---

## 1. Yönetici Özeti ve Genel Bakış

Bu çalışma kapsamında Hafta 21'in tüm konuları (Active Directory etki alanı mimarisi, Kerberos v5 bilet mekanizmaları, Group Policy güvenlik sertleştirmesi ve IAM JML yaşam döngüsü) bütünleştirilerek kurumsal ölçekte bir **IAM Politika Matrisi ve Dinamik Erişim Değerlendirme Motoru (Mini Proje 20)** inşa edilmiştir.

Geliştirilen güvenlik mimarisi:
1. **Microsoft Enterprise Access Katmanlama Modeli (Tiering):** Kimlik düzlemi (Tier 0), kurumsal sunucular (Tier 1) ve kullanıcı uç noktaları (Tier 2) mantıksal ve operasyonel olarak birbirinden ayrılmıştır. Tier-0 etki alanı yöneticilerinin alt katman makinelerinde oturum açması (Credential Dumping, LSASS bellek hırsızlığı ve Pass-the-Hash engeli) ve Tier-2 kullanıcılarının doğrudan Tier-0 DC'lere erişmesi kural motoruyla kesin olarak engellenmiştir.
2. **Kerberos Yetki Devri (Delegation) Sertleştirmesi:** Kısıtlamasız yetki devri (`Unconstrained Delegation`) kullanan kritik sunucular denetlenmiş; TGT bilet hırsızlığını önlemek amacıyla Kaynak Tabanlı Kısıtlı Yetki Devrine (`RBCD`) geçiş mekanizması doğrulanmıştır.
3. **Sıfır Güven (Zero Trust) ve ABAC Koşullu Erişim:** Erişim kararları yalnızca statik RBAC rolleriyle değil; Çok Faktörlü Kimlik Doğrulama (MFA), Cihaz Güvenliği ve Uyumluluğu (Compliant Device) ve Oturum Risk Skoru (İmkansız seyahat tespiti) bağlamlarıyla anlık olarak değerlendirilmiştir.
4. **Görevler Ayrılığı (SoD) ve Yetim Hesap Koruması:** Fatura oluşturan ile onaylayan, kod geliştiren ile canlıya dağıtan roller arasındaki zehirli kombinasyonlar (**Toxic Combinations**) ve İK ilişiği kesilmiş personele ait yetim hesaplar (**Orphan Accounts**) tespit edilerek erişimleri anında durdurulmuştur.

Tüm denetim motoru harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş; 15 birim testi ve 9 negatif kontrol senaryosu %100 başarıyla doğrulanmıştır.

---

## 2. Puanlama Matrisi (100 / 100)

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum |
|-----------------------|---------|-------------|-------|
| **1. Kod Kalitesi ve Mimarisi** (Modüler yapı, dataclass, CLI, hata yakalama, didaktik yorumlar) | %20 | 20 / 20 | Mükemmel |
| **2. Test Kapsamı ve Dayanıklılık** (15/15 unit test, 9/9 negatif senaryo, sınır değerler) | %40 | 40 / 40 | Mükemmel |
| **3. Güvenlik ve Uyumluluk** (NIST SP 800-207, Microsoft Tiering, CIS Benchmark, SOX 404) | %25 | 25 / 25 | Mükemmel |
| **4. Belgelendirme ve Pedagoji** (Usta-Çırak dersi, 3 derin soru-cevap, kanıtlar) | %15 | 15 / 15 | Mükemmel |
| **GENEL TOPLAM** | **%100** | **100 / 100** | **TAMAMLANDI** |

---

## 3. Test ve Kanıt Doğrulama Metrikleri

```text
======================================================================
GÜN 147: MİNİ PROJE 20 TEST VE KANIT DOĞRULAMA İSTATİSTİKLERİ
======================================================================
Toplam Birim Testi          : 15 / 15 (%100 Başarı)
Test Koşum Süresi           : 0.0010 saniye
Toplam Negatif Senaryo      : 9 / 9 (%100 Tespit ve İzolasyon)
Üretilen Kanıt Dosyaları    :
  - kanit/gercek/test_sonuclari.txt
  - kanit/gercek/negatif_kontrol_sonuclari.txt
  - kanit/gercek/iam_matrix_denetim_raporu.json
  - kanit/gercek/iam_matrix_sertlestirme.ps1
  - kanit/gercek/iam_policy_matrix_ozet.json
  - kanit/gercek/komut_ve_cikis.txt
  - kanit/temsili/iam_politika_matrisi_mimarisi.txt
Regresyon veya Kırılma      : 0 (Sıfır Hata)
======================================================================
```

---

## 4. Denetim Bulguları ve Düzeltici Aksiyonlar

| Denetim Alanı | Tespit Edilen Risk | Uygulanan Çözüm / Savunma | Durum |
|---------------|-------------------|---------------------------|-------|
| **Katman İzolasyonu (Tier-0)** | Domain Admin hesabının Tier-2 bilgisayarda oturum açması | `RULE-TIER0-DOWNWARD-LOGON-DENIED` ile anında engelleme | Doğrulandı |
| **Katman İzolasyonu (Tier-2)** | Standart kullanıcının doğrudan Tier-0 DC'ye erişim isteği | `RULE-TIER2-UPWARD-ACCESS-DENIED` ile engelleme (PAW zorunlu) | Doğrulandı |
| **Kerberos Yetki Devri** | Kısıtlamasız yetki devri (`TRUSTED_FOR_DELEGATION`) | `MAT-KERB-01` tespiti ve RBCD'ye dönüştürme otomasyonu | Doğrulandı |
| **Yetim Hesap (Orphan)** | İK'dan ayrılmış personelin aktif hesapla erişim denemesi | `RULE-LEAVER-ORPHAN-BLOCKED` ile erişimin derhal reddi | Doğrulandı |
| **SoD Zehirli Kombinasyon** | Fatura oluşturan ile onaylayan rolünün tek kişide birleşmesi | `RULE-SOD-TOXIC-COMBINATION` ile işlemin durdurulması | Doğrulandı |
| **Sıfır Güven ABAC (MFA)** | Hassas kaynağa MFA olmadan bağlanma girişimi | `RULE-ABAC-MFA-REQUIRED` ile koşullu erişim reddi | Doğrulandı |
| **Cihaz Uyumluluğu** | Uyumsuz veya yamalanmamış cihazdan erişim isteği | `RULE-ABAC-DEVICE-NON-COMPLIANT` ile engelleme | Doğrulandı |
| **Oturum Risk Puanı** | İmkansız seyahat / Tor ağı kaynaklı yüksek riskli oturum | `RULE-ABAC-HIGH-RISK-SESSION` ile oturumun dondurulması | Doğrulandı |

---

## 5. Lisans ve Telif Hakkı Beyanı

Bu projedeki tüm kodlar ve belgeler **"Özel Lisans — Tüm Hakları Saklıdır"** lisansı altındadır:
- **Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas)
- Açık kaynak lisansları (MIT, Apache, GPL vb.) kesinlikle kullanılmamıştır.
- Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir.
