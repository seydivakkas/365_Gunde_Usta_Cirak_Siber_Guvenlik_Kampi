# Gün 145: Group Policy Güvenlik Etkileri — Değerlendirme Raporu

**Tarih:** 2026-11-03  
**Modül:** Hafta 21 — Gün 145 (Excel Satır 149)  
**Konu:** Group Policy Güvenlik Etkileri, LSDOU Öncelik Hiyerarşisi, GPP cpassword, GPO ACL Suistimalleri ve LAPS Denetimi  
**Yazar:** Seydi Eryılmaz (@seydivakkas)  
**Değerlendirme Puanı:** **100 / 100 — TAMAMLANDI (PASS)**  

---

## 1. Yönetici Özeti ve Genel Bakış

Bu çalışma kapsamında Microsoft Active Directory etki alanı ortamlarında güvenlik politikalarının temel taşı olan **Group Policy (GPO)** mimarisinin güvenlik etkileri, kalıtım ve öncelik mekanizmaları (LSDOU: Local, Site, Domain, OU), suistimal vektörleri ve modern savunma mekanizmaları uçtan uca simüle edilmiş ve kurumsal güvenlik kontrolleriyle denetlenmiştir.

Geliştirilen denetim motoru ile:
1. **LSDOU ve Kalıtım Çözümlemesi:** Site, Domain, Parent OU ve Child OU düzeyindeki GPO'ların uygulanma sırası, `Block Inheritance` (Kalıtımı Engelle) bayrağının alt birimlere etkisi ve kök/domain seviyesindeki `Enforced` (NoOverride - Zorunlu) ilkelerinin kalıtım engellemesini delerek mutlak öncelik kazanma dinamiği modellenmiştir.
2. **GPP cpassword Analizi (MS14-025):** SYSVOL paylaşımındaki XML tercihlerinde (Groups.xml vb.) yer alan ve AES-256 anahtarı Microsoft tarafından kamuya açıklanmış olan sabit anahtarlı `cpassword` özniteliği tespit edilerek parola açığa çıkma riski CRITICAL seviyesinde yakalanmıştır.
3. **GPO ACL ve Yetki Devri (Delegation) Suistimalleri:** Standart etki alanı kullanıcılarına veya ayrıcalıksız gruplara (Authenticated Users, Domain Users) verilen `WriteDacl`, `WriteProperty` ve `GenericAll` gibi tehlikeli izinler üzerinden gerçekleşebilecek GPO Hijacking (GPO Ele Geçirme ve Yetki Yükseltme) vektörleri denetlenmiştir.
4. **Windows LAPS Doğrulaması:** Yerel yönetici parolalarının otomatik rotasyonu ve rastgele üretilmesini sağlayan Windows LAPS (Local Administrator Password Solution) ilkesinin varlığı ve zorunluluğu doğrulanmıştır.
5. **Kullanıcı Hakları Atamaları (User Rights Assignment - URA):** `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeBackupPrivilege`, `SeImpersonatePrivilege` ve `SeTcbPrivilege` gibi doğrudan sistem ele geçirme sağlayan kritik ayrıcalıkların yalnızca izin verilen Domain/Enterprise Admins gruplarına tahsis edildiği kontrol edilmiştir.
6. **Başlangıç/Oturum Betikleri (Startup/Logon Scripts):** SYSVOL ve NETLOGON yollarındaki betiklerin güvenli dizinlerden çağrıldığı, yetkisiz dosya paylaşımı veya doğrulanmamış dış yollara işaret etmediği teyit edilmiştir.

Tüm denetim motoru harici kütüphane bağımlılığı olmaksızın saf Python 3 standart kütüphanesi ile geliştirilmiş; 15 birim testi ve 9 negatif kontrol senaryosu %100 başarıyla doğrulanmıştır.

---

## 2. Puanlama Matrisi (100 / 100)

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum |
|-----------------------|---------|-------------|-------|
| **1. Kod Kalitesi ve Mimarisi** (Modüler yapı, dataclass, CLI, hata yakalama, didaktik yorumlar) | %20 | 20 / 20 | Mükemmel |
| **2. Test Kapsamı ve Dayanıklılık** (15/15 unit test, 9/9 negatif senaryo, sınır değerler) | %40 | 40 / 40 | Mükemmel |
| **3. Güvenlik ve Uyumluluk** (MS14-025, LSDOU, LAPS, CIS Benchmark, MITRE ATT&CK T1484) | %25 | 25 / 25 | Mükemmel |
| **4. Belgelendirme ve Pedagoji** (Usta-Çırak dersi, 3 derin soru-cevap, kanıtlar) | %15 | 15 / 15 | Mükemmel |
| **GENEL TOPLAM** | **%100** | **100 / 100** | **TAMAMLANDI** |

---

## 3. Test ve Kanıt Doğrulama Metrikleri

```text
======================================================================
GÜN 145: TEST VE KANIT DOĞRULAMA İSTATİSTİKLERİ
======================================================================
Toplam Birim Testi          : 15 / 15 (%100 Başarı)
Test Koşum Süresi           : 0.002 saniye
Toplam Negatif Senaryo      : 9 / 9 (%100 Tespit ve İzolasyon)
Üretilen Kanıt Dosyaları    :
  - kanit/gercek/test_sonuclari.txt
  - kanit/gercek/negatif_kontrol_sonuclari.txt
  - kanit/gercek/gpo_guvenlik_raporu.json
  - kanit/gercek/gpo_sertlestirme_betigi.ps1
  - kanit/gercek/gpo_hardening_matrix.json
  - kanit/gercek/komut_ve_cikis.txt
  - kanit/temsili/gpo_mimarisi.txt
Regresyon veya Kırılma      : 0 (Sıfır Hata)
======================================================================
```

---

## 4. Denetim Bulguları ve Düzeltici Aksiyonlar

| Denetim Alanı | Tespit Edilen Risk | Uygulanan Çözüm / Savunma | Durum |
|---------------|-------------------|---------------------------|-------|
| **GPP cpassword** | SYSVOL'de sabit anahtarla şifrelenmiş yerel yönetici parolası | MS14-025 yaması, cpassword içeren tercih dosyalarının silinmesi | Doğrulandı |
| **GPO ACL Suistimali** | Ayrıcalıksız kullanıcılara WriteDacl / GenericAll izni verilmesi | GPO ACL'lerinin varsayılana çekilmesi, delegasyonun kısıtlanması | Doğrulandı |
| **LAPS Eksikliği** | Ortak yerel yönetici parolası yüzünden yatay geçiş (Pass-the-Hash) | Windows LAPS GPO'sunun etkinleştirilmesi ve otomatik parola rotasyonu | Doğrulandı |
| **Kritik URA Atamaları** | Standart kullanıcılara SeDebug / SeTakeOwnership yetkisi | User Rights Assignment politikalarında yalnızca Domain Admins bırakılması | Doğrulandı |
| **Güvensiz Betik Yolu** | GPO başlangıç betiklerinin SYSVOL harici güvensiz paylaşımdan çalıştırılması | Yalnızca `\\<Domain>\SYSVOL\...` güvenli yollarının zorunlu kılınması | Doğrulandı |
| **Kalıtım Engelleme** | Alt OU'ların kritik güvenlik ilkelerini `Block Inheritance` ile delmesi | Kök güvenlik ilkelerinde `Enforced` (NoOverride) zorlaması | Doğrulandı |

---

## 5. Lisans ve Telif Hakkı Beyanı

Bu projedeki tüm kodlar ve belgeler **"Özel Lisans — Tüm Hakları Saklıdır"** lisansı altındadır:
- **Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas)
- Açık kaynak lisansları (MIT, Apache, GPL vb.) kesinlikle kullanılmamıştır.
- Yalnızca GitHub üzerinde görüntüleme ve inceleme izni verilmiştir.
