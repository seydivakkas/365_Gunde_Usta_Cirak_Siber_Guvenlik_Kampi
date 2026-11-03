# Gün 146: IAM Yaşam Döngüsü JML (Joiner, Mover, Leaver) ve Kurumsal Kimlik Güvenliği

**Usta-Çırak Derinlemesine Teknik Dersi**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Özel Lisans — Tüm Hakları Saklıdır.*

---

## 🧭 Bölüm 1: Giriş ve Kavramsal Çerçeve (Usta Dersi)

> **Usta:** Evlat, siber güvenlikte saldırganların en çok sevdiği şey nedir bilir misin? Sıfır gün (zero-day) açıkları değil; şirketlerin unuttuğu, terk edilmiş, yetkileri birikmiş ve kapatılmamış eski çalışan hesaplarıdır!
>
> Bir kuruma her gün onlarca kişi girer (**Joiner**), departman veya pozisyon değiştirir (**Mover**) ya da istifa edip ayrılır (**Leaver**). Eğer İnsan Kaynakları (İK) sistemindeki bu hareketler BT sistemlerine (Active Directory, Microsoft Entra ID, AWS, SAP, Salesforce) milisaniyeler seviyesinde ve katı güvenlik kurallarıyla yansıtılmazsa ne olur?
>
> **Çırak:** Usta, ayrılan bir satış müdürü 6 ay sonra şirketin VPN'ine eski şifresiyle girip müşteri veritabanını indirebilir! Ya da finans departmanından BT'ye geçen bir çalışan, hem muhasebede fatura kesme yetkisini hem de sunucularda root yetkisini elinde tutmaya devam eder!
>
> **Usta:** Aynen öyle! İşte bu felaketlerin önüne geçen disipline **IAM Yaşam Döngüsü (JML - Joiner, Mover, Leaver)** diyoruz. Bugün seninle; yetki birikimini (**Privilege Creep**), yetim hesapları (**Orphan Accounts**), görevler ayrılığı (**Separation of Duties - SoD**) ihlallerini ve SCIM tabanlı modern kimlik mutabakatını en ince detayına kadar inceleyeceğiz.

---

## 🏛️ Bölüm 2: JML Yaşam Döngüsünün Üç Temel Direği

```text
+-----------------------------------------------------------------------------------+
|               OTORİTER VERİ KAYNAĞI (HR / İK SİSTEMİ: Workday / SAP)              |
+-----------------------------------------+-----------------------------------------+
                                          |
                JML Olay Tetikleyici (SCIM / Webhook / Event Bus)
                                          |
      +-----------------------------------+-----------------------------------+
      |                                   |                                   |
      v                                   v                                   v
+-------------------+           +-------------------+           +-------------------+
|    1. JOINER      |           |     2. MOVER      |           |    3. LEAVER      |
|  (İşe Başlama)    |           |  (Rol Değişimi)   |           |  (İşten Ayrılış)  |
|-------------------|           |-------------------|           |-------------------|
| - İK Kaydı Doğrula|           | - Yeni Rol Ata    |           | - İK Durumu Term. |
| - Birthright Rol  |           | - ESKİ ROLÜ SİL!  |           | - Anında Hesap    |
| - SoD Kontrolü    |           |   (Privilege Creep|           |   Kapatma (AD/Ent)|
| - MFA Zorunlu     |           |    Engelleme)     |           | - Refresh Token   |
| - İlk Girişte     |           | - SoD Çatışma Test|           |   İptali (Revoke) |
|   Parola Sıfırla  |           | - Yönetici Onayı  |           | - Ayrıcalık Sil   |
+-------------------+           +-------------------+           +-------------------+
```

---

## 🧩 Bölüm 3: Joiner (Katılım / Provisioning) Aşaması

Yeni bir personel kuruma katıldığında süreç **asla** bir sistem yöneticisinin rastgele bir kullanıcı oluşturup "Benim hesap gibi yetki ver" demesiyle yürümez. Bu en büyük güvenlik günahıdır!

1. **Otoriter Kaynak (Authoritative Source):**
   - Hesap açılışı yalnızca onaylı İK sisteminden (Workday, SAP SuccessFactors, BambooHR) gelen doğrulanmış kimlik verisiyle tetiklenir.
   - İK'da kaydı bulunmayan hiçbir şahsa hesap açılamaz.
2. **Doğum Hakkı Rolleri (Birthright Entitlements):**
   - Her çalışanın şirket e-postası, kurumsal portal erişimi ve temel iletişim araçları gibi ilk gün sahip olması gereken asgari rollere denir.
3. **Rol Tabanlı Erişim Kontrolü (RBAC):**
   - Kullanıcıya pozisyonuna ve unvanına göre önceden tanımlanmış rol paketi atanır.
4. **İlk Giriş Sertleştirmesi:**
   - İlk oturumda zorunlu parola değişimi bayrağı (`pwdLastSet = 0`).
   - Çok Faktörlü Kimlik Doğrulama (MFA) kaydı için kısıtlı bir kayıt penceresi (FIDO2 / TOTP).
   - Başlangıç rolleri üzerinde SoD (Görevler Ayrılığı) matris kontrolü.

---

## 🔄 Bölüm 4: Mover (Değişim) ve "Privilege Creep" Tehdidi

Kurum içinde en çok ihmal edilen ve en yüksek riski üreten aşama **Mover** aşamasıdır.

### Privilege Creep (Yetki Birikimi / Yetki Tortusu) Nedir?
Personel çağrı merkezinde işe başlar -> CRM yetkisi alır. 2 yıl sonra Finans'a geçer -> Muhasebe yetkisi alır, ama çağrı merkezi yetkisi silinmez. 2 yıl sonra Bilgi İşlem'e geçer -> Domain Admin yetkisi alır, eski yetkileri hala durur!
Sonuç: Tek bir kullanıcının elinde şirketin tüm veritabanlarını, finans kayıtlarını ve müşteri çağrılarını görebilen bir "Süper Canavar" hesap oluşur.

### Mover Sürecinde Güvenlik Kuralı:
1. **Delta Analizi ve Eski Rollerın İptali:**
   - Yeni departmana ait roller verilmeden önce, eski departmana ait tüm özgül roller **otomatik olarak geri alınmalıdır (revoke)**.
2. **Görevler Ayrılığı (Separation of Duties - SoD):**
   - Yeni verilen roller ile elde tutulacak roller arasında zehirli kombinasyonlar (**Toxic Combinations**) denetlenir.
   - *Örnek:* SAP'ta fatura oluşturan (`Invoice_Create`) ile banka havalesini onaylayan (`Payment_Approve`) yetkisi asla aynı kişide birleştirilemez (SOX 404 / Dolandırıcılık Önleme).
3. **Erişim Sertifikasyonu (Access Certification / Recertification):**
   - Yöneticiler periyodik olarak (en az 6 ayda bir) personellerinin üzerindeki tüm yetkileri tek tek gözden geçirip "Gereklidir" veya "Geri Alınsın" şeklinde onaylamak zorundadır.

---

## 🚪 Bölüm 5: Leaver (Ayrılma / Deprovisioning) ve Yetim Hesaplar

Bir personelin şirketle ilişiği kesildiğinde (istifa, fesih, sözleşme sonu), zaman saniyelerle ölçülür.

### 1. Yetim Hesap (Orphan Account) ve Hayalet Hesap (Ghost Account)
- **Yetim Hesap (Orphan Account):** İK sisteminde `TERMINATED` olmuş ancak hedef sistemlerde (AD, AWS, VPN) unutulduğu için hala `ACTIVE` durumda bekleyen hesaptır.
- **Hayalet Hesap (Ghost Account):** İK sisteminde kimlik kaydı dahi bulunmayan, eski yöneticilerin arka kapı olarak açtığı sahipsiz hesaplardır.

### 2. Anında Deprovisioning Kontrol Listesi:
- **Active Directory / LDAP:** Hesabı derhal pasife al (`Disable-ADAccount`), parolayı rastgele 64 karakter yap, tüm hassas gruplardan (Domain Admins, Remote Desktop vb.) çıkar, `Disabled_Users` OU'suna taşı.
- **Bulut / Entra ID / Okta:** Tüm aktif oturumları ve OAuth/OIDC yenileme jetonlarını anında iptal et (`Revoke-MgUserAllRefreshToken`). Kullanıcı oturum açmış olsa bile token iptal edildiğinde dakikalar içinde bağlantısı koparılır.
- **VPN & Ağ Sertifikaları:** 802.1X ve VPN istemci sertifikalarını CRL (Certificate Revocation List) listesine ekle.
- **Fiziksel Kart ve Tokenlar:** Kartlı geçiş kapı yetkilerini ve donanım tokenlarını dondur.

---

## 🛠️ Bölüm 6: SCIM ve Modern Kimlik Entegrasyonu

Modern mimarilerde JML süreçleri el ile yapılmaz; **SCIM 2.0 (System for Cross-domain Identity Management - RFC 7643 & RFC 7644)** protokolü ile otomatikleştirilir.

- İK sisteminde bir personelin durumu `Terminated` olduğu an:
  1. İK sistemi SCIM API üzerinden Entra ID veya Okta'ya `PATCH /Users/{id} {"active": false}` isteği yollar.
  2. Kimlik sağlayıcı (IdP), bağlı olduğu SaaS uygulamalarına (Slack, Salesforce, GitHub) anında SCIM çağrısı yaparak kullanıcının oturumunu kapatır ve hesabını dondurur.
  3. Süreç uçtan uca insansız ve ortalama 30 saniye içinde tamamlanır!

---

## 🎓 Usta Öğüdü ve Altın Kural

> **"Kullanıcıya yetki vermek cömertlik değil, kurumsal risk yüklenmektir. Bir çalışanın unvanı değiştiğinde eski anahtarlarını teslim almadan yeni anahtarlarını verirsen, kapıda nöbet tutmanın hiçbir anlamı kalmaz!"**
