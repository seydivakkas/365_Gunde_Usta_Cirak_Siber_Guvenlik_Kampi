# Gün 125: Mini Proje 17 — Güvenli Kimlik ve Rol Prototipi (Week 18 Capstone)

> **Usta-Çırak / Hoca Dersi: Hafta 18 Entegrasyon ve Sentez Başyapıtı**  
> *"Evlat; bir kaleyi ne kadar yüksek surlarla kuşatırsan kuşat, kapıdaki muhafız dostla düşmanı ayırt edemiyorsa ya da nöbetçi kulübesi rüşvet veya hileyle düşüyorsa kalen düşmüştür. Bu hafta tehdit modellemeden fail-safe mimarisine, savunma derinliğinden sırlar kasasına kadar öğrendiğin her taşı birleştireceksin. İşte şimdi, kurumsal ölçekte kimliğin, rollerin ve yetkilerin aşılmaz kalesini inşa ediyoruz."*

---

## 1. Giriş ve Büyük Resim: Hafta 18 Sentezi

Hafta 18 boyunca modern siber güvenlik mimarisinin beş temel sütununu inşa ettik:
1. **Gün 120 (STRIDE Tehdit Modellemesi):** Sistemin her bir bileşeninde kimlik sahteciliği (Spoofing), veri manipülasyonu (Tampering), inkar edilemezlik (Repudiation), bilgi ifşası (Information Disclosure), hizmet reddi (DoS) ve yetki yükseltme (Elevation of Privilege) tehditlerini modelledik.
2. **Gün 121 (Risk Skorlama ve Kontrol Seçimi):** Nitel ve nicel (SLE, ARO, ALE, ROSI) risk analiziyle hangi kontrollerin maliyet-etkin olduğunu matematiksel olarak belirledik.
3. **Gün 122 (Savunma Derinliği):** 7 katmanda (Fiziksel, Çevre, Ağ, Host, Uygulama, Veri, İnsan) 5 kontrol tipini harmanlayarak tek nokta arızalarını (SPoF - CWE-1008) ve kör noktaları (CWE-653) ortadan kaldırdık.
4. **Gün 123 (Güvenli Varsayılanlar ve Fail-Safe):** Saltzer-Schroeder (1975) ilkelerine dayalı "Default-Deny" ve "Fail-Secure" (CWE-636) prensiplerini kod seviyesinde zorunlu kıldık.
5. **Gün 124 (Secrets Yönetimi):** Çevre değişkenleri, donanım/yazılım kasaları, zarf şifreleme ve log maskeleme (CWE-532) ile kimlik sırlarını koruma altına aldık.

**Mini Proje 17**, tüm bu kuramsal ve pratik prensipleri tek bir kurumsal motor bünyesinde sentezler: **Güvenli Kimlik ve Rol Yönetim Prototipi (Secure Identity & Role Prototype)**.

```
+-----------------------------------------------------------------------------------+
|               HAFTA 18: GÜVENLİK MİMARİSİ VE KİMLİK SENTEZİ                      |
+-----------------------------------------------------------------------------------+
|  [Gün 120: STRIDE]      --> Tehditleri Belirle (Spoofing, Elevation of Privilege) |
|  [Gün 121: Risk/Kontrol]--> Kontrol Önceliğini Belirle (NIST AC-2 / AC-6)        |
|  [Gün 122: Savunma Der.]--> Katmanlı Doğrulama (PEP, PDP, Token, MFA)             |
|  [Gün 123: Fail-Safe]   --> Default-Deny & Altyapı Çöküşünde Fail-Closed          |
|  [Gün 124: Secrets Mgt] --> PBKDF2 Tuzlama, Kriptografik Token, CWE-532 Maskeleme |
|                                       ||                                          |
|                                       \/                                          |
|  [GÜN 125: CAPSTONE]    --> GÜVENLİ KİMLİK VE ROL PROTOTİPİ MOTORU                 |
+-----------------------------------------------------------------------------------+
```

---

## 2. Kimlik ve Erişim Mimarisi Temelleri (IAM / AAA)

Kurumsal bir IAM (Identity & Access Management) mimarisi **AAA Çerçevesi** üzerine oturur:
- **Authentication (Kimlik Doğrulama):** "Sen kimsin ve bunu nasıl kanıtlarsın?" (Bildiğin bir şey, sahip olduğun bir şey, olduğun bir şey).
- **Authorization (Yetkilendirme):** "Kim olduğunu biliyorum; peki bu kaynağa bu eylemi yapma hakkın var mı?"
- **Accounting / Auditing (Denetim ve İzlenebilirlik):** "Kimin neyi, ne zaman, hangi bağlamda yaptığının inkar edilemez kütüğü nerede?"

### 2.1. PBKDF2-HMAC-SHA256 ile Parola Güvenliği (CWE-521 / CWE-307)
Asla ve asla ham parolaları veya zayıf özetleri (MD5, SHA-1) saklamayız. NIST SP 800-63B standardı uyarınca:
1. **Asgari Uzunluk:** En az 12 karakter.
2. **Kriptografik Tuzlama:** 16-byte (128-bit) CSPRNG tuzu (`secrets.token_bytes(16)`), gökkuşağı tablolarını (rainbow tables) geçersiz kılar.
3. **İterasyon Sayısı:** PBKDF2-HMAC-SHA256 ile en az 100.000 döngü, donanım destekli kaba kuvvet (GPU/ASIC) maliyetini katlar.
4. **Zamanlama Koruması (Constant-Time Compare):** Parola hash karşılaştırmasında `hmac.compare_digest` kullanılarak yan kanal zamanlama atakları (Timing Attacks - CWE-208) engellenir.
5. **Kaba Kuvvet Koruması (Lockout):** 5 ardışık başarısız girişte hesap kilitlenir (`is_locked = True`).

---

## 3. Yetkilendirme Modelleri ve Görevler Ayrılığı (SoD)

### 3.1. Hiyerarşik Rol Tabanlı Erişim Denetimi (Hierarchical RBAC)
Basit düz (flat) RBAC modelinde yüzlerce kullanıcıya yüzlerce rol atanması "rol patlamasına" (role explosion) yol açar. Hiyerarşik RBAC modelinde roller bir yönlü asiklik graf (DAG) oluşturur:
- `guest` rolü kamuya açık kaynakları okur (`public:read`).
- `employee` rolü `guest`'i miras alır ve kendi profil izinlerini ekler (`profile:read`, `profile:edit`).
- `manager` rolü `employee`'yi miras alır ve bütçe/onay yetkileri ekler.
- `super_admin` rolü tüm alt rolleri miras alır ve joker yetki (`system:*`) taşır.

> [!WARNING]
> **Döngüsel Rol Mirası Tehlikesi (CWE-674):** Rol hiyerarşisinde `Role A -> Role B -> Role A` şeklinde döngü kurulursa, yetki çözümleme algoritmaları sonsuz özyinelemeye girerek Stack Overflow veya CPU tükenmesine yol açar. Prototipimiz `_is_descendant` graf taraması ile döngüleri tespit edip anında `CircularRoleHierarchyError` fırlatır.

### 3.2. Statik Görevler Ayrılığı (Static Separation of Duties - Static SoD - CWE-863)
İç dolandırıcılığı ve suiistimali önlemenin bir numaralı kuralı: **Tek bir kişi kritik bir sürecin hem hazırlayıcısı hem de onaylayıcısı olamaz.**
- `payment_maker`: Ödemeyi hazırlar, taslak oluşturur.
- `payment_checker`: Ödemeyi denetler, bankaya iletim onayını verir.

Prototip motorumuzda bu iki rol "zehirli rol çifti" (`toxic_role_pairs`) olarak tanımlanır. Bir kullanıcıya veya aynı oturuma bu iki rol birden verilmeye çalışıldığında motor işlemi anında durdurur ve `SeparationOfDutyConflictError` üretir.

---

## 4. Modern Savunma Mekanizmaları

### 4.1. Adım Yükseltme Doğrulaması (Step-Up MFA - CWE-308)
Kullanıcı normal işlemlerini (e-posta okuma, profil güncelleme) standart parola ile yapabilir. Ancak kritik bir işlem yapılacağı zaman (örneğin sunucu yeniden başlatma `system:reboot`, veritabanı yedeği alma veya yüksek meblağlı para transferi), oturumun ikinci bir faktörle doğrulanmış olması şart koşulur. Prototipimiz, `requires_mfa=True` işaretli rolleri veya `critical_action` bağlamını tespit ettiğinde token üzerinde `mfa_verified` bayrağını denetler; eksikse `StepUpMFARequiredError` ile işlemi keser.

### 4.2. Saltzer-Schroeder: Fail-Safe Defaults ve Fail-Secure (CWE-636)
1. **Default-Deny:** Bir kullanıcı açıkça izin verilmemiş hiçbir kaynağa erişemez. Eşleşme yoksa karar daima `DENY`'dir.
2. **Fail-Secure Arıza İzolasyonu:** Yetkilendirme kararı alınırken harici kimlik dizini (LDAP/Active Directory), veritabanı veya MFA sağlayıcısı zaman aşımına uğrar ya da çökerse, sistem "açık kapı" (fail-open) bırakmaz. Hata anında `simulate_failure` yakalanır ve kapılar derhal kilitlenerek `DENY` kararı verilir.

### 4.3. Maskelenmiş Denetim Günlüğü (Audit Logging with CWE-532 Masking)
Denetim kütükleri güvenlik olaylarının delilidir; ancak kütüğe düz metin parola veya oturum token'ı yazılırsa günlük dosyasının kendisi bir sızıntı kaynağına dönüşür. Prototip motorumuz `mask_log_message` filtresi ile tüm parolaları ve aktif 32-byte tokenları otomatik olarak `[REDACTED_SENSITIVE_DATA]` etiketiyle sansürler.

---

## 5. Çırağa Usta Öğüdü

Evlat, bugün yazdığın kod sadece bir script değil; bir bankanın, bir savunma sanayii firmasının veya bir e-ticaret devinin kimlik omurgasının minyatür prototipidir:
1. Asla "Kullanıcı zaten giriş yaptı, yetkilendirmeyi sonra kontrol ederiz" deme. Kimlik doğrulama sadece kapıyı açar; hangi odalara gireceğini yetkilendirme belirler.
2. Asla arıza durumunda kullanıcı deneyimini güvenliğin önüne koyma. "Veritabanı çöktü, bari herkes geçsin" demek intihardır; her zaman Fail-Secure kal.
3. Rolleri hiyerarşik tut ama döngülere karşı tetikte ol. SoD kurallarını mimarinin en başına kazı.
