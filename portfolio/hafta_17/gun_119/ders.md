# Hafta 17 / Gün 119: Mini Proje 16 — Rol Tabanlı Erişim Simülatörü — Usta-Çırak Hoca Dersi

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Eğitim Modeli:** Usta-Çırak / Hoca Dersi Pedagojisi  
**Proje:** Hafta 17 Capstone — Kurumsal RBAC Simülatörü ve Politika Doğrulama Motoru  

---

## 1. Atölye Sohbeti: "Ustam, Tüm IAM Haftasını Bir Simülatörde Nasıl Taçlandırıyoruz?"

**Çırak:**  
"Ustam, geride bıraktığımız 6 günde Kimlik ve Erişim Yönetimi'nin (IAM) en derin sularına daldık:  
- **Gün 113:** Parola tuzlama (salt), PBKDF2 ve hesap kilitlemeyle kimlik doğrulama ile yetkilendirme ayrımını yaptık.  
- **Gün 114:** FIDO2 WebAuthn ile Evilginx2 benzeri AiTM ters vekil phishing saldırılarını kriptografik olarak çökerttik.  
- **Gün 115:** RFC 7636 PKCE ile kod yakalama saldırılarını durdurduk, OIDC ile federe kimliği çözdük.  
- **Gün 116:** JWT'de `alg: none` ve algorithm confusion açıklarını katı anahtar doğrulamasıyla mühürledik.  
- **Gün 117:** NIST RBAC ve ABAC'ı birleştirerek rol patlaması ve IDOR açıklarını kapattık.  
- **Gün 118:** Sıfır Güven (Zero Trust) ve En Az Ayrıcalık (PoLP) ile kalıcı admin hesaplarını tarihe gömdük.  

Şimdi bugün, Hafta 17'nin zirvesinde **Mini Proje 16: Rol Tabanlı Erişim Simülatörü** geliştireceğiz. Bir simülatör inşa etmek bize sahada ne kazandırır?"

**Usta:**  
*(Keyifle gülümser, tahtanın başına geçer)*  
"Aferin evlat! Bütün bu taşları yerine oturttun.  
Sahada bir kurumsal güvenlik mimarının en büyük korkusu nedir bilir misin?  
Canlı üretim ortamında (Production) yetki değişikliği yaparken ya kritik bir servisi çökerterek şirketi durdurmak ya da farkında olmadan bir personele aşırı yetki verip dolandırıcılığa kapı aralamaktır!

Bir uçak pilotu, gerçek yolcuları bindirmeden önce yüzlerce saat uçuş simülatöründe acil durum çalışır.  
İşte bugün inşa ettiğimiz **Mini Proje 16**, güvenlik mühendislerinin **'Siber Güvenlik Uçuş Simülatörü'**dür!  
Bu simülatör ile canlı sistemlere dokunmadan önce:
1. Rol hiyerarşisinde döngüsel bir kilitlenme (Circular Dependency) var mı?
2. Bir personele atanmış roller Statik Görevler Ayrılığı (SSD) kuralını deliyor mu?
3. Personel oturum açtığında çatışan rolleri (DSD) aynı anda aktifleştirebiliyor mu?
4. Kullanıcı üzerinde zamanla gereksiz yetkiler birikmiş mi (Privilege Creep)?
5. 10.000 işlem simüle edildiğinde hangi kurallar izin veriyor, hangi kurallar engelliyor?  
Tüm bu soruları saniyeler içinde, matematiksel kesinlikle analiz edeceğiz."

---

## 2. Simülatörün Mimari Tasarımı: NIST Core & Hierarchical RBAC

**Usta:**  
"Simülatörün merkezinde üç temel bileşen yer alır:

```
┌────────────────────────────────────────────────────────┐
│             RBAC SİMÜLATÖR MOTORU MİMARİSİ            │
│                                                        │
│  [Rol Miras Grafı (DAG)] ────► [Döngü Denetleyicisi]   │
│           │                           │                │
│           ▼                           ▼                │
│  [Miraslı İzin Çözümleyici] ──► [SSD / DSD Denetimi]   │
│           │                           │                │
│           ▼                           ▼                │
│  [Kullanıcı & Oturum] ──────► [Erişim Karar Motoru]    │
│                                       │                │
│                                       ▼                │
│                             [Simülasyon Karnesi]       │
└────────────────────────────────────────────────────────┘
```

### A. Yönlü Döngüsüz Çizge (DAG) ve Döngü Koruması (CWE-674)
Rol hiyerarşisi bir ağaç değil, bir Yönlü Döngüsüz Çizgedir (Directed Acyclic Graph - DAG).  
Bir üst rol, birden fazla alt rolü miras alabilir (`finance_director -> accountant`, `accountant -> employee`).  
Ancak bir çırak yanlışlıkla `employee` rolüne `finance_director` rolünü miras verirse ne olur?  
Sonsuz özyineleme (Infinite Recursion) başlar ve sistem çöker! (CWE-674).  
Simülatörümüz, her yeni hiyerarşi bağı eklendiğinde **Derinlemesine Arama (DFS)** ile döngü kontrolü yapar. Eğer bir alt rol kendi atasına bağlanmaya çalışılırsa derhal `RoleHierarchyCycleDetectedError` fırlatır."

---

## 3. Toksik Kombinasyonların Engellenmesi: SSD ve DSD

**Usta:**  
"Kurumsal dolandırıcılıkların %80'i rollerin kötü niyetli veya dikkatsizce bir araya gelmesinden doğar:

1. **Statik Görevler Ayrılığı (SSD - Static Separation of Duties):**  
   - `accountant` (faturayı kesen) ile `cashier` (ödeme emrini bankaya ileten) aynı kişiye kesinlikle atanamaz.  
   - Kullanıcı siciline ikinci rol eklenmek istendiği anda sistem işlemi kilitler ve `StaticSoDViolationError` üretir.

2. **Dinamik Görevler Ayrılığı (DSD - Dynamic Separation of Duties):**  
   - Diyelim ki Ahmet Bey küçük bir şubede hem `sec_officer` (güvenlik denetçisi) hem de `developer` (yazılımcı) rollerine vekaleten sahip olmak zorunda kaldı (SSD esnetildi).  
   - Ancak Ahmet Bey sisteme giriş yaptığında **aynı oturumda (Session) iki şapkayı birden takamaz!**  
   - Ya geliştirici oturumu açıp kod yazacak ya da güvenlik oturumu açıp denetim yapacak. Kendi yazdığı koda kendi güvenlik onayı veremez!  
   - Oturum açılışında çatışan iki rol birden seçilirse sistem `DynamicSoDViolationError` fırlatır."

---

## 4. Yetki Birikimi (Privilege Creep) ve Dinamik Oturum Kapsamı

**Usta:**  
"Bir kurumda 10 yıl çalışan bir personeli hayal et:  
Önce stajyerdi (`intern`), sonra yazılımcı oldu (`developer`), sonra test uzmanı oldu (`qa_tester`), sonra ürün yöneticisi oldu (`product_owner`), en son da şube müdürü oldu (`branch_manager`).  
Eğer eski roller her terfide silinmediyse, bu personelin hesabında 15 farklı rol birikir! Buna **Yetki Birikimi (Privilege Creep - CWE-250)** denir. Personelin hesabı çalındığında saldırgan tüm şirketin anahtarına sahip olur.

Simülatörümüz:
1. Kullanıcı başına azami rol sınırı (örn: 3 veya 4) uygular; sınır aşıldığında alarm verir (`PrivilegeCreepWarningError`).
2. Kullanıcının oturum açarken sahip olduğu rollerin yalnızca o an ihtiyaç duyduğu alt kümesini aktive etmesine izin verir (**Session-Scoped Least Privilege**)."

---

## 5. Ustanın Hafta 17 Değerlendirmesi

> "Çırağım, 17. haftayı muazzam bir başarıyla tamamladın.  
> Kimlik doğrulama kapıyı kimin çaldığını söyler; yetkilendirme ise içeri girenin nereye basabileceğini tayin eder.  
> Yazdığın bu Rol Tabanlı Erişim Simülatörü, bir şirketin yetki haritasını röntgen gibi çeker; gizli çatışmaları, döngüleri ve yetki sızıntılarını canlıya geçmeden önce ortaya çıkarır.  
> Asla unutma: İyi bir güvenlik mühendisi yangın çıktığında söndüren değil; mimariyi simülatörde öyle kusursuz kuran kişidir ki o binada yangın çıkması imkansız olsun!"
