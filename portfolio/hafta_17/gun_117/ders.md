# Hafta 17 / Gün 117: RBAC ve ABAC — Usta-Çırak Hoca Dersi

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Eğitim Modeli:** Usta-Çırak / Hoca Dersi Pedagojisi  
**Konu:** Rol Tabanlı Erişim Kontrolü (NIST RBAC) ve Öznitelik Tabanlı Erişim Kontrolü (NIST ABAC)  

---

## 1. Atölye Sohbeti: "Ustam, 'if user.is_admin' Yazmak Yetmez mi?"

**Çırak:**  
"Ustam, dün JWT ile kimliği kusursuz şekilde doğruladık; belirtecin kime ait olduğunu, süresini ve imzasını doğruladık. Artık iş çok kolay değil mi? Kodun başına `if user.role == 'admin': izin_ver()` yazar geçeriz. Neden kurumsal dünyada herkes RBAC, ABAC, SoD ve XACML gibi karmaşık kavramlardan bahsediyor?"

**Usta:**  
*(Gülümser, çayından bir yudum alır ve beyaz tahtaya bir şema çizmeye başlar)*  
"Evlat, o dediğin `if user.is_admin` yaklaşımı, bir bakkal dükkanını yönetirken işe yarar. Ama 10.000 çalışanı, 50 farklı departmanı, 8 ülkede şubesi olan bir bankayı veya bir hastaneyi yönetmeye kalktığında o tek satırlık kod seni cehennemin ortasına fırlatır!

Düşün bakalım: Bir hastane yazılımındasın. Doktor var, hemşire var, hasta var. Sadece 'Doktor' rolü verirsen ne olur? Kardiyoloji doktoru, Onkoloji servisindeki bir hastanın psikiyatrik geçmişini veya şirket CEO'sunun gizli ameliyat raporunu görebilir mi? Görmemeli!  
Peki mesai saati bittiğinde, evindeki kişisel bilgisayarından acil servis veritabanını indirebilir mi? İndirememeli!  
Peki ameliyatı yapan cerrah, aynı zamanda ameliyat faturasını onaylayan muhasebeci olabilir mi? Asla, dolandırıcılık patlar!

İşte bu yüzden, yetkilendirme (Authorization) kimlik doğrulamadan (Authentication) çok daha çetrefilli bir sanattır. Bugün seninle kaba taneli kapıcı olan **RBAC** ile mikroskopik güvenlik görevlisi olan **ABAC**'ın evliliğini inşa edeceğiz."

---

## 2. NIST ANSI/INCITS 359-2004: Rol Tabanlı Erişim Kontrolü (RBAC)

**Usta:**  
"Önce Amerikan Ulusal Standartlar Enstitüsü'nün (NIST) tanımladığı RBAC modelini anlayalım. RBAC üç temel seviyede incelenir:

```
┌────────────────────────────────────────────────────────┐
│                   HİYERARŞİK RBAC                     │
│                       [Admin]                          │
│                          │                             │
│                          ▼ (Miras Alır)                │
│                      [Manager]                         │
│                          │                             │
│                          ▼ (Miras Alır)                │
│                       [Staff]                          │
│                          │                             │
│                          ▼ (Miras Alır)                │
│                       [User]                           │
└────────────────────────────────────────────────────────┘
```

1. **Çekirdek RBAC (Core RBAC):** Kullanıcılar (Users) rollere, roller de izinlere (Permissions) atanır. Kullanıcıya doğrudan yetki verilmez; araya 'Rol' soyutlaması girer.
2. **Hiyerarşik RBAC (Hierarchical RBAC - RBAC1):** Üst roller, alt rollerin tüm yetkilerini otomatik olarak miras alır. Bir `Manager`, altındaki `Staff` personelinin yapabildiği her şeyi yapabilir. Böylece izin tekrarı önlenir.
3. **Kısıtlı RBAC ve Görevler Ayrılığı (Constrained RBAC / SoD - RBAC2):**
   - **Statik Görevler Ayrılığı (SSD - Static Separation of Duties):** Bir kullanıcıya aynı anda birbirini denetleyen iki zıt rol verilemez! Örneğin: `Purchaser` (Satın Alma Emri Veren) ile `Approver` (Fatura Onaylayan) rollerini aynı kişiye verirsen, kendi kendine fatura kesip şirketi soyabilir (CWE-863).
   - **Dinamik Görevler Ayrılığı (DSD - Dynamic Separation of Duties):** Kullanıcı her iki role sahip olsa dahi, aynı aktif oturumda ikisini birden etkinleştiremez.

### "Rol Patlaması" (Role Explosion) Tehlikesi
**Çırak:**  
"Ustam, madem RBAC bu kadar düzenli, neden ABAC'a ihtiyaç duyuldu?"

**Usta:**  
"Çünkü organizasyon büyüdükçe roller çıldırır evlat!  
Doktora 'Gece Nöbetçisi Kardiyolog', 'Gündüz Nöbetçisi Onkolog', 'A Kliniği Doktoru', 'B Kliniği Doktoru' diye roller açmaya başlarsın. Şirkette 5.000 çalışan varken bir bakarsın 12.000 farklı rol türemiş! Kimin hangi role sahip olduğunu kimse takip edemez hale gelir. Buna literatürde **Role Explosion (Rol Patlaması)** denir."

---

## 3. NIST SP 800-162: Öznitelik Tabanlı Erişim Kontrolü (ABAC)

**Usta:**  
"İşte bu patlamayı çözmek için NIST SP 800-162 standardı ile **ABAC** sahneye çıktı.  
ABAC'ta peşin hükümlü roller yoktur; **bağlamsal öznitelikler (Attributes)** vardır. Yetkilendirme kararı bir mantık denklemi gibi anlık hesaplanır:

$$\text{Karar} = f(\text{Özne}, \text{Kaynak}, \text{Eylem}, \text{Çevre})$$

Bu dört kutuyu zihnine kazı çırağım:

| Bağlam Bileşeni | Örnek Öznitelikler (Attributes) | Güvenlik Anlamı |
|---|---|---|
| **Özne (Subject)** | Departman, Güvenlik Seviyesi (Clearance), Kiracı Kimliği (Tenant_ID), MFA Durumu | İsteği yapan kim ve hangi koşullarda doğrulandı? |
| **Kaynak (Resource)** | Gizlilik Derecesi (Classification), Sahip Departman, Kilit/Arşiv Durumu, Kiracı | Erişilmek istenen veri ne kadar kritik? |
| **Eylem (Action)** | Read, Write, Delete, Export, Approve | Yapılmak istenen işlem sisteme ne kadar zarar verebilir? |
| **Çevre (Environment)** | Mesai Saati, İstemci IP / CIDR Bloğu, Coğrafi Konum, Risk Puanı | İstek nereden, ne zaman ve hangi tehdit ikliminde geliyor? |

### XACML Mimarisi ve Karar Kombinasyonu
ABAC motorları arkada 4 temel rolde çalışır:
- **PEP (Policy Enforcement Point):** Kapıdaki bekçidir; gelen API isteğini yakalar ve kararı PDP'ye sorar.
- **PDP (Policy Decision Point):** Kuralları işleten beyindir; öznitelikleri değerlendirir ve `Permit` veya `Deny` döner.
- **PIP (Policy Information Point):** Eksik öznitelikleri veritabanından veya LDAP'tan tamamlayan bilgi kaynağıdır.
- **PAP (Policy Administration Point):** Kuralların yazıldığı yönetim konsoludur.

**Birleştirme Kuralı (Combining Algorithm):**  
Bizim motorumuzda **'Deny-Overrides' (Reddetme Öncelikli)** kuralı geçerlidir. 100 kural izin verse dahi, tek bir güvenlik kuralı 'Reddet' diyorsa kapı kilitlenir! (Fail-Closed Default Deny)."

---

## 4. İki Modelin Evliliği: Hibrit Yetkilendirme Mimarisi

**Usta:**  
"Sahada en güçlü şirketler ne sırf RBAC ne de sırf ABAC kullanır; **Hibrit Model** işletir:

```
[İstemci İsteği]
       │
       ▼
[1. Aşama: RBAC Kapıcısı] ──(Yetki Yoksa)──> [HATA: CWE-862 RBACPermissionDenied]
       │
       ▼ (Rol İzni Var)
[2. Aşama: ABAC Denetçisi]
       ├─ Çok Kiracılı Sınır (Tenant) ──(Farklıysa)──> [HATA: CWE-284 MultiTenantBreach]
       ├─ Gizlilik vs Seviye (Clearance) ──(Yetersizse)──> [HATA: CWE-285 InsufficientClearance]
       ├─ Departman İzolasyonu (IDOR) ──(Farklıysa)──> [HATA: CWE-639 IDORPolicyDenied]
       ├─ Kritik Eylemde MFA Şartı ──(MFA Yoksa)──> [HATA: CWE-308 MissingMFA]
       └─ Çevre (Mesai Saati & Güvenli IP) ──(Aykırıysa)──> [HATA: CWE-284 EnvironmentalConstraint]
       │
       ▼ (Tüm Koşullar PASS)
[ERİŞİM ONAYLANDI + AUDIT LOG]
```

Bu model sayesinde:
1. Basit rolü olmayan saldırganlar ABAC'ın ağır kurallarını işletmeden en başta elenir (Maksimum Performans).
2. Rolü olan ayrıcalıklı kullanıcılar ise bağlamsal sınırlar dışına çıkamaz; içeriden gelen tehditler (Insider Threat) ve yatay yetki yükseltmeler (IDOR) imkansız kılınır."

---

## 5. Ustanın Çırağa Öğüdü

> "Çırağım, kimlik doğrulama kapıdaki güvenlik görevlisine kimlik göstermektir; yetkilendirme ise o binanın içindeki hangi odalara, saat kaçta ve kimin gözetiminde girebileceğini belirlemektir.  
> Asla tek bir 'rol' dizesine güvenip veritabanının kapılarını ardına kadar açma. Kullanıcının rolü ne kadar yüksek olursa olsun; kaynağın sahibini, gizlilik derecesini ve isteğin geldiği ortamı her işlemde yeniden sorgula. Gerçek güvenlik, güvenin bittiği ve sürekli doğrulamanın (Zero Trust) başladığı yerde doğar."
