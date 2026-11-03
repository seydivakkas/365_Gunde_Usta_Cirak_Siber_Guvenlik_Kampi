# Hafta 17 / Gün 117: RBAC ve ABAC — Derin Teknik Soru & Cevap

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Pedagojik Format:** Usta-Çırak Derin Teknik Mülakat ve Saha Deneyimi  

---

## Soru 1: RBAC'ta "Rol Patlaması" (Role Explosion) Krizi ve Statik/Dinamik Görevler Ayrılığı (Separation of Duties — CWE-863)

### 1. Soru Başlığı ve Tanımı
NIST ANSI/INCITS 359-2004 standardı kapsamında Rol Tabanlı Erişim Kontrolü (RBAC) modelleri büyüyen kurumlarda neden **"Rol Patlaması" (Role Explosion)** krizine yol açar? Ayrıca **Statik Görevler Ayrılığı (SSD)** ile **Dinamik Görevler Ayrılığı (DSD)** arasındaki fark nedir ve dolandırıcılığı (Fraud - CWE-863) kriptografik/mantıksal olarak nasıl önler?

### 2. Derinlemesine Teknik Analiz
RBAC, kullanıcıları izinlere doğrudan değil, soyut 'Rol' kümeleri aracılığıyla bağlar. Ancak organizasyonel gereksinimler karmaşıklaştıkça roller yetersiz kalmaya başlar:
- Bir şirket coğrafi konuma (`Şube-A`, `Şube-B`), departmana (`Muhasebe`, `Ar-Ge`), çalışma saatine (`Gündüz`, `Gece`) ve veri hassasiyetine (`Gizli`, `Açık`) göre farklı erişimler tanımlamak istediğinde, rol sayısı bu boyutların Kartezyen çarpımı kadar artar:
  $$\text{Rol Sayısı} = N_{\text{departman}} \times N_{\text{şube}} \times N_{\text{zaman}} \times N_{\text{yetki}}$$
- 10 departman, 20 şube, 3 vardiya ve 5 yetki seviyesi olduğunda, teorik olarak **3.000 farklı rol** tanımlanması gerekir. Bu durum yetki matrisini yönetilemez hale getirir (Role Explosion).

**Görevler Ayrılığı (Separation of Duties - SoD - CWE-863):**
Kurumsal iç tehditleri ve dolandırıcılığı önlemek için kritik işlemler tek bir bireyin inisiyatifine bırakılamaz:
1. **Statik SoD (SSD):** Bir kullanıcıya birbirini denetleyen çatışan roller (Toxic Role Combination) **hiçbir zaman aynı anda atanamaz**.
   Örnek: $\text{Kullanıcı} \cap \{\text{Fatura\_Oluşturan}, \text{Fatura\_Ödeyen}\} \le 1$.
   Eğer veritabanında bu iki rol aynı kullanıcı kimliğine atanmaya çalışılırsa sistem işlemi engeller.
2. **Dinamik SoD (DSD):** Kullanıcı kariyeri veya vekalet gereği her iki role de sahip olabilir; fakat **aynı oturumda veya aynı işlem bağlamında** iki rolü birden aktifleştiremez. Kendi başlattığı satın alma emrini, yönetici vekaleti olsa dahi kendisi onaylayamaz.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Uluslararası bir lojistik şirketinde ERP sistemi işletilmektedir. Bir ambar şefi, muhasebe departmanına terfi etmiş ancak eski ambar yetkisi sistemden alınmamıştır. Şef, ambarda "kayıp/hurda" olarak işaretlediği 500.000 TL değerindeki yedek parçaları, muhasebe rolünü kullanarak hurda bedeliyle kendi kurduğu paravan şirkete satmış ve faturayı da bizzat kendisi onaylayarak zimmetine para geçirmiştir (CWE-863).

**Pratik Çözüm (Python SSD Doğrulayıcı):**
```python
def enforce_static_sod(user_roles: set[str], forbidden_pairs: list[tuple[str, str]]):
    for role_a, role_b in forbidden_pairs:
        if role_a in user_roles and role_b in user_roles:
            raise RBACSoDRuleConflictError(
                f"KRİTİK GÜVENLİK İHLALİ (CWE-863): '{role_a}' ve '{role_b}' "
                f"rolleri aynı kullanıcıya atanamaz! Görevler ayrılığı kuralı ihlal edildi."
            )
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, paranın ve yetkinin olduğu yerde tek bir kişinin imzasına asla güvenilmez. Satın almayı başlatan ile parayı kasadan çıkaran el aynı olursa, o şirketin batması kaçınılmazdır. SoD kurallarını veritabanı kısıtlaması (constraint) seviyesinde zorunlu kıl; kimsenin 'vekaleten hallettim' bahanesine geçit verme."

---

## Soru 2: NIST SP 800-162 ABAC Mimarisi, XACML Standart Bileşenleri ve 'Deny-Overrides' Karar Mantığı

### 1. Soru Başlığı ve Tanımı
NIST SP 800-162 standardı ve OASIS XACML mimarisinde yer alan **PEP, PDP, PIP ve PAP** bileşenlerinin rolleri nelerdir? Karar birleştirme algoritmalarında (Combining Algorithms) **"Deny-Overrides" (Reddetme Öncelikli)** politikasının benimsenmesi güvenlik açığı oluşmasını (Fail-Safe Defaults — CWE-276) nasıl engeller?

### 2. Derinlemesine Teknik Analiz
ABAC (Attribute-Based Access Control), erişim kontrolünü statik roller yerine çok boyutlu özniteliklerin (Özne, Kaynak, Eylem, Çevre) mantıksal birleşimine dayandırır.

**Mimari Bileşenler:**
1. **PEP (Policy Enforcement Point):** İstemcinin kaynağa erişim talebini (API çağrısını) ilk yakalayan kapıdır (örn: API Gateway veya Web Filter). İsteği durdurur ve PDP'ye danışır.
2. **PDP (Policy Decision Point):** Politika motorudur. Kuralları okur, öznitelikleri tartar ve matematiksel olarak `PERMIT`, `DENY` veya `NOT_APPLICABLE` kararı üretir.
3. **PIP (Policy Information Point):** Karar için gerekli olan ancak istek paketinde bulunmayan ek öznitelikleri sağlayan veri tabanı veya dizin servisidir (örn: LDAP, veritabanı, coğrafi IP servisi).
4. **PAP (Policy Administration Point):** Güvenlik yöneticilerinin ilkeleri (politikaları) JSON/XML formatında yazdığı ve dağıttığı yönetim merkezidir.

**Deny-Overrides (Kusurlu Güvenlik Önleme):**
Bir erişim talebini birden fazla kural denetleyebilir:
- Kural 1: "Kullanıcı finans departmanındaysa okuyabilir." -> `PERMIT`
- Kural 2: "Kullanıcı kurumsal ağdaysa okuyabilir." -> `PERMIT`
- Kural 3: "Mesai saati dışındaysa finansal veri okunamaz." -> `DENY`

Eğer sistem `Permit-Overrides` kullanırsa, Kural 1 veya Kural 2 sağlandığı için erişime izin verilir; bu da mesai kısıtlamasını baypas eder!
Oysa **Deny-Overrides (Reddetme Öncelikli)** mantığında:
$$\text{Nihai Karar} = \text{DENY} \iff \exists i: \text{Kural}_i = \text{DENY}$$
Tek bir güvenlik kuralı bile ihlal edilmişse, diğer 99 kural izin verse dahi istek anında reddedilir (Fail-Closed Güvenlik Prensibi).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir sağlık kuruluşu bulut sistemine geçmiştir. Yazılımcılar 'Permit-Overrides' mantığıyla bir politika motoru kurmuştur. Sistemde "Hastanın atandığı doktor veriyi görebilir" kuralı vardır. Ancak "Gizlilik şerhi konulmuş VIP hastaların kaydı başhekim onayı olmadan açılamaz" kuralı da bulunmaktadır. Doktor hastanın doktoru olduğu için izin kuralı tetiklenmiş ve VIP gizlilik şerhi hiçe sayılarak ünlü bir siyasetçinin sağlık raporu basına sızdırılmıştır.

**Pratik Çözüm (Deny-Overrides Karar Döngüsü):**
```python
def evaluate_policies_deny_overrides(rules, context):
    permit_found = False
    for rule in rules:
        decision = rule.evaluate(context)
        # EN KÜÇÜK BİR RED BİLE DERHAL ERİŞİMİ KESER
        if decision == "DENY":
            return False, f"Politika Engeli: {rule.name} kuralı ihlal edildi!"
        if decision == "PERMIT":
            permit_found = True
            
    if permit_found:
        return True, "Tüm ABAC politikaları başarıyla sağlandı."
    return False, "Varsayılan Ret: Hiçbir açık izin kuralı bulunamadı (Default Deny)."
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, güvenlikte demokrasiler işlemez. Dokuz kural 'Girebilir' dese, tek bir kural 'Şüpheli hareket var' diyorsa kapı kilitlenir. Güvenlik sistemini daima 'Fail-Safe Default' üzerine kur: Varsayılan durum daima ret olmalı, izin vermek için her bir güvenlik halkasının kusursuz kapanması beklenmelidir."

---

## Soru 3: Çok Kiracılı (Multi-Tenant) Bulut Mimarilerinde IDOR (CWE-639) ve Kiracı İzolasyon İhlalinin (CWE-284) Hibrit Model ile Engellenmesi

### 1. Soru Başlığı ve Tanımı
Hizmet Olarak Yazılım (SaaS) ve çok kiracılı (multi-tenant) bulut platformlarında, yalnızca RBAC kullanıldığında ortaya çıkan **Nesne Düzeyinde Yetkisiz Erişim (IDOR — CWE-639)** ve **Çapraz Kiracı Sızıntısı (Cross-Tenant Breach — CWE-284)** nasıl gerçekleşir? **Hibrit RBAC + ABAC** mimarisi bu açıkları nasıl kesin olarak kapatır?

### 2. Derinlemesine Teknik Analiz
Salt RBAC mimarisinde API uç noktası sadece kullanıcının rolüne bakar:
```python
# YALNIZCA RBAC KULLANAN TEHLİKELİ KOD:
@app.route("/api/invoices/<invoice_id>")
def get_invoice(invoice_id):
    if not current_user.has_role("accounting_staff"):
        abort(403) # RBAC KONTROLÜ
    return db.query("SELECT * FROM invoices WHERE id = ?", invoice_id)
```
**Saldırı Yolu (IDOR / BOLA):**
1. Saldırgan `Tenant_A` şirketinin muhasebe personeli (`accounting_staff`) rolüne sahiptir.
2. RBAC kontrolü `has_role("accounting_staff")` çağrısına `True` yanıtı verir.
3. Saldırgan `invoice_id` parametresini `1001` yerine rakip şirketin (`Tenant_B`) faturası olan `2002` yapar.
4. Sunucu faturanın kime ait olduğunu (kaynak özniteliği) ve kullanıcının kiracısını (özne özniteliği) kontrol etmediği için rakip şirketin tüm müşteri ve fiyat verilerini saldırgana teslim eder (CWE-639 & CWE-284).

**Hibrit Modelin Çözümü:**
Hibrit model iki katmanlı savunma hattı çeker:
- **Katman 1 (RBAC):** "Bu kullanıcı genel olarak fatura okuma (`invoice:read`) yetkisine sahip bir personel mi?" (Kaba filtreleme).
- **Katman 2 (ABAC):** "Bu faturanın `tenant_id` değeri ile kullanıcının `tenant_id` değeri eşit mi? Faturanın departmanı kullanıcının departmanı ile örtüşüyor mu? Kullanıcı bu işlemi güvenli IP'den mi yapıyor?" (İnce filtreleme).

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Popüler bir bulut İK yazılımında 500 farklı şirket barınmaktadır. Bir şirketin İK uzmanı, tarayıcının geliştirici araçlarını kullanarak çalışan profil URL'sindeki `employee_id` numarasını değiştirmiş ve rakip teknoloji şirketinin tüm yazılımcı maaşlarını ve performans notlarını indirerek rakip şirketin çalışanlarını transfer etmiştir.

**Pratik Çözüm (Hibrit ABAC Doğrulaması):**
```python
def enforce_hybrid_tenant_security(subject: SubjectContext, resource: ResourceContext, action: ActionContext):
    # 1. Aşama: RBAC Rol İzni
    if not rbac_engine.has_permission(subject.roles, f"{resource.resource_type}:{action.name}"):
        raise RBACPermissionDeniedError("CWE-862: Rol izni yetersiz!")
        
    # 2. Aşama: ABAC Çok Kiracılı ve Departman İzolasyonu
    if subject.tenant_id != resource.tenant_id:
        raise MultiTenantIsolationBreachError(
            f"KRİTİK İHLAL (CWE-284): Kiracı '{subject.tenant_id}' personeli, "
            f"'{resource.tenant_id}' kiracısına ait kaynağa erişemez!"
        )
        
    if resource.classification >= 2 and subject.department != resource.department_owner:
        if "security_auditor" not in subject.roles:
            raise ABACPolicyDeniedError("CWE-639: Departman veri izolasyonu ihlal edildi!")
            
    return True
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, rol bir rozettir, tapu senedi değildir. Bir polisin rozetinin olması, komşu ilçedeki her kasayı açabileceği anlamına gelmez. Veriye dokunurken daima sor: 'Bu veri senin dükkanının verisi mi?' Kiracı izolasyonu bulutun namusudur; orada tek bir açık verirsen, tüm müşterilerini aynı gün kaybedersin."
