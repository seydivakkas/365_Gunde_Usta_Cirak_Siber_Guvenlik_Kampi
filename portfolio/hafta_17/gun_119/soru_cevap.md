# Hafta 17 / Gün 119: Mini Proje 16 — Derin Teknik Soru & Cevap

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Pedagojik Format:** Usta-Çırak Derin Teknik Mülakat ve Saha Deneyimi  

---

## Soru 1: Rol Tabanlı Erişim Kontrolünde (RBAC) Hiyerarşik Miras Grafı (DAG) ve Döngüsel Bağımlılık (Circular Dependency — CWE-674) Tespiti

### 1. Soru Başlığı ve Tanımı
NIST ANSI/INCITS 359-2004 standardı kapsamında hiyerarşik RBAC (Hierarchical RBAC - Level 2) mimarisi roller arasındaki miras ilişkilerini nasıl modeller? Rol hiyerarşisinde yöneticilerin veya konfigürasyon betiklerinin sebep olabileceği **Döngüsel Bağımlılık (Circular Dependency — CWE-674)** hatası sistemi nasıl kilitler ve grafik algoritmaları (DFS/Cycle Detection) ile nasıl engellenir?

### 2. Derinlemesine Teknik Analiz
Rol hiyerarşisi, rollerin birbirinden yetki devralmasını sağlayan bir **Yönlü Döngüsüz Çizge (Directed Acyclic Graph - DAG)** olarak modellenir:
$$G = (V, E)$$
Burada $V$ roller kümesini, $E$ ise miras ilişkilerini ($r_1 \rightarrow r_2$: $r_1$ rolü $r_2$ rolünün yetkilerini devralır) temsil eder.

**Döngüsel Bağımlılık Riski (CWE-674):**
Eğer bir sistemde aşağıdaki gibi bir miras zinciri oluşursa:
$$R_{\text{Admin}} \rightarrow R_{\text{Manager}} \rightarrow R_{\text{Staff}} \rightarrow R_{\text{Admin}}$$
1. Kullanıcının etkin izinleri hesaplanırken özyineli (recursive) veya yığın tabanlı bir arama fonksiyonu çalıştırıldığında fonksiyon sonsuz döngüye girer.
2. İşlem belleği (Call Stack) hızla tükenir ve **Yığın Taşması (Stack Overflow - CWE-674)** meydana gelerek tüm yetkilendirme motorunu çökertir (Hizmet Dışı Bırakma - Denial of Service).

**Matematiksel ve Algoritmik Çözüm (Depth-First Search - DFS):**
Yeni bir miras bağı ($u \rightarrow v$) sisteme eklenmeden önce:
1. $v$ düğümünden başlanarak graf taranır.
2. Eğer $v$'nin alt dalları taranırken $u$ düğümüne ulaşılabiliyorsa ($\text{Path}(v \leadsto u)$ mevcutsa), bu bağın eklenmesi bir döngü ($u \rightarrow v \leadsto u$) yaratacaktır!
3. Bu durum saptandığı anda işlem derhal engellenmeli ve `RoleHierarchyCycleDetectedError` fırlatılmalıdır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Büyük bir telekom şirketinin Active Directory / IAM altyapısında 50.000 kullanıcı ve yüzlerce grup vardır. Otomasyon betiği yazan bir stajyer, "Tüm çalışanlar şirket içi portalı görsün" diyerek `Domain Users` grubunu `Portal Access` grubuna üye yapmış; başka bir yönetici ise `Portal Access` grubunu `Domain Users` grubunun altına eklemiştir. Ertesi sabah kimlik doğrulama sunucusu (Kerberos/LDAP) döngüsel grup çözümlemesi sırasında kilitlenmiş ve 50.000 personel mesaiye başlayamamıştır.

**Pratik Çözüm (Python Döngü Önleme Kodu):**
```python
def add_hierarchy_edge_safe(hierarchy: dict[str, set[str]], parent: str, child: str):
    # Çocuğun alt dallarında ebeveyn var mı? (DFS ile arama)
    visited = set()
    stack = [child]
    while stack:
        current = stack.pop()
        if current == parent:
            raise RoleHierarchyCycleDetectedError(
                f"KRİTİK HATA (CWE-674): '{parent}' -> '{child}' ilişkisi döngü yaratır!"
            )
        if current not in visited:
            visited.add(current)
            stack.extend(hierarchy.get(current, set()))
            
    # Döngü yoksa güvenle ekle
    hierarchy.setdefault(parent, set()).add(child)
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, graf teorisini bilmeyen güvenlik mühendisi, labirentte kaybolan çırağa benzer. Miras zincirine her halka eklediğinde arkana bak; başladığın noktaya dönen bir ilmik varsa o ilmik senin boynuna geçer. Grafını daima yönsüz ve döngüsüz (DAG) tut."

---

## Soru 2: Statik (SSD) ile Dinamik (DSD) Görevler Ayrılığı (SoD — CWE-863) Arasındaki Fark ve Oturum Düzeyinde Rol Kısıtlama

### 1. Soru Başlığı ve Tanımı
NIST RBAC standardında yer alan **Statik Görevler Ayrılığı (SSD)** ile **Dinamik Görevler Ayrılığı (DSD)** arasındaki temel fark nedir? Bir kullanıcının kariyeri gereği çatışan iki role birden sahip olması zorunlu olduğunda, **Oturum Düzeyinde Rol Aktivasyonu (Session-Scoped Least Privilege)** dolandırıcılığı (CWE-863) nasıl kesin olarak önler?

### 2. Derinlemesine Teknik Analiz
Görevler Ayrılığı (Separation of Duties - SoD), hiçbir kullanıcının denetimsiz tek başına kritik bir iş sürecini başlatıp sonlandıramamasını güvence altına alır.

| Özellik | Statik Görevler Ayrılığı (SSD) | Dinamik Görevler Ayrılığı (DSD) |
|---|---|---|
| **Denetim Noktası** | Kullanıcıya rol atanırken (User-Role Assignment). | Oturum açılırken veya işlem yapılırken (Session Activation). |
| **Kural Mantığı** | Çatışan roller aynı kullanıcının siciline **asla yazılamaz**. | Kullanıcı iki role de sahiptir ancak **aynı oturumda ikisini birden çalıştıramaz**. |
| **Örnek Senaryo** | Muhasebeci ile Kasiyer rollerinin tek kişiye atanması kesinlikle yasaktır. | Güvenlik Denetçisi ile Yazılım Geliştirici rolleri aynı kişide olabilir fakat aynı oturumda açılamaz. |
| **Zafiyet Engeli** | CWE-863 Kalıcı çıkar çatışması ve dolandırıcılık. | CWE-863 Anlık çıkar çatışması ve kendi kendini onaylama hilesi. |

**Oturum Düzeyinde Rol Aktivasyonu (Session-Scoped RBAC):**
Kullanıcının sicilinde $R_{\text{Assigned}} = \{\text{Developer}, \text{Sec\_Officer}\}$ olsun:
1. Kullanıcı sisteme giriş yaparken hedef bağlamı seçer: `Session_Roles = {"Developer"}`.
2. Simülatör motoru bu oturumda yalnızca `Developer` izinlerini etkinleştirir; `Sec_Officer` izinlerini dondurur.
3. Kullanıcı kendi yazdığı kodun güvenlik onayını vermeye kalktığında oturumunda onay yetkisi bulunmadığı için sistem işlemi reddeder (`CWE-862`).
4. Onay vermek isterse mevcut oturumunu kapatıp denetçi oturumu açmak zorundadır; bu işlem de denetim günlüğüne (audit log) ayrı bir kimlik olayı olarak düşer.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir kamu bankasında nöbetçi yazılımcı, acil durum desteği için aynı zamanda nöbetçi veri tabanı onaycısı rolüne atanmıştır. Nöbetçi personel gece vardiyasında kendi yazdığı arka kapılı SQL script'ini çalıştırmış ve onay makamı olarak da kendi diğer rolünü kullanarak 5 milyon liralık mevduatı yurt dışı hesabına aktarmıştır (CWE-863).

**Pratik Çözüm (DSD Oturum Doğrulayıcı):**
```python
def create_secure_session(user: SimulationUser, requested_roles: set[str], dsd_conflicts: list[tuple[str, str]]):
    # 1. Kullanıcının atanmamış rol açması engellenir (CWE-285)
    if not requested_roles.issubset(user.assigned_roles):
        raise UnassignedRoleActivationError("Kullanıcı sahip olmadığı rolü aktive edemez!")
        
    # 2. Dinamik SoD çatışma kontrolü yapılır (CWE-863)
    for role_a, role_b in dsd_conflicts:
        if role_a in requested_roles and role_b in requested_roles:
            raise DynamicSoDViolationError(
                f"DSD İHLALİ (CWE-863): '{role_a}' ve '{role_b}' rolleri aynı anda açılamaz!"
            )
            
    # Oturum güvenle üretilir
    return UserSession(session_id=generate_token(), user_id=user.user_id, active_roles=requested_roles)
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, bir insanın iki ayrı şapkası olabilir; ama aynı kafada iki şapka üst üste takılmaz. Savcı aynı davada hem iddia makamı hem de yargıç kürsüsüne oturamaz. Kullanıcıya rollerini tek bir torbada kullandırma; her işlem için ayrı oturum açtır ve o oturumda sadece o işe yetecek asgari rolü taşıt."

---

## Soru 3: Yetki Birikimi (Privilege Creep — CWE-250) Problemi ve Toplu Politika Simülasyonunun (Batch Dry-Run) Rolü

### 1. Soru Başlığı ve Tanımı
Kurumsal şirketlerde çalışanların zaman içinde departman ve pozisyon değiştirmesiyle ortaya çıkan **Yetki Birikimi (Privilege Creep — CWE-250)** tehlikesi nedir? Bir güvenlik yöneticisinin rol tanımlarını veya hiyerarşi kurallarını değiştirmeden önce **Toplu Politika Simülasyonu (Batch Policy Dry-Run)** yapması iş sürekliliği ve güvenlik açısından neden hayati önem taşır?

### 2. Derinlemesine Teknik Analiz
**Yetki Birikimi (Privilege Creep - CWE-250):**
- Çalışan bir departmandan diğerine geçerken, eski departmandaki erişimleri genellikle "işler aksamasın" denilerek silinmez.
- Yıllar geçtikçe kullanıcı hem İK, hem Finans, hem IT sistemlerine erişebilen bir "Süper Canavar" hesaba dönüşür.
- Bu durum **En Az Ayrıcalık İlkesini (PoLP)** kökten dinamitler.
- Saldırgan tek bir eski personelin parolasını ele geçirdiğinde tüm kurumsal ağa erişim sağlar.

**Toplu Politika Simülasyonunun (Batch Dry-Run) Gerekliliği:**
Güvenlik ekipleri aşırı yetkileri temizlemek için radikal bir karar aldığında (örn: `accountant` rolünden `invoice:export` yetkisini kaldırmak veya miras bağını koparmak):
1. **Canlıda Körlemesine Yapılırsa:** Binlerce muhasebeci sabah işe başladığında fatura kesemez, şirket operasyonları durur (Availability kaybı).
2. **Simülatör ile Dry-Run Yapılırsa:**
   - Son 30 günün 50.000 gerçek erişim isteği (`SimulationRequest`) simülatöre verilir.
   - Simülatör yeni kurallarla toplu simülasyon çalıştırır (`run_batch_simulation`).
   - Hangi departmanların işinin aksayacağı, hangi zafiyetlerin başarıyla kapandığı tek bir raporda görünür.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir e-ticaret şirketi PCI-DSS denetiminden geçecektir. Güvenlik lideri panikle bir rol kısıtlaması yapmış ve geliştiricilerin log okuma yetkisini kapatmıştır. Aynı gece canlı ödeme sisteminde bir arıza çıkmış; geliştiriciler logları göremediği için arızayı 12 saat boyunca çözememiş ve şirket milyonlarca liralık satış kaybetmiştir.

**Pratik Çözüm (Toplu Simülasyon Etki Analizi):**
```python
def dry_run_policy_impact(simulator: RBACSimulatorEngine, historical_requests: list[SimulationRequest]):
    results = simulator.run_batch_simulation(historical_requests)
    denied_count = sum(1 for r in results if not r.is_permitted)
    permitted_count = len(results) - denied_count
    
    print(f"Toplam Test Edilen İstek : {len(results)}")
    print(f"Başarılı İzinler         : {permitted_count}")
    print(f"Engellenen İstekler      : {denied_count}")
    
    # Etki analizi raporu üret
    return {"total": len(results), "permitted": permitted_count, "denied": denied_count}
```

### 4. Ustanın Çırağa Tavsiyesi
> "Çırağım, güvenlik operasyonları cerrahi müdahaleye benzer. Teşhis koymadan bıçak vurursan hastayı masada bırakırsın. Şirketin yetki haritasında yapacağın her değişikliği önce simülatörde yüzlerce kez test et. Gerçek dünyada 'Pardon, sistem durdu' deme lüksün yoktur."
