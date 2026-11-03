# Gün 125: Soru & Cevap — Güvenli Kimlik ve Rol Prototipi (Capstone)

---

### Soru 1: Hiyerarşik RBAC mimarilerinde döngüsel kalıtım (Circular Role Inheritance - CWE-674) riski nedir ve mimaride nasıl tespit edilip izole edilir?

#### 1. Soru Başlığı ve Tanımı
Hiyerarşik Rol Tabanlı Erişim Denetimi (Hierarchical RBAC - NIST standardı), rollerin birbirinden izin miras almasını sağlayan yönlü asiklik bir graf (DAG) yapısıdır. Ancak yönetici arayüzlerinden veya dinamik API'lerden rol ilişkileri tanımlanırken, yanlışlıkla ya da yetki yükseltme (Privilege Escalation) amacıyla dairesel döngüler (`Role A -> Role B -> Role C -> Role A`) oluşturulabilir. Bu duruma döngüsel rol mirası denir.

#### 2. Derinlemesine Teknik Analiz
Bir izin denetimi yapıldığında, kullanıcının rollerinden başlayarak özyinelemeli (recursive) veya derinlik öncelikli (DFS) arama ile tüm üst rollerin izinleri toplanır. Eğer graf içerisinde bir döngü varsa:
1. **Sonsuz Özyineleme ve DoS (CWE-674):** Ziyaret edilen düğümler (visited set) takip edilmiyorsa yığın taşması (Stack Overflow) meydana gelir ve kimlik doğrulama/yetkilendirme servisi çöker (Hizmet Reddi).
2. **Yetki Yükseltme ve Mantıksal Bozulma:** Döngü sayesinde en düşük seviyeli bir rol (`guest`), dolaylı yoldan en yüksek seviyeli (`super_admin`) rolün yetkilerini miras alabilir.

Çözüm iki katmanlıdır:
- **Tasarım / Ekleme Zamanı (Write-Time Validation):** Yeni bir rol eklendiğinde veya ebeveyn bağlandığında, `_is_descendant(parent, target_role)` kontrolü yapılarak grafın çevrimsiz (asiklik) kaldığı matematiksel olarak doğrulanır. Döngü varsa işlem `CircularRoleHierarchyError` ile reddedilir.
- **Çalışma Zamanı (Runtime Guard):** İzin toplama (`_resolve_all_permissions`) fonksiyonunda her çağrıda `visited: Set[str]` kümesi kullanılarak daha önce ziyaret edilmiş roller ikinci kez işlenmeden atlanır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Büyük bir bulut yönetim platformunda 2.000'den fazla rol bulunmaktadır. Bir güvenlik mühendisi `Kubernetes-Auditor` rolüne yanlışlıkla `Cloud-Admin` rolünü üst grup olarak atar; ancak `Cloud-Admin` rolü zaten `Infrastructure-Viewer` üzerinden `Kubernetes-Auditor`'ı miras almaktadır. Sistemde döngü kontrolü olmadığı için ilk kullanıcı API çağrısında mikroservis iş parçacığı çöker ve tüm Kubernetes yetkilendirme kapıları kilitlenir.
**Pratik Çözüm:**
Kod seviyesinde derinlik taraması eklenir:
```python
def register_role(self, role_name, permissions, parent_roles=None):
    for parent in (parent_roles or []):
        if parent == role_name or self._is_descendant(parent, role_name):
            raise CircularRoleHierarchyError(f"Döngü tespit edildi: {role_name} -> {parent}")
```

#### 4. Ustanın Çırağa Tavsiyesi
Rol hiyerarşisi ağaç değil, yönsüz ağ hiç değildir; o bir **Yönlü Asiklik Graf (DAG)** olmak zorundadır. Kullanıcı rol atamalarını ve rol miraslarını asla serbest metin olarak veritabanına doğrudan yazma. Mimari katmanda mutlaka döngü tespit eden graf algoritmaları çalıştır.

---

### Soru 2: Statik (Static SoD) ve Dinamik (Dynamic SoD) Görevler Ayrılığı (CWE-863) arasındaki fark nedir ve yüksek güvenlikli finansal sistemlerde nasıl uygulanır?

#### 1. Soru Başlığı ve Tanımı
Görevler Ayrılığı (Separation of Duties - SoD), hiçbir tekil kullanıcının kritik bir iş sürecini (finansal transfer, üretim kodu canlıya alma, denetim kaydı silme) baştan sona tek başına tamamlayamaması ilkesidir. Bu ilke iç tehditleri, dolandırıcılığı ve operasyonel hataları önler (CWE-863).

#### 2. Derinlemesine Teknik Analiz
SoD iki temel biçimde hayata geçirilir:
1. **Statik Görevler Ayrılığı (Static SoD):**
   - Kullanıcı tanımlama ve rol atama aşamasında denetlenir.
   - Belirlenen iki çatışan (zehirli) rol çifti asla aynı kullanıcı hesabına aynı anda atanamaz.
   - Örnek: Bir kullanıcı hem `payment_maker` (ödeme emri hazırlayan) hem de `payment_checker` (ödeme emrini onaylayan) rolüne sahip olamaz. Veritabanında veya dizin servisinde ikinci rol atanmaya çalışıldığında `SeparationOfDutyConflictError` üretilir.
2. **Dinamik Görevler Ayrılığı (Dynamic SoD):**
   - Kullanıcının yetkileri geniş olabilir (örneğin nöbetçi müdür her iki role de sahip olabilir), ancak çalışma zamanında (runtime transaction) aynı işlem üzerinde her iki yetkiyi kullanamaz.
   - Örnek: Ali Bey bir faturayı bizzat kendisi hazırladıysa (`created_by == 'ali'`), aynı faturanın onaylama butonuna bastığında sistem "Kendi hazırladığınız faturayı onaylayamazsınız (Dual-Control / 4-Eyes Principle)" diyerek işlemi reddeder.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankacılık uygulamasında kıdemli operasyon uzmanı Ayşe Hanım, personel yetersizliği nedeniyle hem "Kredi Açma" hem de "Kredi Onaylama" rollerine atanmıştır (Statik SoD ihlali). Kötü niyetli bir akrabası adına 5 milyon TL'lik kredi başvurusu açmış ve dakikalar içinde kendi yetkisiyle onaylayarak parayı yurt dışı hesaba transfer etmiştir.
**Pratik Çözüm:**
Sistem çekirdeğinde Statik SoD zorunlu kılınır:
```python
mgr.add_toxic_role_pair("loan_originator", "loan_approver")
# Kullanıcıya ikinci rol verilirken motor durdurur:
def _check_sod_conflict(self, user_roles):
    for r_a, r_b in self.toxic_role_pairs:
        if r_a in set(user_roles) and r_b in set(user_roles):
            raise SeparationOfDutyConflictError("SoD İhlali: Çatışan roller同一 hesaba atanamaz!")
```

#### 4. Ustanın Çırağa Tavsiyesi
"Operasyon aksamasın, tek kişi her işi yapsın" diyen yönetici, dolandırıcılığa davetiye çıkaran yöneticidir. Yazılımcı olarak senin görevin, iş birimi istese dahi kod seviyesinde zehirli rol çiftlerini engellemek ve istisnaları sadece yönetim kurulu imzalı özel çift anahtar (dual-custody) süreçlerine bağlamaktır.

---

### Soru 3: Yetkilendirme sistemlerinde Altyapı Arızaları anında Fail-Secure (CWE-636) vs. Fail-Open kararı nasıl yönetilir ve Step-Up MFA (CWE-308) ile nasıl birleştirilir?

#### 1. Soru Başlığı ve Tanımı
Dağıtık yetkilendirme sistemlerinde (Policy Enforcement Point - PEP / Policy Decision Point - PDP), arka plandaki kimlik dizini (Active Directory, LDAP), yetki veritabanı veya MFA doğrulama servisi ağ kesintisi, zaman aşımı veya servis çökmesi yaşayabilir. Bu kriz anında sistemin nasıl tepki vereceği güvenlik mimarisinin kaderini belirler (CWE-636).

#### 2. Derinlemesine Teknik Analiz
- **Fail-Open (Açık Hata Modu):** Sistem hata aldığında kullanıcıların işi aksamasın diye erişime izin verir (`try ... except: return PERMIT`). Bu yaklaşım can güvenliği sistemlerinde (örneğin yangın anında acil çıkış kapılarının kilidinin açılması - Fail-Safe) zorunlu olabilir; ancak bilgi güvenliği ve veri erişiminde kabul edilemez bir zafiyettir (CWE-636). Saldırganlar kimlik doğrulama sunucusuna kasıtlı DoS/DDoS saldırısı yaparak sistemin Fail-Open moduna geçmesini ve tüm kapıların şifresiz açılmasını sağlar.
- **Fail-Secure / Fail-Closed (Kapalı Hata Modu):** Sistem altyapı arızası (`DATABASE_UNAVAILABLE`, `IDENTITY_STORE_TIMEOUT`) hissettiği anda Saltzer-Schroeder kuralını işletir: "Erişim kesin olarak doğrulanamıyorsa karar daima DENY'dir."
- **Step-Up MFA (CWE-308) ile Entegrasyon:** Rutin okuma işlemlerinde tek faktör yeterli olsa da kritik eylemlerde (`critical_action=True` veya admin rolü) oturumun `mfa_verified` olması şart koşulur. MFA servisi çöktüğünde sistem "MFA servisi çalışmıyor, bari geçsin" demez; Fail-Secure ilkesi gereği kritik işlemi derhal durdurur.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir e-ticaret ödeme ağ geçidinde, Fraud denetim servisi 3 saniyeden uzun süren isteklere zaman aşımı verip ödemeyi onaylamaktadır (Fail-Open). Bir siber suç örgütü, ağ geçidinin Fraud API uç noktasına botnet ile yoğun paket göndererek servisi yavaşlatmış ve çalıntı kartlarla 10 milyon TL değerinde sahte siparişi hiçbir kontrole takılmadan onaylatmıştır.
**Pratik Çözüm:**
Arıza durumunda Fail-Secure garantisi kodlanır:
```python
if simulate_failure is not None:
    self._log_event("FAIL_SECURE_TRIGGERED", {"failure": simulate_failure.value})
    return AccessEvaluationResult(
        decision="DENY",
        reason=f"Altyapı Arızası ({simulate_failure.value}) nedeniyle Fail-Secure devrede. Erişim REDDİ (CWE-636)."
    )
```

#### 4. Ustanın Çırağa Tavsiyesi
Çırak! Kullanıcı "Sayfa açılmadı, hata verdi" diye şikayet edebilir; bu birkaç dakika içinde çözülür. Ama "Hata oldu, herkes admin oldu" dediğin gün şirket batar. Siber güvenlikte sessiz kalıp kapıyı kilitlemek, panikle kapıyı ardına kadar açık bırakmaktan bin kat daha erdemlidir.
