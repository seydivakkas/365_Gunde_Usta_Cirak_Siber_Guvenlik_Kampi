# Gün 146: IAM Yaşam Döngüsü (JML) — 3 Derin Teknik Soru ve Kapsamlı Yanıtlar

**Modül:** Hafta 21 — Gün 146 (Excel Satır 150)  
**Konu:** IAM Yaşam Döngüsü JML (Joiner, Mover, Leaver), Yetki Birikimi, Yetim Hesaplar ve SoD  
**Telif Hakkı:** (c) 2026 Seydi Eryılmaz (@seydivakkas) — Özel Lisans (Tüm Hakları Saklıdır)

---

### Soru 1: Mover Sürecinde Yetki Birikimi (Privilege Creep) ve Görevler Ayrılığı (SoD) Çatışmalarının Önlenmesi

#### 1. Soru Başlığı ve Tanımı
Kurum içi departman, pozisyon veya proje transferlerinde (Mover aşaması) personelin önceki görevlerine ait yetkilerin otomatik geri alınmaması sonucu oluşan **Yetki Birikimi (Privilege Creep)** tehlikesi nedir? Bu durum kurumsal süreçlerde **Görevler Ayrılığı (Separation of Duties - SoD)** zehirli kombinasyonlarına (Toxic Combinations) nasıl dönüşür ve mimari düzeyde nasıl engellenir?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Kurumsal şirketlerde çalışanların ortalama %30'u kariyerleri boyunca en az bir kez unvan veya departman değiştirir. Geleneksel sistem yönetiminde yeni departmana geçen çalışana "işi aksamasın" diye yeni yetkiler hızla tanımlanırken, eski departman yetkileri "belki lazım olur" gerekçesiyle açık bırakılır.

Bu durum üç kritik kurumsal risk üretir:
1. **İç Tehdit ve Dolandırıcılık Riski (Fraud / Insider Threat):** Finans departmanında fatura girişi yapan bir personel, daha sonra onay merciine veya BT departmanına geçtiğinde eski yetkisini korursa; kendi adına sahte fatura kesip yine kendi yetkisiyle bu faturanın ödemesini onaylayabilir (Maker-Checker ilkesinin delinmesi).
2. **Saldırı Yüzeyinin Katlanması (Lateral Movement Target):** Bir saldırgan tek bir çalışanın kimlik bilgilerini ele geçirdiğinde, o çalışanın yıllar içinde biriktirdiği CRM, ERP, bulut konsolu ve kod depolarına aynı anda erişerek kurum içinde yatay geçiş yapabilir.
3. **Mevzuat ve Denetim İhlalleri (SOX, ISO 27001, KVKK/GDPR):** SOX 404 (Sarbanes-Oxley) finansal denetimlerinde SoD ihlalleri doğrudan "Maddi Kontrol Zafiyeti" (Material Weakness) olarak sınıflandırılır ve kurumun bağımsız denetim raporunun olumsuz sonuçlanmasına yol açar.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Bu zafiyetin önlenmesi için aşağıdaki mimari kontroller uygulanmalıdır:

```text
[Mover Talebi: İK Sistemi] 
           │
           ▼
[Delta Analizi (Rol Çıkarma Motoru)]
  ├── 1. Eski Departman Rollerini Belirle -> [Otomatik İptal Listesi (Revocation)]
  ├── 2. Yeni Departman Rollerini Ekle    -> [Aday Rol Kümesi]
  └── 3. SoD Matris Kontrolü             -> Zehirli Eşleşme Var mı?
                                              ├── [EVET] -> İşlemi Bloke Et / Güvenlik Onayı İste
                                              └── [HAYIR] -> İptalleri ve Yeni Rolleri Eşzamanlı Uygula
```

- **Sıfır Tabanlı Rol Ataması (Zero-Base Role Provisioning):** Mover işlemi bir "yetki ekleme" değil, kullanıcının profilinin sıfırlanıp yalnızca yeni rolü için tanımlanan standart rol şablonuyla yeniden inşa edilmesi olarak ele alınmalıdır.
- **Otomatik SoD Matris Motoru:** Her rol atama isteğinde, `check_sod_conflict()` mantığı çalıştırılarak adayın sahip olacağı nihai rol kümesinde birbirine zıt yetkilerin (örn. `Invoice_Create` ile `Payment_Approve`, `Dev_Code_Write` ile `Prod_Deploy`) bir arada bulunması engellenmelidir.
- **Erişim Sertifikasyonu (Access Certification Campaigns):** Kimlik Yönetimi (IGA) sistemi üzerinden yılda en az iki kez tüm birim yöneticilerine, sorumluluklarındaki personellerin yetki listeleri sunulmalı ve "Aktif olarak işi için gerekli olmayan" yetkiler tek tıkla geri alınmalıdır.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Eski anahtarını teslim etmeyene yeni odanın anahtarı verilmez! Bir çalışana terfi veya transfer verdiğinde ilk yapacağın iş, eski masasının çekmecesini boşaltmaktır."
- *Altın Kural:* Mover süreçlerinde "Rol Tutma" (Keep Existing Roles) seçeneği varsayılan olarak kapalı olmalı; istisnai durumlarda ise CISO düzeyinde gerekçeli ve süreli (azami 15 gün devir teslim süresi) onay şartına bağlanmalıdır.

---

### Soru 2: Leaver Sürecinde Yetim Hesaplar (Orphan Accounts), Oturum Jetonu Kalıntıları ve Anında Kapatma Mimarisi

#### 1. Soru Başlığı ve Tanımı
Kurumdan ayrılan bir personelin (Leaver aşaması) ardından geride kalan **Yetim Hesaplar (Orphan Accounts)** nasıl oluşur? Active Directory'de bir hesabın pasife alınması, kullanıcının Microsoft 365, AWS veya SaaS uygulamalarındaki aktif oturumlarını ve OAuth yenileme jetonlarını (Refresh Tokens) sonlandırmak için neden tek başına YETERSİZDİR?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Personel işten ayrıldığında İK birimi sistem yöneticisine e-posta atmayı unutabilir ya da BT yöneticisi sadece yerel Active Directory hesabını devre dışı bırakıp SaaS ve bulut konsollarını unutabilir. 

Oluşan tehdit dinamikleri şunlardır:
1. **Zaman Penceresi Açığı (Window of Exposure):** İntikamcı eski çalışanlar (Disgruntled Employees) ayrılış anı ile hesap kapatma arasındaki birkaç saatlik veya günlük gecikmeyi kullanarak şirket içi fikri mülkiyeti, müşteri listelerini veya kaynak kodları dışarı sızdırabilir (Data Exfiltration).
2. **Kalıcı Oturum Jetonları (Persistent OAuth Tokens):** Kullanıcının AD hesabı kapatılsa dahi; telefonundaki kurumsal e-posta istemcisi veya tarayıcısındaki bulut oturumu geçerli bir OAuth Refresh Token'a sahipse, bu token açıkça geçersiz kılınmadığı sürece (Revocation) sistem haftalarca kullanıcıdan yeni parola istemeden veri akışını sürdürebilir.
3. **Shadow IT ve Harici Kimlikler:** Şirket kimliğiyle açılmış GitHub, AWS IAM yerel kullanıcıları, Slack ve Salesforce hesapları merkezi İK ile senkronize değilse yıllarca "hayalet hesap" olarak kalır.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Eksiksiz ve saniyeler içinde icra edilen bir Leaver mimarisi şu adımları içermelidir:

1. **Çok Katmanlı ve Eşzamanlı Kapatma (Orchestrated Deprovisioning):**
   ```powershell
   # 1. Active Directory Hesabını Kapat ve Parolayı Rastgele Yap
   Disable-ADAccount -Identity $Username
   Set-ADAccountPassword -Identity $Username -NewPassword (New-Guid).ToString() -Reset
   Move-ADObject -Identity $UserDN -TargetPath "OU=Disabled_Users,DC=kurum,DC=local"

   # 2. Microsoft 365 / Entra ID Oturumlarını ve Jetonlarını Anında Düşür
   Revoke-MgUserAllRefreshToken -UserId "$Username@kurum.local"

   # 3. Tüm Güvenlik Gruplarından ve Lisanslardan Çıkar
   Get-ADPrincipalGroupMembership -Identity $Username | Where-Object {$_.Name -ne "Domain Users"} | Remove-ADPrincipalGroupMembership -Identity $Username -Confirm:$false
   ```
2. **Sürekli Yetim Hesap Taraması (Orphan Account Hunting):**
   - IAM motoru her gece hedef sistemlerdeki (AD, AWS, SAP) tüm aktif hesapların `owner_employee_id` alanını İK veri tabanındaki durum ile karşılaştırmalıdır.
   - İK durumu `TERMINATED` olan veya İK'da hiç karşılığı bulunmayan aktif hesaplar anında karantinaya alınmalı ve alarm üretilmelidir.
3. **Koşullu Erişimle Sürekli Değerlendirme (Continuous Access Evaluation - CAE):**
   - Modern IdP sistemlerinde (Entra ID / Okta) CAE protokolü aktif edilerek hesap kapatıldığı anda açık olan tarayıcı sekmelerinin milisaniyeler içinde zorla oturumunun sonlandırılması sağlanmalıdır.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "AD'den disable etmekle iş bitti sanan çırak, ayrılan personelin cep telefonundan e-postaları okumaya devam ettiğini görünce şaşkına döner. İşi bitiren şey parolanın değişmesi değil, havada uçuşan jetonların düşürülmesidir!"
- *Altın Kural:* Leaver protokolünde kritik ayrılışlar (fesih, disiplin) için İK departmanı ile "Kırmızı Buton" (Emergency Offboarding) API entegrasyonu kurulmalı; görüşme başladığı anda personelin tüm erişimleri tek tuşla 15 saniyede kesilmelidir.

---

### Soru 3: İnsan Kaynakları Otoriter Veri Kaynağı ile Hedef Sistemler Arasında SCIM Entegrasyonu ve Mutabakat (Reconciliation) Denetimleri

#### 1. Soru Başlığı ve Tanımı
Kurumsal Kimlik ve Erişim Yönetiminde (IAM) **Otoriter Veri Kaynağı (Authoritative Source / Single Source of Truth)** kavramı ne anlama gelir? İK sistemleri ile hedef sistemler arasındaki veri uyumsuzluklarını çözen **Mutabakat (Reconciliation)** denetimleri nasıl kurgulanır ve SCIM 2.0 protokolü bu süreci nasıl standartlaştırır?

#### 2. Kapsam ve Kurumsal Risk / Tehdit Analizi
Büyük ölçekli kurumlarda binlerce personel, yüzlerce sunucu ve onlarca SaaS uygulaması bulunur. Eğer İK sistemi ile Active Directory veya SaaS uygulamaları arasında çift yönlü otomatik bir köprü kurulmazsa, sistemler zamanla birbirinden ayrışır (Configuration Drift):
- İK'da işten ayrılmış görünen 50 kişinin AD'de hesabı açık kalabilir.
- Departman değiştiren 100 kişinin e-posta unvanı güncellenirken sunucu yetkileri eski departmanında kalabilir.
- İK'dan habersiz sistem yöneticileri tarafından "acil iş" bahanesiyle doğrudan hedef sistemde manuel açılmış hesaplar (Bypassed Provisioning) oluşur.

Bu durum, siber güvenlik denetimlerinde sistemlerin denetlenebilirliğini ve hesap verilebilirliğini tamamen yok eder.

#### 3. Derinlemesine Teknik Çözüm ve Mimari Yaklaşım
Standartlaştırılmış çözüm SCIM 2.0 ve Otonom Mutabakat Motorudur:

```text
+-----------------------+              +-----------------------+
|  İK / HR (Workday)    |              | Hedef Sistemler (SaaS)|
|  Otoriter Kaynak      |              | (Entra, AD, GitHub)   |
+-----------+-----------+              +-----------+-----------+
            |                                      |
            |--- 1. SCIM REST API (Push) --------->| (Anlık Yaşam Döngüsü)
            |                                      |
            |                                      |
            v                                      v
    +------------------------------------------------------+
    |          GÜNLÜK MUTABAKAT DENETİMİ (RECONCILIATION)   |
    |------------------------------------------------------|
    | - İK Kayıtlarını Oku                                 |
    | - Hedef Sistem Hesaplarını Çek                       |
    | - Karşılaştır:                                       |
    |     * İK'da var, Sistemde yok -> Provisioning Hatası |
    |     * İK'da yok, Sistemde var -> Yetim / Gölge Hesap!|
    |     * Durum Uyuşmazlığı       -> Kapatma Gecikmesi!  |
    | - Otomatik Düzeltme Betiği Üret                      |
    +------------------------------------------------------+
```

1. **SCIM 2.0 (RFC 7643 / RFC 7644) Standardı:**
   - Kimlik nesnelerini JSON formatında temsil eder (`urn:ietf:params:scim:schemas:core:2.0:User`).
   - Standart HTTP fiilleri (`POST`, `PUT`, `PATCH`, `DELETE`) ile çalışır.
   - Personel ayrıldığında `PATCH /v2/Users/{id}` ile `{"Operations": [{"op": "replace", "path": "active", "value": false}]}` gönderilerek tescilli bağlayıcılara gerek kalmadan tüm SaaS sağlayıcılarında hesap kapatılır.
2. **Çift Yönlü Mutabakat (Bidirectional Reconciliation):**
   - **Forward Reconciliation:** İK'daki yeni durumların hedef sistemlere yansıdığını denetler.
   - **Reverse Reconciliation:** Hedef sistemlerde doğrudan sistem yöneticisi tarafından manuel açılmış, İK karşılığı olmayan "kaçak/gölge" hesapları yakalar ve derhal dondurur.

#### 4. Usta Öğüdü ve Altın Kurallar
- *Ustanın Sözü:* "Sistem yöneticisinin kendi eliyle kullanıcı açtığı yer bakkal dükkanıdır, kurumsal şirket değildir! Otoriter İK kaynağından geçmeyen her hesap potansiyel bir arka kapıdır."
- *Altın Kural:* Hedef sistemlerde el ile hesap açma yetkisi yalnızca acil durum "Break-Glass" hesapları için geçerli olmalı; diğer tüm hesaplar merkezi SCIM/IAM motoru tarafından açılıp kapatılmalıdır.
