<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 143: Active Directory Etki Alanı — Usta-Çırak Dersi

**Modül:** Hafta 21 (Zafiyet Yönetimi, Güvenlik Açıkları ve Otomasyon)  
**Konu:** Active Directory Domain Services (AD DS) Mimarisi ve Etki Alanı Güvenliği  
**Pedagojik Yaklaşım:** Usta-Çırak / Hoca Dersi Modeli  
**Standartlar:** Microsoft AD DS Hardening Guidelines, CIS Windows Server Benchmark, MITRE ATT&CK Enterprise Matrix

---

## 1. Ustanın Girişi: "Kurumsal Ağların Beyni ve Taht Odası"

> "Yaklaş çırak, bugün siber güvenlik dünyasının en büyük ve en kritik kalelerinden birinin kapısını aralıyoruz: **Active Directory (Etki Alanı Hizmetleri)**.
>
> Dünyadaki Fortune 500 şirketlerinin %90'ından fazlası, tüm kullanıcılarını, bilgisayarlarını, sunucularını, yetkilerini ve sertifikalarını Active Directory üzerinde yönetir. Yani bir kurumsal ağın kalbi, beyni ve taht odası burasıdır.
>
> Bir saldırgan bir şirkete sızdığında nihai hedefi daima aynıdır: **Domain Admin** olmak ve etki alanı denetleyicisini (Domain Controller - DC) ele geçirmek. DC düştüğü anda, o şirketteki her bilgisayar, her e-posta, her veri tabanı ve her şifreli dosya saldırganın eline geçer.
>
> Bu yüzden bir güvenlik mühendisi, Active Directory'yi sadece 'kullanıcı ekleyip çıkarma aracı' olarak göremez. Kerberos protokolünün bilet mekanizmasını, NTLM'in zayıflıklarını, LDAP imzalama zorunluluğunu ve delegasyon risklerini iliklerine kadar bilmelidir."

---

## 2. Active Directory Mimari Hiyerarşisi

Active Directory nesneleri mantıksal bir hiyerarşi içinde organize edilir:

```
+-------------------------------------------------------------------------+
| ORMAN (FOREST): En üst güvenlik sınırıdır (Security Boundary).          |
| -> Kendi şemasına (Schema) ve Global Catalog'a (GC) sahiptir.          |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| AĞAÇ (TREE) & ETKİ ALANI (DOMAIN): Yönetim sınırıdır (Admin Boundary).  |
| -> Örn: corp.internal, us.corp.internal                                 |
| -> Ortak bir güvenlik ilkesini ve dizin veritabanını (NTDS.dit) paylaşır|
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| ÖRGÜTSEL BİRİM (OU - ORGANIZATIONAL UNIT): GPO ve yetki devri konteyneri|
| -> Örn: OU=Servers, OU=Users, OU=Tier0_Admins                           |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| NESNELER: Kullanıcılar, Gruplar, Bilgisayarlar, Servis Hesapları (gMSA) |
+-------------------------------------------------------------------------+
```

### FSMO Rolleri (Flexible Single Master Operations)
Etki alanı denetleyicileri çoklu ana (multi-master) mimaride çalışırken, çakışmayı önlemek için 5 kritik rol tek bir DC'ye atanır:
1. **Schema Master (Orman Çapında):** Dizin şemasını değiştirme yetkisi.
2. **Domain Naming Master (Orman Çapında):** Yeni etki alanı ekleme/çıkarma yetkisi.
3. **PDC Emulator (Etki Alanı Çapında):** Parola değişikliklerinin ilk işlendiği, saat senkronizasyonunu sağlayan ve hesap kilitlenmelerini yöneten en kritik rol.
4. **RID Master (Etki Alanı Çapında):** Nesnelere benzersiz SID havuzu dağıtan rol.
5. **Infrastructure Master (Etki Alanı Çapında):** Gruplar arası nesne referanslarını güncelleyen rol.

---

## 3. Kimlik Doğrulama: Kerberos v5 Protokolü

Active Directory'nin varsayılan ve en güçlü kimlik doğrulama protokolü **Kerberos v5**'tir (Port 88). Üç başlı köpek Kerberos gibi, üç taraf arasında işler: **Kullanıcı**, **KDC (Key Distribution Center - DC)** ve **Hedef Servis**.

```
  [ KULLANICI ]                 [ KDC / DOMAIN CONTROLLER ]          [ HEDEF SERVİS (SQL/Web) ]
        │                                    │                                    │
        │─── 1. AS-REQ (Ön Kimlik Doğrulama) ─>│                                    │
        │<── 2. AS-REP (TGT Bilet + Oturum K)─│                                    │
        │                                    │                                    │
        │─── 3. TGS-REQ (TGT + Hedef SPN) ──>│                                    │
        │<── 4. TGS-REP (Servis Bileti - ST) ─│                                    │
        │                                    │                                    │
        │─── 5. AP-REQ (Servis Bileti) ──────────────────────────────────────────>│
        │<── 6. AP-REP (Karşılıklı Doğrulama) ────────────────────────────────────│
```

1. **AS-REQ / AS-REP:** Kullanıcı parolasının karmasıyla (hash) şifrelenmiş bir zaman damgası gönderir (Pre-Authentication). DC doğrularsa `krbtgt` hesabı tarafından imzalanmış **TGT (Ticket Granting Ticket)** döner.
2. **TGS-REQ / TGS-REP:** Kullanıcı TGT biletini sunarak belirli bir servis (SPN) için bilet ister. DC, hedef servisin parola karmasıyla şifrelenmiş **Servis Bileti (TGS/ST)** üretir.
3. **AP-REQ:** Kullanıcı servis biletini hedef sunucuya sunar ve oturum açar.

---

## 4. Active Directory'nin En Tehlikeli 4 Saldırı Vektörü

### 4.1. Kerberoasting (T1558.003)
- **Nasıl Çalışır:** Etki alanındaki standart (en düşük yetkili) bir kullanıcı, ağdaki herhangi bir servis hesabı için SPN talebinde bulunarak (`setspn -T`) KDC'den Servis Bileti (TGS) isteyebilir. KDC bu bileti servis hesabının NTLM karmasıyla şifreler. Saldırgan bu bileti RAM'den çeker ve çevrimdışı (offline) Hashcat/John the Ripper ile kırar.
- **Önlem:**
  - Servis hesaplarında en az 25+ karakterlik karmaşık parolalar kullanılmalı veya **gMSA (Group Managed Service Accounts)** tercih edilmelidir.
  - Ayrıcalıklı yönetici hesaplarına (Domain Admins) asla SPN tanımlanmamalıdır.
  - RC4-HMAC şifreleme kapatılmalı, AES zorlanmalıdır.

### 4.2. AS-REP Roasting (T1558.004)
- **Nasıl Çalışır:** Bazı eski uygulamalar için hesaplarda `DONT_REQ_PREAUTH` (Kerberos Ön Kimlik Doğrulama Gerekmez) bayrağı açılır. Saldırgan, hedef kullanıcı adına KDC'ye AS-REQ gönderir. KDC şifre kontrolü yapmadan kullanıcının parola karmasıyla şifrelenmiş AS-REP paketini döner. Saldırgan bu paketi çevrimdışı kırar.
- **Önlem:** Hiçbir hesapta `DONT_REQ_PREAUTH` bayrağı aktif olmamalıdır.

### 4.3. Sınırsız Delegasyon (Unconstrained Delegation - T1558.002)
- **Nasıl Çalışır:** Bir sunucuya "Unconstrained Delegation" yetkisi verildiğinde, o sunucuya bağlanan herhangi bir kullanıcının (Domain Admin dahil) TGT bileti o sunucunun RAM'inde saklanır. Saldırgan o sunucuyu ele geçirdiği anda, bellekteki Domain Admin TGT biletini çalarak tüm etki alanını ele geçirir.
- **Önlem:** Sınırsız delegasyon tamamen yasaklanmalı, yalnızca **Kısıtlı Delegasyon (Constrained Delegation)** veya **RBCD (Resource-Based Constrained Delegation)** kullanılmalıdır.

### 4.4. Golden Ticket ve krbtgt Parolası (T1558.001)
- **Nasıl Çalışır:** Saldırgan DC'ye sızıp `krbtgt` hesabının parola karmasını ele geçirirse; sahte bir TGT bileti (Golden Ticket) üreterek kendini istediği gruba (Enterprise Admins) ekleyebilir. Bu bilet 10 yıl geçerli kılınabilir ve DC parola değişikliklerinden etkilenmez.
- **Önlem:** `krbtgt` hesabının parolası yılda en az 2 kez (ardışık iki defa) Microsoft'un `Reset-KrbTgt-Password` betiği ile sıfırlanmalıdır.

---

## 5. Protokol Sıkılaştırma: NTLM, LDAP ve SMB

1. **NTLMv1'in Yasaklanması:** NTLMv1 DES tabanlıdır ve gökkuşağı tablolarıyla (rainbow tables) dakikalar içinde kırılabilir. GPO'da `LmCompatibilityLevel = 5` (Yalnızca NTLMv2) zorunlu tutulmalıdır.
2. **LDAP İmzalama ve Kanal Bağlama (Channel Binding):** Saldırganların NTLM kimlik doğrulamasını LDAP üzerine yansıtmasını (LDAP Relay) önlemek için `LDAPServerIntegrity = 2` (Require signature) ve `LdapEnforceChannelBinding = 2` yapılmalıdır.
3. **SMB İmzalama (SMB Signing):** NTLM Relay saldırılarının en yaygın hedefi SMB servisidir. DC ve kritik sunucularda SMB Signing zorunlu (`RequireSecuritySignature = True`) tutulmalıdır.

---

## 6. Ustanın Çırağa Öğüdü

> "Unutma çırak: Active Directory'de güvenliği sağlamak, surlara okçu dizmekle bitmez; kalenin içindeki hainleri ve açık pencereleri kapatacaksın.
> Bir etki alanını yönetirken şu üç altın kuralı aklından çıkarma:
> 1. `krbtgt` şifresini unutan yönetici, saldırgana sınırsız altın anahtar bırakmıştır.
> 2. Domain Admin hesabına SPN bağlayan yönetici, şifresini panoya asmış demektir.
> 3. NTLMv1 ve imzasız LDAP'ı açık bırakan kurum, ağındaki her stajyeri potansiyel root yapmıştır.
>
> Kodunu sıkı tut, GPO'nu denetle ve Active Directory'yi daima katmanlı Tier modeliyle koru!"
