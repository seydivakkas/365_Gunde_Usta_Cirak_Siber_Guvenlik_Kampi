# Gün 147: Mini Proje 20 — Bütünleşik Kurumsal IAM Politika Matrisi ve Katman Güvenliği

**Hafta 21 Kapanış Mini Projesi: Usta-Çırak Derinlemesine Teknik Dersi**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Özel Lisans — Tüm Hakları Saklıdır.*

---

## 🧭 Bölüm 1: Hafta 21'in Büyük Resmi ve Mini Projenin Amacı

> **Usta:** Evlat, bu hafta boyunca kurumsal savunmanın bel kemiğini inşa ettik.
> - **Gün 143'te:** Active Directory etki alanı yapısını, güven sınırlarını ve orman (forest) mimarisini modelledik.
> - **Gün 144'te:** Kerberos v5 bilet akışını (AS, TGS, AP takasları), PAC HMAC imzalarını ve bilet sahteciliği (Golden/Silver Ticket) saldırılarını inceledik.
> - **Gün 145'te:** Group Policy (GPO) öncelik kurallarını (LSDOU), kalıtım engellemeyi, GPP cpassword sızıntısını ve Windows LAPS uygulamasını denetledik.
> - **Gün 146'da:** İK otoriter kaynağından beslenen IAM Yaşam Döngüsünü (Joiner, Mover, Leaver), yetki birikimini (Privilege Creep) ve Görevler Ayrılığı (SoD) matrisini kurguladık.
>
> Şimdi **Mini Proje 20** ile bu parçaları tek bir potada eritiyoruz: **Kurumsal IAM Politika Matrisi!** Gerçek dünyada bir saldırgan son kullanıcı iş istasyonuna (Tier 2) sızdığında, hedefi doğrudan Domain Controller'ı (Tier 0) ele geçirmektir. Bu projede, saldırganın yatay geçişini ve yetki yükseltmesini imkansız kılan **Microsoft Enterprise Access Katmanlama Modelini (Tier 0 - Tier 1 - Tier 2)**, **Kerberos Kısıtlı Delegasyonunu (RBCD)** ve **Sıfır Güven (Zero Trust) ABAC motorunu** inşa edeceğiz.
>
> **Çırak:** Usta, yani tek bir matris üzerinden hem katman izolasyonunu hem de dinamik oturum riskini aynı anda mı kontrol edeceğiz?
>
> **Usta:** Kesinlikle! Bir kullanıcı kim olursa olsun; doğru katmanda değilse, cihazı kurumsal şartlara uymuyorsa veya üzerinde zehirli bir SoD rolü taşıyorsa kapı yüzüne kapanacak!

---

## 🏛️ Bölüm 2: Microsoft Enterprise Access Katmanlama Modeli (Tiering)

Geleneksel ağlarda herkes herkese erişebilir; bu bir felakettir. Modern kurumsal mimaride Microsoft'un Privileged Access Tiering modeli üç katmandan oluşur:

```text
+-----------------------------------------------------------------------------------+
|            TIER 0 : KİMLİK VE GÜVENLİK KONTROL DÜZLEMİ (CONTROL PLANE)            |
|  - Domain Controllers (DC), PKI/CA, AD FS, Azure AD Connect, Tier-0 PAW           |
|  - KURAL: Tier-0 hesapları ASLA Tier-1 veya Tier-2 makinelerinde oturum açamaz!   |
+-----------------------------------------+-----------------------------------------+
                                          | (Yalnızca PAW ve Güvenli Yönetim)
                                          v
+-----------------------------------------------------------------------------------+
|            TIER 1 : KURUMSAL SUNUCULAR VE UYGULAMALAR (DATA PLANE)                |
|  - Kurumsal Veritabanları (SQL/Oracle), ERP, CRM, Dosya ve Web Sunucuları          |
|  - KURAL: Sunucularda LAPS ve kısıtlı delegasyon (RBCD) zorunludur.              |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|            TIER 2 : KULLANICI UÇ NOKTALARI (USER ACCESS PLANE)                     |
|  - Standart Çalışan İş İstasyonları, Taşınabilir Cihazlar, Yazıcılar              |
|  - KURAL: Tier-2 asla doğrudan Tier-0'a erişemez; yatay geçiş LAPS ile engellenir.|
+-----------------------------------------------------------------------------------+
```

### Katman İzolasyonunun Matematiksel Savunma Mantığı:
Bir saldırgan bir Tier-2 iş istasyonunu ele geçirdiğinde, belleği (LSASS) tarayarak yönetici parolalarını veya Kerberos biletlerini çalmaya çalışır (**Credential Dumping / Mimikatz**).
Eğer bir Domain Admin (Tier 0), destek vermek için o Tier-2 iş istasyonuna RDP yaparsa veya oturum açarsa, NTLM hash'i veya TGT bileti o makinenin belleğinde kalır! Saldırgan bu hash'i alarak anında tüm etki alanını ele geçirir (**Pass-the-Hash / Overpass-the-Hash**).
**Altın Çözüm:** GPO üzerinden `DenyLogonLocally`, `DenyLogonThroughRemoteDesktopServices` ve `DenyLogonAsNetworkService` kuralları ile Tier-0 hesaplarının Tier-1 ve Tier-2 makinelerine oturum açması donanımsal ve mantıksal olarak yasaklanır!

---

## 🔐 Bölüm 3: Kerberos Yetki Devri (Delegation) Evrimi

Kurumsal mimaride çok katmanlı web uygulamaları (Web -> SQL) kullanıcı adına veritabanına bağlanmak ister. Bunun Kerberos protokolündeki karşılığı **Delegation (Yetki Devri)**dir:

1. **Kısıtlamasız Yetki Devri (Unconstrained Delegation - YASAK!):**
   - İstemci web sunucusuna bağlandığında, KDC'den aldığı TGT biletinin bir kopyasını web sunucusuna verir.
   - *Risk:* Eğer saldırgan web sunucusunu ele geçirirse, o web sunucusuna bağlanan HERKESİN (Domain Admins dahil) TGT biletini LSASS belleğinden çalarak Domain Controller'ı ele geçirebilir!
2. **Kısıtlı Yetki Devri (Constrained Delegation / S4U):**
   - Sunucuya yalnızca belirli SPN'lere (Service Principal Name) yetki devri yapma hakkı tanınır.
3. **Kaynak Tabanlı Kısıtlı Yetki Devri (Resource-Based Constrained Delegation - RBCD):**
   - En modern ve güvenli yaklaşım. Yetki devri iznini öndeki web sunucusu değil, **arkadaki hedef kaynak (SQL veritabanı)** kendi `msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliği üzerinden belirler. Böylece yetki kontrolü hedef kaynağın elinde kalır.

---

## 🎯 Bölüm 4: Sıfır Güven (Zero Trust) ve ABAC Koşullu Erişim

Statik roller (RBAC) modern tehditleri durdurmaya yetmez. Kullanıcının kimliğinin yanı sıra **bağlamı (Context)** da değerlendirilmelidir:

$$\text{Erişim Kararı} = \text{RBAC(Rol)} \land \text{TierUyum} \land \text{MFA} \land \text{CihazUyumu} \land (\text{RiskSkoru} < 0.70) \land \neg\text{SoDİhlali}$$

- **MFA Doğrulaması:** Özellikle Tier-0 ve Tier-1 kaynaklara erişimde FIDO2/TOTP zorunluluğu.
- **Cihaz Uyumluluğu (Compliant Device):** EDR ajanı çalışan, BitLocker şifrelemesi aktif ve güncel işletim sistemine sahip cihazlar.
- **Risk Skoru / İmkansız Seyahat (Impossible Travel):** Kullanıcı 10 dakika önce İstanbul'dan oturum açmışken, 5 dakika sonra yabancı bir IP bloğundan istek gelirse risk skoru 0.85'e fırlar ve oturum derhal engellenir.
- **Görevler Ayrılığı (SoD):** Finansal süreçlerde fatura oluşturan ile onaylayan yetkilerinin aynı kişide birleşmesi engellenir.

---

## 🛠️ Bölüm 5: Mini Proje 20 Denetim ve Uygulama Mimarisi

Bugün geliştirdiğimiz `IAMPolicyMatrixEngine`:
1. Kurumsal JSON spesifikasyonunu okur.
2. Tüm kullanıcı ve kaynakları Katman (Tier 0-2) matrisine yerleştirir.
3. Erişim taleplerini mikro-saniyeler içinde dinamik ABAC kurallarıyla değerlendirir.
4. Kısıtlamasız delegasyonları, yetim hesapları ve katman ihlallerini tespit eder.
5. Zafiyetleri otomatik olarak düzelten kurumsal `iam_matrix_sertlestirme.ps1` betiğini üretir.

---

## 🎓 Usta Öğüdü ve Altın Kural

> **"Evlat, güçlü bir savunma yüksek duvarlarla değil, doğru katmanlarla kurulur. Bir etki alanı yöneticisinin standart kullanıcının bilgisayarına oturum açtığı gün, o şirket zaten hacklenmiştir. Katman sınırları delinemez, taviz verilemez kurallardır!"**
