<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 003: Etik, Yasal Yetki ve Test Kapsamı
## Angajman Kuralları (Rules of Engagement - RoE), TCK 243/244 ve Kapsam Kapısı Mimarisi

---

### 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Masamıza otur evlat. Bugün belki de 365 günlük serüven boyunca seni hapisten, mahkemelerden ve kariyerini bitirecek adli felaketlerden koruyacak en hayati dersi işliyoruz: **Yasal Yetki, Etik ve Test Kapsamı.**

Sana çok net bir zihinsel model anlatacağım:
Bir çilingir düşün. Çilingirin elinde her türlü kilidi açabilen onlarca özel maymuncuk ve alet takımı vardır. 
- Bir apartman sakini anahtarını kaybeder, kimliğini ve tapusunu gösterir, çilingire "Lütfen dairemin kapısını aç" der. Çilingir kapıyı açar, parasını alır ve evine gider. Bu **yasal, meşru ve etik** bir hizmettir.
- Aynı çilingir, gece vakti komşusunun dairesinin kilidini "Bakalım bu kilit sağlam mıymış, komşuma iyilik olsun diye deneyeyim" diyerek gizlice kurcalarsa ne olur? O artık bir çilingir değil, **hırsız ve konut dokunulmazlığını ihlal eden bir suçludur!**

İşte siber güvenlikteki araçlar (Nmap, Wireshark, Burp Suite, Metasploit) o çilingir aletleridir! 
Seni bir "siber güvenlik uzmanı" ile "siber korsan (hacker)" arasındaki farkı belirleyen şey klavyendeki hızın değil; **elindeki ıslak imzalı YASAL YETKİ BELGESİDİR (Rules of Engagement - RoE).**

Unutma: Kendi bilgisayarına veya kendi kurduğun sanal laboratuvara istediğini yapabilirsin. Ancak kablonun ucu başkasının sistemine değdiği anda, yazılı izin yoksa suç işliyorsun demektir!

---

### 2. Sıfırdan Başlayan Kristal Netliğinde Teori (0'dan Uzmanlığa Derinlik)

Hukuk ve etik kavramlarını teknik bir güvenlik mühendisi bakışıyla inceleyelim.

```
                      +---------------------------------------+
                      |       YAZILI YETKİLENDİRME (RoE)     |
                      |   (Hangi hedef, ne zaman, nasıl?)     |
                      +-------------------+-------------------+
                                          |
                +-------------------------+-------------------------+
                |                                                   |
                v                                                   v
   +-------------------------+                         +-------------------------+
   |  KAPSAM İÇİ (In-Scope)  |                         | KAPSAM DIŞI (Out-of-Sc.)|
   | - Test sunucuları       |                         | - Canlı ödeme sistemleri|
   | - Belirlenmiş IP/subnet |                         | - Ağ omurgası/Firewall  |
   | - İzinli API uçları     |                         | - Üçüncü taraf servisler|
   +------------+------------+                         +------------+------------+
                |                                                   |
                v                                                   v
         [İZİNLİ VE GÜVENLİ]                               [TCK 243-244 KAPSAMINDA SUÇ!]
```

#### A. Yasal Mevzuat ve Kanun Maddeleri (Türkiye ve Dünya)
1. **Türk Ceza Kanunu (TCK) Madde 243:** "Bir bilişim sisteminin bütününe veya bir kısmına, hukuka aykırı olarak giren veya orada kalmaya devam eden kimseye bir yıla kadar hapis veya adlî para cezası verilir."
   *Hocanın Notu:* Sisteme hiçbir zarar vermesen bile, sadece izinsiz giriş yapıp ekrana bakman dahi TCK 243 uyarınca suçtur!
2. **TCK Madde 244:** "Bir bilişim sisteminin işleyişini engelleyen veya bozan kişi, bir yıldan beş yıla kadar hapis cezası ile cezalandırılır. Bir bilişim sistemindeki verileri bozan, yok eden, değiştiren veya erişilmez kılan... altı aydan üç yıla kadar hapis."
   *Hocanın Notu:* İzin almadan DoS/DDoS testi yapmak, canlı veriyi değiştirmek doğrudan bu kapsama girer.
3. **Uluslararası Hukuk (CFAA - Computer Fraud and Abuse Act):** ABD ve uluslararası arenada yetkisiz erişimi ağır federal suç sayan temel yasa.

#### B. Sızma Testi Angajman Kuralları (Rules of Engagement - RoE)
Profesyonel bir güvenlik testine başlamadan önce müşteri ile analist arasında imzalanan bu sözleşme şu 4 sacayağını barındırır:
- **Kapsam İçi (In-Scope):** Test edilmesine açıkça izin verilen IP adresleri, alan adları ve web servisleri.
- **Kapsam Dışı (Out-of-Scope):** Kesinlikle dokunulmaması gereken varlıklar (Canlı üretim veritabanları, ödeme ağ geçitleri, ağ omurga yönlendiricileri).
- **Test Zaman Penceresi (Testing Window):** Testin yapılabileceği gün ve saatler (Örn: Hafta içi 09:00 - 18:00 veya mesai dışı bakım penceresi).
- **Yasaklı Faaliyetler (Prohibited Actions):** Sistemin çökmesine yol açabilecek DoS/DDoS saldırıları, veri silme, çalışanlara yönelik izinsiz oltalama (phishing) veya fidye simülasyonları.

---

### 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

| Durum | Kötü Niyetli Saldırgan (Black Hat) | Etik Güvenlik Uzmanı (White Hat) |
| :--- | :--- | :--- |
| **Hedef Seçimi** | Sınır tanımaz; canlı sistemlere, üçüncü taraf servis sağlayıcılara, çalışanların kişisel hesaplarına saldırır. | Yalnızca sözleşmede yazılı olan IP ve alan adlarına odaklanır; kapsam dışı hedeflere tek bir ping dahi atmaz. |
| **Yıkıcılık** | Verileri çalar, şifreler, sistemleri çökerterek fidye talep eder veya hizmeti durdurur. | Sisteme asla zarar vermez; DoS yapmaz; bulduğu açığı zararsız bir PoC (Proof of Concept) ile kanıtlayıp raporlar. |
| **Yasal Dayanak** | Kanun tanımaz, suç örgütleriyle çalışır. | Islak/dijital imzalı RoE sözleşmesiyle, avukatlar ve yönetim kurulu onayıyla çalışır. |

---

### 4. Hocayla Birlikte Canlı Laboratuvar (Adım Adım Gerçek Kod ve Komutlar)

Bugün geliştirdiğimiz Yasal Kapsam Kapısı (RoE Gatekeeper) uygulamasını çalıştıracağız.

#### Adım 1: Kapsam Politikası Dosyamızı İnceleyelim
Dosyamız: [`kapsam_belgesi.json`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/ornek_veri/kapsam_belgesi.json)
İçinde Acme Finans A.Ş. için tanımlanmış:
- İzinli IP'ler: `192.168.10.50`, `192.168.10.51`, `192.168.10.48/28` ağı
- Yasaklı IP'ler: `192.168.10.1` (Router), `canli-odeme.acme-finans.com`, `8.8.8.8` (Harici)
- Yasaklı Eylemler: `DOS_ATTACK`, `DATA_DELETION`

#### Adım 2: Kapsamlı Güvenlik Denetimini Çalıştırma
```powershell
python portfolio/hafta_01/gun_003/uygulama/scope_validator.py --audit
```

**Konsol Çıktısı Analizi:**
1. **İzinli Faaliyetler Onaylandı:** `192.168.10.50` üzerinde `PORT_SCAN` ve `dev-portal.acme-finans.local` üzerinde `WEB_VULN_SCAN` yasal olarak onaylandı.
2. **Yasaklı Hedefler Bloke Edildi:** `8.8.8.8` ve `192.168.10.1` hedeflerine yönelik girişimler `ExplicitlyForbiddenTargetError` ile durduruldu.
3. **Kapsam Dışı Hedef Reddedildi:** Listede olmayan `10.99.99.50` hedefi `OutOfScopeTargetError` ile engellendi.
4. **Yıkıcı Eylemler Engellendi:** İzinli hedef bile olsa `DOS_ATTACK` ve `DATA_DELETION` eylemleri `ForbiddenActionError` ile derhal bloke edildi!

#### Adım 3: Manuel Tekil Sorgu Yapma
Bir analist şüpheli bir hedefi taramadan önce şu komutla yetkisini teyit edebilir:
```powershell
python portfolio/hafta_01/gun_003/uygulama/scope_validator.py --check --target 192.168.10.50 --action PORT_SCAN
```
*Sonuç:* `[+] ONAY: '192.168.10.50' hedefine 'PORT_SCAN' faaliyeti uygulamak YASAL VE İZİNLİDİR.`

---

### 5. Hocanın "Ölümcül Hatalar ve Mülakat Tuzakları" Notu

> [!WARNING]
> **Ölümcül Hata 1: "İyi niyetliydim, açığı bulup yönetime mail atacaktım; o yüzden suç işlemedim."**
> Bu savunma adliyelerde en çok duyulan ama Türk Ceza Kanunu karşısında 1 saniye bile geçerliliği olmayan trajik bir hatadır. İster şirket CEO'sunun oğlu ol, ister dünyanın en iyi niyetli insanı ol; yazılı izin olmadan bir sisteme paket göndermek, zafiyet taramak suçtur. Bug bounty (ödül avcılığı) yapacaksanız dahi HackerOne veya Bugcrowd üzerindeki açık kapsam kurallarını harfiyen okumak zorundasınız!

> [!NOTE]
> **Mülakat Sorusu: "Sızma testi sırasında hedef şirketin yan kuruluşuna veya barındırma sağlayıcısının (AWS/Azure) altyapısına denk gelirsen ne yaparsın?"**
> **Doğru Yanıt:** "Derhal testi durdururum! Müşterinin bana verdiği izin yalnızca kendi sahip olduğu varlıkları kapsar. Üçüncü taraf bulut sağlayıcıları veya yan kuruluşlar kapsam dışıdır. Kapsamı genişletmek için müşteri ve bulut sağlayıcıdan ek yazılı izin alınana kadar o hedefe tek bir istek dahi gönderilmez."

---

### 6. Günün Pratik Görevi (Challenge & Walkthrough)

**Müfredat Görevi:** Kurgusal laboratuvar için izin verilen ve yasaklanan faaliyetleri belgeleyen kapsam dosyasını hazırla ve doğrula:
1. **İzinli Hedefler:** Test web sunucusu (`192.168.10.50`), geliştirme veritabanı (`192.168.10.51`), test CIDR ağı (`192.168.10.48/28`).
2. **Yasaklı Hedefler:** Canlı ödeme altyapısı (`canli-odeme.acme-finans.com`), ağ geçidi yönlendiricisi (`192.168.10.1`), genel internet IP'leri (`8.8.8.8`).
3. **İzinli Faaliyetler:** Pasif keşif, port taraması, servis sürüm tespiti (banner grabbing), web zafiyet taraması.
4. **Yasaklı Faaliyetler:** DoS/DDoS, veri silme veya değiştirme, sosyal mühendislik, brute-force hesap kilitleme.

---

### 7. Hocanın Soru Odası (Excel Soru Bankası Detaylı Yanıtları)

#### Soru 1 (G003-SC1): Etik, yasal yetki ve test kapsamı: Temel mekanizmayı ve güvenlik önemini açıkla.
- **1. Yanıt:** Siber güvenlik dünyasında bir faaliyeti "meşru güvenlik testi" veya "bilişim suçu" yapan temel unsur teknik yöntem değil, **yasal yetki (Authorization) ve kapsam sınırlarıdır (Scope / RoE).**
- **2. Teknik Gerekçe:** TCK Madde 243 bilişim sistemine yetkisiz girmeyi, Madde 244 ise sistemi engellemeyi veya verileri bozmayı (DoS/veri silme) suç sayar. Meşru zemin, sistem sahibi ile imzalanan **Angajman Kuralları (Rules of Engagement - RoE)** sözleşmesidir.
- **3. Yaygın Hata:** "İyi niyetliydim, açığı bildirecektim" savunması mahkemede geçersizdir; yazılı izin olmadan yapılan tarama suç teşkil eder.
- **4. Standart ve Kaynak:** TCK Madde 243 & 244 | ABD CFAA | PTES Pre-engagement Standard.

#### Soru 2 (G003-SC2): Etik, yasal yetki ve test kapsamı: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?
- **1. Yanıt:** Gün 003 laboratuvarı (`scope_validator.py`), sızma testi öncesi yasal kapsam ve eylem denetimini ölçülebilir teknik kontrollerle doğrular.
- **2. Teknik Gerekçe:** Girdi: `kapsam_belgesi.json` RoE politikası ve hedef/eylem parametreleri. İşlem: IP/CIDR/Domain doğrulaması ve eylem izin kontrolü. Beklenen Sonuç: İzinli hedeflerin (`192.168.10.50`, `dev-portal.acme-finans.local`) ve eylemlerin (`PORT_SCAN`, `WEB_VULN_SCAN`) onaylanması.
- **3. Yaygın Hata (Negatif Kontrol):** Canlı üretim sistemlerini veya üçüncü taraf IP'leri kazara taramak. Negatif kontrollerimiz: Dış IP (`8.8.8.8`) veya canlı ödeme sistemi sorgulandığında `ExplicitlyForbiddenTargetError`; kapsam dışı IP'de `OutOfScopeTargetError`; yıkıcı `DOS_ATTACK` veya `DATA_DELETION` istendiğinde `ForbiddenActionError` üretilmesidir.
- **4. Standart ve Kaynak:** NIST SP 800-115 (Planning and Scoping).

#### Soru 3 (G003-SC3): 'Etik, yasal yetki ve test kapsamı' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?
- **1. Yanıt:** Risk; analistin yazılı izin sınırlarını aşması, canlı üretim sistemlerine yetkisiz müdahale etmesi veya yıkıcı testlerle hizmeti aksatmasıyla oluşur.
- **2. Teknik Gerekçe:** Kapsam dışı sunucuya saldırılması, canlı veritabanının DoS ile kilitlenmesi veya izinsiz zafiyet tespiti yasal ve operasyonel risk yaratır. Çalıştırma Öncesi Doğrulama (Pre-execution Gatekeeper), ağ analizi ve SIEM loglarıyla tespit edilir; imzalı RoE ve kapsam filtreleriyle önlenir.
- **3. Yaygın Hata:** Kendi sanal makinesini test etmek ile müşterinin sistemini test etmeyi aynı yetki sanmak. Üçüncü taraf sağlayıcıların da politikalarına uyulması zorunludur.
- **4. Standart ve Kaynak:** ISO/IEC 27001:2022 Ek A.5.31 | OSSTMM 3.0.
