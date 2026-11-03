<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 003: Soru ve Cevap Odası
## Etik, Yasal Yetki ve Test Kapsamı — Sızma Testi Angajman Kuralları (RoE)

---

### Soru 1 (G003-SC1): Etik, yasal yetki ve test kapsamı: Temel mekanizmayı ve güvenlik önemini açıkla.

- **1. Yanıt:** Siber güvenlik dünyasında bir faaliyeti "meşru güvenlik testi" veya "bilişim suçu" yapan temel unsur teknik yöntem değil, **yasal yetki (Authorization) ve kapsam sınırlarıdır (Scope / RoE).**
- **2. Teknik Gerekçe:** Türk Ceza Kanunu (TCK) Madde 243 bilişim sistemine yetkisiz girmeyi ve kalmayı, Madde 244 ise sistemi engellemeyi, bozmayı veya verileri değiştirmeyi (DoS/tahrifat) hapis cezasıyla suç sayar. Bu suçların oluşmasını engelleyen yegane meşru zemin, sistem sahibi ile imzalanan yazılı **Angajman Kuralları (Rules of Engagement - RoE)** sözleşmesidir.
- **3. Yaygın Hata:** "İyi niyetliyim, güvenlik açığını bulup yardım etmek için bildirecektim" savunması. Hukukta iyi niyet yetkisiz erişimi suç olmaktan çıkarmaz; yazılı izin olmadan yapılan her tarama hukuka aykırıdır.
- **4. Standart ve Kaynak:** TCK Madde 243 & 244 | ABD CFAA (Computer Fraud and Abuse Act) | PTES (Penetration Testing Execution Standard - Pre-engagement).

---

### Soru 2 (G003-SC2): Etik, yasal yetki ve test kapsamı: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

- **1. Yanıt:** Gün 003 laboratuvarı ([`scope_validator.py`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/uygulama/scope_validator.py)), sızma testi öncesi yasal kapsam ve eylem denetimini ölçülebilir teknik kontrollerle doğrular.
- **2. Teknik Gerekçe:**
  - *Girdi:* [`kapsam_belgesi.json`](file:///c:/Users/seydieryilmaz/Desktop/Siber_Guvenlik_365_Gun_Standart_ve_Mufredat_Paketi/portfolio/hafta_01/gun_003/ornek_veri/kapsam_belgesi.json) RoE politikası ve test edilecek hedef IP/eylem çiftleri.
  - *İşlem:* IP ve CIDR ağ bloğu doğrulaması, alan adı eşleştirmesi, eylem izin ve yasak filtrelemesi.
  - *Beklenen Sonuç:* Kapsam içi test hedeflerinin (`192.168.10.50`, `dev-portal.acme-finans.local`) ve zararsız tarama faaliyetlerinin (`PORT_SCAN`, `WEB_VULN_SCAN`) onaylanması.
- **3. Yaygın Hata (Negatif Kontrol):** Canlı sistemleri veya üçüncü taraf servisleri kazara taramak. Negatif kontrollerimiz: Dış IP (`8.8.8.8`) veya canlı ödeme sistemi (`canli-odeme.acme-finans.com`) sorgulandığında `ExplicitlyForbiddenTargetError`; kapsam dışı IP sorgulandığında `OutOfScopeTargetError`; yıkıcı `DOS_ATTACK` veya `DATA_DELETION` istendiğinde `ForbiddenActionError` fırlatılmasıdır.
- **4. Standart ve Kaynak:** NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment, Bölüm 2: Planning and Scoping).

---

### Soru 3 (G003-SC3): 'Etik, yasal yetki ve test kapsamı' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

- **1. Yanıt:** Risk; analistin yazılı izin sınırlarını aşması, canlı üretim sistemlerine yetkisiz müdahale etmesi veya yıkıcı testlerle hizmeti aksatmasıyla oluşur.
- **2. Teknik Gerekçe:**
  - *Oluşumu:* Heyecanla veya dikkatsizlikle kapsam dışı bir sunucuya saldırılması, canlı veritabanının DoS ile kilitlenmesi veya izinsiz zafiyet araştırması yapılması yasal ve operasyonel risk yaratır.
  - *Tespiti:* Çalıştırma Öncesi Doğrulama (Pre-execution Gatekeeper), ağ trafiği analizi ve güvenlik duvarı loglarının sözleşmeyle karşılaştırılmasıyla tespit edilir.
  - *Önlenmesi:* Islak/dijital imzalı RoE sözleşmesi, test araçlarında kapsam dışı hedefleri engelleyen filtreler (scope exclusions) ve yıkıcı eylemlerin (DoS/veri silme) kod seviyesinde engellenmesiyle önlenir.
- **3. Yaygın Hata:** Kendi evindeki sanal makineye test yapmak ile müşterinin bulutundaki sunucuya test yapmayı aynı yetki sanmak. Üçüncü taraf servis sağlayıcıların (AWS, Azure vb.) da test politikalarına uyulması zorunludur.
- **4. Standart ve Kaynak:** ISO/IEC 27001:2022 Ek A.5.31 (Yasal, Düzenleyici ve Sözleşmeye Bağlı Gereksinimler) | OSSTMM 3.0.
