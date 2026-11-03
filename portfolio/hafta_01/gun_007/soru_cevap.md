<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 007: Soru-Cevap ve Kavram Doğrulama

Bu belge, Mini Proje 1 (Güvenli Laboratuvar Sözleşmesi) konusuna ilişkin `SORU BANKASI` standartlarına göre katı 4 bölümlü formatta hazırlanmıştır.

---

### G007-SC1: Mini proje 1: güvenli laboratuvar sözleşmesi: Temel mekanizmayı ve güvenlik önemini açıkla.

#### 1. Yanıt
İlk haftanın amaç ve sınırlamaları (CIA üçlüsü, risk analizi, yasal kapsam, NIST CSF 2.0, varlık envanteri ve tehdit modelleme) doğrulanabilir bir kurulum sözleşmesine ve izole ağ topolojisine dönüştürülür. Bu mekanizma; güvenlik deneylerinin ve saldırı simülasyonlarının dış dünyaya (genel internet veya şirket ağına) sızmasını imkansız kılan, hipervizör kaçışlarını engelleyen ve her adımın etik/hukuki sınırlarını önceden çizen teknik ve idari bir güvenlik sözleşmesidir.

#### 2. Teknik Gerekçe
Siber güvenlik laboratuvarlarında kullanılan araçlar (exploitler, zararlılar, ağ tarayıcıları) doğası gereği yıkıcıdır. Laboratuvar ortamı Host-Only sanal ağlarla izole edilmezse, paketler kontrolsüz biçimde yerel ağa veya internete sızar. Ayrıca sanal makine misafir araçları (pano paylaşımı, paylaşılan klasörler) kapatılmazsa, zararlı yazılımlar hipervizör açıklarını kullanarak ana işletim sistemine sıçrayabilir (VM Escape). Bu sözleşme, hem teknik bariyerleri (Air-Gap) hem de idari onayları (CISO imzası) tek bir doğrulanabilir modelde birleştirir.

#### 3. Yaygın Hata
Laboratuvar kurulumunu yalnızca "VirtualBox veya VMware açıp içine Kali kurmak" sanmak; ağ adaptörünü varsayılan "Bridged" veya "NAT" modunda bırakarak internete ve ev/şirket ağına sızıntı riskini göz ardı etmek.

#### 4. Standart ve Kaynak
* ISO/IEC 27001:2022 Madde 8.31 (Geliştirme ve Test Ortamlarının Ayrılması).
* NIST SP 800-115: Technical Guide to Information Security Testing and Assessment.

---

### G007-SC2: Mini proje 1: güvenli laboratuvar sözleşmesi: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

#### 1. Yanıt
Laboratuvarımızın girdisi; tarafları, imzaları, izinli/yasaklı IP bloklarını, hipervizör güvenlik ayarlarını ve 5 düğümlü ağ topolojisini içeren `laboratuvar_sozlesmesi.json` veri dosyasıdır. İşlem, `lab_contract_validator.py` motorunun yasal onayları denetlemesi, IP çakışmalarını ve genel internet kapsamlarını sorgulaması ve hipervizör izolasyon açığı taraması yapmasıdır. Beklenen sonuç, 5 düğümün tam izolasyonla doğrulanması ve ASCII topoloji şemasının üretilmesidir. Negatif kontrol ise izinli kapsama genel internet (`0.0.0.0/0`) eklendiğinde veya pano paylaşımı açıldığında sistemin hata üretmesidir.

#### 2. Teknik Gerekçe
Siber güvenlik laboratuvarının açılış düğmesine basılmadan önce tüm ön koşulların otomatik olarak doğrulanması gerekir. İnsan dalgınlığıyla yapılabilecek küçük bir hata (örneğin internete açık bir IP bloğunun teste dahil edilmesi), şirketi doğrudan TCK 243/244 bilişim suçları kapsamına sokabilir. Doğrulama motorunun negatif kontrollerle bu hataları anında yakalaması operasyonel bir zorunluluktur.

#### 3. Yaygın Hata
Laboratuvar testlerinde yalnızca "her şeyin çalıştığı" ideal durumları denemek; yasaklı IP çakışması, köprü adaptör sızıntısı veya onaylanmamış taslak sözleşme senaryolarını test etmemek.

#### 4. Standart ve Kaynak
* NIST SP 800-53 Rev. 5: SC-7 (Boundary Protection) ve SA-11 (Developer Testing and Evaluation).
* OWASP Rules of Engagement (RoE) Framework.

---

### G007-SC3: 'Mini proje 1: güvenli laboratuvar sözleşmesi' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; laboratuvar sanal makinelerinin yanlışlıkla üretim ağına köprülenmesi (Bridged), zararlı yazılımın hipervizör zafiyetleriyle ana makineye sıçraması (VM Escape) veya testlerin izin verilmeyen harici sistemlere taşmasıyla oluşur. Risk, ağ trafiğinin analizi (sızıntı tespit sensörleri), sözleşme denetim betikleri ve hipervizör konfigürasyon taramalarıyla tespit edilir. Önleme ise katı Host-Only ağ kısıtlaması, pano/klasör paylaşımının kapatılması, acil durum panik butonu (vSwitch Down) ve çift taraflı imzalı kurulum sözleşmesiyle sağlanır.

#### 2. Teknik Gerekçe
Sanal makineler mantıksal olarak izole görünse de donanımsal olarak aynı işlemci, bellek ve ağ kartını paylaşırlar. Gelişmiş tehdit aktörleri sanal makine sürücülerindeki (vboxguest, vmx) bellek taşmalarını istismar ederek ana sisteme çıkabilir. Bu risk, donanım sanallaştırma izolasyonu (VT-x/AMD-V sıkılaştırması), misafir eklentilerinin tehlikeli özelliklerinin kapatılması ve sanal ağın fiziksel ağ kartından tamamen ayrılmasıyla (Air-Gap) sıfıra indirilir.

#### 3. Yaygın Hata
Zararlı yazılım analizini günlük kullanılan kişisel bilgisayarda izolesiz çalıştırmak; laboratuvardaki bir testin evdeki veya ofisteki diğer cihazları etkilemeyeceğini varsaymak.

#### 4. Standart ve Kaynak
* SANS Institute: "Building a Malware Analysis Laboratory".
* CIS Controls v8: Control 13 (Network Monitoring and Defense).
