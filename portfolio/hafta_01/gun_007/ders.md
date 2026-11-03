<!-- ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR / Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) -->
<!-- Açık kaynak lisans (MIT, GPL, Apache vb.) KULLANILMAZ. -->

# GÜN 007: Mini Proje 1 — Güvenli Laboratuvar Kurulum Sözleşmesi ve Topolojisi

---

## 1. Hocanın Giriş Sohbeti & Zihinsel Model (Mental Model)

Evlat, tebrik ederim! İlk haftanın sonuna, siber güvenlik yolculuğumuzun ilk büyük dönüm noktasına (Milestone 1) ulaştık.
Geriye dönüp baktığında masaya neler koyduğumuzu hatırla:
* **G001:** CIA Üçlüsü ile güvenliğin felsefesini kurduk.
* **G002:** Tehdit, Zafiyet ve Riski matematiksel matrisle ayırdık.
* **G003:** Etik, yasal izin ve test kapsamının (RoE) kırmızı çizgilerini çektik.
* **G004:** NIST CSF 2.0'ın altı işlevli orkestrasyonunu zihnimize nakşettik.
* **G005:** Varlıkları envantere alıp "Crown Jewels" değerini donanım faturasından kurtardık.
* **G006:** Tehdit modelleme ve STRIDE ile güven sınırlarını haritalandırdık.

İşte bugün, **GÜN 007 Mini Projesinde**, bu altı günün tüm birikimini tek bir teknik ve hukuki başyapıtta birleştiriyoruz: **Güvenli Laboratuvar Sözleşmesi (Secure Lab Contract & Topology Charter)**.

Sana sormak istiyorum: Ölümcül bir virüs (Ebola, Marburg) üzerinde çalışan biyoloji bilimcileri araştırmalarını evlerindeki mutfak masasında, pencere açıkken mi yaparlar?
Elbette hayır! BSL-4 (Biyogüvenlik Seviyesi 4) adı verilen; negatif hava basınçlı, çift kilitli hava odaları olan, astronot kıyafetleriyle girilen ve dışarıya tek bir mikrop sızdırmayan özel laboratuvarlarda çalışırlar.

Siber güvenlikte de durum birebir aynıdır!
Bir analist Kali Linux açtığında, Metasploit çalıştırdığında veya gerçek bir fidye yazılımı (Ransomware) numunesini incelediğinde elinde dijital bir veba virüsü tutmaktadır. Eğer senin sanal laboratuvarının ağ adaptörü **"Bridged" (Köprü)** modundaysa veya sanal makine ile ana makine arasında **Pano Paylaşımı (Clipboard)** açıksa; o pencere sonuna kadar açıktır demektir!
Tek bir yanlış komut, WannaCry gibi kendi kendine yayılan tek bir solucan (Worm); sanal makineden çıkar, evindeki Wi-Fi ağına veya çalıştığın şirketin üretim sunucularına sıçrar ve tüm sistemleri şifreler!

İşte bu yüzden ilk haftanın taçlandırma kuralı şudur:
> **Doğrulanabilir, yasal olarak onaylanmış ve teknik olarak hava aralıklı (Air-Gapped/Host-Only) bir laboratuvar sözleşmesi imzalanmadan hiçbir siber saldırı veya savunma deneyi başlatılamaz!**

Bugün inşa ettiğimiz sözleşme ve topoloji, bizim dijital BSL-4 laboratuvarımızın yıkılmaz kalesidir.

```
  +----------------------------------------------------------------------------+
  |              FİZİKSEL HOST MAKİNE (Windows 11 / Linux Ana Sistem)           |
  |                                                                            |
  |   [Hipervizör İzolasyon Duvarı]                                            |
  |   - Pano Paylaşımı (Clipboard): DEVRE DIŞI                                  |
  |   - Ortak Klasörler (Shared Folders): DEVRE DIŞI                            |
  |   - Sürükle & Bırak: DEVRE DIŞI                                            |
  |                                                                            |
  |   [Fiziksel Ağ Kartı: Wi-Fi / Ethernet]                                    |
  |   ====================== X KESİNLİKLE BAĞLANTI YOK X ===================== |
  |   (İnternete ve Ev/Şirket Ağına Sızıntı Sıfır Toleransla Engellenmiştir)   |
  +----------------------------------------------------------------------------+
                                        |
                   +--------------------+--------------------+
                   |                                         |
                   v                                         v
   +-------------------------------+         +---------------------------------+
   | [İÇ GÜVENLİK DUVARI: NODE-05] |         | [AYNA PORT / SPAN SENSÖR: 04]   |
   | pfSense Sanal Ağ Geçidi       |         | Zeek NIDS & Wazuh SIEM          |
   | IP: 192.168.100.1             |         | IP: 192.168.100.40              |
   | Rol: Yönlendirme ve Loglama   |         | Segment: BLUE_ZONE (İzleme)     |
   +---------------+---------------+         +----------------+----------------+
                   |                                          |
   ================+=========== SANAL ANAHTAR ================+=================
   (vSwitch / Host-Only İzole Sanal Ağ: 192.168.100.0/24 - Paket Dışarı Çıkamaz)
                   |                                          |
         +---------+---------+                      +---------+---------+
         |                   |                      |                   |
         v                   v                      v                   v
 +---------------+   +---------------+      +---------------+   +---------------+
 | [NODE-01]     |   | [NODE-02]     |      | [NODE-03]     |   | [SNAPSHOT]    |
 | SALDIRGAN     |   | HEDEF DOMAIN  |      | HEDEF LINUX   |   | Her test      |
 | Kali Linux    |   | Win Server AD |      | Ubuntu Web/DB |   | öncesi temiz  |
 | 192.168.100.10|   | 192.168.100.20|      | 192.168.100.30|   | duruma dönüş  |
 | RED_ZONE      |   | TARGET_ZONE   |      | TARGET_ZONE   |   | garantisi     |
 +---------------+   +---------------+      +---------------+   +---------------+
```

---

## 2. Sıfırdan Başlayan Kristal Netliğinde Teori

### 2.1. Güvenli Laboratuvar Sözleşmesinin 4 Temel Sütunu
Bir siber güvenlik laboratuvarı tesadüfen kurulmaz. Dört temel ilke üzerine bina edilir:

1. **Yasal Yetki ve Kapsam Sözleşmesi (Legal Charter):**
   Laboratuvarın sahibi kimdir? Hangi IP bloklarında test yapılabilir? Bu alanda CISO ve Baş Araştırmacı imzası olmak zorundadır. İzinli IP blokları içinde genel internet (`0.0.0.0/0`) veya şirket omurga ağı (`10.0.0.0/8`) kesinlikle yer alamaz.
2. **Hipervizör Sıkılaştırması ve VM Escape Koruması:**
   Zararlı yazılımlar sadece sanal makinenin içinde çalışmakla kalmaz; hipervizörün (VMware, VirtualBox, KVM) açıklarını kullanarak ana işletim sistemine (Host OS) sıçramaya çalışırlar (**VM Escape**).
   * Pano Paylaşımı (Clipboard): Saldırgan sanal makineden ana makinenin panosuna zararlı shellcode veya şifre kopyalayabilir. **KESİNLİKLE KAPALI OLMALIDIR.**
   * Ortak Klasörler (Shared Folders): Sanal makineden ana makine diskine yazma hakkı tanır. Fidye yazılımı doğrudan ana diski şifreleyebilir. **KESİNLİKLE KAPALI OLMALIDIR.**
   * Sürükle & Bırak (Drag & Drop): Dosya ayrıştırma zafiyetlerine yol açar. **DEVRE DIŞI BIRAKILMALIDIR.**
3. **Ağ Segmentasyonu ve Adaptör Türleri:**
   * **Bridged (Köprü):** Sanal makine fiziksel ağdaki bir cihaz gibi IP alır. Evdeki akıllı TV veya şirketteki muhasebe sunucusuyla aynı ağa düşer. Laboratuvar için **ÖLÜMCÜL BİR HATADIR.**
   * **NAT:** İnternete çıkabilir ancak dışarıdan içeri girilemez. Zararlı yazılım analizi için tehlikelidir; zararlı C2 (Komuta Kontrol) sunucusuyla konuşabilir.
   * **Host-Only / Internal Network:** Yalnızca sanal makinelerin kendi arasında ve istenirse sadece host ile haberleştiği, dış dünyaya tamamen kapalı, hava aralıklı en güvenli laboratuvar modudur.
4. **Operasyonel Dayanıklılık ve Anlık Görüntü (Snapshot):**
   Bir saldırı simülasyonu çalıştırıldığında hedef sunucu çöker veya kilitlenir. Her deney öncesinde temiz bir anlık görüntü (Clean Snapshot) alınmalı ve test bitince sistem tek tuşla bu temiz duruma döndürülmelidir.

---

## 3. İki Yönlü Bakış: Saldırganın Gözü (Offensive) vs Savunmacının Kalkanı (Defensive)

### Saldırganın Gözü (Offensive Angle)
Bir sızma testi uzmanı (Red Team) veya zararlı yazılım geliştirici laboratuvarda çalışırken gerçek dünyayı taklit etmek ister:
1. **Kurumsal Ağ Simülasyonu:** Saldırgan tek bir makineye bakmaz. Active Directory (`NODE-02`), Linux Web Uygulaması (`NODE-03`) ve bunları ayıran bir Güvenlik Duvarı (`NODE-05`) görmek ister. Böylece yanal hareket (Lateral Movement), Kerberoasting ve Privilege Escalation tekniklerini gerçekçi bir ortamda dener.
2. **Kaçış ve Yayılma İştahı:** Gelişmiş zararlı yazılımlar (APTs), çalıştıkları ortamın sanal makine olduğunu anladıklarında (Evasion) çevre IP'leri (`192.168.1.0/24`) tarayarak ev/ofis ağına kaçmaya çalışırlar. İzole edilmemiş bir laboratuvar, saldırgan için kontrolden çıkan bir biyolojik sızıntıdır.

### Savunmacının Kalkanı (Defensive Angle)
Mavi Takım (Blue Team) bu laboratuvarda savunma sensörlerini biler:
1. **Tam Ağ Telemetrisi ve SPAN Port:** Sanal anahtar üzerinden geçen her paket, `NODE-04` (Zeek NIDS ve Wazuh SIEM) makinesine ayna port (Promiscuous Mode) ile kopyalanır. Saldırganın attığı her Nmap paketi, her SQL enjeksiyonu ve her brute-force denemesi gerçek zamanlı olarak loglanır.
2. **Panik Butonu (Kill Switch):** Eğer saldırı simülasyonu beklenmedik bir davranış gösterirse, araştırmacı tek bir komutla sanal anahtar arayüzünü kapatır (vSwitch Down) ve elektriksel olarak tüm trafiği 5 saniye içinde sıfırlar.

---

## 4. Hocayla Birlikte Canlı Laboratuvar (Gerçek Kod & Canlı Sistem)

Geliştirdiğimiz `lab_contract_validator.py` motoru; sözleşmeyi, onayları, hipervizör güvenlik ayarlarını ve ağ topolojisini matematiksel olarak denetler. İzinli listeye genel internet (`0.0.0.0/0`) eklendiğinde veya pano paylaşımı açık bırakıldığında süreci derhal durdurur.

### Canlı Betiğimizin Kod Mimarisi ve Kritik Doğrulama Bloğu
Aşağıda, genel internet sızıntısını ve hipervizör kaçış zafiyetlerini denetleyen kritik Python kod blokları yer almaktadır:

```python
# uygulama/lab_contract_validator.py dosyasından kritik bölüm:
# 1. Kapsam ve Genel İnternet İhlali Kontrolü:
for blok_str in izinli_bloklar:
    ag = ipaddress.ip_network(blok_str, strict=False)
    # İzinli blok genel interneti (0.0.0.0/0) kapsıyorsa bu çok tehlikeli bir yasal ihlaldir!
    if ag.prefixlen == 0 or ag.is_global:
        hatalar.append(f"YASAL İHLAL: İzinli kapsama genel internet bloğu ({blok_str}) eklenemez!")

# 2. Hipervizör Kaçış (VM Escape) Ayarlarının Denetimi:
hyp = self.veri.get("hypervisor_guvenlik_ayarlari", {})
if str(hyp.get("pano_paylasimi_clipboard")).upper() != "DEVRE_DISI":
    bulgular.append({
        "seviye": "KRİTİK İZOLASYON KUSURU",
        "alan": "Pano Paylaşımı (Clipboard)",
        "mesaj": "Pano paylaşımı açık! Zararlı yazılım ana işletim sistemine sıçrayabilir."
    })
```

### Canlı Terminal Yürütmesi
Aracımızı `laboratuvar_sozlesmesi.json` üzerinde çalıştırdığımızda elde ettiğimiz canlı topoloji ve denetim raporu:

```text
========================================================================================================
  GÜVENLİ LABORATUVAR KURULUM VE İZOLASYON TOPOLOJİSİ: Anadolu Siber Güvenlik Araştırma Laboratuvarı (ASGAL) Kurulum Sözleşmesi
  Sözleşme Durumu: ONAYLANDI | Gün: G007 | Toplam Düğüm: 5
========================================================================================================

  [DIŞ DÜNYA / İNTERNET]  <--- X (KESİNLİKLE YASAK / AIR-GAPPED İZOLASYON) X --->
                                   |
          +------------------------v------------------------+
          | [NODE-05] pfSense Sanal Güvenlik Duvarı & Ağ Geçidi |
          | IP: 192.168.100.1 (Yalnızca İç VLAN Yönlendirme)|
          +------------------------+------------------------+
                                   |
        ================= SANAL ANAHTAR (vSwitch: Host-Only) =================
               |                           |                          |
  +------------v-----------+  +------------v-----------+  +-----------v------------+
  | [NODE-01] SALDIRGAN    |  | [NODE-02] HEDEF DOMAIN |  | [NODE-04] MAVİ TAKIM   |
  | Kali Linux Rolling     |  | Windows Server 2022 AD |  | Zeek NIDS & Wazuh SIEM |
  | IP: 192.168.100.10     |  | IP: 192.168.100.20     |  | IP: 192.168.100.40     |
  | Segment: RED_ZONE      |  | Segment: TARGET_ZONE   |  | Segment: BLUE_ZONE     |
  +------------------------+  +------------------------+  +------------------------+
                                           |
                              +------------v-----------+
                              | [NODE-03] HEDEF LINUX  |
                              | Ubuntu 22.04 Web & DB  |
                              | IP: 192.168.100.30     |
                              | Segment: TARGET_ZONE   |
                              +------------------------+

--------------------------------------------------------------------------------------------------------
  HİPERVİZÖR SIKILAŞTIRMA VE İZOLASYON DENETİMİ:
  * Pano Paylaşımı (Clipboard)     : DEVRE_DISI (VM Escape Engellendi)
  * Ortak Klasörler (Shared Folders): DEVRE_DISI (Disk İzolasyonu Sağlandı)
  * Sürükle & Bırak (Drag & Drop)  : DEVRE_DISI (Bellek İzolasyonu Sağlandı)
--------------------------------------------------------------------------------------------------------
  [+] SÖZLEŞME VE İZOLASYON DOĞRULANDI: Sıfır sızıntı riski, tüm düğümler güvenli Host-Only modunda.
      Etik kurallar ve onaylı CISO imzaları eksiksizdir.
========================================================================================================
```

---

## 5. Hocanın "Ölümcül Hatalar" Notu

Evlat, kendi laboratuvarını kurarken şu 5 felaket hatasına asla izin verme:

1. **Sanal Makineyi "Bridged" (Köprü) Adaptörle Çalıştırmak:**
   Laboratuvardaki en büyük amatörlük hatasıdır. Sanal makine evinin router'ından IP alır; çalıştırdığın bir tarama veya zararlı yazılım evindeki tüm telefonlara, televizyonlara ve ana bilgisayarına ulaşır.
2. **Misafir Eklentileri (Guest Additions) Pano Paylaşımını Açık Bırakmak:**
   "Kolaylık olsun, sanal makineye şifre kopyalayayım" diyerek açılan pano paylaşımı, zararlı yazılımların hipervizör belleğini istismar ederek ana bilgisayara sıçramasının 1 numaralı yoludur.
3. **Test Öncesi Snapshot (Anlık Görüntü) Almamak:**
   Fidye yazılımı çalıştırdığında sanal diski şifreler, işletim sistemi bir daha açılmaz. Sıfırdan makine kurmak zorunda kalmamak için her test öncesi temiz snapshot zorunludur.
4. **Sözleşmesiz ve Kapsamsız Test Başlatmak:**
   Hedef IP'leri yazılı olarak tanımlamadan konsola `nmap -sS 192.168.1.0/24` yazarsan, komşunun veya şirket muhasebesinin sunucusunu tararsın. Bu durum seni adli soruşturma ve TCK 243/244 maddeleriyle karşı karşıya getirir.
5. **İzleme Sensörü (SIEM / NIDS) Olmayan Kör Laboratuvar Kurmak:**
   Saldırıyı yapıp ekranda ne olduğunu görememek kör dövüşüdür. Bir laboratuvarın amacı sadece hacklemek değil; arkada nasıl bir log, paket ve alarm bıraktığını incelemektir.

---

## 6. Laboratuvar Görevi ve Beklenen Çıktılar

### Görev Tanımı
README, kapsam, riskler ve laboratuvar topolojisini içeren `laboratuvar_sozlesmesi.json` dosyasını oluştur; `lab_contract_validator.py` motoruyla çalıştırarak yasal onayları, hipervizör ayarlarını ve ağ topolojisini doğrula; negatif kontrol senaryolarını test et.

### Girdi Verisi (`ornek_veri/laboratuvar_sozlesmesi.json`)
* **Proje:** ASGAL Güvenli Laboratuvar Kurulum Sözleşmesi (G007).
* **Kapsam:** İzinli IP: `192.168.100.0/24`, `10.0.50.0/24`. Yasaklı: `0.0.0.0/0`, `8.8.8.8`, `192.168.1.1`.
* **Topoloji:** 5 Düğüm (Kali Linux, Windows Server AD, Ubuntu Web/DB, Zeek/Wazuh Sensörü, pfSense Firewall).
* **Hipervizör:** Pano: DEVRE_DISI, Ortak Klasör: DEVRE_DISI, Sürükle-Bırak: DEVRE_DISI.
* **Riskler:** Ağ sızıntısı, VM Escape, operasyonel çökme kontrolleri.

### Pozitif ve Negatif Kontroller
1. **Pozitif Kontrol:** Onaylı sözleşme, 5 düğüm ve tam izolasyon ayarlarıyla hatasız doğrulanır; 0 kusur üretilir.
2. **Negatif Kontrol 1 (Genel İnternet Kapsamı):** İzinli listeye `0.0.0.0/0` eklendiğinde `ContractViolationError` fırlatılır.
3. **Negatif Kontrol 2 (Pano Paylaşımı Açık):** Pano paylaşımı etkinleştirildiğinde `KRİTİK İZOLASYON KUSURU` raporlanır.
4. **Negatif Kontrol 3 (Köprü/Bridged Adaptör):** Düğüme köprü adaptör verildiğinde `GÜVENLİKSİZ AĞ ADAPTÖRÜ` uyarısı verilir.
5. **Negatif Kontrol 4 (IP Çakışması):** İki düğüme aynı IP verildiğinde sistem işlemi durdurur.

---

## 7. Hocanın Soru Odası (Kapsamlı Soru-Cevap)

Müfredatımızın `SORU BANKASI` gereksinimlerine göre 4 katı alt başlık kuralıyla cevaplanmıştır:

### Soru 1: Mini proje 1: güvenli laboratuvar sözleşmesi: Temel mekanizmayı ve güvenlik önemini açıkla.

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

### Soru 2: Mini proje 1: güvenli laboratuvar sözleşmesi: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

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

### Soru 3: 'Mini proje 1: güvenli laboratuvar sözleşmesi' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

#### 1. Yanıt
Risk; laboratuvar sanal makinelerinin yanlışlıkla üretim ağına köprülenmesi (Bridged), zararlı yazılımın hipervizör zafiyetleriyle ana makineye sıçraması (VM Escape) veya testlerin izin verilmeyen harici sistemlere taşmasıyla oluşur. Risk, ağ trafiğinin analizi (sızıntı tespit sensörleri), sözleşme denetim betikleri ve hipervizör konfigürasyon taramalarıyla tespit edilir. Önleme ise katı Host-Only ağ kısıtlaması, pano/klasör paylaşımının kapatılması, acil durum panik butonu (vSwitch Down) ve çift taraflı imzalı kurulum sözleşmesiyle sağlanır.

#### 2. Teknik Gerekçe
Sanal makineler mantıksal olarak izole görünse de donanımsal olarak aynı işlemci, bellek ve ağ kartını paylaşırlar. Gelişmiş tehdit aktörleri sanal makine sürücülerindeki (vboxguest, vmx) bellek taşmalarını istismar ederek ana sisteme çıkabilir. Bu risk, donanım sanallaştırma izolasyonu (VT-x/AMD-V sıkılaştırması), misafir eklentilerinin tehlikeli özelliklerinin kapatılması ve sanal ağın fiziksel ağ kartından tamamen ayrılmasıyla (Air-Gap) sıfıra indirilir.

#### 3. Yaygın Hata
Zararlı yazılım analizini günlük kullanılan kişisel bilgisayarda izolesiz çalıştırmak; laboratuvardaki bir testin evdeki veya ofisteki diğer cihazları etkilemeyeceğini varsaymak.

#### 4. Standart ve Kaynak
* SANS Institute: "Building a Malware Analysis Laboratory".
* CIS Controls v8: Control 13 (Network Monitoring and Defense).
