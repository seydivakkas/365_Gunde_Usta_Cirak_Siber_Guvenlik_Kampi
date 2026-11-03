# GÜN 120: Tehdit Modellemede STRIDE Metodolojisi ve DFD Analizi

## 1. Usta-Çırak Açılış Konuşması

**Usta:** Evlat, yazılım geliştirirken veya bir güvenlik altyapısı kurarken güvenlik uzmanlarının en büyük yanılgısı nedir bilir misin? "Sistemi yazalım, ayağa kaldıralım, en son bir sızma testi (penetration test) yapar açıkları kapatırız" demektir. Bu, bir gökdeleni inşa edip bitirdikten sonra kolonların depreme dayanıklı olup olmadığını test etmeye benzer! Kolon çürükse, binayı yıkmadan düzeltemezsin.

İşte bu sebeple güvenlik, sistemin tasarım (architecture & design) aşamasında başlamak zorundadır. "Shift-Left Security" dediğimiz kavramın kalbinde **Tehdit Modelleme (Threat Modeling)** yatar. Ve tehdit modellemenin dünya standardı dili **STRIDE**'dır.

STRIDE, 1999 yılında Loren Kohnfelder ve Praerit Garg tarafından Microsoft bünyesinde geliştirilmiş, ardından Michael Howard ve David LeBlanc tarafından sistemleştirilmiş yapısal bir tehdit sınıflandırma metodolojisidir. Bugün bir mimari çizime baktığında bir hacker'ın veya tehdit aktörünün nereden saldırabileceğini tahmin etmekle kalmayacak, bunu matematiksel bir disiplinle ortaya koyacaksın.

**Çırak:** Hocam, peki bir sistemdeki bileşenleri nasıl modelleriz ve STRIDE bu bileşenlere nasıl uygulanır?

**Usta:** Harika bir soru evlat. Tehdit modellemenin ilk adımı **Veri Akış Diyagramı (Data Flow Diagram - DFD)** çıkarmaktır. Bir DFD temel olarak 4 temel yapı taşından ve bunların arasından geçen **Güven Sınırlarından (Trust Boundaries)** oluşur:
1. **Dış Varlıklar (External Entities):** Kullanıcılar, üçüncü parti API'ler, tarayıcılar (Sistemin doğrudan kontrolü dışındaki aktörler).
2. **Süreçler / İşlemler (Processes):** Web sunucuları, mikroservisler, arka plan worker'ları (Veriyi işleyen, dönüştüren kod blokları).
3. **Veri Depoları (Data Stores):** Veritabanları, Redis önbellekleri, dosya sistemleri, konfigürasyon dosyaları.
4. **Veri Akışları (Data Flows):** Ağ bağlantıları, RPC çağrıları, REST istekleri, mesaj kuyrukları.

Ve en can alıcı nokta: **Güven Sınırı (Trust Boundary)!** Veri akışı güven düzeyi farklı iki bölge arasından geçerken (örneğin internetten DMZ'ye veya DMZ'den iç kurumsal veri tabanına) tehdit potansiyeli tavan yapar.

---

## 2. STRIDE Tehdit Matrisi ve Güvenlik Karşılıkları

STRIDE bir akronimdir; her harfi hem bir tehdit sınıfını hem de ihlal edilen temel bilgi güvenliği prensibini temsil eder:

| Tehdit (Threat) | Tanım ve Anlamı | İhlal Edilen Güvenlik Özelliği | Standart Azaltma (Mitigation) Mekanizması | İlgili Zafiyet (CWE) |
|---|---|---|---|---|
| **S - Spoofing** (Kimlik Sahteciliği) | Bir kullanıcının, servisin veya sistem bileşeninin başka bir kimliğe bürünmesi. | **Kimlik Doğrulama (Authentication)** | Güçlü kimlik doğrulama, MFA, mTLS, JWT imzalama, asimetrik anahtar doğrulaması. | CWE-290, CWE-287 |
| **T - Tampering** (Veri Tahrifatı) | Bellekteki, diskteki veya iletim halindeki verinin yetkisiz biçimde değiştirilmesi. | **Bütünlük (Integrity)** | Kriptografik özetler (HMAC, SHA-256), dijital imzalar, TLS şifrelemesi, veri tabanı yazma kısıtları. | CWE-353, CWE-345 |
| **R - Repudiation** (İnkar Edilebilirlik) | Bir kullanıcının gerçekleştirdiği kritik eylemi reddetmesi ve bunu ispatlayacak delil bulunmaması. | **İnkar Edilemezlik (Non-Repudiation)** | Değiştirilemez denetim izleri (WORM audit logs), kriptografik zaman damgaları, dijital imzalar. | CWE-778 |
| **I - Information Disclosure** (Bilgi İfşası) | Gizli veya hassas verinin yetkisiz kişilerin veya sistemlerin eline geçmesi. | **Gizlilik (Confidentiality)** | Uçtan uca şifreleme (TLS 1.3, AES-GCM), veri maskeleme, sıkı erişim kontrolleri. | CWE-200, CWE-319 |
| **D - Denial of Service** (Hizmet Engelleme) | Sistemin veya servisin meşru kullanıcıların erişimine kapatılması, çökertilmesi. | **Erişilebilirlik (Availability)** | Hız sınırlama (Rate limiting), kaynak kotaları, DDoS koruması (WAF/CDN), kuyruk yönetimi. | CWE-400 |
| **E - Elevation of Privilege** (Yetki Yükseltme) | Düşük yetkili bir kullanıcının veya sürecin admin/root yetkileri kazanması. | **Yetkilendirme (Authorization)** | En az yetki ilkesi (PoLP), RBAC/ABAC, sandbox, parametreli sorgular, katı yetki denetimi. | CWE-250, CWE-285 |

---

## 3. DFD Bileşenleri ve STRIDE Eşleme Kuralları

Bir DFD elemanına her STRIDE tehdidi uygulanabilir mi? Hayır! Tehdit modelleme literatüründe kabul görmüş katı bir kural vardır:

```
+-------------------+---+---+---+---+---+---+
| DFD Elemanı       | S | T | R | I | D | E |
+-------------------+---+---+---+---+---+---+
| External Entity   | X |   | X |   |   |   |  -> Sadece Spoofing ve Repudiation
| Process           | X | X | X | X | X | X |  -> Tüm 6 STRIDE tehdidi geçerlidir
| Data Store        |   | X | X | X | X |   |  -> Tampering, Repudiation, Info Disc, DoS
| Data Flow         |   | X |   | X | X |   |  -> Tampering, Info Disclosure, DoS
+-------------------+---+---+---+---+---+---+
```

- **Dış Varlık (External Entity):** Kodunu kontrol edemediğimiz dış aktördür. Kendi içinde kod çalıştırmadığımız için "Yetki Yükseltme" (E) veya "Tahrifat" (T) doğrudan dış varlığın içinde olmaz; o varlık sisteme bağlanırken kimliğini taklit edebilir (**S**) veya yaptığı çağrıyı inkar edebilir (**R**).
- **Süreç (Process):** Bellek alanı, CPU döngüleri ve yetki sınırları olan çalışan kod parçasıdır. Her 6 STRIDE tehdidine de maruz kalabilir!
- **Veri Deposu (Data Store):** Veriyi saklar. Veri değiştirilebilir (**T**), işlem inkar edilebilir (**R**), veri sızabilir (**I**), disk veya bağlantı havuzu doldurulup kilitlenebilir (**D**).
- **Veri Akışı (Data Flow):** Ağ hattı veya kanal. İletimdeki paket değiştirilebilir (**T**), dinlenebilir (**I**), hat tıkanabilir (**D**).

---

## 4. Tehditlerin Sayısallaştırılması: DREAD Skoru

Tehditleri tespit etmek yetmez evlat; hangi tehdidin önce çözüleceğini belirlemek için bir risk derecelendirmesi gerekir. Burada **DREAD** devreye girer:
- **D - Damage Potential:** Hasar potansiyeli (1-10)
- **R - Reproducibility:** Tekrarlanabilirlik / Saldırının yeniden üretilebilirliği (1-10)
- **E - Exploitability:** İstismar edilebilirlik kolaylığı (1-10)
- **A - Affected Users:** Etkilenen kullanıcı oranı (1-10)
- **D - Discoverability:** Zafiyetin keşfedilebilirlik kolaylığı (1-10)

$$\text{DREAD Skoru} = \frac{D + R + E + A + D}{5}$$

- **8.0 - 10.0:** KRİTİK (Critical) — Sistem üretime çıkamaz, derhal düzeltilmelidir!
- **6.0 - 7.9:** YÜKSEK (High) — Öncelikli sprint hedefi.
- **4.0 - 5.9:** ORTA (Medium) — Planlı iyileştirme.
- **1.0 - 3.9:** DÜŞÜK (Low) — İzleme ve kabul edilebilir risk.

---

## 5. Uygulama Mimarisi ve Kod Yapısı

Bugün yazdığımız `stride_threat_engine.py` modülü:
1. `ThreatModel` sınıfı ile DFD elemanlarını (`ExternalEntity`, `Process`, `DataStore`, `DataFlow`) yönetir.
2. DFD elemanları arasındaki güven sınırlarını (`TrustBoundaryCrossing`) tespit eder.
3. STRIDE matrisini otomatik işleterek sistemdeki tüm potansiyel tehditleri modeller.
4. Her tehdit için DREAD skorlaması yapar.
5. Tanımlanan güvenlik kontrolleriyle (mitigations) tehditleri eşleştirir, artık riski (residual risk) hesaplar.
6. Eğer sistemde henüz azaltılmamış KRİTİK veya YÜKSEK bir tehdit varsa `UnmitigatedCriticalThreatError` fırlatarak üretime geçişi engeller (CWE-1025).

Evlat, bu motoru iyi kavra. Yarın bir mikroservis mimarisi veya bulut altyapısı tasarlarken ilk işin bu motoru çalıştırıp mimarini denetlemek olacak!
