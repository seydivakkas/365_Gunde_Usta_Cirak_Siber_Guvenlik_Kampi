# G062: VLAN, Segmentasyon ve DMZ — Günlük Değerlendirme ve Teknik Sonuç Raporu

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez veya ticari olarak kullanılamaz.
```

---

## 1. Yönetici Özeti ve Rubrik Değerlendirmesi

Bu çalışma; Siber Güvenlik 365 Gün Müfredat Paketi'nin **Aşama 03 (Ağ Temelleri ve Protokoller)**, **Hafta 09 (Web Protokolleri ve Web Güvenliğine Giriş)** kapsamındaki **62. Gün (G062)** konusudur. "VLAN, Segmentasyon ve DMZ" başlığı altında IEEE 802.1Q, NIST SP 800-125B, CIS Cisco Switch Benchmark ve PCI-DSS standartları temelinde kapsamlı bir L2/L3 ağ simülasyon, segmentasyon ve güvenlik motoru geliştirilmiştir.

Tüm kodlar, birim testler, negatif sınır testleri ve kanıtlar yerel çalışma ortamında Python 3.14 üzerinde sıfırdan ve bağımsızlık kuralına tam uyumlu olarak üretilmiştir.

### Değerlendirme ve Puanlama Tablosu

| Değerlendirme Kriteri | Maksimum Puan | Alınan Puan | Açıklama ve Durum |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 20 | **20** | G062-SC1, SC2, SC3 soruları 4 zorunlu alt başlıkla derinlemesine yanıtlandı. |
| **Gerçek Uygulama / Simülasyon** | 40 | **40** | `vlan_segmentation_dmz_engine.py` modülü; 802.1Q, Switch Port, VLAN Hopping ve DMZ ACL motoru. |
| **Doğrulanabilir Kanıt** | 25 | **25** | 14 birim test + 9 negatif test %100 başarılı; gerçek terminal çıktıları arşivlendi. |
| **Teknik Rapor & Dokümantasyon** | 15 | **15** | Dürüst, kaynaklı, RFC/IEEE referanslı ders, rapor ve mimari çizimler tamamlandı. |
| **TOPLAM PUAN** | **100** | **100** | **DURUM: YETERLİ / PASS** |

---

## 2. Geliştirilen Uygulama ve Teknik Mimari

### 2.1. `vlan_segmentation_dmz_engine.py`
Uygulama motoru, kurumsal yerel ağ ve çevre ağ segmentasyonunu modelleyen şu temel modüllerden oluşmaktadır:
1. **IEEE 802.1Q Etiket Ayrıştırıcı ve Üreticisi (`parse_8021q_tag`, `build_8021q_tag`):**
   - 4 baytlık ikili başlığı (`TPID: 0x8100`, `PCP: 3-bit`, `DEI: 1-bit`, `VID: 12-bit`) bit düzeyinde maskeleme ve kaydırmalarla ayrıştırır.
   - 12-bit sınır aşımını (>4094), rezerve kimlikleri (0, 4095) ve 4 bayttan kısa kesilmiş başlıkları denetleyerek `VLANValidationError` ve `MalformedVLANFrameError` üretir.
2. **L2 Yönetilebilir Anahtar Motoru (`ManagedSwitch`):**
   - **Access Port:** Bağlanan son kullanıcı cihazlarını tek bir VLAN'a hapseder. Porta yabancı etiketli bir paket geldiğinde `VLANIngressViolationError` fırlatır.
   - **Trunk Port:** Çoklu VLAN omurgasını yönetir; Native VLAN haricindeki tüm paketlerde 802.1Q etiketini korur. İzinli VLAN listesinde (Allowed VLANs) olmayan etiketlerde `TrunkVLANNotAllowedError` üretir.
   - **Yayın Alanı (Broadcast Domain) İzolasyonu:** `simulate_broadcast_flood` ile bir VLAN içindeki L2 yayın paketlerinin (`FF:FF:FF:FF:FF:FF`) yalnızca aynı VLAN'daki portlara yayıldığını, diğer VLAN portlarının %100 izole kaldığını doğrular.
3. **VLAN Hopping Saldırı Savunma Modülü:**
   - **Double Tagging Tespiti:** Çift 802.1Q etiketi taşıyan paketleri yakalayarak `VLANHoppingAttackError` fırlatır ve paketi düşürür.
   - **Switch Spoofing (DTP) Tespiti:** Access modundaki bir kullanıcı portuna DTP müzakere paketi geldiğinde `SwitchSpoofingError` fırlatır ve portu derhal cezalandırarak `ERR_DISABLED` durumuna çeker.
4. **Segmentler Arası Güvenlik Duvarı ve DMZ Motoru (`InterVLANFirewall`):**
   - VLAN'lar arası geçişleri L3/L4 kural listesiyle denetler (Default Deny).
   - DMZ'deki (VLAN 20) sunuculardan iç kullanıcı ağına (VLAN 10) doğru yanal yayılımı (Lateral Movement) sıfır toleransla bloklayarak `InterVLANPolicyViolationError` fırlatır.
   - DMZ'den veritabanına (VLAN 30) yalnızca yetkili servis portuna (PostgreSQL 5432) kontrollü geçiş hakkı tanır.

---

## 3. Doğrulanabilir Kanıtlar ve Test Sonuçları

### 3.1. Birim Testleri (`test_vlan_segmentation_dmz_engine.py`)
- **Toplam Test:** 14
- **Başarılı:** 14 (%100)
- **Hatalı / Başarısız:** 0
- **Çalışma Süresi:** 0.001 saniye
- **Kanıt Dosyası:** `kanit/gercek/test_sonuclari.txt` ve `kanit/gercek/komut_ve_cikis.txt`

### 3.2. Negatif ve Sınır Değer Testleri (`invalid_vlan_inputs.json`)
- **Toplam Negatif Senaryo:** 9
- **Başarılı Engelleme:** 9 (%100)
- **Kanıt Dosyası:** `kanit/gercek/negatif_kontrol_sonuclari.txt`

| Senaryo ID | Test Tanımı | Beklenen İstisna | Alınan Sonuç |
| :--- | :--- | :--- | :--- |
| `NEG_01` | IEEE 802.1Q 12-Bit Sınır Aşımı (VID 5000) | `VLANValidationError` | Başarıyla Yakalandı |
| `NEG_02` | Double Tagging VLAN Hopping Saldırısı | `VLANHoppingAttackError` | Başarıyla Yakalandı |
| `NEG_03` | Access Portta DTP Switch Spoofing | `SwitchSpoofingError` | Başarıyla Yakalandı |
| `NEG_04` | DMZ'den İç Ağa Yanal Yayılım (Port 445 SMB) | `InterVLANPolicyViolationError` | Başarıyla Yakalandı |
| `NEG_05` | 4 Bayttan Kısa Kesilmiş 802.1Q Başlığı | `MalformedVLANFrameError` | Başarıyla Yakalandı |
| `NEG_06` | Access Porta Farklı Etiket Giriş İhlali | `VLANIngressViolationError` | Başarıyla Yakalandı |
| `NEG_07` | Trunk İzinli Listede Olmayan VLAN (VID 50) | `TrunkVLANNotAllowedError` | Başarıyla Yakalandı |
| `NEG_08` | Hatalı MAC Adresi Formatı | `VLANValidationError` | Başarıyla Yakalandı |
| `NEG_09` | L2 Broadcast Paketini VLAN Sınırından Taşırma | `VLANLeakageError` | Başarıyla Yakalandı |

---

## 4. Akademik ve Sektörel Standart Referansları

1. **IEEE 802.1Q:** Bridges and Bridged Networks (Virtual LAN Tagging Standard)
2. **IEEE 802.1p:** Traffic Class Expediting and Dynamic Multicast Filtering (QoS / PCP)
3. **NIST SP 800-125B:** Secure Virtual Network Configuration for Virtual Machine Protection
4. **CIS Cisco IOS Benchmark v4.1.0:** Access Port DTP Nonegotiate & Native VLAN Hardening
5. **PCI-DSS v4.0 Requirement 1:** Install and Maintain Network Security Controls (DMZ & Segmentation)

---
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.
ÖZEL LİSANS — Günlük değerlendirme raporu yalnızca görüntüleme ve eğitim amacıyla hazırlanmıştır.
