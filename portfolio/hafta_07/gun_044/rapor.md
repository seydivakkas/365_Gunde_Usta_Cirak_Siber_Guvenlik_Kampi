# G044 — Ethernet, MAC ve Çerçeve Değerlendirme Raporu

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

---

## 1. Yönetici Özeti ve Görev Kapsamı
- **Gün No ve Kimliği:** Gün 044 / `G044` (Aşama 03, Hafta 07, Gün 44).
- **Konu Başlığı:** Ethernet, MAC ve çerçeve yapısı.
- **Tarih:** 2026-10-27.
- **Usta-Çırak Pedagojisi:** Didaktik anlatım, yerinde açıklamalı Python kodu, negatif ve pozitif test senaryoları, somut delil üretimi.
- **Genel Değerlendirme:** 100/100 (YETERLİ / PASS).

---

## 2. Puanlama Rubriği ve Detaylı Analiz

| Rubrik Kriteri | Ağırlık / Alınan | Durum | Gerekçe ve Doğrulama Kanıtı |
|---|---|---|---|
| **1. Kavramsal Derinlik ve Katman 2 Mimarisi** | 20 / 20 | PASS | MAC adresinin 48-bit yapısı, I/G ve U/L bitlerinin anlamı, Ethernet II çerçeve başlığı, FCS CRC32 ve asgari 64 bayt kuralı teorik ve mimari derinlikte incelendi. |
| **2. Uygulama ve Çerçeve Analiz Motoru Geliştirme** | 40 / 40 | PASS | `ethernet_frame_analyzer.py` motoru yazıldı. Her satır didaktik yorumlarla açıklandı; MAC bit analizi, OUI çözümlemesi, EtherType kontrolü, dolgu denetimi ve Markdown raporlayıcı uygulandı. |
| **3. Test Kapsamı ve Negatif Kontrol Doğrulaması** | 25 / 25 | PASS | `test_ethernet_frame_analyzer.py` altında 14 adet birim ve negatif test başarıyla koşturuldu (14/14 PASS, 0.003s). Kaynak MAC'in multicast olması kural ihlali, bozuk MAC, geçersiz EtherType ve cüce (runt) çerçeve durumları test edildi. |
| **4. Savunma, Tespit ve Port Güvenliği** | 15 / 15 | PASS | MAC Flooding, MAC Spoofing, Port Security (Sticky MAC), Dynamic ARP Inspection (DAI) ve 802.1X savunma stratejileri somut komutlarla belgelendi. |
| **TOPLAM PUAN** | **100 / 100** | **PASS** | **Müfredat ve operasyonel standartlara tam uyumlu.** |

---

## 3. Üretilen Dosyalar ve Kanıtlar

### Uygulama ve Test Dosyaları
1. `uygulama/ethernet_frame_analyzer.py`: Katman 2 çerçevelerini ayrıştıran, MAC bit seviyesini ve dolgulamayı doğrulayan didaktik motor.
2. `tests/test_ethernet_frame_analyzer.py`: 14 adet birim ve negatif kontrol testi içeren test süiti.
3. `ornek_veri/sample_ethernet_frames.json`: Unicast IPv4, Broadcast ARP ve 802.1Q VLAN etiketli referans çerçeve verisi.
4. `ornek_veri/corrupted_ethernet_frames.json`: Negatif kontrol test senaryoları.

### Gerçek ve Temsilî Kanıtlar
1. `kanit/gercek/test_sonuclari.txt`: 14 testin başarıyla geçtiğini gösteren Python `unittest` çıktısı (14/14 PASS, 0.003s).
2. `kanit/gercek/komut_ve_cikis.txt`: Komut satırı üzerinden analiz motorunun çalıştırılması ve terminal yürütme kaydı.
3. `kanit/gercek/ethernet_cerceve_analiz_raporu.txt`: Üretilen resmi Markdown analiz raporu (Çerçeve tablosu, bit analizleri, güvenlik notları).
4. `kanit/gercek/negatif_kontrol_sonuclari.txt`: 6 adet negatif sınır durumunun başarıyla yakalandığını kanıtlayan denetim günlüğü.
5. `kanit/temsili/ethernet_cerceve_mimarisi.txt`: `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` bayraklı Ethernet II ve 802.1Q çerçeve anatomisi şeması.

---

## 4. Çerçeve Ayrıştırma ve Analiz Özeti

| Çerçeve ID | Tür | Hedef MAC & İletim | Kaynak MAC & OUI | EtherType | Toplam Boyut | FCS (CRC32) |
|---|---|---|---|---|---|---|
| **ETH-001** | Ethernet II | `00:50:56:C0:00:08` (UNICAST) | `00:0C:29:12:34:56` (VMware) | `0x0800` (IPv4) | 78 Bayt | `0x4a12bc90` |
| **ETH-002** | Ethernet II | `FF:FF:FF:FF:FF:FF` (BROADCAST) | `00:0C:29:12:34:56` (VMware) | `0x0806` (ARP) | 64 Bayt (18B Dolgu) | `0x89ab12cd` |
| **ETH-003** | 802.1Q Tagged | `01:00:5E:00:00:FB` (MULTICAST) | `00:0C:29:12:34:56` (VMware) | `0x0800` (VLAN 20) | 86 Bayt | `0xfe32110a` |

---

## 5. Usta-Çırak Değerlendirmesi
Çırak, Katman 2 seviyesinde yerel ağın omurgasını oluşturan Ethernet çerçeve yapısını ve MAC adresi bit matematiğini mükemmel biçimde kavramıştır. Geliştirilen denetim motoru temiz, dayanıklı ve hatasızdır; negatif kontroller tam güvence sağlamıştır.

Bir sonraki adım olan **G045 ("IP adresleme ve alt ağlar (subnetting): CIDR ve ağ maskesi")** gününe geçilmesi uygundur.
