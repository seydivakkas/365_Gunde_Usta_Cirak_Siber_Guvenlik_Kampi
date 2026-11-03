# Gün 051: Teknik Değerlendirme ve Uygulama Raporu

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Çalışma Özeti ve Görev Kapsamı

Bu çalışma, Aşama 03 (Ağ Temelleri ve Ağ Güvenliği) 8. Hafta 51. Gün müfredatında yer alan **"TCP Sıralama ve Yeniden İletim"** konusunu kapsar. Gerçekleştirilen çalışmalar:
- **Bayt Akışı ve Sıra Numarası Modellemesi:** TCP veri segmentlerinde `next_seq = seq_no + payload_len` matematiksel ilerleyişi ve kümülatif onay (Cumulative ACK) mekanizması sıfırdan geliştirilmiştir.
- **Kayar Pencere (Sliding Window) ve Akış Kontrolü:** Gönderici ve alıcı arasındaki tampon sınırları, pencere boyutu (Window Size) takibi ve alıcı tamponunun dolması durumunda ortaya çıkan Sıfır Pencere (`Window = 0`) mekanizması modellenmiştir.
- **Paket Kaybı ve Yeniden İletim Mekanizmaları:**
  - Sıra dışı gelen paketlerin (Out-of-Order Segments) ve aradaki veri boşluklarının (Gaps) tespiti.
  - Alıcının son eksiksiz baytı tekrarlaması (Duplicate ACK).
  - Peş peşe 3 adet yinelenen onay ile devreye giren **Hızlı Yeniden İletim (Fast Retransmit)** tetiklenmesi ve kayıp parçanın tekrar iletilerek boşluğun kapatılması.
- **Güvenlik Tehditleri ve Anomali Analizi:**
  - "Yinelenen paketler tek başına saldırı değildir" ilkesinin doğrulanması; ağ gecikmesi kaynaklı sahte yeniden iletimler (Spurious Retransmissions) ile DoS saldırılarının ayrıştırılması.
  - Aktif kayar pencere içine sahte sıra numarasıyla enjekte edilen **Blind TCP Reset (RST) Injection** saldırısının tespiti.
  - İstemcinin sunucuyu kilitlemek amacıyla `Window=0` anons etmesiyle oluşan **Zero Window DoS** riskinin analizi.
- 14 birim testi ve 8 negatif kontrol senaryosu hazırlanmış; tümü başarıyla tamamlanmıştır.

---

## 2. Değerlendirme Rubriği ve Puanlama

| Kriter No | Değerlendirme Boyutu | Ağırlık / Tam Puan | Alınan Puan | Açıklama ve Gerekçe |
|---|---|---|---|---|
| **1** | Kavramsal Derinlik | 20 | **20** | TCP bayt akışı matematiği, kümülatif ACK işleyişi, kayar pencere sınırları, 3 Dup ACK ile Fast Retransmit tetiklenmesi ve "yinelenen paketler tek başına saldırı değildir" felsefesi usta-çırak pedagojisiyle derinlemesine aktarıldı. |
| **2** | Uygulama Geliştirme | 40 | **40** | `tcp_sequence_retransmit_analyzer.py` çift yönlü TCP akışını takip eden, sıra dışı paketleri, Duplicate ACK'leri, Fast Retransmit'i ve Blind RST enjeksiyonunu tespit eden motor olarak sıfırdan kodlandı; her bir satır didaktik açıklamalarla zenginleştirildi. |
| **3** | Test Kapsamı ve Doğrulama | 25 | **25** | `test_tcp_sequence_retransmit_analyzer.py` altında 14 birim testi hazırlandı; pytest ile 14/14 PASS elde edildi; 8 negatif kontrol senaryosu başarıyla engellendi ve kanıtlandı. |
| **4** | Savunma ve Sıkılaştırma | 15 | **15** | RFC 5961 Challenge ACK mekanizması, TCP MD5 / AO kimlik doğrulama seçenekleri, agresif sıfır pencere zaman aşımları ve akıllı IDS eşik kuralları detaylandırıldı. |
| **TOPLAM** | **Genel Performans** | **100** | **100** | **DURUM: YETERLİ / PASS** |

---

## 3. Test ve Doğrulama Kanıtları Özeti

- **Birim Testleri (`kanit/gercek/test_sonuclari.txt`):**
  - Toplam Test: 14
  - Başarılı: 14 (100%)
  - Hatalı / Kırılan: 0
  - Yürütme Süresi: 0.03 saniye
- **Uygulama Çalıştırma Kanıtı (`kanit/gercek/komut_ve_cikis.txt` & `kanit/gercek/tcp_siralama_ve_retransmit_raporu.txt`):**
  - 14 segmentlik TCP akışı incelendi; 3 adet sıra dışı paket, 1 adet Fast Retransmit olayı, 1 adet Sıfır Pencere kilitlenmesi ve 1 adet Blind RST oturum koparma saldırısı başarıyla tespit edildi ve alarmlandı.
- **Negatif Kontrol Kanıtı (`kanit/gercek/negatif_kontrol_sonuclari.txt`):**
  - 8 geçersiz girdi biçimi (negatif yük uzunluğu, 32-bit sıra taşması, 32-bit onay taşması, negatif pencere boyutu, 16-bit pencere taşması, geçersiz port 0, bozuk IP formatı, sayısal olmayan zaman damgası) `TCPSequenceError` istisnası ile başarıyla yakalandı ve engellendi.
- **Kavramsal Mimari Şeması (`kanit/temsili/tcp_sliding_window_ve_retransmission_mimarisi.txt`):**
  - Zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığı altında kayar pencere modeli, paket kaybı, 3 Dup ACK ile Fast Retransmit döngüsü ve RFC 5961 Blind RST savunma mimarisi görselleştirildi.

---

## 4. Güvenlik ve Savunma Çıkarımları

1. **Yeniden İletimler Ağın Doğal Bir Parçasıdır:** Yüksek gecikmeli veya kablosuz ağlarda yeniden iletimler kaçınılmazdır. Güvenlik analistleri her yeniden iletimi DoS olarak nitelememeli, anomalileri eşik değerleri (threshold) ile izlemelidir.
2. **RFC 5961 ile Blind RST Savunması Şarttır:** Güvenlik duvarları ve işletim sistemi TCP yığınları, pencere içi herhangi bir RST paketini doğrudan kabul etmemeli; tam Seq eşleşmesi aramalı veya sorgu doğrulaması (Challenge ACK) talep etmelidir.
3. **Sıfır Pencere (Zero Window) Sınırlamaları:** İstemcilerin sunucu kaynaklarını kilit altında tutmasını önlemek amacıyla `tcp_retries2` ve probe zaman aşımları agresif şekilde yapılandırılmalıdır.

---

## 5. Sonuç ve Onay

Gün 051 kapsamındaki tüm teorik, uygulamalı, test ve güvenlik gereksinimleri eksiksiz olarak tamamlanmış, tüm kanıtlar yerel olarak üretilmiş ve doğrulanmıştır.

- **Nihai Karar:** `PASS`
- **Genel Not:** 100 / 100
