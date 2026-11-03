# Gün 050: Teknik Değerlendirme ve Uygulama Raporu

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.*

---

## 1. Çalışma Özeti ve Görev Kapsamı

Bu çalışma, Aşama 03 (Ağ Temelleri ve Ağ Güvenliği) 8. Hafta 50. Gün müfredatında yer alan **"TCP Üçlü El Sıkışma"** konusunu kapsar. Gerçekleştirilen çalışmalar:
- **RFC 793 ve RFC 9293 İkili Başlık Modellemesi:** 20 baytlık sabit TCP başlığı, portlar, 32-bit sıra numarası (Seq), 32-bit onay numarası (Ack), veri ofseti, pencere boyutu ve 8 kontrol bayrağı (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR) ikili düzeyde paketlenmiş ve ayrıştırılmıştır.
- **RFC 793 Sahte Başlık (Pseudo-Header) ve Sağlama Toplamı:** IPv4 kaynak/hedef IP, sıfır dolgusu, protokol (6) ve TCP uzunluğundan oluşan sahte başlık üzerinden RFC 1071 1's complement sağlama toplamı motoru geliştirilmiştir.
- **Üç Aşamalı El Sıkışma (Three-Way Handshake) Durum Makinesi:**
  - 1. Adım: İstemci `SYN` gönderimi (`Seq = ISN_c`, `Ack = 0`), durum geçişleri: `CLOSED -> SYN_SENT`, Sunucu: `LISTEN -> SYN_RECEIVED`.
  - 2. Adım: Sunucu `SYN-ACK` cevabı (`Seq = ISN_s`, `Ack = ISN_c + 1`), İstemci durumu: `ESTABLISHED`.
  - 3. Adım: İstemci `ACK` cevabı (`Seq = ISN_c + 1`, `Ack = ISN_s + 1`), Sunucu durumu: `ESTABLISHED`.
  - Handshake paketlerinde veri yükü (payload) taşınmaması kuralı ve yük taşıyan paketlerin anomali olarak etiketlenmesi.
- **Güvenlik Tehditleri ve Anomali Tespit Motoru:**
  - `SYN Flood (DDoS)` belirtisi (küçük pencere boyutlu ve yanıtsız SYN paketleri).
  - `Stealth SYN Port Taraması` (Nmap `-sS` benzeri tekil RST paketleri).
  - `XMAS Port Taraması` (`FIN+PSH+URG` bayrakları).
  - `NULL Port Taraması` (Hiçbir bayrağın set edilmemesi).
  - `Protokol İhlali` (`SYN + FIN` bayraklarının aynı anda bulunması).
- 14 birim testi ve 8 negatif kontrol senaryosu hazırlanmış; tümü başarıyla tamamlanmıştır.

---

## 2. Değerlendirme Rubriği ve Puanlama

| Kriter No | Değerlendirme Boyutu | Ağırlık / Tam Puan | Alınan Puan | Açıklama ve Gerekçe |
|---|---|---|---|---|
| **1** | Kavramsal Derinlik | 20 | **20** | RFC 793 anatomisi, durum makinesi geçişleri, ISN rastgeleliği ve Kevin Mitnick TCP Spoofing saldırısının arka planı, handshake paketlerinin veri taşımama kuralı usta-çırak pedagojisiyle derinlemesine aktarıldı. |
| **2** | Uygulama Geliştirme | 40 | **40** | `tcp_handshake_analyzer.py` ikili düzeyde TCP başlığı paketleyen, pseudo-header checksum hesaplayan, durum makinesini yürüten ve anomali analizi yapan motor olarak sıfırdan geliştirildi; her satır didaktik açıklamalarla zenginleştirildi. |
| **3** | Test Kapsamı ve Doğrulama | 25 | **25** | `test_tcp_handshake_analyzer.py` altında 14 birim testi hazırlandı; pytest ile 14/14 PASS elde edildi; 8 negatif kontrol senaryosu başarıyla engellendi ve kanıtlandı. |
| **4** | Savunma ve Sıkılaştırma | 15 | **15** | SYN Cookies (RFC 4987) matematiksel çalışma prensibi, Stateful Firewall durum takibi (`conntrack`), RFC 6528 kriptografik ISN üretimi ve kural dışı bayrak filtreleme yöntemleri belgelendi. |
| **TOPLAM** | **Genel Performans** | **100** | **100** | **DURUM: YETERLİ / PASS** |

---

## 3. Test ve Doğrulama Kanıtları Özeti

- **Birim Testleri (`kanit/gercek/test_sonuclari.txt`):**
  - Toplam Test: 14
  - Başarılı: 14 (100%)
  - Hatalı / Kırılan: 0
  - Yürütme Süresi: 0.03 saniye
- **Uygulama Çalıştırma Kanıtı (`kanit/gercek/komut_ve_cikis.txt` & `kanit/gercek/tcp_el_sikisma_raporu.txt`):**
  - 5 TCP oturumu incelendi; 1 meşru oturum başarıyla `ESTABLISHED` durumuna ulaştı; 5 adet güvenlik anomalisi (SYN Flood, Stealth RST, XMAS Scan, SYN+FIN kural ihlali) eksiksiz yakalandı ve alarmlandı.
- **Negatif Kontrol Kanıtı (`kanit/gercek/negatif_kontrol_sonuclari.txt`):**
  - 8 geçersiz girdi biçimi (Port 70000, Port 0, Ofset 4, 14 baytlık eksik başlık, negatif sıra numarası, geçersiz bayrak tipi, boş ikili veri, float port) `TCPValidationError` istisnası ile başarıyla yakalandı ve engellendi.
- **Kavramsal Mimari Şeması (`kanit/temsili/tcp_uc_asamali_el_sikisma_ve_syn_flood_mimarisi.txt`):**
  - Zorunlu `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` başlığı altında normal el sıkışma döngüsü, Seq/Ack ilerleyişi, SYN Flood backlog tükenmesi ve SYN Cookies savunma mekanizması görselleştirildi.

---

## 4. Güvenlik ve Savunma Çıkarımları

1. **El Sıkışma Paketlerinde Yük Taşınması Şüphelidir:** Standart bir TCP el sıkışmasında SYN ve SYN-ACK paketlerinin payload uzunluğu 0 olmalıdır. Yük içeren el sıkışma paketleri derin paket inceleme (DPI) ile denetlenmelidir.
2. **SYN Cookies Donanım Seviyesinde Açılmalıdır:** Sunucu ve güvenlik duvarı seviyesinde `net.ipv4.tcp_syncookies = 1` parametresi aktif edilerek, durum tablosu belleğinin tüketilmesi (SYN Flood) engellenmelidir.
3. **Kural Dışı Bayrak Kombinasyonları Doğrudan Düşürülmelidir:** Ağ sınırında `SYN+FIN`, `XMAS` (FIN+PSH+URG) ve `NULL` paketleri durum denetimli kurallarla tespit edilip doğrudan düşürülmeli (DROP) ve SIEM'e alarm gönderilmelidir.

---

## 5. Sonuç ve Onay

Gün 050 kapsamındaki tüm teorik, uygulamalı, test ve güvenlik gereksinimleri eksiksiz olarak tamamlanmış, tüm kanıtlar yerel olarak üretilmiş ve doğrulanmıştır.

- **Nihai Karar:** `PASS`
- **Genel Not:** 100 / 100
