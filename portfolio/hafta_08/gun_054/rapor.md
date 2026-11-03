<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 54: DNS Sorguları ve Kayıt Türleri — Değerlendirme ve Teknik İnceleme Raporu

---

## 1. Yürütme ve Değerlendirme Özeti

| Parametre | Değer |
|---|---|
| **Eğitim Günü / ID** | Gün 54 / G054 |
| **Aşama / Hafta** | Aşama 03 (Ağ Temelleri ve Protokol Güvenliği) / Hafta 08 |
| **Konu Başlığı** | DNS sorguları ve kayıt türleri |
| **Tarih** | 2026-10-29 |
| **Nihai Değerlendirme Puanı** | **100 / 100** |
| **Nihai Karar** | **YETERLİ / PASS** |
| **Yürütme Modu** | OTOMATIK_ZINCIR (Tamamen Yerel ve Bağımsız Çalıştırma) |
| **Toplam Test Sayısı / Başarı** | 14 Test / 14 Başarılı (%100 PASS, 0.001 saniye) |
| **Kod Açıklama Satırları** | Tamamlandı (Uygulama ve test kodlarının her satırı didaktik yorumlarla yazıldı) |

---

## 2. Ajan Kalite Rubriği Puanlama Detayı

```
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| Rubrik Kriteri                     | Max Puan  | Alınan Puan  | Gerekçe ve Teknik Doğrulama                                |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| 1. Kavramsal Derinlik              | 20        | 20           | RFC 1034/1035 mimarisi, ikili başlık yapısı, 5 kayıt türü  |
|                                    |           |              | ve 'DNS Yanıtı Doğrulanmış Kimlik Değildir' incelendi.     |
| 2. Uygulama Geliştirme             | 40        | 40           | Etiket kodlama/çözme, 12 bayt başlık, RR modellemesi,      |
|                                    |           |              | SPF/DMARC denetimi, Subdomain Takeover ve tünelleme yazıldı|
| 3. Test Kapsamı ve Kanıtlar        | 25        | 25           | 14 birim testi PASS (%100); 8 negatif sınır kontrolü      |
|                                    |           |              | yapıldı; gerçek ve temsilî kanıtlar üretildi.             |
| 4. Savunma ve Sıkılaştırma         | 15        | 15           | DNSSEC, DoH/DoT şifrelemesi, katı SPF (-all) ve DMARC      |
|                                    |           |              | (p=reject) ile DNS RPZ savunma mimarisi detaylandırıldı.   |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
| TOPLAM PUAN                        | 100       | 100          | DURUM: YETERLİ / PASS                                      |
+------------------------------------+-----------+--------------+------------------------------------------------------------+
```

---

## 3. Gerçekleştirilen Teknik İncelemeler ve Bulgular

### A. RFC 1035 İkili Başlık ve Etiketleme
- **Başlık Paketleme:** 12 baytlık ikili DNS başlığı (`!HHHHHH`) başarıyla paketlenmiş, QR, Opcode, AA, TC, RD, RA ve RCODE bayrakları doğrulanmıştır.
- **Etiket Kodlama:** `encode_domain_name("example.com")` çağrısı `\x07example\x03com\x00` ikili dizisine dönüştürülmüş ve geri çözümlenerek 63 baytlık etiket ve 253 baytlık toplam uzunluk sınırları doğrulanmıştır.

### B. Kaynak Kayıtları (Resource Records) Modellemesi
- **A Kaydı (Tip 1):** IPv4 adres doğrulaması ile `93.184.216.34` modellenmiştir.
- **AAAA Kaydı (Tip 28):** IPv6 adres doğrulaması ile `2606:2800:220:1:248:1893:25c8:1946` modellenmiştir.
- **CNAME Kaydı (Tip 5):** `www.example.com` takma adı yönlendirmesi doğrulanmıştır.
- **MX Kaydı (Tip 15):** Öncelik (10) ve posta sunucusu (`mail.example.com`) başarıyla ayrıştırılmıştır.
- **TXT Kaydı (Tip 16):** SPF ve DMARC güvenlik metinleri modellenmiştir.

### C. Güvenlik Denetimleri ve Tehdit Analizleri
1. **SPF ve DMARC E-posta Güvenliği:**
   - Katı SPF (`v=spf1 ... -all`) ve katı DMARC (`v=DMARC1; p=reject;`) tam güvenlik onayı almıştır.
   - Zayıf SPF (`+all`) ve yalnızca izleme modundaki DMARC (`p=none`) denetçisi tarafından anında uyarılmıştır (`WEAK_SPF_POLICY`, `DMARC_MONITORING_ONLY`).
2. **Subdomain Takeover (Sahipsiz CNAME):**
   - `blog.example.com` adresinin silinmiş bir S3 deposuna (`abandoned-bucket.s3-website-us-east-1.amazonaws.com`) işaret etmesi `CRITICAL` seviyesinde `SUBDOMAIN_TAKEOVER_RISK` olarak yakalanmıştır.
3. **DNS Tünelleme ve Veri Sızıntısı:**
   - `48656c6c6f576f726c64457866696c74726174696f6e.c2.attacker.com` sorgusu Shannon entropisi (2.977 bit) ve 44 karakterlik olağandışı etiket boyutu ile `TUNNELING_DETECTED` olarak yakalanmış; meşru `api.example.com` sorgusu temiz çıkmıştır.

---

## 4. Negatif Kontroller ve Sınır Güvenliği Doğrulaması

`ornek_veri/invalid_dns_inputs.json` dosyasındaki 8 sınır aşımı ve biçim hatası test edilmiş ve `kanit/gercek/negatif_kontrol_sonuclari.txt` dosyasına kaydedilmiştir:
1. `NEG-DNS-01 (ERR_INVALID_QTYPE_STRING)`: Bilinmeyen tür `'UNKNOWN_TYPE_XYZ'` -> `DNSValidationError` ile engellendi.
2. `NEG-DNS-02 (ERR_LABEL_LENGTH_OVERFLOW)`: 63 karakterden uzun etiket (80+ karakter) -> `DNSValidationError` ile engellendi.
3. `NEG-DNS-03 (ERR_NEGATIVE_TTL)`: TTL `-60` -> `DNSValidationError` ile engellendi.
4. `NEG-DNS-04 (ERR_MALFORMED_A_RDATA)`: Hatalı IPv4 `'999.1.2.3'` -> `DNSValidationError` ile engellendi.
5. `NEG-DNS-05 (ERR_MALFORMED_AAAA_RDATA)`: Hatalı IPv6 `'gecersiz:ipv6:formati'` -> `DNSValidationError` ile engellendi.
6. `NEG-DNS-06 (ERR_EMPTY_DOMAIN_NAME)`: Boş alan adı `""` -> `DNSValidationError` ile engellendi.
7. `NEG-DNS-07 (ERR_TRANSACTION_ID_OVERFLOW)`: ID `70000` -> `DNSValidationError` ile engellendi.
8. `NEG-DNS-08 (ERR_DOMAIN_TOTAL_LENGTH_OVERFLOW)`: 253 karakterden uzun alan adı -> `DNSValidationError` ile engellendi.

**Negatif Başarı Oranı:** 8 / 8 (%100).

---

## 5. Mühendislik ve Savunma Tavsiyeleri

1. **DNSSEC Zorunluluğu:** Alan adındaki tüm kaynak kayıtları RRSIG ve DNSKEY ile imzalanmalı, istemciler imzasız veya geçersiz imzalı kayıtları reddetmelidir.
2. **DoH/DoT Uygulaması:** Kurumsal ağda ve uç noktalarda DNS trafiği TLS ile şifrelenmeli; açık UDP 53 trafiği yerel ağ dinlemelerine karşı kapatılmalıdır.
3. **Sahipsiz CNAME Denetimi:** Bulut kaynakları silindiğinde ilişkili CNAME kayıtları otomatik temizlenmeli; dangling CNAME tarayıcıları CI/CD sürecine dahil edilmelidir.
4. **E-posta Güvenlik Politikası:** DMARC politikası derhal `p=reject` seviyesine çıkarılmalı, SPF kaydı `-all` ile sınırlandırılmalıdır.
