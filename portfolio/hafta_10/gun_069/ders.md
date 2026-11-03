# Hafta 10 Gün 69: Mini Proje 9 - Wireshark Analiz Raporu (Usta-Çırak Dersi)

> **Usta Notu:**  
> *"Evlat, 10 haftadır ilmek ilmek işlediğimiz ağ analizi yolculuğunun zirvesine geldik: Mini Proje 9. Wireshark'ı açıp paketlere bakmak bir teknisyenin işidir; fakat o milyonlarca baytlık karmaşanın içinden kurumun güvenliğini tehdit eden kök sebebi çıkarıp, hem genel müdüre (C-Level) sunulacak bir yönetici özeti hem de kıdemli SOC analistine yol gösterecek bir adli inceleme raporu haline getirmek gerçek bir siber güvenlik mimarının sanatıdır! Bu projede protokol hiyerarşisinden TCP sağlık anomalilerine, SQL enjeksiyonundan DNS tünellemeye kadar öğrendiğin tüm cephaneliği tek bir raporda sentezleyeceksin!"*

---

## 1. Profesyonel Bir Wireshark Analiz Raporunun Anatomisi

Kurumsal bir siber olay müdahale (Incident Response) sürecinde üretilen ağ analiz raporu rastgele ekran görüntülerinden oluşamaz. Uluslararası standartlarda (SANS, NIST SP 800-86) bir rapor 7 temel sütun üzerine inşa edilir:

```
[1. Yönetici Özeti & Skor]  ---> C-Level için risk seviyesi ve maliyet
[2. Protokol Hiyerarşisi]   ---> Ağdaki trafik kompozisyonu (L2 - L7)
[3. En Aktif Konuşmalar]    ---> Top Talkers & Bant Genişliği Tüketimi
[4. TCP Sağlık Metrikleri]  ---> Zero Window, Retransmission, Bufferbloat
[5. Siber Tehdit Bulguları] ---> SQLi, DGA/DNS Exfil, Cleartext Passwords
[6. Adli Tehdit Göstergeleri] -> IoC Listesi (Zararlı IP, Alan Adı, Hash)
[7. İyileştirme Eylem Planı] --> SOC ve Sistem Ekipleri İçin Aksiyonlar
```

---

## 2. Derinlemesine Analiz Katmanları

### 2.1 Protokol Hiyerarşisi (Protocol Hierarchy Statistics)
Wireshark'ta `Statistics -> Protocol Hierarchy` menüsü, yakalanan tüm paketlerin OSI katmanlarına göre ağacını çıkarır.
- **Tehdit Avcılığı İpucu:** Normal bir kurumsal ağda trafiğin %80'den fazlası TLS/HTTPS (Port 443) olmalıdır. Eğer raporda şifrelenmemiş HTTP (Port 80) veya beklenmedik biçimde yüksek oranda DNS (Port 53), IRC, Telnet veya FTP görülüyorsa, bu durum içeride eski/güvensiz sistemlerin çalıştığının ya da bir C2 tünelinin açık olduğunun doğrudan kanıtıdır.

### 2.2 Konuşmalar ve En Çok Konuşanlar (Conversations / Top Talkers)
`Statistics -> Conversations` menüsü, 2 uç nokta arasındaki karşılıklı iletişimi paket ve bayt hacmine göre listeler.
- Tek bir IP adresinin ağdaki onlarca farklı IP'ye kısa aralıklarla küçük paketler göndermesi **Port Taraması (Reconnaissance)** göstergesidir.
- İki IP arasında anormal yüksek bayt transferi olması ise **Veri Sızdırma (Data Exfiltration)** veya yedekleme sunucusu tıkanıklığı işaretidir.

### 2.3 TCP Bağlantı Sağlığı (TCP Expert Info)
Wireshark'ın analiz motoru paketleri incelerken TCP durum anomalilerini bayraklar:
1. **TCP Zero Window:** Alıcı sunucunun işletim sistemi tampon belleğinin tamamen dolduğunu ve artık veri kabul edemeyeceğini (`Window Size = 0`) bildirir. Sunucuda aşırı CPU/RAM yükü veya DoS saldırısı belirtisidir.
2. **TCP Retransmission & Duplicate ACK:** Ağda paket kaybı yaşandığını ve iletimin tıkandığını belgeler.

### 2.4 Siber Tehdit Göstergeleri (IoC Çıkarımı)
- **Web Saldırıları:** URL'de `%27 OR 1=1` veya `sqlmap` imzası doğrudan uygulama güvenliği açığını gösterir.
- **DNS Tünelleme:** TXT kayıtlarında Base64 kodlu uzun alan adları (`dGhpcy...exfil.org`) veri kaçırma göstergesidir.
- **Açık Parola İfşası:** Ağda temiz metin (cleartext) iletilen `USER` ve `PASS` komutları PCI-DSS ve KVKK ihlalidir.

---

## 3. Yönetici Özeti ve Güvenlik Skoru Matematiği

Raporun en başında teknik terimlere boğulmamış bir risk seviyesi yer almalıdır. Güvenlik skoru 100 tam puan üzerinden hesaplanır:
$$\text{Güvenlik Skoru} = 100 - \sum (\text{Kritik} \times 25 + \text{Yüksek} \times 15 + \text{Orta} \times 5 + \text{Düşük} \times 2)$$

- **90 - 100 Puan:** DÜŞÜK RİSK (Ağ temiz ve sağlıklı)
- **70 - 89 Puan:** ORTA RİSK (İyileştirme gereken yapılandırma eksikleri)
- **40 - 69 Puan:** YÜKSEK RİSK (Aktif güvenlik açıkları ve şüpheli akışlar)
- **0 - 39 Puan:** KRİTİK TEHLİKE (Aktif veri sızıntısı, sömürü veya DoS saldırısı)

---

## 4. Ustanın Çırağa Öğüdü
Çırak! Yazdığın rapor bir savcının iddianamesi, bir doktorun teşhis raporu gibidir. Rapordaki her iddianın altına paket numarasını (`Paket #4`), zaman damgasını ve ham yük kanıtını koyacaksın. Kanıtı olmayan iddia dedikodudur; siber güvenlikte dedikoduya değil, kablodan geçen baytın matematiğine inanılır!
