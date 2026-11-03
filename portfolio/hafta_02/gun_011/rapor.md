# GÜN 011: Değerlendirme ve Denetim Raporu
**Konu:** Laboratuvar Ağ Sınırları (Mikro-Segmentasyon, VLAN İzolasyonu, Statefull Conntrack ve DNS Sinkhole)  
**Tarih:** 2026-10-27  
**Değerlendirme Puanı:** 100 / 100  
**Durum:** YETERLİ (PASS)

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)  
> Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.  
> Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

---

## 📊 1. Puanlama Tablosu

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Durum | Açıklama |
| :--- | :---: | :---: | :---: | :--- |
| **Teorik Derinlik ve Kavramsal Model** | 20 | **20** | Eksiksiz | Denizaltı su geçirmez bölmeleri (Bulkheads) analojisiyle 4 bölgeli mikro-segmentasyon, durum takipli conntrack, asimetrik yönlendirme ve DNS sinkhole mimarisi derinlemesine açıklandı. |
| **Uygulama ve Kod Kalitesi** | 40 | **40** | Eksiksiz | Her satırı zengin pedagojik açıklamalarla yazılmış `lab_network_boundary_auditor.py` CLI motoru geliştirildi; ağ sızıntısı analizi ve kurumsal `iptables_rules.sh` üretimi eksiksiz kodlandı. |
| **Birim Testler ve Negatif Kontroller** | 25 | **25** | Eksiksiz | 14 birim test ile pozitif altın topoloji, karantina internet sızıntısı, düz ağ, çakışan CIDR, DNS sızıntısı, tersine kabuk ve durum takipsizlik açıkları 0.189s'de %100 doğrulandı. |
| **Dokümantasyon, Soru-Cevap ve Kanıtlar** | 15 | **15** | Eksiksiz | 7 bölümlü masterclass ders metni, 4 katı alt başlıklı 3 soru-cevap, gerçek CLI yürütme çıktısı ve temsilî ASCII topoloji şeması eksiksiz üretildi. |
| **TOPLAM** | **100** | **100** | **YETERLİ (PASS)** | Müfredat ve kalite standartlarının tüm şartları tam olarak karşılandı. |

---

## 🔍 2. Pozitif ve Negatif Kontrol Doğrulama Matrisi

| Kontrol Türü | Test Fonksiyonu | Beklenen Davranış | Gözlenen Sonuç | Durum |
| :--- | :--- | :--- | :--- | :---: |
| **Pozitif Kontrol** | `test_01_altin_topoloji_pozitif_kontrol` | 4 bölgeli tam izole topolojide 100/100 skor ve 0 bulgu üretilmeli. | Skor: 100, Bulgu: 0, Durum: GÜVENLİ | **GEÇTİ** |
| **Negatif Kontrol (İnternet)** | `test_02_karantina_internet_cikis_felaket_kontrol` | Karantina bölgesinde internet açıkken FELAKET uyarısıyla 50 puan kesilmeli. | Skor: 50, 1 adet FELAKET bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Düz Ağ)** | `test_03_duz_ag_segmentasyon_negatif_kontrol` | Bölge sayısı 3'ten azken düz ağ riskiyle 25 ceza puanı kesilmeli. | Skor: 75, YÜKSEK risk bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (CIDR)** | `test_04_cakisan_cidr_negatif_kontrol` | İki bölgeye aynı CIDR atandığında yönlendirme çöküşü uyarısı verilmeli. | Skor: 70, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (DNS Sızıntı)**| `test_05_harici_dns_engellenmemis_negatif_kontrol` | Harici DNS sorguları izinliyken DNS tünelleme uyarısı verilmeli. | Skor: 80, YÜKSEK risk bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Sinkhole)** | `test_06_dns_sinkhole_eksik_negatif_kontrol` | DNS sinkhole tanımlı değilken sahte yanıtlayıcı eksikliği uyarısı üretilmeli. | Skor: 85, ORTA risk bulgusu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Forward)** | `test_07_varsayilan_forward_accept_negatif_kontrol` | Varsayılan forward eylemi ACCEPT iken açık geçiş uyarısı verilmeli. | Skor: 65, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Conntrack)**| `test_08_statefull_conntrack_kapali_negatif_kontrol` | Durum takibi kapalıyken durumsuz yönlendirme riski yakalanmalı. | Skor: 70, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Yeni Bağlantı)**| `test_09_kurbandan_yeni_baglanti_engeli_yok_kontrol`| Kurbandan çıkan NEW paketler serbestken tersine kabuk uyarısı verilmeli. | Skor: 70, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Tersine Kabuk)**| `test_10_kurbandan_saldirgana_new_baglanti_tersine_kabuk_kontrol`| Kurbandan saldırgana NEW bağlantı kuralı tespit edilirse engellenmeli. | Skor: 70, KRİTİK bulgu üretildi. | **GEÇTİ** |
| **Negatif Kontrol (Geniş İzin)** | `test_11_karantinadan_internete_genis_izin_felaket_kontrol`| Karantinadan INTERNET'e ACCEPT kuralı varsa FELAKET uyarısı verilmeli. | Skor: 50, FELAKET bulgusu üretildi. | **GEÇTİ** |
| **İşlevsellik (iptables Üretimi)**| `test_12_iptables_betik_uretimi_dogrulamasi`| Üretilen betikte -P FORWARD DROP ve DNAT sinkhole kuralları doğrulanmalı. | Betik üretildi ve kurallar teyit edildi. | **GEÇTİ** |
| **Hata Yönetimi (Şema)** | `test_13_gecersiz_sema_ve_alan_eksikligi` | Zorunlu alan eksikliğinde NetworkBoundaryValidationError fırlatılmalı. | Hata yakalandı ve doğrulandı. | **GEÇTİ** |
| **Hata Yönetimi (Dosya)** | `test_14_olmayan_dosya_hatasi` | Bulunmayan dosya yolunda FileNotFoundError fırlatılmalı. | Hata yakalandı ve doğrulandı. | **GEÇTİ** |

---

## 🛠️ 3. Tamamlanan Çıktılar ve Kanıt Dosyaları

1. `ornek_veri/laboratuvar_ag_topolojisi.json`: Mikro-segmente (`TOPOLOGY-SEC-01`) ve güvensiz düz ağ (`TOPOLOGY-RISK-99`) veri tabanı.
2. `ornek_veri/iptables_rules.sh`: Otomatik üretilen kurumsal laboratuvar ağ sınırları ve güvenlik duvarı kural betiği.
3. `uygulama/lab_network_boundary_auditor.py`: Her satırı pedagojik açıklamalarla yazılmış ağ sınırları denetim ve iptables üretim motoru.
4. `tests/test_lab_network_boundary_auditor.py`: 14 birim test senaryosunu içeren ve 0.189 saniyede sonuçlanan tam test paketi.
5. `kanit/gercek/komut_ve_cikis.txt`: Gerçek CLI yürütme çıktısı ve platform ortam kaydı.
6. `kanit/gercek/test_sonuclari.txt`: 14/14 unittest başarı çıktısı.
7. `kanit/temsili/laboratuvar_ag_topolojisi.txt`: 4 VLAN bölgesi, durum takipli conntrack ve DNS sinkhole akışını gösteren pedagojik ASCII şeması.
8. `ders.md`: 7 aşamalı "Usta-Çırak" masterclass ders metni.
9. `soru_cevap.md`: Soru bankasındaki 3 soruya (`G011-SC1`, `G011-SC2`, `G011-SC3`) ait 4 katı alt başlıklı kurumsal yanıtlar.

---

## 🏁 4. Sonuç ve Bir Sonraki Güne Geçiş

GÜN 011 çalışması; siber güvenlik laboratuvarlarında kurban, saldırgan ve izleme düğümlerinin mikro-segmentasyonla nasıl izole edileceğini, durum takipli (conntrack) güvenlik duvarı asimetrisini ve DNS sinkholing ile sızıntı önleme kalkanını başarıyla tamamlamıştır.

Tüm testler ve denetimler **%100 PASS** ile sonuçlanmış olup, Aşama 01 Hafta 02 kapsamındaki **GÜN 012 ("Temel Linux komutları ve dosya sistemi hiyerarşisi")** konusuna geçiş için tüm ön koşullar eksiksiz sağlanmıştır.
