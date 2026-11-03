# GÜN 012: Değerlendirme ve Denetim Raporu
**Konu:** Anlık Görüntü (Snapshot), Yedekleme ve Geri Dönüş Mimarisi (3-2-1-1-0 Standardı, WORM Değişmezlik ve SHA-256 Bütünlük Kalkanı)  
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
| **Teorik Derinlik ve Kavramsal Model** | 20 | **20** | Eksiksiz | "Laboratuvar masası fotoğrafı vs Nükleer sığınak kasası" analojisiyle Snapshot'ın bir yedek olmadığı, Copy-on-Write delta disk mimarisi, 3-2-1-1-0 kuralı, RPO/RTO hedefleri ve fidye yazılımlarının VSS imha teknikleri derinlemesine açıklandı. |
| **Uygulama ve Kod Kalitesi** | 40 | **40** | Eksiksiz | Her satırı zengin pedagojik açıklamalarla donatılmış `vm_snapshot_backup_manager.py` CLI motoru geliştirildi; snapshot alma, rollback, WORM değişmezlik kilitli tam yedekleme, kriptografik SHA-256 bütünlük doğrulaması ve 6 kritik risk kriteri eksiksiz kodlandı. |
| **Birim Testler ve Negatif Kontroller** | 25 | **25** | Eksiksiz | 14 birim test ile pozitif altın yedek akışı, snapshot rollback, snapshot-as-backup yanılgısı, 72 saat yaş aşımı, aşırı zincir derinliği, WORM kilidi yokluğu, VSS açık yüzeyi, hash bozulması durumunda `BackupIntegrityError` fırlatılması 0.018s'de %100 doğrulandı. |
| **Dokümantasyon, Soru-Cevap ve Kanıtlar** | 15 | **15** | Eksiksiz | 7 bölümlü masterclass ders metni, 4 katı alt başlıklı 3 soru-cevap, gerçek CLI yürütme çıktısı ve temsilî ASCII mimari şeması eksiksiz üretildi. |
| **TOPLAM** | **100** | **100** | **YETERLİ (PASS)** | Müfredat ve kalite standartlarının tüm şartları tam olarak karşılandı. |

---

## 🔍 2. Pozitif ve Negatif Kontrol Doğrulama Matrisi

| Kontrol Türü | Test Fonksiyonu | Beklenen Davranış | Gözlenen Sonuç | Durum |
| :--- | :--- | :--- | :--- | :---: |
| **Pozitif Kontrol (Altın Yedek)** | `test_01_altin_yedek_yapilandirmasi_pozitif_kontrol` | 3-2-1 uyumlu ve WORM kilitli VM-SEC-LNX-01 100/100 tam puan almalıdır. | Skor: 100, Bulgu: 0, Durum: GUVENLI | **GEÇTİ** |
| **Pozitif Kontrol (Snapshot)** | `test_02_snapshot_olusturma_ve_ana_disk_kilitleme_pozitif_kontrol` | Snapshot alındığında ana disk salt-okunur olmalı ve delta diski açılmalıdır. | Ana disk salt_okunur=True, yeni snap oluşturuldu. | **GEÇTİ** |
| **Pozitif Kontrol (Rollback)** | `test_03_snapshot_rollback_temiz_duruma_donus_pozitif_kontrol` | Rollback icrasında delta disk sıfırlanmalı ve altın duruma dönülmelidir. | Delta boyutu sıfırlandı, durum: BASARILI. | **GEÇTİ** |
| **Pozitif Kontrol (Tam Yedek)** | `test_04_tam_bagimsiz_yedek_olusturma_pozitif_kontrol` | Bağımsız tam yedekte SHA-256 özeti ve WORM kilidi üretilmelidir. | WORM kilidi aktif, 64-karakter SHA-256 üretildi. | **GEÇTİ** |
| **Pozitif Kontrol (Bütünlük)** | `test_05_yedek_kriptografik_butunluk_dogrulamasi_pozitif_kontrol` | Doğru hash sağlandığında geri yükleme bütünlüğü onaylanmalıdır. | Durum: GECERLI_VE_BASARILI, SHA-256 doğrulandı. | **GEÇTİ** |
| **Negatif Kontrol (Yedek Sanma)** | `test_06_snapshot_as_backup_yanilgisi_negatif_kontrol` | Yedeği olmayan ancak snapshot'ı olan VM'de KRİTİK RISK-01 bulgusu oluşmalıdır. | RISK-01-SNAP-AS-BACKUP tespit edildi (-30 puan). | **GEÇTİ** |
| **Negatif Kontrol (72 Saat Yaş)** | `test_07_snapshot_yas_siniri_asimi_negatif_kontrol` | 72 saati aşmış açık snapshot tespitinde YÜKSEK RISK-02 cezası kesilmelidir. | RISK-02-SNAPSHOT-AGE-EXCEEDED tespit edildi (-20 puan). | **GEÇTİ** |
| **Negatif Kontrol (Zincir Derinliği)**| `test_08_derin_snapshot_zinciri_negatif_kontrol` | 3'ten fazla snapshot olan makinede RISK-03 I/O gecikme uyarısı verilmelidir. | RISK-03-DEEP-SNAPSHOT-CHAIN tespit edildi (-15 puan). | **GEÇTİ** |
| **Negatif Kontrol (WORM Kilidi)** | `test_09_degismezlik_kilidi_yoklugu_negatif_kontrol` | WORM değişmezlik kilidi bulunmayan sistemde fidye yazılımı riski yakalanmalıdır. | RISK-04-IMMUTABILITY-MISSING tespit edildi (-20 puan). | **GEÇTİ** |
| **Negatif Kontrol (VSS Saldırısı)** | `test_10_vss_golge_kopya_saldiri_yuzeyi_negatif_kontrol` | Windows VSS aktif fakat harici koruma yoksa vssadmin saldırı riski saptanmalıdır. | RISK-05-VSS-TAMPER-SURFACE tespit edildi (-15 puan). | **GEÇTİ** |
| **Negatif Kontrol (Hash Uyuşmazlığı)**| `test_11_kriptografik_butunluk_hatasi_ve_fidye_yazilimi_bozulmasi_kontrol` | Bozuk veya manipüle edilmiş hash sağlandığında BackupIntegrityError fırlatılmalıdır. | BackupIntegrityError yakalandı, işlem durduruldu. | **GEÇTİ** |
| **Negatif Kontrol (Limit Aşımı)** | `test_12_maksimum_snapshot_zincir_limiti_asimi_kontrol` | 5'ten fazla snapshot eklenmeye çalışıldığında SnapshotPolicyViolationError fırlatılmalıdır. | SnapshotPolicyViolationError yakalandı ve doğrulandı. | **GEÇTİ** |
| **Hata Yönetimi (Tanımsız VM)** | `test_13_tanimsiz_vm_veya_kayit_hata_yonetimi` | Tanımsız VM kimliği sorgulandığında SnapshotPolicyViolationError fırlatılmalıdır. | Hata yakalandı ve doğrulandı. | **GEÇTİ** |
| **İşlevsellik (Streaming Hash)** | `test_14_fiziksel_dosya_sha256_hesaplama_ve_olmayan_dosya` | Gerçek dosyanın SHA-256 özeti doğru hesaplanmalı, olmayan dosyada hata verilmelidir. | Hesaplama doğrulandı, FileNotFoundError teyit edildi. | **GEÇTİ** |

---

## 🛠️ 3. Tamamlanan Çıktılar ve Kanıt Dosyaları

1. `ornek_veri/vm_lab_envanteri.json`: Sentetik sanal makineler, snapshot zincirleri ve yedek kayıtları veri tabanı.
2. `ornek_veri/restore_drill_policy.json`: Geri dönüş tatbikatları, RPO/RTO hedefleri ve WORM standartları politikası.
3. `uygulama/vm_snapshot_backup_manager.py`: Her satırı pedagojik açıklamalarla yazılmış snapshot, yedekleme ve risk denetim motoru.
4. `tests/test_vm_snapshot_backup_manager.py`: 14 birim test senaryosunu içeren ve 0.018 saniyede sonuçlanan tam test paketi.
5. `kanit/gercek/komut_ve_cikis.txt`: Gerçek CLI yürütme çıktısı ve platform ortam kaydı.
6. `kanit/gercek/test_sonuclari.txt`: 14/14 unittest başarı çıktısı.
7. `kanit/temsili/snapshot_ve_yedek_mimarisi.txt`: Snapshot disk mekanizması, 3-2-1-1-0 kuralı ve fidye yazılımı vssadmin saldırı zincirini gösteren pedagojik ASCII şeması.
8. `ders.md`: 7 aşamalı "Usta-Çırak" masterclass ders metni.
9. `soru_cevap.md`: Soru bankasındaki 3 soruya (`G012-SC1`, `G012-SC2`, `G012-SC3`) ait 4 katı alt başlıklı kurumsal yanıtlar.

---

## 🏁 4. Sonuç ve Bir Sonraki Güne Geçiş

GÜN 012 çalışması; sanallaştırma laboratuvarlarında snapshot mekanizmasının nasıl çalıştığını, neden bir yedekleme alternatifi olamayacağını, 72 saat yaş sınırını, fidye yazılımlarının VSS imha saldırılarını ve 3-2-1-1-0 değişmez (WORM) yedekleme kalkanını başarıyla tamamlamıştır.

Tüm testler ve denetimler **%100 PASS** ile sonuçlanmış olup, Aşama 01 Hafta 02 kapsamındaki **GÜN 013** konusuna geçiş için tüm ön koşullar eksiksiz sağlanmıştır.
