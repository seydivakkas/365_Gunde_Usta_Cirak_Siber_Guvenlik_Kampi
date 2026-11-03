# GÜN 32: BAŞLANGIÇ UYGULAMALARI VE HİZMET YÖNETİMİ — TEKNİK RAPOR VE DEĞERLENDİRME

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu rapor ve değerlendirme içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, çoğaltılamaz, ticari amaçla kullanılamaz.
```

---

## 1. GÖREV VE PEDAGOJİK HEDEF ÖZETİ
- **Gün:** 32 (G032)
- **Hafta:** 05 | **Aşama:** 02 (Sistem ve Ağ Temelleri)
- **Konu:** Başlangıç uygulamaları ve hizmet yönetimi (Startup applications and service management)
- **Standart Kaynak:** `standart_gun.md §3–12`
- **Resmî Kaynak:** [Microsoft Learn: Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- **Öğrenme Çıktısı:**
  1. Başlangıç noktalarının (Registry Run, Startup Folder, SCM Services, Scheduled Tasks, systemd/cron) mimarisini kavrama.
  2. Otomatik başlayan uygulamaların sistem saldırı yüzeyini genişlettiğini somut örneklerle anlama.
  3. Gelişigüzel hizmet kapatmanın yaratacağı bağımlılık kopması ve güvenlik körlüğünü analiz etme.
  4. Tırnaksız servis yolları (Unquoted Service Path - MITRE T1574.009), isim sahteciliği (Masquerading - MITRE T1036) ve savunma tahrifatı (Impair Defenses - MITRE T1562.001) zafiyetlerini otomatik tespit edip raporlayabilme.

---

## 2. DÖRT BİLEŞENLİ DEĞERLENDİRME RUBRİĞİ (100 / 100)

| Rubrik Kriteri | Taban Puan | Alınan Puan | Açıklama ve Gerekçe |
| :--- | :---: | :---: | :--- |
| **Açıklamalı Soru-Cevap** | 0 – 20 | **20** | `soru_cevap.md` içinde G032-SC1, SC2 ve SC3 soruları tam pedagojik derinlikle, 4 zorunlu alt başlık (Temel Kavram, Soru/Didaktik Çözüm, Savunma/Tespit, Usta-Çırak İpuçları) eksiksiz uygulanarak hazırlanmıştır. |
| **Gerçek Uygulama / Simülasyon** | 0 – 40 | **40** | `startup_service_auditor.py` aracı bağımsız ve sıfırdan geliştirilmiştir. Çalıştırılabilir her bir kod satırı didaktik açıklamalarla zenginleştirilmiş; unquoted path, şüpheli dizin, masquerading, servis tahrifatı ve risk skoru motorları eksiksiz kodlanmıştır. |
| **Doğrulanabilir Kanıt** | 0 – 25 | **25** | `kanit/gercek/` altında 14/14 birim test çıktısı (`test_sonuclari.txt`), CLI yürütme dökümü (`komut_ve_cikis.txt`), ASCII denetim çıktısı (`baslangic_ve_servis_denetim_raporu.txt`) ve bozuk veri reddini belgeleyen `negatif_kontrol_sonuclari.txt` doğrulanmıştır. `kanit/temsili/` altında etiketli mimari şema yer almaktadır. |
| **Teknik Raporlama** | 0 – 15 | **15** | Rapor; bulguların teknik kök nedenlerini, MITRE ATT&CK eşleşmelerini, çözüm önerilerini ve etik/savunma sınırlarını net bir şekilde ortaya koymaktadır. |
| **TOPLAM PUAN** | **100** | **100** | **SONUÇ: YETERLİ / PASS (TAM BAŞARI)** |

---

## 3. LABORATUVAR VE DENETİM BULGULARI ÖZETİ

`sample_startup_service_inventory.json` dosyasında yer alan 14 başlangıç/servis kaydı taranmış ve aşağıdaki kritik güvenlik bulguları saptanmıştır:

1. **Unquoted Service Path (T1574.009) — HIGH:**
   - **Servis Adı:** `VulnBackupService`
   - **İkili Yol:** `C:\Program Files\Vulnerable Backup Solution\BackupAgent.exe -daemon`
   - **Risk:** Çift tırnak bulunmayan ve boşluk içeren yol, SCM tarafından çalıştırılırken `C:\Program.exe` aramasından ötürü Yerel Yetki Yükseltmeye (LPE) açıktır.
   - **İyileştirme:** `sc.exe config "VulnBackupService" binPath= "\"C:\Program Files\Vulnerable Backup Solution\BackupAgent.exe\" -daemon"`
2. **Masquerading / Typosquatting (T1036) — CRITICAL:**
   - **Servis Adı:** `svch0st_service` (Yol: `C:\Windows\Temp\svch0st.exe`)
   - **Servis Adı:** `lsasss_service` (Yol: `C:\ProgramData\lsasss.exe`)
   - **Risk:** Meşru sistem servislerinin isimlerini taklit ederek analistleri yanıltmaya çalışan imzasız kalıcılık mekanizmaları.
3. **Impair Defenses / Service Tampering (T1562.001) — CRITICAL:**
   - **Servis Adı:** `MpsSvc` (Windows Defender Firewall)
   - **Mevcut Durum:** `Stopped` | Başlangıç Modu: `Disabled`
   - **Risk:** Saldırganın yatay yayılma ve tespit atlatma amacıyla güvenlik duvarını susturması.
4. **Suspicious Script Execution (T1059.001) — CRITICAL:**
   - **Görev:** `PowerShellScriptAuto`
   - **Risk:** `-ExecutionPolicy Bypass`, `-WindowStyle Hidden` ve `-EncodedCommand` bayraklarıyla gizlenmiş arka plan komutu.

**Sistem Risk Puanı:** `100 / 100` (CRITICAL_THREAT)

---

## 4. NEGATİF KONTROL VE HATA DAYANIKLILIĞI

`corrupted_startup_service_test.json` dosyasında yer alan 7 bozuk/hatalı kayıt (eksik zorunlu alanlar, geçersiz başlangıç modları, sözlük olmayan tipler) `validate_entry` fonksiyonu tarafından güvenle tespit edilmiş, sistemin çökmesi engellenmiş ve tüm hatalı kayıtlar `corrupted_records` günlüğüne kaydedilmiştir. 14 birim testin tamamı 0.020 saniyede hatasız geçmiştir.

---

## 5. SONUÇ VE BİR SONRAKİ ADIM
Gün 32 çalışmaları; bağımsızlık kuralına tam riayetle, Usta-Çırak pedagojisine uygun şekilde, her satırı açıklamalı kod ve testlerle başarıyla tamamlanmıştır.

- **Sonraki Gün:** Gün 33 (G033 - Hafta 05)
- **Hazırlık:** Gün 32'nin yedeklenmesi, manifest dosyasının üretilmesi ve Excel çizelgesinin güncellenmesi.
