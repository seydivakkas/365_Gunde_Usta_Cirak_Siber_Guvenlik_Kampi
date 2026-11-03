# Gün 127: Doğrulama ve Değerlendirme Raporu — Uç Nokta Tehdit Modeli

> **Modül:** Hafta 19 — Uç Nokta Güvenliği ve Sertleştirme  
> **Konu:** Uç Nokta Tehdit Modeli (Endpoint Threat Model)  
> **Aşama:** 06 (Uç Nokta Savunması)  
> **Tarih:** 2026-11-02  
> **Nihai Skor:** 100 / 100 (TAM BAŞARI / YETERLİ)

---

## 1. Yönetici Özeti

**Gün 127**, 365 Günlük Siber Güvenlik Müfredatı'nın **Aşama 6 (Uç Nokta Güvenliği ve Sertleştirme)** modülünün ilk günüdür. Bu kapsamda geliştirilen **Uç Nokta Tehdit Modeli Motoru (Endpoint Threat Model Engine)**; Windows ve Linux uç noktalarında kimlik belleği (LSASS), yetki yükseltme vektörleri (Unquoted Service Paths, SUID), kalıcılık mekanizmaları (Registry Run Keys), savunma atlatma (EDR Tamper Protection) ve ağ açıklıklarını MITRE ATT&CK ve CWE taksonomileriyle analiz etmiştir. Yapılan testler sonucunda 15 birim test (%100 PASS) ve 9 negatif sınır kontrolü (%100 PASS) sıfır toleransla başarıyla tamamlanmıştır.

---

## 2. Değerlendirme Karnesi

| Değerlendirme Kriteri | Ağırlık | Alınan Puan | Açıklama |
|---|---|---|---|
| **1. Kod Kalitesi ve Didaktik Yorumlar** | 20 | 20 | Motor, CLI, test ve kanıt üretim betiklerindeki tüm yürütülebilir Python satırları didaktik Türkçe açıklamalarla zenginleştirilmiştir. Tip ipuçları ve veri modelleri eksiksizdir. |
| **2. Birim Testler ve Kapsam (15 Test)** | 40 | 40 | Sıkılaştırılmış sistem doğrulaması, LSASS/RunAsPPL, Unquoted Path, SUID, EDR ve Tamper Protection, Sysmon telemetrisi, PowerShell CLM, açık portlar ve rol katsayısı testleri (15/15) tam başarıyla geçmiştir (0.001s). |
| **3. Negatif Kontroller ve Sınır Durumları (9 Senaryo)** | 25 | 25 | EDR eksikliği, LSA koruması yokluğu, tırnaksız servis yolu, Linux SUID hatası, telemetri kör noktası, CLM eksikliği, tehlikeli portlar, disk şifreleme yokluğu ve zayıf autorun senaryolarının tümü (9/9) başarıyla tespit edilmiştir. |
| **4. Mimari Tasarım, Güvenlik ve Belgeleme** | 15 | 15 | ASCII temsili mimari şeması (zorunlu banner ile), CIS Benchmark & Microsoft Baseline uyumlu sıkılaştırma yol haritası, didaktik Usta-Çırak dersi ve CLI aracı eksiksiz tamamlanmıştır. |
| **TOPLAM SKOR** | **100** | **100** | **DURUM: YETERLİ / ÜRETİM DÜZEYİ** |

---

## 3. CWE ve MITRE ATT&CK Eşleştirme Matrisi

| Tehdit Alanı | CWE Kodu | MITRE ATT&CK Kimliği | Tespit Mekanizması ve Savunma |
|---|---|---|---|
| **LSASS Bellek Koruması** | **CWE-311** | **T1003.001** (LSASS Memory) | LSA Protection (RunAsPPL) ve Credential Guard yokluğunun tespiti ve GPO ile sıkılaştırma. |
| **Tırnaksız Servis Yolu** | **CWE-428** | **T1574.009** (Path Interception) | Boşluklu ve tırnaksız ImagePath kayıtlarının tespiti ve çift tırnak zorunluluğu. |
| **Linux SUID İstismarı** | **CWE-250** | **T1548.001** (Setuid and Setgid) | GTFOBins uyumlu tehlikeli SUID ikililerinin tespiti ve SUID bitinin kaldırılması. |
| **EDR Savunma Felci** | **CWE-693** | **T1562.001** (Impair Defenses) | EDR yokluğu veya Kurcalama Koruması (Tamper Protection) kapalılığının tespiti. |
| **Telemetri Eksikliği** | **CWE-778** | **T1070** (Indicator Removal) | Sysmon veya Auditd süreç izleme eksikliğinin tespiti ve Event Forwarding kurulumu. |
| **PowerShell Betik Riskleri** | **CWE-284** | **T1059.001** (PowerShell) | FullLanguage modunun tespiti ve Kısıtlı Dil Modu (CLM) zorunluluğu. |
| **Ağ Port Açıklıkları** | **CWE-319** | **T1021** (Remote Services) | SMBv1 ve NLA'sız RDP gibi tehlikeli portların tespiti ve kapatılması. |
| **Disk Şifreleme Yokluğu** | **CWE-311** | **T1005** (Data from Local System) | BitLocker/LUKS yokluğunun tespiti ve TPM 2.0 şifreleme zorunluluğu. |
| **Zayıf Kayıt Defteri İzinleri** | **CWE-732** | **T1547.001** (Registry Run Keys) | Run/RunOnce anahtarlarında standart kullanıcı yazma izninin tespiti ve ACL kilitleme. |

---

## 4. Test ve Doğrulama Kanıtları Özeti

1. **Birim Test Çıktısı (`kanit/gercek/test_sonuclari.txt`):**
   - 15 test koşuldu, 0 hata, 0 başarısızlık.
   - Süre: 0.001 saniye.
   - Sonuç: BAŞARILI (100% PASS).
2. **Negatif Kontrol Çıktısı (`kanit/gercek/negatif_kontrol_sonuclari.txt`):**
   - 9 senaryo koşuldu, 9/9 başarılı.
   - Uç nokta saldırı yüzeyindeki tüm kritik zafiyetler ve MITRE taktikleri doğrulandı.
3. **Uç Nokta Tehdit Analiz Raporu (`kanit/gercek/uc_nokta_tehdit_analiz_raporu.json`):**
   - Hedef Uç Nokta: `CORP-W11-FINANCE-04` (Windows 11 İş İstasyonu).
   - Tehdit Skoru: 0.0 / 100 (Tüm kontroller tam, duruş: GÜVENLİ / SIKILAŞTIRILMIŞ).
4. **CLI Etkileşim Kanıtı (`kanit/gercek/komut_ve_cikis.txt`):**
   - `quick-check` ve `model` komutları çalıştırılarak çıktılar arşivlendi.
5. **Temsili Mimari Şeması (`kanit/temsili/uc_nokta_tehdit_mimarisi.txt`):**
   - Zorunlu banner ile uç nokta saldırı yüzeyleri ve savunma katmanları görselleştirildi.
