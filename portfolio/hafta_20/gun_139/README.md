# Gün 139: Linux Audit ve Journal Güvenliği

![License: All Rights Reserved](https://img.shields.io/badge/license-All%20Rights%20Reserved-red?style=flat-square)
![Tests: 15 Passed](https://img.shields.io/badge/tests-15%20passed-brightgreen?style=flat-square)
![Score: 100/100](https://img.shields.io/badge/score-100%2F100-success?style=flat-square)
![Platform: Pure Python 3](https://img.shields.io/badge/platform-Python%203-blue?style=flat-square)

## Genel Bakış

Bu modül, Linux işletim sistemlerinde kurumsal düzeyde denetim (auditing) ve günlükleme (logging) güvenliğini sağlamak amacıyla geliştirilmiştir. Çekirdek seviyesindeki Denetim Alt Sistemi (`auditd`), `systemd-journald` servisi ve CIS Linux Benchmark Bölüm 4.1 & 4.2 standartları baz alınarak tam teşekküllü bir denetim motoru (`linux_audit_engine.py`) ve CLI yönetim aracı (`audit_security_cli.py`) inşa edilmiştir.

Modül; kritik kimlik ve yetkilendirme dosyalarının (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`) izlenmesini, çekirdek modülü yükleme/kaldırma (`init_module`, `delete_module`) ve sistem saati manipülasyonu (`adjtimex`, `settimeofday`) çağrılarının filtrelenmesini, kurcalanamaz çekirdek kilitlemesini (`-e 2`) ve `systemd-journald` Forward Secure Sealing (FSS) kriptografik mühürlemesini doğrular ve otomatik sıkılaştırma betikleri üretir.

---

## Dizin Yapısı

```
portfolio/hafta_20/gun_139/
├── README.md                              # Proje özeti, kullanım kılavuzu ve lisans
├── ders.md                                # Usta-Çırak pedagojisi ile derinlemesine teknik ders
├── soru_cevap.md                          # 4 alt başlıklı 3 kapsamlı derinleşme sorusu ve cevabı
├── rapor.md                               # 100/100 tam puanlı başarı karnesi ve metrikler
├── sonuc.json                             # Makine tarafından okunabilir sonuç özeti
├── manifest.json                          # Dizin dosya bütünlüğü ve SHA-256 sağlama toplamları
├── kanit_uretici.py                       # Testleri koşturan ve kanıtları üreten otomasyon aracı
├── uygulama/
│   ├── __init__.py                        # Paket başlatıcı
│   ├── linux_audit_engine.py              # CIS uyumlu Audit ve Journald denetim motoru
│   └── audit_security_cli.py              # Komut satırı yönetim arayüzü
├── tests/
│   ├── __init__.py                        # Test paketi başlatıcı
│   └── test_linux_audit_security.py       # 15 birim testi içeren test paketi (100% PASS)
├── ornek_veri/
│   ├── audit_inventory_spec.json          # Örnek audit ve journald yapılandırma envanteri
│   └── invalid_audit_scenarios.json       # 9 adet negatif kontrol ve zafiyet senaryosu
└── kanit/
    ├── gercek/
    │   ├── test_sonuclari.txt             # 15 birim testinin çalışma logları
    │   ├── negatif_kontrol_sonuclari.txt  # 9 negatif senaryonun yakalanma logları
    │   ├── audit_guvenlik_analiz_raporu.json # JSON formatında denetim raporu
    │   ├── otomatik_sikilastirma.sh       # Üretilen Bash sıkılaştırma betiği
    │   ├── komut_ve_cikis.txt             # CLI yürütme çıktıları
    │   ├── cis_audit_rules_template.rules # CIS uyumlu kural şablonu
    │   └── journald_secure.conf           # Güvenli journald yapılandırması
    └── temsili/
        └── audit_mimarisi.txt             # ASCII sistem mimarisi diyagramı
```

---

## Temel Özellikler

1. **Çekirdek Düzeyinde Değiştirilemezlik (`-e 2`):** Çekirdeğin audit kurallarını dondurarak root yetkisine sahip saldırganların bile kuralları silememesini sağlar.
2. **Kritik Dosya ve Sistem Çağrısı İzleme:** `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` dosya erişimleri ile `init_module`, `delete_module`, `adjtimex` sistem çağrılarını CIS standartlarında izler.
3. **Kriptografik İleri Yönde Mühürleme (FSS):** `systemd-journald` loglarının geriye dönük tahrif edilmesini matematiksel olarak engelleyen FSS (`Seal=yes`) doğrulamasını gerçekleştirir.
4. **Denetim Puanlama Algoritması:** 0-100 arası ağırlıklı puanlama ile sistemin audit ve logging güvenliğini derecelendirir.
5. **Otomatik İyileştirme (Remediation):** Tespit edilen eksiklikleri gidermek için anında çalıştırılabilir Bash sıkılaştırma betiği ve referans konfigürasyon şablonları üretir.

---

## Hızlı Başlangıç

### 1. Testleri ve Kanıt Üreticisini Çalıştırma
```powershell
python kanit_uretici.py
```

### 2. CLI ile Denetim Gerçekleştirme
```powershell
# Envanter dosyasını denetle
python uygulama/audit_security_cli.py audit ornek_veri/audit_inventory_spec.json

# Detaylı JSON rapor üret
python uygulama/audit_security_cli.py audit ornek_veri/audit_inventory_spec.json --output kanit/gercek/audit_guvenlik_analiz_raporu.json

# Otomatik sıkılaştırma betiği oluştur
python uygulama/audit_security_cli.py generate-remediation ornek_veri/audit_inventory_spec.json --output kanit/gercek/otomatik_sikilastirma.sh
```

---

## Lisans

```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır.

YASAKLAR:
  1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
  2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
  3. Alt lisanslanamaz, satılamaz veya devredilemez.
  4. Tersine mühendislik yapılamaz.

İZİN VERİLEN KULLANIM:
  - GitHub üzerinde görüntüleme ve okuma.
  - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).

YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
İzin talepleri için: GitHub @seydivakkas
```
