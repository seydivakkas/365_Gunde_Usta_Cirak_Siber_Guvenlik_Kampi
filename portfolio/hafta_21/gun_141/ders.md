<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 141: Yama Yönetimi ve CVE — Usta-Çırak Dersi

**Modül:** Hafta 21 (Zafiyet Yönetimi, Güvenlik Açıkları ve Otomasyon)  
**Konu:** Yama Yönetimi ve CVE (Common Vulnerabilities and Exposures)  
**Pedagojik Yaklaşım:** Usta-Çırak / Hoca Dersi Modeli  
**Standartlar:** NIST SP 800-40 Rev. 4, CISA BOD 22-01 (KEV), FIRST CVSS v3.1, EPSS

---

## 1. Ustanın Girişi: "Zafiyeti Bilmek Yetmez, Zamanla Yarışmak Gerekir"

> "Hoş geldin evlat, Hafta 21'e adım attık. Geçen hafta seninle Linux işletim sisteminin savunma surlarını (Sudo, PAM, Systemd, SSH, Firewall, Audit) taş taş ördük. Ama unutma: Dünyanın en sağlam kalesini de inşa etsen, surların yapıldığı taşların içinde zamanla çatlaklar (güvenlik zafiyetleri - vulnerabilities) belirecektir.
>
> Yazılım dünyasında hiçbir kod ebediyen hatasız kalmaz. Bir kütüphanede, bir çekirdek fonksiyonunda ya da bir ağ protokolünde yeni bir açık keşfedildiğinde, bu açık bir **CVE (Common Vulnerabilities and Exposures)** numarası ile küresel sisteme kaydedilir.
>
> İşte o andan itibaren geri sayım başlar. Saldırganlar o açığı istismar edecek araçları (exploit) geliştirmeye başlarken, savunucular (yani bizler) o açığı kapatacak yamayı (patch) üretip test etmek ve üretim sistemlerine dağıtmak zorundadır. Bu bir hız ve strateji yarışıdır. Eğer kurumsal bir yama politikan ve zafiyet triyaj mekanizman yoksa, saldırganlar senden önce o kapıdan içeri süzülür."

---

## 2. Zafiyet Ekosisteminin Dört Büyük Sacayağı

Bir siber güvenlik mühendisi, zafiyetleri yönetirken yalnızca tek bir metrikle (örneğin sadece CVSS skoruyla) karar veremez. Modern zafiyet yönetiminde dört temel mekanizma birlikte değerlendirilir:

```
+-------------------------------------------------------------------------+
| SACAYAĞI 1: CVE (Ortak Güvenlik Açığı Sözlüğü - MITRE / NVD)            |
| -> Format: CVE-YYYY-NNNNN (Örn: CVE-2024-6387 regreSSHion)             |
| -> Dünyadaki her benzersiz zafiyete evrensel bir kimlik numarası atar.  |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| SACAYAĞI 2: CVSS (Ortak Zafiyet Puanlama Sistemi - FIRST)               |
| -> v3.1 / v4.0 Taban Skoru (0.0 - 10.0) ve Vektör Dizesi                 |
| -> Saldırı vektörü (AV), Karmaşıklık (AC), Yetki (PR), Etki (C, I, A)   |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| SACAYAĞI 3: CISA KEV (Bilinen ve İstismar Edilen Zafiyetler Kataloğu)   |
| -> "Vahşi doğada (in the wild) aktif saldırıda kullanılıyor mu?" sorusu |
| -> KEV listesinde yer alan açıklar derhal "ACİL (EMERGENCY)" ilan edilir|
+-------------------------------------------------------------------------+
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| SACAYAĞI 4: EPSS (İstismar Tahmin Puanlama Sistemi - FIRST)             |
| -> Gelecek 30 gün içinde bir zafiyetin istismar edilme olasılık yüzdesi |
| -> CVSS skoru orta olsa bile yüksek EPSS acil müdahale gerektirir.      |
+-------------------------------------------------------------------------+
```

---

## 3. CVSS v3.1 Metrikleri ve Anlamları

CVSS skoru, bir açığın teorik tehlike potansiyelini 0 ile 10 arasında puanlar. Bir CVSS vektör dizesi incelendiğinde şu metrikler okunmalıdır:

$$\text{CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H}$$

1. **AV (Attack Vector - Saldırı Vektörü):**
   - `N (Network)`: İnternet üzerinden uzaktan tetiklenebilir (En tehlikeli).
   - `A (Adjacent)`: Aynı yerel ağ (LAN/VLAN) veya Wi-Fi menzili gerekir.
   - `L (Local)`: Saldırganın zaten makinede bir kullanıcı hesabı veya kabuk erişimi olmalıdır.
   - `P (Physical)`: Sunucunun başına fiziksel olarak oturmak gerekir.
2. **AC (Attack Complexity - Saldırı Karmaşıklığı):**
   - `L (Low)`: Özel bir yarış durumu (race condition) gerektirmez, doğrudan tetiklenir.
   - `H (High)`: Belirli bellek adreslerinin tutması veya hassas zamanlama gerekir.
3. **PR (Privileges Required - Gereken Yetki):**
   - `N (None)`: Kimlik doğrulama gerekmez, anonim saldırgan istismar edebilir.
   - `L (Low)`: Standart kullanıcı yetkisi gerekir.
   - `H (High)`: Yönetici/root yetkisi gerekir.
4. **UI (User Interaction - Kullanıcı Etkileşimi):**
   - `N (None)`: Kurbanın hiçbir şey yapmasına gerek yoktur.
   - `R (Required)`: Kurbanın bir linke tıklaması veya dosya açması gerekir (Phishing).
5. **C / I / A (Confidentiality, Integrity, Availability):**
   - Gizlilik, Bütünlük ve Erişilebilirlik üzerindeki etki (`High`, `Low`, `None`).

---

## 4. Kurumsal Yama Yaşam Döngüsü ve Hizmet Seviyesi Taahhütleri (SLA)

NIST SP 800-40 Rev. 4 yönergelerine göre yama yönetimi 5 aşamalı bir döngüdür:

1. **Keşif ve Envanter (Inventory & Discovery):** Sistemde kurulu tüm yazılımların ve sürümlerinin `dpkg -l`, `rpm -qa` veya merkezi ajanlar ile listelenmesi.
2. **Triyaj ve Risk Önceliklendirme (Triage):**
   - Zafiyet CISA KEV listesinde mi?
   - Tehdit seviyesi nedir?
   - SLA süresi ne kadardır?
3. **Test Ortamı (Staging & Canary Sandbox):** Üretim sistemlerine yamayı basmadan önce izole bir test sunucusunda bağımlılık çatışmaları ve regresyon testleri yapılır.
4. **Aşamalı Dağıtım (Phased Rollout):** Önce test grubu (%10), ardından genişletilmiş dağıtım (%50), en son tüm filo (%100).
5. **Yeniden Başlatma ve Doğrulama (Post-Patch Verification):**
   - Linux'ta çekirdek veya glibc güncellemeleri sonrası `/var/run/reboot-required` dosyası oluşur.
   - Servislerin ayağa kalktığı ve CVE'nin kapandığı doğrulanır.

### Kurumsal SLA Matrisi

| Şiddet Seviyesi | Kriter | Maksimum Yama Süresi (SLA) | Onay Mercii |
| :--- | :--- | :---: | :--- |
| **EMERGENCY (Acil)** | CISA KEV (Aktif İstismar) VEYA (CVSS $\ge 9.0$ + EPSS $\ge 0.40$) | **72 Saat (3 Gün)** | Acil Değişiklik Kurulu (Emergency CAB) |
| **CRITICAL (Kritik)** | CVSS 9.0 - 10.0 (KEV Harici) | **7 Gün** | Standart Değişiklik Kurulu |
| **HIGH (Yüksek)** | CVSS 7.0 - 8.9 | **14 Gün** | Haftalık Bakım Döngüsü |
| **MEDIUM (Orta)** | CVSS 4.0 - 6.9 | **30 Gün** | Aylık Bakım Penceresi |
| **LOW (Düşük)** | CVSS 0.1 - 3.9 | **60 Gün** | Çeyreklik (Quarterly) Güncelleme |

---

## 5. Otomatik Güncellemeler: `unattended-upgrades`

Linux sistemlerinde güvenlik yamalarının insan eli değmeden otomatik uygulanması için Debian/Ubuntu sistemlerinde `unattended-upgrades` aracı kullanılır:

```ini
// /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Package-Blacklist {
    // Üretimde risk taşıyan kritik paketler hariç tutulabilir
};
Unattended-Upgrade::Automatic-Reboot "false";
```

RHEL tabanlı sistemlerde ise `dnf-automatic` servisi aynı görevi üstlenir.

---

## 6. Ustanın Çırağa Öğüdü

> "Kulak ver evlat: Bir sistem yöneticisinin en büyük hatası, 'yamayı uygulayayım da bitsin' diyerek doğrudan canlı ortamda `apt-get upgrade` çekmektir! 
> Yama uygulamak kadar, bir şeyler ters gittiğinde **nasıl geri döneceğini (rollback)** bilmek de hayati öneme sahiptir.
> Her yama operasyonundan önce sistemin bir anlık görüntüsünü (snapshot) alacak ya da paket yöneticisinin geri alma komutunu (`apt-get install <pkg>=<eski_surum>` veya `dnf downgrade`) elinin altında hazır tutacaksın. Hazırlıksız yama, saldırganın yapacağı kesintiden daha büyük hasar verebilir!"
