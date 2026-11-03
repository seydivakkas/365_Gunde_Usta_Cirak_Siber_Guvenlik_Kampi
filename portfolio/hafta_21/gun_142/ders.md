<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 142: CVSS Temel Metrikleri — Usta-Çırak Dersi

**Modül:** Hafta 21 (Zafiyet Yönetimi, Güvenlik Açıkları ve Otomasyon)  
**Konu:** CVSS v3.1 Temel Metrikleri (Common Vulnerability Scoring System Base Metrics)  
**Pedagojik Yaklaşım:** Usta-Çırak / Hoca Dersi Modeli  
**Standart:** FIRST CVSS v3.1 Specification Section 7.1

---

## 1. Ustanın Girişi: "Puanı Bilmeyen, Tehlikeyi Ölçemez"

> "Dün seninle zafiyetlerin genel yaşam döngüsünü ve yama yönetimini konuştuk evlat. Bugün ise o zafiyetlerin kalbine, onları matematiksel olarak tarttığımız teraziye ineceğiz: **CVSS (Ortak Zafiyet Puanlama Sistemi)**.
>
> Sektörde çok sayıda analist görürsün; NVD sayfasına bakar, 'Bu zafiyet 9.8 imiş, çok fena!' der geçer. Ama ona '9.8 nereden çıktı, hangi metrik bu puanı fırlattı?' diye sorsan susup kalır.
>
> Gerçek bir siber güvenlik mühendisi, bir CVSS vektör dizesine baktığında bir röntgen filmine bakar gibi sistemi görür. Saldırganın ağdan mı geldiğini (AV:N), kullanıcının bir linke tıklamasının gerekip gerekmediğini (UI:R), zafiyetin konteyner sınırını aşıp ana makineye sıçrayıp sıçramadığını (S:C) bir bakışta okur.
>
> Bugün seninle FIRST CVSS v3.1 standardının 8 temel metriğini, etki ve istismar formüllerini ve o meşhur 'Scope Changed' kırılmasını adım adım öğreneceğiz."

---

## 2. CVSS v3.1 Taban Metrik Mimarisi

Bir CVSS v3.1 vektörü standart olarak şu biçimdedir:
$$\text{CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H}$$

Bu vektör iki ana alt skordan oluşur:
1. **İstismar Edilebilirlik Alt Skoru (Exploitability Sub-Score):** Açığın istismar edilmesinin ne kadar kolay veya zor olduğunu ölçer.
2. **Etki Alt Skoru (Impact Sub-Score - CIA):** Açık başarıyla istismar edildiğinde ortaya çıkacak tahribatı ölçer.
Bu iki skorun kesiştiği yerde ise **Kapsam (Scope)** kararı bulunur.

```
                              [ CVSS TABAN SKORU ]
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 ▼                                           ▼
   [ İSTİSMAR EDİLEBİLİRLİK ]                       [ ETKİ METRİKLERİ (CIA) ]
    - Saldırı Vektörü (AV)                           - Gizlilik Etkisi (C)
    - Saldırı Karmaşıklığı (AC)                      - Bütünlük Etkisi (I)
    - Gereken Yetki (PR)                             - Erişilebilirlik Etkisi (A)
    - Kullanıcı Etkileşimi (UI)                              │
                 │                                           ▼
                 │                                 Ham Etki: ISS = 1-[(1-C)(1-I)(1-A)]
                 │                                           │
                 └─────────────────────┬─────────────────────┘
                                       │
                                       ▼
                             [ KAPSAM (SCOPE: S) ]
                            ┌──────────┴──────────┐
                            ▼                     ▼
                     Scope Unchanged (U)    Scope Changed (C)
                     Impact = 6.42 * ISS    Impact = 7.52*(ISS-0.029)-...
                     Base = Impact+Exploit  Base = 1.08*(Impact+Exploit)
                                       │
                                       ▼
                          [ FIRST ROUNDUP FONKSİYONU ]
                            (0.1 yukarı yuvarlama)
```

---

## 3. Metriklerin Matematiksel Katsayıları ve Anlamları

### 3.1. İstismar Metrikleri (Exploitability)
$$\text{Exploitability} = 8.22 \times AV \times AC \times PR \times UI$$

1. **AV (Attack Vector - Saldırı Vektörü):**
   - `N (Network) = 0.85`: İnternet veya WAN üzerinden doğrudan erişilebilir.
   - `A (Adjacent) = 0.62`: Bitişik ağ (aynı subnet, Bluetooth, Wi-Fi menzili).
   - `L (Local) = 0.55`: Yerel kullanıcı hesabı, SSH kabuğu veya yerel klavye.
   - `P (Physical) = 0.20`: Cihaza fiziksel temas (USB, JTAG, konsol kablosu).
2. **AC (Attack Complexity - Saldırı Karmaşıklığı):**
   - `L (Low) = 0.77`: Özel bir koşul gerekmez, exploit her çalıştırıldığında başarılı olur.
   - `H (High) = 0.44`: Yarış durumu (race condition), ASLR/DEP atlatma veya zamanlama gerekir.
3. **PR (Privileges Required - Gereken Yetki):**
   - *Scope Unchanged ise:* `N (None) = 0.85`, `L (Low) = 0.62`, `H (High) = 0.27`
   - *Scope Changed ise:* `N (None) = 0.85`, `L (Low) = 0.68`, `H (High) = 0.50`
4. **UI (User Interaction - Kullanıcı Etkileşimi):**
   - `N (None) = 0.85`: Hedef sistemdeki kurbanın hiçbir şey yapmasına gerek yoktur.
   - `R (Required) = 0.62`: Kurbanın zararlı linke tıklaması, belgeyi açması veya oturum açması gerekir.

---

## 4. Etki Metrikleri (Impact) ve Scope Kırılması

Etki metrikleri, bilgi güvenliğinin meşhur CIA üçlüsünü temsil eder:
- `C (Confidentiality)`, `I (Integrity)`, `A (Availability)`
- Değerler: `H (High) = 0.56`, `L (Low) = 0.22`, `N (None) = 0.0`

Önce ham etki puanı (ISS - Impact Sub-Score) hesaplanır:
$$\text{ISS} = 1 - [(1 - \text{Impact}_C) \times (1 - \text{Impact}_I) \times (1 - \text{Impact}_A)]$$

### Scope (Kapsam) Neden Oyunun Kurallarını Değiştirir?
- **Scope Unchanged (S:U):** Zafiyet yalnızca bulunduğu yazılım bileşenini etkiler (Örn: Web sunucusu çöker ama işletim sistemi etkilenmez).
  $$\text{Impact} = 6.42 \times \text{ISS}$$
  $$\text{BaseScore} = \text{Roundup}(\min((\text{Impact} + \text{Exploitability}), 10.0))$$
- **Scope Changed (S:C):** Zafiyet bir güvenlik sınırını aşar! Örneğin:
  - Konteynerden ana makineye sıçrama (Container Breakout - runc CVE-2024-21626).
  - Sanal makineden hipervizöre sıçrama (VM Escape).
  - Tarayıcı sandbox'ından işletim sistemine kod çalıştırma.
  - XSS (Web uygulamasından kurban kullanıcının tarayıcısına sıçrama).
  
  Scope Changed olduğunda formül değişir ve **1.08 çarpanı** devreye girer:
  $$\text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$$
  $$\text{BaseScore} = \text{Roundup}(\min(1.08 \times (\text{Impact} + \text{Exploitability}), 10.0))$$

---

## 5. FIRST Roundup Fonksiyonunun Sırrı

Standart yuvarlamada `4.02` sayısı `4.0` olur. Ancak CVSS'te güvenlik riski asla küçümsenemez! FIRST şartnamesinde tanımlanan `Roundup` fonksiyonu, **en küçük bir kesri dahi daima bir üst 0.1 basamağına yuvarlar**:
- `4.00 -> 4.0`
- `4.01 -> 4.1`
- `4.02 -> 4.1`
- `9.80001 -> 9.9`

Bu matematiksel kural, zafiyet puanının kağıt üzerinde düşürülmesini engeller.

---

## 6. Ustanın Çırağa Öğüdü

> "Kulak ver evlat: Bir gün yönetim kuruluna veya CISO'ya rapor sunarken 'Bu zafiyet çok tehlikeli' demek yetersizdir. Onlara şunu diyeceksin:
> 'Efendim, bu zafiyet CVSS 9.8'dir; çünkü saldırı ağ üzerinden kimlik doğrulaması olmadan (AV:N, PR:N) ve kullanıcı etkileşimi gerekmeden (UI:N) tetiklenmektedir. Gizlilik, bütünlük ve erişilebilirliğin tamamı (C:H/I:H/A:H) yok olmaktadır.'
>
> Rakamlarla ve metriklerle konuşan mühendisin sözü kanundur. CVSS formülünü ezbere bil ki zafiyetin gerçek ağırlığını tereddütsüz ortaya koyabilesin!"
