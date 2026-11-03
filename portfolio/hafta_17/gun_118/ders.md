# Hafta 17 / Gün 118: En Az Ayrıcalık (PoLP) ve Sıfır Güven (Zero Trust) — Usta-Çırak Hoca Dersi

**Telif Hakkı:** © 2026 Seydi Eryılmaz (@seydivakkas) — Tüm Hakları Saklıdır.  
**Eğitim Modeli:** Usta-Çırak / Hoca Dersi Pedagojisi  
**Konu:** En Az Ayrıcalık İlkesi (PoLP), Sıfır Kalıcı Yetki (ZSP) ve NIST SP 800-207 Sıfır Güven Mimarisi  

---

## 1. Atölye Sohbeti: "Ustam, Adam Zaten İç Ağda ve Admin, Neden Rahat Bırakmıyoruz?"

**Çırak:**  
"Ustam, dün harika bir RBAC ve ABAC motoru kurduk. Diyelim ki sistem yöneticimiz şirket VPN'i ile iç ağa bağlandı. Adamın rolü zaten 'Sistem Yöneticisi'. Neden ona her dakika 'Sen kimsin, cihazın güncel mi, diskin şifreli mi, bu işlemi yapmaya yetkin var mı?' diye eziyet ediyoruz? 'Adam içeride işte, bırakalım da işini yapsın' desek ne kaybederiz?"

**Usta:**  
*(Derin bir iç çeker, sandalyeye yaslanır ve duvardaki siber saldırı zaman çizelgesini işaret eder)*  
"Evlat, o kurduğun tek bir cümle, son yirmi yılda Target'tan SolarWinds'e, Colonial Pipeline'dan Uber'e kadar trilyon dolarlık şirketlerin çöküş gerekçesidir!  
Tarihin en büyük veri ihlallerinin ortak mezar taşı yazısı şudur: **'İç ağımız güvenliydi ve o hesabın admin yetkisi vardı.'**

Eski siber güvenlik dünyası 'Kale ve Hendek' (Castle and Moat) mantığıyla çalışırdı. Dışarıya devasa bir güvenlik duvarı (Firewall) örerdin. Hendekten içeri giren herkese 'dost' muamelesi yapardın.  
Peki ya o hendekten içeri giren şey, yöneticinin bilgisayarına oltalamayla (phishing) sızmış bir truva atıysa? Ya da bir fidye yazılımı (Ransomware)?  
İçeride kontrol yoksa, saldırgan kaledeki tüm kapıları (veritabanlarını, yedekleri, domain controller'ı) tek tek kırarak ilerler. Buna siber güvenlikte **Yanal Hareket (Lateral Movement)** denir!

Bugün bu köhne anlayışı çöpe atıyoruz. Sıfır Güven (Zero Trust) mimarisi şunu söyler:  
**'Ağ diye bir güven sınırı yoktur. Kale çökmüştür. İçerideki herkes potansiyel olarak ele geçirilmiş olabilir. Asla güvenme, daima doğrula!'**"

---

## 2. En Az Ayrıcalık İlkesi (Principle of Least Privilege - PoLP) ve ZSP

**Usta:**  
"En Az Ayrıcalık İlkesi, 1975 yılında Jerome Saltzer ve Michael Schroeder tarafından formüle edilmiştir:  
*Bir kullanıcı, program veya süreç; yalnızca o an icra ettiği görevi tamamlamak için asgari düzeyde gereken yetkilere sahip olmalı, fazlasına asla sahip olmamalıdır.*

Geleneksel kurumlarda yapılan en büyük hata nedir biliyor musun?  
**Kalıcı Ayrıcalıklar (Standing Privileges):**  
Ahmet Bey veritabanı yöneticisidir. Ahmet Bey'e işe girdiği ilk gün `sa` veya `root` yetkisi verilir. Ahmet Bey 5 yıl boyunca, gece uyurken de, evinde film izlerken de o sınırsız yetkiyi cebinde taşır!  
Ahmet'in şifresi sızdığı an, hacker şirketin şahdamarını keser.

### Sıfır Kalıcı Yetki (Zero Standing Privileges - ZSP) ve JIT Devrimi
Modern güvenlikte **Kalıcı Admin Hesabı DİYE BİR ŞEY YOKTUR (CWE-250)**.  
Kullanıcıların normal hesabı sıradan bir kullanıcı yetkisindedir.  
Peki veritabanı bakımı yapması gerektiğinde ne olur?

```
┌────────────────────────────────────────────────────────┐
│        JUST-IN-TIME (JIT) YETKİLENDİRME AKIŞI         │
│                                                        │
│  [Sıradan Kullanıcı]                                   │
│           │                                            │
│           ▼ 1. JIT Talep Et (Kapsam: db:backup, 30 Dk) │
│  [JIT Yöneticisi & Onay Mekanizması]                   │
│           │                                            │
│           ▼ 2. Geçici Bilet Üret (TTL = 1800 sn)       │
│  [Geçici Yetkili Oturum] ──(Süre Bitti)──> [İPTAL!]    │
└────────────────────────────────────────────────────────┘
```

1. **İhtiyaç Anında Talep (Just-In-Time):** Kullanıcı 'Bana 30 dakikalığına `db:maintenance_backup` yetkisi ver' der.
2. **Kapsam Asgarileştirme:** Kullanıcı 'admin' olamaz; sadece o işe özel tekil izni (`db:maintenance_backup`) alır (CWE-272 önlenir).
3. **Zaman Aşımı (TTL):** 30 dakika dolduğu anda yetki havaya uçar! Saldırgan 31. dakikada şifreyi çalsa dahi hiçbir şey yapamaz (CWE-613)."

---

## 3. NIST SP 800-207: Sıfır Güven Mimarisi (Zero Trust Architecture)

**Usta:**  
"Amerikan Ulusal Standart ve Teknoloji Enstitüsü'nün (NIST) **SP 800-207** belgesi, sıfır güvenin kutsal kitabıdır. Üç temel aksiyomu vardır:

1. **Ağ Konumu Bir Ayrım Değildir:** Ofiste Ethernet kablosu takmış olmanla, Starbucks'ın açık Wi-Fi ağından bağlanman arasında sıfır güven açısından hiçbir fark yoktur. İkisi de aynı derecede güvensizdir!
2. **Sürekli Dinamik Doğrulama (Continuous Diagnostics & Mitigation):** Oturumu açarken şifreni girmiş olman yeterli değildir. Her işlemde cihazının sağlığı ve güven skoru yeniden hesaplanır.
3. **İhlal Varsayımı (Assume Breach):** Sistemin zaten saldırı altında olduğunu ve ağda bir casusun dolaştığını varsayarak tasarla.

### A. Uç Nokta Sağlığı (Device Posture Assessment)
PDP kapısına bir istek geldiğinde sadece kullanıcıya değil, kullanıcının bilgisayarına bakarız:
- Bu bilgisayar kurumsal MDM tarafından yönetiliyor mu?
- Antivirüs / EDR açık ve güncel mi?
- Sabit disk şifrelenmiş (BitLocker) mi?
- En son güvenlik yaması ne zaman kurulmuş?

Eğer yönetilmeyen bir ev bilgisayarından (BYOD) veya antivirüsü kapatılmış bir laptop'tan istek geliyorsa, şifre doğru olsa dahi kapı yüzüne kapanır (CWE-284)!

### B. Dinamik Güven Skoru (Dynamic Trust Scoring)
Güven ikili (binary - 0 veya 1) bir durum değildir; bir spektrumdur:

$$\text{Güven Skoru} = 0.50 \times \text{Cihaz Sağlığı} + 0.50 \times \text{Kimlik Gücü} - \text{Anomali Cezası}$$

Eğer kullanıcı birdenbire 1 saniyede 100 farklı API sorgusu çekerse, anormal bir tarama yaparsa; güven skoru 100'den 40'a düşer ve oturumu anında sonlandırılır.

### C. Mikro-Segmentasyon (Micro-Segmentation)
Geleneksel ağlarda herkes aynı VLAN'dedir. Bir web sunucusu hacklendiğinde, saldırgan aynı ağdaki veritabanına doğrudan TCP bağlantısı kurabilir.  
Mikro-segmentasyonda her servis kendi izole adacığındadır. Misafir Wi-Fi'ından veya DMZ'den iç bankacılık çekirdeğine (Core Banking) doğrudan paket geçemez; her geçiş PEP kapısına toslar ve durdurulur (CWE-284)."

---

## 4. Ustanın Çırağa Öğüdü

> "Çırağım, eski dünya 'Güven ama denetle' derdi. Modern siber güvenlik ise 'Asla güvenme, sürekli doğrula' der.  
> Bir çalışana kalıcı root şifresi vermek, beline pimini çektiğin bir el bombası bağlamaya benzer; patlaması sadece bir zaman meselesidir. Yetkiyi anlık ver, süresini kısa tut, arkasından da gözünü bir an olsun ayırma. Sıfır Güven bir ürün veya yazılım değil, bir hayatta kalma felsefesidir."
