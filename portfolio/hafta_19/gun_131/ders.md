# GÜN 131: WINDOWS FIREWALL PROFİLLERİ VE SERTLEŞTİRME DERSİ
**Eğitmen:** Usta Siber Güvenlik Mimarı  
**Öğrenci:** Çırak Güvenlik Mühendisi  
**Tarih:** 2 Kasım 2026  
**Konu:** Windows Filtering Platform (WFP), Güvenlik Duvarı Ağ Profilleri (Domain, Private, Public), Varsayılan Bloklama ve Gelişmiş Kütükleme  

---

## 1. GİRİŞ VE USTADAN ÇIRAĞA TAVSİYELER

**Usta:** Evlat, düne kadar dosya sistemini, izinleri ve yerel hesapları kurşun geçirmez hale getirdik. Ancak bir bilgisayar ağ kablosunu taktığı veya Wi-Fi'ye bağlandığı andan itibaren tüm dünyayla konuşmaya başlar. İşte işletim sisteminin ağ seviyesindeki en temel sınır muhafızı **Windows Defender Gelişmiş Güvenlikli Güvenlik Duvarı (Windows Defender Firewall with Advanced Security - WFAS)** bileşenidir.

Pek çok kullanıcı veya acemi BT personeli güvenlik duvarını "bir oyun veya program çalışmadığında hemen kapatılan" önemsiz bir ayar gibi görür (`netsh advfirewall set allprofiles state off`). Oysa kurumsal bir ağda güvenlik duvarının kapatılması, saldırgana davetiye çıkarmakla kalmaz; yanal hareket (Lateral Movement) ve fidye yazılımlarının (WannaCry, NotPetya gibi SMB solucanlarının) dakikalar içinde tüm şirketi rehin almasına sebep olur.

**Çırak:** Hocam, Windows'ta neden tek bir güvenlik duvarı ayarı yok da üç farklı profil (Domain, Private, Public) var?

**Usta:** Çok yerinde bir soru evlat! Bir dizüstü bilgisayarı düşün: Sabah şirkette etki alanına (Active Directory) bağlıyken çalışır; öğlen bir kafede açık Wi-Fi'ye bağlanır; akşam ise evindeki modem üzerinden internete çıkar. Her bir ortamın tehdit seviyesi taban tabana zıttır!
- **Domain Profili:** Şirket ağındadır, makineler birbirini tanır ve dosya/yazıcı paylaşımı kontrollü olarak açılabilir.
- **Private Profili:** Ev veya güvenilir yerel ağdır.
- **Public Profili:** Havaalanı, kafe veya doğrudan internettir. Oradaki herkes potansiyel bir saldırgandır! Bu profilde RDP (3389), SMB (445) veya WinRM gibi yönetim portlarının açık kalması demek, kapıyı hırsıza ardına kadar açmak demektir.

Bugün Windows Filtering Platform (WFP) çekirdeğine inecek, üç profilin CIS standartlarına göre nasıl sıkılaştırılacağını ve düşürülen paketlerin nasıl kütükleneceğini öğreneceğiz.

---

## 2. WINDOWS GÜVENLİK DUVARI MİMARİSİ VE ÇEKİRDEK FİLTRE MOTORU

```
+---------------------------------------------------------------------------------------+
|                    WINDOWS FILTERING PLATFORM (WFP) ÇEKİRDEK MİMARİSİ                 |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|  [GELEN AĞ PAKETİ (INBOUND)]                                                         |
|           │                                                                           |
|           ▼                                                                           |
|  [Network Location Awareness (NLA) Servisi] ──► [Profil Tespiti: Domain/Private/Public]|
|           │                                                                           |
|           ▼                                                                           |
|  [Base Filtering Engine (BFE) & WFP Kernel Sürücüsü]                                  |
|           │                                                                           |
|           ├───► 1. Açık Engelleme Kuralları (Explicit Block Rules)                    |
|           ├───► 2. Açık İzin Verme Kuralları (Explicit Allow Rules)                  |
|           └───► 3. Varsayılan Profil İlkesi (Default Action: BLOCK INBOUND)           |
|                                                                                       |
|  [SONUÇ]                                                                              |
|    ├── Eşleşen Paket Geçer                                                           |
|    └── Eşleşmeyen / Bloklanan Paket Düşürülür ──► [pfirewall.log (Kütükleme)]         |
|                                                                                       |
+---------------------------------------------------------------------------------------+
```

### 2.1 Ağ Konumu Farkındalığı (Network Location Awareness - NLA)
Windows, bir ağ bağdaştırıcısına IP adresi atandığı anda arka planda NLA servisi ile ağın türünü doğrular:
- Eğer makine etki alanı denetleyicisine (Domain Controller) LDAP/Kerberos ile erişebiliyorsa ve etki alanı kimliğini doğrulayabiliyorsa **Domain Profili** devreye girer.
- Kullanıcı ağı "Ev / Özel" olarak işaretlemişse **Private Profili** atanır.
- Tanınmayan veya yeni bağlanılan tüm ağlara varsayılan olarak en kısıtlayıcı olan **Public Profili** atanır.

### 2.2 Varsayılan Eylem Stratejisi (Default Block vs Default Allow)
Güvenlik mimarisinin en temel kuralı: **"Açıkça izin verilmeyen her şey varsayılan olarak yasaktır (Default Deny / Zero Trust)."**
- **DefaultInboundAction = Block:** Kural listesinde açıkça tanımlanmış bir "Allow" kuralı bulunmayan tüm gelen bağlantı talepleri sessizce düşürülür.
- **DefaultOutboundAction = Allow:** İstemci makinelerde internete ve sunuculara giden bağlantılar varsayılan olarak açıktır (Yüksek güvenlikli SCADA/Sunucu ortamlarında bu da `Block` yapılabilir).

---

## 3. CIS WINDOWS BENCHMARK GÜVENLİK DUVARI STANDARTLARI (BÖLÜM 9)

CIS kılavuzuna göre kurumsal bir uç noktada şu kurallar tavizsiz uygulanmalıdır:

| Denetim Maddesi | CIS Kuralı | Teknik Gerekçe & Güvenlik Riski |
|---|---|---|
| **Domain Profil Durumu** | `Enabled: True` | Etki alanında güvenlik duvarını kapatmak, yanal hareket (Pass-the-Hash) saldırılarına kapı aralar (`CWE-693`). |
| **Private Profil Durumu** | `Enabled: True` | Yerel ağdaki diğer ele geçirilmiş cihazlardan gelebilecek sızmaları önler (`CWE-693`). |
| **Public Profil Durumu** | `Enabled: True` | Dış dünyadan doğrudan gelen port tarama ve sömürü girişimlerini keser (`CWE-693`). |
| **Varsayılan Gelen Eylem** | `DefaultInboundAction: Block` | İstisna haricindeki tüm portları kapatır (`CWE-284`). |
| **Public Gelen İstisnalar** | `AllowInboundRules: False` | Genel ağda yerel servislerin dinleme yapmasını tamamen yasaklar. |
| **Yerel Kural Birleştirme** | `AllowLocalFirewallRules: False` | Yerel yöneticilerin veya zararlı yazılımların yerel kural ekleyerek merkezi politikayı delmesini engeller. |
| **Engellenen Paket Kütüğü**| `LogBlocked: True` | Düşürülen paketlerin kütüklenmesi, SIEM ve SOC ekiplerinin port taramalarını yakalamasını sağlar (`CWE-778`). |
| **Kütük Dosya Boyutu** | `LogMaxSizeKilobytes >= 16384` | Kütüklerin erken üzerine yazılmasını (log rollover) engeller. |

---

## 4. KAMUSAL AĞDA (PUBLIC PROFILE) EN TEHLİKELİ PORTLAR VE SALDIRI SENARYOLARI

### 4.1 Uzak Masaüstü Protokolü (RDP - Port 3389)
- **Risk:** Saldırganların kaba kuvvet (brute-force) ve BlueKeep (CVE-2019-0708) zafiyetleriyle hedef aldığı bir numaralı porttur.
- **Kural:** RDP kuralı asla Public profile uygulanmamalıdır. Yalnızca şirket VPN'i veya Domain profili ile sınırlandırılmalıdır.

### 4.2 Sunucu Mesaj Bloğu (SMB - Port 445 / 139)
- **Risk:** WannaCry, EternalBlue (MS17-010) ve Pass-the-Hash saldırılarının birincil taşıyıcısıdır.
- **Kural:** Public profilde SMB açık bırakılırsa, makine kafedeki Wi-Fi ağından birkaç saniye içinde solucan (worm) tarafından enfekte edilebilir.

### 4.3 Windows Uzaktan Yönetim (WinRM - Port 5985 HTTP / 5986 HTTPS)
- **Risk:** PowerShell remoting arayüzüdür. Genel ağda açık olması, kimlik bilgisi püskürtme (password spraying) saldırılarına zemin hazırlar.

---

## 5. POWERSHELL VE NETSH İLE OTOMATİK SERTLEŞTİRME REÇETESİ

```powershell
# ====================================================================
# WINDOWS DEFENDER GÜVENLİK DUVARI CIS SIKILAŞTIRMA BETİĞİ
# ====================================================================

# 1. Tüm Profilleri (Domain, Private, Public) Etkinleştir
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# 2. Varsayılan Gelen Trafiği Blokla, Giden Trafiğe İzin Ver
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow

# 3. Kütükleme (Logging) Ayarlarını Yapılandır (CIS: >= 16 MB)
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogBlocked True `
    -LogMaxSizeKilobytes 16384 `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

# 4. Public Profilde Gelen İstisnaları Kapat (En Üst Savunma)
Set-NetFirewallProfile -Profile Public -AllowInboundRules False

# 5. Tehlikeli Portların (RDP, SMB, WinRM) Public Profil İstisnalarını Kaldır
Get-NetFirewallRule -Direction Inbound | Where-Object {
    $_.Profile -match "Public" -and ($_.LocalPort -in @("3389", "445", "139", "5985", "5986"))
} | Set-NetFirewallRule -Profile Domain,Private

Write-Host "[+] Windows Güvenlik Duvarı CIS Standartlarına Göre Sıkılaştırıldı." -ForegroundColor Green
```

---

## 6. ÖZET VE KAZANIMLAR

Bugün:
- Windows Filtering Platform (WFP) ve NLA servisinin çalışma mantığını kavradık.
- Domain, Private ve Public profillerinin güvenlik hedeflerini ve ayrımını öğrendik.
- "Default Block Inbound" ilkesinin ağ savunmasındaki vazgeçilmez yerini gördük.
- Açık portların oluşturduğu sızma risklerini ve PowerShell ile otomatik sıkılaştırma yöntemlerini uyguladık.
