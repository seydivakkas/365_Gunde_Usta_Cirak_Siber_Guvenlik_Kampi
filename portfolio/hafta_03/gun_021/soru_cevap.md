# GÜN 021: Soru & Cevap — Mini Proje 2: İşletim Sistemi Envanteri

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*  
*Bu soru-cevap dokümanı Siber Güvenlik 365 Gün Müfredatı kapsamında hazırlanmıştır.*

---

## G021-SC1: Mini proje 2: işletim sistemi envanteri: Temel mekanizmayı ve güvenlik önemini açıkla.

### Temel Mekanizma ve Güvenlik Önemi
İşletim sistemi güvenlik envanteri mekanizması, CIS Control 1-2 ve NIST SP 800-53 CM-8 standartları uyarınca bir bilgi sisteminin donanımsal ve yazılımsal varlıklarının sürekli, eksiksiz ve doğrulanabilir biçimde kataloglanması sürecidir. Bir işletim sisteminin güvenlik duruşunun (security posture) net biçimde anlaşılabilmesi için envanter mekanizması şu 5 kritik boyutu birbirinden bağımsız alanlarda tutmak zorundadır:
1. **İşletim Sistemi ve Sürüm/Çekirdek Bilgisi:** İşletim sisteminin edisyonu, mimarisi ve yapı derleme numarası. Bu bilgi, sistemin destek ömrü (EOL) durumunu ve bilinen yerel yetki yükseltme (LPE) açıklarına karşı kırılganlığını ortaya koyar.
2. **Donanım ve Depolama Mimarisi:** CPU çekirdekleri, RAM miktarı ve özellikle tam disk şifreleme (BitLocker / LUKS) durumu. Durağan verinin (Data at Rest) fiziksel çalınmalara karşı korunup korunmadığını belgeler.
3. **Kullanıcı ve Grup Hesapları:** Sistemde tanımlı tüm hesaplar, bunların SID/UID değerleri, ayrıcalıklı (Local Admin / Sudo) yetkileri, aktiflik durumları ve parola yaşlandırma tarihleri. En Az Ayrıcalık (Least Privilege) ilkesinin uygulanıp uygulanmadığını gösterir.
4. **Çalışan Servisler ve Arka Plan Daemon'ları:** Sistemde koşan servisler, çalışma durumları (Running/Stopped), başlangıç biçimleri ve çalıştırma bağlamları. Sistemin ağa açık saldırı yüzeyini (Attack Surface) doğrudan belirler.
5. **Yama ve Güncelleme Durumu:** Yüklü güncellemeler (KB'ler / paketler), son yama tarihi ve bekleyen kritik güvenlik yaması sayısı. Zafiyet yönetimi ve siber hijyenin temel göstergesidir.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** 5 zorunlu alanı içeren örnek Windows (`os_inventory_windows_sample.json`) ve Linux (`os_inventory_linux_sample.json`) envanter dosyaları.
- **İşlem:** `os_security_inventory_collector.py` aracı çalıştırılarak şema doğrulaması (`validate_schema`) ve canlı sistem tespiti icra edilir.
- **Beklenen Çıktı:** 5 alanın eksiksiz tespit edildiği, şemanın onaylandığı ve canlı makineden CPU, RAM, disk ve kullanıcı bilgilerinin yapılandırılmış JSON çıktısı olarak elde edildiği gözlenir.
- **Negatif Kontrol:** Envanter verisinden `guncellemeler` veya `hesaplar` kategorisi silindiğinde sistemin çökmek yerine `ValueError` fırlatarak eksik kategorileri açıkça raporlaması doğrulanır (`test_07_sema_eksik_kategori_negatif_kontrol`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** Eksik veya güncel olmayan envanter nedeniyle gölge sistemlerin (Shadow IT) oluşması, desteği bitmiş işletim sistemlerinin ağda barınması ve kapatılmamış eski protokollerin açık hedef haline gelmesi.
- **Tespit Sinyali:** Ağ taramalarında (Nmap/Nessus) CMDB'de kaydı bulunmayan bilinmeyen IP/MAC adreslerinin ortaya çıkması; uç noktalarda bekleyen kritik yamaların 30 günü aşması.
- **Savunma Kontrolü:** Merkezi EDR/MDM ajanları aracılığıyla otomatik envanter toplama; CIS Benchmark politikalarına göre onaylanmamış donanım ve yazılımların ağ erişiminin NAC (Network Access Control) ile engellenmesi.

### Etik ve Yasal Sınırlar
Envanter toplama ve telemetri faaliyetleri yalnızca kurumun sahip olduğu veya denetim yetkisi verilmiş varlıklar üzerinde yürütülmelidir. Kullanıcıların kişisel dosyalarının veya özel iletişimlerinin gözetlenmesi kişisel verilerin korunması kanunlarına (KVKK / GDPR) aykırıdır; denetim yalnızca sistem seviyesi yapılandırmalarla sınırlı kalmalıdır.

---

## G021-SC2: Mini proje 2: işletim sistemi envanteri: Bağımsız laboratuvarın girdisi, işlemi, beklenen sonucu ve negatif kontrolü nedir?

### Temel Mekanizma ve Güvenlik Önemi
Bağımsız laboratuvar uygulaması, heterojen kurumsal ortamlarda (Windows ve Linux sunucular) güvenlik parametrelerinin standart bir matris üzerinde karşılaştırılabilirliğini ve doğrulanabilirliğini hedefler. Farklı işletim sistemleri farklı komut ve veri yapılarına sahip olsa da, siber güvenlik denetçisi her iki dünyayı aynı risk terazisinde tartmalıdır.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** 
  1. `os_inventory_windows_sample.json`: Windows Server 2022 datacenter güvenlik envanteri.
  2. `os_inventory_linux_sample.json`: Ubuntu 24.04 LTS sunucu güvenlik envanteri.
  3. `os_inventory_schema.json`: CIS/NIST kurallarını ve CSV sütun haritasını içeren referans şeması.
- **İşlem:**
  `os_security_inventory_collector.py` aracı komut satırından `--windows`, `--linux`, `--schema` ve `--csv` parametreleriyle çağrılarak karşılaştırmalı analiz yürütülür.
- **Beklenen Çıktı:**
  `kanit/gercek/karsilastirmali_os_envanter.csv` dosyası üretilir. CSV içerisinde 5 zorunlu kolon (`kategori`, `ozellik_adi`, `windows_degeri`, `linux_degeri`, `guvenlik_onemi_ve_etkisi`) altında OS sürümü, derleme/çekirdek, donanım, dosya sistemi şifrelemesi (BitLocker vs LUKS), hesap yetkileri, çalışan güvenlik servisleri ve yama durumu yan yana raporlanır.
- **Negatif Kontrol:**
  1. Var olmayan bir envanter dosyası yolu verildiğinde aracın `FileNotFoundError` fırlatması (`test_05`).
  2. Bozuk sözdizimine sahip bir JSON verildiğinde `ValueError` ile güvenli biçimde durması (`test_06`).
  3. Karalistedeki bir servis (Telnet) aktif olduğunda denetleyicinin `KRITIK_IHLAL` tespiti yapması (`test_09`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk:** Windows ve Linux sistemlerin farklı ekiplerce yönetilmesi sonucu ortaya çıkan güvenlik kör noktaları; örneğin Linux'ta LUKS zorunlu tutulurken Windows'ta BitLocker'ın unutulması.
- **Tespit Sinyali:** Üretilen karşılaştırmalı CSV raporunda bir platformda "BitLocker Etkin" görünürken diğerinde disk şifrelemenin "Devre Dışı" olarak raporlanması.
- **Savunma Kontrolü:** Platformlar arası birleşik güvenlik politikası (Unified Security Baseline) tanımlanması; CI/CD ve konfigürasyon yönetim araçları (Ansible, Terraform) ile disk şifreleme ve servis kapatma kurallarının zorlanması.

### Etik ve Yasal Sınırlar
Envanter karşılaştırma çıktıları hassas sunucu IP adresleri, etki alanı adları ve kullanıcı isimleri içerebileceğinden Gizli Bilgi (Confidential) sınıfında saklanmalı; yetkisiz üçüncü şahıslara veya halka açık ortamlara sızdırılmamalıdır.

---

## G021-SC3: 'Mini proje 2: işletim sistemi envanteri' bağlamında risk nasıl oluşur, nasıl tespit edilir ve hangi kontrolle önlenir?

### Temel Mekanizma ve Güvenlik Önemi
İşletim sistemi envanterinde güvenlik riski üç temel aşamada oluşur:
1. **Gereksiz İzinler ve Hesap İhlalleri:** Varsayılan Konuk (Guest) hesaplarının açık bırakılması veya eski çalışanların/servislerin yönetici ayrıcalıklarının korunması (CWE-732).
2. **Yanlış ve Güvensiz Servis Yapılandırmaları:** Şifresiz ve zafiyetli protokollerin (Telnet, FTP, SMBv1, rsh) sistemde aktif olarak çalışması (CWE-319).
3. **Yama Gecikmesi ve Güncelleme İhmali:** Kritik sıfır-gün veya N-gün güvenlik yamalarının 30 günden fazla geciktirilmesi.

### Bağımsız Laboratuvar ve Doğrulama Adımları (Girdi, İşlem, Beklenen Çıktı, Negatif Kontrol)
- **Girdi:** Zafiyetli test senaryosu içeren envanter (çalışan Telnet servisi, aktif Guest hesabı, 3 bekleyen kritik yama).
- **İşlem:** `audit_security_posture()` fonksiyonu çağrılarak kural motoru çalıştırılır.
- **Beklenen Çıktı:** 
  - Telnet servisi için: `KRITIK` risk ve "Servisi derhal durdurun ve devre dışı bırakın" önerisi.
  - Aktif Guest hesabı için: `YUKSEK` risk ve "Konuk hesabını devre dışı bırakın" önerisi.
  - Bekleyen yamalar için: `YUKSEK` risk ve "Sistemi en son güvenlik yamaları ile derhal güncelleyin" önerisi.
- **Negatif Kontrol:** Tüm kuralların sağlandığı temiz bir envanterde hiçbir ihlal üretilmeyip `genel_durum: GUVENLI` sonucunun alınması (`test_08`).

### Risk, Tespit Sinyali ve Savunma Kontrolü
- **Risk Senaryosu:** Bir Linux sunucusunda `telnetd` servisinin açık kalması durumunda, saldırgan ağ üzerindeki ARP zehirleme veya dinleme ile yönetici parolasını açık metin (cleartext) olarak ele geçirebilir. Benzer şekilde güncellenmeyen bir Windows Server üzerinde SMBv1 aktifse EternalBlue (MS17-010) ile uzaktan kod yürütülebilir (RCE).
- **Tespit Sinyalleri:**
  - `netstat -tulpn` veya `Get-NetTCPConnection` çıktısında Port 23 (Telnet) dinleme kaydı.
  - Fark Raporu (Inventory Diff): Önceki hafta ile bu haftanın envanteri karşılaştırıldığında onaylanmamış yeni bir servisin durumunun "Running"e dönmesi.
- **Savunma Kontrolleri:**
  - **En Az Ayrıcalık ve Servis Sertleştirme:** Karalistedeki servislerin işletim sistemi paket seviyesinde kaldırılması (`apt purge telnetd`, Windows Features üzerinden Telnet Client/Server kaldırılması).
  - **Geri Alınabilir Yapılandırma Kodu (IaC / GitOps):** Sistem yapılandırmalarının versiyon kontrolünde (Git) tutulması; onaylanmamış her konfigürasyon değişikliğinin otomatik olarak bilinen güvenli duruma (Known Good State) geri döndürülmesi.

### Etik ve Yasal Sınırlar
Güvenlik açığı tespiti amacıyla yapılan envanter denetimleri yalnızca yetkili sistem yöneticileri veya sözleşmeli siber güvenlik uzmanları tarafından yapılmalıdır. Denetim esnasında tespit edilen açıklar ilgili sistem sahiplerine sorumlu açıklama (Responsible Disclosure) kuralları çerçevesinde derhal raporlanmalıdır.
