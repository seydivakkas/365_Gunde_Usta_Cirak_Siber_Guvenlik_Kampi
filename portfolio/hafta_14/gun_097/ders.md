# Gün 097: Mini Proje 13 — Çevrimdışı (Air-Gapped) Güvenlik Araç Seti Mimarisi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu ders notu yalnızca görüntüleme ve kişisel eğitim amacıyla paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya ticari amaçla kullanılamaz.*

---

## 1. Usta Girişi: Hava Boşluklu (Air-Gapped) Dünyaya Adım Atmak

Evlat, siber güvenliğin en üst seviyesi klimalı modern ofislerde internete bağlı çalışmak değildir. Gerçek ustalık; internet bağlantısının yasak olduğu, cep telefonlarının içeri sokulmadığı, nükleer santral SCADA kontrol odalarında, banka HSM (Hardware Security Module) kasalarında veya askeri komuta merkezlerinde başlar. Bu tür izole sistemlere **Hava Boşluklu (Air-Gapped)** ağlar denir.

Böyle bir odaya girdiğinde:
- `pip install` yazamazsın; çünkü internet yoktur.
- `apt-get` veya `yum update` çalışmaz; dış dünyaya kapalıdır.
- GitHub'dan hazır araç indiremezsin.
- Elinde yalnızca işletim sisteminin saf çekirdeği ve Python'un **Standart Kütüphanesi (Standard Library)** vardır!

İşte Mini Proje 13'ün amacı budur: Hafta 14 boyunca adım adım geliştirdiğimiz veri doğrulama, kriptografik bütünlük, kişisel veri maskeleme, performans ölçümü ve belgeleme yeteneklerini; tek bir harici pakete dahi ihtiyaç duymayan, **%100 saf ve bağımsız bir Çevrimdışı Güvenlik Araç Seti (`sec_toolkit`)** halinde sentezlemektir.

---

## 2. Hafta 14 Kazanımlarının Mimari Sentezi

Bu araç seti 5 ana güvenlik motorunu tek bir komut satırı çatısı altında birleştirir:

### 1. Ağ Varlığı ve Veri Doğrulama Motoru (G092)
İzole ağlarda yapılandırma dosyalarındaki hatalı IP veya port tanımları sistemleri kilitler. Motorumuz;
- IPv4 oktetlerini inceler, baştaki sıfırları (**Octal IP - CWE-704**) tespit edip reddeder.
- Port numaralarını `[1, 65535]` kapalı aralığında sınırlar; `bool` tipinin `int` yerine sızmasını engeller (**CWE-843 Type Confusion**).
- MAC ve Hostname alanlarında kabuk ayracı enjeksiyonlarını (**CWE-88**) temizler.

### 2. Kriptografik Bütünlük ve Dosya Bütünlük İzleme (FIM - G093)
Kritik SCADA konfigürasyonlarının veya ikili dosyalarının (firmware) tahrif edilip edilmediğini denetler:
- Dosyaları 64 KB sabit parçalar halinde okuyarak bellek taşmasını önler (**CWE-400**).
- Zayıf algoritmaları (MD5, SHA-1) reddeder (**CWE-328**).
- Karşılaştırmaları `hmac.compare_digest` ile yaparak zamanlama saldırılarına izin vermez (**CWE-208**).
- Dizin taban çizgisi (baseline) oluşturarak `ADDED`, `MODIFIED` ve `REMOVED` dosyaları adli kesinlikle raporlar.

### 3. ReDoS Korumalı Kişisel Veri Maskeleme ve DLP (G094)
İzole sistemlerden dışarı çıkarılacak denetim loglarındaki hassas verileri temizler:
- TCKN için resmi 10. ve 11. hane modüler doğrulamasını uygular.
- Kredi kartları için ISO/IEC 7812 Luhn (Mod-10) algoritmasını çalıştırır.
- Katastrofik geri izleme (**ReDoS - CWE-1333**) şablonlarını ve Null-Byte zehirlemelerini (**CWE-158**) engeller.

### 4. Yüksek Hassasiyetli Profilleme ve SLA Denetimi (G095)
Zaman duyarlı operasyonlarda güvenlik fonksiyonlarının sistem kaynaklarını tüketmesini engeller:
- `time.perf_counter` ile duvar süresini, `tracemalloc` ile tepe bellek tahsisatını ölçer.
- Tanımlı performans eşiği aşıldığında `PerformanceBudgetExceededError` fırlatarak DoS riskini bertaraf eder.

### 5. Air-Gap Doctor ve Çevresel Sağlık Kontrolü
Araç setinin ilk alt komutu olan `doctor`, çalışılan ortamda yetkisiz harici modüllerin (`requests`, `urllib3` vb.) bulunmadığını ve Python sürümünün uyumlu olduğunu teyit eder.

---

## 3. Komut Satırı Tasarımı ve Operasyonel İş Akışı

Aracımız standart POSIX çıkış kodları ve alt komut (subparser) mimarisiyle çalışır:

```bash
# 1. Hava boşluğu sağlık ve bağımsızlık taraması
$ sec_toolkit doctor

# 2. SCADA ağ varlıkları JSON dosyasını doğrula
$ sec_toolkit validate --file assets.json

# 3. Kritik ayar dosyasının SHA-256 özetini al
$ sec_toolkit hash --file system_conf.ini --algo sha256

# 4. İzole dizin için FIM taban çizgisi oluştur
$ sec_toolkit fim --dir /etc/scada/ --action baseline --baseline-file base.json

# 5. Dizin bütünlüğünü tara (Tahrifat varsa çıkış kodu: 1)
$ sec_toolkit fim --dir /etc/scada/ --action scan --baseline-file base.json

# 6. Güvenlik telemetri loglarındaki kişisel verileri maskele
$ sec_toolkit mask --file traffic.log --style MASK
```

---

## 4. Ustanın Çırağa Öğütleri

1. **"Hava Boşluğu Güvenliği" Bir Efsane Değildir Ama Zırh da Değildir:** Stuxnet saldırısını hatırla evlat; dünyanın en sıkı korunan hava boşluklu nükleer tesisine bir USB bellek üzerinden sızıldı. "Bizim sistemimiz internete bağlı değil, güvendeyiz" rehavetine asla kapılma. İçerideki bütünlük kontrollerini internete açık bir sistemden daha sıkı tutacaksın.
2. **Kendi Alet Çantanı Kendin İnşa Et:** İnternet paketlerine bağımlı olan bir analist, internet kesildiğinde silahsız bir asker gibidir. Standart kütüphaneyi avucunun içi gibi bil; 50 satır kodla kendi hashleyicini, kendi regex filtreleyicini ve kendi FIM motorunu yazabilecek yetkinlikte ol.
3. **Hafta 14'ün Özeti:** Tip güvenliğini aldın, hash bütünlüğünü sağladın, hassas veriyi maskeledin, performansı ölçtün, belgeyi linter ile denetledin ve hepsini çevrimdışı bir araç setinde birleştirdin. Artık sadece kod yazan değil; güvenli, standart ve kurumsal sistem inşa eden bir mühendissin.
