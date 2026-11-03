<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 071: Python Çalışma Ortamı, Sanal Ortam (venv) ve Bağımlılık Güvenliği

## Ustanın Girişi: Yeni Aşama, Yeni Disiplin

Çırak, hoş geldin. Bugün **Aşama 04: Siber Güvenlik için Python Geliştirme ve Otomasyon** kapısını açıyoruz. 

Ağ analizinde paketlerin mantığını, baytların diliyle konuşmayı öğrendin. Ancak bir siber güvenlik mühendisi sadece başkalarının yazdığı araçları çalıştıran bir teknisyen olarak kalamaz. Kendi ofansif keşif scriptlerini, savunma otomasyonlarını, SIEM korelasyon filtrelerini ve adli ayrıştırıcılarını bizzat kendisi kodlamak zorundadır. Ve bu dünyada sektörün fiili standardı **Python**'dur.

Fakat dur! Kod yazmaya başlamadan önce, ilk ve en ölümcül hatayı yapan acemilerin düştüğü çukuru kapatacağız: **Çalışma Ortamı ve Bağımlılık Tedarik Zinciri Güvenliği**.

Birçok kişi Python ile geliştirme yaparken terminali açıp `pip install ...` diyerek işletim sisteminin global Python ortamına paket yağdırır. Bu, kurumsal bir ortamda yapılabilecek en büyük güvenlik zafiyetidir. Neden mi? Çünkü indirdiğin o paket sistem haklarıyla çalışır, global kütüphaneleri bozar ve daha da kötüsü, kötü niyetli bir bağımlılık tüm makineni ele geçirebilir.

Bugün sanal ortamların (`venv`) anatomisini, hermetik (sızdırmaz) yalıtımı, sürüm sabitleme (version pinning) disiplinini ve kriptografik SHA-256 hash kontrollerini öğreneceksin.

---

## 1. Sanal Ortamın (venv) Güvenlik Anatomisi

Python'da `venv` (Virtual Environment), izole bir çalışma alanı oluşturur. Bu alan, işletim sisteminin ana kütüphanelerinden tamamen bağımsız, kendi `site-packages` dizinine sahip bir kum havuzudur (sandbox).

Bir sanal ortam oluşturulduğunda (`python -m venv .venv`), dizin kökünde `pyvenv.cfg` adlı bir yapılandırma dosyası doğar:

```ini
home = C:\Python312
include-system-site-packages = false
version = 3.12.2
executable = C:\Python312\python.exe
command = C:\Python312\python.exe -m venv .venv
```

### Buradaki En Kritik Güvenlik Satırı:
`include-system-site-packages = false`

Eğer bu değer `true` yapılırsa:
1. Global sistemde kurulu eski, zafiyetli veya değiştirilmiş paketler bu sanal ortama sızar.
2. İzole edilmiş olması gereken adli script veya güvenlik otomasyonu, sistem seviyesindeki zehirlenmiş bir DLL veya kütüphaneyi içe aktarabilir.
3. Paket sürümleri deterministik olmaktan çıkar; "benim makinemde çalışıyordu, sunucuda çöktü" kabusu başlar.

---

## 2. Yazılım Tedarik Zinciri Saldırıları (Software Supply Chain Attacks)

Modern yazılım geliştirmenin en zayıf karnı dış bağımlılıklardır (third-party dependencies). Saldırganlar doğrudan senin sistemini hedef almak yerine, kullandığın kütüphanelerin ekosistemine saldırırlar:

### A. Typosquatting (Yazım Hatası İstismarı)
Saldırgan, PyPI (Python Package Index) gibi genel depolara çok popüler kütüphanelerin isimlerine 1-2 harf benzeyen zararlı paketler yükler:
- Meşru: `requests` ──► Zararlı Taklit: `reqeusts`, `request-python`
- Meşru: `scapy` ──► Zararlı Taklit: `scapppy`, `scapy-lib`
- Meşru: `cryptography` ──► Zararlı Taklit: `cryptograpy`, `python-crypto`

Geliştirici dalgınlıkla `pip install reqeusts` yazdığı anda, zararlı paketin `setup.py` dosyası çalışır. Bu dosya bir tersine kabuk (reverse shell) açabilir, SSH anahtarlarını çalabilir veya ortam değişkenlerindeki API belirteçlerini sızdırabilir.

### B. Dependency Confusion & Namespace Hijacking
Kurum içi özel paketlerle aynı isimde PyPI'ya daha yüksek sürüm numaralı sahte paket yüklenerek, pip'in genel depodan zararlı kodu çekmesi sağlanır.

---

## 3. Sürüm Sabitleme ve Kriptografik Bütünlük (Pip Hashes)

Tedarik zinciri saldırılarına karşı savunmanın altın standardı: **Deterministik ve Kriptografik Olarak Mühürlenmiş Bağımlılık Dosyasıdır**.

### Asla Yapılmaması Gereken (Gevşek Sabitleme):
```text
requests
scapy>=2.0.0
cryptography~=40.0
```
Bu sözdiziminde, `pip install` her çalıştığında internetten en yeni sürümü çeker. Eğer saldırgan o kütüphanenin geliştirici hesabını ele geçirip v2.0.1 olarak zararlı bir güncelleme yayınladıysa, sunucun doğrudan zehirlenir!

### Kurumsal Standart (Kesin Sabitleme ve SHA-256 Mührü):
```text
requests==2.31.0 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f
scapy==2.5.0 \
    --hash=sha256:9f64bf77699709289ee76742111d4e08c6c5bf7695ff53018e268a0c21625902
```

`pip install --require-hashes -r requirements.txt` komutu çalıştırıldığında:
1. Pip paketi indirir.
2. İndirilen dosyanın SHA-256 özetini hesaplar.
3. Dosyadaki `--hash` değeriyle karşılaştırır.
4. Tek bir bit bile uyuşmazsa kurulum derhal iptal edilir. Bu sayede Ortadaki Adam (MitM) saldırıları veya PyPI sunucularındaki paket manipülasyonları tamamen engellenir.

---

## Ustanın Çırağa Öğüdü

Evlat, siber güvenlikte "hızlıca bir script yazıp çalıştırayım" rehaveti yoktur. Geliştirdiğin aracın kendisi güvenli değilse, onunla güvenliği sağlayamazsın. Kendi alet çantasını koruyamayan usta, başkasının evini hırsızdan koruyamaz. 

Yazdığın her araç için taze bir `venv` açacaksın, sürümleri `==` ile çivileyeceksin ve her paketi SHA-256 ile mühürleyeceksin. Bu disiplin seni sıradan bir script yazıcısından, kurumsal bir siber güvenlik mühendisine dönüştürecektir.
