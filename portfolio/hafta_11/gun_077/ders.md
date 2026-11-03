# GÜN 077: MİNİ PROJE 10 — BAĞIMSIZ GÜVENLİK LOG AYRIŞTIRICI (STANDALONE SECURITY LOG PARSER)
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞ DERSİ: HAFTA 11'İN ŞAHESERİ — BAĞIMSIZ VE SAVUNMACI LOG MOTORU

Evlat, 11. haftayı geride bırakırken Python programlama dilini sıradan bir betik aracı olarak değil, endüstri standardı bir siber savunma kalkanı olarak nasıl inşa edeceğini öğrendin:
- **Gün 071'de:** İzole sanal ortamları (`venv`), bağımlılık sabitlemeyi ve tedarik zinciri güvenliğini kurduk.
- **Gün 072'de:** Tip güvenliğini, katı girdi doğrulamasını ve Unicode NFKC canonicalization'ı işledik.
- **Gün 073'te:** Koşullar, fail-closed kural motorları ve savunmacı döngü sınırlarını (CWE-835) yazdık.
- **Gün 074'te:** Saf fonksiyonları (Pure Functions), değişmezliği (Immutability) ve sözleşmeye dayalı tasarımı (DbC) hayata geçirdik.
- **Gün 075'te:** $O(1)$ karma tablolarını, küme cebrini ve bellek tavanı korumasını kodladık.
- **Gün 076'da:** ReDoS (CWE-1333) savunmasını, IDN homograf analizini ve Trojan Source Bidi filtrelerini entegre ettik.

İşte bu hafta sonu projemiz olan **Mini Proje 10**, tüm bu savunma katmanlarını tek bir mimaride birleştiren, heterojen kurumsal ağ ve sunucu loglarını (Apache/Nginx, Linux SSHD, Linux Kernel iptables) milisaniyeler içinde inceleyen, saldırganları kilitleyen ve sıfır yanlış pozitif (False Positive) ile adli rapor üreten bağımsız bir güvenlik motorudur.

---

## 2. HETEROJEN LOG AKIŞLARI VE BİÇİM ÇEŞİTLİLİĞİ

Gerçek dünyada bir SOC analisti veya SIEM mühendisi tertemiz, tek tip verilerle karşılaşmaz. Aynı log akışında hem web istekleri, hem SSH oturum denemeleri, hem de güvenlik duvarı engellemeleri akar:

1. **Web Sunucu Logu (Combined Access Log):**
   `192.168.1.50 - - [31/Oct/2026:10:00:01 +0300] "GET /index.html HTTP/1.1" 200 1420 "https://kurum.local" "Mozilla/5.0"`
   - Saldırı vektörü: SQL Injection (`UNION SELECT`), Path Traversal (`../../`), XSS, Web Scanner (`sqlmap`, `nikto`).
2. **Kimlik Doğrulama Logu (Linux Syslog / SSHD):**
   `Oct 31 10:00:10 srv-auth01 sshd[14201]: Failed password for invalid user admin from 198.51.100.99 port 52341 ssh2`
   - Saldırı vektörü: Parola kaba kuvvet (Brute-Force), sözlük saldırısı (Dictionary Attack), yetkisiz root erişimi.
3. **Güvenlik Duvarı Çekirdek Logu (Netfilter / iptables):**
   `OCT 31 10:00:25 fw-edge kernel: [FW_BLOCK] SRC=203.0.113.5 DST=192.168.1.10 PROTO=TCP SPT=49152 DPT=4444 ACTION=DROP`
   - Saldırı vektörü: Port tarama (Port Scan), C2 komuta kontrol iletişimi, izinsiz port trafiği.

---

## 3. SAVUNMACI ÖN İŞLEME VE ENJEKSİYON ARINDIRMA HATTI

Bir güvenlik yazılımı gelen log satırına körü körüne regex uygulamamalıdır. Öncesinde katı bir temizlik hattı zorunludur:

### 1. Boyut Sınırı (ReDoS Kalkanı):
```python
if len(raw_line) > 4096:
    raise ValueError("ReDoS ve bellek aşımı koruması: Satır uzunluğu 4096 karakteri aştı!")
```
Saldırgan 100.000 karakterlik bir string göndererek NFA motorunu kilitleyemez; satır sınırda düşürülür.

### 2. Null-Byte (`\x00`) ve Trojan Source Bidi (`\u202E`) Filtresi:
Dosya yolu kesme (string truncation) ve sağdan sola ters çevirme hileleri regex'e girmeden önce ayıklanır.

### 3. URL Decoding (Kanonikleştirme) Olmadan İmza Taraması Yapılamaz:
Bir web saldırganı `UNION SELECT` yerine `UNION%20SELECT` gönderir. Eğer regex motorun ham URL üzerinde arama yaparsa saldırıyı kaçırır. Savunmacı motor:
```python
decoded_uri = urllib.parse.unquote_plus(raw_uri)
if sig.search(raw_uri) or sig.search(decoded_uri):
    # Saldırı yakalandı!
```
diyerek URL kodlaması arkasına saklanan tüm atlatmaları (bypass) felç eder.

---

## 4. KÜME CEBRİ VE SIFIR YANLIŞ POZİTİF (FALSE POSITIVE) BEYAZ LİSTESİ

Mini Proje 10'da uyguladığımız en kritik matematiksel savunma:
$$T_{raporlanan} = (\text{Gelen IP'ler} \cap \text{Zararlı IoC Kümesi}) \setminus \text{Kurumsal Beyaz Liste}$$

Örnek veri setimizde Google DNS adresi olan `8.8.8.8`, bilinen tehdit istihbaratı karalistesinde yer almaktadır. Ancak kurumumuz bu adresi meşru DNS çözümleyicisi olarak beyaz listeye almıştır.
Ayrıştırıcı motor, küme farkı (`difference`) sayesinde `8.8.8.8` için **tek bir hatalı alarm dahi üretmemiştir**. Bu sayede SOC analistinin ekranı gürültüden arındırılmış, gerçek saldırganlar öne çıkarılmıştır.

---

## 5. KAYAN PENCERE (SLIDING WINDOW) BRUTE-FORCE KİLİT MOTORU

Saldırganlar parola denemelerini tek bir saniyeye yığmak yerine dakikalara yayarak geleneksel statik sayaçları atlatmaya çalışırlar.
Motorumuz her IP için bir zaman damgası listesi tutar:
1. Başarısız girişim anında geçerli zaman (`time.time()`) listeye eklenir.
2. 60 saniyeden (`brute_force_window_seconds`) eski tüm zaman damgaları listeden temizlenir:
   `[t for t in attempts if t >= now - 60]`
3. Kalan liste boyutu $\ge 5$ olduğunda IP adresi `locked_out_ips` kümesine alınır ve `BRUTE_FORCE_LOCKOUT` alarmı tetiklenir.

---

## 6. USTANIN ÇIRAĞA ÖĞÜTLERİ VE HAFTA 11 SENTEZİ

> "Evlat, bu mini proje ile çıraklıktan kalfalığa giden yolda çok büyük bir eşiği aştın. Yazdığın kod sadece bir metin ayrıştırmıyor; çok katmanlı savunma (Defense-in-Depth) felsefesini satır satır hayata geçiriyor.
> Unutma:
> 1. Güvenlik kodu asla çökmeyecek (Fail-Safe / Resilient).
> 2. Girdiyi asla olduğu gibi kabul etmeyecek (Validate & Sanitize).
> 3. Hızı matematiksel olarak garanti edecek ($O(1)$ Hash / Set).
> 4. Yanlış alarm üretmeyecek (Whitelist Suppression).
> Bu dört prensibi aklına mıhla. 12. haftada Python ile nesne yönelimli güvenlik mimarilerini ve ağ soket programlamasını inşa etmeye başlayacağız!"
