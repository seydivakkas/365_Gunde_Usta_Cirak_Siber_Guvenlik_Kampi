# GÜN 093: Hashlib ile Dosya Doğrulama — Usta-Çırak Siber Güvenlik Dersi

> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  
> *Bu eğitim materyali yalnızca görüntüleme ve kişisel öğrenim amaçlıdır. İzinsiz çoğaltılamaz, dağıtılamaz veya ticari projelerde kullanılamaz.*

---

## 1. Ustanın Giriş Dersi: Siber Güvenlikte Bütünlük — "Gözünle Gördüğüne Değil, Matematikle Özetlediğine Güven!"

Evlat, siber güvenliğin kutsal üçlüsü **CIA (Confidentiality, Integrity, Availability)** ilkelerinden ikincisi olan **Bütünlük (Integrity)**, bir verinin oluşturulduğu andan hedefe ulaştığı ana kadar yetkisiz hiçbir el tarafından değiştirilmediğinin matematiksel garantisidir.

Bir sunucuya girdiğinde `sshd` veya `sudo` ikili dosyasının boyutunun aynı kaldığını, değiştirilme tarihinin (timestamp) dün gibi göründüğünü düşünebilirsin. Oysa gelişmiş bir saldırgan (APT - Advanced Persistent Threat), sisteme sızdıktan sonra dosyanın oluşturulma ve değiştirilme tarihlerini sahteler (**Timestomping**). Dosyanın boyutunu da aynı bırakacak şekilde içine zararlı kabuk kodu enjekte edebilir.

İşte tam bu noktada devreye **Kriptografik Tek Yönlü Özetleme (Cryptographic One-Way Hashing)** girer. Bir dosyadaki tek bir bit (0'ın 1 yapılması) değiştiğinde bile, ortaya çıkan özet tamamen öngörülemez bir şekilde altüst olur (**Avalanche Effect / Çığ Etkisi**).

Usta der ki: **"Bir dosyanın adına, uzantısına veya tarihine inanan mühendis aldanır. Güvenlik mühendisi dosyaya değil, onun kriptografik özetine bakar. Özet eşleşiyorsa hakikattir; eşleşmiyorsa ihanettir."**

---

## 2. Şifreleme vs. Özetleme vs. Kodlama: Karıştırılmaması Gereken 3 Kavram

Gençlerin en çok karıştırdığı üç terimi netleştirelim:
1. **Kodlama (Encoding - örn: Base64, Hex):** Veriyi gizlemek için değil, farklı iletişim kanallarından (örneğin 7-bit ASCII ağ protokollerinden) güvenle iletmek için kullanılır. Anahtar yoktur; algoritmayı bilen herkes tek adımda orijinal veriyi çözer.
2. **Şifreleme (Encryption - örn: AES-256, RSA):** Veriyi yetkisiz gözlerden gizlemek içindir (Gizlilik - Confidentiality). İki yönlüdür; şifreyi çözmek için gizli bir anahtar (key) gerekir.
3. **Özetleme (Hashing - örn: SHA-256, BLAKE2b):** Verinin sabit uzunlukta matematiksel parmak izini çıkarır. **Tek yönlüdür (One-way)**; özetten orijinal veriye geri dönülemez ve anahtarsızdır. Amacı gizlilik değil, **bütünlüktür (Integrity)**.

---

## 3. Akış Tabanlı (Chunk-based Streaming) Hash Hesaplama ve DoS Savunması

Acemi bir Python geliştiricisi dosya hash'i alırken şunu yazar:
```python
# YANLIŞ VE TEHLİKELİ (CWE-400 DoS Riski)
with open("buyuk_log_veya_imaj.iso", "rb") as f:
    veri = f.read()  # TÜM DOSYA RAM'E YÜKLENİR!
    ozet = hashlib.sha256(veri).hexdigest()
```
Eğer taranan dosya 16 GB boyutunda bir bellek dökümü (RAM dump) veya adli imaj ise; sunucunun 8 GB'lık RAM'i anında tükenir, Out-of-Memory (OOM) mekanizması Python sürecini öldürür ve sistem çökerek hizmet reddi (**Denial of Service - CWE-400**) yaşanır.

### Doğru ve Güvenli Yaklaşım (Sabit O(1) Bellek):
```python
# DOĞRU VE KURUMSAL (Sabit 64 KB Tampon Bellek)
hasher = hashlib.sha256()
with open("buyuk_log_veya_imaj.iso", "rb") as f:
    while True:
        tampon = f.read(65536)  # 64 KB'lık bloklar
        if not tampon:
            break
        hasher.update(tampon)
ozet = hasher.hexdigest()
```
Bu sayede dosya ister 10 kilobayt ister 500 terabayt olsun; Python sabit 64 KB bellek kullanarak işlemi güvenle tamamlar.

---

## 4. Zayıf Özet Algoritmaları (CWE-328) ve Çarpışma Saldırıları (Collision Attacks)

Neden artık **MD5** ve **SHA-1** kullanmıyoruz?
- **Çarpışma (Collision):** İki farklı girdinin ($M_1 \ne M_2$) aynı hash değerini üretmesidir ($H(M_1) = H(M_2)$).
- **MD5 Felaketi:** 2004 yılında Wang ve ekibi MD5'in çarpışma direncini kırdı. 2012 yılında Flame casus yazılımı, sahte bir Microsoft sertifikasını meşru gibi göstermek için MD5 çarpışma saldırısını kullandı.
- **SHA-1'in Sonu:** 2017 yılında CWI Amsterdam ve Google, iki farklı PDF dosyasının aynı SHA-1 özetini ürettiği **SHAttered** saldırısını gerçekleştirdi.

Bu nedenle kurumsal ve adli bilişim standartlarında MD5 ve SHA-1 kesinlikle yasaktır (**CWE-328**). Kullanılması gereken minimum standart:
- **SHA-256 / SHA-512 (SHA-2 Ailesi)**
- **SHA3-256 / SHA3-512 (Keccak Tabanlı SHA-3 Ailesi)**
- **BLAKE2b / BLAKE2s (Modern, son derece hızlı ve güvenli)**

---

## 5. Yan Kanal ve Zamanlama Saldırıları (Timing Attacks - CWE-208)

Birçok yazılımcı hash doğrulaması yaparken ölümcül bir hata yapar:
```python
# YANLIŞ VE ZAMANLAMA SALDIRISINA AÇIK (CWE-208)
if hesaplanan_hash == beklenen_hash:
    print("Doğrulandı")
```
Python'daki standart `==` işleci iki string'i karakter karakter soldan sağa karşılaştırır. Eşleşmeyen ilk karakterde döngüyü kırar (**Short-circuit evaluation**). 
- Eğer ilk karakter yanlışsa işlem 2 nanosaniyede biter.
- Eğer ilk 15 karakter doğru, 16. karakter yanlışsa işlem 30 nanosaniye sürer.

Uzaktan hassas bir ağ analizörü ile zaman farklarını ölçen bir saldırgan, mikrosaniyelik gecikmelere bakarak karakterleri tek tek tahmin edebilir (**Timing Attack**).

### Kurşun Geçirmez Çözüm: Sabit Zamanlı Karşılaştırma
```python
import hmac

# DOĞRU: Her durumda tüm dizeyi sabit sürede karşılaştırır
if hmac.compare_digest(hesaplanan_hash, beklenen_hash):
    print("Doğrulandı")
```
`hmac.compare_digest`, dize ne kadar eşleşirse eşleşsin her zaman sabit sürede çalışarak zamanlama bilgilerinin sızmasını tamamen engeller.

---

## 6. Dosya Bütünlüğü İzleme (File Integrity Monitoring - FIM) Mimarisi

FIM sistemleri (Tripwire, OSSEC, Wazuh) şu döngüyle çalışır:
1. **Altın İmaj / Taban Çizgisi (Baseline):** Sistem temizken tüm kritik sistem dosyalarının (`/bin`, `/etc`, `C:\Windows\System32`) SHA-256 özetleri çıkarılır ve mühürlü bir veritabanına kaydedilir.
2. **Periyodik Denetim:** Sistem düzenli aralıklarla tekrar taranır.
3. **Anomali Ayrıştırması:**
   - **Değiştirilen Dosyalar:** Hash'i değişmiş dosyalar (Olası Rootkit veya yetkisiz müdahale).
   - **Yeni Eklenen Dosyalar:** Web dizinine eklenen beklenmeyen `.php` dosyaları (Webshell).
   - **Silinen Dosyalar:** Güvenlik loglarının veya antivirüs ikililerinin silinmesi.

---

## 7. Çırağa Öğütler ve Altın Kurallar

1. **Katı Modu (Strict Mode) Asla Kapatma:** Eski sistemlerle uyumluluk bahanesiyle güvenlik aracında MD5 kullanımını varsayılan yapma. Katı modda MD5 istendiğinde doğrudan `WeakHashAlgorithmError` fırlat.
2. **Hash Doğrularken `compare_digest` Kullan:** Parola özetleri, API anahtarları veya kriptografik hashler karşılaştırılırken asla `==` kullanma; daima `hmac.compare_digest` kullan.
3. **Akış Tamponunu Doğru Boyutlandır:** Ne 1 baytlık mini tamponlarla CPU'yu yor, ne de tüm dosyayı belleğe yükle. 64 KB ($65536$ bayt) endüstri standardı altın orandır.
