# Gün 105: Mini Proje 14 — Kriptografik Hash Bütünlük Manifesti ve Dosya Doğrulama Motoru (FIM)
## Usta-Çırak / Hoca Dersi: Dosya Bütünlüğü İzleme, Kriptografik Mühürleme ve Tedarik Zinciri Güvenliği

---

### 1. Ustanın Giriş Dersi: "Bütünlüğü Kanıtlanmamış Kod ve Veri Güvenilmezdir"

Evlat, siber güvenliğin en temel üç sacayağından biri "Bütünlük" (Integrity) ilkesidir. Gizlilik (Confidentiality) veriyi meraklı gözlerden saklarken, Bütünlük verinin yetkisiz, kazara veya kötü niyetli tek bir baytının dahi değiştirilmediğini matematiksel kesinlikle temin eder.

Geliştiriciler ve sistem yöneticileri genellikle şöyle düşünür:
> *"Sunucuma yalnızca yetkili kullanıcılar erişebilir, diskteki ikili dosyalar (binaries), yapılandırma dosyaları (config) veya web scriptleri kendiliğinden değişmez."*

Bu ölümcül bir yanılgıdır! Gelişmiş kalıcı tehdit (APT) aktörleri, fidye yazılımları, kök kullanıcı kitleri (rootkit) veya tedarik zinciri (supply chain) saldırganları; bir sisteme sızdıklarında ilk iş olarak kritik ikili dosyaları (`/bin/login`, `sshd`, çekirdek modülleri veya üretim kütüphanelerini) arka kapılı türevleriyle değiştirirler.

İşte bu mini projede; Tripwire, AIDE, OSSEC, Linux `dm-verity` ve Git'in temelini oluşturan **Kriptografik Dosya Bütünlüğü İzleme (File Integrity Monitoring - FIM)** mimarisini sıfırdan, endüstri standardı seviyesinde inşa ettik.

```
       [ Üretim / Proje Dosya Ağacı ]
                      │
                      ▼
     ┌─────────────────────────────────┐
     │  Streaming (64 KB Chunk) Hash   │ ──► Bellek Patlamasını (DoS/OOM) Önler
     │  Multi-Hash: SHA-256 + BLAKE2b  │ ──► Kripto-Çeviklik ve Çakışma Direnci
     └─────────────────────────────────┘
                      │
                      ▼
     ┌─────────────────────────────────┐
     │   Path Traversal & Symlink      │ ──► CWE-22 & CWE-59 Savunması
     │   Güvenlik Filtresi (Root Sınır)│
     └─────────────────────────────────┘
                      │
                      ▼
     ┌─────────────────────────────────┐
     │  HMAC-SHA256 Mühürleme Motoru   │ ──► CWE-353 Mühürsüz Manifest Zafiyetini
     │  (Gizli Anahtar ile İmzalanır)  │     ve Dosya Sahteciliğini Önler
     └─────────────────────────────────┘
                      │
                      ▼
            [ manifest.json ] (Kriptografik Bütünlük Belgesi)
```

---

### 2. Derinlemesine Teknik Mimari ve Güvenlik İlkeleri

#### A. Akışlı (Streaming) Hashing ve Bellek Yönetimi (CWE-400 Savunması)
Bir güvenlik aracının diski tararken dosyaları tek seferde belleğe (`f.read()`) yüklemesi en büyük acemiliktir. Sistemde 10 GB'lık bir log veya veri tabanı yedeği bulunduğunda, aracınız `MemoryError` fırlatır veya sistemi Out-Of-Memory (OOM) krizine sokarak çökertir (Denial of Service - CWE-400).

`hash_manifest_engine.py` motorumuzda her dosya sabit **64 KB'lık (65.536 bayt)** tampon bloklarla akışlı olarak okunur:
```python
# Sabit 64 KB bellek tamponu tanımlanır
chunk_size = 65536
with open(file_path, "rb") as f:
    while True:
        # Belleği tüketmeden yalnızca 64 KB okunur
        buffer = f.read(chunk_size)
        if not buffer:
            break
        # Her algoritmanın iç durumuna tampon beslenir
        sha256_hasher.update(buffer)
        blake2b_hasher.update(buffer)
```
Bu sayede motorumuz 50 GB'lık devasa disk kalıplarını dahi 10-15 MB gibi sabit, minimum bellek ayak iziyle saniyeler içinde özetleyebilir.

#### B. Dizin Aşımı ve Sembolik Bağ Kaçış Atakları (CWE-22 & CWE-59)
Bir saldırgan, meşru bir kaynak dizin içine sembolik bağ (symlink) koyarak `/etc/shadow` veya hassas sistem anahtarlarını hedef gösterebilir. Manifest oluşturucu veya doğrulayıcı bu bağı takip ederse:
1. İstem dışı sistem sırlarını manifestoya dökebilir (Bilgi ifşası).
2. Doğrulama aşamasında kök dizinin dışına yazı yazdırabilir veya hedef dosyayı manipüle edebilir.

Motorumuz, `safe_resolve_path()` fonksiyonunda kanonik (`resolve()`) mutlak yolları denetler ve projenin kök sınırını aşan veya sembolik bağ içeren her yola `SymlinkEscapeError` veya `PathTraversalError` fırlatarak operasyonu anında durdurur.

#### C. Mühürsüz Manifest Zafiyeti ve HMAC Kriptografik İmzası (CWE-353)
Birçok ilkel FIM aracı, dosya adlarını ve SHA-256 özetlerini düz metin bir dosyada saklar. Saldırgan sisteme sızdığında dosyayı değiştirir, ardından manifestodaki hash değerini de yeniden hesaplayıp dosyayı günceller! Doğrulama çalıştırıldığında araç "Her şey yolunda" der.

Buna **Mühürsüz Manifest Zafiyeti (CWE-353)** denir. Bunu engellemek için manifestonun tüm gövdesi, yalnızca güvenli anahtar yönetim sisteminde (KMS/Vault) veya çevrimdışı HSM'de saklanan bir **Gizli Mühür Anahtarı (Seal Key)** kullanılarak **HMAC-SHA256** ile mühürlenir. Saldırgan anahtarı bilmeden manifestodaki hash'i güncelleyemez; güncellerse mühür doğrulaması (`hmac.compare_digest` - CWE-208) anında başarısız olur!

---

### 3. Çırağın Uygulama Rehberi: CLI ile Gerçek Zamanlı Denetim

Sistemimizde oluşturulan `manifest_cli.py` aracı hem adli bilişim (digital forensics) hem de CI/CD derleme boru hatlarında doğrudan çalışabilecek modüler yeteneklere sahiptir:

```bash
# 1. Proje ağacının kriptografik manifestosunu HMAC mühürlü olarak üretme
python uygulama/manifest_cli.py --create ornek_veri/sample_project_tree \
    --output test_manifest.json \
    --seal-key "GizliUretimMuhurAnahtari2026!#"

# 2. Manifestonun bütünlüğünü ve dosyaları doğrulama
python uygulama/manifest_cli.py --verify ornek_veri/sample_project_tree \
    --manifest test_manifest.json \
    --seal-key "GizliUretimMuhurAnahtari2026!#"

# 3. Kötü niyetli manipülasyon (Tampering) simülasyonu ve alarm üretimi
python uygulama/manifest_cli.py --tamper-sim ornek_veri/sample_project_tree/config.json
```

---

### 4. Ustanın Altın Öğütleri ve Özeti

1. **Özet Algoritmalarını Asla Tek Başına Bırakma:** MD5 ve SHA-1 kırılmıştır (CWE-328). SHA-256'yı tek başına kullanmak yerine, kütüphanende BLAKE2b gibi modern, son derece hızlı ve güvenli alternatifleri bir arada tutarak kripto-çeviklik (crypto-agility) sağla.
2. **Kritik Doğrulamalarda Zamanlama Zafiyetine İzin Verme:** İki hash veya HMAC mührünü karşılaştırırken asla `==` operatörü kullanma. `hmac.compare_digest()` fonksiyonu ile sabit zamanlı (constant-time) karşılaştırma yap (CWE-208).
3. **Mühürsüz Manifest Manifest Değildir:** Mühürsüz veya imzasız bir manifest belgesi saldırgan tarafından kolayca manipüle edilebilir. Her bütünlük belgesini ya asimetrik imza (RSA/Ed25519) ya da simetrik HMAC ile mühürle!
