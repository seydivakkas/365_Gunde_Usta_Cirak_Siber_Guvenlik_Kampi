# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 084: Mini Proje 11: Test Edilen Güvenlik Log Aracı (Capstone)

## Usta-Çırak Açılış Hasbihali

Evladım, çırağım;
Bugün 12. haftamızın taçlandırma günü, yani Capstone (Mini Proje) durağımızdır. 
Geriye dönüp baktığında bu hafta neleri ilmek ilmek dokuduğumuzu gör:
- **Gün 078'de** `pathlib` ile güvenli dosya yolunu, `resolve()` ve `relative_to()` sınırlarını, sembolik bağ (symlink) tuzaklarını öğrendin.
- **Gün 079'da** CSV formül enjeksiyonu (CWE-1236) ve derin JSON DoS bombalarını nötralize etmeyi kavradın.
- **Gün 080'de** fail-closed mimariyi, hata sızıntısını (CWE-209) ve benzersiz olay tokenlarını koduna mühürledin.
- **Gün 081'de** Log Injection (CWE-117) saldırılarını, CRLF karakterlerini ve regex ile hassas veri maskelemeyi (CWE-532) inşa ettin.
- **Gün 082'de** `pytest` ile profesyonel birim testlerini, fikstürleri ve parametrik sınır analizlerini uyguladın.
- **Gün 083'te** Git commit ve Unified Diff analiziyle Trojan Source (CVE-2021-42574) ve Shannon bilgi entropisini çözdün.

İşte bugün Mini Proje 11'de tüm bu bağımsız becerileri tek bir potada eritiyoruz: **Test Edilen Endüstriyel Düzeyde Güvenlik Log Aracı (`TestedSecurityLogTool`)**. Bir güvenlik operasyon merkezinde (SOC) ya da bulut tabanlı bir SIEM altyapısında gerçek zamanlı logları güvenle içeri alabilen, saldıranı anında tespit eden ve kendisi asla zafiyet barındırmayan bir motor kuruyoruz.

---

## 1. Bir Güvenlik Log Aracının Mimarisi ve Karşılaştığı Tuzaklar

Bir SIEM veya log analiz aracının kendisi birincil hedef haline gelebilir. Neden? Çünkü saldırganın ürettiği ham veriyi doğrudan okur ve işler. Eğer araç zayıf yazılmışsa, saldırgan aracı hackleyerek tüm sunucuya sıçrayabilir.

Bu sebeple log işleme boru hattı 5 savunma hattından oluşmalıdır:

### 1.1. Dosya Yolu Sınırlandırması (Boundary Confinement)
Araca analiz etmesi için bir log dosyası verildiğinde, saldırgan dosya adı yerine `../../../../windows/system32/config/SAM` veya `/etc/shadow` yazabilir (Path Traversal - CWE-22). Ya da `safe_dir` içine gizlice işletim sistemi dosyasına işaret eden bir `symlink` koyabilir (CWE-59).
- Çözüm: Dosya yolu önce `is_symlink()` ile kontrol edilir. Ardından `resolve()` edilerek `relative_to(allowed_base_dir)` ile sınır kontrolünden geçirilir. Sınır dışına taşan her istek derhal reddedilir.

### 1.2. Log Enjeksiyonu ve CRLF Nötralizasyonu (CWE-117)
Saldırgan kullanıcı adı veya mesaj kısmına `\r\n[CRITICAL] ADMIN AUTHORIZED` yazarak SIEM'i aldatabilir veya adli analiz yapan mühendisi yanıltabilir.
- Çözüm: Log satırı işlenmeden önce tüm CRLF karakterleri ayıklanır veya tek bir boşluğa indirgenir. Kati modda (`strict=True`) ise işlem anında kesilip `LogInjectionAttemptException` üretilir.

### 1.3. Hassas Veri Maskeleme (CWE-532 & CWE-359)
Geliştiricilerin loglara düşürdüğü parolalar, AWS gizli anahtarları, JWT belirteçleri ve kredi kartı numaraları log saklama alanında açık metin kalamaz (PCI-DSS ve GDPR zorunluluğu).
- Çözüm: Regex motoru kredi kartlarını `****-****-****-XXXX`, parolaları `password=***REDACTED***`, AWS anahtarlarını `AKIA***REDACTED***` formatına dönüştürür.

### 1.4. Tehdit Tespiti ve Kural Motoru
Loglar yalnızca temizlenmez, içindeki saldırı sinyalleri yakalanır:
- **Kaba Kuvvet (Brute Force):** Aynı IP adresinden gelen ardışık 401/403 yanıtları eşik değerini (varsayılan 3) aştığında `AUTHENTICATION_BRUTE_FORCE` alarmı verilir.
- **SQL Enjeksiyonu (SQLi):** İstek URL'sinde veya gövdesinde `UNION SELECT`, `OR 1=1`, `--` kalıpları görüldüğünde `CRITICAL` seviyede alarm üretilir.
- **Kötü Niyetli Tarayıcı:** `sqlmap`, `nikto` veya `nmap` tarayıcıları yakalandığında alarm tetiklenir.

---

## 2. pytest ile Güvenlik Kodunu Test Etmenin İlkeleri

Bir güvenlik aracının güvenilirliği, testlerinin katılığıyla ölçülür:
1. **İzole Fikstürler (`@pytest.fixture`):** Testler birbirini etkilememeli, her test taze nesnelerle çalışmalıdır.
2. **Parametrik Testler (`@pytest.mark.parametrize`):** Bir fonksiyonu tek bir girdiyle değil; geçerli IPv4, IPv6, geçersiz IP'ler, farklı kredi kartı formatları gibi onlarca varyasyonla tek seferde sınamalısın.
3. **Kasıtlı Hata Doğrulaması (`pytest.raises`):** Sadece kodun çalıştığını değil; zararlı girdide beklenen özel istisnayı fırlattığını (`match="..."`) denetlemelisin.

---

## 3. Ustanın Çırağa Hafta 12 Nasihati

"Çırağım, güvenlik araçları yazmak cerrah bıçağı bileyicisi olmaya benzer. Bileyici kör olursa cerrah hastayı kurtaramaz. Yazdığın log aracı, kurumsal bir ağın gözü ve kulağıdır. Gözü kör etmeye çalışan her sahte loga, kulağı yanıltmaya çalışan her fısıltıya karşı uyanık olacaksın. Bu hafta öğrendiklerin senin savunma cephaneliğinin temel direkleridir!"
