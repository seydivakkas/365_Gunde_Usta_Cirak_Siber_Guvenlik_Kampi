# GÜN 34: DOSYA TÜRLERİ, METADATA VE MIME ANALİZİ
## Usta-Çırak / Hoca Dersi Notları

---

### Lisans Bildirimi
```
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve eğitim amaçlıdır.
Kopyalanamaz, dağıtılamaz, ticari amaçla kullanılamaz.
```

---

### 1. Giriş ve Temel Pedagojik Yaklaşım: Çırağa Öğüt
Evlat, dijital dünyada gözünle gördüğün hiçbir dosya uzantısına asla peşinen inanmayacaksın. Bir dosyanın adının sonunda `.pdf`, `.jpg` veya `.docx` yazıyor olması, o dosyanın gerçekten bir doküman veya resim olduğunu kanıtlamaz. 

Windows gibi kullanıcı dostu görünmeye çalışan işletim sistemleri, varsayılan olarak "bilinen dosya uzantılarını gizle" (Hide extensions for known file types) seçeneğiyle gelir. Saldırganlar bu zaafı onlarca yıldır tepe tepe kullanır. Bir saldırgan bir Truva Atı'nı alır, adını `maas_bordrosu.pdf.exe` yapar. Windows kullanıcısı ekranda yalnızca masum bir PDF simgesi ve `maas_bordrosu.pdf` ismini görür; çift tıkladığında ise işletim sistemi arka planda çalıştırılabilir ikiliyi (executable) tam yetkiyle çalıştırır!

Bugün seninle şu temel ilkeyi zihnimize kazıyacağız:
> **"Dosya adı uzantısından bağımsız olarak imza ve MIME gibi metadata içerir; bazı bilgiler kolayca değiştirilebilir."**

Dosyanın gerçek kimliğini dışındaki boyalı tabeladan değil, içindeki ilk baytlarından (Magic Bytes) okumayı öğreneceksin.

---

### 2. Dosya Uzantısı Yanılsaması (Extension Illusion) ve Saldırı Vektörleri

Bir dosya uzantısı (file extension), işletim sisteminin kullanıcı kabuğuna (Windows Shell / GNOME / KDE) "bu dosyaya tıklandığında hangi varsayılan uygulamayı açayım?" sorusuna verilmiş yüzeysel bir ipucundan başka hiçbir şey değildir.

Saldırganların dosya uzantılarını istismar etme yöntemleri:
1. **Çift Uzantı Hilesi (Double Extension - MITRE ATT&CK T1036.007):**
   Örnek: `fatura.pdf.exe`, `tatil_fotografi.jpg.vbs`
   Kullanıcı ilk uzantıyı görüp dosyanın zararsız olduğunu düşünür.
2. **Uzantı Değiştirme (Extension Spoofing - MITRE ATT&CK T1036.008):**
   Saldırgan tehlikeli bir PE çalıştırılabilir dosyasını doğrudan `logo.png` veya `rehber.txt` olarak adlandırır. Bir web sitesine resim yükleme alanından bu dosyayı yükler; ardından web sunucusundaki yerel dosya dahil etme (LFI) veya komut yürütme zafiyetiyle bu dosyayı çalıştırır.
3. **Sağdan Sola Geçersiz Kılma (Right-to-Left Override - RTLO - MITRE ATT&CK T1036.002):**
   Unicode `U+202E` karakteri kullanılarak dosya adının sağdan sola yazılması sağlanır. Örneğin `fatura[U+202E]cod.exe` ismi ekranda `faturaexe.doc` olarak görünür!

---

### 3. Sihirli Baytlar (Magic Bytes / File Signatures)

Bir dosyanın gerçek biçimini (format) belirleyen yegâne otorite, dosyanın başlangıcında (offset 0) yer alan sabit başlık baytlarıdır. Bunlara **Sihirli Baytlar (Magic Bytes)** veya **Dosya İmzası (File Signature)** denir.

Linux sistemlerdeki meşhur `file` komutu (`libmagic` kütüphanesi) dosya uzantısına bakmaz; doğrudan dosyanın başındaki bu baytları okur.

#### Temel Dosya İmzaları Referans Tablosu:
| Biçim | Sihirli Baytlar (Hex) | ASCII Gösterimi | Açıklama |
| :--- | :--- | :--- | :--- |
| **Windows PE (EXE / DLL / SYS)** | `4D 5A` | `MZ` | Mark Zbikowski (MS-DOS mimarı). PE ikilisinin başlangıcı. |
| **Linux ELF** | `7F 45 4C 46` | `\x7fELF` | Linux ve Unix çalıştırılabilir ikili program başlığı. |
| **Adobe PDF** | `25 50 44 46` | `%PDF-` | Taşınabilir belge biçimi başlığı. |
| **PNG Resim** | `89 50 4E 47 0D 0A 1A 0A` | `\x89PNG\r\n\x1a\n` | 8 baytlık kayıpsız grafik başlığı. |
| **JPEG Resim** | `FF D8 FF` | ÿØÿ | JFIF/EXIF fotoğraf dosyası başlangıcı. |
| **ZIP / Office (DOCX/XLSX)** | `50 4B 03 04` | `PK\x03\x04` | Phil Katz (PKZIP standardı). Modern Office belgeleri de ZIP kapsayıcısıdır. |
| **Unix Shell Script** | `23 21` | `#!` | Shebang; betiğin hangi yorumlayıcıyla çalışacağını belirtir. |

---

### 4. MIME Türleri (Multipurpose Internet Mail Extensions) ve Web Açıkları

MIME türleri; internet protokollerinde (HTTP, SMTP) aktarılan içeriğin biçimini standartlaştırmak için IANA tarafından tanımlanmıştır (`Content-Type: application/pdf`, `image/png`, `text/html`).

#### Kritik Web Güvenlik Açığı: Yüzeysel MIME Doğrulaması
Bir web geliştiricisi dosya yükleme (File Upload) modülünde güvenlik önlemi olarak yalnızca istemcinin gönderdiği HTTP başlığına güvenirse:
```http
POST /upload HTTP/1.1
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg
```
Burada istemci (saldırgan), dosyanın içine bir PHP web shell koyduğu halde `Content-Type: image/jpeg` başlığını el ile ekleyebilir. Eğer sunucu dosyayı diske yazarken fiziksel başlık baytlarını denetlemezse, saldırgan sunucuya tam yetkili bir arka kapı bırakmış olur!

**Kural:** Sunucu tarafında `Content-Type` başlığına asla güvenilmez; dosyanın ilk 16-32 baytı fiziksel olarak okunup sihirli bayt doğrulaması (magic bytes whitelist) yapılmalıdır.

---

### 5. Metadata'nın Doğası ve Değiştirilebilirliği (G034-SC1)

Metadata, "veri hakkındaki veri"dir. Dosya boyutu, oluşturulma tarihi, yazar bilgisi, kamera modeli, GPS koordinatları vb.

#### A. Zaman Damgaları ve Timestomping (MITRE ATT&CK T1070.006)
Dosya sistemlerinde (NTFS, EXT4) dört temel zaman damgası tutulur (MACB):
- **M (Modified):** İçeriğin son değiştirilme tarihi.
- **A (Accessed):** Dosyaya son erişim tarihi.
- **C (Changed / MFT Modified):** Dosya metadata'sının son değişim tarihi.
- **B (Birth / Created):** Dosyanın oluşturulma tarihi.

**Dikkat:** M, A ve B zaman damgaları standart kullanıcı veya yazılımlar tarafından Windows API (`SetFileTime`) ile **kolayca geriye alınabilir (Timestomping)**. Saldırgan sisteme bıraktığı zararlının tarihini 2018 yılına çekerek adli bilişim analistinin "son 24 saatte değişen dosyalar" aramasından kaçmaya çalışır.

#### B. EXIF Metadata ve Bilgi İfşası (Information Disclosure)
Fotoğrafların içine gömülen EXIF verileri; saldırganlar için keşif (reconnaissance) kaynağıdır. Bir şirket binasının fotoğrafındaki GPS koordinatları veya kamera yazılım sürümü OSINT istihbaratı sağlar.

---

### 6. Tespit, Denetim ve Savunma Kılavuzu

1. **Uzantı - İmza Uyuşmazlığı Taraması (Extension vs Signature Mismatch):**
   Bir dosyanın adı `.pdf` olduğu halde başlığında `4D 5A` (MZ) veya `7F 45 4C 46` (ELF) varsa, bu durum istisnasız **CRITICAL** bir güvenlik ihlalidir. Dosya derhal izole edilmelidir.
2. **Gelişmiş Denetim Araçları:**
   - Linux: `file -b --mime-type <dosya>`
   - Windows Sysinternals: `sigcheck.exe -e -v <dosya>` (Dijital imza ve PE doğrulaması)
   - ExifTool: `exiftool <dosya>` (Tüm gizli metadata alanlarını çıkarma)
3. **Web Uygulama Savunması:**
   - Yüklenen dosyaları doğrudan web kök dizinine (web root) koymayın.
   - Dosya isimlerini rastgele hash'lerle (UUID) değiştirin ve uzantıyı yalnızca tespit edilen gerçek MIME türüne göre sunucu tarafında siz atayın.
   - Dosyaları `Content-Disposition: attachment` ve `X-Content-Type-Options: nosniff` başlıklarıyla sunun.

---

### Resmî Kaynaklar
- Microsoft Learn: [Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- Gary Kessler: [File Signature Table](https://www.garykessler.net/library/file_sigs.html)
- MITRE ATT&CK: [T1036.008 - Masquerade File Type](https://attack.mitre.org/techniques/T1036/008/)
- MITRE ATT&CK: [T1070.006 - Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)
