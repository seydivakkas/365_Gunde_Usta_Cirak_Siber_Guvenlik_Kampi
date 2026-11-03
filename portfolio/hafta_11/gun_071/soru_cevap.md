<!--
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
-->

# Gün 071: Soru ve Cevaplar (Python Ortamı, venv ve Paket Güvenliği)

---

## G071-SC1: Python Sanal Ortamlarında (venv) `include-system-site-packages = false` İlkesinin Güvenlik Önemi ve Yalıtım Mekanizması

### Soru Başlığı ve Tanımı
Python sanal ortamı (`venv`) oluşturulurken `pyvenv.cfg` dosyasında yer alan `include-system-site-packages = false` yönergesinin hermetik (sızdırmaz) yalıtım açısından güvenlik önemi nedir ve bu değerin `true` yapılması kurumsal sistemlerde ne tür güvenlik risklerine yol açar?

### Derinlemesine Teknik Analiz
Python çalışma zamanı (runtime), bir kütüphaneyi içe aktarırken (`import module`) `sys.path` listesindeki dizinleri sırayla arar. Normal şartlarda `venv` başlatıldığında, `sys.prefix` sanal ortam dizinine yönlendirilir. 
1. **Yalıtım Mekanizması (`false`):** `include-system-site-packages = false` olduğunda, `sys.base_prefix` (küresel/işletim sistemi Python dizini) altında bulunan `site-packages` dizini `sys.path` listesine **dahil edilmez**. Sanal ortam yalnızca kendi içindeki izole kütüphaneleri görür.
2. **Sızıntı ve Yetki Genişlemesi Riski (`true`):** Eğer bu değer `true` yapılırsa:
   - Küresel sistemde root/administrator yetkileriyle kurulmuş olan eski, güncellenmemiş veya zafiyetli paketler sanal ortama sızar.
   - Geliştiricinin sanal ortamda güvenli olduğunu varsaydığı bir script, arka planda işletim sisteminin global paketini yükleyerek beklenmedik davranışlar sergileyebilir.
   - Farklı projelerin bağımlılıkları birbirine karışır (dependency pollution) ve deterministik bağımlılık yönetimi imkansız hale gelir.
   - Sistem düzeyinde yazma yetkisi olan başka bir saldırgan, küresel dizine yerleştirdiği truva atı (trojanized) bir `.pth` veya `.py` dosyası üzerinden sanal ortamda çalışan tüm güvenlik otomasyonlarını zehirleyebilir.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir kurumda SOC analisti, şüpheli ağ paketlerini incelemek üzere izole bir sunucuda Python scripti çalıştırmaktadır. Ancak sanal ortam oluşturulurken `include-system-site-packages = true` unutulmuştur. Sunucuda aylar önce sistem yöneticisi tarafından küresel olarak kurulmuş ve artık EOL (End of Life) durumundaki eski bir `urllib3` (v1.26.4) kütüphanesi bulunmaktadır. Analist kendi requirements dosyasına güvenli sürüm yazdığını düşünse de, Python çalışma zamanı global dizindeki zafiyetli sürümü yüklemiş ve script ReDoS saldırısıyla kilitlenerek SOC izlemesini devre dışı bırakmıştır.
**Pratik Çözüm:** `PythonEnvAndDependencyAuditor.audit_pyvenv_cfg()` fonksiyonumuz, sanal ortam denetiminde `include-system-site-packages` anahtarının kesinlikle `false` olduğunu doğrular. Değer `true` ise `EnvSecurityAuditError` fırlatarak geliştirme ortamının çalışmasını engeller.

### Ustanın Çırağa Tavsiyesi
Çırak, sanal ortam sadece kütüphaneleri düzenli tutmak için bir klasör değildir; o senin laboratuvarının biyogüvenlik kabinidir. Küresel sistemle sanal ortam arasına cam fanusu koymazsan, dışarıdaki virüs içeri, içerideki patojen dışarı sızar.

---

## G071-SC2: Yazılım Tedarik Zincirinde Typosquatting Saldırıları, Levenshtein Tespiti ve `setup.py` Arbitrary Code Execution Riskleri

### Soru Başlığı ve Tanımı
Yazılım tedarik zincirinde (Software Supply Chain) yaygın olarak görülen Typosquatting (yazım hatası avcılığı) saldırısı nasıl işler, Levenshtein düzenleme uzaklığı ile nasıl otomatik tespit edilir ve bir paketin indirilmesi sırasında `setup.py` dosyası üzerinden keyfi kod çalıştırma (RCE) riski nasıl engellenir?

### Derinlemesine Teknik Analiz
PyPI ve benzeri açık paket depoları, herhangi bir geliştiricinin paket yüklemesine olanak tanır.
1. **Typosquatting Mekanizması:** Saldırganlar popüler siber güvenlik kütüphanelerinin (`requests`, `scapy`, `cryptography`, `paramiko`) isimlerindeki harflerin yerini değiştirerek (`reqeusts`, `scapppy`, `cryptograpy`) veya tire ekleyerek (`python-requests`) sahte paketler yayınlarlar.
2. **Levenshtein Uzaklığı Tespiti:** Bir metinden diğerine ulaşmak için gereken minimum ekleme, silme ve değiştirme işlem adedine Levenshtein uzaklığı denir. Motorumuz dinamik programlama matrisi ($O(m \times n)$) ile paket adını meşru liste ile karşılaştırır:
   $$\text{Levenshtein}(\text{"reqeusts"}, \text{"requests"}) = 2$$
   Uzaklık 1 veya 2 olduğunda sistem bunu anında **Tedarik Zinciri Saldırısı** olarak etiketler.
3. **`setup.py` Tehlikesi ve Wheel Savunması:** Geleneksel `.tar.gz` (Source Distribution - sdist) paketlerinde `pip install` çalıştırıldığında, paketin içindeki `setup.py` dosyası derleme aşamasında yerel makinede Python betiği olarak doğrudan icra edilir. Bu, saldırgana daha paket kurulmadan önce sistemde kod çalıştırma imkanı verir. Savunma için `pip install --only-binary :all:` parametresiyle yalnızca önceden derlenmiş `.whl` (Wheel) paketlerinin kabul edilmesi ve statik regex/isim denetimi zorunludur.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir sızma testi uzmanı, acil bir operasyonda terminalden `pip install scapppy` yazar. Farkında olmadan indirdiği bu paket, `setup.py` dosyası içerisine gizlenmiş bir Python koduyla kullanıcının `~/.ssh/id_rsa` anahtarlarını ve ortam değişkenlerindeki AWS/Cloud API anahtarlarını saldırganın webhook adresine POST eder.
**Pratik Çözüm:** `PythonEnvAndDependencyAuditor.detect_typosquatting()` fonksiyonu, `requirements.txt` dosyasındaki her paket adını analiz eder. `requests`, `scapy` gibi kritik güvenlik kütüphanelerinin 2 karakter yakınlığındaki tüm varyantlarını tespit ederek `EnvSecurityAuditError` fırlatır ve paketin kurulmasını baştan önler.

### Ustanın Çırağa Tavsiyesi
Evlat, parmakların klavyede ne kadar hızlı olursa olsun, gözlerin terminale yazılan her harfi bir kuyumcu terazisi gibi tartmalıdır. Tek bir harf hatası, saatlerce verdiğin savunma emeğini saldırganın eline teslim edebilir.

---

## G071-SC3: Pip Hash Pinning (`--require-hashes`) ile Deterministik Bütünlük Doğrulaması ve MitM Saldırılarına Karşı Savunma

### Soru Başlığı ve Tanımı
Geleneksel `requirements.txt` dosyalarında yalnızca sürüm numarası sabitlemenin (`package==1.2.3`) yetersiz kaldığı durumlar nelerdir ve SHA-256 hash sabitlemesi (`--hash=sha256:...`) ile `--require-hashes` bayrağı bu açıkları nasıl kapatır?

### Derinlemesine Teknik Analiz
Birçok geliştirici `package==1.2.3` yazdığında güvende olduğunu zanneder. Ancak bu yaklaşım üç büyük güvenlik açığına karşı tamamen savunmasızdır:
1. **PyPI Paket Değiştirme (Tampering / Compromised Maintainer):** Bir geliştiricinin PyPI hesabı çalındığında veya bir içerik dağıtım ağı (CDN) önbelleği zehirlendiğinde, aynı sürüm numarası (`1.2.3`) altında değiştirilmiş, içine kötü amaçlı kod enjekte edilmiş yeni bir derleme (build) sunulabilir. Pip varsayılan olarak sürüm numarasına bakar, dosyanın değiştiğini fark edemez.
2. **Ortadaki Adam (MitM) ve DNS Zehirlenmesi:** Kurumsal ağda TLS sonlandırma (TLS Inspection) veya sahte sertifika kullanan bir ağ saldırganı, indirme sırasında araya girip paketi modifiye edebilir.
3. **Kriptografik Hash Pinning Çözümü:** Pip'in RFC uyumlu hash doğrulama mekanizmasında, indirilen paket dosyası (wheel veya sdist) RAM üzerinde SHA-256 algoritmasından geçirilir:
   $$H = \text{SHA256}(\text{package\_bytes})$$
   Eğer $H \neq \text{hash\_in\_requirements}$, pip paketi anında siler ve `Hash mismatch` hatasıyla süreci durdurur. Ayrıca `--require-hashes` bayrağı kullanıldığında, dosyadaki tek bir paketin bile hash değeri eksikse pip tüm kurulumu reddeder; böylece hiçbir kontrolsüz veya üçüncü parti ikincil bağımlılık kurulamayacaktır.

### Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir finans kurumunun CI/CD boru hattında her gece otomatik siber güvenlik testleri çalıştırılmaktadır. Bir gece genel depodaki popüler bir yardımcı kütüphanenin maintainer hesabı saldırganlar tarafından ele geçirilir ve mevcut sürümün altına kripto madenci (cryptominer) içeren bir güncelleme yerleştirilir. Normal sürüm kontrolü bu değişikliği yakalayamaz ve zararlı kod şirket sunucularına sızar.
**Pratik Çözüm:** `guvenli_requirements.txt` dosyamızda her paket için `cryptography==42.0.5 --hash=sha256:7c7c...` formatında kesin hash mühürleri tanımlanmıştır. `PythonEnvAndDependencyAuditor`, `strict_hash=True` modunda her paketin geçerli bir 64 karakterli SHA-256 hash'ine sahip olduğunu matematiksel olarak doğrular.

### Ustanın Çırağa Tavsiyesi
Çırak, siber güvenlikte "güven ama doğrula" sözü yetersizdir; bizim ilkemiz "asla güvenme, daima kriptografik olarak hesapla"dır. Bir paketin adı ve sürümü iddiadır, SHA-256 hash'i ise delildir. Sen her zaman delille hareket et!
