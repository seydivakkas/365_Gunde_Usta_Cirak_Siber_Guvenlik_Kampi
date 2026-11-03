# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 098: Soru-Cevap — Aşama 4 Kalite Özeti ve Otomasyon Güvenliği

---

## Soru 1: Güvenlik otomasyonu betiklerinin denetiminde dinamik analiz (kodu çalıştırarak test etme) yerine neden öncelikle AST tabanlı statik analiz tercih edilmelidir?

### 1. Soru Başlığı ve Tanımı
Güvenlik betiklerinin kalite ve zafiyet denetiminde dinamik analiz ile Soyut Sözdizimi Ağacı (AST) tabanlı statik analiz arasındaki temel farklar ve AST'nin güvenlik operasyonlarındaki vazgeçilmez rolü.

### 2. Derinlemesine Teknik Analiz
Dinamik analizde kod çalıştırılır ve çalışma anı davranışları incelenir. Ancak güvenlik otomasyonunda denetlenen betik güvenilmez bir kaynaktan gelmiş olabilir ya da içerisinde zararlı kod veya telafisi imkansız yan etkiler barındırabilir. Örneğin `os.system("rm -rf /")`, zararlı bir soket bağlantısı veya `eval(untrusted_payload)` içeren bir betik dinamik olarak çalıştırıldığı an ana sistemi zehirleyebilir.

Python'ın `ast.parse()` modülü kodu baytkoda derlemez ve çalıştırmaz. Kaynak kodu doğrudan hiyerarşik bir düğüm (node) ağacına dönüştürür. `ast.walk()` ile bu ağaç üzerinde dolaşılırken:
- `ast.Call`: `eval`, `exec`, `subprocess.Popen(shell=True)` gibi tehlikeli çağrılar,
- `ast.ExceptHandler`: `node.type is None` koşuluyla tüm hataları yutan çıplak `except:` blokları,
- `ast.Attribute` veya `ast.Name`: Beklenen standart argüman ayrıştırıcılarının (`argparse.ArgumentParser`) varlığı,
çalıştırma riski sıfır olan deterministik ve son derece hızlı bir süreçle incelenir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir DevSecOps boru hattında üçüncü taraf geliştiricilerin yazdığı 200 adet güvenlik betiği depoya (repository) çekilmektedir. CI/CD sunucusu bu betikleri bir sandbox'ta çalıştırmayı denediğinde, bazı betikler ortam değişkenlerini sızdırmış ve test ortamındaki veritabanını sıfırlamıştır.

**Çözüm:** CI/CD öncesinde pre-commit aşamasına `Stage4QualityAuditor` entegre edilir. Kod diskten okunur ve AST filtresine sokulur. Dinamik çalıştırma olmadan kod içinde `eval`, `exec` veya sabit parola tespit edilirse boru hattı 5 milisaniyede reddedilir ve zararlı eylem daha başlamadan bertaraf edilir.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, şüphelendiğin bombayı patlatarak inceleyemezsin! Bilmediğin kodu çalıştırmadan önce röntgenini çekeceksin. AST, Python kodunun röntgen cihazıdır. Kodun içine girmeden iskeletini gör, zafiyeti düğüm seviyesinde yakala.

---

## Soru 2: Çıplak `except:` (Bare Except - CWE-391) blokları güvenlik otomasyonunda neden yüksek riskli bir anti-pattern olarak kabul edilir ve sistem kararlılığını nasıl bozar?

### 1. Soru Başlığı ve Tanımı
Hata yönetiminde spesifik istisna sınıfları yerine çıplak `except:` kullanımının siber güvenlik operasyonlarındaki tehlikeleri, `KeyboardInterrupt` / `SystemExit` yutulması ve doğru hata mimarisi.

### 2. Derinlemesine Teknik Analiz
Python'da tüm istisnaların atası `BaseException` sınıfıdır. Standart hatalar (`ValueError`, `KeyError`, `IOError` vb.) `Exception` sınıfından türerken, sürecin sonlandırılmasını yöneten kritik sinyaller (`KeyboardInterrupt`, `SystemExit`, `GeneratorExit`) doğrudan `BaseException`'dan türer.

Çıplak `except:` ifadesi `except BaseException:` ile eşdeğerdir. Bu ifade yazıldığında:
1. Operatör veya izleme sistemi `Ctrl+C` gönderdiğinde veya `kill -15` (SIGTERM) sinyali iletildiğinde betik durmaz; sinyali yutar ve sonsuz döngüde asılı kalır.
2. `sys.exit(1)` ile başarısızlık bildirilmek istendiğinde `SystemExit` istisnası yakalanır ve işlem sessizce yutularak sanki başarılı olmuş gibi (çıkış kodu 0) sona erebilir.
3. Arka planda meydana gelen bellek taşması (`MemoryError`) veya kritik mantık hataları gizlenir; sistem körleşir.

Doğru yaklaşım spesifik hataları (`except (ValueError, FileNotFoundError) as err:`) yakalamak ve en genel durumda dahi yalnızca `except Exception as exc:` kullanmaktır.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Bir bankanın gece çalışan otomatik mutabakat ve DLP tarama betiği, disk dolduğu için `IOError` fırlatmıştır. Ancak geliştirici betikte `try ... except: pass` kullandığı için betik hata kaydetmemiş, işlemi yarıda kesmiş ve ana orkestrasyona başarı sinyali vermiştir. Sonuç olarak 50.000 şüpheli finansal işlem 3 gün boyunca taranmamış kalmıştır.

**Çözüm:** `Stage4QualityAuditor` motorunda `SEC_RULE_04_BARE_EXCEPT` kuralı uygulanır. AST üzerinde `isinstance(node, ast.ExceptHandler) and node.type is None` koşulu arandığı an betik ARL-1 seviyesine düşürülür ve geliştiriciden spesifik istisna ve loglama mimarisi talep edilir.

### 4. Ustanın Çırağa Tavsiyesi
Çırağım, hatayı gizlemek kusuru örtmez, felaketi büyütür. Bir güvenlikçi hatadan korkmaz; hatayı açıkça karşılar, kaydeder ve zarifçe yönetir. Çıplak except kullanmak, yangın alarmı çaldığında binayı tahliye etmek yerine alarmın kablosunu kesmeye benzer!

---

## Soru 3: Otomasyon Hazır Bulunuşluk Seviyesi (ARL) mimarisi bir güvenlik orkestrasyonunda (SOAR) hangi operasyonel riskleri önler ve seviye geçişleri nasıl yönetilir?

### 1. Soru Başlığı ve Tanımı
Güvenlik operasyonlarında betiklerin ve araçların ARL-1'den ARL-4'e kadar sınıflandırılmasının getirdiği kurumsal yönetişim modeli ve üretim ortamı güvencesi.

### 2. Derinlemesine Teknik Analiz
Güvenlik Operasyon Merkezlerinde (SOC) ve SOAR platformlarında çalışan yüzlerce playbook ve betik bulunur. Eğer bu betiklerin kalite standartları homojen değilse:
- Standart dışı çıkış kodları boru hattının yanlış kararlar almasına (False Positive / False Negative tetiklemeler) neden olur.
- Bellek sınırı olmayan betikler SOAR sunucusunu tüketerek (CWE-400) diğer kritik olay müdahale süreçlerini durdurur.
- Loglama standardı olmayan betikler adli bilişim (forensics) denetimlerinde kanıt zincirini bozar.

ARL modeli 4 kademeli bir kalite barajı uygular:
- **ARL-1 (Red):** Güvenlik kusurları olan betiklerin üretime sızmasını engeller.
- **ARL-2 (Revizyon):** Eksik mimari ve hata yönetimi olan betikleri izole laboratuvarda tutar.
- **ARL-3 (Şartlı):** Kritik olmayan yardımcı görevlere izin verir.
- **ARL-4 (Üretim):** Tam otonom, 100/100 puanlı, girdi doğrulamalı ve kanıt üreten betikleri doğrudan çekirdek savunmaya yerleştirir.

### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
Büyük bir e-ticaret holdingi, SOC analistlerinin yazdığı Python betiklerini doğrudan SOAR platformuna aktarmaktadır. Analistlerden birinin yazdığı IP engelleme betiği, çıkış kodunu her durumda `0` döndürdüğü için güvenlik duvarı kuralı eklenemese dahi bilet "Çözüldü" olarak kapanmış ve saldırgan IP engellenmemiştir.

**Çözüm:** Holding, SOAR entegrasyonu öncesi CI/CD kapısına ARL zorunluluğu getirmiştir. `auditor_cli.py -f script.py --strict` komutu çalıştırılmadan ve `ARL-4` onayı alınmadan hiçbir betik SOAR havuzuna aktarılmaz. Bu sayede hatalı çıkış kodları ve mantık kusurları daha geliştirme aşamasında yakalanmıştır.

### 4. Ustanın Çırağa Tavsiyesi
Evlat, kılıç kınında paslanmaz, ama bilenin elinde can kurtarır. ARL senin kalite mühründür. Çıraklıkta aceleyle yazılan kod belki iş görür, ama ustalıkta yazılan kod yüz yıl sonra bile güven verir. Üretime giden her satırın ARL-4 olsun!
