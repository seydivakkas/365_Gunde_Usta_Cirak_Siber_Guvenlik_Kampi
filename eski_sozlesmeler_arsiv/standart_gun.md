# standart_gun.md — Siber Güvenlik Müfredatı Günlük Uygulama Sözleşmesi

**Sürüm:** 1.0  
**Kapsam:** Excel `365 GÜN` sayfasındaki gün 001–365; aynı sözleşme daha sonra belirlenecek 366–455 günlerinde de geçerlidir.  
**Sorumlu uygulayıcı:** AI kodlama ve ders hazırlama ajanı.  
**Süre:** 90 dakika/gün.  
**Çalışma ilkesi:** Windows-first, offline-first, izinli ve izole laboratuvar, Türkçe dokümantasyon, doğrulanabilir kanıt.  
**Bağlayıcı yardımcı belgeler:** `ajan_kodlama_ve_teslim.md`, `simulasyon_ve_gorsel.md`, `gunluk_kalite_kontrol.md`, `ai_security_ek.md`.

## 0. Değişmez sözleşme — tek gün, tek tamamlanmış sonuç

1. Her gün **atomik ve bağımsız bir ders/üretim birimidir**. Önceki günün koduna, dosyasına, verisine, çalışma dizinine, test sonucuna veya bitmemiş görevine dayanılamaz. Gün `n`, gün `n-1` tamamlanmamış olsa bile kendi örnek girdileriyle tek başına açılabilir. Konusal ön koşullar, ürün bağımlılığı anlamına gelmez.
2. Önceki gün hakkında **yalnızca bir cümlelik kavram hatırlatması** yapılabilir. `n-1`, `n-7`, `n-30`, `n-90` günlerinden bilgi tekrarı eklenebilir; önceki günün ürettiği bir dosya, komut, servis veya proje devralınamaz.
3. Haftalık mini projeler de **bağımsızdır**. Önceki haftanın projesi `v1→v2` biçiminde devam ettirilmez. Konu adında `v1`, “final”, “entegrasyon” veya “ilk sürüm” geçse bile, ajan tek günde sıfırdan bağımsız örnek/fixture üretir.
4. 351–365. günlerdeki bitirme aşaması da bağımsız günlük dikey kesitlerle yürütülür. 365. gündeki portföy özeti önceki çalışmaları *isteğe bağlı referans* olarak listeleyebilir; bunları çalıştırmak veya yeniden kullanmak zorunda değildir.
5. **Kod, ders notu, soru ve yanıtların üreticisi AI ajandır.** Kullanıcıya uygulamalı kabul sınavı veya kendisinin kod yazması zorunluluğu yüklenmez. Üretilen kod; açık, sürdürülebilir, gerçek çalışabilir, testli ve güvenli olmak bakımından deneyimli bir geliştiricinin koduyla aynı mühendislik standardını karşılamalıdır. Ajan üretimini insan yazmış gibi yanlış etiketleme yapılmaz.
6. Hiçbir gerçek test çalışmadan `PASS`, gerçek olmayan video/screenshot olmadan “kanıt”, erişilmemiş siteyi incelenmiş kaynak, üretilmemiş commit'i var olan commit olarak beyan etme.
7. Bir günün süresi dolduğunda bitmeyen iş ertesi güne **aktarılmaz**. Gerçek durum `HOLD`/`TAMAMLANAMADI` olarak yazılır; o günün kendi klasöründeki telafi iş listesi kalır. Sonraki gün başka bir gündür.

## 1. Veri kaynağı ve kimlik

Ajan, Excel'den yalnız seçilen günün şu kayıtlarını okur:
- `365 GÜN`: Gün, aşama, konu, tür, 90 dakikalık süre, ön koşul, kaynak, bağımsızlık kuralı.
- `DERSLER`: Tanım, önem, işleyiş, somut örnek, karşı örnek, İngilizce–Türkçe terimler, saldırı–tespit–savunma.
- `LABORATUVAR`: İzinli ortam, beş uygulama adımı, sentetik alternatif, durdurma koşulları.
- `SORU BANKASI`: O güne ait en az üç **hazır soru + doğru yanıt + gerekçe**.
- `GÜNLÜK KONTROL`, `SİMÜLASYON`, `AI SECURITY` (ilgiliyse): Kalite ve teknik güvenlik çerçevesi.

**Gün kimliği:** `G001` … `G365`. Tek günlük çıktı dizini: `gun_001/` … `gun_365/`. Kullanıcı tarih tanımlamamışsa gün numarası yeterlidir.

## 2. Zorunlu 90 dakika planı

| Dilim | Normal gün | Haftalık mini proje / aşama kalite günü | Ajanın çıktısı |
|---|---:|---:|---|
| Ön bilgi, etik ve kısa aralıklı tekrar | 10 dk | 10 dk | Ön koşul kartı / kısa konu hatırlatması |
| Ayrıntılı ders anlatımı | 25 dk | 15 dk | `ders.md` |
| Yerel laboratuvar / bağımsız mini proje | 40 dk | 50 dk | `uygulama/`, `tests/`, gerçek veya sentetik yürütme kanıtı |
| Teknik kanıt ve raporlama | 10 dk | 10 dk | `rapor.md`, `kanit/`, `manifest.json` |
| Hazır soru–cevap ve kalite özeti | 5 dk | 5 dk | `soru_cevap.md`, `sonuc.json` |
| **Toplam** | **90 dk** | **90 dk** | **Bütün çıktılar yalnız bu güne aittir** |

> 90 dakika içerik/etkinlik bütçesidir; bilgisayarın çok yavaş olması veya kurulum engeli halinde gerçek çalıştırma tamamlanmış gibi gösterilmez. Bu standardın uygulanması, sürenin otomatik olarak garanti edildiği iddiası değildir.

## 3. Ön koşul kapısı (S-01)

- Ön koşullar bir **konunun kavramsal yeterlilik koşuludur**, önceki güne veya onun projesine bağımlılık değildir.
- Bağlı ön koşul örnekleri: **OSI/TCP/IP → paket analizi; TCP/IP ve HTTP → web/API güvenliği; Windows/Linux süreç/izin temeli → sistem sertleştirme; Python/Git → DevSecOps otomasyonu; temel IAM ve güven sınırları → LLM araç yetkisi.**
- Ajan, bu kavramları aynı gün 10 dakikalık özet ile hatırlatır. Kritik ön bilgi hiç kurulmamışsa laboratuvarı atlayıp `HOLD:PREREQ` yazar; önceki günün dosyasını istemez.
- İlgili protokol kavramları daha sonra ayrıntılı anlatılacaksa, o günün işlemine yetecek asgari tanım açıkça verilir; ileri konunun öğrenildiği varsayılmaz.

## 4. Ayrıntılı ders notunun değişmez başlıkları (S-02)

Her `ders.md` aynı sırayla şu bilgileri içerir:

1. **Bugünün konusu ve öğrenme kazanımları** — 3 ölçülebilir madde.
2. **Tanım:** Doğru, açık ve kaynakla tutarlı açıklama.
3. **Neden önemli?** Gerçek sistem, savunma operasyonu veya kod kalitesi açısından değer.
4. **Teknik mekanizma:** Veri akışı, işlem sırası, aktörler, protokol alanları veya formül.
5. **İngilizce–Türkçe terminoloji:** En az 3 konuyla ilgili terim; İngilizce açılım, Türkçe karşılık ve bağlamsal örnek. Daha az terim gerçekten ilgiliyse bunu gerekçelendir.
6. **Somut açıklamalı örnekler:** En az iki giriş→işlem→çıktı örneği. Sentetik/gerçek ayrımı açıkça yazılır.
7. **En sık iki yanlış yaklaşım:** Hatanın nedeni, sonucu ve düzeltilmiş uygulama.
8. **Risk nasıl oluşur?** Saldırı/yanlış yapılandırma/tehdit modeli; yalnız kontrollü güvenlik öğretimi.
9. **Nasıl tespit edilir?** Gözlenebilir sinyal, log alanı, kural, negatif/pozitif karşılaştırma.
10. **Nasıl önlenir?** Kod veya yapılandırma kontrolü, doğrulama, en az ayrıcalık, izleme.
11. **Etik, hukuk, sınır ve belirsizlikler.**
12. **Kaynak ve sürüm:** Resmî bağlantı, belge sürümü/erişim durumu. İndirilemeyen kaynak `çevrimdışı teyit bekliyor` olur.

Yalnız bir satırlık konu adı veya genel-geçer AI metni ders olarak kabul edilmez. Teknik iddialar gerçek gözlemle/standartla uyumlu olmalıdır.

## 5. Laboratuvar seçimi ve simülasyon (S-03)

**Öncelik sırası:**

1. İzinli **yerel Windows / izole Linux VM / loopback laboratuvarı**. Gerçek komut ve test gerçekten çalıştırılır.
2. Birinci yol mümkün değilse **tamamen yerel deterministik PC simülatörü** (Python stdlib, PowerShell veya yerel inert örnek). Simülatör çalıştırılır; gerçek yürütme kayıtları saklanır. Simülatörün gerçek ortamın eşdeğeri olmadığı belirtilir.
3. Her iki yol da mümkün değilse, **AI illüstrasyonu veya statik adım şeması**. Her görselde `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` ibaresi bulunur; hayalî CLI çıktısı ölçülmüş değer diye sunulmaz. Bu yol **tek başına PASS sağlamaz**.

Her uygulamanın beş adımı: **hazırlık → başlangıç durumu → kontrollü uygulama → negatif kontrol → rapor ve geri dönüş**. Hedef dış IP taraması, canlı servis saldırısı, kişisel veri, şüpheli ikili veya yetkisiz erişim fark edilirse anında `STOP`.

## 6. Mini proje ve gerçek hayata bağlama (S-04 / S-05)

Gün `7, 14, …, 364` için tek güne sığan 52 bağımsız mini proje vardır. Her birinin:
- Somut kullanıcı hikâyesi, teknik gereksinimi, kapsam dışı maddesi;
- Ajan tarafından üretilmiş çalışır kaynak kodu **veya** gerçekten denetlenmiş yapılandırma/teknik raporu;
- En az bir olumlu + bir olumsuz test, gerçek sonuca dayalı PASS/HOLD;
- Türkçe `README.md`, test komutları, örnek sentetik veri, varsa güvenli ekran görüntüsü;
- NIST/OWASP/MITRE ilgili sınıflandırması ve yanlış pozitif/sınırlama açıklaması olur.

“v2”, “devam”, “önceki projeyi genişlet” veya “dünkü testi düzelt” günlük teslim hedefi olarak kullanılamaz. SOC, DFIR, AppSec, IAM, servis sertleştirme vb. gerçek senaryolar **sentetik olayların bağımsız benzetimleriyle** gösterilir.

## 7. Bilgi testi yerine AI soru–cevap (S-06)

Uygulamalı kabul sınavı **YOKTUR**. Günün bilgi kısmı öğrenciden yanıt beklemez. AI ajanı en az üç soru ve tam yanıtını hazırlar:
1. “Kavramın tanımı ve neden önemli olduğu nedir?” → gerekçeli yanıt;
2. “Mekanizma/laboratuvar hangi girdiyi nasıl dönüştürür?” → beklenen çıktılı yanıt;
3. “Risk nasıl oluşur, nasıl tespit edilir, nasıl azaltılır?” → savunma odaklı yanıt.

Her sorunun altında **doğru yanıt, kısa teknik gerekçe, yaygın yanlış anlama, kaynak bağlantısı** vardır. Haftalık proje günlerinde buna üç senaryo sorusu eklenebilir. Sorular kullanıcıya sınav olarak yöneltilmez; **ajan tarafından hazırlanmış eğitim içeriğidir**.

## 8. Ajanın kodlama standardı (S-07)

- Kod örnekleri sözde kod değil; gerçekten yürütülebilir, tam dosyalardır. Gereken modüller, girdiler, bağımlılıklar, çalışma komutu ve testler aynı gün oluşturulur.
- Python için tip ipuçları, küçük anlamlı fonksiyonlar, hata yönetimi, `pathlib`, gerekli yerde `argparse`, standart testler; PowerShell için parametre/girdi doğrulama, kontrollü hata kodu, güvenli yol kullanımı.
- Örnek test verileri **sentetik**, gizli anahtar/token/parola gerçek olmayan ve git'e işlenen veri sadece güvenli olmalıdır. Ağ denemelerinde yerel loopback dışında izin aranır.
- Savunmacı çalışma ve asgari yetki; SQL parametreleştirme, güvenli çıktı işlemi, güvenli logging, sabit gizli bilgi bulundurmama; bağımlılık sürümleri belgelendirme.
- Üretilen kaynak kodun **insan eliyle yazılmış üretim kalitesinde** olması hedeflenir; test çıktısı yoksa çalışma iddiası verilmez. Ajanın yazdığı içerik insan tarafından yazıldı diye gösterilmez.

Ayrıntılar: `ajan_kodlama_ve_teslim.md`.

## 9. Portföy, dosya sınırları ve teslim paketi (S-08)

Her gün için önerilen dosya ağacı:

```text
gun_050/
├── README.md                # Amaç, bağımsız kurulum, nasıl kullanılır
├── ders.md                  # Ayrıntılı Türkçe anlatım
├── soru_cevap.md            # En az 3 soru + yanıt + gerekçe
├── uygulama/                # Gerçek yürütülebilir kod veya yapılandırma
├── tests/                   # Olumlu/olumsuz testler
├── ornek_veri/              # Sadece sentetik fixture
├── kanit/                   # Gerçek çıktı VEYA etiketli temsili görseller
├── rapor.md                 # Bulgular, test durumu, sınırlar, kaynaklar
├── manifest.json            # Gün ID, ortam, üretici, artefaktlar, hash
└── sonuc.json               # PASS/HOLD/STOP; gerçek kanıt yolu
```

GitHub'a eklenecek kaynak ve Markdown belgeleri Türkçedir (kod sözdizimi, kütüphane adları, JSON anahtarları değiştirilmez). Commit SHA, test çıktısı, ekran görüntüsü veya hash ancak gerçekten üretildiyse kaydedilir. Açıklanmayan başarısız testler gizlenmez.

## 10. Aralıklı tekrar, telafi ve günlük sınır (S-09)

- 1/7/30/90 gün aralıklı tekrar **yalnız kavram** için geçerlidir; yeni günün projesinin girişini/durumunu etkilemez.
- `HOLD:PREREQ`, `HOLD:RUN`, `HOLD:EVIDENCE`, `HOLD:SECURITY`, `HOLD:TIME` etiketlerinden uygun olanını kullan.
- Eksik iş yalnız **aynı güne ait ayrı telafi kaydı** olarak tutulabilir. Sonraki gün başka bir projedir; telafi bitmediyse önceki gün `HOLD` kalır.

## 11. Kademeli kontrol; sınav değil doğrulanabilir kalite (S-10)

Her günün AI teslim kalite rubriği: **bilgi ve soru-cevap 20 + gerçek uygulama/simülasyon 40 + doğrulanabilir kanıt 25 + raporlama 15 = 100**. Excel `DEĞERLENDİRME` sayfasına yalnız gerçek denetimden sonra yazılır.

`PASS` için bütün şartlar: durum `Tamamlandı`; toplam ≥80; uygulama ≥24/40; kanıt ≥15/25; kanıt `Evet`; yürütme türü `Yerel çalıştırıldı` **veya** kavramsal/belgesel iş için `Belge doğrulandı`; etik kapsam uygun; negatif kontrol değerlendirilmiş. Yalnız temsili AI görsel varsa `HOLD`.

Haftalık/aylık/aşama sonlarında **sınav uygulanmaz**. Ajan kaynak ve çıktı kalitesine dair kalite özetini üretir; eksik kalemleri telafi listesine alır. Gerçek bilgisayarda test yapılamamışsa eksik dürüstçe raporlanır.

## 12. AI Security için ek zorunlu kontrol (S-11)

337–350. günlerde ayrıca `ai_security_ek.md` izlenir: offline LLM/RAG mock, prompt injection veri-talimât ayrımı, vektör/veri kökeni, model hash/SBOM, hassas veri, araç allowlist, aşırı ajan yetkisi, halüsinasyon, veri zehirleme, kontrollü görsel giriş, tüketim sınırı, olay müdahalesi. **Harici LLM API veya API anahtarı gerekmez.**

## 13. Etik ve yasal sınır (S-12)

- Yazılı kapsam ve açık yetki olmadan üçüncü taraf sistem, ağ, web sitesi veya hesap üzerinde tarama/güvenlik testi yapılmaz.
- Gerçek kötü amaçlı yazılım yürütülmez; kontrollü inert dosya veya güvenli eğitim fixture'ları kullanılır.
- KVKK ve veri minimizasyonu gözetilir; portföye gerçek kullanıcı verisi konulmaz.
- Sorumlu zafiyet bildirimi ve açıklama politikası üzerinde ancak yetkili bağlamda çalışılır.
- NIST NICE/CSF, MITRE ATT&CK ve OWASP eşleştirmeleri müfredat rehberidir; **resmî meslek/sertifika yeterliliği iddiası değildir**.

## 14. Gün başlatma ve kapatma kontrolü (AI ajanı için)

```text
[ ] Gün ID ve konu tek kayıt olarak seçildi.
[ ] Ön koşul kavramı aynı gün doğrulandı; başka güne dosya bağımlılığı yok.
[ ] 90 dakika bütçesi ve konu kapsamı tanımlı.
[ ] Ayrıntılı Türkçe ders + teknik terimler + somut örnekler hazır.
[ ] Risk, tespit ve savunma mekanizmaları açıklandı.
[ ] Laboratuvar yetkili/izole; gerekirse sentetik offline alternatif seçildi.
[ ] Kod veya teknik belge tek günde ve baştan üretildi; gerçek testler kaydedildi.
[ ] Pozitif/negatif senaryo ve güvenlik durdurma koşulu gösterildi.
[ ] AI en az üç açıklamalı soru-cevap oluşturdu; kullanıcıya sınav verilmedi.
[ ] Temsilî AI görselleri açıkça etiketlendi ve gerçek kanıt sayılmadı.
[ ] Teslim klasörü, README, rapor, manifest ve sonuç durumu hazır.
[ ] PASS/HOLD/STOP kararı gerçek doğrulama ve etik sınırla tutarlı.
```

**Ana kaynaklar:**
- NICE: https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- MITRE ATT&CK: https://attack.mitre.org/
- OWASP Web Top 10:2025: https://top10.owasp.org/2025/en/
- OWASP LLM Top 10:2025: https://genai.owasp.org/llm-top-10/
- NIST AI RMF / GenAI Profile: https://www.nist.gov/itl/ai-risk-management-framework
