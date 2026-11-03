# ajan_kodlama_ve_teslim.md — AI ajanı için mühendislik kuralları

**Geçerli olduğu yer:** 001–365 ve daha sonra netleşecek 366–455. günler. `standart_gun.md` üst sözleşmedir.

## 1. Ajanın görevi

Ajan **dersi anlatır, örnekleri ve kodu bizzat yazar, laboratuvarı güvenli biçimde hazırlar/gerçekten yürütürse kanıtlar, her soru için doğru yanıtı açıklar, test eder ve raporlar.** Öğrenciye kod yazma ödevi veya uygulamalı kabul sınavı verilmez. Kullanıcı isterse sonucu inceleyebilir; kullanıcı yapmış gibi teslimat üretilemez.

## 2. Gün bağımsızlığı

- **`gun_NNN/` sıfırdan oluşturulur.** Başka günün klasöründen kod, modül, JSON, CSV, model, test veya çalışmış hizmet devralma.
- Projede kullanılan örnek veri/fixture aynı gün üretilir; Python ve standart araçlar sistemde kurulu olabilir. Kurulum gereksinimlerini bu günün README'sinde belirt.
- Gün bağımsızlığı, öğrenme ön koşullarını yok saymak değildir: eksik kavramlar o gün anlatılır ve doğrulanır.
- Haftalık projelerin kodu da bağımsızdır. Entegrasyon varsa **aynı gün oluşturulmuş bileşenler** arasındadır.
- Derste 90 dakika içinde gerçekleştirilemeyecek kapsamı küçült; aynı konuyu sonraki güne taşıyarak devam ettirme.

## 3. İnsan kalitesinde kod gereksinimi

1. Çalışır ve okunur tam kaynak dosyası; sözde kod/yarım fonksiyon/`TODO` veya gizli dış servis bağımlılığı yok.
2. Amaca uygun küçük fonksiyonlar ve anlamlı isimler; tek sorumluluk, düşük gereksiz karmaşıklık.
3. Girdi doğrulama, yol güvenliği, hata işleme, anlamlı dönüş/çıkış kodu ve başarısızlık halinde güvenli davranış.
4. Python için mümkünse **Python standart kütüphanesi**, tip ipuçları, `pathlib`, `argparse`, `unittest` (veya yerelde mevcutsa `pytest`). PowerShell için `param()`, `-ErrorAction Stop`, kontrollü `try/catch`, `exit` kodu.
5. Sürüm/sabit bağımlılıkların kaydı; izinli paketler dışında otomatik indirme yok, internet bağımlılığı yok.
6. Sırlar, gerçek parola, token ve kullanıcı verileri kaynak kodda/logda yok. Dummy/sentetik anahtar gerçek anahtarmış gibi gösterilmez.
7. Önce beklenen sonucu yaz, sonra güvenli uygulamayı çalıştır, **en az bir pozitif ve bir negatif test** uygula.
8. Test gerçekten çalıştırılmadıysa `NOT_RUN`; başarısızsa `FAIL`; başarı ancak komut ve çıktı gerçekse `PASS`.
9. Terminalden veya kullanıcı dosya sisteminden kapsam dışı okumalar, izinsiz değişiklikler ve internet taramaları yasak.
10. Ajan tarafından üretilen kod profesyonel insan kodunun işlevsellik ve bakım kalitesi standardında olabilir; **yazarlığı hakkında yanıltıcı beyan yapılamaz**.

## 4. Platform ve çalıştırma

- Ana hedef: **Windows 10/11 + PowerShell + Edge**. Linux pratiği gerekiyorsa izole VM veya sentetik veri; Windows kullanıcı sistemini kalıcı değiştirme.
- Her komutun çalışma dizini, sürüm/araç ön koşulu, gerçek çıkış kodu ve kullanılan sentetik veri belirtilir.
- İsteğe bağlı Linux komutları, PowerShell eşdeğerlerinden ayrı verilir. macOS/iOS ya da bulut hesabı zorunlu yapılmaz.
- Dosya ve rapor işlemleri için offline-first; **LLM API, API key, ticari bulut hesabı şartı yoktur**. AI Security için yerel mock/kural motoru tercih edilir.

## 5. Kodu iki yönlü değerlendir

Her üretilen güvenlik öğretimi şunu açıklamalı:

| Boyut | Ajanın yazacağı kanıt |
|---|---|
| Risk oluşumu | Hatalı işlem veya saldırı yüzeyinin kavramsal modeli (zararsız/sentetik) |
| Tespit | Log alanı, anomali kuralı, beklenen/gerçek fark, ölçüm |
| Önleme | Validasyon, en az ayrıcalık, sınırlama, yapılandırma veya kaynak doğrulama |
| Negatif test | Kasıtlı yanlış girdi karşısında sistemin güvenli tepkisi |
| Etik sınır | Testin yalnızca yerel/yetkili/sentetik olması ve durdurma kuralı |

## 6. Günlük dosya sözleşmesi

```text
gun_NNN/
  README.md
  ders.md
  soru_cevap.md
  uygulama/
  tests/
  ornek_veri/
  kanit/
  rapor.md
  manifest.json
  sonuc.json
```

`README.md`: gün ID, başlık, kapsam, ön koşul, kullanılan araç, bağımsız kurulum, çalışma komutu, test komutu, dosya şeması, etik sınır, gerçek test durumu ve lisans. `soru_cevap.md`: en az üç açıklamalı hazır soru ve yanıt. `rapor.md`: amaç, yöntem, çıktı, negatif kontrol, kaynak, sınırlamalar, PASS/HOLD gerekçesi.

`manifest.json` örnek yapı (*örnek değerler başarı kanıtı değildir*):

```json
{
  "gun": 50,
  "baslik": "TCP üçlü el sıkışma",
  "uretim_turu": "AI ajanı",
  "bagimsiz": true,
  "platform": "Windows / yerel",
  "internet_gerekli": false,
  "test_durumu": "NOT_RUN",
  "kanit_durumu": "BEKLIYOR",
  "simulasyon_turu": "YEREL_TRAFIK",
  "kaynak": "https://www.wireshark.org/docs/"
}
```

**Gerçek yürütme olmadan** yukarıdaki durumlar `PASS` yapılamaz. JSON adları teknik sözleşme olarak korunabilir; dokümantasyon Türkçedir.

## 7. GitHub ve portföy

- İdeal yol: `portfolio/hafta_XX/gun_NNN/`. Gün klasörü bağımsız çalışır.
- Ajan README, kaynak, testler, küçük ve anonim fixture, örnek rapor ve lisans bilgilerini üretir.
- Commit SHA gerçek Git işlemi yapıldıktan sonra yazılır; uydurulmaz. GitHub’a otomatik push/PR/merge için ayrı yetki ve araç gereklidir.
- Üretilen görseller, gerçek test kanıtlarından farklı dizinde tutulur: `kanit/gercek/` ve `kanit/temsili/`. Kişisel veya gizli veri yayımlanmaz.

## 8. Günlük ajan kontrol çıkışı

Ajan gün sonunda şunları raporlar:

```text
Gün: GNNN
Ön koşul: TAMAM / HOLD
Çalışma modu: YEREL / SENTETİK_SIMÜLASYON / GÖRSEL_ÖĞRETİM
Kaynak dosyaları: gerçek yollar
Çalıştırılan komutlar: varsa gerçek komutlar ve çıkış kodları
Pozitif/negatif testler: PASS / FAIL / NOT_RUN
Hazır soru-cevap sayısı: >=3
Kanıt türü: GERÇEK / BELGE_DOĞRULANDI / TEMSİLÎ
Kalite: .../100 (yalnızca dayanak varsa)
Karar: PASS / HOLD / STOP
Eksik / sınırlama: ...
Sonraki güne taşınacak çalışma: YOK
```

## 9. Ajan başlangıç talimatı (kopyalanabilir)

> Excel'den yalnız belirtilen günün ders, laboratuvar ve soru-cevap alanlarını al. `standart_gun.md` ve bu belgeyi uygula. Önceki günün kodunu, dosyasını veya bitmemiş işini kullanma. Kullanıcıya sınav sorma, tam ve doğru soru-cevapları sen hazırla. Gerekliyse Windows için kaliteli gerçek kod, sentetik fixture ve pozitif/negatif testleri sıfırdan üret. Kapsam sadece yerel/izinli. Çalıştırmadığın işlemi çalıştırdım deme; simüle edilmiş veya temsili görselleri dürüstçe etiketle. 90 dakikalık içerik sınırını aşma; bitmeyeni o güne ait HOLD olarak işaretle. İnsanın yazdığı üretim kalitesindeki okunur kodu ve gerçek kanıt durumunu teslim et.
