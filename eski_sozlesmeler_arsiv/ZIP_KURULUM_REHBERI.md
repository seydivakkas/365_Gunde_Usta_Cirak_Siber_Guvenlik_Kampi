# ZIP Paketini Windows'ta Kurma ve AI Kodlama Ajanıyla Kullanma

## 1. Dosyalar nasıl kullanılacak?

| Paket dosyası | Rolü | Her gün kullanımı |
|---|---|---|
| `PAKET_OKU_BENI.md` | Paket içerik ve kararı | Başlangıçta oku |
| `standart_gun.md` | Üst günlük sözleşme | Her gün zorunlu |
| `ajan_kodlama_ve_teslim.md` | Kod/kanıt/README kalite standardı | Kod veya teknik belge üretiminde |
| `simulasyon_ve_gorsel.md` | Güvenli yerel lab/sentetik/görsel yolu | Her laboratuvarda |
| `gunluk_kalite_kontrol.md` | PASS/HOLD/STOP ve puanlama | Her günün sonunda |
| `ai_security_ek.md` | AI Security özel kontrolü | G337–G350 |
| `Siber_Guvenlik_455_Gun_Mufredat_365_Gun_Guncellenmis.xlsx` | 365 günün kanonik konu, ders, lab, soru-cevap, durum ve formül kaynağı | Her gün yalnız ilgili satırlar |
| `gun_050_ornek.md` ve `gun_050_ornek/` | Öğretici referans örnek | İhtiyaç halinde biçim referansı; kod kopyalanmaz |
| `AJAN_ANA_PROMPT.md` | Ajanın orkestrasyon görevi | Başta/kalıcı talimat |
| `SONRAKI_GUN_TETIKLE.md` | İlk gün, devam, otomatik zincir, HOLD telafi için kopyalanabilir komutlar | İstenilen tetik modunda |

## 2. Windows PowerShell'de ZIP'i çıkar

1. Güncellenmiş ZIP dosyasını örneğin `İndirilenler` klasöründen aşağıdaki konuma taşıyabilir veya aşağıdaki `$Zip` değişkenini gerçek dosya yoluna uyarlayabilirsin.
2. **Yeni** proje klasörünü oluştur. Mevcut proje dosyalarını üstüne yazma.

```powershell
$ErrorActionPreference = 'Stop'
$Zip = Join-Path $env:USERPROFILE 'Downloads\Siber_Guvenlik_Ajan_Tetikleme_Paketi.zip'
$Root = 'C:\Projects\SiberGuvenlik-455Gun'
if (-not (Test-Path -LiteralPath $Zip)) { throw "ZIP bulunamadı: $Zip" }
New-Item -ItemType Directory -Path $Root -Force | Out-Null
Expand-Archive -LiteralPath $Zip -DestinationPath $Root -Force
Set-Location -LiteralPath $Root
Get-ChildItem -Name
```

**İndirme dosya adı farklıysa** yalnız `$Zip` değerini değiştir. `Expand-Archive -Force` mevcut aynı adlı dosyaları değiştirebilir; bu komutu yalnız yeni/boş bir `$Root` için kullan.

## 3. Ajanın proje çalışma kökünü seç

Cursor, VS Code/Copilot, Codex, Claude Code veya başka bir dosya erişimli kodlama ajanında **klasör olarak** `C:\Projects\SiberGuvenlik-455Gun` konumunu aç. Ajanın proje dosyalarını gerçekten görebildiğini teyit et. Sadece ChatGPT'nin normal metin sohbetinde prompt vermek, yerel bilgisayardaki klasöre otomatik erişim sağlamaz.

İlk talimat olarak `AJAN_ANA_PROMPT.md` dosyasını ver veya ajanın kalıcı proje talimatlarına ekle. Ardından `SONRAKI_GUN_TETIKLE.md` içindeki **A — İlk gün** komutunu gönder.

**Günler için ayrı kaynak kökü:** `portfolio/hafta_XX/gun_NNN/`; otomasyon durum dosyaları: `ilerleme/`; Excel yedekleri: `yedekler/`. Yardımcı `*.md` sözleşmelerini kaynak olarak oku fakat eğitim projesi veya test verisi olarak başka bir güne kopyalama.

## 4. Excel kaynak haritası ve güvenli yazma

- `365 GÜN`: A = Gün; D = konu; M = durum; O = kanıt; P = hesaplanan kabul; U = gün ID; Y = yürütme kanıt durumu.
- `DERSLER`: A = Gün; dersin ayrıntılı açıklaması, ön bilgi, İngilizce terminoloji, kaynak, tehdit/tespit/önleme.
- `LABORATUVAR`: A = Gün; 5 adımlı uygulama ve negatif test, teslim/kanıt.
- `SORU BANKASI`: B = Gün; yalnız o güne ait hazır soru/yanıtlar.
- `DEĞERLENDİRME`: A = Gün; C:F = 20+40+25+15 puan, G:H = formül.
- `PROJELER`, `PORTFÖY`: ilgili haftalık projeler ve isteğe bağlı gerçek portföy kanıtları.
- `GÜNLÜK KONTROL`: günlük gereksinimler ve otomatik kabul.
- `AI SECURITY`: G337–G350 arasında ek doğrulama.

**Önemli:** Excel'de başlık satırları üstte açıklama satırlarından sonra başlayabilir; **gün numarasını arayarak eşleştir**, konuyu satır numarasından tahmin etme. Excel'in diğer gün kayıtlarını/formüllerini koru; güncellenmiş dosyayı açıp yalnız değiştirilen günün durumunu doğrula. Excel'e bozuk veya hatalı kayıt oluşursa yedekten geri dön.

## 5. Gün örneği (G001 → G002)

1. Ajan G001'i Excel'den okur: *Siber güvenlik nedir ve neyi korur?*.
2. `portfolio/hafta_01/gun_001/` içinde ayrıntılı CIA anlatımı, sentetik okul bilgi sistemi senaryosu, gerekiyorsa offline uygulama/test, üç açıklamalı soru-cevap, rapor ve gerçek kanıt oluşturur.
3. Gerçek kontrolleri çalıştırır; Excel'deki sadece G001 kalite kayıtlarını günceller.
4. **PASS** doğrulanırsa `ilerleme/ajan_durum.json` içine `sonraki_aday_gun: 2` kaydeder.
5. `TEK_GUN`: kullanıcı `SONRAKI_GUN_TETIKLE.md` / B komutunu gönderince G002 başlar. `OTOMATIK_ZINCIR`: ajan destekliyorsa G002'yi aynı oturumda başlatır; her günün dosyaları bağımsız kalır.
6. **HOLD/STOP**: yeni güne otomatik geçilmez; aynı günün raporu ve telafisi bırakılır. Kullanıcı isterse GNNN için telafi (D) komutunu uygular.

## 6. Öğrenci değil, AI ajanı uygulayıcıdır

Ajan şu içerikleri **kendisi** üretir: ayrıntılı Türkçe teori, güvenlik matrisi, insan kalitesinde kod, pozitif ve negatif test, gerçek yürütme kanıtı, soru-cevaplar, rapor ve portföy için dosyalar. Üretilen kodun yapay zekâ tarafından üretildiği gizlenmez. Öğrenciden soru cevaplaması veya programlama yapması beklenmez; kullanıcı kontrol/yetki kararlarını verebilir.

**Güvenlik:** üçüncü taraf IP/ağ/web taraması, izinsiz exploit, gerçek kullanıcı verisi, tehlikeli kötü amaçlı yazılım çalıştırma, kullanıcı bilgisayarında kalıcı güvenlik ayarı değişikliği yasaktır. AI illüstrasyonu gerçek test kanıtı değildir. GitHub'a otomatik push yetkisi bu belgelerle verilmez.

## 7. Eğer ajan otomatik devam edemiyorsa

Ajanın `ilerleme/SONRAKI_GUN_PROMPT.md` dosyasını üretmesini iste. Dosyadaki kısa tetik komutunu bir sonraki ajan mesajına yapıştır. Arka planda çalışan hizmet veya saatli görev kurulmuş sayılmaz. Bu rehber gerçek bir harici scheduler / agent runner kurmaz; böyle bir sistem ayrı kodlanmalı ve kullanıcının yetkisiyle çalıştırılmalıdır.

## 8. Tamamlanma sınırı

365 gün ortak temel bittikten sonra **dur**. G366–G455 yalnızca kullanıcının seçtiği uzmanlık yoluna göre ayrıntılı ders/lab içerikleri Excel'e onaylı biçimde eklendikten sonra başlatılabilir.
