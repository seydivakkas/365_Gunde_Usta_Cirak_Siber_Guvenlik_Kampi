# simulasyon_ve_gorsel.md — Yerel laboratuvar ve AI görsel standardı

**Üst sözleşme:** `standart_gun.md`. **Amaç:** Kullanıcıya uygulamalı sınav yaptırmak yerine AI ajanın kontrollü, aşamalı teknik gösterim hazırlaması.

## 1. Karar ağacı

1. **İzin + yerel araç + güvenli çalıştırma mevcut mu?** Evet → izinli yerel laboratuvar/VM/loopback'te gerçek çalıştırma. Log, komut, sürüm, çıkış kodu, test raporunu kaydet.
2. Hayır → **aynı olguyu sentetik veriyle yerel PC'de simüle etmek mümkün mü?** Evet → Python stdlib/PowerShell ile deterministik simülasyon, gerçek çalışma sonucu, iki test; mod `SENTETİK_SIMÜLASYON`.
3. Hayır → **adım adım öğretim görseli veya şeması** hazırla, açıkça `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` etiketle. Komut çalıştırma kanıtı, zafiyet doğrulaması veya PASS iddiası üretme; `HOLD:GÖRSEL`.
4. **Kapsam dışı bir kaynak veya kişisel veri gerekiyor mu?** Evet → denemeyi durdur, sentetik alternatife geç; izinsiz hedefe erişme.

## 2. İzolasyon ilkeleri

- Windows ana makine üzerinde salt-okunur gözlem; riskli yapılandırmayı yalnız geri döndürülebilir VM'de yap. Snapshot gerçek yedek yerine geçmez.
- Ağ deneyleri loopback `127.0.0.1` ve `::1` veya izole host-only VM ağı üzerinde yapılır. Dış IP ve üçüncü taraf servis taranmaz.
- Web güvenliği yerel eğitim amaçlı uygulamada; gerçek kurumsal müşteri API'si veya erişim anahtarı kullanılmaz.
- SOC/DFIR örnekleri sentetik log, PCAP, dosya meta verisi ve sahte olay kimliklerinden oluşur.
- Zararlı yazılım için yalnız **inert dosya / zararsız demo örneği**; bilinmeyen zararlı ikili çalıştırma yok.
- AI güvenlik için bulut/LLM API zorunlu değildir: yerel statik mock, test fikstürü ve policy-check tercih edilir.

## 3. Beş adımlı laboratuvar anlatımı

Her gerçek veya simüle uygulama için:

| Adım | Açıklama | İşaretlenen kanıt |
|---|---|---|
| 1. Hazırlık | Amaç, izin, sürüm, klasör, sentetik veri | `01_hazirlik.md` |
| 2. Başlangıç | Girdi, mevcut durum, beklenen davranış | `02_girdi.json` veya açıklama |
| 3. Uygulama | Gerçek komut veya çalıştırılan simülatör kodu | Gerçek terminal çıktısı / test logu |
| 4. Negatif kontrol | Hatalı girişte güvenli cevap ve neden | Test sonucu (PASS/FAIL/NOT_RUN) |
| 5. Raporlama | Bulgular, sınırlama, temizleme/geri dönüş | `rapor.md` ve `sonuc.json` |

## 4. AI görsel üretilecekse

Her görselin adı: `gun_NNN_adim_01_temsili.png` vb. Görselin içine yerleştirilecek ibare:

> **TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL**

Önerilen 3–5 kare:
- Hazırlık ve güvenlik sınırları; ortam ikonları.
- Girdi/parametrelerin açıklaması.
- Protokol/algoritmanın gerçeğe uygun işlem sırası.
- Pozitif ve olumsuz örneğin şematik karşılaştırılması.
- Risk, tespit, önlem ve beklenen sonuç.

Görselde uydurma zaman damgası, sahte gerçek kullanıcı adı/IP, var olmayan araç çıktısı, 'tarandı/istismar edildi/başarı sağlandı' gibi gerçek test iddiaları gösterilmez. İstenirse tamamen hayalî örnek adresler için belgelemeye ayrılmış `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) tercih edilebilir; bunlar tarama hedefi olarak **kullanılmaz**.

## 5. Kanıt güven seviyesi

| Seviye | Kaynak | Kabul durumu |
|---|---|---|
| E1 | Gerçek izinli yerel uygulama + olumlu/olumsuz test | Diğer koşullar sağlanırsa PASS adayı |
| E2 | PC'de gerçekten çalıştırılmış deterministik sentetik simülatör + test | Kısıtları yazılırsa PASS adayı |
| E3 | Kaynağı incelenmiş, doğrulanabilir teknik belge/diyagram/risk matrisi | Belge ağırlıklı günlerde PASS adayı |
| E4 | AI ile üretilmiş açıklamalı temsili görsel | **Öğretim için uygun; tek başına PASS değil** |
| E0 | Kod veya testin çalıştırılmadığı / kaynağın doğrulanmadığı iddia | HOLD |

Herhangi bir görsel, başlı başına `E1` veya `E2` kanıtı olmaz. Bir simülasyonun *görünümünü* çizmek, simülasyonu çalıştırmak değildir.

## 6. Gün 50 için doğru örnek (TCP 3 yönlü el sıkışma)

1. **Ön bilgi:** TCP/IP katmanları, bağlantı, istemci-sunucu ve port kavramı aynı gün özetlenir; gün 49 dosyası kullanılmaz.
2. **Gerçek yerel senaryo:** Yalnızca `127.0.0.1` üzerinde açılan yerel sunucu/istemci, uygun araç bulunursa gerçek ağ yakalaması; SYN, SYN-ACK, ACK bayraklarının sırası gösterilir. İşletim sistemi/loopback yakalama kısıtları belirtilir.
3. **Offline simülasyon:** Ağ yakalama yapılamazsa, 3 TCP kontrol bayrağını ve durum geçişini temsil eden **deterministik protokol eğitim simülatörü** çalıştırılır. Bu paket yakalama değildir; modelleme olarak etiketlenir.
4. **Negatif kontrol:** Beklenmeyen ACK sırası kabul edilmeyip reddedilir; beklenen/gerçek sonuç saklanır.
5. **Yalnız görsel:** Yukarıdaki modeller çalıştırılamıyorsa 4 adımlı paket akış illüstrasyonu çizilir, ancak test PASS yazılmaz.

Dersin ayrıntılı temsili için `gun_050_ornek.md` dosyasına bak.
