# Gün 050 — TCP üçlü el sıkışma (bağımsız ders kartı örneği)

**Aşama:** 03 — Ağlar ve Protokol Analizi  
**Düzey:** Başlangıç / Orta  
**Süre:** 90 dakika (10 + 25 + 40 + 10 + 5)  
**Üretici:** AI ajanı  
**Gün sınırı:** Gün 49'dan veya başka bir günden **hiçbir kod, dosya, veriset, rapor, çalışan servis alınmaz**.  
**Güvenlik:** Sadece yerel model/simülasyon veya yetkili loopback. Üçüncü taraf trafik yakalama yok.

## 1. Ön koşul ve 10 dakikalık kavram hatırlatma

Ajan, TCP/IP katmanlarının veri iletimi görevini, istemci–sunucu ayrımını, IP adresinin cihazı ve portun uygulama uç noktasını temsil ettiğini kısaca anlatır. Önceki günün içeriği yalnızca kavram hatırlatması olabilir; onun çıktısı gerekmez. Kavramlar açıklanamıyorsa gün `HOLD:PREREQ` olur.

## 2. Ayrıntılı ders ve mekanizma — 25 dakika

TCP (*Transmission Control Protocol*, İletim Kontrol Protokolü) güvenilir ve sıralı bayt akışı sağlayan, bağlantı yönelimli bir taşıma katmanı protokolüdür. İletişim iki uç arasındaki sıra ve onay numaralarının eşgüdümüyle kurulur. Normal üç yönlü el sıkışmada:

1. **SYN:** İstemci kendi başlangıç sıra numarasını (ISN) önerir.
2. **SYN-ACK:** Sunucu SYN'i onaylar (`ack = client_isn + 1`) ve kendi ISN'sini gönderir.
3. **ACK:** İstemci sunucunun SYN'ini onaylar (`ack = server_isn + 1`).

Bu kontrol bayraklarının görünmesi, **uygulama katmanının kimlik doğruladığını veya TLS güvenliği bulunduğunu kanıtlamaz**. Paket kaybı, yeniden iletim, kurulu soket durumu, sıradışı ağ cihazları ve protokol ayrıntıları gerçek yakalamada farklı gözlemler doğurabilir. Eğitimde kullanılan küçük durum modeli gerçek bir TCP stack değildir.

**Teknik terimler:** SYN (*Synchronize*, sıra eşleme isteği), ACK (*Acknowledgment*, onay bayrağı), ISN (*Initial Sequence Number*, başlangıç sıra numarası), TCP (*Transmission Control Protocol*, iletim kontrol protokolü), socket (IP+port bağlamlı iletişim uç noktası).

**Risk:** Trafikte SYN görülmesinin tek başına doğrulanmış istemci kimliği sayılması veya paket sırası yanlış yorumlanması.  
**Tespit:** Paket sıra numarası, onay numarası ve bayrak tutarlılığı.  
**Savunma:** TCP üstünde uygun uygulama kimlik doğrulama/TLS, bağlantı sınırlandırması ve açıklanabilir trafik analizi.

## 3. Bağımsız yerel laboratuvar / simülasyon — 40 dakika

Ajanın bu örnek için ürettiği gerçek kod ve test dosyaları, ayrı klasördedir:

```text
gun_050_ornek/
├── uygulama/tcp_handshake_sim.py
├── tests/test_handshake_sim.py
└── kanit/test_sonuclari.txt
```

Windows'ta Python 3 kuruluysa PowerShell komutları:

```powershell
cd .\gun_050_ornek
py -3 .\uygulama\tcp_handshake_sim.py
py -3 -m unittest discover -s .\tests -v
```

Beklenen eğitim modeli sıralaması: `SYN → SYN+ACK → ACK`; olumlu test bunu kabul eder. Negatif testte yanlış ACK veya eksik paket reddedilir. Program ağ paketi üretmez, port açmaz, `127.0.0.1` bağlantısı kurmaz; yalnız **deterministik eğitim modelidir**.

Alternatif olarak kullanıcının bilgisayarında izinli loopback trafik yakalama ortamı varsa, Wireshark ile gerçek TCP bağlantısının adımları gözlemlenebilir. Bu örnekte **gerçek Wireshark/Windows testi yapılmış değildir**. Gerçek ekran yakalama olmayan durumda AI tarafından dört adımlı temsili şema hazırlanabilir; `TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL` etiketi zorunludur.

## 4. Doğrulama ve raporlama — 10 dakika

Bu dosya oluşturulurken mevcut çalışma ortamında (**Linux/Python**, kullanıcının Windows bilgisayarı değil) bağımsız örnek çalıştırıldı ve `unittest` ile **5/5 test PASS** sonucu alındı. Gerçek test kaydı `gun_050_ornek/kanit/test_sonuclari.txt` içindedir. Windows ve gerçek ağ yığını ile fiziksel kabul **yapılmadı**.

Olumlu doğrulama: üç paket ve onay numarası eşleşmesi. Negatif doğrulama: yanlış ACK/eksik paket reddi; geçersiz ISN girdi hatası. Kısıt: kod gerçek TCP handshake trafiğini analiz etmez veya üretmez.

## 5. Ajanın hazırladığı soru-cevap — 5 dakika

**S1: TCP neden üç yönlü el sıkışma kullanır?**  
**Yanıt:** Her iki tarafın bağlantı başlatma niyeti ve ilk sıra numaraları karşılıklı onaylanır. İstemci SYN gönderir; sunucu SYN-ACK döndürür; istemci ACK ile onaylar. Bu alışveriş, uygulama kimlik doğrulaması veya TLS şifrelemesi anlamına gelmez.

**S2: Örnek istemci ISN=100 ve sunucu ISN=200 iken hangi ACK numaraları beklenir?**  
**Yanıt:** Sunucu SYN-ACK paketinde 101'i, istemci son ACK paketinde 201'i onaylar. Eğitim örneğinde SYN, sıra alanında bir birim tüketir; 32-bit modüler aritmetik kullanılır.

**S3: Bozuk bir ACK nasıl saptanır, koruma nasıl düşünülür?**  
**Yanıt:** Beklenen `server_isn + 1` onay değeriyle gelen ACK karşılaştırılır; uyuşmayan model girdisi reddedilir. Gerçek sistemde ek sıra/pencere/doğrulama kuralları vardır; bu demo bunların yerine geçmez.

## 6. Gün sonu sınırı

- AI soru-cevapları yazmıştır; kullanıcıya sınav yoktur.
- Çalışan gerçek, bağımsız örnek kod ve pozitif/negatif test mevcuttur (yalnız oluşturma ortamında test edilmiş).
- Bu eğitim modelinden canlı ağda TCP güvenliğinin kanıtlandığı sonucu çıkarılamaz.
- Gün 51 bu dosyaların **hiçbirine** bağlı değildir. Sonraki güne aktarılacak iş: **YOK**.

**Kaynak:** https://www.rfc-editor.org/rfc/rfc9293 , https://www.wireshark.org/docs/
