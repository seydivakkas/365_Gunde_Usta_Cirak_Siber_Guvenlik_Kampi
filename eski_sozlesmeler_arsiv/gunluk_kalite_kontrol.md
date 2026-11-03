# gunluk_kalite_kontrol.md — AI ajanı kalite kapıları ve telafi sözleşmesi

## Amaç ve aktörler

Bu belge **öğrenci sınavı** veya uygulamalı kabul sınavı tanımlamaz. Konu anlatımını, kodu, simülasyonu, hazır soru-cevapları ve kanıtlı kalite özetini **AI ajanı** hazırlar. Kullanıcı isterse raporları gözden geçirir; gerçek Windows bilgisayarında yürütme gerekli olup yapılamamışsa durum `HOLD` kalır.

## 1. Günlük kalite rubriği (100 puan)

| Ölçüt | Üst sınır | Somut değerlendirme |
|---|---:|---|
| AI soru-cevaplarının ve açıklamanın doğruluğu | 20 | En az üç doğru, gerekçeli soru-cevap; tanım, mekanizma, yanlış anlama, kaynak |
| Gerçek yerel uygulama / gerçekten yürütülmüş simülasyon | 40 | Bağımsız çalışır kod/işlem, pozitif test, negatif test, güvenlik sınırı |
| Gerçek doğrulanabilir kanıt | 25 | Komut, test logu, kaynak belge incelemesi, hash, çıktı eşleştirme, tarih/sürüm |
| Teknik rapor | 15 | Kapsam, yöntem, bulgu, risk/tespit/savunma, sınırlama, yeniden üretilebilirlik |
| **Toplam** | **100** | **En az 80 ve alt eşikler ile PASS adayı** |

Minimum ek koşullar: uygulama ≥24/40; gerçek kanıt ≥15/25; etik kapsam uygun; gün kendi kendine çalışır; Excel'de `Kanıt=Evet`; `Yürütme kanıtı = Yerel çalıştırıldı` **veya** belge odaklı bir gün için `Belge doğrulandı`.

**Sadece AI illüstrasyonu**, uydurulmuş terminal çıktısı veya çalıştırılmamış simülasyon **PASS olamaz**. Puanların otomatik doldurulması yalnızca gerçek araç çıktısı/denetimi mevcutsa yapılır; sırf ajanın kendi metnini beğenmesi yetmez.

## 2. Ajanın sorumlu olduğu hazır soru-cevaplar

Normal gün: üç soru (kavram, mekanizma, risk/tespit/savunma) ve her biri için doğru yanıt + gerekçe + kaynak + yaygın hata. Haftalık proje: bunlara en fazla üç senaryo soru-cevap eklenebilir. **Kullanıcıdan cevap istenmez**, not kullanıcıya sınav olarak verilmez.

Yetersiz yanıt varsa AI ajanı **aynı günün** `soru_cevap.md` dosyasını düzeltir. Başka günün dosyasından kopyalayarak tamamlamaz.

## 3. Kalite karar makinesi

```text
if etik_sinir_ihlali: STOP
elif onkosul_dogrulanmadi: HOLD:PREREQ
elif gunler_arasi_kod_veri_devri: HOLD:BOUNDARY
elif gercek_yurutme_yok and belge_dogrulama_yok: HOLD:RUN
elif sadece_temsili_ai_gorseli: HOLD:VISUAL_ONLY
elif puan_veya_kanıt_yetersiz: HOLD:EVIDENCE
elif sure_icin_kapsam_asildi: HOLD:TIME
else: PASS
```

Yalnız açıklayıcı belge/risk matrisi üretilen günlerde **belgenin gerçekten oluşturulmuş ve içerik açısından kontrol edilmiş** olması `Belge doğrulandı` koşulunun temelidir. Teknik kod/simülasyon gerekli günlerde görsel veya soyut belge, yürütme kanıtının yerini alamaz.

## 4. Kanıt güvencesi

- Test logunda gerçek `command`, `timestamp` (varsa), `exit_code`, test sayısı, başarısız test sayısı, kaynak dosya yolu yer alır.
- **NOT_RUN** ile **PASS** aynı şey değildir. Hata durumları `HOLD` veya `FAIL` olarak dürüstçe yazılır.
- Testin sentetik koşulları ve gerçek dünya sınırları mutlaka raporlanır. Gerçek sistemi sınamayan simülatör ile gerçek sistemin güvenli olduğu iddia edilmez.
- Üçüncü taraf sisteme izinsiz tarama, PII veya gerçek sır sızıntısı `STOP` nedenidir.
- AI görseli her zaman temsili dizindedir ve gerçek ekran görüntüsü olarak sunulamaz.

## 5. Haftalık, aylık ve aşama kalite özeti

- **Her 7. gün:** bağımsız tek günlük mini proje; ajan gerçek çıktı, test, rapor ve eksikleri özetler. Uygulamalı sınav yok.
- **30 günlük aralıklar:** tamamlanan, HOLD kalan, telafi gerektiren kavramların kalite raporu; eksik projeler sonraki güne devredilmez.
- **14 aşama kapanışı:** günlük işlerden zorunlu kod/servis devralmadan, bağımsız kalite matrisi (gerçek kanıtlar referans verilebilir; günün çalışması yine tek başına yürür).
- **365. gün:** 365 günün portföy ve teknik gelişim indeksini oluşturur; yeni bağımsız örnek ve genel kalite raporu hazırlanır. Bu bir uygulamalı kabul sınavı değildir.
- **455. gün:** sonraki 90 günlük uzmanlık yolu seçildiğinde, aynı kalite sözleşmesiyle kapatılır.

## 6. Aralıklı tekrar uygulaması (1/7/30/90 gün)

Örneğin gün 100 için kavramsal hatırlatma adayları gün 99, 93, 70 ve 10 başlıklarıdır. En çok 10 dakikada birer temel kavram kartı gözden geçirilir. **Önceki günün oluşturduğu proje, modül, kaynak dosya, data veya görev devralınmaz**. Konu hatırlatması gün 100'ün temel görevini değiştirmez.

Kavram yeterliliği eksikse o gün kısa açıklama yapılır; asgari şart karşılanmıyorsa `HOLD:PREREQ`. Eksik çalışma için aynı günün klasöründe `telafi.md` açılabilir. Başka güne otomatik aktarılmaz.

## 7. Excel ile birebir eşleştirme

| Excel sayfası/alan | İşlev |
|---|---|
| `365 GÜN!M` | Çalışma durumu |
| `365 GÜN!O` | Gerçek kanıt mevcut mu? |
| `365 GÜN!Y` | Yerel çalıştırıldı / Belge doğrulandı / Temsilî görsel / Bekliyor |
| `365 GÜN!P` | Gerçek puan ve kanıt koşullarına göre formül PASS/HOLD |
| `DEĞERLENDİRME!C:F` | 20 + 40 + 25 + 15 somut kalite puanı |
| `DEĞERLENDİRME!G:H` | Otomatik toplam / yeterlilik-telafi |
| `GÜNLÜK KONTROL!N` | `365 GÜN!P` sonucu ile eşlenir |
| `SİMÜLASYON` | Gerçek → sentetik → temsili seçenekleri |
| `PROJELER` ve `PORTFÖY` | Haftalık bağımsız kaynak/kanıt teslimleri |

## 8. Gün sonu raporu şablonu

```markdown
# GNNN — Kalite özeti
- [ ] 90 dakika bütçesi takip edildi.
- [ ] Ön koşul aynı gün doğrulandı.
- [ ] Başka günden kod/veri/yarım görev alınmadı.
- [ ] Kavram, mekanizma, 2 örnek ve 2 hata anlatıldı.
- [ ] İngilizce-Türkçe terimler ve risk/tespit/önlem var.
- [ ] AI en az 3 hazır soru-cevap yazdı.
- [ ] Gerçek uygulama veya belge doğrulaması kanıtlandı.
- [ ] Pozitif ve negatif test / belge karşılaştırması var.
- [ ] Görseller gerçek/temsili doğru etiketlendi.
- [ ] Güvenlik ve hukuk sınırı ihlal edilmedi.
- Puan: __/100 (kanıta dayalı değilse boş bırak)
- Karar: PASS / HOLD:... / STOP
- Kanıt yolları:
- Eksikler:
- Sonraki güne aktarılacak çalışma: **YOK**
```
