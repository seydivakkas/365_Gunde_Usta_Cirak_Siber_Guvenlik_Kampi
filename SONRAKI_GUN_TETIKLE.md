# Tetik Komutları (kopyala-yapıştır)

Önce ajana `AJAN_ANA_PROMPT.md` dosyasını kalıcı talimat olarak ver. Excel aynı klasörde olmalı.

## A — İlk gün (G001)
> `AJAN_ANA_PROMPT.md`'yi oku ve uygula. Excel'den Gün=1'i bul. Hoca Dersi standardıyla (7 bölümlü ders.md, gerçek lab kodu, pozitif/negatif test, gerçek kanıt, soru-cevap, rapor) G001'i sıfırdan üret. Kalite kapısını gerçek kanıtla doğrula, sadece G001'i Excel'e işle, sonuc.json ve ilerleme/ajan_durum.json yaz. MOD=TEK_GUN. PASS ise G002 komutunu ver, otomatik başlatma.

## B — Sonraki gün
> SONRAKİ GÜNE GEÇ. `AJAN_ANA_PROMPT.md`'yi uygula. Önce ilerleme/ajan_durum.json, son sonuc.json, kanıtlar ve Excel tutarlı mı doğrula; önceki gün PASS değilse dur. PASS ise sonraki_aday_gun'u Hoca Dersi standardıyla sıfırdan üret, doğrula, Excel'e yalnız bu günü işle. MOD=TEK_GUN.

## C — Otomatik zincir (en fazla 3 gün)
> OTOMATİK_ZİNCİR. `AJAN_ANA_PROMPT.md`'yi uygula. İlerleme kaydındaki sonraki_aday_gun'dan (yoksa G001) başla. Her gün ayrı klasör, ayrı PASS kapısı. PASS → sıradaki gün; HOLD/STOP → dur. En fazla 3 gün, son gün 365. Otomatik devam desteklenmiyorsa ilerleme/SONRAKI_GUN_PROMPT.md yaz, "başlatıldı" deme.

## D — HOLD günü düzelt
> GÜNÜ_YENİDEN_DENE: HOLD olan GNNN'i seç. Yalnız o günün dosyalarını düzelt, testleri yeniden çalıştır, eski başarısız sonuçları silmeden düzeltme izini ekle, gerçek kanıta göre sonuc.json ve Excel'i güncelle. Yeni günü başlatma.

## E — 365. gün kapanışı
> G365_KAPANIŞI: Tamamlanan/HOLD kalan günlerin envanterini, portföy bağlantılarını, kalan riskleri ve uzmanlık yolu seçeneklerini raporla. Uzmanlık seçilip Excel'e eklenmeden G366'ya geçme.
