# Kurulum (3 adım)

1. Boş bir klasör aç: `C:\Projects\SiberGuvenlik-455Gun`. İçine şunları koy:
   - `AJAN_ANA_PROMPT.md`
   - `SONRAKI_GUN_TETIKLE.md`
   - `Siber_Guvenlik_455_Gun_Mufredat_365_Gun_Guncellenmis.xlsx`
2. Dosya erişimi olan bir kodlama ajanında (Claude Code, Cursor, Codex vb.) bu klasörü aç. Normal sohbet penceresi klasöre erişemez.
3. `AJAN_ANA_PROMPT.md`'yi kalıcı talimat yap, sonra `SONRAKI_GUN_TETIKLE.md` içindeki **A** komutunu gönder.

Ajan şu klasörleri kendisi oluşturur: `portfolio/`, `ilerleme/`, `yedekler/`.

Günlük kullanım: PASS gelince **B** komutunu gönder. HOLD gelirse **D** komutu.

Notlar:
- Eski dosyalar (`standart_gun.md`, `HOCA_DERSI_STANDARDI.md`, `ai_security_ek.md`, `gun_050_ornek.md` vb.) artık gerekmez; tüm kurallar `AJAN_ANA_PROMPT.md` içindedir. Bu dosyalar klasörde durursa ajanın kafası karışır, taşı veya sil.
- Excel'in diğer sayfaları (`DERSLER`, `LABORATUVAR`, `SORU BANKASI` vb.) aynen kalır.
