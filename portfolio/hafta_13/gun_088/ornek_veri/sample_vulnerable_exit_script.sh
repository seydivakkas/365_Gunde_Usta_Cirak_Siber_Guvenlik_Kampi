#!/bin/sh
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# G088: Güvenlik Zaafiyetleri İçeren Örnek Betik (Denetim Amaçlı)
# ZAAFİYET 1: Katı mod yok (Hatalar görmezden gelinir)

DB_PASSWORD="SuperSecretAdminPass123!"

# ZAAFİYET 2: Hata akışını tamamen yutma (CWE-390: Silent Error Suppression)
# Kritik ağ hatası oluşsa bile 2> /dev/null ile gizlenir, çıkış kodu kontrol edilmez
curl -s http://internal.database/connect 2> /dev/null

# ZAAFİYET 3: Hata akışına (stderr) açık metin kimlik bilgisi sızdırma (CWE-209 / CWE-532)
echo "HATA: Veritabanı bağlantısı kurulamadı. Parola: $DB_PASSWORD" >&2

# ZAAFİYET 4: Çıkış kodunu denetlemeden kritik işleme devam etme
tar -czf backup.tar.gz /non_existent_folder

# ZAAFİYET 5: Önceki tüm adımlar çökse dahi yanıltıcı başarılı çıkış (exit 0) dönme
echo "Yedekleme bitti!"
exit 0
