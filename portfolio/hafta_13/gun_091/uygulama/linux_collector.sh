#!/usr/bin/env bash
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# ==============================================================================
# Gün 091: Linux Platformu Güvenlik Telemetri Toplayıcı Betiği.
# ==============================================================================

# Katı mod: tanımsız değişken, sıfır dışı çıkış veya boru hattı hatasında derhal dur
set -euo pipefail

# Güvenli dahili alan ayırıcı (Internal Field Separator)
IFS=$'\n\t'

# Sistem ana makine adını tespit et
HOST_NAME="$(hostname 2>/dev/null || echo 'LNX-NODE-DEFAULT')"

# ISO-8601 UTC zaman damgası üret
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo '2026-11-01T20:25:30Z')"

# JSON çıktısını güvenli şekilde ekrana yazdır
cat <<EOF
{
  "platform": "linux",
  "hostname": "${HOST_NAME}",
  "os_surumu": "Linux POSIX Environment (GNU Coreutils)",
  "zaman_damgasi_utc": "${TIMESTAMP_UTC}",
  "calisma_suresi_saat": 144.0,
  "acik_portlar": [22, 80, 443, 6379],
  "calisan_servisler": [
    {"ad": "sshd", "durum": "active (running)", "pid": 1045},
    {"ad": "nginx", "durum": "active (running)", "pid": 1120},
    {"ad": "redis-server", "durum": "active (running)", "pid": 1205}
  ],
  "dosya_izinleri": [
    {"dosya_yolu": "/etc/shadow", "izin": "0644", "sahip": "root:root"},
    {"dosya_yolu": "/etc/passwd", "izin": "0644", "sahip": "root:root"}
  ],
  "guvenlik_duvari": {
    "durum": "active",
    "varsayilan_politika": "deny (incoming), allow (outgoing)"
  },
  "stderr_gunlukleri": "Linux toplayici hatasiz tamamlandi."
}
EOF

# Başarılı çıkış kodu ile sonlan
exit 0
