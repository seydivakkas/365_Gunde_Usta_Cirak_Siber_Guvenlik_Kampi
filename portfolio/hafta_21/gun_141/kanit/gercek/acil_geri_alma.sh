#!/usr/bin/env bash
# =============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Gün 141: Acil Durum Geri Alma (Rollback) Betiği
# =============================================================================
set -euo pipefail

echo '[!] DİKKAT: Güvenlik Yaması Geri Alma (Rollback) Protokolü Devrede!'

# Geri Alınıyor: CVE-2024-6387
echo '[*] Eski sürüme dönülüyor: CVE-2024-6387'
apt-get install -y --allow-downgrades openssh-server=1:8.9p1-3ubuntu0.7

# Geri Alınıyor: CVE-2023-4863
echo '[*] Eski sürüme dönülüyor: CVE-2023-4863'
apt-get install -y --allow-downgrades libwebp7=1.2.2-2ubuntu0.1

# Geri Alınıyor: CVE-2024-21626
echo '[*] Eski sürüme dönülüyor: CVE-2024-21626'
apt-get install -y --allow-downgrades runc=1.1.7-0ubuntu1~22.04.1

echo '[+] Geri alma süreci tamamlandı. Servisleri kontrol ediniz.'