#!/usr/bin/env bash
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# UFW (Uncomplicated Firewall) CIS Uyumlu Hızlı Sertleştirme Betiği
# ==============================================================================
set -euo pipefail

echo '[*] UFW kuralları yapılandırılıyor...'
# UFW'yi varsayılan ayarlara sıfırla
ufw --force reset

# Varsayılan politikalar: Gelen DROP, Yönlendirilen DROP, Giden ACCEPT (CIS 3.5.2)
ufw default deny incoming
ufw default deny routed
ufw default allow outgoing

# SSH erişimini rate-limit ile güvene al (Kaba kuvvet koruması)
ufw limit 22/tcp comment 'SSH Rate Limited'

# Meşru Web portlarına izin ver
ufw allow 80/tcp comment 'HTTP Web'
ufw allow 443/tcp comment 'HTTPS Web'

# Güvenlik duvarı loglamasını aç (CIS 3.5.1)
ufw logging on

# UFW'yi etkinleştir
ufw --force enable
echo '[✓] UFW güvenlik duvarı başarıyla kilitlendi ve aktif edildi.'
ufw status verbose