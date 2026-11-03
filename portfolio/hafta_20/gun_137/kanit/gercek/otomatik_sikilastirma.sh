#!/usr/bin/env bash
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Linux SSH Anahtar ve Sunucu Güvenliği Otomatik Sıkılaştırma Betiği
# ==============================================================================
set -euo pipefail

echo '[+] SSH güvenlik sertleştirmesi başlatılıyor...'

# --- 1. Adım: SSH Dosya ve Dizin İzinlerini Düzelt ---
echo '[*] Özel anahtar izinleri kilitleniyor: /home/legacy_user/.ssh/id_dsa'
chmod 0600 /home/legacy_user/.ssh/id_dsa
chown legacy_user:legacy_user /home/legacy_user/.ssh/id_dsa 2>/dev/null || chown root:root /home/legacy_user/.ssh/id_dsa
echo '[*] authorized_keys izinleri kilitleniyor: /home/legacy_user/.ssh/authorized_keys'
chmod 0600 /home/legacy_user/.ssh/authorized_keys
chown legacy_user:legacy_user /home/legacy_user/.ssh/authorized_keys 2>/dev/null || chown root:root /home/legacy_user/.ssh/authorized_keys

# --- 2. Adım: sshd_config CIS Standartlarında Sıkılaştırma ---
SSHD_CONFIG='/etc/ssh/sshd_config'
BACKUP_CONFIG="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
cp "$SSHD_CONFIG" "$BACKUP_CONFIG"
echo "[*] sshd_config yedeği alındı: $BACKUP_CONFIG"

# Güvenlik direktiflerini uygula
sed -i -E 's/^#?PermitRootLogin .*/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i -E 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' "$SSHD_CONFIG"
sed -i -E 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
sed -i -E 's/^#?PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
sed -i -E 's/^#?X11Forwarding .*/X11Forwarding no/' "$SSHD_CONFIG"
sed -i -E 's/^#?MaxAuthTries .*/MaxAuthTries 3/' "$SSHD_CONFIG"
sed -i -E 's/^#?ClientAliveInterval .*/ClientAliveInterval 300/' "$SSHD_CONFIG"
sed -i -E 's/^#?ClientAliveCountMax .*/ClientAliveCountMax 2/' "$SSHD_CONFIG"

# Dosya izinlerini kovala
chown root:root "$SSHD_CONFIG"
chmod 0600 "$SSHD_CONFIG"

# Yapılandırma sözdizimini doğrula ve servisi yeniden yükle
if sshd -t; then
    echo '[*] sshd yapılandırma sözdizimi doğrulandı. Servis yeniden yükleniyor...'
    systemctl reload sshd || systemctl reload ssh
    echo '[✓] SSH sunucusu başarıyla sertleştirildi.'
else
    echo '[-] HATA: sshd sözdizimi hatalı! Yedek geri yükleniyor...'
    cp "$BACKUP_CONFIG" "$SSHD_CONFIG"
    exit 1
fi