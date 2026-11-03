#!/usr/bin/env bash
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Linux Systemd ve Servis Güvenliği Otomatik Sıkılaştırma Betiği
# ==============================================================================
set -euo pipefail

echo '[+] Systemd servis sertleştirme işlemi başlatılıyor...'

# --- 1. Adım: Güvensiz ve Gereksiz Servisleri Kapat / Maskele (CIS) ---
echo '[*] Kapatılıyor ve maskeleniyor: telnet.socket'
systemctl stop telnet.socket 2>/dev/null || true
systemctl disable telnet.socket 2>/dev/null || true
systemctl mask telnet.socket

# --- 2. Adım: Servis Unit ve İkili Dosya İzinlerini Düzelt ---
echo '[*] Unit dosya izinleri düzeltiliyor: /etc/systemd/system/legacy-worker.service'
chown root:root /etc/systemd/system/legacy-worker.service
chmod 0644 /etc/systemd/system/legacy-worker.service
echo '[*] İkili dosya izinleri düzeltiliyor: /opt/worker/bin/run_worker.sh'
chown root:root /opt/worker/bin/run_worker.sh
chmod 0755 /opt/worker/bin/run_worker.sh
echo '[*] İkili dosya izinleri düzeltiliyor: /usr/local/bin/sysmon'
chown root:root /usr/local/bin/sysmon
chmod 0755 /usr/local/bin/sysmon
chmod u-s /usr/local/bin/sysmon

# --- 3. Adım: Systemd Sandboxing Override Yapılandırmalarını Uygula ---
echo '[*] Sandboxing uygulanıyor: nginx.service'
mkdir -p /etc/systemd/system/nginx.service.d
cat << 'EOF' > /etc/systemd/system/nginx.service.d/99-security-hardening.conf
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
EOF
chmod 0644 /etc/systemd/system/nginx.service.d/99-security-hardening.conf
chown root:root /etc/systemd/system/nginx.service.d/99-security-hardening.conf

echo '[*] Sandboxing uygulanıyor: api-backend.service'
mkdir -p /etc/systemd/system/api-backend.service.d
cat << 'EOF' > /etc/systemd/system/api-backend.service.d/99-security-hardening.conf
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
EOF
chmod 0644 /etc/systemd/system/api-backend.service.d/99-security-hardening.conf
chown root:root /etc/systemd/system/api-backend.service.d/99-security-hardening.conf

echo '[*] Sandboxing uygulanıyor: legacy-worker.service'
mkdir -p /etc/systemd/system/legacy-worker.service.d
cat << 'EOF' > /etc/systemd/system/legacy-worker.service.d/99-security-hardening.conf
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
# UYARI: Servis root olarak çalıştırılmaktadır. Ayrılmış bir servis kullanıcısı atayınız:
# User=legacy-worker_svc
# Group=legacy-worker_svc
EOF
chmod 0644 /etc/systemd/system/legacy-worker.service.d/99-security-hardening.conf
chown root:root /etc/systemd/system/legacy-worker.service.d/99-security-hardening.conf

echo '[*] Sandboxing uygulanıyor: debug-monitor.service'
mkdir -p /etc/systemd/system/debug-monitor.service.d
cat << 'EOF' > /etc/systemd/system/debug-monitor.service.d/99-security-hardening.conf
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
EOF
chmod 0644 /etc/systemd/system/debug-monitor.service.d/99-security-hardening.conf
chown root:root /etc/systemd/system/debug-monitor.service.d/99-security-hardening.conf

# --- 4. Adım: Yapılandırmayı Yeniden Yükle ---
echo '[*] Systemd yapılandırmaları yeniden yükleniyor...'
systemctl daemon-reload
echo '[✓] Systemd servis sertleştirme işlemi başarıyla tamamlandı.'