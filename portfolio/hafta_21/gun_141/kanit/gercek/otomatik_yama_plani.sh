#!/usr/bin/env bash
# =============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Gün 141: Otomatik Yama Uygulama ve Aşamalı Dağıtım Betiği
# =============================================================================
set -euo pipefail

echo '[+] Güvenlik Yaması Dağıtım Protokolü Başlatılıyor...'
echo '[+] Hedef Sunucu: srv-prod-app01.corp.internal'

# --- AŞAMA 1: ACİL VE KRİTİK GÜVENLİK YAMALARI (CISA KEV / HIGH CVSS) ---
# CVE: CVE-2024-6387 (Şiddet: HIGH, Aciliyet: EMERGENCY)
echo '[*] Uygulanıyor: CVE-2024-6387'
apt-get update && apt-get install --only-upgrade -y openssh-server=1:8.9p1-3ubuntu0.10

# CVE: CVE-2023-4863 (Şiddet: HIGH, Aciliyet: EMERGENCY)
echo '[*] Uygulanıyor: CVE-2023-4863'
apt-get update && apt-get install --only-upgrade -y libwebp7=1.2.2-2ubuntu0.2

# --- AŞAMA 2: STANDART VE RUTİN GÜVENLİK YAMALARI ---
# CVE: CVE-2024-21626 (Şiddet: HIGH)
apt-get update && apt-get install --only-upgrade -y runc=1.1.7-0ubuntu1~22.04.2

# --- AŞAMA 3: OTOMATİK GÜVENLİK GÜNCELLEMESİ (UNATTENDED UPGRADES) ---
if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
    echo '[*] unattended-upgrades paketi kuruluyor...'
    apt-get update && apt-get install -y unattended-upgrades
fi
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# --- AŞAMA 4: YENİDEN BAŞLATMA GEREKSİNİMİ DENETİMİ ---
if [ -f /var/run/reboot-required ]; then
    echo '[!] UYARI: Çekirdek veya kritik kütüphane güncellendi. Sistem yeniden başlatma bekliyor!'
    cat /var/run/reboot-required.pkgs 2>/dev/null || true
fi

echo '[+] Yama uygulama süreci başarıyla tamamlandı.'