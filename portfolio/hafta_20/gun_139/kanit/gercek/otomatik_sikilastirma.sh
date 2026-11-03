#!/usr/bin/env bash
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Linux Audit ve Journal Güvenliği Otomatik İyileştirme Betiği
# ==============================================================================
set -euo pipefail

echo '[+] Audit ve Journald güvenlik sertleştirmesi başlatılıyor...'

# --- 1. Adım: audit.rules Yapılandırmasını Uygula ---
cat << 'EOF' > /etc/audit/rules.d/audit.rules
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# CIS Linux Benchmark v2.0.0 Uyumlu Kurumsal audit.rules Şablonu
# ==============================================================================
# Önceki kuralları temizle
-D
# Tampon bellek sınırını artır (Yoğun olay trafiği için)
-b 8192
# Hata durumunda sistem aksiyonu (1 = printk uyarı, 2 = panic)
-f 1

# --- 1. Kritik Kimlik ve Kullanıcı Dosyaları (CIS 4.1.4) ---
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# --- 2. Ayrıcalık Devri ve Sudo Yapılandırması (CIS 4.1.14) ---
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# --- 3. PAM Kimlik Doğrulama Modülleri (CIS 4.1.13) ---
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k pam

# --- 4. Zaman Manipülasyonu Syscall Denetimi (CIS 4.1.3) ---
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change

# --- 5. Çekirdek Modülü Yükleme/Çıkarma Syscall Denetimi (CIS 4.1.16) ---
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules

# --- 6. Yetkisiz Başarısız Dosya Erişimleri (EACCES/EPERM) (CIS 4.1.10) ---
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access

# --- 7. Kuralları Yeniden Başlatma Olmaksızın Değiştirilemez Kıl (CIS 4.1.18) ---
# DİKKAT: -e 2 eklendiğinde kurallar sunucu reboot edilmeden silinemez!
-e 2
EOF
chmod 0640 /etc/audit/rules.d/audit.rules
chown root:root /etc/audit/rules.d/audit.rules

# --- 2. Adım: auditd.conf Ayarlarını Sıkılaştır ---
AUDITD_CONF='/etc/audit/auditd.conf'
if [ -f "$AUDITD_CONF" ]; then
    sed -i 's/^space_left_action =.*/space_left_action = email/' "$AUDITD_CONF"
    sed -i 's/^admin_space_left_action =.*/admin_space_left_action = halt/' "$AUDITD_CONF"
    sed -i 's/^disk_full_action =.*/disk_full_action = halt/' "$AUDITD_CONF"
    sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' "$AUDITD_CONF"
fi

# --- 3. Adım: journald.conf Yapılandırmasını Uygula ---
cat << 'EOF' > /etc/systemd/journald.conf
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# CIS Linux Benchmark v2.0.0 Uyumlu Kurumsal journald.conf Şablonu
# ==============================================================================
[Journal]
# Logların diske kalıcı olarak yazılması zorunludur (CIS 4.2.1.2)
Storage=persistent
# Log dosyalarının sıkıştırılması
Compress=yes
# Forward Secure Sealing (FSS) ile kriptografik mühürleme (CIS 4.2.1.3)
Seal=yes
# Logların Syslog / SIEM sistemine iletilmesi
ForwardToSyslog=yes
# Maksimum disk kullanım sınırı
SystemMaxUse=2G
SystemKeepFree=1G
# Hız sınırlaması (Log flood saldırılarına karşı)
RateLimitIntervalSec=30s
RateLimitBurst=10000
EOF
chmod 0644 /etc/systemd/journald.conf
chown root:root /etc/systemd/journald.conf

# --- 4. Adım: Servisleri Etkinleştir ve Yeniden Yükle ---
systemctl enable auditd
systemctl restart auditd || service auditd restart
systemctl restart systemd-journald
augenrules --load || true
echo '[✓] Audit ve Journald servisleri başarıyla sertleştirildi ve devreye alındı.'