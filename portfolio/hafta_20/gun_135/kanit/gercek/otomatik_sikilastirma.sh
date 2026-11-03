#!/bin/bash
# ===========================================================================
# Linux PAM ve Oturum Politikası Otomatik Sıkılaştırma Betiği
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) - Tüm Hakları Saklıdır
# ===========================================================================
set -euo pipefail

echo '[*] Linux PAM ve Oturum Güvenliği Sıkılaştırma Başlatılıyor...'

# 1. PAM Dosya İzinlerinin Sıkılaştırılması
chown -R root:root /etc/pam.d/ /etc/security/
chmod 0755 /etc/pam.d/ /etc/security/
find /etc/pam.d/ -type f -exec chmod 0644 {} +
find /etc/security/ -type f -exec chmod 0644 {} +
echo '[+] PAM ve security dosyaları 0644 (root:root) olarak mühürlendi.'

# 2. Oturum Zaman Aşımı (TMOUT = 900s / 15 dk)
cat << 'EOF' > /etc/profile.d/timeout.sh
# Oturum Inactivity Zaman Asimi (CIS Kurali)
readonly TMOUT=900
export TMOUT
EOF
chmod 0644 /etc/profile.d/timeout.sh
echo '[+] Oturum zaman aşımı (TMOUT=900) /etc/profile.d/timeout.sh dosyasına yazıldı.'

# 3. Parola Karmaşıklığı (pwquality.conf)
if [ -f /etc/security/pwquality.conf ]; then
    sed -i '/^minlen/d' /etc/security/pwquality.conf
    sed -i '/^dcredit/d' /etc/security/pwquality.conf
    sed -i '/^ucredit/d' /etc/security/pwquality.conf
    sed -i '/^lcredit/d' /etc/security/pwquality.conf
    sed -i '/^ocredit/d' /etc/security/pwquality.conf
    sed -i '/^enforce_for_root/d' /etc/security/pwquality.conf
    echo 'minlen = 14' >> /etc/security/pwquality.conf
    echo 'dcredit = -1' >> /etc/security/pwquality.conf
    echo 'ucredit = -1' >> /etc/security/pwquality.conf
    echo 'lcredit = -1' >> /etc/security/pwquality.conf
    echo 'ocredit = -1' >> /etc/security/pwquality.conf
    echo 'enforce_for_root' >> /etc/security/pwquality.conf
    echo '[+] pwquality.conf başarıyla güncellendi.'
fi

# 4. Hesap Kilitleme (faillock.conf)
if [ -f /etc/security/faillock.conf ]; then
    sed -i '/^deny/d' /etc/security/faillock.conf
    sed -i '/^unlock_time/d' /etc/security/faillock.conf
    sed -i '/^fail_interval/d' /etc/security/faillock.conf
    sed -i '/^even_deny_root/d' /etc/security/faillock.conf
    echo 'deny = 5' >> /etc/security/faillock.conf
    echo 'unlock_time = 900' >> /etc/security/faillock.conf
    echo 'fail_interval = 900' >> /etc/security/faillock.conf
    echo 'even_deny_root' >> /etc/security/faillock.conf
    echo '[+] faillock.conf başarıyla güncellendi.'
fi

echo '[+] PAM ve oturum güvenlik sıkılaştırması başarıyla tamamlandı!'