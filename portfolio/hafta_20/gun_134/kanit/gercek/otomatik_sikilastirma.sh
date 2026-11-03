#!/bin/bash
# ===========================================================================
# Linux Sudo Güvenlik Sıkılaştırma ve Otomatik İyileştirme Betiği
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) - Tüm Hakları Saklıdır
# ===========================================================================
set -euo pipefail

echo '[*] Linux Sudoers Güvenlik İyileştirmesi Başlatılıyor...'

# 1. Sudoers Dosya İzinlerinin Kilitlenmesi
if [ -f /etc/sudoers ]; then
    chown root:root /etc/sudoers
    chmod 0440 /etc/sudoers
    echo '[+] /etc/sudoers izinleri 0440 (root:root) olarak mühürlendi.'
fi

if [ -d /etc/sudoers.d ]; then
    chown -R root:root /etc/sudoers.d
    chmod 0750 /etc/sudoers.d
    find /etc/sudoers.d -type f -exec chmod 0440 {} +
    echo '[+] /etc/sudoers.d dizin izinleri sıkılaştırıldı.'
fi

# Adım 1: GTFOBins Kabuk Kaçışı Zafiyeti (vim) [devops] (CWE-250)
echo '[>] Düzeltme Notu: 'vim' ikili dosyasını doğrudan sudoers içerisine eklemeyin. İhtiyaç duyulan işlevi özel bir kısıtlı script içerisine alarak NOEXEC etiketi uygulayın.'
# Adım 2: GTFOBins Kabuk Kaçışı Zafiyeti (find) [operator] (CWE-250)
echo '[>] Düzeltme Notu: 'find' ikili dosyasını doğrudan sudoers içerisine eklemeyin. İhtiyaç duyulan işlevi özel bir kısıtlı script içerisine alarak NOEXEC etiketi uygulayın.'
# Adım 3: Şifresiz Tam Root Yetkisi (NOPASSWD: ALL) [intern] (CWE-250)
echo '[>] Düzeltme Notu: /etc/sudoers dosyasında 'intern' için NOPASSWD etiketini kaldırın ve komutları kısıtlayın.'
# Adım 4: Komut Yolunda Denetimsiz Wildcard (*) Kullanımı [support] (CWE-88)
echo '[>] Düzeltme Notu: Wildcard yerine tam ve kesin dosya yolları tanımlayın veya regex doğrulayıcı wrapper script kullanın.'
# Adım 5: Defaults env_reset Direktifi Kapalı (CWE-250)
echo '[>] Düzeltme Notu: /etc/sudoers dosyasına 'Defaults env_reset' satırını ekleyin.'
# Adım 6: Tehlikeli Çevre Değişkeni Koruması (env_keep Injection) (CWE-426)
echo '[>] Düzeltme Notu: env_keep listesinden LD_PRELOAD değişkenlerini derhal kaldırın.'
# Adım 7: Gevşek Sudoers Dosya İzni (/etc/sudoers - Mod: 0666) (CWE-732)
echo '[>] Düzeltme Notu: chmod 0440 /etc/sudoers'
# Adım 8: Sudoers Dosyası Root Sahipliğinde Değil (/etc/sudoers.d/01-devops) (CWE-732)
echo '[>] Düzeltme Notu: chown root:root /etc/sudoers.d/01-devops'
# Adım 9: Gevşek Sudoers Dosya İzni (/etc/sudoers.d/01-devops - Mod: 0644) (CWE-732)
echo '[>] Düzeltme Notu: chmod 0440 /etc/sudoers.d/01-devops'

# Sudoers Sözdizimi Doğrulaması (Syntax Check)
if command -v visudo >/dev/null 2>&1; then
    visudo -c
    echo '[+] visudo sözdizimi doğrulaması BAŞARILI!'
fi

echo '[+] Sudo güvenlik sıkılaştırması tamamlandı!'