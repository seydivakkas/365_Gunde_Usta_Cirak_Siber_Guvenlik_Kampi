#!/usr/bin/env bash
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Linux Firewall (nftables) Otomatik İyileştirme Betiği
# ==============================================================================
set -euo pipefail

echo '[+] Güvenlik duvarı iyileştirme işlemi başlatılıyor...'

# nftables yapılandırmasını /etc/nftables.conf üzerine yaz
cat << 'EOF' > /etc/nftables.conf
#!/usr/sbin/nft -f
# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# CIS Linux Benchmark v2.0.0 Uyumlu Kurumsal nftables Yapılandırması
# ==============================================================================

# Önceki tüm kural kümeleri temizlenir (Atomic flush)
flush ruleset

table inet filter {
    chain input {
        # Varsayılan Politika: DROP (Default Deny - CIS 3.4.3)
        type filter hook input priority 0; policy drop;

        # 1. Loopback trafiğine izin ver
        iif "lo" accept

        # 2. Loopback dışı arayüzden gelen sahte (spoofed) 127.0.0.0/8 trafiğini engelle
        ip saddr 127.0.0.0/8 iif != "lo" drop
        ip6 saddr ::1 iif != "lo" drop

        # 3. Durum Denetimi: Kurulmuş ve ilişkili bağlantıları kabul et (conntrack)
        ct state established,related accept

        # 4. Bozuk / geçersiz paketleri derhal düşür
        ct state invalid drop

        # 5. ICMP (ping) sınırlandırması (Rate-limit: DoS önleme)
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept

        # 6. Yetkili Servisler (Örn: SSH Port 22 ve Web 80/443)
        # Kaba kuvvet önleme: SSH bağlantı hızını sınırla
        tcp dport 22 ct state new limit rate 10/minute accept
        tcp dport { 80, 443 } ct state new accept

        # 7. Engellenen paketleri logla (CIS 3.4.3)
        log prefix "[NFTABLES-DROPPED]: " flags all counter drop
    }

    chain forward {
        # Yönlendirme Varsayılan Politika: DROP (CIS 3.4.3)
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        # Giden Trafik: ACCEPT (Sunucu çıkışı serbest veya kısıtlı)
        type filter hook output priority 0; policy accept;
    }
}
EOF
chmod 0600 /etc/nftables.conf
chown root:root /etc/nftables.conf

# Yapılandırma sözdizimini doğrula ve servisi başlat
nft -c -f /etc/nftables.conf
systemctl enable --now nftables
systemctl reload nftables
echo '[✓] nftables güvenlik duvarı başarıyla sıkılaştırıldı ve yeniden yüklendi.'