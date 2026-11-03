#!/bin/bash
# ==============================================================================
# KURUMSAL LABORATUVAR AĞ SINIRLARI VE GÜVENLİK DUVARI KURAL SETİ (IPTABLES)
# Üretici: Lab Network Boundary Auditor | (c) 2026 Seydi Eryılmaz (@seydivakkas)
# ==============================================================================

# 1. Mevcut tüm kuralları ve zincirleri temizle
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# 2. Varsayılan Güvenlik Politikaları (Açıkça izin verilmeyen her şey YASAKTIR)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Yerel döngü (Loopback) trafiğine izin ver
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 4. Karantina Bölgesi (VLAN 66 - 192.168.66.0/24) DNS Sinkhole Yönlendirmesi
# Tüm DNS sorgularını yerel INetSim sahte sunucusuna yönlendir (Dış DNS sızıntısını önle)
iptables -t nat -A PREROUTING -s 192.168.66.0/24 -p udp --dport 53 -j DNAT --to-destination 192.168.66.2:53
iptables -t nat -A PREROUTING -s 192.168.66.0/24 -p tcp --dport 53 -j DNAT --to-destination 192.168.66.2:53

# 5. Kırmızı Takım (VLAN 10) -> Karantina (VLAN 66) İzinli Test Trafiği
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.66.0/24 -p tcp -m multiport --dports 80,443,445,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

# 6. Karantina (VLAN 66) -> Kırmızı Takım (VLAN 10) Geri Dönüş Trafiği
# Kurban yalnızca başlatılan oturumlara yanıt verebilir; YENİ (NEW) tersine kabuk başlatamaz!
iptables -A FORWARD -s 192.168.66.0/24 -d 192.168.10.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# 7. Karantina (VLAN 66) -> Mavi Takım / SIEM (VLAN 20) Telemetri ve Log Gönderimi
iptables -A FORWARD -s 192.168.66.0/24 -d 192.168.20.0/24 -p udp -m multiport --dports 514,1514 -m state --state NEW,ESTABLISHED -j ACCEPT

# 8. Karantinadan Dış İnternete Çıkışı KESİNLİKLE ENGELLE (Logla ve Düşür)
iptables -A FORWARD -s 192.168.66.0/24 -o eth0 -j LOG --log-prefix "[LAB-SIZINTI-ENGELI]: "
iptables -A FORWARD -s 192.168.66.0/24 -o eth0 -j DROP

echo "[+] Laboratuvar ağ sınırları ve güvenlik duvarı kuralları başarıyla devreye alındı."
