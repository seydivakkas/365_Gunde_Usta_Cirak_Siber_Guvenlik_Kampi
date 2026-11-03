# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Güvenlik Duvarı (Firewall) Denetim ve Sertleştirme Motoru (LinuxFirewallSecurityEngine)
Bu modül, modern Linux çekirdeğinin nftables ve UFW (Uncomplicated Firewall) yapılandırmalarını,
varsayılan filtreleme politikalarını (Default Deny), durum denetimli paket analizini (Stateful/conntrack),
loopback arayüz izolasyonunu, anti-spoofing kurallarını ve açık port risklerini CIS Linux Benchmark
Section 3.4 ve 3.5 standartlarına göre denetler.
"""

# Tip ipuçları için standart kütüphane sınıfları dahil edilir
from typing import Dict, List, Any, Optional
# Nesne yönelimli veri modelleri için dataclass modülü dahil edilir
from dataclasses import dataclass, field
# Düzenli ifade işlemleri için re modülü dahil edilir
import re
# Dosya ve sistem yolu işlemleri için os modülü dahil edilir
import os
# JSON formatlama ve ayrıştırma için json modülü dahil edilir
import json


@dataclass
class FirewallRule:
    """
    Güvenlik duvarı içerisindeki tek bir paket filtreleme kuralını temsil eder.
    """
    # Kuralın ait olduğu zincir (chain: input, output, forward)
    chain: str
    # Kural eşleştiğinde uygulanacak eylem (accept, drop, reject, limit)
    action: str
    # Ağ protokolü (tcp, udp, icmp, all)
    protocol: str = "tcp"
    # Kaynak IP adresi veya alt ağı (Örn: any, 10.0.0.0/8, 192.168.1.100)
    source_ip: str = "any"
    # Hedef IP adresi
    dest_ip: str = "any"
    # Hedef port numarası veya aralığı (Örn: 22, 80, 443)
    dest_port: str = ""
    # Ağ arayüzü (Örn: lo, eth0, ens33)
    interface: str = ""
    # Bağlantı takip durumları (Örn: established, related, invalid, new)
    state: List[str] = field(default_factory=list)
    # Kural açıklaması veya yorumu
    comment: str = ""


@dataclass
class FirewallConfiguration:
    """
    Sistemin güvenlik duvarı (nftables veya UFW) genel çalışma parametrelerini temsil eder.
    """
    # Güvenlik duvarı motoru türü (nftables veya ufw)
    firewall_type: str = "nftables"
    # Güvenlik duvarının çalışır durumda (active/running) olup olmadığı
    is_active: bool = True
    # Sistem açılışında otomatik başlama (enabled on boot) bayrağı
    is_enabled_on_boot: bool = True
    # Gelen paketler için varsayılan politika (drop, accept, reject)
    input_policy: str = "drop"
    # Yönlendirilen paketler için varsayılan politika (drop, accept, reject)
    forward_policy: str = "drop"
    # Giden paketler için varsayılan politika (accept, drop)
    output_policy: str = "accept"
    # Güvenlik duvarı loglamasının aktif olup olmadığı
    logging_enabled: bool = True
    # Loopback (lo) arayüz trafiğine izin verilip verilmediği
    loopback_accepted: bool = True
    # Loopback harici arayüzlerden gelen 127.0.0.0/8 spoof paketlerinin engellenmesi
    loopback_spoof_drop: bool = True
    # Önceden kurulmuş meşru bağlantılara (established, related) izin verilmesi
    stateful_established_accepted: bool = True
    # Bozuk/geçersiz (invalid) bağlantı paketlerinin drop edilmesi
    stateful_invalid_dropped: bool = True
    # Tanımlı kurallar listesi
    rules: List[FirewallRule] = field(default_factory=list)
    # Yapılandırma dosyasının dosya yolu
    config_file_path: str = "/etc/nftables.conf"
    # Yapılandırma dosyasının izin modu (0600 veya 0644 olmalı)
    config_file_mode: str = "0600"
    # Yapılandırma dosyasının sahibi
    config_file_owner: str = "root"


@dataclass
class SecurityFinding:
    """
    Güvenlik duvarı denetiminde tespit edilen her bir zafiyet ve eksikliği temsil eder.
    """
    rule_id: str
    target: str
    cwe: str
    mitre_attack: str
    severity: str
    title: str
    description: str
    remediation_advice: str
    deduction_points: float


class LinuxFirewallSecurityEngine:
    """
    nftables ve UFW güvenlik duvarı yapılandırmalarını inceleyen, CIS Benchmark
    kriterlerine göre puanlayan ve otomatik sertleştirme betikleri üreten motor.
    """

    # Doğrudan internete veya tüm ağa açık olmaması gereken tehlikeli portlar
    DANGEROUS_PORTS = {
        "23": "Telnet şifrelenmemiş metin protokolü",
        "21": "FTP şifresiz dosya transferi",
        "69": "TFTP kimlik doğrulamasız dosya transferi",
        "445": "SMB Windows dosya paylaşımı (WannaCry/EternalBlue vektörü)",
        "139": "NetBIOS oturum servisi",
        "3389": "RDP Uzak Masaüstü protokolü (Brute-force hedefi)",
        "5900": "VNC şifresiz grafik masaüstü",
        "111": "RPC portmapper (DDoS yükseltme vektörü)"
    }

    def __init__(self) -> None:
        """
        Güvenlik motorunu başlatır ve bulgular listesini oluşturur.
        """
        self.findings: List[SecurityFinding] = []

    def audit_firewall(self, config: FirewallConfiguration) -> Dict[str, Any]:
        """
        Verilen güvenlik duvarı yapılandırmasını kurallara göre denetler ve puanlar.
        """
        # Bulgular listesi temizlenir
        self.findings.clear()

        # 1. Kural: Güvenlik Duvarı Aktiflik Durumu (CIS 3.4.1 & 3.5.1 / CWE-284 / T1562.004)
        if not config.is_active or not config.is_enabled_on_boot:
            self.findings.append(SecurityFinding(
                rule_id="FW-001",
                target=f"{config.firewall_type} servisi",
                cwe="CWE-284",
                mitre_attack="T1562.004",
                severity="CRITICAL",
                title="Güvenlik Duvarı Devre Dışı veya Durdurulmuş (Firewall Inactive)",
                description=f"{config.firewall_type} servisi aktif değil veya açılışta başlamıyor. Sunucu ağ seviyesinde tamamen savunmasızdır.",
                remediation_advice=f"Güvenlik duvarını başlatın ve kalıcı yapın: systemctl enable --now {config.firewall_type} (veya ufw enable)",
                deduction_points=25.0
            ))

        # 2. Kural: Varsayılan Gelen (INPUT) Politikası (CIS 3.4.3 & 3.5.2 / CWE-284 / T1046)
        if config.input_policy.lower() not in ["drop", "deny", "reject"]:
            self.findings.append(SecurityFinding(
                rule_id="FW-002",
                target=f"{config.firewall_type}:INPUT_POLICY",
                cwe="CWE-284",
                mitre_attack="T1046",
                severity="CRITICAL",
                title="Varsayılan Giriş Politikası ACCEPT (Default Deny İhlali)",
                description=f"Gelen (INPUT) trafiğin varsayılan politikası '{config.input_policy}'. Açıkça izin verilmeyen tüm paketler içeri alınmaktadır.",
                remediation_advice="Varsayılan gelen politikasını DROP olarak değiştirin: ufw default deny incoming veya nftables input chain drop",
                deduction_points=20.0
            ))

        # 3. Kural: Varsayılan Yönlendirme (FORWARD) Politikası (CIS 3.4.3 & 3.5.2 / CWE-284)
        if config.forward_policy.lower() not in ["drop", "deny", "reject"]:
            self.findings.append(SecurityFinding(
                rule_id="FW-003",
                target=f"{config.firewall_type}:FORWARD_POLICY",
                cwe="CWE-284",
                mitre_attack="T1046",
                severity="HIGH",
                title="Varsayılan Yönlendirme Politikası DROP Değil",
                description=f"Yönlendirme (FORWARD) politikası '{config.forward_policy}'. Router olmayan sunucularda paket aktarımı yasaklanmalıdır.",
                remediation_advice="Varsayılan yönlendirme politikasını DROP yapın: ufw default deny routed veya nftables forward chain drop",
                deduction_points=15.0
            ))

        # 4. Kural: Durum Denetimli Paket Filtreleme (Stateful / conntrack) (CIS 3.4.3 / CWE-693)
        if not config.stateful_established_accepted or not config.stateful_invalid_dropped:
            self.findings.append(SecurityFinding(
                rule_id="FW-004",
                target=f"{config.firewall_type}:ConnectionTracking",
                cwe="CWE-693",
                mitre_attack="T1059",
                severity="HIGH",
                title="Durum Denetimli Filtreleme (conntrack) Kuralları Eksik",
                description="Önceden kurulmuş bağlantılara (established, related) izin verilmemekte veya bozuk/geçersiz (invalid) paketler düşürülmemektedir.",
                remediation_advice="nftables içine 'ct state established,related accept' ve 'ct state invalid drop' kurallarını ekleyin.",
                deduction_points=15.0
            ))

        # 5. Kural: Loopback İzolasyonu ve Anti-Spoofing (CIS 3.4.3 / CWE-290 / T1584.004)
        if not config.loopback_accepted or not config.loopback_spoof_drop:
            self.findings.append(SecurityFinding(
                rule_id="FW-005",
                target=f"{config.firewall_type}:LoopbackPolicy",
                cwe="CWE-290",
                mitre_attack="T1584.004",
                severity="HIGH",
                title="Loopback İzolasyonu veya Anti-Spoofing Koruması Eksik",
                description="Yerel loopback (lo) arayüzüne izin verilmemekte ya da loopback dışı arayüzlerden gelen 127.0.0.0/8 sahte paketleri filtrelenmemektedir.",
                remediation_advice="lo arayüzünü kabul edin ve harici arayüzlerden gelen 127.0.0.0/8 kaynaklı paketleri drop edin.",
                deduction_points=15.0
            ))

        # 6. Kural: Herkese Açık Tehlikeli Port Kontrolleri (CWE-250 / T1046)
        for rule in config.rules:
            # Gelen (input) kuralı ve kabul (accept) ise
            if rule.chain.lower() == "input" and rule.action.lower() == "accept":
                # Kaynak IP kısıtlanmamışsa (any veya 0.0.0.0/0)
                if rule.source_ip in ["any", "0.0.0.0/0", ""]:
                    # Port kontrolü
                    if rule.dest_port in self.DANGEROUS_PORTS:
                        self.findings.append(SecurityFinding(
                            rule_id="FW-006",
                            target=f"Port {rule.dest_port} ({self.DANGEROUS_PORTS[rule.dest_port]})",
                            cwe="CWE-250",
                            mitre_attack="T1046",
                            severity="HIGH",
                            title=f"Tehlikeli Servis Portu Tüm Ağlara Açık (Port {rule.dest_port})",
                            description=f"Port {rule.dest_port} ({self.DANGEROUS_PORTS[rule.dest_port]}) herhangi bir IP kısıtlaması olmaksızın herkese açıktır.",
                            remediation_advice=f"Port {rule.dest_port} kuralını kaldırın veya yalnızca yetkili yönetim IP bloğu ile sınırlandırın.",
                            deduction_points=15.0
                        ))

        # 7. Kural: Güvenlik Duvarı Loglaması (CIS 3.5.1 / CWE-778)
        if not config.logging_enabled:
            self.findings.append(SecurityFinding(
                rule_id="FW-007",
                target=f"{config.firewall_type}:Logging",
                cwe="CWE-778",
                mitre_attack="T1562.001",
                severity="MEDIUM",
                title="Güvenlik Duvarı Paket Loglaması Kapalı",
                description="Engellenen şüpheli paketler log dosyalarına yazılmamaktadır. Ağ ihlallerinin tespiti zorlaşır.",
                remediation_advice="Güvenlik duvarı loglamasını etkinleştirin: ufw logging on veya nftables log prefix kuralı ekleyin.",
                deduction_points=10.0
            ))

        # 8. Kural: Yapılandırma Dosya İzinleri (CWE-732 / T1565.001)
        if config.config_file_path and self._is_mode_too_permissive(config.config_file_mode, threshold=0o644):
            self.findings.append(SecurityFinding(
                rule_id="FW-008",
                target=config.config_file_path,
                cwe="CWE-732",
                mitre_attack="T1565.001",
                severity="LOW",
                title="Gevşek Güvenlik Duvarı Dosya İzinleri",
                description=f"'{config.config_file_path}' dosyası '{config.config_file_mode}' modundadır. Yetkisiz yazma riski taşır.",
                remediation_advice=f"Dosya izinlerini sıkılaştırın: chmod 0600 {config.config_file_path} && chown root:root {config.config_file_path}",
                deduction_points=5.0
            ))

        # Puanlama hesabı
        total_deduction = sum(f.deduction_points for f in self.findings)
        final_score = max(0.0, min(100.0, 100.0 - total_deduction))

        if final_score >= 80.0:
            status_text = "GÜVENLİ (STANDARTLARA UYGUN)"
        elif final_score >= 60.0:
            status_text = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            status_text = "KRİTİK RİSK (ACİL MÜDAHALE GEREKLİ)"

        return {
            "guvenlik_skoru": round(final_score, 1),
            "durum": status_text,
            "firewall_turu": config.firewall_type,
            "aktiflik": config.is_active,
            "toplam_kural": len(config.rules),
            "toplam_bulgu": len(self.findings),
            "kritik_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "yuksek_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "HIGH"),
            "orta_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "dusuk_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "LOW"),
            "bulgular": [
                {
                    "rule_id": f.rule_id,
                    "target": f.target,
                    "cwe": f.cwe,
                    "mitre_attack": f.mitre_attack,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation_advice": f.remediation_advice,
                    "deduction_points": f.deduction_points
                }
                for f in self.findings
            ]
        }

    def _is_mode_too_permissive(self, mode_str: str, threshold: int = 0o644) -> bool:
        """
        Sekizli dosya modunun gevşek olup olmadığını sınar.
        """
        try:
            mode_int = int(mode_str, 8)
            # Diğer kullanıcılar (others) için yazma izni (002) varsa kesinlikle gevşektir
            if mode_int & 0o002:
                return True
            # Grup (group) için yazma izni (020) varsa gevşektir
            if mode_int & 0o020:
                return True
            return mode_int > threshold
        except (ValueError, TypeError):
            return True

    def parse_inventory_json(self, json_data: Dict[str, Any]) -> FirewallConfiguration:
        """
        JSON tabanlı envanteri okuyarak FirewallConfiguration nesnesine dönüştürür.
        """
        rules: List[FirewallRule] = []
        for r in json_data.get("rules", []):
            rules.append(FirewallRule(
                chain=r.get("chain", "input"),
                action=r.get("action", "accept"),
                protocol=r.get("protocol", "tcp"),
                source_ip=r.get("source_ip", "any"),
                dest_ip=r.get("dest_ip", "any"),
                dest_port=str(r.get("dest_port", "")),
                interface=r.get("interface", ""),
                state=r.get("state", []),
                comment=r.get("comment", "")
            ))

        return FirewallConfiguration(
            firewall_type=json_data.get("firewall_type", "nftables"),
            is_active=json_data.get("is_active", True),
            is_enabled_on_boot=json_data.get("is_enabled_on_boot", True),
            input_policy=json_data.get("input_policy", "drop"),
            forward_policy=json_data.get("forward_policy", "drop"),
            output_policy=json_data.get("output_policy", "accept"),
            logging_enabled=json_data.get("logging_enabled", True),
            loopback_accepted=json_data.get("loopback_accepted", True),
            loopback_spoof_drop=json_data.get("loopback_spoof_drop", True),
            stateful_established_accepted=json_data.get("stateful_established_accepted", True),
            stateful_invalid_dropped=json_data.get("stateful_invalid_dropped", True),
            rules=rules,
            config_file_path=json_data.get("config_file_path", "/etc/nftables.conf"),
            config_file_mode=json_data.get("config_file_mode", "0600"),
            config_file_owner=json_data.get("config_file_owner", "root")
        )

    def generate_nftables_hardening_conf(self) -> str:
        """
        CIS Linux Benchmark Section 3.4 standartlarına tam uyumlu örnek /etc/nftables.conf şablonu üretir.
        """
        lines = [
            "#!/usr/sbin/nft -f",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# CIS Linux Benchmark v2.0.0 Uyumlu Kurumsal nftables Yapılandırması",
            "# ==============================================================================",
            "",
            "# Önceki tüm kural kümeleri temizlenir (Atomic flush)",
            "flush ruleset",
            "",
            "table inet filter {",
            "    chain input {",
            "        # Varsayılan Politika: DROP (Default Deny - CIS 3.4.3)",
            "        type filter hook input priority 0; policy drop;",
            "",
            "        # 1. Loopback trafiğine izin ver",
            "        iif \"lo\" accept",
            "",
            "        # 2. Loopback dışı arayüzden gelen sahte (spoofed) 127.0.0.0/8 trafiğini engelle",
            "        ip saddr 127.0.0.0/8 iif != \"lo\" drop",
            "        ip6 saddr ::1 iif != \"lo\" drop",
            "",
            "        # 3. Durum Denetimi: Kurulmuş ve ilişkili bağlantıları kabul et (conntrack)",
            "        ct state established,related accept",
            "",
            "        # 4. Bozuk / geçersiz paketleri derhal düşür",
            "        ct state invalid drop",
            "",
            "        # 5. ICMP (ping) sınırlandırması (Rate-limit: DoS önleme)",
            "        ip protocol icmp icmp type echo-request limit rate 5/second accept",
            "        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept",
            "",
            "        # 6. Yetkili Servisler (Örn: SSH Port 22 ve Web 80/443)",
            "        # Kaba kuvvet önleme: SSH bağlantı hızını sınırla",
            "        tcp dport 22 ct state new limit rate 10/minute accept",
            "        tcp dport { 80, 443 } ct state new accept",
            "",
            "        # 7. Engellenen paketleri logla (CIS 3.4.3)",
            "        log prefix \"[NFTABLES-DROPPED]: \" flags all counter drop",
            "    }",
            "",
            "    chain forward {",
            "        # Yönlendirme Varsayılan Politika: DROP (CIS 3.4.3)",
            "        type filter hook forward priority 0; policy drop;",
            "    }",
            "",
            "    chain output {",
            "        # Giden Trafik: ACCEPT (Sunucu çıkışı serbest veya kısıtlı)",
            "        type filter hook output priority 0; policy accept;",
            "    }",
            "}"
        ]
        return "\n".join(lines)

    def generate_ufw_hardening_script(self) -> str:
        """
        Ubuntu/Debian sunucularında UFW'yi CIS Section 3.5 standartlarında yapılandıran betik üretir.
        """
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# UFW (Uncomplicated Firewall) CIS Uyumlu Hızlı Sertleştirme Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "echo '[*] UFW kuralları yapılandırılıyor...'",
            "# UFW'yi varsayılan ayarlara sıfırla",
            "ufw --force reset",
            "",
            "# Varsayılan politikalar: Gelen DROP, Yönlendirilen DROP, Giden ACCEPT (CIS 3.5.2)",
            "ufw default deny incoming",
            "ufw default deny routed",
            "ufw default allow outgoing",
            "",
            "# SSH erişimini rate-limit ile güvene al (Kaba kuvvet koruması)",
            "ufw limit 22/tcp comment 'SSH Rate Limited'",
            "",
            "# Meşru Web portlarına izin ver",
            "ufw allow 80/tcp comment 'HTTP Web'",
            "ufw allow 443/tcp comment 'HTTPS Web'",
            "",
            "# Güvenlik duvarı loglamasını aç (CIS 3.5.1)",
            "ufw logging on",
            "",
            "# UFW'yi etkinleştir",
            "ufw --force enable",
            "echo '[✓] UFW güvenlik duvarı başarıyla kilitlendi ve aktif edildi.'",
            "ufw status verbose"
        ]
        return "\n".join(lines)

    def generate_remediation_script(self, config: FirewallConfiguration) -> str:
        """
        Denetlenen sunucu için tespit edilen açıkları kapatacak genel Bash betiği üretir.
        """
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            f"# Linux Firewall ({config.firewall_type}) Otomatik İyileştirme Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "echo '[+] Güvenlik duvarı iyileştirme işlemi başlatılıyor...'",
            ""
        ]

        if config.firewall_type == "ufw":
            lines.extend([
                "# UFW Servisini etkinleştir ve varsayılan politikaları sıkılaştır",
                "ufw default deny incoming",
                "ufw default deny routed",
                "ufw default allow outgoing",
                "ufw logging on",
                "ufw limit 22/tcp",
                "ufw allow 80/tcp",
                "ufw allow 443/tcp",
                "ufw --force enable",
                "systemctl enable ufw",
                "echo '[✓] UFW yapılandırması tamamlandı.'"
            ])
        else:
            lines.extend([
                "# nftables yapılandırmasını /etc/nftables.conf üzerine yaz",
                "cat << 'EOF' > /etc/nftables.conf",
                self.generate_nftables_hardening_conf(),
                "EOF",
                "chmod 0600 /etc/nftables.conf",
                "chown root:root /etc/nftables.conf",
                "",
                "# Yapılandırma sözdizimini doğrula ve servisi başlat",
                "nft -c -f /etc/nftables.conf",
                "systemctl enable --now nftables",
                "systemctl reload nftables",
                "echo '[✓] nftables güvenlik duvarı başarıyla sıkılaştırıldı ve yeniden yüklendi.'"
            ])

        return "\n".join(lines)
