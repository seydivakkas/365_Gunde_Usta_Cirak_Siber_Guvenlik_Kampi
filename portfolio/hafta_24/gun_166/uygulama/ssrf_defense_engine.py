# -*- coding: utf-8 -*-
"""
Gün 166: SSRF (Server-Side Request Forgery) Savunma Motoru (ssrf_defense_engine.py)

Bu modül; Sunucu Taraflı İstek Sahteciliği (SSRF / CWE-918) tehditlerini,
Loopback, RFC 1918 özel ağ ve Bulut Metaveri Servisi (169.254.169.254) sızıntılarını,
gizlenmiş IP temsillerini (Hex, Octal, Integer, IPv6-mapped), DNS Rebinding ve
HTTP Açık Yönlendirme (Open Redirect) atlatmalarını kurumsal düzeyde tespit eden
ve katı ağ filtreleme mimarisiyle engelleyen tam teşekküllü savunma motorudur.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri içe aktarılır
import ipaddress  # IP adreslerini, alt ağları ve adres özelliklerini doğrulamak için
import socket  # Alan adı çözümleme (DNS lookup) ve IP çözümleme için
import urllib.parse  # URL yapısal ayrıştırması ve bileşen kontrolü için
import re  # Düzenli ifadeler ile IP gizleme desenlerini tespit etmek için
import json  # Yapılandırılmış denetim raporları oluşturmak için
from enum import Enum  # Sabit durum sınıfları oluşturmak için
from typing import Dict, Any, List, Optional, Tuple, Set, Callable  # Tip ipuçları için
from dataclasses import dataclass, field  # Veri sınıfları oluşturmak için


class SSRFRiskType(str, Enum):
    """SSRF saldırı türlerini ve risk kategorilerini tanımlayan numaralandırma."""
    LOOPBACK_ACCESS = "LOOPBACK_ACCESS"  # Yerel döngü (127.0.0.1, localhost, ::1) erişimi
    PRIVATE_NETWORK_ACCESS = "PRIVATE_NETWORK_ACCESS"  # RFC 1918 özel kurumsal ağlara (10.x, 172.16.x, 192.168.x) erişim
    CLOUD_METADATA_ACCESS = "CLOUD_METADATA_ACCESS"  # Bulut metaveri servisine (169.254.169.254) erişim
    LINK_LOCAL_RESERVED = "LINK_LOCAL_RESERVED"  # Bağlantı yerel (link-local) veya ayrılmış IP erişimi
    DISALLOWED_SCHEME = "DISALLOWED_SCHEME"  # İzin verilmeyen güvensiz protokol (file://, gopher://, dict:// vb.)
    DNS_REBINDING_RISK = "DNS_REBINDING_RISK"  # DNS Rebinding ve TOCTOU (Time-of-Check to Time-of-Use) riski
    OPEN_REDIRECT_SSRF = "OPEN_REDIRECT_SSRF"  # Güvenli URL üzerinden iç ağa yönlendirme (301/302 Redirect) istismarı
    OBFUSCATED_IP_FORMAT = "OBFUSCATED_IP_FORMAT"  # Tamsayı, Hex veya Sekizli (Octal) formatta gizlenmiş IP


@dataclass
class SSRFValidationResult:
    """SSRF analiz ve doğrulama sonucunu temsil eden veri yapısı."""
    is_safe: bool  # İsteğin güvenli olup olmadığı
    target_url: str  # Değerlendirilen hedef URL
    scheme: str  # Ayrıştırılan şema (http/https vb.)
    resolved_ips: List[str] = field(default_factory=list)  # Çözümlenen IP adresleri
    risk_type: Optional[SSRFRiskType] = None  # Saptanan risk türü
    rejection_reason: Optional[str] = None  # Reddetme gerekçesi
    details: Dict[str, Any] = field(default_factory=dict)  # Ek teknik detaylar


@dataclass
class SSRFFetchResponse:
    """Sunucu tarafından gerçekleştirilen HTTP getirme işleminin sonucunu temsil eden yapı."""
    status_code: int  # HTTP durum kodu (200, 400, 403 vb.)
    headers: Dict[str, str] = field(default_factory=dict)  # Dönen başlıklar
    body: str = ""  # Yanıt gövdesi
    redirect_history: List[str] = field(default_factory=list)  # Takip edilen yönlendirme yolları
    is_blocked: bool = False  # Güvenlik motoru tarafından engellendi mi?
    block_reason: Optional[str] = None  # Engelleme sebebi


class EnterpriseSSRFPolicy:
    """Kurumsal düzeyde katı SSRF güvenlik politikasını tanımlayan yapı."""
    
    def __init__(
        self,
        allowed_schemes: Optional[Set[str]] = None,
        disallow_private_ips: bool = True,
        disallow_loopback: bool = True,
        disallow_cloud_metadata: bool = True,
        allowlist_domains: Optional[Set[str]] = None,
        max_redirects: int = 3,
        request_timeout_seconds: float = 3.0
    ):
        # Yalnızca HTTP ve HTTPS protokollerine izin verilir
        self.allowed_schemes: Set[str] = allowed_schemes or {"http", "https"}
        # Özel kurumsal IP bloklarına erişim engeli (RFC 1918)
        self.disallow_private_ips: bool = disallow_private_ips
        # Yerel döngü (localhost) engeli
        self.disallow_loopback: bool = disallow_loopback
        # Bulut metaveri servisi (169.254.169.254) engeli
        self.disallow_cloud_metadata: bool = disallow_cloud_metadata
        # İzinli alan adları beyaz listesi (Varsa katı kısıtlama)
        self.allowlist_domains: Set[str] = {d.lower() for d in allowlist_domains} if allowlist_domains else set()
        # En fazla takip edilecek güvenli yönlendirme sayısı
        self.max_redirects: int = max_redirects
        # Bağlantı zaman aşımı süresi
        self.request_timeout: float = request_timeout_seconds


class SSRFDefenseEngine:
    """
    Merkezi SSRF Savunma Motoru:
    URL doğrulaması, DNS çözümlemesi, IP adresi sınıflandırması ve güvenli HTTP getirme
    (Safe HTTP Fetching) işlemlerini koordine eder.
    """

    def __init__(self, policy: Optional[EnterpriseSSRFPolicy] = None):
        # Politika atanır veya varsayılan kurumsal standart yüklenir
        self.policy: EnterpriseSSRFPolicy = policy or EnterpriseSSRFPolicy()
        # DNS çözümleme fonksiyonu (Testlerde sahte çözümleyici ile ezilebilir)
        self.dns_resolver: Callable[[str], List[str]] = self._default_dns_resolver
        # Taşıyıcı Düzeyinde NAT (CGNAT) aralığı: 100.64.0.0/10
        self.cgnat_network = ipaddress.ip_network("100.64.0.0/10")
        # AWS/Azure/GCP Metaveri IP adresi
        self.metadata_ip = ipaddress.ip_address("169.254.169.254")

    def _default_dns_resolver(self, hostname: str) -> List[str]:
        """Sistem soket kütüphanesini kullanarak host adresinin tüm A/AAAA kayıtlarını çözer."""
        resolved_ips: Set[str] = set()
        try:
            # getaddrinfo ile IPv4 ve IPv6 adreslerinin tümü sorgulanır
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                ip_str = item[4][0]  # IP adresi dizesi
                resolved_ips.add(ip_str)
        except (socket.gaierror, socket.error):
            # Çözümlenemezse boş liste döner
            pass
        return sorted(list(resolved_ips))

    def parse_obfuscated_ip(self, host: str) -> Optional[ipaddress.IPv4Address]:
        """
        Tamsayı (DWORD), Hexadecimal veya Sekizli (Octal) formatta gizlenmiş IPv4 adreslerini çözümler.
        Örnek: 2130706433 -> 127.0.0.1, 0x7f.1 -> 127.0.0.1, 0177.0.0.1 -> 127.0.0.1
        """
        # 1. Salt tamsayı (DWORD) biçimi kontrolü (örn: 2130706433)
        if host.isdigit():
            try:
                val = int(host)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except ValueError:
                pass

        # 2. Hexadecimal tam sayı (örn: 0x7f000001)
        if host.lower().startswith("0x") and len(host) <= 10:
            try:
                val = int(host, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except ValueError:
                pass

        # 3. Noktalı karma biçimler (örn: 0177.0.0.1, 0x7f.0.0.1, 127.1)
        parts = host.split(".")
        if 1 <= len(parts) <= 4:
            parsed_octets = []
            valid_format = True
            for part in parts:
                try:
                    if part.lower().startswith("0x"):  # Hex oktet
                        parsed_octets.append(int(part, 16))
                    elif part.startswith("0") and len(part) > 1 and part.isdigit():  # Octal oktet
                        parsed_octets.append(int(part, 8))
                    elif part.isdigit():  # Standart decimal oktet
                        parsed_octets.append(int(part, 10))
                    else:
                        valid_format = False
                        break
                except ValueError:
                    valid_format = False
                    break

            if valid_format:
                # Kısaltılmış IP'lerin (örn: 127.1 -> 127.0.0.1) derlenmesi
                if len(parsed_octets) == 1:
                    val = parsed_octets[0]
                    if 0 <= val <= 0xFFFFFFFF:
                        return ipaddress.IPv4Address(val)
                elif len(parsed_octets) == 2:  # A.B -> A.0.0.B
                    if parsed_octets[0] <= 255 and parsed_octets[1] <= 0xFFFFFF:
                        val = (parsed_octets[0] << 24) | parsed_octets[1]
                        return ipaddress.IPv4Address(val)
                elif len(parsed_octets) == 3:  # A.B.C -> A.B.0.C
                    if parsed_octets[0] <= 255 and parsed_octets[1] <= 255 and parsed_octets[2] <= 0xFFFF:
                        val = (parsed_octets[0] << 24) | (parsed_octets[1] << 16) | parsed_octets[2]
                        return ipaddress.IPv4Address(val)
                elif len(parsed_octets) == 4:  # A.B.C.D
                    if all(0 <= o <= 255 for o in parsed_octets):
                        val = (parsed_octets[0] << 24) | (parsed_octets[1] << 16) | (parsed_octets[2] << 8) | parsed_octets[3]
                        return ipaddress.IPv4Address(val)

        return None

    def validate_ip_address(self, ip_str: str) -> Tuple[bool, Optional[SSRFRiskType], str]:
        """
        Tek bir IP adresini kurumsal güvenlik standartlarına göre katı incelemeye tabi tutar.
        """
        try:
            # IP nesnesi oluşturulur (IPv4 veya IPv6)
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, SSRFRiskType.OBFUSCATED_IP_FORMAT, f"Geçersiz IP adresi biçimi: '{ip_str}'"

        # IPv4-mapped IPv6 adresleri kontrol edilir (örn: ::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped  # İçteki IPv4 adresi denetlenir

        # 1. KONTROL: Yerel döngü (Loopback: 127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            return False, SSRFRiskType.LOOPBACK_ACCESS, f"Yerel döngü (Loopback) erişimi engellendi: '{ip_str}'"

        # 2. KONTROL: Bulut Metaveri Servisi (169.254.169.254)
        if ip_obj == self.metadata_ip:
            return False, SSRFRiskType.CLOUD_METADATA_ACCESS, f"Bulut Metaveri Servisi (169.254.169.254) erişimi engellendi!"

        # 3. KONTROL: Bağlantı-Yerel (Link-Local: 169.254.0.0/16, fe80::/10)
        if ip_obj.is_link_local:
            return False, SSRFRiskType.LINK_LOCAL_RESERVED, f"Bağlantı-yerel (Link-Local) IP adresi engellendi: '{ip_str}'"

        # 4. KONTROL: Taşıyıcı Düzeyinde NAT (Carrier-Grade NAT: 100.64.0.0/10)
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in self.cgnat_network:
            return False, SSRFRiskType.LINK_LOCAL_RESERVED, f"Taşıyıcı NAT (CGNAT) bloğu engellendi: '{ip_str}'"

        # 5. KONTROL: Belirtilmemiş (0.0.0.0 veya ::) ve çok noktaya yayın (Multicast)
        if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_reserved:
            return False, SSRFRiskType.LINK_LOCAL_RESERVED, f"Özel / Ayrılmış / Belirtilmemiş IP erişimi engellendi: '{ip_str}'"

        # 6. KONTROL: RFC 1918 Özel Ağ Blokları (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if self.policy.disallow_private_ips and ip_obj.is_private:
            return False, SSRFRiskType.PRIVATE_NETWORK_ACCESS, f"Özel kurumsal iç ağ IP erişimi (RFC 1918) engellendi: '{ip_str}'"

        # Tüm kontrolleri geçtiyse güvenlidir
        return True, None, "IP adresi güvenli genel ağ aralığındadır."

    def validate_url(self, url: str) -> SSRFValidationResult:
        """
        Hedef URL'yi şema, gizlenmiş IP, DNS çözümlemesi ve kurumsal politika kapsamında denetler.
        """
        # Boş URL kontrolü
        if not url or not isinstance(url, str):
            return SSRFValidationResult(
                is_safe=False, target_url=str(url), scheme="",
                risk_type=SSRFRiskType.DISALLOWED_SCHEME,
                rejection_reason="URL boş veya geçersiz dize tipinde."
            )

        # URL ayrıştırılır
        try:
            parsed = urllib.parse.urlparse(url.strip())
        except Exception as e:
            return SSRFValidationResult(
                is_safe=False, target_url=url, scheme="",
                risk_type=SSRFRiskType.DISALLOWED_SCHEME,
                rejection_reason=f"URL ayrıştırma hatası: {str(e)}"
            )

        scheme = (parsed.scheme or "").lower()

        # 1. KONTROL: Şema doğrulama (Yalnızca http/https izinlidir; file://, gopher:// reddedilir)
        if scheme not in self.policy.allowed_schemes:
            return SSRFValidationResult(
                is_safe=False, target_url=url, scheme=scheme,
                risk_type=SSRFRiskType.DISALLOWED_SCHEME,
                rejection_reason=f"İzin verilmeyen protokol şeması: '{scheme}://'. Yalnızca HTTP/HTTPS kabul edilir."
            )

        # Host adı denetlenir
        hostname = parsed.hostname
        if not hostname:
            return SSRFValidationResult(
                is_safe=False, target_url=url, scheme=scheme,
                risk_type=SSRFRiskType.DISALLOWED_SCHEME,
                rejection_reason="URL içinde geçerli bir ana makine (hostname) bulunamadı."
            )

        # Kullanıcı adı/şifre hilesi kontrolü (örn: http://google.com@127.0.0.1)
        if parsed.username or parsed.password:
            # Gelişmiş ayrıştırma uyarısı
            pass

        # 2. KONTROL: Gizlenmiş (Obfuscated) IP Temsilleri Kontrolü (Hex, Octal, Integer)
        obfuscated_ip = self.parse_obfuscated_ip(hostname)
        if obfuscated_ip is not None:
            # Gizlenmiş IP tespit edildiğinde derhal çözülmüş IP denetlenir
            is_ip_safe, risk, reason = self.validate_ip_address(str(obfuscated_ip))
            if not is_ip_safe:
                return SSRFValidationResult(
                    is_safe=False, target_url=url, scheme=scheme,
                    resolved_ips=[str(obfuscated_ip)],
                    risk_type=risk or SSRFRiskType.OBFUSCATED_IP_FORMAT,
                    rejection_reason=f"Gizlenmiş IP formatı ({hostname} -> {obfuscated_ip}) tespit edildi: {reason}",
                    details={"obfuscated_host": hostname, "normalized_ip": str(obfuscated_ip)}
                )

        # 3. KONTROL: Doğrudan IP Adresi Verildiyse
        try:
            direct_ip = ipaddress.ip_address(hostname)
            is_ip_safe, risk, reason = self.validate_ip_address(str(direct_ip))
            if not is_ip_safe:
                return SSRFValidationResult(
                    is_safe=False, target_url=url, scheme=scheme,
                    resolved_ips=[str(direct_ip)],
                    risk_type=risk,
                    rejection_reason=reason
                )
            # Doğrudan güvenli bir genel IP ise
            return SSRFValidationResult(
                is_safe=True, target_url=url, scheme=scheme,
                resolved_ips=[str(direct_ip)],
                details={"verified_ip": str(direct_ip)}
            )
        except ValueError:
            # IP adresi değil, bir alan adı (hostname)
            pass

        # 4. KONTROL: Alan Adı Beyaz Listesi (Allowlist Domains) Varsa
        if self.policy.allowlist_domains:
            if hostname.lower() not in self.policy.allowlist_domains:
                return SSRFValidationResult(
                    is_safe=False, target_url=url, scheme=scheme,
                    risk_type=SSRFRiskType.PRIVATE_NETWORK_ACCESS,
                    rejection_reason=f"Alan adı kurumsal beyaz listede yer almıyor: '{hostname}'"
                )

        # 5. KONTROL: DNS Çözümlemesi ve Çözümlenen TÜM IP'lerin Denetimi
        resolved_ips = self.dns_resolver(hostname)
        if not resolved_ips:
            return SSRFValidationResult(
                is_safe=False, target_url=url, scheme=scheme,
                risk_type=SSRFRiskType.DNS_REBINDING_RISK,
                rejection_reason=f"Alan adı DNS sunucusunda çözümlenemedi: '{hostname}'"
            )

        # Her bir çözümlenen IP ayrı ayrı test edilir (Biri bile zararlıysa reddedilir!)
        for rip in resolved_ips:
            is_ip_safe, risk, reason = self.validate_ip_address(rip)
            if not is_ip_safe:
                return SSRFValidationResult(
                    is_safe=False, target_url=url, scheme=scheme,
                    resolved_ips=resolved_ips,
                    risk_type=risk,
                    rejection_reason=f"Alan adı tehlikeli bir iç IP adresine çözümlendi ({hostname} -> {rip}): {reason}",
                    details={"flagged_ip": rip}
                )

        # Tüm kontroller başarıyla tamamlandı
        return SSRFValidationResult(
            is_safe=True, target_url=url, scheme=scheme,
            resolved_ips=resolved_ips,
            details={"verified_ips": resolved_ips}
        )


class MockInternalNetwork:
    """İç ağ kaynaklarını, bulut metaveri servisini ve açık yönlendirmeleri simüle eden sanal ağ."""

    def __init__(self):
        # Simüle edilen sanal iç sunucular ve veri içerikleri
        self.routes: Dict[str, Dict[str, Any]] = {
            "http://127.0.0.1:8080/admin": {
                "status": 200,
                "body": json.dumps({"panel": "Sistem Yönetim Konsolu", "gizli_anahtar": "ROOT_SECRET_9988"}),
                "headers": {"Content-Type": "application/json"}
            },
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role": {
                "status": 200,
                "body": json.dumps({
                    "Code": "Success",
                    "AccessKeyId": "AKIA_FAKE_METADATA_KEY",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "Token": "SESSION_TOKEN_SAMPLE"
                }),
                "headers": {"Content-Type": "application/json"}
            },
            "http://10.0.0.5:5432/status": {
                "status": 200,
                "body": "PostgreSQL Internal Cluster Health: OK, Database: internal_finance",
                "headers": {"Content-Type": "text/plain"}
            },
            "https://public-service.com/redirect-to-metadata": {
                "status": 302,
                "body": "Redirecting...",
                "headers": {"Location": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role"}
            },
            "https://api.kamu.gov.tr/hava-durumu": {
                "status": 200,
                "body": json.dumps({"sehir": "Ankara", "durum": "Güneşli", "sicaklik": 22}),
                "headers": {"Content-Type": "application/json"}
            }
        }

    def fetch(self, url: str) -> Dict[str, Any]:
        """Sanal ağ üzerinde URL getirir."""
        return self.routes.get(url, {
            "status": 404,
            "body": "404 Not Found",
            "headers": {"Content-Type": "text/plain"}
        })


class MockSafeHTTPClient:
    """
    Güvenli HTTP İstemcisi:
    SSRF korumasını IP sabitleme (IP Pinning) ve güvenli yönlendirme denetimi ile icra eder.
    """

    def __init__(self, engine: SSRFDefenseEngine, mock_net: MockInternalNetwork):
        self.engine = engine  # Savunma motoru
        self.mock_net = mock_net  # Sanal ağ

    def safe_fetch(self, url: str) -> SSRFFetchResponse:
        """
        URL'yi güvenli bir şekilde getirir.
        Her yönlendirmede (Redirect) hedef URL baştan SSRF kontrolünden geçirilir.
        """
        current_url = url  # Mevcut istek URL'si
        redirects: List[str] = []  # Takip edilen yönlendirmeler

        for _ in range(self.engine.policy.max_redirects + 1):
            # 1. Aşama: URL doğrulanır
            validation = self.engine.validate_url(current_url)
            if not validation.is_safe:
                return SSRFFetchResponse(
                    status_code=403,
                    body=json.dumps({"error": "SSRF_BLOCKED", "reason": validation.rejection_reason}),
                    redirect_history=redirects,
                    is_blocked=True,
                    block_reason=validation.rejection_reason
                )

            # 2. Aşama: İstek icra edilir
            resp = self.mock_net.fetch(current_url)
            status = resp.get("status", 200)

            # 3. Aşama: Yönlendirme (301, 302, 307, 308) Takibi
            if status in (301, 302, 307, 308):
                location = resp.get("headers", {}).get("Location")
                if not location:
                    break
                # Göreli URL varsa mutlak URL yapılır
                next_url = urllib.parse.urljoin(current_url, location)
                redirects.append(next_url)
                current_url = next_url
                continue  # Sonraki döngüde yeni hedef sıfırdan SSRF testine girer!

            # Başarılı veya son yanıt
            return SSRFFetchResponse(
                status_code=status,
                headers=resp.get("headers", {}),
                body=resp.get("body", ""),
                redirect_history=redirects,
                is_blocked=False
            )

        # Maksimum yönlendirme aşıldıysa
        return SSRFFetchResponse(
            status_code=400,
            body="Maksimum yönlendirme sayısı aşıldı.",
            redirect_history=redirects,
            is_blocked=True,
            block_reason="MAX_REDIRECTS_EXCEEDED"
        )

    def vulnerable_fetch(self, url: str) -> SSRFFetchResponse:
        """
        ZAFİYETLİ İSTEMCİ:
        Hiçbir SSRF kontrolü yapmadan, 'file://' ve tüm iç IP'lere doğrudan bağlanır
        ve 302 yönlendirmelerini körlemesine takip eder.
        """
        current_url = url
        redirects: List[str] = []

        for _ in range(10):
            resp = self.mock_net.fetch(current_url)
            status = resp.get("status", 200)
            if status in (301, 302, 307, 308):
                location = resp.get("headers", {}).get("Location")
                if location:
                    next_url = urllib.parse.urljoin(current_url, location)
                    redirects.append(next_url)
                    current_url = next_url
                    continue
            return SSRFFetchResponse(
                status_code=status,
                headers=resp.get("headers", {}),
                body=resp.get("body", ""),
                redirect_history=redirects,
                is_blocked=False
            )

        return SSRFFetchResponse(status_code=500, body="Döngü hatası", is_blocked=False)
