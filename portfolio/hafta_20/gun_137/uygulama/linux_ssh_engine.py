# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux SSH Anahtar Güvenliği ve Sunucu Sertleştirme Motoru (LinuxSshSecurityEngine)
Bu modül, SSH özel ve açık anahtarlarının kriptografik gücünü, dosya/dizin izinlerini,
authorized_keys kısıtlamalarını ve OpenSSH sunucu (sshd_config) yapılandırmasını
CIS Linux Benchmark Section 5.2 ve NIST SP 800-123 standartlarına göre denetler.
"""

# Tip ipuçları için standart kütüphane sınıfları dahil edilir
from typing import Dict, List, Any, Optional
# Nesne yönelimli veri modelleri için dataclass modülü dahil edilir
from dataclasses import dataclass, field
# Düzenli ifade işlemleri için re modülü dahil edilir
import re
# Dosya ve dizin yolu işlemleri için os modülü dahil edilir
import os
# JSON formatlama ve ayrıştırma için json modülü dahil edilir
import json


@dataclass
class SshKey:
    """
    Sistemde bulunan bir SSH anahtar dosyasını ve kriptografik özelliklerini temsil eder.
    """
    # Anahtar dosyasının adı (Örn: id_ed25519, id_rsa, id_dsa)
    name: str
    # Anahtar dosyasının dosya sistemindeki mutlak yolu
    path: str
    # Anahtarın ait olduğu algoritma türü (ed25519, ecdsa, rsa, dsa)
    key_type: str
    # Anahtar uzunluğu (bit cinsinden, Örn: 256, 384, 521, 2048, 3072, 4096, 1024)
    key_bits: int
    # Dosyanın özel anahtar (private key) olup olmadığı
    is_private: bool
    # Özel anahtarın bir parola (passphrase) ile şifrelenip şifrelenmediği
    is_passphrase_protected: bool
    # Dosyanın disk üzerindeki sahibi
    file_owner: str = "root"
    # Dosyanın disk üzerindeki grubu
    file_group: str = "root"
    # Dosyanın sekizli (octal) izin modu (Örn: 0600, 0644, 0777)
    file_mode: str = "0600"
    # Anahtarın ilişkili olduğu kullanıcı hesabı (Örn: deploy, devops)
    associated_user: str = "root"


@dataclass
class AuthorizedKeyEntry:
    """
    authorized_keys dosyası içerisindeki bir açık anahtar kaydını ve izinlerini temsil eder.
    """
    # Yetkilendirilmiş kullanıcı
    user: str
    # Anahtar algoritması (Örn: ssh-ed25519, ssh-rsa)
    key_type: str
    # Anahtar uzunluğu
    key_bits: int
    # Anahtar yorum veya e-posta alanı
    comment: str = ""
    # Anahtar kısıtlama seçenekleri (Örn: from="10.0.0.0/8", no-pty, no-port-forwarding)
    options: List[str] = field(default_factory=list)
    # authorized_keys dosyasının disk yolu
    file_path: str = ""
    # authorized_keys dosyasının izin modu
    file_mode: str = "0600"
    # authorized_keys dosyasının sahibi
    file_owner: str = "root"


@dataclass
class SshdConfig:
    """
    OpenSSH sunucu (/etc/ssh/sshd_config) güvenlik yapılandırmasını temsil eder.
    """
    # Root kullanıcısının doğrudan giriş izni (no, prohibit-password, yes)
    permit_root_login: str = "no"
    # Parola ile kimlik doğrulama izni (Güvenli sistemlerde False olmalı)
    password_authentication: bool = False
    # Açık anahtar ile kimlik doğrulama izni (True olmalı)
    pubkey_authentication: bool = True
    # Boş parola ile giriş izni (Kesinlikle False olmalı)
    permit_empty_passwords: bool = False
    # X11 grafik arayüz yönlendirmesi izni (False olmalı)
    x11_forwarding: bool = False
    # Oturum başına maksimum başarısız kimlik denemesi sınırı (CIS: <= 4)
    max_auth_tries: int = 4
    # İstemci hareketsizlik ping aralığı (saniye cinsinden, Örn: 300)
    client_alive_interval: int = 300
    # Yanıt vermeyen istemcinin düşürülme deneme sayısı (Örn: 2)
    client_alive_count_max: int = 2
    # SSH dinleme portu
    port: int = 22
    # sshd_config dosyasının disk izin modu (0600 veya 0644 olmalı)
    config_file_mode: str = "0600"
    # sshd_config dosyasının sahibi (root olmalı)
    config_file_owner: str = "root"


@dataclass
class SecurityFinding:
    """
    SSH denetiminde tespit edilen her bir zafiyet ve eksikliği temsil eder.
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


class LinuxSshSecurityEngine:
    """
    SSH anahtarlarını, yetkilendirme dosyalarını ve sshd_config yapılandırmalarını
    analiz eden, puanlayan ve otomatik sıkılaştırma üreten güvenlik motoru.
    """

    def __init__(self) -> None:
        """
        Güvenlik motorunu başlatır ve tespit listesini hazırlar.
        """
        # Bulgular listesi tanımlanır
        self.findings: List[SecurityFinding] = []

    def audit_environment(
        self,
        keys: List[SshKey],
        authorized_keys: List[AuthorizedKeyEntry],
        sshd: SshdConfig
    ) -> Dict[str, Any]:
        """
        Verilen SSH anahtarlarını, authorized_keys kayıtlarını ve sunucu yapılandırmasını denetler.
        """
        # Bulgular listesi temizlenir
        self.findings.clear()

        # 1. Aşama: SSH Anahtarlarını (Özel ve Açık) Denetle
        for key in keys:
            self._audit_ssh_key(key)

        # 2. Aşama: authorized_keys Dosyalarını ve Girdilerini Denetle
        for auth_entry in authorized_keys:
            self._audit_authorized_key(auth_entry)

        # 3. Aşama: sshd_config Sunucu Yapılandırmasını Denetle
        self._audit_sshd_config(sshd)

        # Toplam ceza puanı hesaplanır
        total_deductions = sum(f.deduction_points for f in self.findings)
        # Sistem güvenlik skoru 0.0 ile 100.0 arasında sınırlandırılır
        final_score = max(0.0, min(100.0, 100.0 - total_deductions))

        # Genel güvenlik durumu metni belirlenir
        if final_score >= 80.0:
            status_text = "GÜVENLİ (STANDARTLARA UYGUN)"
        elif final_score >= 60.0:
            status_text = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            status_text = "KRİTİK RİSK (ACİL MÜDAHALE GEREKLİ)"

        # Denetim özet raporu döndürülür
        return {
            "guvenlik_skoru": round(final_score, 1),
            "durum": status_text,
            "toplam_anahtar": len(keys),
            "toplam_authorized_key": len(authorized_keys),
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

    def _audit_ssh_key(self, key: SshKey) -> None:
        """
        Tek bir SSH anahtarını dosya izinleri, kriptografik güç ve parola koruması yönünden inceler.
        """
        # Kural 1: Özel Anahtar Dosya İzinleri (CWE-732 / T1552.004)
        if key.is_private:
            # Özel anahtarlar 0600 (-rw-------) veya 0400 (-r--------) olmalıdır
            if self._is_mode_too_permissive(key.file_mode, threshold=0o600):
                self.findings.append(SecurityFinding(
                    rule_id="SSH-001",
                    target=key.path,
                    cwe="CWE-732",
                    mitre_attack="T1552.004",
                    severity="CRITICAL",
                    title="Gevşek Özel Anahtar (Private Key) Dosya İzinleri",
                    description=f"'{key.path}' özel anahtar dosyasının izin modu '{key.file_mode}' güvensizdir. Başka kullanıcılar tarafından okunabilir.",
                    remediation_advice=f"Özel anahtarın izinlerini derhal sınırlandırın: chmod 0600 {key.path}",
                    deduction_points=20.0
                ))

            # Kural 2: Özel Anahtar Parola Koruması Eksikliği (CWE-522 / T1552.004)
            if not key.is_passphrase_protected:
                self.findings.append(SecurityFinding(
                    rule_id="SSH-002",
                    target=key.path,
                    cwe="CWE-522",
                    mitre_attack="T1552.004",
                    severity="MEDIUM",
                    title="Özel Anahtar Parola (Passphrase) ile Korunmuyor",
                    description=f"'{key.path}' özel anahtarı diske düz metin kaydedilmiştir. Sunucuya sızan saldırgan anahtarı kopyalayıp anında kullanabilir.",
                    remediation_advice=f"Anahtara güçlü bir parola ekleyin: ssh-keygen -p -f {key.path}",
                    deduction_points=10.0
                ))

        # Kural 3: Zayıf ve Güvensiz Kriptografik Algoritma Denetimi (CWE-327 / CWE-326)
        # DSA anahtarları (1024 bit) tamamen kırılmıştır ve güvensizdir
        if key.key_type.lower() == "dsa":
            self.findings.append(SecurityFinding(
                rule_id="SSH-003",
                target=key.path,
                cwe="CWE-327",
                mitre_attack="T1552.004",
                severity="CRITICAL",
                title="Güvensiz ve Kullanımdan Kaldırılmış DSA Anahtarı",
                description=f"'{key.path}' anahtarı 1024-bit DSA algoritması kullanmaktadır. DSA şifreleme standardı güvensizdir ve OpenSSH tarafından terk edilmiştir.",
                remediation_advice="DSA anahtarını derhal iptal edin ve yerine Ed25519 anahtarı üretin: ssh-keygen -t ed25519",
                deduction_points=20.0
            ))
        # RSA anahtarları minimum 2048 bit olmalıdır (3072+ önerilir)
        elif key.key_type.lower() == "rsa" and key.key_bits < 2048:
            self.findings.append(SecurityFinding(
                rule_id="SSH-004",
                target=key.path,
                cwe="CWE-326",
                mitre_attack="T1552.004",
                severity="HIGH",
                title="Yetersiz RSA Anahtar Uzunluğu (< 2048 bit)",
                description=f"'{key.path}' anahtarı {key.key_bits} bit uzunluğundadır. RSA için minimum güvenli uzunluk 2048 bittir.",
                remediation_advice="En az 3072 bit RSA veya modern Ed25519 anahtarına geçiş yapın.",
                deduction_points=15.0
            ))

    def _audit_authorized_key(self, auth_entry: AuthorizedKeyEntry) -> None:
        """
        authorized_keys dosya izinlerini ve anahtar girişlerini inceler.
        """
        # Kural 4: authorized_keys Dosya İzinleri ve Sahipliği (CWE-732 / T1098.004)
        if auth_entry.file_path and self._is_mode_too_permissive(auth_entry.file_mode, threshold=0o644):
            self.findings.append(SecurityFinding(
                rule_id="SSH-005",
                target=auth_entry.file_path,
                cwe="CWE-732",
                mitre_attack="T1098.004",
                severity="CRITICAL",
                title="Gevşek authorized_keys Dosya İzinleri (Yazılabilir)",
                description=f"'{auth_entry.file_path}' dosyasının izinleri ({auth_entry.file_mode}) başkalarına yazma hakkı vermektedir. Saldırgan kendi açık anahtarını ekleyebilir.",
                remediation_advice=f"Dosya izinlerini sıkılaştırın: chmod 0600 {auth_entry.file_path}",
                deduction_points=20.0
            ))

        # Kural 5: authorized_keys İçinde Zayıf DSA/Küçük RSA Anahtarı Kullanımı (CWE-327)
        if auth_entry.key_type.lower() in ["ssh-dss", "dsa"]:
            self.findings.append(SecurityFinding(
                rule_id="SSH-006",
                target=f"authorized_keys ({auth_entry.comment or auth_entry.user})",
                cwe="CWE-327",
                mitre_attack="T1078.003",
                severity="HIGH",
                title="authorized_keys Dosyasında Zayıf DSA Anahtarı Tanımlı",
                description=f"Kullanıcı '{auth_entry.user}' için yetkilendirilmiş DSA anahtarı tespit edildi. Zayıf anahtarla giriş yapılabilir.",
                remediation_advice="Bu açık anahtarı authorized_keys dosyasından silin ve Ed25519 ile değiştirin.",
                deduction_points=15.0
            ))

    def _audit_sshd_config(self, sshd: SshdConfig) -> None:
        """
        sshd_config sunucu direktiflerini CIS Benchmark standartlarına göre denetler.
        """
        # Kural 6: PermitRootLogin Denetimi (CIS 5.2.5 / CWE-250 / T1078.003)
        if sshd.permit_root_login.lower() == "yes":
            self.findings.append(SecurityFinding(
                rule_id="SSH-007",
                target="/etc/ssh/sshd_config:PermitRootLogin",
                cwe="CWE-250",
                mitre_attack="T1078.003",
                severity="HIGH",
                title="Doğrudan Root SSH Girişine İzin Verilmiş (PermitRootLogin yes)",
                description="Root kullanıcısının SSH üzerinden doğrudan oturum açması açıktır. Kaba kuvvet saldırılarına ve denetimsiz yetki kullanımına yol açar.",
                remediation_advice="PermitRootLogin direktifini 'no' veya 'prohibit-password' olarak ayarlayın.",
                deduction_points=15.0
            ))

        # Kural 7: PasswordAuthentication Denetimi (CIS 5.2.9 / CWE-307 / T1110.001)
        if sshd.password_authentication:
            self.findings.append(SecurityFinding(
                rule_id="SSH-008",
                target="/etc/ssh/sshd_config:PasswordAuthentication",
                cwe="CWE-307",
                mitre_attack="T1110.001",
                severity="HIGH",
                title="Parola ile Kimlik Doğrulama Açık (PasswordAuthentication yes)",
                description="SSH servisinde parola tabanlı giriş açıktır. Sunucu sözlük ve kaba kuvvet saldırılarına açık kalmaktadır.",
                remediation_advice="Parola doğrulamasını kapatıp sadece anahtara zorlayın: PasswordAuthentication no",
                deduction_points=15.0
            ))

        # Kural 8: PermitEmptyPasswords Denetimi (CIS 5.2.11 / CWE-258 / T1078)
        if sshd.permit_empty_passwords:
            self.findings.append(SecurityFinding(
                rule_id="SSH-009",
                target="/etc/ssh/sshd_config:PermitEmptyPasswords",
                cwe="CWE-258",
                mitre_attack="T1078",
                severity="CRITICAL",
                title="Boş Parola ile SSH Girişine İzin Verilmiş (PermitEmptyPasswords yes)",
                description="Boş şifreli hesapların SSH ile şifresiz sisteme girmesine izin verilmektedir.",
                remediation_advice="PermitEmptyPasswords direktifini derhal 'no' yapın.",
                deduction_points=20.0
            ))

        # Kural 9: MaxAuthTries Denetimi (CIS 5.2.7 / CWE-307)
        if sshd.max_auth_tries > 4:
            self.findings.append(SecurityFinding(
                rule_id="SSH-010",
                target="/etc/ssh/sshd_config:MaxAuthTries",
                cwe="CWE-307",
                mitre_attack="T1110.001",
                severity="MEDIUM",
                title="Maksimum Başarısız Giriş Denemesi Sınırı Çok Yüksek (MaxAuthTries > 4)",
                description=f"MaxAuthTries değeri {sshd.max_auth_tries} olarak yapılandırılmış. CIS standardı maksimum 4 önermektedir.",
                remediation_advice="MaxAuthTries değerini 3 veya 4 olarak sınırlayın.",
                deduction_points=8.0
            ))

        # Kural 10: X11Forwarding Denetimi (CIS 5.2.6 / CWE-200)
        if sshd.x11_forwarding:
            self.findings.append(SecurityFinding(
                rule_id="SSH-011",
                target="/etc/ssh/sshd_config:X11Forwarding",
                cwe="CWE-200",
                mitre_attack="T1059",
                severity="LOW",
                title="X11 Grafik Yönlendirmesi Aktif (X11Forwarding yes)",
                description="Sunucularda gereksiz X11 yönlendirmesi pencere yakalama ve tuş vuruşu izleme risklerine yol açabilir.",
                remediation_advice="X11Forwarding direktifini 'no' yapın.",
                deduction_points=4.0
            ))

        # Kural 11: ClientAlive Oturum Zaman Aşımı Denetimi (CIS 5.2.16 / CWE-613)
        if sshd.client_alive_interval == 0 or sshd.client_alive_interval > 900:
            self.findings.append(SecurityFinding(
                rule_id="SSH-012",
                target="/etc/ssh/sshd_config:ClientAliveInterval",
                cwe="CWE-613",
                mitre_attack="T1078",
                severity="LOW",
                title="SSH Oturum Hareketsizlik Zaman Aşımı Eksik veya Çok Uzun",
                description="Boşta kalan SSH oturumları otomatik sonlandırılmamaktadır veya 15 dakikadan uzundur.",
                remediation_advice="ClientAliveInterval 300 ve ClientAliveCountMax 2 olarak yapılandırın.",
                deduction_points=5.0
            ))

    def _is_mode_too_permissive(self, mode_str: str, threshold: int = 0o600) -> bool:
        """
        Dosya izin modunu eşik değerle karşılaştırır.
        """
        try:
            mode_int = int(mode_str, 8)
            # Others yazma veya okuma izni varsa
            if mode_int & 0o007:
                # Eşik 0600 iken others'ta izin olması kabul edilemez
                if threshold <= 0o600:
                    return True
                # Eşik 0644 iken others'ta yazma izni (002) varsa gevşektir
                if mode_int & 0o002:
                    return True
            # Group yazma izni varsa
            if mode_int & 0o020:
                return True
            return mode_int > threshold
        except (ValueError, TypeError):
            return True

    def parse_sshd_config(self, content: str) -> SshdConfig:
        """
        Ham bir sshd_config metnini satır satır ayrıştırarak SshdConfig nesnesi üretir.
        """
        cfg = SshdConfig()

        for line in content.splitlines():
            stripped = line.strip()
            # Yorum veya boş satırlar atlanır
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split(None, 1)
            if len(parts) < 2:
                continue

            key = parts[0].strip().lower()
            val = parts[1].strip()

            if key == "permitrootlogin":
                cfg.permit_root_login = val.lower()
            elif key == "passwordauthentication":
                cfg.password_authentication = val.lower() in ["yes", "true"]
            elif key == "pubkeyauthentication":
                cfg.pubkey_authentication = val.lower() in ["yes", "true"]
            elif key == "permitemptypasswords":
                cfg.permit_empty_passwords = val.lower() in ["yes", "true"]
            elif key == "x11forwarding":
                cfg.x11_forwarding = val.lower() in ["yes", "true"]
            elif key == "maxauthtries":
                try:
                    cfg.max_auth_tries = int(val)
                except ValueError:
                    pass
            elif key == "clientaliveinterval":
                try:
                    cfg.client_alive_interval = int(val)
                except ValueError:
                    pass
            elif key == "clientalivecountmax":
                try:
                    cfg.client_alive_count_max = int(val)
                except ValueError:
                    pass
            elif key == "port":
                try:
                    cfg.port = int(val)
                except ValueError:
                    pass

        return cfg

    def parse_inventory_json(self, json_data: Dict[str, Any]) -> tuple[List[SshKey], List[AuthorizedKeyEntry], SshdConfig]:
        """
        JSON envanter verisini ayrıştırıp SshKey, AuthorizedKeyEntry ve SshdConfig nesneleri döner.
        """
        keys: List[SshKey] = []
        for k in json_data.get("ssh_keys", []):
            keys.append(SshKey(
                name=k.get("name", "unknown_key"),
                path=k.get("path", "/root/.ssh/id_rsa"),
                key_type=k.get("key_type", "rsa"),
                key_bits=k.get("key_bits", 2048),
                is_private=k.get("is_private", True),
                is_passphrase_protected=k.get("is_passphrase_protected", False),
                file_owner=k.get("file_owner", "root"),
                file_group=k.get("file_group", "root"),
                file_mode=k.get("file_mode", "0600"),
                associated_user=k.get("associated_user", "root")
            ))

        auth_keys: List[AuthorizedKeyEntry] = []
        for a in json_data.get("authorized_keys", []):
            auth_keys.append(AuthorizedKeyEntry(
                user=a.get("user", "root"),
                key_type=a.get("key_type", "ssh-rsa"),
                key_bits=a.get("key_bits", 2048),
                comment=a.get("comment", ""),
                options=a.get("options", []),
                file_path=a.get("file_path", "/root/.ssh/authorized_keys"),
                file_mode=a.get("file_mode", "0600"),
                file_owner=a.get("file_owner", "root")
            ))

        sshd_dict = json_data.get("sshd_config", {})
        sshd = SshdConfig(
            permit_root_login=sshd_dict.get("permit_root_login", "no"),
            password_authentication=sshd_dict.get("password_authentication", False),
            pubkey_authentication=sshd_dict.get("pubkey_authentication", True),
            permit_empty_passwords=sshd_dict.get("permit_empty_passwords", False),
            x11_forwarding=sshd_dict.get("x11_forwarding", False),
            max_auth_tries=sshd_dict.get("max_auth_tries", 4),
            client_alive_interval=sshd_dict.get("client_alive_interval", 300),
            client_alive_count_max=sshd_dict.get("client_alive_count_max", 2),
            port=sshd_dict.get("port", 22),
            config_file_mode=sshd_dict.get("config_file_mode", "0600"),
            config_file_owner=sshd_dict.get("config_file_owner", "root")
        )

        return keys, auth_keys, sshd

    def generate_remediation_script(
        self,
        keys: List[SshKey],
        auth_keys: List[AuthorizedKeyEntry],
        sshd: SshdConfig
    ) -> str:
        """
        SSH zafiyetlerini gideren tam çalıştırılabilir Bash sertleştirme betiği üretir.
        """
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Linux SSH Anahtar ve Sunucu Güvenliği Otomatik Sıkılaştırma Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "echo '[+] SSH güvenlik sertleştirmesi başlatılıyor...'",
            "",
            "# --- 1. Adım: SSH Dosya ve Dizin İzinlerini Düzelt ---"
        ]

        # Özel anahtar izinlerini düzeltme
        for k in keys:
            if k.is_private and self._is_mode_too_permissive(k.file_mode, threshold=0o600):
                lines.append(f"echo '[*] Özel anahtar izinleri kilitleniyor: {k.path}'")
                lines.append(f"chmod 0600 {k.path}")
                lines.append(f"chown {k.associated_user}:{k.associated_user} {k.path} 2>/dev/null || chown root:root {k.path}")

        # authorized_keys izinlerini düzeltme
        for a in auth_keys:
            if a.file_path and self._is_mode_too_permissive(a.file_mode, threshold=0o644):
                lines.append(f"echo '[*] authorized_keys izinleri kilitleniyor: {a.file_path}'")
                lines.append(f"chmod 0600 {a.file_path}")
                lines.append(f"chown {a.user}:{a.user} {a.file_path} 2>/dev/null || chown root:root {a.file_path}")

        lines.extend([
            "",
            "# --- 2. Adım: sshd_config CIS Standartlarında Sıkılaştırma ---",
            "SSHD_CONFIG='/etc/ssh/sshd_config'",
            "BACKUP_CONFIG=\"/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)\"",
            "cp \"$SSHD_CONFIG\" \"$BACKUP_CONFIG\"",
            "echo \"[*] sshd_config yedeği alındı: $BACKUP_CONFIG\"",
            "",
            "# Güvenlik direktiflerini uygula",
            "sed -i -E 's/^#?PermitRootLogin .*/PermitRootLogin no/' \"$SSHD_CONFIG\"",
            "sed -i -E 's/^#?PasswordAuthentication .*/PasswordAuthentication no/' \"$SSHD_CONFIG\"",
            "sed -i -E 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' \"$SSHD_CONFIG\"",
            "sed -i -E 's/^#?PermitEmptyPasswords .*/PermitEmptyPasswords no/' \"$SSHD_CONFIG\"",
            "sed -i -E 's/^#?X11Forwarding .*/X11Forwarding no/' \"$SSHD_CONFIG\"",
            "sed -i -E 's/^#?MaxAuthTries .*/MaxAuthTries 3/' \"$SSHD_CONFIG\"",
            "sed -i -E 's/^#?ClientAliveInterval .*/ClientAliveInterval 300/' \"$SSHD_CONFIG\"",
            "sed -i -E 's/^#?ClientAliveCountMax .*/ClientAliveCountMax 2/' \"$SSHD_CONFIG\"",
            "",
            "# Dosya izinlerini kovala",
            "chown root:root \"$SSHD_CONFIG\"",
            "chmod 0600 \"$SSHD_CONFIG\"",
            "",
            "# Yapılandırma sözdizimini doğrula ve servisi yeniden yükle",
            "if sshd -t; then",
            "    echo '[*] sshd yapılandırma sözdizimi doğrulandı. Servis yeniden yükleniyor...'",
            "    systemctl reload sshd || systemctl reload ssh",
            "    echo '[✓] SSH sunucusu başarıyla sertleştirildi.'",
            "else",
            "    echo '[-] HATA: sshd sözdizimi hatalı! Yedek geri yükleniyor...'",
            "    cp \"$BACKUP_CONFIG\" \"$SSHD_CONFIG\"",
            "    exit 1",
            "fi"
        ])

        return "\n".join(lines)

    def generate_hardened_sshd_config(self) -> str:
        """
        CIS Linux Benchmark Section 5.2 standartlarına tam uyumlu örnek sshd_config üretir.
        """
        lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# CIS Linux Benchmark v2.0.0 Uyumlu Güvenli OpenSSH Sunucu Yapılandırması",
            "# ==============================================================================",
            "Port 22",
            "Protocol 2",
            "HostKey /etc/ssh/ssh_host_ed25519_key",
            "HostKey /etc/ssh/ssh_host_rsa_key",
            "",
            "# --- Kimlik Doğrulama ve Yetkilendirme ---",
            "PermitRootLogin no",
            "PubkeyAuthentication yes",
            "PasswordAuthentication no",
            "PermitEmptyPasswords no",
            "AuthenticationMethods publickey",
            "MaxAuthTries 3",
            "MaxSessions 4",
            "",
            "# --- Oturum ve İletim İzolasyonu ---",
            "X11Forwarding no",
            "AllowAgentForwarding no",
            "AllowTcpForwarding no",
            "ClientAliveInterval 300",
            "ClientAliveCountMax 2",
            "LoginGraceTime 60",
            "",
            "# --- Kriptografik Algoritmalar (Modern & Güvenli) ---",
            "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
            "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
            "",
            "# --- Günlükleme ve Uyarı ---",
            "LogLevel VERBOSE",
            "Banner /etc/issue.net"
        ]
        return "\n".join(lines)
