# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Servisleri ve Systemd Güvenlik Motoru (LinuxSystemdSecurityEngine)
Bu modül, systemd servis birimlerinin (unit files) güvenlik yapılandırmalarını,
sandboxing direktiflerini (NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp,
PrivateDevices), dosya sistemi izinlerini, ExecStart ikili dosya güvenliğini ve
CIS Linux Benchmark gereksinimlerine göre gereksiz/tehlikeli servisleri denetler.
"""

# Tip ipuçları için standart kütüphane sınıfları içe aktarılır
from typing import Dict, List, Any, Optional
# Veri yapılarını nesne yönelimli temsil etmek için dataclass modülü dahil edilir
from dataclasses import dataclass, field
# Düzenli ifadeler ile metin analizi yapmak için re modülü dahil edilir
import re
# Dosya yolu işlemleri için os modülü dahil edilir
import os
# JSON formatında girdi ve çıktı yönetimi için json modülü dahil edilir
import json


@dataclass
class ServiceUnit:
    """
    Bir systemd servis biriminin (unit) tüm yapılandırma ve dosya özelliklerini temsil eder.
    """
    # Servisin birim adı (Örn: nginx.service, custom-api.service)
    name: str
    # Servis dosyasının disk üzerindeki mutlak yolu (Örn: /etc/systemd/system/nginx.service)
    path: str
    # Servis unit dosyasının sahibi (Örn: root)
    file_owner: str = "root"
    # Servis unit dosyasının grubu (Örn: root)
    file_group: str = "root"
    # Servis unit dosyasının izin modu (Örn: 0644)
    file_mode: str = "0644"
    # Servisin insan tarafından okunabilir açıklaması
    description: str = ""
    # Servisin hangi kullanıcı kimliğiyle çalışacağı (Boş veya root ise tehlikelidir)
    user: str = ""
    # Servisin hangi grup kimliğiyle çalışacağı
    group: str = ""
    # Servisi başlatan komut ve ikili dosya yolu (ExecStart)
    exec_start: str = ""
    # ExecStart ile hedeflenen ikili dosyanın disk üzerindeki sahibi
    binary_owner: str = "root"
    # ExecStart ile hedeflenen ikili dosyanın dosya modu
    binary_mode: str = "0755"
    # ExecStart ikili dosyasında SUID biti bulunup bulunmadığı
    binary_suid: bool = False
    # Alt süreçlerin yeni yetki kazanmasını engelleyen bayrak (prctl PR_SET_NO_NEW_PRIVS)
    no_new_privileges: bool = False
    # Dosya sistemini salt-okunur bağlama derecesi (strict, full, yes, no, boş)
    protect_system: str = ""
    # Kullanıcı ev dizinlerini gizleme derecesi (yes, read-only, tmpfs, no, boş)
    protect_home: str = ""
    # Sürece özel /tmp ve /var/tmp namespace'i oluşturma bayrağı
    private_tmp: bool = False
    # Fiziksel donanım aygıtlarına (/dev) doğrudan raw erişimi engelleme bayrağı
    private_devices: bool = False
    # Çekirdek parametrelerinin (/proc/sys, /sys) değiştirilmesini engelleme bayrağı
    protect_kernel_tunables: bool = False
    # Kontrol gruplarının (/sys/fs/cgroup) değiştirilmesini engelleme bayrağı
    protect_control_groups: bool = False
    # Servisin sahip olabileceği Linux çekirdek yetenekleri listesi (CapabilityBoundingSet)
    capability_bounding_set: List[str] = field(default_factory=list)
    # Servisin erişebileceği ağ soket aileleri (Örn: AF_INET, AF_INET6)
    restrict_address_families: List[str] = field(default_factory=list)
    # Servisin sistem açılışında otomatik başlatılıp başlatılmayacağı
    enabled: bool = True
    # Servisin şu anda çalışır (active/running) durumda olup olmadığı
    active: bool = True
    # Servisin maskelenmiş (mask) olup olmadığı (devre dışı bırakmanın en güçlü hali)
    masked: bool = False


@dataclass
class SecurityFinding:
    """
    Denetim sırasında tespit edilen her bir güvenlik bulgusunu temsil eder.
    """
    # Bulguyu tanımlayan benzersiz kod (Örn: SYS-001)
    rule_id: str
    # Bulgudan etkilenen servis birimi adı
    service_name: str
    # Ortak zafiyet numaralandırması (CWE) referansı
    cwe: str
    # MITRE ATT&CK matrisi taktik ve teknik referansı
    mitre_attack: str
    # Bulgusunun tehlike derecesi (CRITICAL, HIGH, MEDIUM, LOW)
    severity: str
    # Bulgusunun kısa başlığı
    title: str
    # Bulgusunun ayrıntılı teknik açıklaması ve güvenlik riski
    description: str
    # Zafiyeti gidermek için önerilen somut iyileştirme adımı
    remediation_advice: str
    # Sistem genel güvenlik puanından düşülecek ceza puanı
    deduction_points: float


class LinuxSystemdSecurityEngine:
    """
    Systemd servis birimlerinin güvenlik denetimini, sandboxing analizini,
    risk puanlamasını ve otomatik sertleştirme betiği üretimini gerçekleştiren motor.
    """

    # CIS Benchmark standartlarına göre kurumsal sunucularda aktif olmaması gereken güvensiz servisler
    LEGACY_INSECURE_SERVICES = {
        "telnet.socket": "Telnet şifrelenmemiş metin protokolü (CIS 2.1.1)",
        "telnet.service": "Telnet şifrelenmemiş metin servisi (CIS 2.1.1)",
        "rsh.service": "Uzak kabuk (RSH) güvensiz kimlik doğrulama (CIS 2.1.2)",
        "rlogin.service": "Rlogin şifrelenmemiş oturum servisi (CIS 2.1.3)",
        "rexec.service": "Rexec uzaktan komut yürütme servisi (CIS 2.1.4)",
        "tftp.service": "TFTP kimlik doğrulamasız dosya transferi (CIS 2.1.5)",
        "tftp.socket": "TFTP dinleme soketi (CIS 2.1.5)",
        "xinetd.service": "Xinetd eski süper sunucu mekanizması (CIS 2.1.6)",
        "chargen.service": "Chargen DoS yükseltme vektörü servisi",
        "daytime.service": "Daytime bilgi sızdırma servisi",
        "echo.service": "Echo DoS yükseltme vektörü servisi",
        "avahi-daemon.service": "mDNS sıfır-yapılandırma ağ yayını (CIS 2.2.3)",
        "cups.service": "CUPS yazdırma sunucusu genel sunucularda gereksizdir (CIS 2.2.4)",
        "nfs-server.service": "Gereksiz NFS dosya paylaşım servisi (CIS 2.2.8)"
    }

    # Süreçlere verilmesi son derece tehlikeli olan Linux yetenekleri (Capabilities)
    DANGEROUS_CAPABILITIES = {
        "CAP_SYS_ADMIN",    # Tam sistem yöneticisi yetkileri, container kaçışı ve kernel modifikasyonu
        "CAP_SYS_PTRACE",   # Diğer süreçlerin belleğini okuma ve shellcode enjekte etme
        "CAP_SYS_RAWIO",    # Ham I/O ve donanım belleğine doğrudan erişim
        "CAP_SYS_MODULE",   # Çekirdeğe dinamik kernel modülü (LKM) yükleme
        "CAP_SETUID",       # Keyfi UID değiştirme (root olma)
        "CAP_SETGID",       # Keyfi GID değiştirme
        "CAP_DAC_OVERRIDE", # Dosya okuma/yazma izinlerini bypass etme
        "CAP_DAC_READ_SEARCH" # Dosya izinlerini bypass ederek okuma
    }

    def __init__(self) -> None:
        """
        Güvenlik motorunu başlatır ve bulgu listesini hazırlar.
        """
        # Denetim esnasında tespit edilen bulguların tutulduğu liste
        self.findings: List[SecurityFinding] = []

    def audit_services(self, services: List[ServiceUnit]) -> Dict[str, Any]:
        """
        Verilen servis birimlerini baştan sona denetler, puanlar ve rapor üretir.
        """
        # Bulgular listesi her denetim başında sıfırlanır
        self.findings.clear()

        # Sistemdeki servis sayısı kontrol edilir; boşsa sıfır puan döner
        if not services:
            # Boş liste durumunda yapılandırılmış varsayılan çıktı üretilir
            return {
                "guvenlik_skoru": 0.0,
                "durum": "KRİTİK RİSK (EN SIKINTILI)",
                "toplam_servis": 0,
                "denetlenen_servis_sayisi": 0,
                "toplam_bulgu": 0,
                "bulgular": [],
                "servis_detaylari": []
            }

        # Servis bazlı detay analiz listesi oluşturulur
        service_evaluations: List[Dict[str, Any]] = []

        # Her bir servis birimi sırayla incelenir
        for service in services:
            # Servis için exposure (maruziyet) analizi ve bulgu denetimi yapılır
            service_eval = self._audit_single_service(service)
            # Analiz sonucu listeye eklenir
            service_evaluations.append(service_eval)

        # Genel sistem puanı hesaplanır (100.0 üzerinden toplam ceza puanları düşülür)
        total_deduction = sum(f.deduction_points for f in self.findings)
        # Puanın 0.0 ile 100.0 arasında kalması güvence altına alınır
        final_score = max(0.0, min(100.0, 100.0 - total_deduction))

        # Puan eşiklerine göre nihai sistem güvenlik durumu belirlenir
        if final_score >= 80.0:
            status_text = "GÜVENLİ (STANDARTLARA UYGUN)"
        elif final_score >= 60.0:
            status_text = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            status_text = "KRİTİK RİSK (ACİL MÜDAHALE GEREKLİ)"

        # Denetim sonuç raporu sözlük olarak döndürülür
        return {
            "guvenlik_skoru": round(final_score, 1),
            "durum": status_text,
            "toplam_servis": len(services),
            "toplam_bulgu": len(self.findings),
            "kritik_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "yuksek_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "HIGH"),
            "orta_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "dusuk_bulgu_sayisi": sum(1 for f in self.findings if f.severity == "LOW"),
            "bulgular": [
                {
                    "rule_id": f.rule_id,
                    "service_name": f.service_name,
                    "cwe": f.cwe,
                    "mitre_attack": f.mitre_attack,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation_advice": f.remediation_advice,
                    "deduction_points": f.deduction_points
                }
                for f in self.findings
            ],
            "servis_detaylari": service_evaluations
        }

    def _audit_single_service(self, service: ServiceUnit) -> Dict[str, Any]:
        """
        Tek bir servis biriminin güvenlik direktiflerini ve dosya izinlerini inceler.
        """
        # Servise özgü yerel bulgular listesi
        local_findings: List[SecurityFinding] = []
        # systemd-analyze security benzeri exposure (0.0 en güvenli, 10.0 en tehlikeli) puanı
        exposure_score: float = 0.0

        # Kural 1: Güvensiz / Gereksiz Legacy Servis Kontrolü (CIS 2.1 & 2.2)
        if service.name in self.LEGACY_INSECURE_SERVICES and (service.active or service.enabled) and not service.masked:
            # Zafiyet bulgusu oluşturulur
            finding = SecurityFinding(
                rule_id="SYS-001",
                service_name=service.name,
                cwe="CWE-250",
                mitre_attack="T1059",
                severity="HIGH",
                title="Gereksiz ve Güvensiz Servis Aktif (CIS Benchmark)",
                description=f"'{service.name}' servisi kurumsal sunucularda aktif olmamalıdır: {self.LEGACY_INSECURE_SERVICES[service.name]}.",
                remediation_advice=f"Servisi durdurun, devre dışı bırakın ve maskeleyin: systemctl disable --now {service.name} && systemctl mask {service.name}",
                deduction_points=15.0
            )
            # Genel ve yerel listelere eklenir
            self.findings.append(finding)
            local_findings.append(finding)
            # Exposure skoru artırılır
            exposure_score += 2.5

        # Kural 2: Servis Unit Dosya İzinleri ve Sahipliği (CWE-732 / T1543.002)
        is_mode_loose = self._is_mode_too_permissive(service.file_mode, threshold=0o644)
        is_owner_non_root = (service.file_owner != "root" or service.file_group != "root")
        if is_mode_loose or is_owner_non_root:
            # Servis dosyasının yetkisizlerce yazılabilir olması sistem ele geçirme riskidir
            finding = SecurityFinding(
                rule_id="SYS-002",
                service_name=service.name,
                cwe="CWE-732",
                mitre_attack="T1543.002",
                severity="CRITICAL",
                title="Gevşek Servis Unit Dosyası İzinleri / Sahipliği",
                description=f"Unit dosyası '{service.path}' izinleri ({service.file_mode}) veya sahipliği ({service.file_owner}:{service.file_group}) güvensizdir. Yazma yetkisi olan kullanıcı ExecStart komutunu değiştirip root olabilir.",
                remediation_advice=f"Dosya sahipliğini root yapın ve izinleri 0644 ile sınırlandırın: chown root:root {service.path} && chmod 0644 {service.path}",
                deduction_points=20.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 3.0

        # Kural 3: ExecStart İkili Dosya (Binary) İzinleri ve SUID Biti (CWE-732 / CWE-250 / T1548.001)
        is_bin_mode_loose = self._is_mode_too_permissive(service.binary_mode, threshold=0o755)
        if is_bin_mode_loose or service.binary_suid:
            # Hedef binary tahrif edilebilir veya SUID bayrağı barındırıyor
            finding = SecurityFinding(
                rule_id="SYS-003",
                service_name=service.name,
                cwe="CWE-732",
                mitre_attack="T1548.001",
                severity="CRITICAL",
                title="Güvensiz Servis Binary İzinleri veya SUID Bayrağı",
                description=f"Servisin çalıştırdığı ikili dosya gevşek izinlere ({service.binary_mode}) sahiptir veya tehlikeli SUID bayrağı içermektedir (SUID: {service.binary_suid}).",
                remediation_advice="İkili dosyanın yazma izinlerini yalnızca root ile sınırlandırın (chmod 0755) ve gereksiz SUID bitini kaldırın (chmod u-s).",
                deduction_points=20.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 3.0

        # Kural 4: Servisin root Olarak Çalışması veya User Tanımsızlığı (CWE-250 / T1068)
        # Eğer servis legacy/insecure değilse ve kullanıcı root ise veya boşsa (systemd varsayılanı root'tur)
        if not service.user or service.user == "root":
            # Servis en yüksek yetkilerle çalışıyor
            finding = SecurityFinding(
                rule_id="SYS-004",
                service_name=service.name,
                cwe="CWE-250",
                mitre_attack="T1068",
                severity="HIGH",
                title="Servis 'root' Kullanıcısıyla Çalıştırılıyor (Aşırı Yetki)",
                description=f"'{service.name}' servisinde 'User=' direktifi tanımlanmamış veya doğrudan 'root' olarak atanmıştır. Servis zafiyete uğradığında saldırgan doğrudan root hakları kazanır.",
                remediation_advice="Servis için ayrılmış yetkisiz bir sistem kullanıcısı oluşturun ve unit dosyasına ekleyin (Örn: User=appuser, Group=appuser).",
                deduction_points=15.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 2.0

        # Kural 5: NoNewPrivileges Direktifinin Olmaması (CWE-250 / T1548)
        if not service.no_new_privileges:
            # Servisin alt süreçleri SUID dosyaları çalıştırıp yetki yükseltebilir
            finding = SecurityFinding(
                rule_id="SYS-005",
                service_name=service.name,
                cwe="CWE-250",
                mitre_attack="T1548",
                severity="HIGH",
                title="NoNewPrivileges Sandboxing Direktifi Eksik",
                description=f"'{service.name}' servisinde 'NoNewPrivileges=yes' tanımlanmamış. Bu durum, servisin SUID/SGID ikili dosyaları kullanarak çekirdek seviyesinde yetki yükseltmesine izin verir.",
                remediation_advice="Unit dosyasının [Service] bölümüne 'NoNewPrivileges=yes' satırını ekleyin.",
                deduction_points=10.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 1.5

        # Kural 6: ProtectSystem Eksikliği (CWE-732 / T1565.001)
        if service.protect_system not in ["strict", "full", "yes"]:
            # Dosya sistemi tahrifatına açık
            finding = SecurityFinding(
                rule_id="SYS-006",
                service_name=service.name,
                cwe="CWE-732",
                mitre_attack="T1565.001",
                severity="MEDIUM",
                title="ProtectSystem Dosya Koruma Direktifi Eksik veya Yetersiz",
                description=f"'{service.name}' servisinde ProtectSystem değeri '{service.protect_system or 'tanımsız'}'. Bu durum /usr, /boot ve /etc dizinlerinin değiştirilmesine yol açabilir.",
                remediation_advice="Unit dosyasının [Service] bölümüne 'ProtectSystem=strict' veya 'ProtectSystem=full' direktifini ekleyin.",
                deduction_points=8.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 1.0

        # Kural 7: ProtectHome Eksikliği (CWE-200 / T1005)
        if service.protect_home not in ["yes", "read-only", "tmpfs"]:
            # Kullanıcı ev dizinlerine ve SSH anahtarlarına erişim riski
            finding = SecurityFinding(
                rule_id="SYS-007",
                service_name=service.name,
                cwe="CWE-200",
                mitre_attack="T1005",
                severity="MEDIUM",
                title="ProtectHome Ev Dizini İzolasyonu Eksik",
                description=f"'{service.name}' servisinde ProtectHome değeri '{service.protect_home or 'tanımsız'}'. Servis süreçleri /home, /root ve /run/user altındaki hassas verilere erişebilir.",
                remediation_advice="Unit dosyasının [Service] bölümüne 'ProtectHome=yes' veya 'ProtectHome=read-only' ekleyin.",
                deduction_points=8.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 1.0

        # Kural 8: PrivateTmp Eksikliği (CWE-377 / CWE-379)
        if not service.private_tmp:
            # Geçici dosya yarış koşulları ve sembolik bağ saldırıları
            finding = SecurityFinding(
                rule_id="SYS-008",
                service_name=service.name,
                cwe="CWE-377",
                mitre_attack="T1059",
                severity="LOW",
                title="PrivateTmp Geçici Dizin İzolasyonu Eksik",
                description=f"'{service.name}' servisinde 'PrivateTmp=yes' aktif değil. Servis ortak /tmp alanını kullanmakta ve symlink/race condition saldırılarına açık kalmaktadır.",
                remediation_advice="Unit dosyasının [Service] bölümüne 'PrivateTmp=yes' ekleyerek yalıtılmış geçici dosya alanı tanımlayın.",
                deduction_points=4.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 0.5

        # Kural 9: PrivateDevices Eksikliği (CWE-250)
        if not service.private_devices:
            # Ham donanım aygıtlarına erişim riski
            finding = SecurityFinding(
                rule_id="SYS-009",
                service_name=service.name,
                cwe="CWE-250",
                mitre_attack="T1059",
                severity="LOW",
                title="PrivateDevices Ham Donanım İzolasyonu Eksik",
                description=f"'{service.name}' servisinde 'PrivateDevices=yes' aktif değil. Servis süreçleri doğrudan disk ve bellek blok aygıtlarına erişim talep edebilir.",
                remediation_advice="Unit dosyasının [Service] bölümüne 'PrivateDevices=yes' direktifini ekleyin.",
                deduction_points=4.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 0.5

        # Kural 10: Tehlikeli Linux Capabilities Denetimi (CWE-250 / T1548)
        found_dangerous_caps = [cap for cap in service.capability_bounding_set if cap in self.DANGEROUS_CAPABILITIES]
        if found_dangerous_caps:
            # Sürece aşırı çekirdek yetenekleri devredilmiş
            finding = SecurityFinding(
                rule_id="SYS-010",
                service_name=service.name,
                cwe="CWE-250",
                mitre_attack="T1548",
                severity="HIGH",
                title="Tehlikeli Linux Çekirdek Yetenekleri (Capabilities) Tanımlı",
                description=f"'{service.name}' servisine tehlikeli çekirdek yetenekleri tahsis edilmiştir: {', '.join(found_dangerous_caps)}.",
                remediation_advice=f"CapabilityBoundingSet direktifinden şu yetenekleri çıkarın: {', '.join(found_dangerous_caps)}.",
                deduction_points=12.0
            )
            self.findings.append(finding)
            local_findings.append(finding)
            exposure_score += 2.0

        # Exposure skorunun en fazla 10.0 olması sağlanır
        bounded_exposure = min(10.0, round(exposure_score, 1))

        # Servis maruziyet seviyesi etiketi belirlenir
        if bounded_exposure <= 2.0:
            exposure_label = "OK (DÜŞÜK RİSK)"
        elif bounded_exposure <= 5.0:
            exposure_label = "MEDIUM (ORTA RİSK)"
        elif bounded_exposure <= 7.5:
            exposure_label = "HIGH (YÜKSEK RİSK)"
        else:
            exposure_label = "UNSAFE (ÇOK TEHLİKELİ)"

        # Servis değerlendirme özeti döndürülür
        return {
            "name": service.name,
            "path": service.path,
            "user": service.user or "root (varsayılan)",
            "exposure_skoru": bounded_exposure,
            "exposure_seviyesi": exposure_label,
            "bulgu_sayisi": len(local_findings),
            "bulgular": [f.title for f in local_findings]
        }

    def _is_mode_too_permissive(self, mode_str: str, threshold: int = 0o644) -> bool:
        """
        Sekizli (octal) izin modunu eşik değerle karşılaştırır.
        Örneğin 0666 veya 0777 gibi modlar 0644'ten daha gevşektir.
        """
        try:
            # Sekizli string sayısal tamsayıya dönüştürülür
            mode_int = int(mode_str, 8)
            # Diğer kullanıcılar (others) için yazma izni (0002) kontrol edilir
            if mode_int & 0o002:
                # Herkese yazma izni verilmişse kesinlikle gevşektir
                return True
            # Grup (group) için yazma izni (0020) kontrol edilir
            if mode_int & 0o020:
                # Gruba yazma izni verilmişse de gevşektir
                return True
            # Genel izin büyüklüğü eşikle karşılaştırılır
            return mode_int > threshold
        except (ValueError, TypeError):
            # Geçersiz format durumunda güvenlik gereği gevşek varsayılır
            return True

    def parse_unit_file(self, content: str, service_name: str = "custom.service", file_path: str = "/etc/systemd/system/custom.service") -> ServiceUnit:
        """
        Ham bir systemd .service dosya metnini satır satır ayrıştırarak ServiceUnit nesnesi üretir.
        """
        # Başlangıç değerleriyle ServiceUnit nesnesi oluşturulur
        unit = ServiceUnit(name=service_name, path=file_path)

        # Mevcut aktif INI bölümünü takip etmek için değişken
        current_section = ""

        # Satırlar üzerinde gezinilir
        for line in content.splitlines():
            # Satırın başındaki ve sonundaki boşluklar temizlenir
            stripped = line.strip()
            # Yorum ve boş satırlar atlanır
            if not stripped or stripped.startswith(("#", ";")):
                continue

            # Bölüm başlığı kontrol edilir (Örn: [Service], [Unit], [Install])
            section_match = re.match(r"^\[([a-zA-Z0-9]+)\]$", stripped)
            if section_match:
                # Aktif bölüm güncellenir
                current_section = section_match.group(1)
                continue

            # Anahtar-değer çifti ayrıştırılır
            if "=" in stripped:
                key, val = stripped.split("=", 1)
                key = key.strip()
                val = val.strip()

                # [Unit] bölümü parametreleri
                if current_section == "Unit":
                    if key == "Description":
                        unit.description = val

                # [Service] bölümü güvenlik ve süreç parametreleri
                elif current_section == "Service":
                    if key == "User":
                        unit.user = val
                    elif key == "Group":
                        unit.group = val
                    elif key == "ExecStart":
                        unit.exec_start = val
                    elif key == "NoNewPrivileges":
                        unit.no_new_privileges = val.lower() in ["yes", "true", "1"]
                    elif key == "ProtectSystem":
                        unit.protect_system = val.lower()
                    elif key == "ProtectHome":
                        unit.protect_home = val.lower()
                    elif key == "PrivateTmp":
                        unit.private_tmp = val.lower() in ["yes", "true", "1"]
                    elif key == "PrivateDevices":
                        unit.private_devices = val.lower() in ["yes", "true", "1"]
                    elif key == "ProtectKernelTunables":
                        unit.protect_kernel_tunables = val.lower() in ["yes", "true", "1"]
                    elif key == "ProtectControlGroups":
                        unit.protect_control_groups = val.lower() in ["yes", "true", "1"]
                    elif key == "CapabilityBoundingSet":
                        unit.capability_bounding_set = [c.strip() for c in val.split() if c.strip()]
                    elif key == "RestrictAddressFamilies":
                        unit.restrict_address_families = [a.strip() for a in val.split() if a.strip()]

        # Elde edilen unit nesnesi döndürülür
        return unit

    def parse_inventory_json(self, json_data: Dict[str, Any]) -> List[ServiceUnit]:
        """
        JSON tabanlı envanter dosyasını okuyup ServiceUnit nesneleri listesine dönüştürür.
        """
        # Servisler listesi oluşturulur
        units: List[ServiceUnit] = []
        # JSON içerisindeki servisler dizisi alınır
        services_list = json_data.get("services", [])

        # Her servis kaydı gezilir
        for item in services_list:
            # ServiceUnit nesnesi oluşturulur ve doldurulur
            unit = ServiceUnit(
                name=item.get("name", "unknown.service"),
                path=item.get("path", "/etc/systemd/system/unknown.service"),
                file_owner=item.get("file_owner", "root"),
                file_group=item.get("file_group", "root"),
                file_mode=item.get("file_mode", "0644"),
                description=item.get("description", ""),
                user=item.get("user", ""),
                group=item.get("group", ""),
                exec_start=item.get("exec_start", ""),
                binary_owner=item.get("binary_owner", "root"),
                binary_mode=item.get("binary_mode", "0755"),
                binary_suid=item.get("binary_suid", False),
                no_new_privileges=item.get("no_new_privileges", False),
                protect_system=item.get("protect_system", ""),
                protect_home=item.get("protect_home", ""),
                private_tmp=item.get("private_tmp", False),
                private_devices=item.get("private_devices", False),
                protect_kernel_tunables=item.get("protect_kernel_tunables", False),
                protect_control_groups=item.get("protect_control_groups", False),
                capability_bounding_set=item.get("capability_bounding_set", []),
                restrict_address_families=item.get("restrict_address_families", []),
                enabled=item.get("enabled", True),
                active=item.get("active", True),
                masked=item.get("masked", False)
            )
            # Listeye eklenir
            units.append(unit)

        # Liste döndürülür
        return units

    def generate_remediation_script(self, services: List[ServiceUnit]) -> str:
        """
        Denetlenen servislerdeki tüm zafiyetleri gidermek üzere çalıştırılabilir
        kapsamlı bir Bash sertleştirme betiği üretir.
        """
        # Bash betiği satırları listesi
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Linux Systemd ve Servis Güvenliği Otomatik Sıkılaştırma Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "echo '[+] Systemd servis sertleştirme işlemi başlatılıyor...'",
            ""
        ]

        # 1. Adım: Güvensiz / Gereksiz Servisleri Kapatma ve Maskeleme
        lines.append("# --- 1. Adım: Güvensiz ve Gereksiz Servisleri Kapat / Maskele (CIS) ---")
        legacy_found = False
        for s in services:
            if s.name in self.LEGACY_INSECURE_SERVICES and not s.masked:
                lines.append(f"echo '[*] Kapatılıyor ve maskeleniyor: {s.name}'")
                lines.append(f"systemctl stop {s.name} 2>/dev/null || true")
                lines.append(f"systemctl disable {s.name} 2>/dev/null || true")
                lines.append(f"systemctl mask {s.name}")
                legacy_found = True
        if not legacy_found:
            lines.append("echo '[✓] Kapatılması gereken güvensiz servis bulunamadı.'")
        lines.append("")

        # 2. Adım: Dosya İzinlerini ve Sahipliklerini Düzeltme
        lines.append("# --- 2. Adım: Servis Unit ve İkili Dosya İzinlerini Düzelt ---")
        for s in services:
            # Unit dosyası izni gevşekse
            if self._is_mode_too_permissive(s.file_mode, threshold=0o644) or s.file_owner != "root":
                lines.append(f"echo '[*] Unit dosya izinleri düzeltiliyor: {s.path}'")
                lines.append(f"chown root:root {s.path}")
                lines.append(f"chmod 0644 {s.path}")

            # Binary izni gevşek veya SUID ise
            if self._is_mode_too_permissive(s.binary_mode, threshold=0o755) or s.binary_suid:
                # ExecStart içerisinden ana ikili dosya yolu ayıklanır
                bin_path = s.exec_start.split()[0] if s.exec_start else ""
                if bin_path and bin_path.startswith("/"):
                    lines.append(f"echo '[*] İkili dosya izinleri düzeltiliyor: {bin_path}'")
                    lines.append(f"chown root:root {bin_path}")
                    lines.append(f"chmod 0755 {bin_path}")
                    if s.binary_suid:
                        lines.append(f"chmod u-s {bin_path}")
        lines.append("")

        # 3. Adım: Systemd Drop-in Override ile Sandboxing Direktiflerini Enjekte Etme
        lines.append("# --- 3. Adım: Systemd Sandboxing Override Yapılandırmalarını Uygula ---")
        for s in services:
            # Legacy servisler veya kapalı servisler için override gerekmez
            if s.name in self.LEGACY_INSECURE_SERVICES or s.masked:
                continue

            override_dir = f"/etc/systemd/system/{s.name}.d"
            override_file = f"{override_dir}/99-security-hardening.conf"

            lines.append(f"echo '[*] Sandboxing uygulanıyor: {s.name}'")
            lines.append(f"mkdir -p {override_dir}")
            lines.append(f"cat << 'EOF' > {override_file}")
            lines.append("[Service]")
            # NoNewPrivileges eklenir
            lines.append("NoNewPrivileges=yes")
            # ProtectSystem strict eklenir
            lines.append("ProtectSystem=strict")
            # ProtectHome yes eklenir
            lines.append("ProtectHome=yes")
            # PrivateTmp yes eklenir
            lines.append("PrivateTmp=yes")
            # PrivateDevices yes eklenir
            lines.append("PrivateDevices=yes")
            # ProtectKernelTunables yes eklenir
            lines.append("ProtectKernelTunables=yes")
            # ProtectControlGroups yes eklenir
            lines.append("ProtectControlGroups=yes")
            # RestrictRealtime yes eklenir
            lines.append("RestrictRealtime=yes")
            # Kullanıcı root ise uyarı ve alternatif kullanıcı önerisi yorumu
            if not s.user or s.user == "root":
                lines.append("# UYARI: Servis root olarak çalıştırılmaktadır. Ayrılmış bir servis kullanıcısı atayınız:")
                lines.append(f"# User={s.name.split('.')[0]}_svc")
                lines.append(f"# Group={s.name.split('.')[0]}_svc")
            lines.append("EOF")
            lines.append(f"chmod 0644 {override_file}")
            lines.append(f"chown root:root {override_file}")
            lines.append("")

        # 4. Adım: Systemd Daemon Yeniden Yükleme
        lines.append("# --- 4. Adım: Yapılandırmayı Yeniden Yükle ---")
        lines.append("echo '[*] Systemd yapılandırmaları yeniden yükleniyor...'")
        lines.append("systemctl daemon-reload")
        lines.append("echo '[✓] Systemd servis sertleştirme işlemi başarıyla tamamlandı.'")

        # Metin birleştirilerek döndürülür
        return "\n".join(lines)

    def generate_secure_unit_template(self, service_name: str, exec_path: str, user: str = "appuser") -> str:
        """
        CIS ve systemd sandboxing standartlarına tam uyumlu, örnek güvenli bir .service şablonu üretir.
        """
        # Şablon satırları oluşturulur
        template_lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            f"# CIS Uyumlu Güvenli Systemd Servis Şablonu: {service_name}",
            "# ==============================================================================",
            "[Unit]",
            f"Description={service_name} Sıkılaştırılmış ve Yalıtılmış Servis Birimi",
            "After=network.target",
            "Documentation=man:systemd.exec(5)",
            "",
            "[Service]",
            "Type=simple",
            f"User={user}",
            f"Group={user}",
            f"ExecStart={exec_path}",
            "Restart=on-failure",
            "RestartSec=5s",
            "",
            "# --- Sandboxing ve Güvenlik Direktifleri (CIS & NIST SP 800-123) ---",
            "# SUID/SGID ile yeni yetki kazanımını engeller (prctl PR_SET_NO_NEW_PRIVS)",
            "NoNewPrivileges=yes",
            "",
            "# Dosya sistemini (/usr, /boot, /etc) salt-okunur bağlar",
            "ProtectSystem=strict",
            "",
            "# Kullanıcıların /home ve /root dizinlerine erişimi tamamen gizler",
            "ProtectHome=yes",
            "",
            "# Sürece özel yalıtılmış /tmp ve /var/tmp namespace'i tahsis eder",
            "PrivateTmp=yes",
            "",
            "# Fiziksel donanım aygıtlarına (/dev) doğrudan erişimi engeller",
            "PrivateDevices=yes",
            "",
            "# Çekirdek parametrelerinin (/proc/sys, /sys) değiştirilmesini kilitler",
            "ProtectKernelTunables=yes",
            "",
            "# Çekirdek kontrol gruplarını (/sys/fs/cgroup) salt-okunur yapar",
            "ProtectControlGroups=yes",
            "",
            "# Gerçek zamanlı işlem önceliği (realtime scheduling) almasını engeller",
            "RestrictRealtime=yes",
            "",
            "# Yalnızca standart IPv4/IPv6 ve UNIX soketlerine izin verir",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "",
            "# Çekirdek yeteneklerini (capabilities) minimum seviyeye indirir",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "",
            "[Install]",
            "WantedBy=multi-user.target"
        ]

        # Şablon döndürülür
        return "\n".join(template_lines)
