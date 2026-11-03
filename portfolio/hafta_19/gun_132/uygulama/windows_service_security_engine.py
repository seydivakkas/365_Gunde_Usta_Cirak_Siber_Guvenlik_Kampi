# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Windows Hizmet Güvenliği Denetim ve Sıkılaştırma Motoru.

Bu modül, Windows Service Control Manager (SCM - services.exe) mimarisini,
servis güvenlik tanımlayıcılarını (Service DACL / SDDL), tırnaksız servis yolu
(Unquoted Service Path - CWE-428 / MITRE ATT&CK T1574.009), zayıf binary izinlerini
(CWE-732 / MITRE ATT&CK T1574.010), en az ayrıcalık ihlallerini (CWE-250) ve
gereksiz çalışan riskli servisleri (CIS Windows Benchmark) denetler.
"""

# Güvenli tip doğrulama ve veri yapıları için gerekli standart kütüphaneler içe aktarılıyor
from dataclasses import dataclass, field
# Sözlük ve liste tip ipuçları için Typing modülü içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any
# Metin deseni ve yol ayrıştırma işlemleri için regular expressions modülü içe aktarılıyor
import re
# Dosya ve dizin yolu manipülasyonları için standart os modülü içe aktarılıyor
import os
# JSON formatlama ve ayrıştırma işlemleri için json modülü içe aktarılıyor
import json


# Windows Hizmet Erişim Hakları Sabitleri (Service Access Rights)
# Hizmet üzerinde yapılandırma değiştirme hakkı (En kritik zafiyet noktası)
SERVICE_CHANGE_CONFIG = 0x0002
# Hizmet yapılandırmasını sorgulama hakkı
SERVICE_QUERY_CONFIG = 0x0001
# Hizmet durumunu sorgulama hakkı
SERVICE_QUERY_STATUS = 0x0004
# Hizmeti başlatma hakkı
SERVICE_START = 0x0010
# Hizmeti durdurma hakkı
SERVICE_STOP = 0x0020
# Hizmeti duraklatma ve devam ettirme hakkı
SERVICE_PAUSE_CONTINUE = 0x0040
# Hizmet güvenlik tanımlayıcısını (DACL) değiştirme hakkı (Tam ele geçirme)
WRITE_DAC = 0x00040000
# Hizmet sahipliğini ele geçirme hakkı
WRITE_OWNER = 0x00080000
# Hizmet üzerinde tam denetim hakkı (Full Control)
SERVICE_ALL_ACCESS = 0x000F01FF


# Standart SDDL Hizmet İzin Kısaltmaları Eşlemesi (SCM SDDL Reference)
# SDDL dizgelerindeki harf kodlarını insan tarafından okunabilir haklara dönüştürür
SDDL_SERVICE_RIGHTS_MAP = {
    "CC": "SERVICE_QUERY_CONFIG",
    "DC": "SERVICE_CHANGE_CONFIG",
    "LC": "SERVICE_QUERY_STATUS",
    "SW": "SERVICE_ENUMERATE_DEPENDENTS",
    "RP": "SERVICE_START",
    "WP": "SERVICE_STOP",
    "DT": "SERVICE_PAUSE_CONTINUE",
    "LO": "SERVICE_INTERROGATE",
    "CR": "SERVICE_USER_DEFINED_CONTROL",
    "SD": "DELETE",
    "RC": "READ_CONTROL",
    "WD": "WRITE_DAC",
    "WO": "WRITE_OWNER",
    "GA": "GENERIC_ALL",
    "GX": "GENERIC_EXECUTE",
    "GW": "GENERIC_WRITE",
    "GR": "GENERIC_READ",
}

# Tehlikeli ve düşük yetkili kabul edilen yerel/etki alanı kimlikleri (Well-known SIDs / Groups)
UNPRIVILEGED_PRINCIPALS = {
    "BUILTIN\\Users",
    "BUILTIN\\Remote Desktop Users",
    "Everyone",
    "Authenticated Users",
    "NT AUTHORITY\\Authenticated Users",
    "NT AUTHORITY\\INTERACTIVE",
    "Users",
    "AU",  # SDDL: Authenticated Users
    "IU",  # SDDL: Interactively Logged-on Users
    "WD",  # SDDL: Everyone (World)
    "BU",  # SDDL: Built-in Users
}

# CIS Windows Benchmark uyarınca kurumsal sunucu ve iş istasyonlarında devre dışı bırakılması önerilen servisler
UNNECESSARY_RISKY_SERVICES = {
    "RemoteRegistry": "Uzaktan Kayıt Defteri Erişim Servisi (Yetkisiz reg manipülasyonu riski)",
    "RemoteAccess": "Yönlendirme ve Uzaktan Erişim Servisi (Gereksiz saldırı yüzeyi)",
    "XblAuthManager": "Xbox Live Kimlik Doğrulama Yöneticisi (Kurumsal sistemlerde gereksiz)",
    "XboxGipSvc": "Xbox Aksesuar Yönetim Servisi (Kurumsal sistemlerde gereksiz)",
    "TapiSrv": "Telefoni Servisi (Eski ve zafiyetli protokol desteği)",
    "PNRPsvc": "Eşler Arası İsim Çözümleme Protokolü (Zehirlenme riski taşır)",
    "lltdsvc": "Bağlantı Katmanı Topoloji Haritalayıcı (Ağ keşif zafiyetleri)",
    "dmwappushservice": "WAP Push Yönlendirme Servisi (Telemetri ve gereksiz veri akışı)",
}


@dataclass
class ServiceDaclEntry:
    """Tekil bir Hizmet Erişim Denetim Girişini (Service ACE) temsil eden veri sınıfı."""
    # ACE türü: 'A' (Allow - İzin Ver) veya 'D' (Deny - Engelle)
    ace_type: str
    # İzin verilen veya engellenen kullanıcı/grup kimliği (SID veya isim)
    principal: str
    # Sahip olunan ham erişim hakları (SDDL harf kodları veya izin listesi)
    rights: List[str]
    # İznin tehlikeli olup olmadığını gösteren bayrak
    is_dangerous: bool = False
    # İhlal edilen güvenlik politikasının gerekçesi
    danger_reason: str = ""


@dataclass
class ServiceVulnerability:
    """Tespit edilen tekil bir servis güvenlik zafiyetini modelleyen sınıf."""
    # Zafiyetin ait olduğu servis adı
    service_name: str
    # İlgili CWE (Common Weakness Enumeration) numarası
    cwe_id: str
    # İlgili MITRE ATT&CK taktik ve teknik kimliği
    mitre_id: str
    # Zafiyetin önem derecesi: CRITICAL, HIGH, MEDIUM, LOW
    severity: str
    # Zafiyetin kısa teknik başlığı
    title: str
    # Zafiyetin derinlemesine teknik açıklaması
    description: str
    # Düzeltilmesi için uygulanması gereken net aksiyon
    remediation: str
    # Puan kırma miktarı (skor düşümü)
    penalty_score: float


@dataclass
class WindowsServiceSpec:
    """Denetlenecek bir Windows hizmetinin teknik spesifikasyonunu tutan model."""
    # Servisin sistemdeki kayıtlı teknik adı (Örn: Spooler, W32Time)
    service_name: str
    # Kullanıcı arayüzünde görünen adı (Display Name)
    display_name: str
    # Servisin çalıştırdığı yürütülebilir dosya yolu ve argümanları (ImagePath / binPath)
    image_path: str
    # Servisin başlangıç türü (Boot, System, Automatic, Manual, Disabled)
    start_type: str
    # Servisin hangi kullanıcı/sistem kimliği ile çalıştığı (RunAs Account)
    run_as_account: str
    # Servisin Güvenlik Tanımlayıcısı (SDDL dizgesi)
    sddl: str = ""
    # Servis binary dosyasının dosya sistemi üzerindeki izinleri (Principal -> Rights listesi)
    binary_permissions: Dict[str, List[str]] = field(default_factory=dict)
    # Servisin talep ettiği özel Windows ayrıcalıkları listesi (RequiredPrivileges)
    required_privileges: List[str] = field(default_factory=list)
    # Üçüncü parti yazılıma mı yoksa Windows dahili çekirdeğine mi ait olduğu
    is_third_party: bool = False
    # Servis hakkında açıklama notu
    description: str = ""


class WindowsServiceSecurityEngine:
    """
    Windows Hizmet Güvenliği Denetim, Puanlama ve Sıkılaştırma Motoru.
    
    Tırnaksız servis yolları, zayıf servis DACL izinleri, zayıf dosya izinleri,
    ayrıcalıklı hesap suiistimalleri ve CIS sıkılaştırma kurallarını denetler.
    """

    def __init__(self) -> None:
        """Denetim motorunu başlatır ve kural tablolarını hafızaya yükler."""
        # Toplam başlangıç puanı (100 üzerinden düşüm mantığı uygulanır)
        self.base_score: float = 100.0
        # Tespit edilen tüm zafiyetleri saklayan liste
        self.findings: List[ServiceVulnerability] = []
        # Denetlenen servislerin detaylı analiz sonuçlarını tutan sözlük
        self.audit_results: Dict[str, Any] = {}

    def parse_sddl_dacl(self, sddl: str) -> List[ServiceDaclEntry]:
        """
        Windows SDDL dizgesini ayrıştırarak servis erişim izinlerini (ACE) listeler.
        
        Örnek SDDL formatı: D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
        """
        # Sonuç ACE nesnelerini tutacak liste
        entries: List[ServiceDaclEntry] = []
        # Boş veya geçersiz SDDL kontrolü yapılır
        if not sddl or "D:" not in sddl:
            # Boş SDDL döndürülür
            return entries

        # Sadece DACL bölümünü (D: ile başlayan ve varsa S: öncesine kadar olan kısmı) alırız
        dacl_part = sddl.split("D:")[1].split("S:")[0]
        # Parantez içerisindeki ACE bloklarını düzenli ifade ile yakalarız
        ace_blocks = re.findall(r"\(([^)]+)\)", dacl_part)

        # Her bir ACE bloğu ayrıştırılır
        for block in ace_blocks:
            # ACE bileşenleri noktalı virgül ile 6 parçaya ayrılır
            parts = block.split(";")
            # En az 6 parça olması gerekmektedir (Type;Flags;Rights;ObjectGUID;InheritGUID;SID)
            if len(parts) >= 6:
                # 0. indis: ACE türü (A=Allow, D=Deny)
                ace_type = parts[0]
                # 2. indis: Haklar (Harf kodları: Örn: CCLCSWRPWPDTLOCRRC)
                raw_rights = parts[2]
                # 5. indis: Hedef kullanıcı / grup kimliği (SID veya SID kısaltması: Örn: SY, BA, BU)
                principal = parts[5]

                # Harf kodları ikişerli karakterler halinde listeye dönüştürülür
                parsed_rights: List[str] = []
                # Dizge uzunluğu boyunca ikişer adım atarak kodları çözeriz
                for i in range(0, len(raw_rights), 2):
                    # İki karakterlik hak kodu alınır
                    token = raw_rights[i : i + 2]
                    # Harita tablosunda varsa adını, yoksa ham token değerini ekleriz
                    parsed_rights.append(SDDL_SERVICE_RIGHTS_MAP.get(token, token))

                # Tehlike denetimi yapılır: Düşük yetkili grup tehlikeli haklara sahip mi?
                is_dangerous = False
                danger_reason = ""

                # Eğer hak sahibi düşük yetkili bir grup ise
                if principal in UNPRIVILEGED_PRINCIPALS or any(p in principal for p in ["Users", "Everyone"]):
                    # SERVICE_CHANGE_CONFIG (DC) kontrolü (En tehlikeli hak)
                    if any(r in parsed_rights for r in ["SERVICE_CHANGE_CONFIG", "DC", "GENERIC_ALL", "GA", "GENERIC_WRITE", "GW"]):
                        # Tehlikeli olarak işaretlenir
                        is_dangerous = True
                        danger_reason = f"Düşük yetkili {principal} kullanıcısına SERVICE_CHANGE_CONFIG (DC) yetkisi verilmiş!"
                    # WRITE_DAC veya WRITE_OWNER kontrolü
                    elif any(r in parsed_rights for r in ["WRITE_DAC", "WD", "WRITE_OWNER", "WO"]):
                        # İzin veya sahiplik manipülasyonu riski
                        is_dangerous = True
                        danger_reason = f"Düşük yetkili {principal} kullanıcısına WRITE_DAC / WRITE_OWNER yetkisi verilmiş!"

                # Veri nesnesi oluşturularak listeye eklenir
                entries.append(
                    ServiceDaclEntry(
                        ace_type=ace_type,
                        principal=principal,
                        rights=parsed_rights,
                        is_dangerous=is_dangerous,
                        danger_reason=danger_reason,
                    )
                )

        # Ayrıştırılmış ACE girişleri döndürülür
        return entries

    def detect_unquoted_service_path(self, image_path: str) -> Tuple[bool, List[str]]:
        """
        Tırnaksız servis yolu (Unquoted Service Path - CWE-428) zafiyetini tespit eder.
        
        Boşluk içeren ve çift tırnak içine alınmamış yollar, aradaki dizinlerde
        sahte ikili dosyaların (.exe) çalıştırılmasına (Binary Planting) yol açar.
        """
        # Yol başındaki ve sonundaki boşluklar temizlenir
        path = image_path.strip()
        # Yol zaten çift tırnak ile başlıyorsa zafiyetli değildir
        if path.startswith('"') and '"' in path[1:]:
            # Güvenli: Tırnak içerisine alınmış
            return False, []

        # Yolda boşluk karakteri bulunmuyorsa zafiyet oluşmaz
        if " " not in path:
            # Boşluk yok, doğrudan çalışır
            return False, []

        # Komut satırı argümanları ile asıl çalıştırılabilir dosya yolunu ayırırız
        # İlk .exe uzantısına kadar olan bölümü analiz ederiz
        exe_match = re.search(r"^(.*?\.exe)", path, re.IGNORECASE)
        # Eğer .exe bulunduysa hedef yol olarak o bölümü alırız
        target_path = exe_match.group(1) if exe_match else path

        # Eğer tırnak yoksa ve yol içerisinde boşluk varsa potansiyel tuzak yolları üretiriz
        hijack_candidates: List[str] = []
        # Yol parçalarını boşluğa göre böleriz
        parts = target_path.split(" ")
        # Eğer birden fazla parça varsa, her boşluk ayrımında Windows'un arayacağı dosya adını simüle ederiz
        for i in range(1, len(parts)):
            # Örn: 'C:\Program Files\App Dir\svc.exe' -> 'C:\Program.exe', 'C:\Program Files\App.exe'
            candidate = " ".join(parts[:i]) + ".exe"
            # Listeye ekleriz
            hijack_candidates.append(candidate)

        # Zafiyetli olduğu ve bulunan tuzak yollar döndürülür
        return True, hijack_candidates

    def check_weak_binary_permissions(self, binary_perms: Dict[str, List[str]]) -> Tuple[bool, str]:
        """
        Servis ikili dosyasının (Binary) dosya sistemi izinlerini (CWE-732) denetler.
        
        Düşük yetkili kullanıcıların (Users, Everyone) dosyayı yazma veya değiştirme hakkı varsa
        saldırgan servisi durdurup binary dosyasını kendi zararlısıyla değiştirebilir.
        """
        # Tehlikeli yazma ve değiştirme hakları
        dangerous_rights = {"Write", "Modify", "FullControl", "GENERIC_WRITE", "GENERIC_ALL", "FILE_WRITE_DATA", "FILE_APPEND_DATA"}

        # Belirtilen her bir kullanıcı ve grup izni taranır
        for principal, rights in binary_perms.items():
            # Kullanıcı düşük yetkili bir grup mu kontrol edilir
            is_unprivileged = principal in UNPRIVILEGED_PRINCIPALS or any(p in principal for p in ["Users", "Everyone", "Authenticated Users"])
            # Eğer düşük yetkili grupta tehlikeli yazma hakkı varsa
            if is_unprivileged and any(r in dangerous_rights for r in rights):
                # Zafiyet tespit edildi bildirimi yapılır
                return True, f"{principal} grubuna servis ikili dosyası üzerinde yazma/değiştirme yetkisi ({', '.join(rights)}) verilmiş!"

        # Dosya izinleri güvenli
        return False, ""

    def evaluate_service(self, service: WindowsServiceSpec) -> List[ServiceVulnerability]:
        """
        Tek bir Windows hizmetini tüm güvenlik kontrollerinden geçirir ve zafiyet listesi üretir.
        """
        # Bu servis için tespit edilen zafiyetler
        service_vulns: List[ServiceVulnerability] = []

        # Kontrol 1: Tırnaksız Servis Yolu (Unquoted Service Path - CWE-428 / T1574.009)
        is_unquoted, hijack_paths = self.detect_unquoted_service_path(service.image_path)
        # Eğer tırnaksız yol bulunduysa
        if is_unquoted:
            # Tuzak yolların listesi metne dökülür
            candidates_str = ", ".join(hijack_paths[:3])
            # Zafiyet nesnesi oluşturulur
            vuln = ServiceVulnerability(
                service_name=service.service_name,
                cwe_id="CWE-428",
                mitre_id="T1574.009",
                severity="HIGH",
                title="Tırnaksız Servis Yolu (Unquoted Service Path)",
                description=(
                    f"'{service.service_name}' hizmetinin ImagePath değeri ({service.image_path}) "
                    f"boşluk içermesine rağmen tırnak içine alınmamış. Saldırgan aradaki yollara "
                    f"({candidates_str}) yetkisiz dosya bırakarak SYSTEM haklarına yükselebilir."
                ),
                remediation=(
                    f'sc.exe config "{service.service_name}" binPath= "\\"{service.image_path}\\""'
                ),
                penalty_score=25.0,
            )
            # Listeye eklenir
            service_vulns.append(vuln)

        # Kontrol 2: Zayıf Servis DACL İzinleri (Weak Service Permissions - CWE-732 / T1543.003)
        if service.sddl:
            # SDDL ayrıştırılır
            dacl_entries = self.parse_sddl_dacl(service.sddl)
            # Her bir ACE taranır
            for entry in dacl_entries:
                # Tehlikeli ACE var mı kontrol edilir
                if entry.is_dangerous:
                    # Kritik zafiyet nesnesi oluşturulur
                    vuln = ServiceVulnerability(
                        service_name=service.service_name,
                        cwe_id="CWE-732",
                        mitre_id="T1543.003",
                        severity="CRITICAL",
                        title="Zayıf Servis DACL İzni (Hizmet Yapılandırma Yetkisi)",
                        description=(
                            f"'{service.service_name}' hizmetinin DACL tablosunda "
                            f"{entry.danger_reason}. Standart bir kullanıcı servis komut satırını değiştirip SYSTEM olabilir."
                        ),
                        remediation=(
                            f'sc.exe sdset "{service.service_name}" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"'
                        ),
                        penalty_score=30.0,
                    )
                    # Listeye eklenir
                    service_vulns.append(vuln)

        # Kontrol 3: Zayıf Dosya Sistemi İzinleri (Weak Binary Permissions - CWE-732 / T1574.010)
        has_weak_binary, binary_reason = self.check_weak_binary_permissions(service.binary_permissions)
        # Zayıf dosya izni varsa
        if has_weak_binary:
            # Dosya yolundaki gereksiz tırnaklar ve boşluklar temizlenir
            clean_path = service.image_path.strip().strip('"')
            # Zafiyet nesnesi oluşturulur
            vuln = ServiceVulnerability(
                service_name=service.service_name,
                cwe_id="CWE-732",
                mitre_id="T1574.010",
                severity="CRITICAL",
                title="Zayıf Servis İkili Dosya İzni (Binary Hijacking)",
                description=(
                    f"'{service.service_name}' hizmetinin çalıştırdığı ikili dosyada: {binary_reason} "
                    f"Saldırgan ikili dosyayı kendi zararlı yazılımı ile ezebilir."
                ),
                remediation=(
                    f'icacls "{clean_path}" /inheritance:r /grant:r "SYSTEM:(F)" /grant:r "Administrators:(F)" /grant:r "Users:(RX)"'
                ),
                penalty_score=30.0,
            )
            # Listeye eklenir
            service_vulns.append(vuln)

        # Kontrol 4: En Az Ayrıcalık İhlali / Aşırı Yetkili Hesap (CWE-250)
        # Üçüncü parti servislerin gereksiz yere LocalSystem veya SYSTEM ile çalıştırılması denetimi
        if service.is_third_party and service.run_as_account in ["LocalSystem", "SYSTEM", "NT AUTHORITY\\SYSTEM"]:
            # Orta derece zafiyet
            vuln = ServiceVulnerability(
                service_name=service.service_name,
                cwe_id="CWE-250",
                mitre_id="T1078.003",
                severity="MEDIUM",
                title="Aşırı Yetkili Servis Hesabı (En Az Ayrıcalık Prensibi İhlali)",
                description=(
                    f"Üçüncü parti '{service.service_name}' hizmeti tam yetkili '{service.run_as_account}' "
                    f"hesabıyla çalışmaktadır. Uygulamadaki olası bir zafiyet tüm işletim sisteminin tam ele geçirilmesine yol açar."
                ),
                remediation=(
                    f"Servisi 'NT AUTHORITY\\LocalService', 'NT AUTHORITY\\NetworkService' veya bir gMSA hesabı ile çalışacak şekilde yapılandırın."
                ),
                penalty_score=10.0,
            )
            # Listeye eklenir
            service_vulns.append(vuln)

        # Kontrol 5: Gereksiz / Riskli Servis Durumu (CIS Benchmark)
        if service.service_name in UNNECESSARY_RISKY_SERVICES and service.start_type != "Disabled":
            # Risk açıklaması alınır
            risk_desc = UNNECESSARY_RISKY_SERVICES[service.service_name]
            # Zafiyet nesnesi oluşturulur
            vuln = ServiceVulnerability(
                service_name=service.service_name,
                cwe_id="CWE-16",
                mitre_id="T1003.002",
                severity="HIGH" if service.service_name == "RemoteRegistry" else "MEDIUM",
                title=f"Gereksiz ve Riskli Servis Aktif ({service.service_name})",
                description=(
                    f"CIS Windows Benchmark standartlarına göre '{service.service_name}' servisi ({risk_desc}) "
                    f"kurumsal sistemlerde devre dışı bırakılmalıdır. Mevcut başlangıç türü: {service.start_type}."
                ),
                remediation=(
                    f'Set-Service -Name "{service.service_name}" -StartupType Disabled; Stop-Service -Name "{service.service_name}" -Force'
                ),
                penalty_score=15.0 if service.service_name == "RemoteRegistry" else 10.0,
            )
            # Listeye eklenir
            service_vulns.append(vuln)

        # Kontrol 6: Tehlikeli ve Gereksiz Özel Hak Talepleri (Excessive Privileges - CWE-250)
        dangerous_privs = {"SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege"}
        # Servisin talep ettiği ayrıcalıklar kesiştirilir
        claimed_dangerous_privs = set(service.required_privileges).intersection(dangerous_privs)
        # Eğer üçüncü parti bir servis tehlikeli haklar istiyorsa
        if service.is_third_party and claimed_dangerous_privs:
            # Zafiyet nesnesi oluşturulur
            vuln = ServiceVulnerability(
                service_name=service.service_name,
                cwe_id="CWE-250",
                mitre_id="T1134",
                severity="HIGH",
                title="Servis Tarafından Tehlikeli Ayrıcalık Talebi",
                description=(
                    f"'{service.service_name}' servisi şu tehlikeli Windows haklarını talep ediyor: {', '.join(claimed_dangerous_privs)}. "
                    f"Bu ayrıcalıklar token hırsızlığı ve bellek manipülasyonuna olanak tanır."
                ),
                remediation=(
                    f"Servisin RequiredPrivileges kayıt defteri girdisinden gereksiz ayrıcalıkları çıkarın (Service Hardening)."
                ),
                penalty_score=10.0,
            )
            # Listeye eklenir
            service_vulns.append(vuln)

        # Tüm tespit edilen zafiyetler döndürülür
        return service_vulns

    def audit_service_inventory(self, services: List[WindowsServiceSpec]) -> Dict[str, Any]:
        """
        Tüm servis envanterini denetler, güvenlik skorunu hesaplar ve rapor üretir.
        """
        # Bulgular listesi sıfırlanır
        self.findings.clear()
        # Denetlenen servis sayısı
        total_services = len(services)
        # Servis başına tespit listesi
        per_service_findings: Dict[str, List[Dict[str, Any]]] = {}

        # Toplam ceza puanı sayacı
        total_penalties = 0.0

        # Her servis tek tek incelenir
        for svc in services:
            # Servisi değerlendir
            vulns = self.evaluate_service(svc)
            # Servis bulgularını kaydet
            per_service_findings[svc.service_name] = [
                {
                    "cwe_id": v.cwe_id,
                    "mitre_id": v.mitre_id,
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description,
                    "remediation": v.remediation,
                    "penalty": v.penalty_score,
                }
                for v in vulns
            ]
            # Genel bulgular listesine ekle
            self.findings.extend(vulns)
            # Ceza puanını topla
            for v in vulns:
                total_penalties += v.penalty_score

        # Nihai güvenlik puanı hesaplanır (100 - toplam ceza, minimum 0.0)
        final_score = max(0.0, round(self.base_score - total_penalties, 2))

        # Sistem güvenlik durumu belirlenir
        if final_score >= 85.0:
            status = "SECURE"
        elif final_score >= 60.0:
            status = "WARNING"
        else:
            status = "CRITICAL"

        # Zafiyetlerin önem derecelerine göre dağılımı
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        # Her bir bulgu için sayaç artırılır
        for f in self.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1

        # Rapor sözlüğü oluşturulur
        self.audit_results = {
            "total_services_audited": total_services,
            "security_score": final_score,
            "system_status": status,
            "total_vulnerabilities": len(self.findings),
            "severity_breakdown": severity_counts,
            "per_service_findings": per_service_findings,
            "findings_detail": [
                {
                    "service_name": f.service_name,
                    "cwe_id": f.cwe_id,
                    "mitre_id": f.mitre_id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
        }

        # Sonuç raporu döndürülür
        return self.audit_results

    def generate_powershell_remediation_script(self) -> str:
        """
        Tespit edilen tüm servis zafiyetleri için otomatik PowerShell sıkılaştırma betiği üretir.
        """
        # Betik satırlarını biriktirecek liste
        script_lines: List[str] = [
            "# ===========================================================================",
            "# Windows Hizmet Güvenliği Otomatik Sıkılaştırma ve İyileştirme Betiği",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz - Tüm Hakları Saklıdır",
            "# ===========================================================================",
            "# Bu betik Yönetici (Run as Administrator) olarak çalıştırılmalıdır.",
            "$ErrorActionPreference = 'Continue'",
            "Write-Host '[*] Windows Servis Güvenlik Sıkılaştırma Başlatılıyor...' -ForegroundColor Cyan",
            "",
        ]

        # Eğer hiç zafiyet yoksa
        if not self.findings:
            script_lines.append("Write-Host '[+] Tüm servisler güvenlik standartlarına uygun. Müdahaleye gerek yok.' -ForegroundColor Green")
            return "\n".join(script_lines)

        # Zafiyetlere göre iyileştirme komutları eklenir
        for idx, finding in enumerate(self.findings, 1):
            script_lines.append(f"# Adım {idx}: {finding.service_name} - {finding.title} ({finding.cwe_id})")
            script_lines.append(f"Write-Host '[>] Sıkılaştırılıyor: {finding.service_name} ({finding.title})...' -ForegroundColor Yellow")
            script_lines.append(f"{finding.remediation}")
            script_lines.append("")

        script_lines.append("Write-Host '[+] Servis sıkılaştırma işlemleri tamamlandı!' -ForegroundColor Green")
        # Betik metni birleştirilerek döndürülür
        return "\n".join(script_lines)
