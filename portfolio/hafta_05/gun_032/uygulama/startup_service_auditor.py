# ============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
#
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
#
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
#
# YASAKLAR:
#   1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
#   2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
#   3. Alt lisanslanamaz, satılamaz veya devredilemez.
#   4. Tersine mühendislik yapılamaz.
#
# İZİN VERİLEN KULLANIM:
#   - GitHub üzerinde görüntüleme ve okuma.
#   - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).
#
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ============================================================================
"""
Gün 32: Başlangıç Uygulamaları ve Hizmet Yönetimi Güvenlik Denetleyicisi
Bu modül; sistem başlangıç anahtarlarını (Run/RunOnce), Windows servislerini,
Linux daemon/systemd/cron yapılarını ve zamanlanmış görevleri analiz ederek
yetki yükseltme (Privilege Escalation), savunmayı zayıflatma (Impair Defenses)
ve kalıcılık (Persistence) tehditlerini tespit eder.
"""

# Dosya ve işletim sistemi yol operasyonları için standart kütüphaneyi içe aktarıyoruz
import os
# Komut satırı argümanlarını ve sistem yapılandırmalarını yönetmek için sys kütüphanesi
import sys
# JSON tabanlı envanter dosyalarını okumak ve yapılandırılmış çıktı üretmek için json kütüphanesi
import json
# Regex kalıp eşleştirme ve metin analizi için re kütüphanesi
import re
# Tip ipuçları ve statik analiz desteği için typing modülü
from typing import List, Dict, Any, Tuple, Optional
# Veri sınıfları oluşturmak için dataclass yapısı
from dataclasses import dataclass, field, asdict


@dataclass
class StartupItem:
    """Sistem başlangıç noktasını veya işletim sistemi servisini temsil eden veri modeli."""
    # Envanter kaydına atanmış tekil tanımlayıcı (Örn: SVC-001, RUN-002)
    id: str
    # Servisin veya başlangıç girdisinin kısa sistem adı
    name: str
    # Kullanıcı arayüzünde veya yönetim konsolunda görünen açıklayıcı ad
    display_name: str
    # Başlangıç mekanizmasının türü (service, registry_run, scheduled_task, cron_job)
    entry_type: str
    # Başlatılma mekanizması (Automatic, Manual, Disabled, Boot, System)
    start_mode: str
    # Çalışma anındaki mevcut durum (Running, Stopped, Paused, Unknown)
    status: str
    # Çalıştırılan ikili dosya yolu ve varsa komut satırı parametreleri
    binary_path: str
    # Servisin çalıştığı kullanıcı veya güvenlik bağlamı (NT AUTHORITY\\SYSTEM, LocalService vb.)
    account: str
    # Sınıflandırma kategorisi (security_core, system_core, third_party, automation)
    category: str = "unclassified"
    # İkili dosyanın geçerli bir dijital imza taşıyıp taşımadığı bilgisi
    signed: bool = False
    # Kaydın sistemdeki konumu (Kayıt defteri yolu, dosya yolu veya görev yolu)
    location: str = "N/A"
    # Servis veya uygulamanın sistemdeki işlev açıklaması
    description: str = ""


@dataclass
class StartupSecurityFinding:
    """Tespit edilen güvenlik anomalisini veya zafiyetini modelleyen sınıf."""
    # İlgili başlangıç kaydının kimliği
    item_id: str
    # İlgili servisin veya uygulamanın adı
    item_name: str
    # Zafiyet veya risk düzeyi (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    risk_level: str
    # Zafiyet sınıfı (UNQUOTED_SERVICE_PATH, SUSPICIOUS_PATH, MASQUERADING, SERVICE_TAMPERING, MALICIOUS_SCRIPT)
    vulnerability_type: str
    # Zafiyetin teknik açıklaması ve mekanizması
    description: str
    # MITRE ATT&CK teknik eşleşmesi (Örn: T1574.009, T1547.001)
    mitre_technique: str
    # Güvenlik açığını kapatmak için önerilen adımlar
    remediation: str


class StartupServiceAuditor:
    """
    Başlangıç uygulamalarını ve sistem servislerini güvenlik standartlarına
    göre denetleyen, yetki yükseltme ve kalıcılık vektörlerini çıkaran analizci.
    """

    # Desteklenen geçerli başlangıç mekanizması türleri kümesi
    VALID_ENTRY_TYPES = {"service", "registry_run", "scheduled_task", "cron_job", "startup_folder"}

    # Geçerli başlangıç modları kümesi
    VALID_START_MODES = {"Automatic", "Manual", "Disabled", "Boot", "System", "Unknown"}

    # Kritik işletim sistemi güvenlik servislerinin adları ve beklenen durumları
    CRITICAL_SECURITY_SERVICES = {
        "WinDefend": {"expected_mode": "Automatic", "min_status": "Running", "desc": "Microsoft Defender Antivirus"},
        "EventLog": {"expected_mode": "Automatic", "min_status": "Running", "desc": "Windows Olay Günlüğü"},
        "MpsSvc": {"expected_mode": "Automatic", "min_status": "Running", "desc": "Windows Güvenlik Duvarı"}
    }

    # Saldırganlar tarafından sıkça taklit edilen meşru sistem süreç isimleri
    LEGITIMATE_SYSTEM_NAMES = {
        "svchost.exe": "Hizmet Ana Süreci",
        "lsass.exe": "Yerel Güvenlik Yetki Alt Sistemi",
        "csrss.exe": "İstemci/Sunucu Çalışma Zamanı Alt Sistemi",
        "services.exe": "Hizmet Denetim Yöneticisi",
        "explorer.exe": "Windows Gezgini Kabuğu"
    }

    # Geçici ve standart dışı yazılabilir dizin kalıpları
    SUSPICIOUS_PATH_PATTERNS = [
        r"[\\/]temp[\\/]",
        r"[\\/]tmp[\\/]",
        r"[\\/]appdata[\\/]local[\\/]temp",
        r"[\\/]users[\\/]public[\\/]",
        r"[\\/]programdata[\\/][^\\/]+$"
    ]

    def __init__(self) -> None:
        """Denetleyici nesnesini sıfırdan ve bağımsız envanterle başlatır."""
        # İncelenecek başlangıç öğelerinin dinamik listesi
        self.items: List[StartupItem] = []
        # Denetim sonucunda ortaya çıkan güvenlik bulguları listesi
        self.findings: List[StartupSecurityFinding] = []
        # Doğrulama sırasında reddedilen bozuk kayıtların hata günlüğü
        self.corrupted_records: List[Dict[str, Any]] = []

    def validate_entry(self, entry: Any) -> Tuple[bool, str]:
        """
        Gelen ham veri kaydının şema ve sözleşme kurallarına uygunluğunu doğrular.
        Negatif kontrollerin başarısı ve veri bütünlüğü için temel koruma katmanıdır.
        """
        # Kaydın sözlük (dictionary) tipinde olup olmadığını sınıyoruz
        if not isinstance(entry, dict):
            # Sözlük değilse hemen geçersiz olarak işaretleyip gerekçesini bildiriyoruz
            return False, "KAYIT_SOZLUK_DEGIL: Girdi bir JSON objesi/sözlük olmalıdır."

        # Zorunlu alanların kayıtta bulunup bulunmadığını denetliyoruz
        for mandatory_key in ["name", "binary_path", "entry_type"]:
            # Anahtar yoksa veya boşsa hata üretiyoruz
            if mandatory_key not in entry:
                # Eksik zorunlu alan gerekçesini dönüyoruz
                return False, f"EKSIK_ZORUNLU_ALAN: '{mandatory_key}' alanı tanımlanmalıdır."

        # 'name' alanının metinsel ve boşluktan ibaret olmadığını teyit ediyoruz
        name_val = str(entry.get("name", "")).strip()
        # İsim boşsa doğrulamayı reddediyoruz
        if not name_val:
            # Boş isim hata mesajı
            return False, "GECERSIZ_ISIM: Servis/girdi adı boş veya salt boşluk olamaz."

        # 'binary_path' alanının metinsel ve geçerli olduğunu teyit ediyoruz
        path_val = str(entry.get("binary_path", "")).strip()
        # Yol boşsa doğrulamayı reddediyoruz
        if not path_val:
            # Boş dosya yolu hata mesajı
            return False, "GECERSIZ_YOL: İkili dosya yolu boş veya salt boşluk olamaz."

        # 'entry_type' alanının tanımlı türlerden biri olduğunu denetliyoruz
        entry_type_val = str(entry.get("entry_type", "")).strip().lower()
        # Desteklenmeyen bir tür gelirse reddediyoruz
        if entry_type_val not in self.VALID_ENTRY_TYPES:
            # Desteklenmeyen tür hata bildirimi
            return False, f"GECERSIZ_TUR: '{entry_type_val}' geçerli bir başlangıç türü değildir."

        # Eğer servis ise başlangıç modunu sınıyoruz
        if entry_type_val == "service" and "start_mode" in entry:
            # Mod değerini okuyoruz
            start_mode_val = str(entry.get("start_mode", "")).strip()
            # Tanımlı modlar kümesinde yer alıp almadığına bakıyoruz
            if start_mode_val not in self.VALID_START_MODES:
                # Geçersiz servis başlatma modu hatası
                return False, f"GECERSIZ_BASLANGIC_MODU: '{start_mode_val}' geçerli bir başlatma modu değildir."

        # Tüm sözleşme kuralları sağlanmışsa geçerli sonucunu üretiyoruz
        return True, "GECERLI"

    def add_item(self, entry: Dict[str, Any]) -> bool:
        """Doğrulanmış bir başlangıç kaydını envantere ekler."""
        # Kaydı şema kurallarına göre inceliyoruz
        is_valid, reason = self.validate_entry(entry)
        # Geçersizse envantere katmayıp hata kaydına alıyoruz
        if not is_valid:
            # Bozuk kaydı ve sebebini listeye işliyoruz
            self.corrupted_records.append({"raw_record": entry, "error_reason": reason})
            # Başarısızlık bayrağını döndürüyoruz
            return False

        # Güvenli varsayılan değerlerle StartupItem örneğini inşa ediyoruz
        item = StartupItem(
            id=str(entry.get("id", f"GEN-{len(self.items) + 1:03d}")),
            name=str(entry.get("name", "")).strip(),
            display_name=str(entry.get("display_name", entry.get("name", ""))).strip(),
            entry_type=str(entry.get("entry_type", "")).strip().lower(),
            start_mode=str(entry.get("start_mode", "Unknown")).strip(),
            status=str(entry.get("status", "Unknown")).strip(),
            binary_path=str(entry.get("binary_path", "")).strip(),
            account=str(entry.get("account", "Unspecified")).strip(),
            category=str(entry.get("category", "unclassified")).strip(),
            signed=bool(entry.get("signed", False)),
            location=str(entry.get("location", "N/A")).strip(),
            description=str(entry.get("description", "")).strip()
        )
        # Oluşturulan temiz nesneyi envanter dizisine ilave ediyoruz
        self.items.append(item)
        # Başarı sonucunu iletiyoruz
        return True

    def load_from_json(self, file_path: str) -> int:
        """JSON dosyasından başlangıç ve servis envanterini yükler."""
        # Hedef dosyanın disk üzerinde varlığını kontrol ediyoruz
        if not os.path.exists(file_path):
            # Dosya bulunamadığında açıklayıcı dosya hatası fırlatıyoruz
            raise FileNotFoundError(f"Envanter dosyası diskte bulunamadı: {file_path}")

        # Dosyayı UTF-8 formatında okuma kipinde açıyoruz
        with open(file_path, "r", encoding="utf-8") as f:
            # JSON içeriğini Python veri yapısına çözümlüyoruz
            raw_data = json.load(f)

        # Veri yapısının liste olup olmadığını sınıyoruz
        if not isinstance(raw_data, list):
            # Liste değilse şema ihlali hatası fırlatıyoruz
            raise ValueError("Envanter veri formatı bir liste olmalıdır.")

        # Başarıyla eklenen elemanların sayaç değişkeni
        loaded_count = 0
        # Her bir girdi sözlüğünü tek tek işliyoruz
        for entry in raw_data:
            # Girdiyi eklemeye çalışıp sonucunu denetliyoruz
            if self.add_item(entry):
                # Başarılıysa sayacı bir artırıyoruz
                loaded_count += 1

        # Toplam yüklenen meşru eleman sayısını geri dönüyoruz
        return loaded_count

    def detect_unquoted_service_paths(self) -> List[StartupSecurityFinding]:
        """
        Tırnaksız Servis Yolu (Unquoted Service Path - MITRE T1574.009) zafiyetlerini bulur.
        Servis ikili dosya yolu boşluk içeriyorsa ve çift tırnak içine alınmamışsa,
        Windows Hizmet Denetim Yöneticisi (SCM) her boşlukta yürütme dener.
        """
        # Tespit edilen bulguları tutacak yerel liste
        local_findings: List[StartupSecurityFinding] = []

        # Envanterdeki tüm kayıtları dolaşıyoruz
        for item in self.items:
            # Sadece servis türündeki kayıtları hedef alıyoruz
            if item.entry_type != "service":
                # Servis dışındakileri atlıyoruz
                continue

            # İkili dosya yolunu alıyoruz
            raw_path = item.binary_path.strip()

            # Yol çift tırnak ile başlıyorsa ve kapanıyorsa tırnak içine alınmıştır, güvenlidir
            if raw_path.startswith('"') and '"' in raw_path[1:]:
                # Tırnaklı yol zafiyet içermez
                continue

            # Komut satırı argümanlarını yoldan ayırmak için ilk .exe veya parametre öncesini süzüyoruz
            executable_candidate = raw_path
            # Eğer parametre ayracı olarak boşluk ve tire varsa kaba ayrım yapıyoruz
            if ".exe " in raw_path.lower():
                # .exe bitimine kadar olan kısmı yürütülebilir dosya yolu olarak alıyoruz
                idx = raw_path.lower().index(".exe ") + 4
                # Kesiti güncelliyoruz
                executable_candidate = raw_path[:idx]

            # Yolda boşluk karakteri olup olmadığını sınıyoruz
            if " " in executable_candidate:
                # Genellikle Program Files veya boşluklu dizinler tırnaksız bırakılır
                # Yetki yükseltme potansiyelini değerlendiriyoruz (LocalSystem, SYSTEM vb.)
                is_elevated = any(priv in item.account.upper() for priv in ["SYSTEM", "ADMINISTRATOR"])
                # Yetkili hesapsa zafiyet derecesi HIGH, değilse MEDIUM
                severity = "HIGH" if is_elevated else "MEDIUM"

                # Zafiyet bulgusu nesnesini inşa ediyoruz
                finding = StartupSecurityFinding(
                    item_id=item.id,
                    item_name=item.name,
                    risk_level=severity,
                    vulnerability_type="UNQUOTED_SERVICE_PATH",
                    description=(
                        f"Servis ikili dosya yolu ('{executable_candidate}') boşluk karakteri içermesine rağmen "
                        f"çift tırnak içerisine alınmamış. Windows SCM bileşeni yetki yükseltme saldırılarına "
                        f"açık bir şekilde dosya arama zinciri (Path Interception) işletecektir."
                    ),
                    mitre_technique="T1574.009 (Path Interception by Unquoted Path)",
                    remediation=(
                        f"Kayıt defterinde veya sc.exe yapılandırmasında ikili dosya yolunu çift tırnak içine alınız: "
                        f'sc.exe config "{item.name}" binPath= "\\"{executable_candidate}\\""'
                    )
                )
                # Listeye ekliyoruz
                local_findings.append(finding)

        # Tespit edilen bulguları geri dönüyoruz
        return local_findings

    def detect_suspicious_binary_paths(self) -> List[StartupSecurityFinding]:
        """
        Geçici, standart dışı veya kullanıcı tarafından yazılabilir dizinlerden
        otomatik başlatılan şüpheli yazılımları tespit eder (MITRE T1547.001).
        """
        # Yerel tespit listesi
        local_findings: List[StartupSecurityFinding] = []

        # Her bir başlangıç nesnesini inceliyoruz
        for item in self.items:
            # Dosya yolunu küçük harfe dönüştürerek kalıpları denetliyoruz
            lower_path = item.binary_path.lower()

            # Tanımlı şüpheli dizin kalıplarını regex ile tarıyoruz
            for pattern in self.SUSPICIOUS_PATH_PATTERNS:
                # Eşleşme var mı kontrol ediyoruz
                if re.search(pattern, lower_path):
                    # Kayıt türüne ve imza durumuna göre risk belirliyoruz
                    severity = "CRITICAL" if not item.signed else "HIGH"
                    # Açıklama metnini hazırlıyoruz
                    finding = StartupSecurityFinding(
                        item_id=item.id,
                        item_name=item.name,
                        risk_level=severity,
                        vulnerability_type="SUSPICIOUS_PATH",
                        description=(
                            f"Başlangıç öğesi şüpheli ve kullanıcı tarafından yazılabilir bir konumdan "
                            f"('{item.binary_path}') yürütülmektedir. Bu konumlar zararlı yazılımlar tarafından "
                            f"kalıcılık sağlamak ve standart sistem kontrollerini atlatmak için sıkça tercih edilir."
                        ),
                        mitre_technique="T1547.001 (Registry Run Keys / Startup Folder)",
                        remediation=(
                            f"İlgili başlangıç girdisini ('{item.name}') derhal devre dışı bırakın, "
                            f"dosya karmasını (SHA256) EDR/Sandbox ortamında analiz edin ve kalıcılık anahtarını silin."
                        )
                    )
                    # Bulguyu ekliyoruz
                    local_findings.append(finding)
                    # Bir öğe için bir kere şüpheli yol tespiti yeterlidir
                    break

        # Listeyi dönüyoruz
        return local_findings

    def detect_name_masquerading(self) -> List[StartupSecurityFinding]:
        """
        Meşru sistem servis veya süreç isimlerini taklit eden (Masquerading / Typosquatting)
        zararlı kalıcılık girdilerini tespit eder (MITRE T1036).
        """
        # Yerel bulgu listesi
        local_findings: List[StartupSecurityFinding] = []

        # Envanterdeki kayıtları dolaşıyoruz
        for item in self.items:
            # Kayıt adını küçük harfe alıyoruz
            lower_name = item.name.lower()
            # İkili dosya adını alıyoruz
            base_bin = os.path.basename(item.binary_path.split()[0].replace('"', '')).lower()

            # Meşru sistem isimleri ile benzerlik karşılaştırması yapıyoruz
            for legit_bin, legit_desc in self.LEGITIMATE_SYSTEM_NAMES.items():
                # Temel sistem ismi kökünü alıyoruz (Örn: svchost)
                legit_stem = legit_bin.replace(".exe", "")

                # 1. Durum: Meşru adın sahte yazımı (svch0st, lsasss, csrsss vb.)
                is_typo = False
                # svch0st kontrolü (o yerine 0)
                if legit_stem.replace("o", "0") in lower_name or legit_stem.replace("o", "0") in base_bin:
                    is_typo = True
                # Fazladan harf uzatması (lsasss, svchostt)
                elif (legit_stem + "s" in lower_name or legit_stem + "s" in base_bin) and lower_name != legit_stem:
                    is_typo = True

                # 2. Durum: Meşru ad kullanılmış fakat System32 dışında bir konumdan çalışıyor
                is_wrong_location = False
                if base_bin == legit_bin:
                    # Windows System32 klasöründe değilse taklit olarak değerlendiriyoruz
                    if "system32" not in item.binary_path.lower():
                        is_wrong_location = True

                # Herhangi bir taklit koşulu oluştuysa bulgu üretiyoruz
                if is_typo or is_wrong_location:
                    # Bulgu nesnesi
                    finding = StartupSecurityFinding(
                        item_id=item.id,
                        item_name=item.name,
                        risk_level="CRITICAL",
                        vulnerability_type="MASQUERADING",
                        description=(
                            f"Başlangıç kaydı meşru Windows bileşeni '{legit_bin}' ({legit_desc}) ismini "
                            f"taklit etmektedir (Yol: '{item.binary_path}'). Bu teknik güvenlik analistlerini "
                            f"ve temel izleme araçlarını yanıltmak amacıyla kullanılır."
                        ),
                        mitre_technique="T1036 (Masquerading)",
                        remediation=(
                            f"Süreç ve başlangıç kaydını karantinaya alın. Sürecin meşru System32 ikilisi "
                            f"olmadığını doğrulayarak dosya imzasını ve bellek dökümünü inceleyin."
                        )
                    )
                    # Listeye dahil ediyoruz
                    local_findings.append(finding)
                    # Aynı kayıt için mükerrer kontrolü kesiyoruz
                    break

        # Bulguları döndürüyoruz
        return local_findings

    def detect_security_service_tampering(self) -> List[StartupSecurityFinding]:
        """
        Kritik savunma ve güvenlik servislerinin devre dışı bırakılmasını veya
        durdurulmasını tespit eder (Impair Defenses - MITRE T1562.001).
        """
        # Yerel tespit listesi
        local_findings: List[StartupSecurityFinding] = []

        # Kritik servisler haritasını denetliyoruz
        for critical_name, crit_meta in self.CRITICAL_SECURITY_SERVICES.items():
            # Envanterde bu isimde bir servis var mı arıyoruz
            matched_items = [i for i in self.items if i.name.lower() == critical_name.lower() and i.entry_type == "service"]

            # Eğer kritik servis envanterde yer alıyorsa durumunu sınıyoruz
            for svc in matched_items:
                # Servisin devre dışı bırakılmış veya durdurulmuş olma hali
                is_disabled = svc.start_mode.lower() == "disabled"
                is_stopped = svc.status.lower() == "stopped"

                # Eğer beklenen otomatik çalışma bozulmuşsa alarm üretiyoruz
                if is_disabled or (is_stopped and svc.start_mode.lower() == "automatic"):
                    # Güvenlik zafiyeti derecesi
                    severity = "CRITICAL" if is_disabled else "HIGH"
                    # Bulgu kaydını hazırlıyoruz
                    finding = StartupSecurityFinding(
                        item_id=svc.id,
                        item_name=svc.name,
                        risk_level=severity,
                        vulnerability_type="SERVICE_TAMPERING",
                        description=(
                            f"Kritik güvenlik bileşeni '{svc.name}' ({crit_meta['desc']}) beklenen çalışma durumunda değildir! "
                            f"Mevcut Durum: '{svc.status}', Başlangıç Modu: '{svc.start_mode}'. "
                            f"Saldırganlar tespit edilmemek için savunma araçlarını devre dışı bırakırlar."
                        ),
                        mitre_technique="T1562.001 (Impair Defenses: Disable or Modify Tools)",
                        remediation=(
                            f"Servisi derhal otomatik başlangıç moduna geçirip yeniden başlatınız: "
                            f"sc.exe config {svc.name} start= auto && sc.exe start {svc.name}"
                        )
                    )
                    # Listeye ekliyoruz
                    local_findings.append(finding)

        # Bulguları geri iletiyoruz
        return local_findings

    def detect_suspicious_script_execution(self) -> List[StartupSecurityFinding]:
        """
        Gizli pencere, kod çözme (encoded command) veya yetki bypass parametreleri
        ile çalışan şüpheli betik motorlarını tespit eder (MITRE T1059 / T1027).
        """
        # Yerel liste oluşturuyoruz
        local_findings: List[StartupSecurityFinding] = []

        # Şüpheli komut satırı bayrakları listesi
        suspicious_flags = [
            "-executionpolicy bypass",
            "-windowstyle hidden",
            "-encodedcommand",
            "-nop",
            "-noni",
            "-w hidden",
            "-enc"
        ]

        # Envanterdeki tüm öğeleri tarıyoruz
        for item in self.items:
            # Yolu ve argümanları küçük harfe çeviriyoruz
            cmd_lower = item.binary_path.lower()

            # Betik motorları kontrolü (powershell, cmd, wscript, cscript, mshta)
            script_engines = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "nc.exe"]
            # Herhangi bir motor geçiyor mu sınıyoruz
            has_engine = any(eng in cmd_lower for eng in script_engines)

            # Şüpheli bayraklardan en az biri var mı sınıyoruz
            flag_matches = [flag for flag in suspicious_flags if flag in cmd_lower]

            # Netcat dinleyicisi veya gizli powershell çalıştırma gibi tehditleri yakalıyoruz
            if "nc.exe" in cmd_lower or (has_engine and len(flag_matches) >= 2):
                # Yüksek veya kritik risk atıyoruz
                finding = StartupSecurityFinding(
                    item_id=item.id,
                    item_name=item.name,
                    risk_level="CRITICAL",
                    vulnerability_type="MALICIOUS_SCRIPT",
                    description=(
                        f"Başlangıç girdisi zararlı veya gizlenmiş komut satırı bayrakları "
                        f"({', '.join(flag_matches) if flag_matches else 'Reverse Shell Listener'}) içermektedir: "
                        f"'{item.binary_path}'."
                    ),
                    mitre_technique="T1059.001 (Command and Scripting Interpreter: PowerShell)",
                    remediation=(
                        f"Kalıcılık girdisini derhal sonlandırın ve silin. Betik içeriğini deşifre edip "
                        f"bağlantı kurulan C2 IP adreslerini güvenlik duvarında engelleyiniz."
                    )
                )
                # Listeye katıyoruz
                local_findings.append(finding)

        # Bulguları teslim ediyoruz
        return local_findings

    def calculate_system_risk_score(self) -> Dict[str, Any]:
        """
        Tespit edilen tüm güvenlik bulgularını ağırlıklandırarak
        0-100 arasında bir Sistem Tehdit Puanı (Risk Score) hesaplar.
        """
        # Risk seviyesi ağırlık puanları tablosu
        weights = {
            "CRITICAL": 35,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
            "INFO": 0
        }

        # Ham toplam puanı hesaplıyoruz
        raw_score = sum(weights.get(f.risk_level, 0) for f in self.findings)
        # Puanı maksimum 100 ile sınırlıyoruz
        normalized_score = min(100, raw_score)

        # Tehdit derecelendirme sınıflandırması
        if normalized_score >= 80:
            posture = "CRITICAL_THREAT"
        elif normalized_score >= 50:
            posture = "HIGH_RISK"
        elif normalized_score >= 20:
            posture = "ELEVATED_RISK"
        elif normalized_score > 0:
            posture = "LOW_RISK"
        else:
            posture = "SECURE_BASELINE"

        # Hesaplanan metrikleri sözlük olarak geri dönüyoruz
        return {
            "risk_score": normalized_score,
            "posture": posture,
            "total_findings": len(self.findings),
            "findings_by_severity": {
                "CRITICAL": sum(1 for f in self.findings if f.risk_level == "CRITICAL"),
                "HIGH": sum(1 for f in self.findings if f.risk_level == "HIGH"),
                "MEDIUM": sum(1 for f in self.findings if f.risk_level == "MEDIUM"),
                "LOW": sum(1 for f in self.findings if f.risk_level == "LOW"),
            }
        }

    def run_comprehensive_audit(self) -> Dict[str, Any]:
        """Tüm tespit mekanizmalarını sırayla koşturarak konsolide denetim raporu üretir."""
        # Bulgular listesini sıfırlıyoruz
        self.findings = []

        # 1. Tırnaksız servis yollarını tespit et
        self.findings.extend(self.detect_unquoted_service_paths())

        # 2. Şüpheli dizinlerden çalışan başlangıç girdilerini bul
        self.findings.extend(self.detect_suspicious_binary_paths())

        # 3. İsim taklit etme ve sahtecilik anomalilerini çıkar
        self.findings.extend(self.detect_name_masquerading())

        # 4. Güvenlik servisi tahrifatlarını incele
        self.findings.extend(self.detect_security_service_tampering())

        # 5. Gizlenmiş veya şüpheli betik çalıştırmalarını tespit et
        self.findings.extend(self.detect_suspicious_script_execution())

        # Sistem risk puanını hesaplıyoruz
        risk_metrics = self.calculate_system_risk_score()

        # Konsolide özet yapısını hazırlıyoruz
        audit_summary = {
            "total_items_analyzed": len(self.items),
            "corrupted_records_count": len(self.corrupted_records),
            "risk_metrics": risk_metrics,
            "findings": [asdict(f) for f in self.findings]
        }

        # Özeti döndürüyoruz
        return audit_summary

    def generate_text_report(self) -> str:
        """Denetim sonuçlarını okunabilir ASCII metin formatında raporlar."""
        # Rapor satırları dizisi
        lines: List[str] = []
        # Başlık ve çizgi ekliyoruz
        lines.append("=" * 80)
        lines.append("BAŞLANGIÇ UYGULAMALARI VE HİZMET YÖNETİMİ GÜVENLİK DENETİM RAPORU")
        lines.append("=" * 80)

        # Risk metriklerini alıyoruz
        metrics = self.calculate_system_risk_score()
        lines.append(f"İncelenen Toplam Başlangıç/Servis Öğesi: {len(self.items)}")
        lines.append(f"Reddedilen Bozuk Kayıt Sayısı         : {len(self.corrupted_records)}")
        lines.append(f"Genel Tehdit Puanı (Risk Score)       : {metrics['risk_score']} / 100")
        lines.append(f"Sistem Güvenlik Duruşu (Posture)      : {metrics['posture']}")
        lines.append(f"Tespit Edilen Güvenlik Bulguları      : {metrics['total_findings']}")
        lines.append("-" * 80)
        lines.append("Ciddiyet Dağılımı:")
        for sev, count in metrics["findings_by_severity"].items():
            lines.append(f"  * {sev:<10}: {count}")
        lines.append("-" * 80)

        # Bulguların detaylarını listeliyoruz
        if not self.findings:
            lines.append("Tebrikler: Herhangi bir güvenlik zafiyeti veya anomalisi tespit edilmedi.")
        else:
            lines.append("DETAYLI GÜVENLİK BULGULARI:")
            for idx, finding in enumerate(self.findings, 1):
                lines.append(f"\n[{idx}] [{finding.risk_level}] {finding.item_name} (ID: {finding.item_id})")
                lines.append(f"    Zafiyet Türü : {finding.vulnerability_type}")
                lines.append(f"    MITRE Kodu   : {finding.mitre_technique}")
                lines.append(f"    Açıklama     : {finding.description}")
                lines.append(f"    İyileştirme  : {finding.remediation}")

        # Bozuk kayıtlar varsa listeliyoruz
        if self.corrupted_records:
            lines.append("\n" + "-" * 80)
            lines.append("REDDEDİLEN BOZUK VERİ KAYITLARI (NEGATİF KONTROL):")
            for idx, err in enumerate(self.corrupted_records, 1):
                lines.append(f"  ({idx}) Hata: {err['error_reason']}")

        lines.append("=" * 80)
        # Birleştirip string olarak dönüyoruz
        return "\n".join(lines)


def main() -> None:
    """Komut satırı arayüzünden çalıştırma ve bağımsız test yürütücüsü."""
    # Varsayılan dosya yolları
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_inv = os.path.join(base_dir, "ornek_veri", "sample_startup_service_inventory.json")

    # Denetleyiciyi başlatıyoruz
    auditor = StartupServiceAuditor()

    # Eğer envanter dosyası varsa yüklüyoruz
    if os.path.exists(default_inv):
        auditor.load_from_json(default_inv)
        # Denetimi koşturuyoruz
        auditor.run_comprehensive_audit()
        # Raporu ekrana yazdırıyoruz
        print(auditor.generate_text_report())
    else:
        print(f"Hata: Envanter dosyası bulunamadı: {default_inv}")


# Komut satırından çağrıldığında ana fonksiyonu yürüt
if __name__ == "__main__":
    main()
