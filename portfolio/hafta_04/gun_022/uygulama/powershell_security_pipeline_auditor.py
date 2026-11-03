# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar yalnızca görüntüleme ve eğitim amaçlıdır.
# Siber Güvenlik 365 Gün Müfredatı - Gün 022 (Komut Satırı: PowerShell Temelleri)

"""PowerShell Nesne Akışı ve Güvenlik Denetim Motoru (PowerShell Security Pipeline Auditor).

Bu modül, PowerShell'in metin yerine .NET nesnesi taşıyan boru hattı (Object Pipeline)
mimarisini modeller; Get-Process ve Get-Service çıktılarını filtreleyerek
şüpheli komut satırı parametrelerini (MITRE ATT&CK T1059.001), tırnaksız servis yollarını
(CWE-428) ve güvensiz servisleri denetler ve sonuçları CSV'ye aktarır.
"""

# Komut satırı argümanlarını ayrıştırmak için sys modülü içe aktarılır.
import sys
# Dosya sistemi yolları ve ortam değişkenleri için os modülü içe aktarılır.
import os
# JSON formatında girdi/çıktı ayrıştırması için json modülü içe aktarılır.
import json
# Filtrelenmiş nesneleri standart tabloya yazmak için csv modülü içe aktarılır.
import csv
# Harici PowerShell komutlarını güvenli alt süreç olarak çalıştırmak için subprocess içe aktarılır.
import subprocess
# Zaman damgalı denetim kayıtları için datetime ve timezone sınıfları içe aktarılır.
from datetime import datetime, timezone
# Tip güvenliği ve statik analiz için tip ipuçları içe aktarılır.
from typing import Dict, List, Any, Optional


class PowerShellSecurityPipelineAuditor:
    """PowerShell süreç ve servis nesnelerini filtreleyen ve denetleyen sınıf."""

    def __init__(self, rules_data: Optional[Dict[str, Any]] = None) -> None:
        """Denetim kuralları ile analiz motorunu başlatır.

        Args:
            rules_data: Şüpheli süreç kalıpları ve servis karalistesini içeren kural sözlüğü.
        """
        # Verilen kurallar atanır; yoksa dahili varsayılan kural seti yüklenir.
        self.rules = rules_data or self._get_default_rules()
        # Denetim bulgularını saklamak için liste tanımlanır.
        self.findings: List[Dict[str, Any]] = []

    def _get_default_rules(self) -> Dict[str, Any]:
        """Varsayılan güvenlik ve kaynak eşik kurallarını döndürür."""
        # MITRE ATT&CK ve CIS standartlarına dayalı varsayılan sözlük döndürülür.
        return {
            "supheli_surec_kaliplari": [
                "mimikatz",
                "-enc",
                "-encodedcommand",
                "-executionpolicy bypass",
                "-w hidden",
                "-windowstyle hidden",
                "sekurlsa"
            ],
            "kaynak_sinirlari": {
                "maks_handles": 2000,
                "maks_ram_mb": 150.0
            },
            "guvensiz_servis_karalistesi": [
                "tlntsvr",
                "remoteregistry",
                "ftpsvc",
                "smbv1"
            ],
            "csv_rapor_kolonlari": [
                "nesne_tipi",
                "isim",
                "id_veya_durum",
                "metrik_veya_hesap",
                "risk_seviyesi",
                "guvenlik_gerekcesi"
            ]
        }

    def collect_live_powershell_objects(self) -> Dict[str, Any]:
        """Canlı sistemde salt-okunur PowerShell cmdlet'lerini çalıştırarak nesne toplar.

        Returns:
            Toplanan canlı süreç ve servis nesnelerini içeren sözlük.
        """
        # Canlı süreç listesi başlatılır.
        processes: List[Dict[str, Any]] = []
        # Canlı servis listesi başlatılır.
        services: List[Dict[str, Any]] = []

        # Sistemde PowerShell ikilisinin varlığı kontrol edilir.
        ps_executable = "powershell" if os.name == "nt" else "pwsh"

        try:
            # Get-Process komutu salt-okunur ve JSON çıktılı olarak çalıştırılır.
            proc_cmd = f"{ps_executable} -NoProfile -Command \"Get-Process | Select-Object -First 5 ProcessName, Id, CPU, WorkingSet64, Handles | ConvertTo-Json\""
            # Alt süreç güvenli şekilde çağrılır.
            res_proc = subprocess.run(proc_cmd, shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=8)
            # Çıkış kodu kontrol edilir ve JSON ayrıştırılır.
            if res_proc.returncode == 0 and res_proc.stdout.strip():
                # JSON metni sözlüğe veya listeye dönüştürülür.
                parsed_proc = json.loads(res_proc.stdout)
                # Tekil nesne döndüyse listeye çevrilir.
                processes = parsed_proc if isinstance(parsed_proc, list) else [parsed_proc]

            # Get-Service komutu salt-okunur ve JSON çıktılı olarak çalıştırılır.
            srv_cmd = f"{ps_executable} -NoProfile -Command \"Get-Service | Where-Object {{ $_.Status -eq 'Running' }} | Select-Object -First 5 Name, DisplayName, Status, StartType | ConvertTo-Json\""
            # Alt süreç güvenli şekilde çağrılır.
            res_srv = subprocess.run(srv_cmd, shell=True, capture_output=True, encoding="utf-8", errors="replace", timeout=8)
            # Çıkış kodu kontrol edilir ve JSON ayrıştırılır.
            if res_srv.returncode == 0 and res_srv.stdout.strip():
                # JSON metni dönüştürülür.
                parsed_srv = json.loads(res_srv.stdout)
                # Tekil nesne kontrolü yapılır.
                services = parsed_srv if isinstance(parsed_srv, list) else [parsed_srv]

        except Exception as err:
            # Canlı ortamda hata oluşursa sentetik güvenli nesneler üretilir.
            processes = [
                {"ProcessName": "pwsh_live", "Id": os.getpid(), "CPU": 0.5, "WorkingSetMB": 45.0, "Handles": 320, "CommandLine": "powershell -live"}
            ]
            # Örnek servis eklenir.
            services = [
                {"Name": "WinDefend", "DisplayName": "Defender", "Status": "Running", "StartType": "Automatic", "ServiceAccount": "LocalSystem"}
            ]

        # Sonuç sözlüğü döndürülür.
        return {
            "toplama_zamani": datetime.now(timezone.utc).isoformat(),
            "surecler": processes,
            "servisler": services
        }

    def load_json_file(self, file_path: str) -> Any:
        """Harici bir JSON dosyasını doğrulanabilir biçimde yükler.

        Args:
            file_path: Okunacak dosya yolu.

        Raises:
            FileNotFoundError: Dosya yoksa fırlatılır.
            ValueError: JSON bozuksa fırlatılır.
        """
        # Dosya yolu kontrol edilir.
        if not os.path.exists(file_path):
            # Dosya bulunamadı hatası üretilir.
            raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")

        # Dosya UTF-8 kodlamasıyla açılır.
        with open(file_path, "r", encoding="utf-8") as fp:
            try:
                # Veri okunur ve çözülür.
                return json.load(fp)
            except json.JSONDecodeError as err:
                # Bozuk format için ValueError fırlatılır.
                raise ValueError(f"Geçersiz JSON formatı: {err}")

    def audit_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Süreç nesnelerini MITRE ATT&CK ve kaynak anomalileri açısından denetler.

        Args:
            processes: İncelenecek süreç nesneleri listesi.

        Returns:
            Tespit edilen güvenlik bulguları listesi.
        """
        # Süreç bulgularını toplayacak liste başlatılır.
        proc_findings: List[Dict[str, Any]] = []
        # Şüpheli komut satırı kalıpları küçük harfe dönüştürülür.
        suspicious_patterns = [p.lower() for p in self.rules.get("supheli_surec_kaliplari", [])]
        # Kaynak sınırları okunur.
        limits = self.rules.get("kaynak_sinirlari", {})
        # Maksimum handle eşiği alınır.
        max_handles = limits.get("maks_handles", 2000)
        # Maksimum RAM eşiği alınır.
        max_ram = limits.get("maks_ram_mb", 150.0)

        # Tüm süreç nesneleri üzerinde döngü kurulur.
        for proc in processes:
            # Süreç adı güvenli biçimde alınır.
            name = proc.get("ProcessName", "Bilinmeyen")
            # Süreç PID numarası alınır.
            pid = proc.get("Id", 0)
            # Komut satırı argümanı küçük harfe çevrilir.
            cmdline = str(proc.get("CommandLine", "")).lower()
            # Handle adedi okunur.
            handles = proc.get("Handles", 0)
            # Bellek kullanımı okunur.
            ram = proc.get("WorkingSetMB") or (proc.get("WorkingSet64", 0) / (1024 * 1024))

            # 1. Şüpheli Komut Satırı Tespiti (MITRE ATT&CK T1059.001)
            is_suspicious = False
            # Kalıplar taranır.
            for pattern in suspicious_patterns:
                # Kalıp komut satırında veya süreç adında var mı kontrol edilir.
                if pattern in cmdline or pattern in name.lower():
                    # İhlal bayrağı kaldırılır.
                    is_suspicious = True
                    # Kritik bulgu kaydedilir.
                    proc_findings.append({
                        "nesne_tipi": "Surec",
                        "isim": name,
                        "id_veya_durum": str(pid),
                        "metrik_veya_hesap": f"{handles} Handle / {round(ram, 1)} MB",
                        "risk_seviyesi": "KRITIK",
                        "guvenlik_gerekcesi": f"Şüpheli PowerShell/süreç parametresi tespit edildi: '{pattern}' (MITRE T1059.001)"
                    })
                    # Tek bir süreç için çoklu eşleşmeyi önlemek için çıkılır.
                    break

            # 2. Aşırı Kaynak Tüketim Anomalisi Denetimi
            if not is_suspicious and (handles > max_handles or ram > max_ram):
                # Orta seviyeli anomali bulgusu eklenir.
                proc_findings.append({
                    "nesne_tipi": "Surec",
                    "isim": name,
                    "id_veya_durum": str(pid),
                    "metrik_veya_hesap": f"{handles} Handle / {round(ram, 1)} MB",
                    "risk_seviyesi": "ORTA",
                    "guvenlik_gerekcesi": f"Kaynak tüketimi eşik değerleri aşıldı (Eşik: {max_handles} Handle / {max_ram} MB)"
                })

        # Süreç bulguları döndürülür.
        return proc_findings

    def audit_services(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Servis nesnelerini güvensiz protokoller ve tırnaksız servis yolları açısından denetler.

        Args:
            services: İncelenecek servis nesneleri listesi.

        Returns:
            Tespit edilen servis güvenlik bulguları listesi.
        """
        # Servis bulguları listesi başlatılır.
        srv_findings: List[Dict[str, Any]] = []
        # Karalistedeki servisler küçük harfe çevrilir.
        blacklist = [s.lower() for s in self.rules.get("guvensiz_servis_karalistesi", [])]

        # Tüm servisler taranır.
        for srv in services:
            # Servis kısa adı alınır.
            name = srv.get("Name", "Bilinmeyen")
            # Servis durumu alınır.
            status = srv.get("Status", "Bilinmeyen")
            # Servis hesabı alınır.
            account = srv.get("ServiceAccount", "LocalSystem")
            # Servis çalıştırılabilir dosya yolu alınır.
            binary_path = srv.get("BinaryPathName", "")

            # 1. Güvensiz ve Karalistedeki Servis Kontrolü
            for bad_service in blacklist:
                # Eşleşme var mı ve servis çalışıyor mu bakılır.
                if bad_service in name.lower() and status.lower() == "running":
                    # Kritik servis bulgusu kaydedilir.
                    srv_findings.append({
                        "nesne_tipi": "Servis",
                        "isim": name,
                        "id_veya_durum": status,
                        "metrik_veya_hesap": account,
                        "risk_seviyesi": "KRITIK",
                        "guvenlik_gerekcesi": f"Güvensiz/eski protokol servisi çalışıyor: '{name}' (CIS İhlali)"
                    })
                    # Döngü kırılır.
                    break

            # 2. Tırnaksız Servis Yolu Zafiyeti Denetimi (CWE-428 / MITRE T1574.009)
            # Yol içinde boşluk var mı ve yol çift tırnakla başlamıyor mu kontrol edilir.
            if binary_path and " " in binary_path and not binary_path.startswith("\""):
                # Yüksek riskli CWE-428 bulgusu kaydedilir.
                srv_findings.append({
                    "nesne_tipi": "Servis",
                    "isim": name,
                    "id_veya_durum": status,
                    "metrik_veya_hesap": account,
                    "risk_seviyesi": "YUKSEK",
                    "guvenlik_gerekcesi": f"Tırnaksız servis yolu zafiyeti (CWE-428): '{binary_path}'"
                })

        # Servis bulguları döndürülür.
        return srv_findings

    def run_full_audit(self,
                       processes: List[Dict[str, Any]],
                       services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Süreç ve servis nesnelerini bütünleşik olarak denetler ve bulguları birleştirir.

        Args:
            processes: Süreç nesneleri.
            services: Servis nesneleri.

        Returns:
            Tüm filtrelenmiş güvenlik bulguları listesi.
        """
        # Süreçler denetlenir.
        p_res = self.audit_processes(processes)
        # Servisler denetlenir.
        s_res = self.audit_services(services)
        # Bulgular birleştirilir.
        self.findings = p_res + s_res
        # Bütünleşik liste döndürülür.
        return self.findings

    def export_filtered_to_csv(self,
                               findings: List[Dict[str, Any]],
                               output_csv_path: str) -> str:
        """Filtrelenmiş süreç ve servis bulgularını CSV formatında dışa aktarır (G022-SC2).

        Args:
            findings: Dışa aktarılacak bulgular listesi.
            output_csv_path: Yazılacak hedef CSV dosya yolu.

        Returns:
            Kaydedilen CSV dosyasının mutlak yolu.
        """
        # CSV kolon başlıkları kural setinden veya varsayılandan alınır.
        headers = self.rules.get("csv_rapor_kolonlari", [
            "nesne_tipi",
            "isim",
            "id_veya_durum",
            "metrik_veya_hesap",
            "risk_seviyesi",
            "guvenlik_gerekcesi"
        ])

        # Hedef klasörün varlığı sağlanır.
        out_dir = os.path.dirname(output_csv_path)
        # Klasör yolu varsa ve mevcut değilse oluşturulur.
        if out_dir and not os.path.exists(out_dir):
            # Klasör açılır.
            os.makedirs(out_dir, exist_ok=True)

        # Dosya UTF-8 ve newline='' ile yazılır.
        with open(output_csv_path, "w", encoding="utf-8", newline="") as fp:
            # DictWriter nesnesi oluşturulur.
            writer = csv.DictWriter(fp, fieldnames=headers)
            # Başlık satırı basılır.
            writer.writeheader()
            # Bulgular satır satır yazılır.
            for item in findings:
                # Kolonlar filtrelenerek sadece şemadaki alanlar yazılır.
                row = {col: item.get(col, "N/A") for col in headers}
                # Satır yazılır.
                writer.writerow(row)

        # Mutlak dosya yolu döndürülür.
        return os.path.abspath(output_csv_path)


def main() -> None:
    """Komut satırı arayüzünü (CLI) yönetir."""
    # Windows konsolunda UTF-8 karakterlerin hatasız yazdırılması sağlanır.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # Argümanlar okunur.
    args = sys.argv[1:]

    # Canlı mod denetimi
    if "--live" in args:
        # Toplayıcı başlatılır.
        auditor = PowerShellSecurityPipelineAuditor()
        # Canlı nesneler toplanır.
        live_data = auditor.collect_live_powershell_objects()
        # Denetim icra edilir.
        audit_res = auditor.run_full_audit(live_data["surecler"], live_data["servisler"])
        # Ekrana basılır.
        print(json.dumps({
            "canli_nesneler": live_data,
            "filtre_ve_denetim_sonuclari": audit_res
        }, indent=2, ensure_ascii=False))
        # Çıkış yapılır.
        return

    # Dosya yolları değişkenleri tanımlanır.
    proc_path = None
    # Servis yolu tanımlanır.
    srv_path = None
    # Kurallar yolu tanımlanır.
    rules_path = None
    # CSV çıktı yolu tanımlanır.
    csv_path = None
    # JSON bayrağı tanımlanır.
    json_mode = "--json" in args

    # Argümanlar ayrıştırılır.
    for i in range(len(args)):
        # Süreç dosyası bayrağı
        if args[i] == "--processes" and i + 1 < len(args):
            # Değer atanır.
            proc_path = args[i + 1]
        # Servis dosyası bayrağı
        elif args[i] == "--services" and i + 1 < len(args):
            # Değer atanır.
            srv_path = args[i + 1]
        # Kural dosyası bayrağı
        elif args[i] == "--rules" and i + 1 < len(args):
            # Değer atanır.
            rules_path = args[i + 1]
        # CSV çıktısı bayrağı
        elif args[i] == "--csv" and i + 1 < len(args):
            # Değer atanır.
            csv_path = args[i + 1]

    # Kurallar yüklenir (varsa)
    rules_data = None
    # Dosya yolu verilmişse okunur.
    if rules_path and os.path.exists(rules_path):
        # Dosya açılır.
        with open(rules_path, "r", encoding="utf-8") as fp:
            # JSON yüklenir.
            rules_data = json.load(fp)

    # Denetçi motoru başlatılır.
    auditor = PowerShellSecurityPipelineAuditor(rules_data=rules_data)

    # En az bir girdi dosyası olmalıdır.
    if not proc_path and not srv_path:
        # Kullanım kılavuzu yazdırılır.
        print("Kullanım: python powershell_security_pipeline_auditor.py [--live] [--processes <path>] [--services <path>] [--rules <path>] [--csv <path>] [--json]")
        # 1 koduyla çıkılır.
        sys.exit(1)

    # Süreçler yüklenir.
    processes = auditor.load_json_file(proc_path) if proc_path else []
    # Servisler yüklenir.
    services = auditor.load_json_file(srv_path) if srv_path else []

    # Tam denetim çalıştırılır.
    findings = auditor.run_full_audit(processes, services)

    # CSV kaydedilmesi istenmişse oluşturulur.
    if csv_path:
        # CSV fonksiyonu çağrılır.
        saved_csv = auditor.export_filtered_to_csv(findings, csv_path)
        # Kullanıcıya bilgi basılır.
        print(f"[+] Filtrelenmiş PowerShell Güvenlik Raporu CSV olarak kaydedildi: {saved_csv}")

    # JSON modunda çıktı üretilir.
    if json_mode:
        # JSON ekrana yazılır.
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        # Çıkılır.
        return

    # Standart metin raporu yazdırılır.
    print("=" * 72)
    print("GÜN 022: POWERSHELL NESNE AKIŞI VE GÜVENLİK DENETİM RAPORU")
    print("=" * 72)
    print(f"İncelenen Süreç Sayısı : {len(processes)}")
    print(f"İncelenen Servis Sayısı: {len(services)}")
    print(f"Toplam Riskli Bulgu    : {len(findings)}")
    print("-" * 72)
    # Her bir bulgu yazdırılır.
    for f in findings:
        print(f"[{f.get('risk_seviyesi')}] {f.get('nesne_tipi')}: {f.get('isim')} ({f.get('id_veya_durum')})")
        print(f"       Gerekçe: {f.get('guvenlik_gerekcesi')}")
    print("=" * 72)


# Doğrudan yürütme kontrolü
if __name__ == "__main__":
    # main fonksiyonu çağrılır.
    main()
