# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 05, Gün 031: Process Explorer ve Süreç Ağacı Analiz Motoru.
Bu modül; işletim sistemi süreçlerini PPID-PID ilişkileri üzerinden ağaç grafına
dönüştürür, döngüsel bağımlılıkları tespit eder, meşru karmaşık ağaçlar ile zararlı
süreç zincirlerini (T1059, T1036) bağlamsal olarak ayrıştırır (G031-SC1 & SC2).
"""

# Komut satırı argümanlarını ayrıştırmak için standart kütüphane modülü içe aktarılır.
import argparse
# Zaman damgalarını uluslararası ISO 8601 standardında üretmek için içe aktarılır.
import datetime
# Kriptografik özet (SHA256) hesaplayarak süreç verilerini mühürlemek için içe aktarılır.
import hashlib
# Yapılandırılmış JSON veri dosyalarını okumak ve yazmak için içe aktarılır.
import json
# Dosya sistemi ve dizin varlık kontrollerini yürütmek için içe aktarılır.
import os
# Komut satırı argümanlarında ve ikili yollarda desen aramak için içe aktarılır.
import re
# Standart girdi/çıktı akışlarını ve sistem parametrelerini yönetmek için içe aktarılır.
import sys
# Tip ipuçları ile nesne yönelimli mimarinin güvenliğini pekiştirmek için içe aktarılır.
from typing import Any, Dict, List, Optional, Set, Tuple


# Windows konsollarında Türkçe karakterlerin bozulmasını önlemek için stdout kodlaması yapılandırılır.
if hasattr(sys.stdout, "reconfigure"):
    # Standart çıktı akışı UTF-8 kodlamasına zorlanır ve karakter hataları güvenle ikame edilir.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class ProcessValidationError(Exception):
    """
    Süreç verisinde döngü (cycle), negatif PID veya eksik alan olduğunda fırlatılan istisna.
    Negatif kontrol ve adli veri bütünlüğü doğrulaması için kullanılır.
    """
    # Özel hata mesajını ve hata kodunu saklayan yapıcı fonksiyon.
    def __init__(self, message: str, error_code: str, details: Optional[Dict[str, Any]] = None):
        # Üst sınıf Exception başlatıcısı çağrılır.
        super().__init__(message)
        # Hata kodu nitelik olarak saklanır.
        self.error_code = error_code
        # Detay sözlüğü nitelik olarak atanır.
        self.details = details or {}


class ProcessValidator:
    """
    Süreç listesinin biçimsel doğruluğunu ve döngüsel olmamasını denetleyen sınıf.
    """

    @classmethod
    # Bir süreç listesini baştan sona doğrulayan ve döngüleri tespit eden metod.
    def validate_process_list(cls, processes: List[Dict[str, Any]]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Süreç listesini denetler:
        1. Negatif veya geçersiz PID kontrolü
        2. Eksik süreç adı kontrolü
        3. Mükerrer PID kontrolü
        4. Döngüsel ebeveyn-çocuk ilişkisi (Cycle Detection) kontrolü
        """
        seen_pids: Set[int] = set()
        parent_map: Dict[int, int] = {}

        for p in processes:
            # 1. PID kontrolü
            raw_pid = p.get("pid")
            if raw_pid is None:
                return False, "MISSING_PID", "Süreç ID (PID) alanı eksik!"
            try:
                pid = int(raw_pid)
                if pid < 0:
                    return False, "INVALID_PID", f"Geçersiz negatif PID tespit edildi: {pid}."
            except (ValueError, TypeError):
                return False, "INVALID_PID", f"PID sayısal bir tamsayı olmalıdır: '{raw_pid}'."

            # Mükerrer PID kontrolü
            if pid in seen_pids:
                return False, "DUPLICATE_PID_DETECTED", f"Mükerrer PID çakışması tespit edildi: PID {pid}."
            seen_pids.add(pid)

            # 2. Süreç adı kontrolü
            name = p.get("name")
            if not name or not str(name).strip():
                return False, "MISSING_PROCESS_NAME", f"PID {pid} için süreç adı boş olamaz!"

            # 3. PPID haritası
            raw_ppid = p.get("ppid", 0)
            try:
                ppid = int(raw_ppid)
            except (ValueError, TypeError):
                ppid = 0
            parent_map[pid] = ppid

        # 4. Döngü Tespiti (Cycle Detection)
        for start_pid in parent_map:
            visited_in_path: Set[int] = set()
            curr = start_pid
            while curr in parent_map:
                if curr in visited_in_path:
                    return False, "CIRCULAR_PROCESS_LOOP", f"Döngüsel süreç ilişkisi tespit edildi! PID {curr} döngü oluşturuyor."
                visited_in_path.add(curr)
                curr = parent_map[curr]
                if curr == 0 or curr not in parent_map:
                    break

        return True, None, None


class ProcessTreeNode:
    """
    Süreç ağacındaki her bir düğümü temsil eden nesne yönelimli sınıf.
    """

    # Düğüm başlatıcı fonksiyonu.
    def __init__(self, data: Dict[str, Any]):
        self.pid: int = int(data.get("pid", 0))
        self.ppid: int = int(data.get("ppid", 0))
        self.name: str = str(data.get("name", "Unknown"))
        self.path: str = str(data.get("path", ""))
        self.command_line: str = str(data.get("command_line", ""))
        self.user: str = str(data.get("user", "Unknown"))
        self.is_verified_signature: bool = bool(data.get("is_verified_signature", False))
        self.signer: str = str(data.get("signer", "Unsigned"))
        self.sha256: str = str(data.get("sha256", ""))
        self.children: List["ProcessTreeNode"] = []
        self.anomalies: List[Dict[str, Any]] = []

    # Çocuk süreç ekleme metodu.
    def add_child(self, child: "ProcessTreeNode") -> None:
        """Bu sürece bağlı çocuk süreç ekler."""
        self.children.append(child)


class ProcessTreeBuilder:
    """
    Düz süreç listesinden hiyerarşik süreç ağacı (Process Tree) inşa eden sınıf.
    """

    @classmethod
    # Düz listeyi hiyerarşik kök düğümlere bağlayan metod.
    def build_tree(cls, process_dicts: List[Dict[str, Any]]) -> List[ProcessTreeNode]:
        """Düz listeyi ağaç grafına dönüştürür ve kök düğüm listesini döndürür."""
        node_map: Dict[int, ProcessTreeNode] = {}

        # 1. Adım: Tüm düğümleri oluştur.
        for p in process_dicts:
            node = ProcessTreeNode(p)
            node_map[node.pid] = node

        root_nodes: List[ProcessTreeNode] = []

        # 2. Adım: Ebeveyn-çocuk bağlarını kur.
        for node in node_map.values():
            if node.ppid in node_map and node.ppid != node.pid:
                parent_node = node_map[node.ppid]
                parent_node.add_child(node)
            else:
                # Ebeveyni listede olmayan veya PPID 0 olan kök süreç kabul edilir.
                root_nodes.append(node)

        return root_nodes


class ProcessAnomalyDetector:
    """
    Süreç ağacındaki şüpheli yürütme zincirlerini, taklit (masquerading) girişimlerini
    ve yetkisiz süreç enjeksiyonlarını tespit eden güvenlik analiz motoru.
    G031-SC1 İlkesi: Meşru karmaşık ağaçları tanı ve saldırı zincirlerini izole et.
    """

    # Ofis uygulamaları listesi (Word, Excel, PowerPoint vb.).
    OFFICE_BINARIES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    # Kabuk ve komut yorumlayıcıları.
    SHELL_BINARIES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}

    @classmethod
    # Tek bir süreç ve ebeveyni arasındaki ilişkiyi denetleyen metod.
    def analyze_node(cls, node: ProcessTreeNode, parent: Optional[ProcessTreeNode] = None) -> List[Dict[str, Any]]:
        """Süreç düğümünü güvenlik anomalilerine karşı denetler."""
        anomalies: List[Dict[str, Any]] = []

        # Tehdit 1: Ofis Belgesi Kabuk Başlatma (T1059 / T1204 - Malicious Document Execution)
        if parent and parent.name.lower() in cls.OFFICE_BINARIES:
            if node.name.lower() in cls.SHELL_BINARIES:
                anomalies.append({
                    "type": "OFFICE_SPAWNED_SHELL",
                    "severity": "CRITICAL",
                    "mitre_technique": "T1204.002 / T1059 - Command and Scripting Interpreter",
                    "detail": f"Ofis uygulaması ('{parent.name}', PID {parent.pid}) komut kabuğu ('{node.name}', PID {node.pid}) başlattı!"
                })

        # Tehdit 2: Yanlış Ebeveyn / Süreç Taklidi (T1036.005 - Masquerading)
        # Meşru svchost.exe yalnızca services.exe tarafından başlatılmalıdır!
        if node.name.lower() == "svchost.exe":
            if parent and parent.name.lower() != "services.exe":
                anomalies.append({
                    "type": "INVALID_PARENT_FOR_SVCHOST",
                    "severity": "HIGH",
                    "mitre_technique": "T1036.005 - Masquerading: Match Legitimate Name or Location",
                    "detail": f"svchost.exe meşru ebeveyn 'services.exe' yerine '{parent.name}' (PID {parent.pid}) tarafından başlatılmış!"
                })

        # Tehdit 3: Geçici Dizin veya Kullanıcı Alanından Çalışan Sistem Dosyası
        if node.name.lower() in {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe"}:
            if "temp" in node.path.lower() or "appdata" in node.path.lower():
                anomalies.append({
                    "type": "SUSPICIOUS_SYSTEM_BINARY_PATH",
                    "severity": "CRITICAL",
                    "mitre_technique": "T1036.005 - Masquerading",
                    "detail": f"Kritik sistem ikilisi şüpheli dizinden çalışıyor: '{node.path}'."
                })

        # Tehdit 4: İmzasız Kritik Sistem Süreci
        if node.name.lower() in {"svchost.exe", "lsass.exe", "services.exe"} and not node.is_verified_signature:
            anomalies.append({
                "type": "UNSIGNED_CRITICAL_PROCESS",
                "severity": "HIGH",
                "mitre_technique": "T1036 - Masquerading",
                "detail": f"Kritik sistem süreci '{node.name}' geçerli dijital imzaya sahip değil!"
            })

        # Tehdit 5: Kodlanmış PowerShell Komutu (-enc / -encodedcommand)
        if "powershell" in node.name.lower():
            if re.search(r"-[eE][nN]?[cC]?[oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?", node.command_line):
                anomalies.append({
                    "type": "ENCODED_POWERSHELL_EXECUTION",
                    "severity": "HIGH",
                    "mitre_technique": "T1059.001 - PowerShell Obfuscation",
                    "detail": "PowerShell Base64 kodlanmış gizlenmiş (obfuscated) komut satırı ile çalıştırıldı."
                })

        node.anomalies = anomalies
        return anomalies


class ProcessTreeExplorerAnalyzer:
    """
    Süreç ağacı analiz ve adli denetim motoru.
    Girdileri yükler, hiyerarşik ASCII ağacı çizer ve anomalileri raporlar (G031-SC2).
    """

    def __init__(self):
        self.processes: List[Dict[str, Any]] = []
        self.root_nodes: List[ProcessTreeNode] = []
        self.all_anomalies: List[Dict[str, Any]] = []

    def load_processes_from_json(self, json_path: str) -> List[Dict[str, Any]]:
        """JSON dosyasından süreç envanterini yükler ve doğrular."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_list = data.get("processes", [])
        is_valid, err_code, detail = ProcessValidator.validate_process_list(raw_list)
        if not is_valid:
            raise ProcessValidationError(f"Süreç envanteri doğrulanamadı: {detail}", err_code)

        self.processes = raw_list
        self.root_nodes = ProcessTreeBuilder.build_tree(self.processes)
        self.evaluate_tree_anomalies()
        return self.processes

    def evaluate_tree_anomalies(self) -> List[Dict[str, Any]]:
        """Tüm süreç ağacını özyinelemeli (recursive) olarak tarayarak anomalileri çıkarır."""
        self.all_anomalies = []

        def traverse(node: ProcessTreeNode, parent: Optional[ProcessTreeNode] = None):
            anoms = ProcessAnomalyDetector.analyze_node(node, parent)
            for a in anoms:
                a["pid"] = node.pid
                a["process_name"] = node.name
                self.all_anomalies.append(a)
            for child in node.children:
                traverse(child, node)

        for root in self.root_nodes:
            traverse(root, None)

        return self.all_anomalies

    def generate_ascii_tree(self) -> str:
        """
        Süreç hiyerarşisini güzel bir ASCII ağaç formatında üretir.
        G031-SC2: Örnek süreç ağacını şemalaştır.
        """
        lines: List[str] = []
        lines.append("======================================================================")
        lines.append("PROCESS EXPLORER SÜREÇ AĞACI ŞEMASI (G031-SC2)")
        lines.append("======================================================================")

        def print_subtree(node: ProcessTreeNode, prefix: str = "", is_last: bool = True):
            connector = "└── " if is_last else "├── "
            warn_tag = f" [! TEHDİT: {len(node.anomalies)} Anomali]" if node.anomalies else ""
            signer_tag = f" ({node.signer})" if node.signer else ""
            lines.append(f"{prefix}{connector}[PID: {node.pid:<5}] {node.name} (User: {node.user}){signer_tag}{warn_tag}")

            new_prefix = prefix + ("    " if is_last else "│   ")
            child_count = len(node.children)
            for i, child in enumerate(node.children):
                print_subtree(child, new_prefix, i == (child_count - 1))

        for root in self.root_nodes:
            print_subtree(root, "", True)

        lines.append("======================================================================")
        return "\n".join(lines)

    def test_corrupted_dataset(self, corrupted_json_path: str) -> Dict[str, Any]:
        """Bozuk ve döngüsel süreç test kümesini sınayan negatif kontrol metodu (G031-SC2)."""
        with open(corrupted_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        cases = data.get("corrupted_test_cases", [])
        results: List[Dict[str, Any]] = []
        rejected_count = 0

        for c in cases:
            case_id = c.get("case_id", "CASE-X")
            proc_list = c.get("processes", [])
            expected_err = c.get("expected_error", "")

            is_valid, actual_err, detail = ProcessValidator.validate_process_list(proc_list)
            if not is_valid:
                rejected_count += 1
                matched = (actual_err == expected_err) or (expected_err in str(actual_err))
                results.append({
                    "case_id": case_id,
                    "status": "REJECTED_AS_EXPECTED",
                    "actual_error_code": actual_err,
                    "expected_error_code": expected_err,
                    "rule_matched": matched,
                    "detail": detail
                })
            else:
                results.append({
                    "case_id": case_id,
                    "status": "UNEXPECTEDLY_ACCEPTED",
                    "detail": "Bozuk süreç ağacı doğrulamadan kaçtı!"
                })

        total = len(cases)
        return {
            "total_tested": total,
            "rejected_count": rejected_count,
            "passed": (rejected_count == total),
            "results": results
        }

    def generate_security_audit_report(self) -> str:
        """Detaylı güvenlik analizi ve anomali raporu üretir."""
        lines: List[str] = []
        lines.append("======================================================================")
        lines.append("PROCESS EXPLORER SÜREÇ AĞACI GÜVENLİK DENETİM RAPORU")
        lines.append("======================================================================")
        lines.append(f"Denetim Zamanı (UTC) : {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        lines.append(f"Toplam İncelenen Süreç: {len(self.processes)}")
        lines.append(f"Kök Süreç Sayısı     : {len(self.root_nodes)}")
        lines.append(f"Tespit Edilen Anomali: {len(self.all_anomalies)}")
        lines.append("----------------------------------------------------------------------")
        lines.append("G031-SC1 PRENSİBİ:")
        lines.append("'Ebeveyn-çocuk süreç ilişkisi yürütme zincirine ipucu sağlar fakat")
        lines.append("meşru yazılımlar da karmaşık süreç ağacı üretir (Örn: Chrome çoklu süreçleri).'")
        lines.append("----------------------------------------------------------------------")

        if self.all_anomalies:
            lines.append("TESPİT EDİLEN ŞÜPHELİ YÜRÜTME ZİNCİRLERİ VE ANOMALİLER:")
            for idx, a in enumerate(self.all_anomalies, start=1):
                lines.append(f"\n[BULGU #{idx}] [{a['severity']}] {a['type']} (PID: {a['pid']} - {a['process_name']})")
                lines.append(f"   MITRE ATT&CK : {a['mitre_technique']}")
                lines.append(f"   Açıklama     : {a['detail']}")
        else:
            lines.append("Süreç ağacında herhangi bir güvenlik anomalisi tespit edilmedi.")

        lines.append("\n======================================================================")
        return "\n".join(lines)


def main():
    """CLI giriş noktası."""
    parser = argparse.ArgumentParser(
        description="Gün 031: Process Explorer ve Süreç Ağacı Analiz Motoru."
    )
    parser.add_argument(
        "--inventory",
        type=str,
        default="portfolio/hafta_05/gun_031/ornek_veri/sample_process_inventory.json",
        help="İncelenecek süreç envanteri JSON dosya yolu."
    )
    parser.add_argument(
        "--tree",
        action="store_true",
        help="Süreç hiyerarşisini ASCII ağaç formatında ekrana basar."
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Süreç ağacındaki güvenlik anomalilerini raporlar."
    )
    parser.add_argument(
        "--test-corrupted",
        type=str,
        help="Bozuk/döngüsel süreç ağaçları ile negatif kontrol testi çalıştırır."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Çıktıyı yapılandırılmış JSON formatında basar."
    )

    args = parser.parse_args()
    engine = ProcessTreeExplorerAnalyzer()

    # Negatif kontrol testi istenmişse:
    if args.test_corrupted:
        res = engine.test_corrupted_dataset(args.test_corrupted)
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print("======================================================================")
            print("NEGATİF KONTROL VE DÖNGÜ DOĞRULAMA TESTİ (G031-SC2)")
            print("======================================================================")
            print(f"Toplam Test Edilen Hatalı Vaka : {res['total_tested']}")
            print(f"Başarıyla Reddedilen Vaka      : {res['rejected_count']}")
            print(f"Sonuç                          : {'TAM BAŞARILI (PASS)' if res['passed'] else 'BAŞARISIZ'}")
            print("----------------------------------------------------------------------")
            for item in res["results"]:
                print(f"[{item['status']}] {item['case_id']} -> {item['detail']}")
            print("======================================================================")
        sys.exit(0 if res["passed"] else 1)

    # Süreç envanteri yükleme ve raporlama:
    if os.path.exists(args.inventory):
        engine.load_processes_from_json(args.inventory)

        if args.tree or not args.audit:
            print(engine.generate_ascii_tree())

        if args.audit:
            print(engine.generate_security_audit_report())

        if args.json:
            print(json.dumps({
                "total_processes": len(engine.processes),
                "anomalies": engine.all_anomalies
            }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
