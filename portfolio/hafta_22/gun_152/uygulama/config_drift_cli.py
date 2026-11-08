"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli sistem ve argüman ayrıştırma kütüphaneleri içe aktarılır
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Motor sınıfları ve modelleri içe aktarılır
from config_drift_engine import (
    ConfigDriftAuditor,
    AutoRemediationEngine,
    ConfigRule,
    SettingType,
    SeverityLevel,
    AuditReport
)


def load_baseline_and_state(config_path: str) -> Tuple[List[ConfigRule], Dict[str, Any], str]:
    """JSON dosyasından temel hat kurallarını ve uç nokta durumunu yükler."""
    p = Path(config_path)
    if not p.exists():
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {config_path}")

    with open(p, "r", encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)

    endpoint_id = data.get("endpoint_id", "ENDPOINT-WIN11-SEC01")
    raw_rules = data.get("baseline_rules", [])

    rules: List[ConfigRule] = []
    for r in raw_rules:
        rule = ConfigRule(
            rule_id=r["rule_id"],
            setting_type=SettingType(r["setting_type"]),
            target_key=r["target_key"],
            expected_value=r["expected_value"],
            severity=SeverityLevel(r["severity"]),
            title=r["title"],
            compliance_ref=r.get("compliance_ref", "CIS Benchmark"),
            description=r.get("description", ""),
            remediation_cmd_ps1=r.get("remediation_cmd_ps1", ""),
            remediation_cmd_bash=r.get("remediation_cmd_bash", "")
        )
        rules.append(rule)

    actual_state = data.get("actual_state", {})
    return rules, actual_state, endpoint_id


def handle_audit(args: argparse.Namespace) -> int:
    """Uç nokta konfigürasyon sapmasını denetler."""
    rules, state, endpoint_id = load_baseline_and_state(args.config)
    auditor = ConfigDriftAuditor(rules)
    report = auditor.evaluate_endpoint_state(endpoint_id, state)

    print("=" * 78)
    print(f"[*] GÜVENLİ YAPILANDIRMA SAPMA DENETİMİ: {report.endpoint_identifier}")
    print(f"[*] Zaman: {report.timestamp_utc}")
    print(f"[*] Toplam Değerlendirilen Kural : {report.total_evaluated}")
    print(f"[*] Uyumlu Kural Sayısı         : {report.total_compliant}")
    print(f"[*] Sapma Tespit Edilen Kural   : {report.total_drifted}")
    print(f"[*] UYUMLULUK SKORU             : %{report.compliance_score_pct}")
    print("=" * 78)

    if not report.findings:
        print("[+] TEBRİKLER: Sistem temel hat ile %100 uyumludur. Hiçbir sapma tespit edilmedi.")
        return 0

    for idx, f in enumerate(report.findings, 1):
        print(f"[{idx}] [{f.severity}] {f.rule_id} - {f.title}")
        print(f"    Hedef Yol     : {f.target_key}")
        print(f"    Beklenen Değer: {f.expected_value}")
        print(f"    Gerçek Değer  : {f.actual_value}")
        print(f"    Risk          : {f.risk_description}")
        print(f"    Düzeltme      : {f.remediation_command}")
        print("-" * 78)

    print(f"[-] Toplam Tespit Edilen Sapma Sayısı: {len(report.findings)}")
    return len(report.findings)


def handle_remediate(args: argparse.Namespace) -> int:
    """Sapmış ayarları otomatik olarak temel hat değerlerine geri döndürür."""
    rules, state, endpoint_id = load_baseline_and_state(args.config)
    remediated_state = AutoRemediationEngine.remediate_state(state, rules)

    out_path = Path(args.output) if args.output else Path(f"{endpoint_id}_remediated.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(remediated_state, f, indent=2, ensure_ascii=False)

    print(f"[+] Uç nokta durumu başarıyla temel hata döndürüldü ve kaydedildi: {out_path}")
    return 0


def handle_generate_remediation(args: argparse.Namespace) -> int:
    """Düzeltme betiği üretir."""
    rules, state, endpoint_id = load_baseline_and_state(args.config)
    auditor = ConfigDriftAuditor(rules)
    report = auditor.evaluate_endpoint_state(endpoint_id, state)

    if args.os_type == "windows":
        script_content = AutoRemediationEngine.generate_powershell_remediation_script(report.findings)
        ext = "ps1"
    else:
        script_content = AutoRemediationEngine.generate_bash_remediation_script(report.findings)
        ext = "sh"

    out_path = Path(args.output) if args.output else Path(f"config_remediation.{ext}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(script_content)

    print(f"[+] {args.os_type.upper()} otomatik düzeltme betiği üretildi: {out_path}")
    return 0


def main() -> None:
    """CLI giriş noktası ve komut yöneticisi."""
    parser = argparse.ArgumentParser(
        description="Güvenli Yapılandırma Sapması (Configuration Drift) ve Otomatik Düzeltme Aracı (Usta-Çırak Gün 152)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Denetim
    p_audit = subparsers.add_parser("audit", help="Uç nokta konfigürasyon sapmasını denetler")
    p_audit.add_argument("--config", "-c", required=True, help="Temel hat ve durum JSON dosya yolu")
    p_audit.set_defaults(func=handle_audit)

    # 2. Durumu İyileştirme (State Remediation)
    p_rem = subparsers.add_parser("remediate", help="Sapmış değerleri temel hata döndürür")
    p_rem.add_argument("--config", "-c", required=True, help="Temel hat ve durum JSON dosya yolu")
    p_rem.add_argument("--output", "-o", help="İyileştirilmiş JSON çıktı yolu")
    p_rem.set_defaults(func=handle_remediate)

    # 3. Betik Üretme
    p_gen = subparsers.add_parser("generate-remediation", help="PowerShell veya Bash düzeltme betiği üretir")
    p_gen.add_argument("--config", "-c", required=True, help="Temel hat ve durum JSON dosya yolu")
    p_gen.add_argument("--os-type", choices=["windows", "linux"], default="windows", help="İşletim sistemi türü")
    p_gen.add_argument("--output", "-o", help="Çıktı betik yolu")
    p_gen.set_defaults(func=handle_generate_remediation)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
