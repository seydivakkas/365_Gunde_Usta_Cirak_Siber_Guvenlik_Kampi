# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 128: MICROSOFT DEFENDER VE GÜVENLİK MERKEZİ CLI YÖNETİM ARACI
-----------------------------------------------------------------
Bu CLI aracı, uç noktalardan toplanan Defender yapılandırma verilerini teftiş eder,
güvenlik duruş puanını hesaplar ve CIS uyumlu PowerShell sertleştirme betikleri üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse modülü
import argparse
# JSON verilerini okumak ve ayrıştırmak için json modülü
import json
# Sistem çıkış kodları için sys modülü
import sys
# Dosya ve yol denetimleri için os modülü
import os

# Kök dizini sys.path'e ekleyerek hem doğrudan hem de paket üzerinden çalışmayı garantiye alıyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from uygulama.windows_defender_engine import (
        WindowsDefenderAuditEngine,
        DefenderPreferences,
        DefenderAuditResult
    )
except ImportError:
    from windows_defender_engine import (
        WindowsDefenderAuditEngine,
        DefenderPreferences,
        DefenderAuditResult
    )


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını inşa eder."""
    # Ana ayrıştırıcıyı yapılandırıyoruz
    parser = argparse.ArgumentParser(
        prog="defender_cli",
        description="Microsoft Defender ve Windows Güvenlik Merkezi CIS Sıkılaştırma Aracı"
    )

    # Alt komut yönetimini etkinleştiriyoruz
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 1. 'audit' alt komutu: JSON girdi dosyasını denetler
    audit_parser = subparsers.add_parser("audit", help="Defender yapılandırma JSON dosyasını denetler")
    # Girdi JSON dosya yolu parametresi
    audit_parser.add_argument("--spec", required=True, help="Defender yapılandırma JSON dosya yolu")
    # Hedef makine adı parametresi
    audit_parser.add_argument("--host", default="LOCAL-WORKSTATION", help="Hedef makine adı")
    # Çıktı formatı (json veya markdown)
    audit_parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Çıktı formatı")

    # 2. 'remediate' alt komutu: PowerShell sıkılaştırma betiği üretir
    rem_parser = subparsers.add_parser("remediate", help="PowerShell sıkılaştırma betiğini ekrana veya dosyaya yazar")
    # Girdi JSON dosya yolu parametresi
    rem_parser.add_argument("--spec", required=True, help="Defender yapılandırma JSON dosya yolu")
    # Hedef makine adı parametresi
    rem_parser.add_argument("--host", default="LOCAL-WORKSTATION", help="Hedef makine adı")
    # Çıktı dosya yolu parametresi (opsiyonel)
    rem_parser.add_argument("--out", help="Betiğin yazılacağı dosya yolu (.ps1)")

    # 3. 'asr-list' alt komutu: Kritik ASR kuralları kataloğunu listeler
    subparsers.add_parser("asr-list", help="CIS ve Microsoft kritik ASR kurallarını ve GUID'lerini listeler")

    # Ayrıştırıcıyı döndürüyoruz
    return parser


def parse_preferences_from_dict(data: dict) -> DefenderPreferences:
    """Sözlük verisini DefenderPreferences nesnesine dönüştürür."""
    # DefenderPreferences nesnesini alanlarla eşleştirerek başlatıyoruz
    return DefenderPreferences(
        disable_realtime_monitoring=data.get("disable_realtime_monitoring", False),
        disable_behavior_monitoring=data.get("disable_behavior_monitoring", False),
        disable_ioav_protection=data.get("disable_ioav_protection", False),
        tamper_protection_active=data.get("tamper_protection_active", False),
        cloud_protection_level=data.get("cloud_protection_level", "Basic"),
        submit_samples_consent=data.get("submit_samples_consent", "SendSafeSamples"),
        pua_protection=data.get("pua_protection", "Disabled"),
        controlled_folder_access=data.get("controlled_folder_access", "Disabled"),
        network_protection=data.get("network_protection", "Disabled"),
        exclusion_paths=data.get("exclusion_paths", []),
        exclusion_extensions=data.get("exclusion_extensions", []),
        exclusion_processes=data.get("exclusion_processes", []),
        asr_rules_map=data.get("asr_rules_map", {})
    )


def main() -> int:
    """CLI giriş noktası fonksiyonu."""
    # Ayrıştırıcıyı oluşturuyoruz
    parser = build_parser()
    # Argümanları ayrıştırıyoruz
    args = parser.parse_args()

    # Alt komut seçilmemişse yardım mesajı gösterip çıkıyoruz
    if not args.command:
        # Yardım metnini yazdırıyoruz
        parser.print_help()
        # Başarılı dönüş kodu
        return 0

    # Denetim motorunu başlatıyoruz
    engine = WindowsDefenderAuditEngine()

    # 'asr-list' komutu çalıştırılmışsa
    if args.command == "asr-list":
        # Başlık yazdırıyoruz
        print("=== MICROSOFT DEFENDER KRİTİK ATTACK SURFACE REDUCTION (ASR) KURALLARI ===")
        # Kuralları tek tek yazdırıyoruz
        for guid, rule_name in engine.CRITICAL_ASR_RULES.items():
            print(f"- [{guid}] -> {rule_name}")
        return 0

    # 'audit' veya 'remediate' komutu için dosya varlığını denetliyoruz
    if not os.path.exists(args.spec):
        # Hata mesajı yazdırıyoruz
        print(f"[!] HATA: Belirtilen spec dosyası bulunamadı: {args.spec}", file=sys.stderr)
        return 1

    # Dosyayı okuyup JSON ayrıştırması yapıyoruz
    with open(args.spec, "r", encoding="utf-8") as f:
        spec_data = json.load(f)

    # Tercih nesnesine dönüştürüyoruz
    prefs = parse_preferences_from_dict(spec_data)

    # Denetimi icra ediyoruz
    result = engine.audit_preferences(target_host=args.host, prefs=prefs)

    # 'audit' alt komutu seçilmişse
    if args.command == "audit":
        if args.format == "markdown":
            # Markdown raporunu üretip yazdırıyoruz
            print(engine.export_markdown_report(result))
        else:
            # JSON formatında yazdırıyoruz
            json_output = {
                "audit_id": result.audit_id,
                "timestamp": result.timestamp,
                "target_host": result.target_host,
                "score": result.defender_security_score,
                "posture": result.posture_status,
                "findings": [
                    {
                        "id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "cwe": f.cwe_id,
                        "mitre": f.mitre_technique_id,
                        "current": str(f.current_value),
                        "recommended": str(f.recommended_value),
                        "powershell": f.powershell_remediation
                    }
                    for f in result.findings
                ]
            }
            print(json.dumps(json_output, indent=2, ensure_ascii=False))
        return 0

    # 'remediate' alt komutu seçilmişse
    elif args.command == "remediate":
        # Çıktı dosyası belirtilmişse dosyaya yazıyoruz
        if args.out:
            with open(args.out, "w", encoding="utf-8") as out_f:
                out_f.write(result.remediation_script)
            print(f"[+] PowerShell sertleştirme betiği kaydedildi: {args.out}")
        else:
            # Ekrana yazdırıyoruz
            print(result.remediation_script)
        return 0

    return 0


# Script doğrudan çalıştırıldığında main() çağrılır
if __name__ == "__main__":
    # Çıkış koduyla programı sonlandırıyoruz
    sys.exit(main())
