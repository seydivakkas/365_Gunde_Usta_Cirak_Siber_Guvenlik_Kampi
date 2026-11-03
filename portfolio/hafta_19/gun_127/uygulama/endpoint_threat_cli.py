# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 127: UÇ NOKTA TEHDİT MODELLEME CLI YÖNETİM ARACI
---------------------------------------------------
Bu komut satırı aracı; Windows veya Linux uç noktalarının güvenlik şartnamesini
ayrıştırır, MITRE ATT&CK ve CWE eşleşmelerini çıkarır ve sıkılaştırma
raporunu konsola veya dosyaya sunar.
"""

# Komut satırı argümanları için argparse modülü
import argparse
# Sistem çıkışları ve parametreler için sys modülü
import sys
# Dosya varlık denetimleri için os modülü
import os
# JSON verilerini okumak ve yazmak için json modülü
import json
# Tip ipuçları için typing modülü
from typing import Optional, List, Dict, Any

# Çekirdek motor sınıflarını içe aktarıyoruz
from endpoint_threat_model_engine import (
    EndpointThreatModelEngine,
    OperatingSystemFamily,
    EndpointRole,
    EndpointControlStatus,
    EndpointThreatModelError
)


def load_endpoint_spec(file_path: str) -> Dict[str, Any]:
    """JSON dosyasından uç nokta şartnamesini yükler."""
    # Dosya var mı kontrol ediyoruz
    if not os.path.exists(file_path):
        # Dosya bulunamazsa hata fırlatıyoruz
        raise FileNotFoundError(f"Uç nokta şartname dosyası bulunamadı: {file_path}")
    # Dosyayı okuma modunda açıyoruz
    with open(file_path, "r", encoding="utf-8") as fp:
        # JSON verisini sözlük olarak döndürüyoruz
        return json.load(fp)


def parse_controls_from_dict(raw: Dict[str, Any]) -> EndpointControlStatus:
    """Sözlükten EndpointControlStatus nesnesini inşa eder."""
    # Kontrol durumunu başlatıyoruz
    return EndpointControlStatus(
        edr_active=bool(raw.get("edr_active", False)),
        tamper_protection_active=bool(raw.get("tamper_protection_active", False)),
        telemetry_active=bool(raw.get("telemetry_active", False)),
        credential_guard_active=bool(raw.get("credential_guard_active", False)),
        disk_encryption_active=bool(raw.get("disk_encryption_active", False)),
        strict_uac_active=bool(raw.get("strict_uac_active", False)),
        app_whitelisting_active=bool(raw.get("app_whitelisting_active", False)),
        powershell_clm_active=bool(raw.get("powershell_clm_active", False)),
        unquoted_service_paths_count=int(raw.get("unquoted_service_paths_count", 0)),
        suid_misconfigurations_count=int(raw.get("suid_misconfigurations_count", 0)),
        insecure_open_ports=list(raw.get("insecure_open_ports", [])),
        weak_registry_autoruns_count=int(raw.get("weak_registry_autoruns_count", 0))
    )


def handle_model(args: argparse.Namespace) -> int:
    """Uç nokta şartnamesini modelleyip tehdit analizini üretir."""
    try:
        # Şartname dosyasını yüklüyoruz
        data = load_endpoint_spec(args.spec_file)

        # İşletim sistemi ailesini çözümlüyoruz
        os_str = data.get("os_family", "WINDOWS").upper()
        # Enum karşılığını alıyoruz
        os_family = OperatingSystemFamily[os_str] if os_str in OperatingSystemFamily.__members__ else OperatingSystemFamily.WINDOWS

        # Uç nokta rolünü çözümlüyoruz
        role_str = data.get("role", "WORKSTATION").upper()
        # Enum karşılığını alıyoruz
        role = EndpointRole[role_str] if role_str in EndpointRole.__members__ else EndpointRole.WORKSTATION

        # Kontrolleri ayrıştırıyoruz
        controls = parse_controls_from_dict(data.get("kontroller", {}))

        # Motoru başlatıyoruz
        engine = EndpointThreatModelEngine()
        # Tehdit modelini çıkarıyoruz
        report = engine.model_endpoint_threats(
            endpoint_name=data.get("endpoint_name", "Hedef-Uç-Nokta"),
            os_family=os_family,
            role=role,
            controls=controls
        )

        # İstenen formata göre yazdırıyoruz
        if args.format == "markdown":
            # Markdown çıktısını basıyoruz
            print(engine.export_markdown_report(report))
        else:
            # JSON sözlüğünü hazırlıyoruz
            json_out = {
                "report_id": report.report_id,
                "timestamp": report.timestamp,
                "endpoint_name": report.endpoint_name,
                "os_family": report.os_family.value,
                "role": report.role.value,
                "threat_index_score": report.threat_index_score,
                "security_posture_level": report.security_posture_level,
                "threats_count": len(report.findings),
                "threats": [
                    {
                        "id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "surface": f.surface_area.value,
                        "cwe": f.cwe_id,
                        "mitre": f.mitre_technique_id,
                        "remediation": f.remediation
                    }
                    for f in report.findings
                ],
                "roadmap": report.hardening_roadmap
            }
            # Konsola yazdırıyoruz
            print(json.dumps(json_out, ensure_ascii=False, indent=2))

        # Tehdit endeksi 50'nin altındaysa 0, üstündeyse 2 döndürüyoruz
        return 0 if report.threat_index_score < 50.0 else 2

    except Exception as exc:
        # Hata durumunu ekrana yazdırıyoruz
        print(f"[-] MODELLEME HATASI: {exc}", file=sys.stderr)
        # Hata kodu 1 döndürüyoruz
        return 1


def handle_quick_check(args: argparse.Namespace) -> int:
    """Hızlı parametre kontrolü yapar."""
    # Motoru başlatıyoruz
    engine = EndpointThreatModelEngine()
    # İşletim sistemini alıyoruz
    os_fam = OperatingSystemFamily[args.os.upper()]
    # Rolü alıyoruz
    ep_role = EndpointRole[args.role.upper()]
    # Kontrolleri kuruyoruz
    controls = EndpointControlStatus(
        edr_active=args.edr,
        tamper_protection_active=args.tamper_protection,
        credential_guard_active=args.credential_guard,
        disk_encryption_active=args.disk_encryption,
        unquoted_service_paths_count=args.unquoted_paths
    )
    # Analizi yürütüyoruz
    report = engine.model_endpoint_threats(args.name, os_fam, ep_role, controls)
    # Özet bilgileri ekrana basıyoruz
    print("=== Hızlı Uç Nokta Tehdit Taraması ===")
    print(f"Cihaz: {report.endpoint_name} ({report.os_family.value} - {report.role.value})")
    print(f"Tehdit Endeksi: {report.threat_index_score} / 100")
    print(f"Duruş Seviyesi: {report.security_posture_level}")
    print(f"Bulgu Sayısı: {len(report.findings)}")
    # Bulguları listeliyoruz
    for f in report.findings:
        print(f"  - [{f.severity.value}] {f.title} ({f.cwe_id} / {f.mitre_technique_id})")
    # Çıkış kodu döndürüyoruz
    return 0 if report.threat_index_score < 50.0 else 2


def main(argv: Optional[List[str]] = None) -> None:
    """Komut satırı ana giriş noktası."""
    # Ana ayrıştırıcıyı kuruyoruz
    parser = argparse.ArgumentParser(description="Gün 127: Uç Nokta Tehdit Modelleme CLI Aracı")
    # Alt komutları tanımlıyoruz
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'model' komutu
    model_parser = subparsers.add_parser("model", help="Şartname dosyasını modelle")
    model_parser.add_argument("spec_file", help="Uç nokta JSON şartname dosya yolu")
    model_parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Çıktı formatı")

    # 2. 'quick-check' komutu
    quick_parser = subparsers.add_parser("quick-check", help="Hızlı parametrik denetim yap")
    quick_parser.add_argument("--name", default="HızlıTest-PC", help="Uç nokta adı")
    quick_parser.add_argument("--os", choices=["WINDOWS", "LINUX", "MACOS"], default="WINDOWS", help="İşletim sistemi")
    quick_parser.add_argument("--role", choices=["WORKSTATION", "APPLICATION_SERVER", "DATABASE_SERVER", "DOMAIN_CONTROLLER", "BASTION_HOST"], default="WORKSTATION", help="Uç nokta rolü")
    quick_parser.add_argument("--edr", action="store_true", help="EDR aktif mi?")
    quick_parser.add_argument("--tamper-protection", action="store_true", help="Tamper protection aktif mi?")
    quick_parser.add_argument("--credential-guard", action="store_true", help="Credential Guard aktif mi?")
    quick_parser.add_argument("--disk-encryption", action="store_true", help="Disk şifreleme aktif mi?")
    quick_parser.add_argument("--unquoted-paths", type=int, default=0, help="Tırnaksız servis yolu sayısı")

    # Argümanları ayrıştırıyoruz
    args = parser.parse_args(argv)

    # İlgili işleyiciyi çalıştırıyoruz
    if args.command == "model":
        sys.exit(handle_model(args))
    elif args.command == "quick-check":
        sys.exit(handle_quick_check(args))
    else:
        parser.print_help()
        sys.exit(1)


# Doğrudan çalıştırıldığında main çağrılır
if __name__ == "__main__":
    main()
