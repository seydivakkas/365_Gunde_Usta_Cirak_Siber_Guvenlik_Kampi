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
from backup_recovery_engine import (
    BackupRecoveryEngine,
    BackupPolicy,
    BackupArtifact,
    StorageMediaType,
    ImmutabilityMode,
    BackupType,
    RansomwareAttackSimulator,
    BackupHardeningRemediationGenerator
)


def load_spec_from_json(json_path: str) -> Tuple[BackupPolicy, List[BackupArtifact]]:
    """JSON dosyasından politika ve yedek arşivleri listesini ayrıştırır."""
    p = Path(json_path)
    if not p.exists():
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {json_path}")

    with open(p, "r", encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)

    # Politika nesnesi oluşturulur
    pol_data = data.get("policy", {})
    policy = BackupPolicy(
        policy_name=pol_data.get("policy_name", "Standard_Backup_Policy"),
        target_rpo_minutes=pol_data.get("target_rpo_minutes", 60),
        target_rto_minutes=pol_data.get("target_rto_minutes", 120),
        required_min_copies=pol_data.get("required_min_copies", 3),
        required_min_media_types=pol_data.get("required_min_media_types", 2),
        require_offsite_copy=pol_data.get("require_offsite_copy", True),
        require_immutable_copy=pol_data.get("require_immutable_copy", True),
        max_verification_interval_days=pol_data.get("max_verification_interval_days", 30),
        enforce_vss_hardening=pol_data.get("enforce_vss_hardening", True)
    )

    # Yedek arşivleri yüklenir
    artifacts: List[BackupArtifact] = []
    for item in data.get("artifacts", []):
        art = BackupArtifact(
            backup_id=item["backup_id"],
            created_at_utc=item["created_at_utc"],
            backup_type=BackupType(item.get("backup_type", "FULL")),
            media_type=StorageMediaType(item.get("media_type", "LOCAL_NVME")),
            is_offsite=item.get("is_offsite", False),
            is_air_gapped=item.get("is_air_gapped", False),
            immutability_mode=ImmutabilityMode(item.get("immutability_mode", "NONE")),
            retention_expiry_utc=item.get("retention_expiry_utc"),
            size_mb=item.get("size_mb", 1000),
            sha256_checksum=item.get("sha256_checksum", "0" * 64),
            is_corrupted=item.get("is_corrupted", False),
            vss_shadow_protected=item.get("vss_shadow_protected", True),
            last_verified_at_utc=item.get("last_verified_at_utc")
        )
        artifacts.append(art)

    return policy, artifacts


def handle_audit(args: argparse.Namespace) -> int:
    """Yedekleme mimarisini güvenlik ve SLA standartlarına göre denetler."""
    policy, artifacts = load_spec_from_json(args.config)
    engine = BackupRecoveryEngine(policy, artifacts)
    findings = engine.audit_backup_architecture()

    print("=" * 78)
    print(f"[*] YEDEK DOĞRULAMA VE KURTARMA DENETİMİ: {policy.policy_name}")
    print(f"[*] Hedef RPO: {policy.target_rpo_minutes} dk | Hedef RTO: {policy.target_rto_minutes} dk")
    print(f"[*] Toplam Mevcut Yedek Kopyası Sayısı: {len(artifacts)}")
    print("=" * 78)

    if not findings:
        print("[+] TEBRİKLER: Yedekleme mimarisi 3-2-1 ve WORM standartlarıyla tam uyumlu (100/100).")
        return 0

    for idx, f in enumerate(findings, 1):
        print(f"[{idx}] [{f.severity}] {f.rule_id} - {f.title}")
        print(f"    Standart  : {f.compliance_ref}")
        print(f"    Açıklama  : {f.description}")
        print(f"    Düzeltme  : {f.remediation_step}")
        print("-" * 78)

    print(f"[-] Toplam Tespit Edilen Zafiyet/Sapma Sayısı: {len(findings)}")
    return len(findings)


def handle_simulate_restore(args: argparse.Namespace) -> int:
    """Felaket anında en güncel geçerli yedekten geri yükleme simülasyonu yapar."""
    policy, artifacts = load_spec_from_json(args.config)
    engine = BackupRecoveryEngine(policy, artifacts)
    result = engine.simulate_recovery(args.disaster_time)

    print("=" * 78)
    print(f"[*] YEDEK GERİ YÜKLEME SİMÜLASYONU ({result.simulation_id})")
    print("=" * 78)
    print(f"Durum              : {result.status}")
    print(f"Başarılı mı?       : {'EVET (BAŞARILI)' if result.success else 'HAYIR (BAŞARISIZ)'}")
    print(f"Gerçekleşen RPO    : {result.actual_rpo_minutes} dakika (Hedef: {policy.target_rpo_minutes} dk -> {'UYUMLU' if result.rpo_compliant else 'İHLAL'})")
    print(f"Gerçekleşen RTO    : {result.actual_rto_minutes} dakika (Hedef: {policy.target_rto_minutes} dk -> {'UYUMLU' if result.rto_compliant else 'İHLAL'})")
    print(f"Sağlama Toplamı    : {'DOĞRULANDI (SHA-256 GEÇERLİ)' if result.checksum_verified else 'GEÇERSİZ/BOZUK'}")
    print(f"Detay              : {result.detail}")
    print("=" * 78)

    return 0 if result.success and result.rpo_compliant and result.rto_compliant else 1


def handle_simulate_ransomware(args: argparse.Namespace) -> int:
    """Fidye yazılımı saldırısı simülasyonu koşturur."""
    policy, artifacts = load_spec_from_json(args.config)
    surviving, summary = RansomwareAttackSimulator.simulate_attack(artifacts)

    print("=" * 78)
    print("[*] FİDYE YAZILIMI (RANSOMWARE) YEDEK İMHA SİMÜLASYONU")
    print("=" * 78)
    print(f"Saldırı Öncesi Toplam Yedek : {summary['total_before_attack']}")
    print(f"İmha Edilen / Silinen Yedek : {summary['destroyed_backups']}")
    print(f"Hayatta Kalan (WORM/Airgap) : {summary['surviving_backups']}")
    print(f"Saldırıya Karşı Direnildi mi: {'EVET (WORM KORUDU)' if summary['ransomware_wipeout_resisted'] else 'HAYIR (TÜM YEDEKLER YOK OLDU!)'}")
    print("-" * 78)
    print("Saldırı Olay Günlüğü:")
    for log in summary["attack_log"]:
        print(f"  {log}")
    print("=" * 78)

    return 0 if summary["ransomware_wipeout_resisted"] else 1


def handle_generate_remediation(args: argparse.Namespace) -> int:
    """Sertleştirme betiği üretir."""
    if args.os_type == "windows":
        content = BackupHardeningRemediationGenerator.generate_windows_vss_and_backup_hardening_script()
        ext = "ps1"
    else:
        content = BackupHardeningRemediationGenerator.generate_linux_immutable_backup_script(args.bucket)
        ext = "sh"

    out_path = Path(args.output) if args.output else Path(f"backup_hardening.{ext}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[+] {args.os_type.upper()} sertleştirme betiği başarıyla üretildi: {out_path}")
    return 0


def main() -> None:
    """CLI giriş noktası ve alt komut yöneticisi."""
    parser = argparse.ArgumentParser(
        description="Yedek Doğrulama ve Kurtarma Noktası Yönetim Aracı (Usta-Çırak Serisi Gün 151)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Denetim
    p_audit = subparsers.add_parser("audit", help="Yedekleme mimarisini 3-2-1 ve WORM standartlarına göre denetler")
    p_audit.add_argument("--config", "-c", required=True, help="Yapılandırma JSON dosyası yolu")
    p_audit.set_defaults(func=handle_audit)

    # 2. Geri Yükleme Simülasyonu
    p_rest = subparsers.add_parser("simulate-restore", help="Geri yükleme ve RPO/RTO SLA simülasyonu yapar")
    p_rest.add_argument("--config", "-c", required=True, help="Yapılandırma JSON dosyası yolu")
    p_rest.add_argument("--disaster-time", help="Simüle edilen felaket zamanı (ISO formatı UTC)")
    p_rest.set_defaults(func=handle_simulate_restore)

    # 3. Fidye Yazılımı Simülasyonu
    p_rw = subparsers.add_parser("simulate-ransomware", help="Fidye yazılımı yedek silme saldırısını simüle eder")
    p_rw.add_argument("--config", "-c", required=True, help="Yapılandırma JSON dosyası yolu")
    p_rw.set_defaults(func=handle_simulate_ransomware)

    # 4. Sertleştirme Betiği Üretimi
    p_rem = subparsers.add_parser("generate-remediation", help="Sertleştirme komut dosyası üretir")
    p_rem.add_argument("--os-type", choices=["windows", "linux"], default="windows", help="İşletim sistemi türü")
    p_rem.add_argument("--bucket", default="enterprise-immutable-backups", help="S3 bucket adı")
    p_rem.add_argument("--output", "-o", help="Çıktı dosya yolu")
    p_rem.set_defaults(func=handle_generate_remediation)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
