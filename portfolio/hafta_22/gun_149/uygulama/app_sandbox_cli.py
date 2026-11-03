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
from typing import Any, Dict

# Uygulama motorundan veri sınıfları ve motor bileşenleri içe aktarılır
from app_sandbox_engine import (
    AppSandboxEngine,
    SandboxProfile,
    SeccompAction,
    WindowsIntegrityLevel,
    NetworkIsolationMode,
    ResourceLimits,
    OciSeccompGenerator,
    SandboxRemediationGenerator
)


def load_profile_from_json(json_path: str) -> SandboxProfile:
    """JSON dosyasından SandboxProfile veri modelini ayrıştırır ve yükler."""
    # Dosya yolu Path nesnesine dönüştürülür
    p = Path(json_path)
    # Dosyanın varlığı kontrol edilir
    if not p.exists():
        # Dosya yoksa hata fırlatılır
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {json_path}")

    # Dosya UTF-8 olarak açılır ve JSON içeriği okunur
    with open(p, "r", encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)

    # ResourceLimits nesnesi oluşturulur
    rsrc_dict = data.get("resource_limits", {})
    # Kaynak limitleri nesnesi başlatılır
    rlimits = ResourceLimits(
        max_memory_mb=rsrc_dict.get("max_memory_mb", 512),
        max_pids=rsrc_dict.get("max_pids", 64),
        cpu_quota_pct=rsrc_dict.get("cpu_quota_pct", 50),
        max_file_size_mb=rsrc_dict.get("max_file_size_mb", 100)
    )

    # Seccomp bloklanan çağrılar ayrıştırılır
    raw_blocked = data.get("blocked_syscalls", {})
    # Eylem eşleştirmesi yapılır
    blocked_syscalls = {
        sc: SeccompAction(act) for sc, act in raw_blocked.items()
    }

    # Profil nesnesi inşa edilir
    profile = SandboxProfile(
        profile_name=data.get("profile_name", "custom_sandbox"),
        os_family=data.get("os_family", "linux"),
        default_seccomp_action=SeccompAction(data.get("default_seccomp_action", "SCMP_ACT_ERRNO")),
        allowed_syscalls=set(data.get("allowed_syscalls", [])),
        blocked_syscalls=blocked_syscalls,
        granted_capabilities=set(data.get("granted_capabilities", [])),
        read_only_root_fs=data.get("read_only_root_fs", True),
        masked_paths=data.get("masked_paths", []),
        network_mode=NetworkIsolationMode(data.get("network_mode", "DISCONNECTED")),
        resource_limits=rlimits,
        windows_integrity_level=WindowsIntegrityLevel(data.get("windows_integrity_level", "LOW")),
        windows_app_container=data.get("windows_app_container", True),
        disabled_windows_privileges=data.get("disabled_windows_privileges", [])
    )
    # Oluşturulan profil geri döndürülür
    return profile


def handle_audit(args: argparse.Namespace) -> int:
    """Sandbox profili üzerinde güvenlik denetimi gerçekleştirir."""
    # Profil dosyası yüklenir
    profile = load_profile_from_json(args.config)
    # Motor başlatılır
    engine = AppSandboxEngine(profile)
    # Denetim koşturulur
    findings = engine.audit_sandbox_security()

    # Başlık yazdırılır
    print("=" * 78)
    print(f"[*] SANDBOX GÜVENLİK DENETİM RAPORU: {profile.profile_name}")
    print(f"[*] İşletim Sistemi: {profile.os_family.upper()} | Ağ Modu: {profile.network_mode.value}")
    print("=" * 78)

    # Bulgu yoksa tebrik mesajı yazdırılır
    if not findings:
        print("[+] TEBRİKLER: Profil tam uyumlu, hiçbir güvenlik zafiyeti tespit edilmedi (100/100).")
        return 0

    # Bulgular döngüyle ekrana dökülür
    for idx, f in enumerate(findings, 1):
        print(f"[{idx}] [{f.severity}] {f.rule_id} - {f.title}")
        print(f"    Standart  : {f.compliance_ref}")
        print(f"    Açıklama  : {f.description}")
        print(f"    Düzeltme  : {f.remediation_step}")
        print("-" * 78)

    # Toplam bulgu sayısı raporlanır
    print(f"[-] Toplam Tespit Edilen Zafiyet/Sapma Sayısı: {len(findings)}")
    # Hata kodu olarak bulgu sayısı döndürülür
    return len(findings)


def handle_simulate(args: argparse.Namespace) -> int:
    """Sandbox içinde bir işlem simülasyonu koşturur."""
    # Profil yüklenir
    profile = load_profile_from_json(args.config)
    # Motor başlatılır
    engine = AppSandboxEngine(profile)

    # Ek bağlam hazırlanır
    context = {}
    if args.action == "filesystem" and args.fs_mode:
        context["mode"] = args.fs_mode
    if args.action == "process_fork" and args.current_pids:
        context["current_pids"] = int(args.current_pids)

    # Simülasyon icra edilir
    result = engine.simulate_execution(args.action, args.target, context)

    # Sonuç ekrana basılır
    print("=" * 78)
    print(f"[*] SANDBOX İŞLEM SİMÜLASYONU: {result.action_name}")
    print("=" * 78)
    print(f"Durum           : {'İZİN VERİLDİ (ALLOWED)' if result.allowed else 'ENGELLENDİ (BLOCKED)'}")
    print(f"Denetleyen Katman: {result.enforcing_layer}")
    print(f"Karar Kodu      : {result.verdict}")
    print(f"Detay           : {result.detail}")
    print("=" * 78)

    # İzin verilmişse 0, engellenmişse 1 döndürülür
    return 0 if result.allowed else 1


def handle_export_oci(args: argparse.Namespace) -> int:
    """OCI uyumlu Seccomp-BPF JSON profili üretir."""
    # Profil yüklenir
    profile = load_profile_from_json(args.config)
    # OCI dokümanı oluşturulur
    oci_doc = OciSeccompGenerator.generate_oci_seccomp_profile(profile)

    # Çıktı yolu belirlenir
    out_path = Path(args.output) if args.output else Path(f"{profile.profile_name}_seccomp.json")
    # Dosyaya yazılır
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(oci_doc, f, indent=2, ensure_ascii=False)

    print(f"[+] OCI Seccomp JSON profili başarıyla dışa aktarıldı: {out_path}")
    return 0


def handle_generate_remediation(args: argparse.Namespace) -> int:
    """Sertleştirme betiği üretir."""
    # Profil yüklenir
    profile = load_profile_from_json(args.config)

    # Hedef OS seçilir
    if args.os_type == "windows":
        script_content = SandboxRemediationGenerator.generate_windows_powershell_hardening_script(profile)
        ext = "ps1"
    else:
        script_content = SandboxRemediationGenerator.generate_linux_hardening_script(profile)
        ext = "sh"

    # Çıktı yolu
    out_path = Path(args.output) if args.output else Path(f"sandbox_hardening.{ext}")
    # Dosyaya kaydedilir
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(script_content)

    print(f"[+] {args.os_type.upper()} sertleştirme betiği başarıyla üretildi: {out_path}")
    return 0


def main() -> None:
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    # Ana argüman ayrıştırıcı oluşturulur
    parser = argparse.ArgumentParser(
        description="Uygulama İzinleri ve Sandbox Güvenlik Yönetim Aracı (Usta-Çırak Serisi Gün 149)"
    )
    # Alt komut ayrıştırıcıları eklenir
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Denetim alt komutu
    p_audit = subparsers.add_parser("audit", help="Sandbox yapılandırmasını güvenlik standartlarına göre denetler")
    p_audit.add_argument("--config", "-c", required=True, help="Sandbox JSON profil dosyası yolu")
    p_audit.set_defaults(func=handle_audit)

    # 2. Simülasyon alt komutu
    p_sim = subparsers.add_parser("simulate", help="Sandbox içinde operasyonel eylem simülasyonu yapar")
    p_sim.add_argument("--config", "-c", required=True, help="Sandbox JSON profil dosyası yolu")
    p_sim.add_argument("--action", "-a", required=True, choices=["syscall", "capability", "filesystem", "network", "process_fork"], help="Eylem türü")
    p_sim.add_argument("--target", "-t", required=True, help="Hedef sistem çağrısı, yetenek, dosya yolu veya IP adresi")
    p_sim.add_argument("--fs-mode", choices=["read", "write"], default="read", help="Dosya sistemi erişim türü")
    p_sim.add_argument("--current-pids", type=int, default=1, help="Mevcut süreç sayısı")
    p_sim.set_defaults(func=handle_simulate)

    # 3. OCI Dışa Aktarma alt komutu
    p_oci = subparsers.add_parser("export-oci", help="OCI Seccomp-BPF JSON profili oluşturur")
    p_oci.add_argument("--config", "-c", required=True, help="Sandbox JSON profil dosyası yolu")
    p_oci.add_argument("--output", "-o", help="Çıktı JSON dosya yolu")
    p_oci.set_defaults(func=handle_export_oci)

    # 4. Sertleştirme Betiği Üretme alt komutu
    p_rem = subparsers.add_parser("generate-remediation", help="Sertleştirme betiği (PowerShell/Bash) üretir")
    p_rem.add_argument("--config", "-c", required=True, help="Sandbox JSON profil dosyası yolu")
    p_rem.add_argument("--os-type", choices=["linux", "windows"], default="linux", help="Hedef işletim sistemi")
    p_rem.add_argument("--output", "-o", help="Çıktı betik dosyası yolu")
    p_rem.set_defaults(func=handle_generate_remediation)

    # Argümanlar ayrıştırılır
    args = parser.parse_args()
    # İlgili işleyici çağrılır ve çıkış kodu döndürülür
    exit_code = args.func(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
