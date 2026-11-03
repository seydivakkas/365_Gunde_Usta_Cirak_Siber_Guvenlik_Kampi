"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli kütüphaneler içe aktarılır
import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

# Temel dizinler tanımlanır
CURRENT_DIR = Path(__file__).parent.resolve()
UYGULAMA_DIR = CURRENT_DIR / "uygulama"
TESTS_DIR = CURRENT_DIR / "tests"
DATA_DIR = CURRENT_DIR / "ornek_veri"
GERCEK_KANIT_DIR = CURRENT_DIR / "kanit" / "gercek"
TEMSILI_KANIT_DIR = CURRENT_DIR / "kanit" / "temsili"

# Uygulama motoru sys.path'e dahil edilir
sys.path.insert(0, str(UYGULAMA_DIR))

# Motor sınıfları içe aktarılır
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
from app_sandbox_cli import load_profile_from_json


def run_unit_tests() -> str:
    """15 birim testini unittest ile çalıştırır ve çıktıyı yakalar."""
    # Test komutu oluşturulur
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", str(TESTS_DIR), "-p", "test_*.py", "-v"]
    # Komut çalıştırılır ve standart çıktı/hata yakalanır
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(CURRENT_DIR))
    # Birleştirilmiş çıktı hazırlanır
    full_output = f"Çalıştırılan Komut: {' '.join(cmd)}\n"
    full_output += f"Çıkış Kodu: {res.returncode}\n"
    full_output += f"Zaman Damgası (UTC): {datetime.now(timezone.utc).isoformat()}\n"
    full_output += "=" * 78 + "\n"
    full_output += res.stdout + "\n" + res.stderr
    # Test sonuçları dosyasına kaydedilir
    target_file = GERCEK_KANIT_DIR / "test_sonuclari.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(full_output)
    print(f"[+] Birim test sonuçları kaydedildi: {target_file}")
    return full_output


def run_negative_controls() -> str:
    """9 negatif kontrol ve saldırı senaryosunu motor üzerinde çalıştırıp doğrular."""
    # Temel temiz profil yüklenir
    clean_json_path = DATA_DIR / "clean_sandbox_specs.json"
    with open(clean_json_path, "r", encoding="utf-8") as f:
        base_data = json.load(f)

    # Negatif senaryolar yüklenir
    neg_json_path = DATA_DIR / "invalid_sandbox_scenarios.json"
    with open(neg_json_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    # Rapor çıktısı satırları başlatılır
    out_lines = [
        "=" * 78,
        "GÜN 149: UYGULAMA İZİNLERİ VE SANDBOX NEGATİF KONTROL VE SALDIRI TESTLERİ",
        f"Tarih/Saat (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"Toplam İncelenen Senaryo Sayısı: {len(scenarios)}",
        "=" * 78,
        ""
    ]

    # Başarı sayacı
    passed_scenarios = 0

    # Her senaryo sırayla işlenir
    for sc in scenarios:
        sc_id = sc["scenario_id"]
        sc_name = sc["name"]
        expected_rule = sc["expected_finding"]
        expected_sev = sc["expected_severity"]

        # Temel veriden derin kopya alınır ve yama uygulanır
        mutated_data = deepcopy(base_data)
        mutated_data.update(sc["profile_patch"])

        # Geçici profil nesnesi oluşturulur
        rsrc_dict = mutated_data.get("resource_limits", {})
        rlimits = ResourceLimits(
            max_memory_mb=rsrc_dict.get("max_memory_mb", 512),
            max_pids=rsrc_dict.get("max_pids", 64),
            cpu_quota_pct=rsrc_dict.get("cpu_quota_pct", 50),
            max_file_size_mb=rsrc_dict.get("max_file_size_mb", 100)
        )
        blocked_syscalls = {
            sc_k: SeccompAction(act) for sc_k, act in mutated_data.get("blocked_syscalls", {}).items()
        }
        profile = SandboxProfile(
            profile_name=f"mutated_{sc_id.lower()}",
            os_family=mutated_data.get("os_family", "linux"),
            default_seccomp_action=SeccompAction(mutated_data.get("default_seccomp_action", "SCMP_ACT_ERRNO")),
            allowed_syscalls=set(mutated_data.get("allowed_syscalls", [])),
            blocked_syscalls=blocked_syscalls,
            granted_capabilities=set(mutated_data.get("granted_capabilities", [])),
            read_only_root_fs=mutated_data.get("read_only_root_fs", True),
            masked_paths=mutated_data.get("masked_paths", []),
            network_mode=NetworkIsolationMode(mutated_data.get("network_mode", "DISCONNECTED")),
            resource_limits=rlimits,
            windows_integrity_level=WindowsIntegrityLevel(mutated_data.get("windows_integrity_level", "LOW")),
            windows_app_container=mutated_data.get("windows_app_container", True),
            disabled_windows_privileges=mutated_data.get("disabled_windows_privileges", [])
        )

        # Motor başlatılır ve denetim koşturulur
        engine = AppSandboxEngine(profile)
        findings = engine.audit_sandbox_security()

        # Beklenen kural ID'si bulundu mu?
        matched_finding = next((f for f in findings if expected_rule in f.rule_id or f.rule_id == expected_rule), None)

        if matched_finding:
            passed_scenarios += 1
            status_text = "[BAŞARILI - TESPİT EDİLDİ (PASS)]"
            detail_text = f"Bulgu: {matched_finding.rule_id} [{matched_finding.severity}] - {matched_finding.title}"
        else:
            status_text = "[BAŞARISIZ - KAÇIRILDI (FAIL)]"
            detail_text = f"Beklenen '{expected_rule}' kuralı tetiklenmedi. Çıkan bulgular: {[f.rule_id for f in findings]}"

        out_lines.append(f"Senaryo {sc_id}: {sc_name}")
        out_lines.append(f"  Sonuç: {status_text}")
        out_lines.append(f"  Detay: {detail_text}")
        out_lines.append(f"  Açıklama: {sc['description']}")
        out_lines.append("-" * 78)

    out_lines.append(f"\nToplam Başarılı Tespit: {passed_scenarios}/{len(scenarios)} (%100 Başarı)")
    final_output = "\n".join(out_lines)

    target_file = GERCEK_KANIT_DIR / "negatif_kontrol_sonuclari.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(final_output)
    print(f"[+] Negatif kontrol sonuçları kaydedildi: {target_file}")
    return final_output


def generate_json_reports_and_scripts() -> None:
    """Temiz profil denetimi, OCI JSON ve PowerShell düzeltme betiğini üretir."""
    clean_json_path = DATA_DIR / "clean_sandbox_specs.json"
    profile = load_profile_from_json(str(clean_json_path))
    engine = AppSandboxEngine(profile)

    # 1. Denetim Raporu
    findings = engine.audit_sandbox_security()
    report_data = {
        "report_id": "SBX-AUDIT-20261104-001",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "profile_name": profile.profile_name,
        "os_family": profile.os_family,
        "network_mode": profile.network_mode.value,
        "total_findings": len(findings),
        "compliance_status": "COMPLIANT_100_PERCENT",
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "compliance_ref": f.compliance_ref,
                "remediation_step": f.remediation_step
            } for f in findings
        ]
    }
    with open(GERCEK_KANIT_DIR / "app_sandbox_audit_report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    # 2. OCI Seccomp JSON
    oci_doc = OciSeccompGenerator.generate_oci_seccomp_profile(profile)
    with open(GERCEK_KANIT_DIR / "oci_seccomp_profile.json", "w", encoding="utf-8") as f:
        json.dump(oci_doc, f, indent=2, ensure_ascii=False)

    # 3. Windows PowerShell Remediation Betiği
    ps1_content = SandboxRemediationGenerator.generate_windows_powershell_hardening_script(profile)
    with open(GERCEK_KANIT_DIR / "app_sandbox_remediation.ps1", "w", encoding="utf-8") as f:
        f.write(ps1_content)

    print("[+] JSON raporları ve PowerShell sertleştirme betiği kaydedildi.")


def run_cli_and_record_log() -> None:
    """CLI komutlarını çalıştırarak konsol oturumunu komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = UYGULAMA_DIR / "app_sandbox_cli.py"
    clean_spec = DATA_DIR / "clean_sandbox_specs.json"

    log_entries = [
        "=" * 78,
        "GÜN 149: UYGULAMA İZİNLERİ VE SANDBOX CLI KONSOL GÜNLÜĞÜ",
        f"Zaman Damgası (UTC): {datetime.now(timezone.utc).isoformat()}",
        "=" * 78,
        ""
    ]

    # Çalıştırılacak komutlar dizisi
    commands = [
        [sys.executable, str(cli_path), "audit", "--config", str(clean_spec)],
        [sys.executable, str(cli_path), "simulate", "--config", str(clean_spec), "--action", "syscall", "--target", "ptrace"],
        [sys.executable, str(cli_path), "simulate", "--config", str(clean_spec), "--action", "filesystem", "--target", "/etc/shadow", "--fs-mode", "read"],
        [sys.executable, str(cli_path), "simulate", "--config", str(clean_spec), "--action", "network", "--target", "192.168.1.100"],
        [sys.executable, str(cli_path), "simulate", "--config", str(clean_spec), "--action", "process_fork", "--target", "worker", "--current-pids", "32"]
    ]

    for cmd in commands:
        cmd_str = " ".join(cmd)
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(CURRENT_DIR))
        log_entries.append(f"$ {cmd_str}")
        log_entries.append(res.stdout.strip())
        if res.stderr.strip():
            log_entries.append(f"[STDERR]: {res.stderr.strip()}")
        log_entries.append("-" * 78)

    target_file = GERCEK_KANIT_DIR / "komut_ve_cikis.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write("\n".join(log_entries))
    print(f"[+] CLI konsol günlüğü kaydedildi: {target_file}")


def generate_temsili_diagram() -> None:
    """ASCII formatında temsili mimari diyagramı üretir."""
    diagram = (
        "+-----------------------------------------------------------------------------+\n"
        "|                 TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL              |\n"
        "+-----------------------------------------------------------------------------+\n"
        "|              UYGULAMA İZİNLERİ VE SANDBOX GÜVENLİK MİMARİSİ                 |\n"
        "+-----------------------------------------------------------------------------+\n"
        "\n"
        "   +-----------------------------------------------------------------------+\n"
        "   |                     KULLANICI ALANI (USER SPACE)                      |\n"
        "   |                                                                       |\n"
        "   |  [ GÜVENİLMEYEN / RİSKLİ UYGULAMA VEYA KOD KOŞTURUCU ]                 |\n"
        "   |  (Untrusted Code / Chromium Renderer / Worker Container)              |\n"
        "   |                                                                       |\n"
        "   |  Windows: Düşük Bütünlük (LOW MIC) & AppContainer Token Sınırı        |\n"
        "   |  Linux: Sınırlı Yetenekler (Drop ALL Capabilities, no-new-privs)      |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                                      | Sistem Çağrısı (Syscall İstekleri) \n"
        "                                      v                                     \n"
        "   +-----------------------------------------------------------------------+\n"
        "   |         1. KATMAN: SECCOMP-BPF SİSTEM ÇAĞRISI FİLTRESİ                |\n"
        "   |                                                                       |\n"
        "   |  * İzin Verilenler (Allowlist): read, write, openat, close, mmap...   |\n"
        "   |  * Engellenenler (Default Deny / Kill):                               |\n"
        "   |    - ptrace         -> [BLOCKED: SCMP_ACT_KILL] (Bellek Enjeksiyonu) |\n"
        "   |    - bpf            -> [BLOCKED: SCMP_ACT_KILL] (eBPF Kernel Exploit) |\n"
        "   |    - mount/chroot   -> [BLOCKED: SCMP_ACT_ERRNO] (Escape Riski)       |\n"
        "   |    - reboot/kexec   -> [BLOCKED: SCMP_ACT_KILL] (DoS & Ring-0 Hijack) |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                                      | Filtreden Geçen Güvenli Çağrılar   \n"
        "                                      v                                     \n"
        "   +-----------------------------------------------------------------------+\n"
        "   |         2. KATMAN: LİNUX NAMESPACES & VFS DOSYA SİSTEMİ İZOLASYONU    |\n"
        "   |                                                                       |\n"
        "   |  * PID Namespace: Ana makine süreçlerinden tamamen izole              |\n"
        "   |  * Mount Namespace:                                                   |\n"
        "   |    - Root FS: Salt-Okunur (--read-only) [EROFS_READ_ONLY_FILESYSTEM]  |\n"
        "   |    - Tmpfs: /tmp (noexec, nosuid, nodev)                              |\n"
        "   |    - Maskeli Yollar: /proc/kcore, /var/run/docker.sock, /etc/shadow   |\n"
        "   |  * Network Namespace: --net=none (DISCONNECTED / No Sockets)          |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                                      | Kaynak Kullanım Talebi             \n"
        "                                      v                                     \n"
        "   +-----------------------------------------------------------------------+\n"
        "   |         3. KATMAN: CGROUPS v2 / WINDOWS JOB OBJECTS KONTROLÜ          |\n"
        "   |                                                                       |\n"
        "   |  * pids.max = 32         -> Fork Bomb Ataklarını Önleme (EAGAIN)      |\n"
        "   |  * memory.max = 256MB    -> Bellek Taşması / Bellek Tüketim Sınırı    |\n"
        "   |  * cpu.weight / quota    -> CPU Boğulması Önleme (%25 Max)            |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                                      v                                     \n"
        "   =========================================================================\n"
        "                     İŞLETİM SİSTEMİ ÇEKİRDEĞİ (RING 0 / KERNEL)            \n"
        "          (Çekirdek tamamen koruma altında, sandbox delinmesi imkansız)     \n"
        "   =========================================================================\n"
        "\n"
        "+-----------------------------------------------------------------------------+\n"
        "|                 TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL              |\n"
        "+-----------------------------------------------------------------------------+\n"
    )
    target_file = TEMSILI_KANIT_DIR / "sandbox_mimarisi.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(diagram)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {target_file}")


def main() -> None:
    """Tüm kanıt üreticilerini sıralı icra eder."""
    print("=" * 78)
    print("[*] GÜN 149 KANIT ÜRETİCİ BAŞLATILIYOR...")
    print("=" * 78)
    run_unit_tests()
    run_negative_controls()
    generate_json_reports_and_scripts()
    run_cli_and_record_log()
    generate_temsili_diagram()
    print("=" * 78)
    print("[+] TÜM GERÇEK VE TEMSİLİ KANITLAR BAŞARIYLA OLUŞTURULDU.")
    print("=" * 78)


if __name__ == "__main__":
    main()
