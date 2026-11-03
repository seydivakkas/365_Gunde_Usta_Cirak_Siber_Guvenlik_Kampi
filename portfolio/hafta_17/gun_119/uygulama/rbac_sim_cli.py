# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 119: Mini Proje 16 — Rol Tabanlı Erişim Simülatörü CLI Aracı.
Kurumsal rol hiyerarşisi, SSD/DSD görevler ayrılığı denetimi ve anlık erişim simülasyonu sunar.
"""

# Komut satırı argüman ayrıştırıcısı için argparse modülü
import argparse
# JSON veri işleme için json modülü
import json
# Çıkış kodları için sys modülü
import sys
# Dosya ve dizin yolları için os modülü
import os

# Çekirdek simülatör motorunun içe aktarılması
from uygulama.rbac_simulator_engine import (
    RBACSimulatorEngine,
    SimulationRequest,
    RBACSimulatorError
)


def build_enterprise_simulator() -> RBACSimulatorEngine:
    """Kurumsal seviye ön tanımlı roller ve hiyerarşiyle simülatör inşa eder."""
    sim = RBACSimulatorEngine(max_roles_per_user=4)

    # 1. Rol tanımları
    sim.define_role("admin", {"*:*"})
    sim.define_role("sec_officer", {"audit_log:read", "policy:write", "policy:read"})
    sim.define_role("finance_director", {"budget:approve", "financial_report:read", "financial_report:write"})
    sim.define_role("accountant", {"invoice:create", "invoice:read", "financial_report:read"})
    sim.define_role("cashier", {"payment:execute", "invoice:read"})
    sim.define_role("developer", {"repo:read", "repo:write", "ci_build:trigger"})
    sim.define_role("auditor", {"audit_log:read", "compliance:read"})
    sim.define_role("employee", {"profile:read", "public_wiki:read"})

    # 2. Hiyerarşik miraslar: finance_director -> accountant -> employee
    sim.add_hierarchy_edge("finance_director", "accountant")
    sim.add_hierarchy_edge("accountant", "employee")
    sim.add_hierarchy_edge("developer", "employee")
    sim.add_hierarchy_edge("sec_officer", "auditor")

    # 3. Statik Görevler Ayrılığı (SSD): Fatura oluşturan (accountant) ile Ödeme yapan (cashier) aynı kişiye verilemez!
    sim.add_ssd_conflict("accountant", "cashier")

    # 4. Dinamik Görevler Ayrılığı (DSD): Güvenlik yetkilisi (sec_officer) ile Geliştirici (developer) aynı oturumda açılamaz!
    sim.add_dsd_conflict("sec_officer", "developer")

    # 5. Örnek kullanıcılar
    u1 = sim.register_user("cfo_selim", "Selim Kaya", "Finance")
    sim.assign_role_to_user("cfo_selim", "finance_director")

    u2 = sim.register_user("dev_ayse", "Ayşe Yılmaz", "Engineering")
    sim.assign_role_to_user("dev_ayse", "developer")

    u3 = sim.register_user("staff_mehmet", "Mehmet Demir", "Accounting")
    sim.assign_role_to_user("staff_mehmet", "accountant")

    return sim


def handle_sim_access(args: argparse.Namespace) -> int:
    """Erişim simülasyonunu icra eder."""
    sim = build_enterprise_simulator()

    req = SimulationRequest(
        request_id="REQ-CLI-01",
        user_id=args.user_id,
        target_object=args.target,
        action=args.action
    )

    try:
        res = sim.evaluate_access(req)
        print("=" * 70)
        if res.is_permitted:
            print("[+] ERİŞİM ONAYLANDI (ACCESS PERMITTED)")
            print(f"Kullanıcı   : {req.user_id}")
            print(f"Hedef İşlem : {req.target_object}:{req.action}")
            print(f"Gerekçe     : {res.reason}")
            print("=" * 70)
            return 0
        else:
            print("[-] ERİŞİM REDDEDİLDİ (ACCESS DENIED)")
            print(f"Kullanıcı   : {req.user_id}")
            print(f"Hedef İşlem : {req.target_object}:{req.action}")
            print(f"Gerekçe     : {res.reason}")
            print("=" * 70)
            return 1
    except RBACSimulatorError as err:
        print(f"[-] Simülasyon Güvenlik Hatası: {err}")
        return 1


def handle_check_sod(args: argparse.Namespace) -> int:
    """Belirtilen rollerin SSD veya DSD ihlali yapıp yapmadığını analiz eder."""
    sim = build_enterprise_simulator()
    roles = set(args.roles.split(","))

    print("=" * 70)
    print(f"[*] Görevler Ayrılığı (SoD) Analizi: {roles}")
    try:
        sim.check_ssd_compliance(roles)
        print("[+] Statik SoD (SSD): Çatışma Yok (PASS)")
    except RBACSimulatorError as ssd_err:
        print(f"[-] Statik SoD (SSD) İhlali: {ssd_err}")

    try:
        sim.check_dsd_compliance(roles)
        print("[+] Dinamik SoD (DSD): Çatışma Yok (PASS)")
    except RBACSimulatorError as dsd_err:
        print(f"[-] Dinamik SoD (DSD) İhlali: {dsd_err}")
    print("=" * 70)
    return 0


def main() -> None:
    """CLI giriş noktası."""
    parser = argparse.ArgumentParser(
        description="Mini Proje 16: Kurumsal RBAC Simülatör ve Politika Denetim CLI Aracı"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sim_parser = subparsers.add_parser("sim-access", help="Erişim talebini simüle et")
    sim_parser.add_argument("--user-id", required=True, help="Kullanıcı kimliği")
    sim_parser.add_argument("--target", required=True, help="Hedef nesne (örn: budget, invoice)")
    sim_parser.add_argument("--action", required=True, help="Eylem (örn: approve, read, write)")

    sod_parser = subparsers.add_parser("check-sod", help="Rollerin SoD çakışmasını teyit et")
    sod_parser.add_argument("--roles", required=True, help="Virgülle ayrılmış roller")

    args = parser.parse_args()
    if args.command == "sim-access":
        sys.exit(handle_sim_access(args))
    elif args.command == "check-sod":
        sys.exit(handle_check_sod(args))


if __name__ == "__main__":
    main()
