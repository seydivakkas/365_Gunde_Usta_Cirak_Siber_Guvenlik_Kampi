# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 125: Mini Proje 17 — Güvenli Kimlik ve Rol CLI Yönetim Aracı.
Bu araç komut satırından kimlik doğrulama, MFA, hiyerarşik RBAC yetkilendirme
ve Fail-Secure arıza simülasyonu operasyonlarını icra eder.
"""

# Komut satırı ayrıştırma modülü içe aktarılıyor
import argparse
# Sistem çıkışları ve argümanlar için sys içe aktarılıyor
import sys
# JSON serileştirme işlemleri için json içe aktarılıyor
import json
# Dosya varlık denetimleri için os modülü içe aktarılıyor
import os
# Tip ipuçları için typing modülü içe aktarılıyor
from typing import Optional, List

# Çekirdek motor sınıfları içe aktarılıyor
from secure_identity_role_engine import (
    SecureIdentityRoleManager,
    SystemFailureType,
    SecureIdentityEngineError
)


def load_manager_from_config(config_path: str) -> SecureIdentityRoleManager:
    """JSON yapılandırma dosyasından kimlik ve rol yöneticisini inşa eder."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {config_path}")
    with open(config_path, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    mgr = SecureIdentityRoleManager(system_name=data.get("system_name", "Kurumsal Kimlik Platformu"))

    # 1. Rolleri kaydet
    for r_data in data.get("roles", []):
        mgr.register_role(
            role_name=r_data["name"],
            permissions=set(r_data.get("permissions", [])),
            parent_roles=r_data.get("parents", []),
            requires_mfa=bool(r_data.get("requires_mfa", False))
        )

    # 2. SoD kurallarını kaydet
    for p in data.get("toxic_role_pairs", []):
        mgr.add_toxic_role_pair(p[0], p[1])

    # 3. Kullanıcıları kaydet
    for u_data in data.get("users", []):
        mgr.register_user(
            user_id=u_data["user_id"],
            username=u_data["username"],
            password=u_data["password"],
            roles=u_data.get("roles", []),
            department=u_data.get("department", "Engineering"),
            mfa_secret=u_data.get("mfa_secret")
        )

    return mgr


def handle_report(args: argparse.Namespace) -> int:
    """Mimari ve rol hiyerarşisi raporunu üretir."""
    try:
        mgr = load_manager_from_config(args.config)
        if args.format == "markdown":
            print(mgr.generate_capstone_report())
        else:
            print(json.dumps(mgr.export_summary_dict(), ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"[-] HATA: {exc}", file=sys.stderr)
        return 1


def handle_auth(args: argparse.Namespace) -> int:
    """Kullanıcı kimlik doğrulamasını icra eder ve token üretir."""
    try:
        mgr = load_manager_from_config(args.config)
        token = mgr.authenticate(args.username, args.password)
        print("=== Kimlik Doğrulama Başarılı ===")
        print(f"Kullanıcı ID: {token.user_id}")
        print(f"Roller: {', '.join(token.roles)}")
        print(f"Token: {token.token_id}")
        print(f"Son Geçerlilik: {token.expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"MFA Doğrulandı mı?: {'EVET' if token.mfa_verified else 'HAYIR (Step-Up Gerekebilir)'}")
        return 0
    except SecureIdentityEngineError as sie:
        print(f"[!] KİMLİK DOĞRULAMA HATASI: {sie}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[-] HATA: {exc}", file=sys.stderr)
        return 1


def handle_authorize(args: argparse.Namespace) -> int:
    """Yetki denetimini icra eder ve Fail-Secure korumasını test eder."""
    try:
        mgr = load_manager_from_config(args.config)
        # Önce kullanıcı giriş yapıp token alır
        token = mgr.authenticate(args.username, args.password)
        # Eğer MFA kodu verildiyse doğrulanır
        if args.mfa_code:
            token = mgr.verify_mfa(token.token_id, args.mfa_code)

        sim_fail = SystemFailureType[args.simulate_failure] if args.simulate_failure else None
        res = mgr.authorize(
            token_id=token.token_id,
            resource_id=args.resource_id,
            action=args.action,
            simulate_failure=sim_fail
        )

        print(f"=== Yetki Kararı: [{res.decision}] ===")
        print(f"Talep ID: {res.request_id}")
        print(f"Gerekçe: {res.reason}")
        if res.matched_permission:
            print(f"Eşleşen Yetki: {res.matched_permission}")
        if res.is_fail_secure_intervention:
            print("[GÜVENCE] Fail-Secure müdahalesi: Altyapı arızasında erişim kapalı tutuldu (CWE-636).")
        return 0 if res.decision == "PERMIT" else 3
    except SecureIdentityEngineError as sie:
        print(f"[!] YETKİLENDİRME HATASI: {sie}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[-] HATA: {exc}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> None:
    """Komut satırı ana giriş noktası."""
    parser = argparse.ArgumentParser(description="Mini Proje 17 — Güvenli Kimlik ve Rol CLI Aracı")
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'report' komutu
    rep_parser = subparsers.add_parser("report", help="Rol hiyerarşisi ve mimari raporunu bas")
    rep_parser.add_argument("config", help="Yapılandırma JSON dosya yolu")
    rep_parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Çıktı formatı")

    # 2. 'auth' komutu
    auth_parser = subparsers.add_parser("auth", help="Kullanıcı kimlik doğrulaması yap")
    auth_parser.add_argument("config", help="Yapılandırma JSON dosya yolu")
    auth_parser.add_argument("--username", required=True, help="Kullanıcı adı")
    auth_parser.add_argument("--password", required=True, help="Parola")

    # 3. 'authorize' komutu
    authz_parser = subparsers.add_parser("authorize", help="Erişim talebini denetle")
    authz_parser.add_argument("config", help="Yapılandırma JSON dosya yolu")
    authz_parser.add_argument("--username", required=True, help="Kullanıcı adı")
    authz_parser.add_argument("--password", required=True, help="Parola")
    authz_parser.add_argument("--mfa-code", help="Step-Up MFA doğrulama kodu")
    authz_parser.add_argument("--resource-id", required=True, help="Hedef kaynak (örn: ledger, audit_log)")
    authz_parser.add_argument("--action", required=True, help="Hedef eylem (read, write, transfer)")
    authz_parser.add_argument("--simulate-failure", choices=[f.name for f in SystemFailureType], default=None,
                              help="Simüle edilecek sistem arızası")

    args = parser.parse_args(argv)
    if args.command == "report":
        sys.exit(handle_report(args))
    elif args.command == "auth":
        sys.exit(handle_auth(args))
    elif args.command == "authorize":
        sys.exit(handle_authorize(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
