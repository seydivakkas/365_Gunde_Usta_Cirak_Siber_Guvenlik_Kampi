# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 117: RBAC ve ABAC Erişim Kontrol CLI Yönetim ve Denetim Aracı.
Komut satırından yetkilendirme isteklerini simüle eder, SoD çatışmalarını denetler
ve yapılandırılmış denetim izi (audit log) üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse kütüphanesi
import argparse
# JSON çıktıları biçimlendirmek için json kütüphanesi
import json
# Sistem çıkış kodları için sys modülü
import sys
# Tarih ve saat işlemleri için datetime kütüphanesi
import datetime
# Dosya yolları işlemleri için os modülü
import os

# Uygulama motorunun modüllerini yerel içe aktarma
from uygulama.rbac_abac_engine import (
    RBACEngine,
    ABACPolicyEngine,
    HybridAccessManager,
    SubjectContext,
    ResourceContext,
    ActionContext,
    EnvironmentContext,
    AccessControlSecurityError
)


def build_default_manager() -> HybridAccessManager:
    """Örnek kurumsal kurallarla donatılmış hibrit erişim yöneticisi üretir."""
    # RBAC motoru ilklendirilir
    rbac = RBACEngine()

    # Rol hiyerarşisi tanımlanır: admin > auditor > staff > user
    rbac.add_role_hierarchy("admin", {"auditor", "manager"})
    # Manager hiyerarşisi: manager > staff
    rbac.add_role_hierarchy("manager", {"staff"})
    # Staff hiyerarşisi: staff > user
    rbac.add_role_hierarchy("staff", {"user"})

    # İzin atamaları yapılır
    rbac.assign_permissions_to_role("admin", {"*:*"})
    # Auditor rolü izinleri
    rbac.assign_permissions_to_role("auditor", {"audit_log:read", "financial_report:read", "compliance_doc:read"})
    # Manager rolü izinleri
    rbac.assign_permissions_to_role("manager", {"financial_report:write", "financial_report:read", "financial_ledger:write", "project_doc:write", "project_doc:delete"})
    # Staff rolü izinleri
    rbac.assign_permissions_to_role("staff", {"project_doc:read", "project_doc:write", "public_asset:read"})
    # User rolü izinleri
    rbac.assign_permissions_to_role("user", {"public_asset:read", "profile:read", "profile:write"})

    # SoD Çakışma Kuralı: Satın Alma Talebi Başlatan (Purchaser) ile Onaylayan (Approver) aynı olamaz
    rbac.add_sod_conflict("purchaser", "approver")
    # Geliştirici (developer) ile Canlı Ortam Denetçisi (live_deployer) aynı olamaz
    rbac.add_sod_conflict("developer", "live_deployer")

    # ABAC motoru ilklendirilir
    abac = ABACPolicyEngine(corporate_cidrs=["10.0.0.0/8", "192.168.1.0/24", "127.0.0.1/32"])

    # Hibrit yönetici döndürülür
    return HybridAccessManager(rbac_engine=rbac, abac_engine=abac)


def handle_evaluate(args: argparse.Namespace) -> int:
    """Erişim talebini değerlendirir ve sonucu ekrana yazdırır."""
    # Yönetici motoru inşa edilir
    manager = build_default_manager()

    # Rol listesi ayrıştırılır
    roles_set = set(args.roles.split(",")) if args.roles else {"user"}

    # Özne bağlamı oluşturulur
    subject = SubjectContext(
        user_id=args.user_id,
        roles=roles_set,
        department=args.department,
        clearance_level=args.clearance,
        tenant_id=args.tenant,
        mfa_authenticated=args.mfa,
        ip_address=args.ip
    )

    # Kaynak bağlamı oluşturulur
    resource = ResourceContext(
        resource_id=args.resource_id,
        resource_type=args.resource_type,
        department_owner=args.owner_dept,
        classification=args.classification,
        tenant_id=args.resource_tenant or args.tenant,
        is_locked=args.locked
    )

    # Eylem bağlamı oluşturulur
    action = ActionContext(name=args.action)

    # Çevresel bağlam oluşturulur
    env = EnvironmentContext(
        timestamp=datetime.datetime.now(),
        is_business_hours=not args.after_hours,
        is_corporate_network=manager.abac.is_ip_trusted(args.ip),
        risk_score=args.risk_score
    )

    # Değerlendirme icra edilir
    try:
        # Hibrit politika zorlama fonksiyonu çağrılır
        decision = manager.enforce_access(subject, resource, action, env)
        # Başarılı karar yazdırılır
        print("=" * 70)
        print("[+] ERİŞİM İZNİ VERİLDİ (ACCESS GRANTED)")
        print(f"Denetim No (Audit ID) : {decision.audit_id}")
        print(f"Kullanılan Model      : {decision.model_used}")
        print(f"Karar Kuralı          : {decision.decision_rule}")
        print("Gerekçeler:")
        for r in decision.reasons:
            print(f"  * {r}")
        print("=" * 70)
        return 0
    except AccessControlSecurityError as sec_err:
        # Güvenlik ihlali yakalanır
        print("=" * 70)
        print("[-] ERİŞİM REDDEDİLDİ (ACCESS DENIED - SECURITY VIOLATION)")
        print(f"Hata Sınıfı : {sec_err.__class__.__name__}")
        print(f"Açıklama    : {str(sec_err)}")
        print("=" * 70)
        return 1


def handle_sod_check(args: argparse.Namespace) -> int:
    """Belirtilen rollerin SoD çatışması oluşturup oluşturmadığını teyit eder."""
    # Yönetici inşa edilir
    manager = build_default_manager()
    # Rol listesi ayrıştırılır
    roles = set(args.roles.split(","))

    try:
        # SoD uygunluğu test edilir
        manager.rbac.validate_sod_compliance(roles)
        print(f"[+] SoD Uygunluk Başarılı: '{roles}' kümesinde herhangi bir görevler ayrılığı çatışması yok.")
        return 0
    except AccessControlSecurityError as err:
        print(f"[-] SoD İhlali Saptandı: {err}")
        return 1


def main() -> None:
    """CLI giriş noktası ve argüman yönlendiricisi."""
    # Ana argüman ayrıştırıcı tanımlanır
    parser = argparse.ArgumentParser(
        description="NIST RBAC & ABAC Kurumsal Erişim Kontrolü CLI Aracı"
    )
    # Alt komut ayrıştırıcıları başlatılır
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 'evaluate' alt komutu
    eval_parser = subparsers.add_parser("evaluate", help="Erişim talebini RBAC/ABAC ile değerlendir")
    eval_parser.add_argument("--user-id", required=True, help="Kullanıcı kimliği")
    eval_parser.add_argument("--roles", default="user", help="Virgülle ayrılmış roller")
    eval_parser.add_argument("--department", default="finance", help="Kullanıcı departmanı")
    eval_parser.add_argument("--clearance", type=int, default=1, help="Yetki seviyesi (1-4)")
    eval_parser.add_argument("--tenant", default="tenant_corp", help="Kullanıcı kiracı kimliği")
    eval_parser.add_argument("--mfa", action="store_true", help="MFA doğrulandı mı?")
    eval_parser.add_argument("--ip", default="10.0.1.50", help="İstemci IP adresi")

    eval_parser.add_argument("--resource-id", required=True, help="Kaynak kimliği")
    eval_parser.add_argument("--resource-type", required=True, help="Kaynak türü")
    eval_parser.add_argument("--owner-dept", default="finance", help="Kaynağın ait olduğu departman")
    eval_parser.add_argument("--classification", type=int, default=1, help="Gizlilik seviyesi (1-4)")
    eval_parser.add_argument("--resource-tenant", default=None, help="Kaynak kiracı kimliği (farklı ise)")
    eval_parser.add_argument("--locked", action="store_true", help="Kaynak kilitli mi?")

    eval_parser.add_argument("--action", required=True, help="İşlem (read, write, delete, export)")
    eval_parser.add_argument("--after-hours", action="store_true", help="Mesai saati dışı simülasyonu")
    eval_parser.add_argument("--risk-score", type=int, default=10, help="Risk puanı (0-100)")

    # 'sod-check' alt komutu
    sod_parser = subparsers.add_parser("sod-check", help="Rollerin SoD çatışmasını kontrol et")
    sod_parser.add_argument("--roles", required=True, help="Virgülle ayrılmış roller (örn: purchaser,approver)")

    # Argümanlar ayrıştırılır
    args = parser.parse_args()

    # Komuta göre yönlendirme yapılır
    if args.command == "evaluate":
        sys.exit(handle_evaluate(args))
    elif args.command == "sod-check":
        sys.exit(handle_sod_check(args))


if __name__ == "__main__":
    # Betik doğrudan çağrıldığında ana fonksiyon çalıştırılır
    main()
