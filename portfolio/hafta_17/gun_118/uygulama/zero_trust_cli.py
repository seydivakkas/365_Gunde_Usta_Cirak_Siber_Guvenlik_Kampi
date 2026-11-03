# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 118: Sıfır Güven (Zero Trust) ve En Az Ayrıcalık (PoLP) CLI Yönetim Aracı.
Uç nokta sağlık analizi, JIT yetki yükseltme, dinamik güven puanlama ve mikro-segment denetimi sunar.
"""

# Komut satırı argümanları için argparse modülü
import argparse
# JSON verileri ve biçimlendirme için json modülü
import json
# Sistem çıkış kodları için sys modülü
import sys
# Tarih ve saat işlemleri için datetime modülü
import datetime

# Çekirdek modellerin içe aktarılması
from uygulama.least_privilege_zero_trust_engine import (
    ZeroTrustOrchestrator,
    DevicePosture,
    ProtectedResource,
    ZeroTrustSecurityError
)


def get_default_orchestrator() -> ZeroTrustOrchestrator:
    """Tekil orkestratör örneği oluşturur."""
    return ZeroTrustOrchestrator()


def handle_eval(args: argparse.Namespace) -> int:
    """Erişim talebini Sıfır Güven prensipleriyle değerlendirir."""
    orchestrator = get_default_orchestrator()

    # Cihaz sağlık nesnesi inşa edilir
    device = DevicePosture(
        device_id=args.device_id,
        is_managed=not args.unmanaged,
        os_version=args.os,
        antivirus_active=not args.no_av,
        disk_encrypted=not args.unencrypted,
        patch_lag_days=args.patch_lag
    )

    # Oturum oluşturulur
    session = orchestrator.create_session(
        user_id=args.user_id,
        device=device,
        ip_address=args.ip,
        mfa_verified=args.mfa,
        network_segment=args.segment
    )

    # JIT yetkisi talep edilmişse eklenir
    if args.jit_scope:
        try:
            grant = orchestrator.lp_mgr.request_jit_elevation(
                user_id=args.user_id,
                target_scope=args.jit_scope,
                justification=args.justification or "Planlı sistem bakımı",
                approver_id="sec_ops_director",
                duration_seconds=args.ttl
            )
            session.jit_grants[grant.grant_id] = grant
            print(f"[+] JIT Hibesi Tahsis Edildi: {grant.grant_id} (Kapsam: {grant.granted_scope}, TTL: {args.ttl}s)")
        except ZeroTrustSecurityError as jit_err:
            print(f"[-] JIT Talebi Reddedildi: {jit_err}")
            return 1

    # Anomali simülasyonu
    for _ in range(args.anomalies):
        orchestrator.zt_engine.record_session_anomaly(session, "Şüpheli erişim davranışı")

    # Hedef kaynak tanımlanır
    resource = ProtectedResource(
        resource_id=args.resource_id,
        name=args.resource_name or args.resource_id,
        target_segment=args.target_segment,
        min_trust_score=float(args.min_trust),
        required_jit_scope=args.required_jit or None,
        requires_step_up_mfa=args.step_up
    )

    # Erişim kararı icra edilir
    try:
        record = orchestrator.request_access(session.session_id, resource)
        print("=" * 70)
        print("[+] ERİŞİM ONAYLANDI (ZERO TRUST ACCESS GRANTED)")
        print(f"Denetim ID (Audit ID)  : {record['audit_id']}")
        print(f"Kullanıcı / Oturum     : {record['user_id']} / {record['session_id']}")
        print(f"Dinamik Güven Skoru    : {record['trust_score']:.1f} / 100.0")
        print("Doğrulanan Güvenlik Kalkanları:")
        for r in record["reasons"]:
            print(f"  * {r}")
        print("=" * 70)
        return 0
    except ZeroTrustSecurityError as sec_err:
        print("=" * 70)
        print("[-] ERİŞİM ENGELLENDİ (ZERO TRUST SECURITY DENIAL)")
        print(f"Güvenlik İstisnası : {sec_err.__class__.__name__}")
        print(f"Açıklama           : {str(sec_err)}")
        print(f"Son Güven Skoru    : {session.current_trust_score:.1f}")
        print("=" * 70)
        return 1


def main() -> None:
    """CLI giriş noktası ve argüman yöneticisi."""
    parser = argparse.ArgumentParser(
        description="NIST SP 800-207 Sıfır Güven (Zero Trust) & En Az Ayrıcalık (PoLP) CLI Aracı"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    eval_parser = subparsers.add_parser("eval", help="Sıfır güven erişim değerlendirmesi yap")
    eval_parser.add_argument("--user-id", default="engineer_01", help="Kullanıcı kimliği")
    eval_parser.add_argument("--device-id", default="DEV-CORP-991", help="Cihaz donanım kimliği")
    eval_parser.add_argument("--os", default="Windows 11 Enterprise", help="İşletim sistemi")
    eval_parser.add_argument("--unmanaged", action="store_true", help="Yönetilmeyen (BYOD) cihaz")
    eval_parser.add_argument("--no-av", action="store_true", help="Antivirüs/EDR kapalı")
    eval_parser.add_argument("--unencrypted", action="store_true", help="Disk şifrelenmemiş")
    eval_parser.add_argument("--patch-lag", type=int, default=2, help="Yama gecikmesi (gün)")
    eval_parser.add_argument("--ip", default="10.20.1.50", help="İstemci IP adresi")
    eval_parser.add_argument("--segment", default="management_jumpbox", help="Kaynak ağ segmenti")
    eval_parser.add_argument("--mfa", action="store_true", help="MFA oturumu aktif")
    eval_parser.add_argument("--anomalies", type=int, default=0, help="Simüle edilecek anomali sayısı")

    eval_parser.add_argument("--jit-scope", default=None, help="Talep edilen JIT yetki kapsamı")
    eval_parser.add_argument("--justification", default=None, help="JIT gerekçesi")
    eval_parser.add_argument("--ttl", type=int, default=1800, help="JIT süresi (saniye)")

    eval_parser.add_argument("--resource-id", required=True, help="Hedef kaynak kimliği")
    eval_parser.add_argument("--resource-name", default=None, help="Kaynak adı")
    eval_parser.add_argument("--target-segment", default="core_banking", help="Hedef mikro-segment")
    eval_parser.add_argument("--min-trust", type=float, default=70.0, help="Asgari güven skoru")
    eval_parser.add_argument("--required-jit", default=None, help="Gerekli JIT yetki kapsamı")
    eval_parser.add_argument("--step-up", action="store_true", help="Step-Up MFA zorunlu mu?")

    args = parser.parse_args()
    if args.command == "eval":
        sys.exit(handle_eval(args))


if __name__ == "__main__":
    main()
