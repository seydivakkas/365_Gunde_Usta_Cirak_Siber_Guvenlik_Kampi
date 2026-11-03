# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 113: Kimlik Doğrulama ve Yetkilendirme Komut Satırı Arayüzü (IAM CLI).

Bu araç, kimlik doğrulama (AuthN) ve yetkilendirme (AuthZ) adımlarını komut satırından
test etmek, oturum yönetimi yürütmek, kaynak erişim kontrollerini denetlemek ve
denetim günlüklerini (audit trail) görüntülemek için tasarlanmıştır.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse modülü içe aktarılır
import argparse
# Çıktı formatlama ve JSON dönüşümleri için json modülü içe aktarılır
import json
# Sistem çıkış kodları ve hata yönetimi için sys modülü içe aktarılır
import sys
# Dosya ve dizin yolları için os modülü içe aktarılır
import os
# Tarih ve zaman damgası işlemleri için datetime içe aktarılır
from datetime import datetime, timezone

# Bulunduğumuz dizin ve üst dizin Python arama yoluna eklenir (bağımsız gün standardı)
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# authn_authz_engine modülünden gerekli sınıflar içe aktarılır
from authn_authz_engine import (
    AuthenticationEngine,
    AuthorizationEngine,
    IdentityAndAccessGateway,
    Resource,
    IAMSecurityError
)


def build_demo_environment() -> Tuple[AuthenticationEngine, AuthorizationEngine, IdentityAndAccessGateway]:
    """CLI testleri için standart bir örnek kimlik ve kaynak ortamı hazırlar."""
    # AuthN motoru 5000 iterasyonla başlatılır
    authn = AuthenticationEngine(default_iterations=5000)
    # AuthZ motoru başlatılır
    authz = AuthorizationEngine()
    # Birleşik geçit başlatılır
    gateway = IdentityAndAccessGateway(authn, authz)

    # Örnek kullanıcılar kaydedilir
    # Alice: Finans analisti, TENANT_A
    authn.register_user("alice", "AliceGizliParola!2026", roles=["analyst"], tenant_id="TENANT_A")
    # Bob: Operatör, TENANT_A
    authn.register_user("bob", "BobGucluParola!2026", roles=["operator"], tenant_id="TENANT_A")
    # Charlie: Sistem Yöneticisi, TENANT_A
    authn.register_user("charlie", "CharlieAdminRoot!2026", roles=["admin"], tenant_id="TENANT_A")
    # Eve: Saldırgan / Harici Kiracı, TENANT_B
    authn.register_user("eve", "EveSaldirgan!2026", roles=["analyst"], tenant_id="TENANT_B")

    # Örnek korumalı kaynaklar kaydedilir
    # Kaynak 1: Alice'in finans raporu (TENANT_A)
    gateway.register_resource(Resource(
        resource_id="finans_raporu_2026",
        resource_type="financial_report",
        owner_username="alice",
        tenant_id="TENANT_A",
        classification="CONFIDENTIAL",
        required_permissions={"read": "READ_DOCUMENT", "delete": "DELETE_DOCUMENT"}
    ))

    # Kaynak 2: Sistem yapılandırma ayarı (TENANT_A)
    gateway.register_resource(Resource(
        resource_id="sistem_ayari_01",
        resource_type="system_config",
        owner_username="charlie",
        tenant_id="TENANT_A",
        classification="RESTRICTED",
        required_permissions={"read": "READ_DOCUMENT", "write": "SYSTEM_CONFIG"}
    ))

    # Hazırlanan bileşenler döndürülür
    return authn, authz, gateway


def cmd_giris(args, authn: AuthenticationEngine) -> None:
    """Kullanıcı adı ve parola ile kimlik doğrulama gerçekleştirip oturum belirteci üretir."""
    try:
        # AuthN motoru üzerinden kimlik doğrulanır
        user = authn.authenticate(args.kullanici, args.parola)
        # Doğrulanan kullanıcı için oturum açılır (Session Fixation korumalı)
        session = authn.create_session(user.username, ttl_seconds=args.ttl)
        # Başarı çıktısı yazdırılır
        print(f"[BAŞARILI] Kimlik Doğrulama Geçerli!")
        print(f"Kullanıcı: {session.username} | Kiracı: {session.tenant_id} | Roller: {session.roles}")
        print(f"Oturum Belirteci: {session.token_str}")
        print(f"Bitiş Zamanı: {session.expires_at.isoformat()}")
    except IAMSecurityError as err:
        print(f"[HATA] Kimlik Doğrulama Başarısız: {err}")
        sys.exit(1)


def cmd_dogrula(args, authn: AuthenticationEngine) -> None:
    """Mevcut bir oturum belirtecinin geçerliliğini denetler."""
    try:
        session = authn.validate_session(args.belirtec)
        print(f"[BAŞARILI] Oturum Aktif ve Geçerli.")
        print(f"Kullanıcı: {session.username} | Kiracı: {session.tenant_id} | Bitiş: {session.expires_at.isoformat()}")
    except IAMSecurityError as err:
        print(f"[GEÇERSİZ] Oturum Reddedildi: {err}")
        sys.exit(1)


def cmd_eris(args, gateway: IdentityAndAccessGateway) -> None:
    """Korumalı bir kaynağa erişim talebini (AuthN + AuthZ) çift aşamalı icra eder."""
    try:
        sonuc = gateway.execute_request(
            session_token_str=args.belirtec,
            resource_id=args.kaynak,
            action=args.eylem
        )
        print(f"[ERİŞİM ONAYLANDI] {sonuc['mesaj']}")
        print(json.dumps(sonuc, indent=2, ensure_ascii=False))
    except IAMSecurityError as err:
        print(f"[ERİŞİM ENGELLENDİ] {err}")
        sys.exit(1)
    except Exception as ex:
        print(f"[SİSTEM HATASI] {ex}")
        sys.exit(1)


def cmd_denetim(args, gateway: IdentityAndAccessGateway) -> None:
    """Sistemde kaydedilen denetim izlerini (Audit Logs) listeler."""
    logs = gateway.get_audit_logs()
    print(f"--- Toplam {len(logs)} Adet Denetim Kaydı Bulundu ---")
    for log in logs:
        print(f"[{log['timestamp']}] {log['event_type']} - Özne: {log['subject']} -> Hedef: {log['target']} | Sonuç: {log['outcome']} | Güvenlik Etiketi: {log['security_tag']}")
        print(f"  Detay: {log['details']}")


def main():
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Kimlik Doğrulama ve Yetkilendirme (IAM) Referans CLI Aracı"
    )
    subparsers = parser.add_subparsers(dest="komut", help="Yürütülecek işlem")

    # 'giris' alt komutu
    p_giris = subparsers.add_parser("giris", help="Kullanıcı girişi yap ve oturum belirteci al")
    p_giris.add_argument("--kullanici", required=True, help="Kullanıcı adı")
    p_giris.add_argument("--parola", required=True, help="Düz metin parola")
    p_giris.add_argument("--ttl", type=int, default=3600, help="Oturum geçerlilik süresi (saniye)")

    # 'dogrula' alt komutu
    p_dogrula = subparsers.add_parser("dogrula", help="Oturum belirtecini doğrula")
    p_dogrula.add_argument("--belirtec", required=True, help="Doğrulanacak oturum belirteci")

    # 'eris' alt komutu
    p_eris = subparsers.add_parser("eris", help="Korumalı kaynağa erişim talebinde bulun (AuthN + AuthZ)")
    p_eris.add_argument("--belirtec", required=True, help="Aktif oturum belirteci")
    p_eris.add_argument("--kaynak", required=True, help="Hedef kaynak kimliği (örn. finans_raporu_2026)")
    p_eris.add_argument("--eylem", default="read", help="Talep edilen işlem (read, write, delete)")

    # 'denetim' alt komutu
    subparsers.add_parser("denetim", help="Denetim günlüklerini (audit trail) listele")

    # Argümanlar ayrıştırılır
    args = parser.parse_args()

    # Demo ortamı ayağa kaldırılır
    authn, authz, gateway = build_demo_environment()

    # Komuta göre işlev çağrılır
    if args.komut == "giris":
        cmd_giris(args, authn)
    elif args.komut == "dogrula":
        cmd_dogrula(args, authn)
    elif args.komut == "eris":
        cmd_eris(args, gateway)
    elif args.komut == "denetim":
        cmd_denetim(args, gateway)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
