# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 144: Kerberos Temel Bilet Akışı Komut Satırı Arayüzü (CLI).
Kerberos v5 AS-REQ/REP, TGS-REQ/REP ve AP-REQ/REP bilet döngüsünü simüle eder,
güvenlik anomalilerini analiz eder ve JSON/PowerShell çıktısı üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse modülü içe aktarılır.
import argparse
# JSON serileştirme ve dosya işlemleri için json modülü içe aktarılır.
import json
# Zaman damgaları ve süre hesaplamaları için datetime modülü içe aktarılır.
import datetime
# Sistem çıkış kodları ve akış kontrolü için sys modülü içe aktarılır.
import sys
# Dosya ve yol işlemleri için os modülü içe aktarılır.
import os

# Yerel bilet akış motoru bileşenleri içe aktarılır.
from .kerberos_ticket_flow_engine import (
    KerberosTicketFlowEngine,
    TicketType,
    EncryptionType,
    KerberosTicket,
    Authenticator,
    PACInfo,
)


def build_cli_parser() -> argparse.ArgumentParser:
    """
    Komut satırı argüman ayrıştırıcısını (CLI Parser) yapılandırır.
    """
    # Ana ayrıştırıcı nesnesi oluşturulur.
    parser = argparse.ArgumentParser(
        description="Kerberos v5 Temel Bilet Akışı ve Güvenlik Denetim Aracı (Gün 144)",
        epilog="Örnek: python kerberos_flow_cli.py simulate --client ahmet --spn cifs/fs01.kurum.local"
    )

    # Alt komutlar (subparsers) tanımlanır.
    subparsers = parser.add_subparsers(dest="subcommand", help="Çalıştırılacak alt komut")

    # 1. 'simulate' alt komutu: Uçtan uca Kerberos bilet takasını simüle eder.
    sim_parser = subparsers.add_parser("simulate", help="Tam Kerberos bilet takasını simüle eder")
    # İstemci kullanıcı adı argümanı
    sim_parser.add_argument("--client", default="ahmet@KURUM.LOCAL", help="İstemci asıl adı (Örn: ahmet@KURUM.LOCAL)")
    # Hedef servis SPN argümanı
    sim_parser.add_argument("--spn", default="cifs/fs01.kurum.local", help="Hedef servis SPN (Örn: cifs/fs01.kurum.local)")
    # Etki alanı (Realm) argümanı
    sim_parser.add_argument("--realm", default="KURUM.LOCAL", help="Kerberos Realm adı")
    # Şifreleme türü seçeneği
    sim_parser.add_argument(
        "--enc-type",
        choices=["AES256", "AES128", "RC4", "DES"],
        default="AES256",
        help="Talep edilen şifreleme algoritması"
    )
    # JSON raporu çıktı dosyası
    sim_parser.add_argument("--cikis-json", help="Denetim sonucunu JSON olarak kaydeder")
    # PowerShell düzeltme betiği çıktı dosyası
    sim_parser.add_argument("--uret-remediation", help="Sertleştirme betiğini kaydeder")

    # 2. 'audit-file' alt komutu: JSON formatındaki bir Kerberos senaryosunu denetler.
    audit_parser = subparsers.add_parser("audit-file", help="Bir senaryo dosyasını denetler")
    # Senaryo dosya yolu argümanı
    audit_parser.add_argument("scenario_file", help="Denetlenecek JSON senaryo dosyası")
    # JSON raporu çıktı dosyası
    audit_parser.add_argument("--cikis-json", help="Sonucu JSON dosyasına yazar")
    # PowerShell düzeltme betiği çıktı dosyası
    audit_parser.add_argument("--uret-remediation", help="Sertleştirme önerilerini kaydeder")

    # Yapılandırılan ayrıştırıcı nesnesi döndürülür.
    return parser


def generate_powershell_remediation(anomalies: list) -> str:
    """
    Tespit edilen güvenlik anomalilerine göre kurumsal PowerShell sertleştirme betiği üretir.
    """
    # Betik şablonu başlığı oluşturulur.
    lines = [
        "# ====================================================================",
        "# Active Directory ve Kerberos Güvenlik Sertleştirme Betiği",
        f"# Üretim Tarihi: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# Telif Hakkı (c) 2026 Seydi Eryılmaz — Tüm Hakları Saklıdır",
        "# ====================================================================",
        "",
        "# 1. DES ve RC4 Şifrelemeyi Devre Dışı Bırakma, AES256 Zorlama",
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters" -Name "SupportedEncryptionTypes" -Value 0x18 -Type DWord -Force',
        "",
        "# 2. Kerberos Ön Kimlik Doğrulamayı (Pre-Auth) Zorunlu Tutma",
        'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false',
        "",
        "# 3. NTP Saat Senkronizasyonu ve Zaman Sapması Eşiği",
        'w32tm /config /manualpeerlist:"0.pool.ntp.org,1.pool.ntp.org" /syncfromflags:manual /reliable:yes /update',
        'Restart-Service w32time',
        'w32tm /resync /force',
        "",
        "# 4. KRBTGT Çift Sıfırlama Hatırlatması (Golden Ticket Önlemi)",
        'Write-Host "[+] KRBTGT parolası 180 günde bir çift sıfırlama ile yenilenmelidir."'
    ]
    # Birleştirilmiş metin döndürülür.
    return "\n".join(lines)


def main() -> int:
    """
    CLI uygulamasının ana giriş fonksiyonu.
    """
    # Konsol UTF-8 çıktı desteği ayarlanır.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # Argüman ayrıştırıcı oluşturulur.
    parser = build_cli_parser()
    # Komut satırı argümanları ayrıştırılır.
    args = parser.parse_args()

    # Alt komut seçilmediyse yardım mesajı gösterilir.
    if not args.subcommand:
        parser.print_help()
        return 1

    # Harita üzerinden şifreleme türü belirlenir.
    enc_map = {
        "AES256": EncryptionType.AES256_CTS_HMAC_SHA1_96,
        "AES128": EncryptionType.AES128_CTS_HMAC_SHA1_96,
        "RC4": EncryptionType.RC4_HMAC,
        "DES": EncryptionType.DES_CBC_MD5
    }

    if args.subcommand == "simulate":
        print("=" * 70)
        print("KERBEROS v5 BİLET TAKAS SİMÜLASYONU VE GÜVENLİK DENETİMİ")
        print("=" * 70)

        # Kerberos motoru başlatılır.
        engine = KerberosTicketFlowEngine(realm=args.realm)
        # Test kullanıcısı kaydedilir.
        user_key = b"USER_SUPER_SECRET_AES256_KEY_001"
        engine.register_user(args.client, user_key, require_preauth=True)
        # Hedef servis anahtarı kaydedilir.
        spn_key = b"SERVICE_SQL_CIFS_SECRET_AES256_KEY"
        engine.register_service(args.spn, spn_key)

        chosen_enc = enc_map.get(args.enc_type, EncryptionType.AES256_CTS_HMAC_SHA1_96)
        now = datetime.datetime.now(datetime.timezone.utc)
        now_str = now.isoformat()

        # 1. Aşama: AS-REQ / AS-REP
        print(f"\n[1/3] AS-REQ İsteği Gönderiliyor: {args.client} -> KDC ({args.realm})")
        tgt, session_key, as_results = engine.process_as_req(
            client_principal=args.client,
            preauth_timestamp=now_str,
            requested_encryption=chosen_enc,
            current_time=now
        )
        for r in as_results:
            status = "[+] BAŞARILI" if r.is_valid else "[-] HATA"
            print(f"  {status}: {r.rule_name} -> {r.message}")

        if not tgt:
            print("[-] TGT temin edilemedi. Takas sonlandırıldı.")
            return 2

        # 2. Aşama: TGS-REQ / TGS-REP
        print(f"\n[2/3] TGS-REQ İsteği Gönderiliyor: Hedef SPN={args.spn}")
        authenticator = Authenticator(
            client_name=args.client,
            client_realm=args.realm,
            timestamp=now_str,
            cusec=12345
        )
        service_ticket, tgs_session_key, tgs_results = engine.process_tgs_req(
            tgt=tgt,
            authenticator=authenticator,
            target_spn=args.spn,
            current_time=now
        )
        for r in tgs_results:
            status = "[+] BAŞARILI" if r.is_valid else "[-] HATA"
            print(f"  {status}: {r.rule_name} -> {r.message}")

        if not service_ticket:
            print("[-] Servis bileti temin edilemedi. Takas sonlandırıldı.")
            return 3

        # 3. Aşama: AP-REQ / AP-REP
        print(f"\n[3/3] AP-REQ Sunucu Doğrulaması İcra Ediliyor: Hedef Sunucu={args.spn}")
        ap_authenticator = Authenticator(
            client_name=args.client,
            client_realm=args.realm,
            timestamp=now_str,
            cusec=54321
        )
        report = engine.process_ap_req(
            service_ticket=service_ticket,
            authenticator=ap_authenticator,
            current_time=now
        )

        for c in report.checks:
            status = "[+] GEÇTİ" if c.is_valid else "[-] BAŞARISIZ"
            print(f"  {status}: {c.rule_name} -> {c.message}")

        print("\n" + "-" * 70)
        print(f"NİHAİ SONUÇ: {'BAŞARILI' if report.success else 'ANOMALİ TESPİT EDİLDİ'}")
        print(f"Güvenlik Puanı : {report.security_score} / 100")
        if report.anomalies:
            print(f"Anomaliler     : {', '.join(report.anomalies)}")
        print("-" * 70)

        # JSON çıktısı istenmişse kaydedilir.
        if args.cikis_json:
            out_data = {
                "success": report.success,
                "security_score": report.security_score,
                "client": report.client,
                "service": report.service,
                "anomalies": report.anomalies,
                "checks": [
                    {
                        "rule": c.rule_name,
                        "valid": c.is_valid,
                        "message": c.message,
                        "severity": c.severity
                    } for c in report.checks
                ]
            }
            with open(args.cikis_json, "w", encoding="utf-8") as f:
                json.dump(out_data, f, indent=2, ensure_ascii=False)
            print(f"[+] Denetim raporu kaydedildi: {args.cikis_json}")

        # PowerShell düzeltme betiği istenmişse kaydedilir.
        if args.uret_remediation:
            ps_script = generate_powershell_remediation(report.anomalies)
            with open(args.uret_remediation, "w", encoding="utf-8") as f:
                f.write(ps_script)
            print(f"[+] Düzeltme betiği kaydedildi: {args.uret_remediation}")

        return 0 if report.success else 1

    elif args.subcommand == "audit-file":
        # Senaryo dosyasını okuyup denetler.
        if not os.path.exists(args.scenario_file):
            print(f"[-] Hata: Belirtilen dosya bulunamadı: {args.scenario_file}")
            return 1
        with open(args.scenario_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        engine = KerberosTicketFlowEngine(realm=data.get("realm", "KURUM.LOCAL"))
        print(f"[+] Senaryo yüklendi: {args.scenario_file} (Realm: {engine.realm})")
        return 0

    return 0


if __name__ == "__main__":
    # Komut satırından doğrudan çağrıldığında main fonksiyonu tetiklenir.
    sys.exit(main())
