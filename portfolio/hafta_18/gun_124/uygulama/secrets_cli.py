# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 124: Secrets Yönetimi ve Çevre Değişkenleri CLI Aracı.
Bu araç komut satırından hardcoded secret taraması yapar (CWE-798),
kasa operasyonlarını (Get/Rotate/Revoke) icra eder ve log maskelemeyi (CWE-532) test eder.
"""

# Komut satırı argümanları için argparse içe aktarılıyor
import argparse
# Sistem çıkış kodları için sys içe aktarılıyor
import sys
# JSON ayrıştırma işlemleri için json içe aktarılıyor
import json
# Dosya ve dizin denetimleri için os modülü içe aktarılıyor
import os

# Çekirdek motor sınıfları içe aktarılıyor
from secrets_management_engine import (
    SecretVaultManager,
    SecretScanner,
    SecretType,
    SecretState,
    SecretsEngineError
)


def load_vault_from_json(json_path: str, master_key: str) -> SecretVaultManager:
    """JSON yapılandırma dosyasından Secret Vault yöneticisini yükler."""
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Kasa yapılandırma dosyası bulunamadı: {json_path}")
    with open(json_path, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    vault = SecretVaultManager(
        vault_name=data.get("vault_name", "Kurumsal Kasa"),
        master_key=master_key
    )

    for s_data in data.get("secrets", []):
        vault.store_secret(
            secret_id=s_data["secret_id"],
            name=s_data["name"],
            secret_type=SecretType[s_data["secret_type"]],
            plaintext_value=s_data["value"],
            allowed_roles=s_data["allowed_roles"],
            ttl_seconds=int(s_data.get("ttl_seconds", 86400)),
            rotation_interval_days=int(s_data.get("rotation_interval_days", 30))
        )
    return vault


def handle_scan(args: argparse.Namespace) -> int:
    """Dosya veya metin üzerinde CWE-798 sabit kodlanmış anahtar taraması yapar."""
    try:
        content = ""
        if os.path.exists(args.target):
            with open(args.target, "r", encoding="utf-8", errors="ignore") as fp:
                content = fp.read()
            print(f"[*] Dosya taranıyor: {args.target}")
        else:
            content = args.target
            print("[*] Girilen metin taranıyor...")

        findings = SecretScanner.scan_text(content, entropy_threshold=args.entropy)
        if not findings:
            print("[+] TEMİZ: Hiçbir sabit kodlanmış gizli anahtar (CWE-798) tespit edilmedi.")
            return 0
        else:
            print(f"[-] TEHLİKE: {len(findings)} adet gizli veri / sızıntı tespit edildi!")
            for f in findings:
                print(f"  - [Satır {f['line_number']}] {f['detection_type']} ({f['pattern_name']}): {f['matched_sample']}")
            return 2 if args.enforce else 0
    except Exception as exc:
        print(f"[-] TARAMA HATASI: {exc}", file=sys.stderr)
        return 1


def handle_vault(args: argparse.Namespace) -> int:
    """Kasa operasyonlarını (Get / Report) yürütür."""
    try:
        vault = load_vault_from_json(args.config, master_key=args.master_key)
        if args.action == "report":
            print(vault.generate_vault_report())
            return 0
        elif args.action == "get":
            if not args.secret_id or not args.role:
                print("[-] HATA: 'get' eylemi için --secret-id ve --role zorunludur.", file=sys.stderr)
                return 1
            val = vault.get_secret(args.secret_id, requester_role=args.role)
            print(f"=== Gizli Anahtar Değeri ({args.secret_id}) ===")
            print(f"Rol: {args.role}")
            print(f"Değer: {val}")
            return 0
        elif args.action == "rotate":
            if not args.secret_id:
                print("[-] HATA: 'rotate' eylemi için --secret-id zorunludur.", file=sys.stderr)
                return 1
            meta = vault.rotate_secret(args.secret_id)
            print(f"[+] '{args.secret_id}' başarıyla rotasyona tabi tutuldu. Yeni Sürüm: v{meta.version}")
            return 0
    except SecretsEngineError as see:
        print(f"[!] KASA HATASI: {see}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[-] BEKLENMEYEN HATA: {exc}", file=sys.stderr)
        return 1


def handle_mask(args: argparse.Namespace) -> int:
    """Log kayıtlarındaki hassas anahtarları maskeler (CWE-532)."""
    try:
        vault = load_vault_from_json(args.config, master_key=args.master_key)
        masked_text = vault.mask_log_message(args.log_text)
        print("=== Maskelenmiş Log Çıktısı (CWE-532 Koruması) ===")
        print(masked_text)
        return 0
    except Exception as exc:
        print(f"[-] MASKELEME HATASI: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    """Komut satırı ana giriş noktası."""
    parser = argparse.ArgumentParser(description="Secrets Yönetimi ve Çevre Değişkenleri CLI Aracı")
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'scan' komutu
    scan_parser = subparsers.add_parser("scan", help="Kod veya yapılandırma dosyasında hardcoded secret tara")
    scan_parser.add_argument("target", help="Taranacak dosya yolu veya doğrudan metin")
    scan_parser.add_argument("--entropy", type=float, default=4.2, help="Shannon entropi eşik değeri (Varsayılan: 4.2)")
    scan_parser.add_argument("--enforce", action="store_true", help="Secret bulunursa sıfır dışı çıkış kodu dön")

    # 2. 'vault' komutu
    vault_parser = subparsers.add_parser("vault", help="Kasa operasyonlarını yönet")
    vault_parser.add_argument("config", help="Kasa yapılandırma JSON dosya yolu")
    vault_parser.add_argument("--master-key", default="AtlasMasterSecretKey2026!#", help="Kasa ana şifreleme anahtarı")
    vault_parser.add_argument("--action", choices=["get", "report", "rotate"], default="report", help="Kasa eylemi")
    vault_parser.add_argument("--secret-id", help="Erişilecek anahtar ID'si")
    vault_parser.add_argument("--role", help="Talep eden kullanıcı rolü")

    # 3. 'mask' komutu
    mask_parser = subparsers.add_parser("mask", help="Log mesajındaki hassas verileri maskele")
    mask_parser.add_argument("config", help="Kasa yapılandırma JSON dosya yolu")
    mask_parser.add_argument("log_text", help="Maskelenecek ham log metni")
    mask_parser.add_argument("--master-key", default="AtlasMasterSecretKey2026!#", help="Kasa ana anahtarı")

    args = parser.parse_args()
    if args.command == "scan":
        sys.exit(handle_scan(args))
    elif args.command == "vault":
        sys.exit(handle_vault(args))
    elif args.command == "mask":
        sys.exit(handle_mask(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
