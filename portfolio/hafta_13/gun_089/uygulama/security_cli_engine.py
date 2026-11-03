# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G089: Güvenlik Odaklı Argparse ve CLI Tasarım Motoru.
Bu modül; kurumsal siber güvenlik araçları için katı girdi doğrulama, alt komutlar (subparsers),
karşılıklı dışlayan parametre grupları (mutually exclusive groups), dizin atlama koruması (CWE-22),
ve DoS sınırlamalarıyla güçlendirilmiş güvenli bir CLI altyapısı sunar.
"""

import argparse  # Komut satiri ayrastirici standart kutuphanesi
import hashlib  # Kriptografik ozet hesaplama modulu
from pathlib import Path  # Dosya sistemi yollari yonetimi modulu
import re  # Duzenli ifadeler modulu
import sys  # Sistem parametreleri modulu
from typing import Any, Dict, List, Optional  # Tip ipuclari modulu


class CliAuditorException(Exception):
    """CLI guvenlik motoru temel istisna sinifi."""
    pass


class InvalidCliArgumentException(CliAuditorException):
    """Gecersiz veya guvenlik kuralina uymayan CLI argumani girildiginde firlatilir."""
    pass


class CliPathTraversalException(CliAuditorException):
    """Dosya yolu parametresinde dizin atlama (..) girisimi tespit edildiginde firlatilir."""
    pass


class CliPortOutOfRangeException(CliAuditorException):
    """Ağ portu parametresi [1, 65535] araligi disinda oldugunda firlatilir."""
    pass


class CliNullByteException(CliAuditorException):
    """CLI argumaninda zararli null-byte (0x00) tespit edildiginde firlatilir."""
    pass


class CliOversizedPayloadException(CliAuditorException):
    """Arguman uzunlugu veya sayisi DoS tavan limitini astiginda firlatilir."""
    pass


class CliMissingRequiredSubcommandException(CliAuditorException):
    """Zorunlu alt komut (subcommand) belirtilmediginde firlatilir."""
    pass


class CliMutuallyExclusiveConflictException(CliAuditorException):
    """Ayni anda calisamayacak iki zit bayrak girildiginde firlatilir."""
    pass


def validate_cli_port(val: str) -> int:
    """Port parametresini tam sayi ve [1, 65535] araligi acisindan dogrular."""
    try:
        port = int(val)  # Tamsayiya donusturulur
    except ValueError:
        raise CliPortOutOfRangeException(f"Port sayisal bir tam sayi olmalidir: '{val}'")
    if not (1 <= port <= 65535):  # Gecerli port araligi kontrol edilir
        raise CliPortOutOfRangeException(f"Port degeri [{port}] izin verilen [1, 65535] araligi disindadir.")
    return port  # Onayli port degeri dondurulur


def validate_cli_file_path(val: str) -> Path:
    """Dosya yolu parametresini dizin atlama (CWE-22) ve varlik acisindan dogrular."""
    if "\x00" in val:  # Null byte kontrolu
        raise CliNullByteException("Dosya yolunda zararli null byte tespit edildi.")

    # Dizin atlama (..) denetimi
    normalized_parts = Path(val).as_posix().split("/")
    if ".." in normalized_parts:
        raise CliPathTraversalException(f"Dosya yolunda guvensiz dizin atlama (..) tespit edildi: '{val}'")

    path_obj = Path(val)  # Path nesnesi olusturulur
    if not path_obj.exists():  # Dosya sisteminde var mi
        raise InvalidCliArgumentException(f"Belirtilen dosya mevcut degil: '{val}'")

    return path_obj  # Gecerli dosya nesnesi dondurulur


def validate_cli_host(val: str) -> str:
    """Hedef host veya IP parametresini komut enjeksiyonu karakterlerine karsi dogrular."""
    if "\x00" in val:
        raise CliNullByteException("Host parametresinde zararli null byte tespit edildi.")
    if len(val) > 253:  # RFC standartlarina uygun azami host uzunlugu
        raise CliOversizedPayloadException("Host uzunlugu 253 karakter limitini asamaz.")

    # Yalnizca guvenli alfanumerik, nokta, cizgi ve alt cizgi karakterleri
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", val):
        raise InvalidCliArgumentException(f"Host parametresi gecersiz karakterler iceriyor: '{val}'")

    return val  # Onayli host dizesi


class SecurityArgumentParser(argparse.ArgumentParser):
    """
    Standart argparse.ArgumentParser sinifini genisleterek sys.exit(2) yerine
    yapilandirilmis guvenlik istisnalari firlatan ozel ayrastirici sinif.
    """

    def error(self, message: str) -> None:
        """Hata mesajini analiz eder ve ilgili guvenlik istisnasina donusturur."""
        lower_msg = message.lower()  # Kucuk harfe donusturulur
        if "the following arguments are required: subcommand" in lower_msg or "subcommand is required" in lower_msg:
            raise CliMissingRequiredSubcommandException("Zorunlu alt komut (subcommand) belirtilmedi.")
        elif "not allowed with argument" in lower_msg or "mutually exclusive" in lower_msg:
            raise CliMutuallyExclusiveConflictException(f"Karsilikli dislayan parametre cakismasi: {message}")
        elif "invalid choice" in lower_msg:
            raise InvalidCliArgumentException(f"Gecersiz secim parametresi: {message}")
        else:
            raise InvalidCliArgumentException(f"CLI soz dizimi hatasi: {message}")


class CliSecurityParserFactory:
    """Kurumsal CLI komut hiyerarsisini insa eden fabrika bileseni."""

    @classmethod
    def create_security_parser(cls) -> SecurityArgumentParser:
        """Guvenlik tarama, denetim ve ozetleme alt komutlarini iceren ana ayrastiriciyi uretir."""
        # Ortak Parametreler Ebeveyn Ayrastiricisi (Parent Parser)
        common_parent = argparse.ArgumentParser(add_help=False)
        common_parent.add_argument("-v", "--verbose", action="store_true", help="Ayrintili calisma loglarini gosterir.")
        common_parent.add_argument("--json-output", action="store_true", help="Ciktilari JSON formatinda dondurur.")

        parser = SecurityArgumentParser(
            prog="security_cli",
            parents=[common_parent],
            description="G089: Kurumsal Siber Guvenlik CLI Araci ve Argparse Mimarisi.",
            epilog="Guvenlik Kurali: Tum girdiler katı dogrulama ve sinir kontrollerine tabidir."
        )

        # Alt Komut Yoneticisi (Subparsers)
        subparsers = parser.add_subparsers(
            dest="subcommand",
            required=True,
            help="Calistirilacak guvenlik alt gorevi (scan | audit | hash)"
        )

        # 1. ALT KOMUT: scan (Ağ ve Port Taraması)
        scan_parser = subparsers.add_parser("scan", parents=[common_parent], help="Hedef sunucu ve port guvenlik taramasi.")
        scan_parser.add_argument("--host", required=True, type=validate_cli_host, help="Hedef IP veya alan adi.")
        scan_parser.add_argument("--port", required=True, type=validate_cli_port, help="Hedef port numarasi (1-65535).")
        scan_parser.add_argument("--mode", choices=["stealth", "fast", "thorough"], default="fast", help="Tarama profili.")

        # Karsilikli Dislayan Grup: --fast ve --deep ayni anda verilemez!
        scan_mode_group = scan_parser.add_mutually_exclusive_group(required=False)
        scan_mode_group.add_argument("--fast", action="store_true", help="Hizli yuzeysel tarama modu.")
        scan_mode_group.add_argument("--deep", action="store_true", help="Derinlemesine ayrintili tarama modu.")

        # 2. ALT KOMUT: audit (Dosya Guvenlik Denetimi)
        audit_parser = subparsers.add_parser("audit", parents=[common_parent], help="Hedef dosya ve betik guvenlik denetimi.")
        audit_parser.add_argument("--file", required=True, type=validate_cli_file_path, help="Denetlenecek dosya yolu.")
        audit_parser.add_argument("--strict", action="store_true", help="Kati hata firlatma modunu aktif eder.")

        # 3. ALT KOMUT: hash (Kriptografik Ozet Hesaplama)
        hash_parser = subparsers.add_parser("hash", parents=[common_parent], help="Dosya butunlugu icin guvenli ozet hesaplama.")
        hash_parser.add_argument("--file", required=True, type=validate_cli_file_path, help="Ozeti cikarilacak dosya.")
        hash_parser.add_argument(
            "--algo",
            choices=["sha256", "sha384", "sha512"],
            default="sha256",
            help="Guvenli ozet algoritmasi (Zayif md5/sha1 engellenmistir)."
        )

        return parser  # Hazirlanmis guvenli ayrastirici nesnesi dondurulur


class SecurityCliEngine:
    """
    CLI Guvenlik Denetim ve Yurutme Motoru (Façade Pattern).
    Arguman on-filtrelemesini, ayrastirmayi ve alt komut is yurutumunu yonetir.
    """
    __test__ = False  # pytest tarafindan test sinifi olarak toplanmasi onlenir

    MAX_ARG_COUNT = 100  # Azami arguman sayisi tavanı (DoS korumasi)
    MAX_ARG_LENGTH = 4096  # Azami tekil arguman uzunlugu (DoS korumasi)

    def __init__(self):
        self.parser = CliSecurityParserFactory.create_security_parser()  # Ayrastirici hazirlanir
        self.execution_counter = 0  # Yurutme sayaci

    def sanitize_raw_arguments(self, raw_args: List[str]) -> List[str]:
        """Ham CLI argumanlarini DoS ve null-byte acisindan on-denetimden gecirir."""
        if len(raw_args) > self.MAX_ARG_COUNT:
            raise CliOversizedPayloadException(
                f"Arguman sayisi guvenli limit olan {self.MAX_ARG_COUNT} degerini asti (Verilen: {len(raw_args)})."
            )

        sanitized_args: List[str] = []
        for arg in raw_args:
            if not isinstance(arg, str):
                arg = str(arg)
            if "\x00" in arg:
                raise CliNullByteException("CLI argumaninda zararli null-byte (0x00) tespit edildi.")
            if len(arg) > self.MAX_ARG_LENGTH:
                raise CliOversizedPayloadException(
                    f"Arguman uzunlugu {self.MAX_ARG_LENGTH} karakter limitini asti (Uzunluk: {len(arg)})."
                )
            sanitized_args.append(arg)

        return sanitized_args

    def parse_arguments(self, args_list: List[str]) -> argparse.Namespace:
        """Arguman listesini filtreler ve guvenli namespace nesnesi dondurur."""
        clean_args = self.sanitize_raw_arguments(args_list)  # On temizlik
        if not clean_args:
            raise CliMissingRequiredSubcommandException("Zorunlu alt komut girilmedi.")
        return self.parser.parse_args(clean_args)  # Ayrastirici calistirilir

    def execute_cli_action(self, parsed_args: argparse.Namespace) -> Dict[str, Any]:
        """Ayrastirilan komutu ilgili guvenlik mantigina yonlendirir ve sonuc uretir."""
        self.execution_counter += 1
        subcmd = getattr(parsed_args, "subcommand", None)

        if subcmd == "scan":
            mode_desc = "deep" if getattr(parsed_args, "deep", False) else ("fast" if getattr(parsed_args, "fast", False) else parsed_args.mode)
            return {
                "action": "scan",
                "host": parsed_args.host,
                "port": parsed_args.port,
                "mode": mode_desc,
                "status": "COMPLETED",
                "message": f"Port {parsed_args.port} uzerinde {mode_desc} tarama tamamlandi."
            }

        elif subcmd == "audit":
            file_path: Path = parsed_args.file
            file_size = file_path.stat().st_size
            return {
                "action": "audit",
                "file": file_path.as_posix(),
                "file_size_bytes": file_size,
                "strict_mode": parsed_args.strict,
                "status": "SECURE",
                "message": f"Dosya '{file_path.name}' guvenlik denetiminden gecti."
            }

        elif subcmd == "hash":
            file_path: Path = parsed_args.file
            algo_name: str = parsed_args.algo.lower()
            hasher = getattr(hashlib, algo_name)()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
            return {
                "action": "hash",
                "file": file_path.as_posix(),
                "algorithm": algo_name.upper(),
                "digest": digest,
                "status": "VERIFIED"
            }

        raise InvalidCliArgumentException(f"Desteklenmeyen alt komut eylemi: '{subcmd}'")
