"""
Yasal Yetki, Etik ve Test Kapsamı Doğrulayıcısı (Rules of Engagement - RoE Gatekeeper)
=====================================================================================
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Bu uygulama, siber güvenlik sızma testlerinde yasal zemin (TCK 243/244, CFAA),
yazılı izin ve kapsam sınırlarını (In-Scope vs Out-of-Scope) denetleyen bir güvenlik kapısıdır.
Yetkisiz hedeflere veya yasaklı eylemlere yönelik girişimleri önceden tespit edip engeller.

Kullanım:
    python scope_validator.py --audit
    python scope_validator.py --check --target 192.168.10.50 --action PORT_SCAN
    python scope_validator.py --check --target 8.8.8.8 --action RECONNAISSANCE
"""

import os
import sys
import json
import ipaddress
import argparse
from typing import Dict, List, Any, Tuple


class ScopeException(Exception):
    """Kapsam ve yetki ihlali temel istisnası."""
    pass


class OutOfScopeTargetError(ScopeException):
    """Hedef yazılı izin belgesinde kapsam içinde tanımlanmamış."""
    pass


class ExplicitlyForbiddenTargetError(ScopeException):
    """Hedef açıkça 'Kesinlikle Kapsam Dışı' olarak belirtilmiş (Örn: Canlı sistem, Ağ omurgası)."""
    pass


class UnauthorizedActionError(ScopeException):
    """Talep edilen eylem izin verilen faaliyetler listesinde yok."""
    pass


class ForbiddenActionError(ScopeException):
    """Talep edilen eylem açıkça yasaklanmış (Örn: DoS, Veri Silme, Sosyal Mühendislik)."""
    pass


class EngagementScopeValidator:
    """
    Sızma testi öncesi yasal kapsam ve angajman kurallarını (RoE) denetleyen mekanizma.
    """

    def __init__(self, policy_file: str):
        self.policy_file = os.path.abspath(policy_file)
        self.policy: Dict[str, Any] = {}
        self.load_policy()

    def load_policy(self):
        """Kapsam belgesi JSON dosyasını okur."""
        if not os.path.exists(self.policy_file):
            raise FileNotFoundError(f"Kapsam belgesi bulunamadı: {self.policy_file}")
        with open(self.policy_file, "r", encoding="utf-8") as f:
            self.policy = json.load(f)

    def is_ip_in_network(self, ip_str: str, network_str: str) -> bool:
        """Bir IP'nin verilen CIDR ağ bloğu içinde olup olmadığını doğrular."""
        try:
            ip = ipaddress.ip_address(ip_str)
            net = ipaddress.ip_network(network_str, strict=False)
            return ip in net
        except ValueError:
            return False

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """
        Hedefin (IP veya Alan Adı) izinli kapsamda olup olmadığını denetler.
        Önce yasaklı listeye bakar, sonra kapsam içi listelere bakar.
        """
        target = target.strip().lower()

        # 1. Açıkça Yasaklı Hedef Kontrolü
        forbidden_ips = [ip.lower() for ip in self.policy.get("kesinlikle_kapsam_disi_hedefler", {}).get("ip_listesi", [])]
        forbidden_domains = [d.lower() for d in self.policy.get("kesinlikle_kapsam_disi_hedefler", {}).get("alan_adlari", [])]

        if target in forbidden_ips or target in forbidden_domains:
            raise ExplicitlyForbiddenTargetError(
                f"YASAL ALARM! Hedef '{target}' açıkça KESİNTİSİZ YASAKLANMIŞ hedefler listesindedir! "
                f"Bu hedefe yönelik herhangi bir paket göndermek TCK Madde 243/244 kapsamında suç teşkil eder."
            )

        # 2. Kapsam İçi Hedef Kontrolü
        in_scope = self.policy.get("kapsam_ici_hedefler", {})
        allowed_ips = [ip.lower() for ip in in_scope.get("ip_listesi", [])]
        allowed_cidrs = in_scope.get("cidr_bloklari", [])
        allowed_domains = [d.lower() for d in in_scope.get("alan_adlari", [])]

        # Doğrudan IP eşleşmesi
        if target in allowed_ips:
            return True, f"Hedef IP '{target}' izinli IP listesinde kayıtlı."

        # Alan adı eşleşmesi
        if target in allowed_domains:
            return True, f"Hedef alan adı '{target}' izinli alan adları listesinde kayıtlı."

        # CIDR blok eşleşmesi
        for cidr in allowed_cidrs:
            if self.is_ip_in_network(target, cidr):
                return True, f"Hedef IP '{target}', izinli {cidr} ağ bloğu içerisindedir."

        # Hiçbiri tutmadıysa -> Kapsam Dışı!
        raise OutOfScopeTargetError(
            f"ERİŞİM ENGELLENDİ: '{target}' hedefi yazılı kapsam belgesinde (RoE) YER ALMAMAKTADIR! "
            f"Yazılı izin olmadan yapılan testler yetkisiz erişim sayılır."
        )

    def validate_action(self, action: str) -> Tuple[bool, str]:
        """
        Talep edilen faaliyetin (faaliyet türü) etik ve yasal kurallara uygunluğunu denetler.
        """
        action = action.strip().upper()

        forbidden_actions = [a.upper() for a in self.policy.get("kesinlikle_yasaklanan_faaliyetler", [])]
        allowed_actions = [a.upper() for a in self.policy.get("izin_verilen_faaliyetler", [])]

        if action in forbidden_actions:
            raise ForbiddenActionError(
                f"YIKICI/YASAK EYLEM TESPİT EDİLDİ: '{action}' faaliyeti sözleşmede kesinlikle yasaklanmıştır! "
                f"(DoS, veri silme veya çalışanları manipüle etme yasaktır)."
            )

        if action not in allowed_actions:
            raise UnauthorizedActionError(
                f"TANIMSIZ/YETKİSİZ EYLEM: '{action}' faaliyeti izin verilen test metodolojisi listesinde bulunamadı."
            )

        return True, f"'{action}' faaliyeti sözleşme kapsamında onaylanmıştır."

    def authorize_execution(self, target: str, action: str) -> bool:
        """Hedef ve eylemi birlikte denetler; her iki koşul da geçerliyse onay verir."""
        self.validate_target(target)
        self.validate_action(action)
        return True


def run_comprehensive_scope_audit(policy_path: str) -> bool:
    """Tüm kapsam kurallarını pozitif ve negatif kontrollerle denetler."""
    print("=" * 80)
    print("SİBER GÜVENLİK 365: GÜN 003 — YASAL KAPSAM VE ANGAJMAN KURALLARI DENETİMİ")
    print("=" * 80)

    validator = EngagementScopeValidator(policy_path)
    print(f"[*] Kurum: {validator.policy.get('kurum_adi')}")
    print(f"[*] Belge: {validator.policy.get('belge_adi')}")
    print(f"[*] Yasal Dayanak: {validator.policy.get('yasal_dayanak')}\n")

    # 1. POZİTİF KONTROLLER
    print("--- [1. TEST BÖLÜMÜ: POZİTİF KONTROLLER (İZİNLİ FAALİYETLER)] ---")
    positives = [
        ("192.168.10.50", "PORT_SCAN"),
        ("dev-portal.acme-finans.local", "WEB_VULN_SCAN"),
        ("192.168.10.51", "SERVICE_BANNER_GRABBING")
    ]
    for target, action in positives:
        try:
            validator.authorize_execution(target, action)
            print(f"  [+] ONAYLANDI: Hedef: {target:<30} | Eylem: {action:<20} -> YASAL VE KAPSAM İÇİ")
        except Exception as e:
            print(f"  [-] HATA: İzinli eylem reddedildi: {e}")
            return False

    # 2. NEGATİF KONTROLLER
    print("\n--- [2. TEST BÖLÜMÜ: NEGATİF KONTROLLER (YASAKLI/KAPSAM DIŞI)] ---")
    negatives = [
        ("8.8.8.8", "RECONNAISSANCE", ExplicitlyForbiddenTargetError, "Yasaklı Dış IP (8.8.8.8)"),
        ("192.168.10.1", "PORT_SCAN", ExplicitlyForbiddenTargetError, "Ağ Omurga Yönlendiricisi"),
        ("canli-odeme.acme-finans.com", "WEB_VULN_SCAN", ExplicitlyForbiddenTargetError, "Canlı Ödeme Üretim Sistemi"),
        ("10.99.99.50", "PORT_SCAN", OutOfScopeTargetError, "Tanımsız/Kapsam Dışı IP"),
        ("192.168.10.50", "DOS_ATTACK", ForbiddenActionError, "Yıkıcı Hizmet Engelleme Saldırısı"),
        ("192.168.10.50", "DATA_DELETION", ForbiddenActionError, "Yıkıcı Veri Silme Faaliyeti"),
        ("192.168.10.50", "TANIMSIZ_SALDIRI", UnauthorizedActionError, "Sözleşme Dışı Eylem")
    ]

    for target, action, expected_exc, desc in negatives:
        try:
            validator.authorize_execution(target, action)
            print(f"  [-] HATA: Yasaklı eylem onay aldı! {desc} -> {target} / {action}")
            return False
        except expected_exc as e:
            print(f"  [+] BLOKE EDİLDİ (NEGATİF KONTROL BAŞARILI): [{desc}] -> {type(e).__name__}")

    print("\n" + "=" * 80)
    print("[SONUÇ] TÜM KAPSAM VE YASAL YETKİ KONTROLLERİ EKSİKSİZ DOĞRULANDI!")
    print("=" * 80)
    return True


def main():
    default_policy = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "kapsam_belgesi.json")
    parser = argparse.ArgumentParser(description="Etik, Yasal Yetki ve Test Kapsamı Denetleyicisi (Gün 003)")
    parser.add_argument("--policy", default=default_policy, help="Kapsam belgesi JSON dosyası")
    parser.add_argument("--audit", action="store_true", help="Kapsamlı yasal yetki denetimini çalıştır")
    parser.add_argument("--check", action="store_true", help="Belirli bir hedef ve eylemi sorgula")
    parser.add_argument("--target", type=str, help="Hedef IP veya alan adı")
    parser.add_argument("--action", type=str, help="Uygulanacak faaliyet/eylem adı")

    args = parser.parse_args()
    validator = EngagementScopeValidator(args.policy)

    if args.audit:
        success = run_comprehensive_scope_audit(args.policy)
        sys.exit(0 if success else 1)

    elif args.check:
        if not args.target or not args.action:
            print("[!] HATA: --check ile birlikte hem --target hem de --action belirtilmelidir.")
            sys.exit(1)
        try:
            validator.authorize_execution(args.target, args.action)
            print(f"\n[+] ONAY: '{args.target}' hedefine '{args.action}' faaliyeti uygulamak YASAL VE İZİNLİDİR.")
        except ScopeException as e:
            print(f"\n[-] ENGELLEME: {e}")
            sys.exit(2)

    else:
        # Varsayılan denetimi çalıştır
        success = run_comprehensive_scope_audit(args.policy)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
