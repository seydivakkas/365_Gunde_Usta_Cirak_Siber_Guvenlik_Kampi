# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 122: Savunma Derinliği ve Kontrol Tipleri CLI Aracı.
Bu araç, komut satırından 7 katmanlı savunma mimarisini denetler,
katman boşluğu (gap) ve tek hata noktası (SPoF) analizini yapar,
siber saldırı zinciri (kill chain) simülasyonunu icra eder.
"""

# Komut satırı bağımsız değişkenlerini işlemek için argparse içe aktarılıyor
import argparse
# Çıkış kodları ve akışlar için sys içe aktarılıyor
import sys
# JSON dosyalarını ayrıştırmak için json içe aktarılıyor
import json
# Dosya kontrolü için os modülü içe aktarılıyor
import os

# Çekirdek motor sınıfları içe aktarılıyor
from defense_in_depth_engine import (
    DefenseInDepthManager,
    DefenseLayer,
    ControlType,
    AttackCategory,
    LayerControl,
    AttackStep,
    AttackScenario,
    DefenseInDepthError
)


def load_architecture_from_json(json_path: str) -> DefenseInDepthManager:
    """JSON yapılandırma dosyasından savunma derinliği mimarisini yükler."""
    # Dosya varlığı kontrol edilir
    if not os.path.exists(json_path):
        # Dosya yoksa istisna fırlatılır
        raise FileNotFoundError(f"Mimari dosyası bulunamadı: {json_path}")
    # Dosya okunur
    with open(json_path, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    # Yönetici nesnesi oluşturulur
    manager = DefenseInDepthManager(architecture_name=data.get("architecture_name", "Kurumsal Mimari"))
    # Kontroller yüklenir
    for c_data in data.get("controls", []):
        # Desteklenen saldırı kategorileri çözümlenir
        attacks = [AttackCategory[a] for a in c_data.get("supported_attacks", [])]
        ctrl = LayerControl(
            control_id=c_data["control_id"],
            name=c_data["name"],
            layer=DefenseLayer[c_data["layer"]],
            control_type=ControlType[c_data["control_type"]],
            effectiveness=float(c_data.get("effectiveness", 0.8)),
            supported_attacks=attacks,
            is_active=bool(c_data.get("is_active", True))
        )
        manager.add_control(ctrl)
    # Senaryolar yüklenir
    for s_data in data.get("scenarios", []):
        cat = AttackCategory[s_data["category"]]
        steps = []
        for st in s_data.get("steps", []):
            step = AttackStep(
                step_number=int(st["step_number"]),
                target_layer=DefenseLayer[st["target_layer"]],
                technique=st.get("technique", "Generic Exploit"),
                evasion_power=float(st.get("evasion_power", 0.5))
            )
            steps.append(step)
        scenario = AttackScenario(
            scenario_id=s_data["scenario_id"],
            name=s_data["name"],
            category=cat,
            steps=steps
        )
        manager.add_scenario(scenario)
    return manager


def handle_audit(args: argparse.Namespace) -> int:
    """Mimari dayanıklılık denetimini icra eder."""
    try:
        manager = load_architecture_from_json(args.config)
        if args.format == "markdown":
            print(manager.generate_defense_matrix_report())
        elif args.format == "json":
            print(json.dumps(manager.export_summary_dict(), ensure_ascii=False, indent=2))
        else:
            print(f"=== {manager.architecture_name} Savunma Derinliği Denetimi ===")
            passed, flaws = manager.audit_architecture_resilience()
            if passed:
                print("[+] MİMARİ DAYANIKLILIK DURUMU: BAŞARILI (Tüm katmanlar korumalı ve izleniyor).")
            else:
                print(f"[-] MİMARİ DAYANIKLILIK DURUMU: ZAYIF ({len(flaws)} zaafiyet bulundu)!")
                for flaw in flaws:
                    print(f"  - {flaw}")
        if args.enforce:
            manager.enforce_resilience()
        return 0
    except DefenseInDepthError as die:
        print(f"[!] HATA: {die}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[-] BEKLENMEYEN HATA: {exc}", file=sys.stderr)
        return 1


def handle_simulate(args: argparse.Namespace) -> int:
    """Kayıtlı bir saldırı senaryosunu mimari üzerinde simüle eder."""
    try:
        manager = load_architecture_from_json(args.config)
        outcome = manager.simulate_attack(args.scenario_id)
        print(f"=== Saldırı Simülasyonu: [{outcome.scenario_id}] ===")
        print(f"Saldırı Durduruldu mu?: {'EVET' if outcome.stopped else 'HAYIR'}")
        if outcome.stopped and outcome.stopped_at_layer:
            print(f"Püskürtüldüğü Katman: {outcome.stopped_at_layer.value}")
        print(f"Delinen Katman Sayısı: {outcome.total_layers_penetrated}")
        print(f"Veri İhlal Edildi mi?: {'EVET (KRİTİK VERİ SIZDI)' if outcome.data_compromised else 'HAYIR'}")
        print("\n--- Katman Bazlı Olay Detayları ---")
        for r in outcome.layer_results:
            status = "DURDURULDU" if r.prevented else "DELİNDİ"
            print(f"Katman [{r.layer.value}]: {status}")
            for msg in r.log_messages:
                print(f"   {msg}")
        return 0 if outcome.stopped else 3
    except Exception as exc:
        print(f"[-] SİMÜLASYON HATASI: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    """Komut satırı ana giriş noktası."""
    parser = argparse.ArgumentParser(description="Savunma Derinliği ve Kontrol Tipleri CLI Aracı")
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'audit' komutu
    audit_parser = subparsers.add_parser("audit", help="7 katmanlı savunma mimarisini denetle")
    audit_parser.add_argument("config", help="Mimari yapılandırma JSON dosya yolu")
    audit_parser.add_argument("--format", choices=["text", "markdown", "json"], default="text", help="Çıktı formatı")
    audit_parser.add_argument("--enforce", action="store_true", help="Katman boşluğu veya SPoF durumunda hata fırlat")

    # 2. 'simulate' komutu
    sim_parser = subparsers.add_parser("simulate", help="Mimari üzerinde saldırı senaryosu koştur")
    sim_parser.add_argument("config", help="Mimari yapılandırma JSON dosya yolu")
    sim_parser.add_argument("scenario_id", help="Simüle edilecek senaryo kimliği")

    args = parser.parse_args()
    if args.command == "audit":
        sys.exit(handle_audit(args))
    elif args.command == "simulate":
        sys.exit(handle_simulate(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
