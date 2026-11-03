# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 121: Risk Skorlama ve Kontrol Seçimi CLI Aracı.
Bu araç, komut satırından risk kütüklerini değerlendirir, NIST/CIS kontrollerini doğrular,
finansal kayıp ve ROSI hesaplamalarını gerçekleştirir.
"""

# Komut satırı bağımsız değişkenlerini işlemek için argparse içe aktarılıyor
import argparse
# Sistem çıkış kodları ve argüman erişimi için sys içe aktarılıyor
import sys
# JSON dosyalarını okumak ve serileştirmek için json içe aktarılıyor
import json
# Dosya varlığı kontrolleri için os modülü içe aktarılıyor
import os
# Çekirdek risk motoru sınıfları içe aktarılıyor
from risk_control_engine import (
    RiskAssessmentManager,
    SecurityControl,
    RiskItem,
    RiskTreatmentStrategy,
    ControlFamily,
    ControlType,
    RiskAppetiteExceededError
)


def load_model_from_json(json_path: str) -> RiskAssessmentManager:
    """JSON yapılandırma dosyasından kurumsal risk modelini yükler."""
    # Dosya varlığı kontrol edilir
    if not os.path.exists(json_path):
        # Dosya yoksa hata fırlatılır
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {json_path}")
    # JSON dosyası UTF-8 olarak okunur
    with open(json_path, "r", encoding="utf-8") as fp:
        # JSON verisi sözlüğe dönüştürülür
        data = json.load(fp)
    # Risk yöneticisi nesnesi oluşturulur
    manager = RiskAssessmentManager(
        organization_name=data.get("organization", "Bilinmeyen Kurum"),
        risk_appetite_score=int(data.get("risk_appetite_score", 10)),
        max_acceptable_ale=float(data.get("max_acceptable_ale", 50000.0))
    )
    # Kontroller kataloğu döngüyle eklenir
    for c_data in data.get("controls_catalog", []):
        # Güvenlik kontrolü nesnesi inşa edilir
        control = SecurityControl(
            control_id=c_data["control_id"],
            name=c_data["name"],
            family=ControlFamily[c_data.get("family", "AC")],
            control_type=ControlType[c_data.get("control_type", "PREVENTIVE")],
            annual_cost=float(c_data.get("annual_cost", 0.0)),
            implementation_cost=float(c_data.get("implementation_cost", 0.0)),
            effectiveness_ratio=float(c_data.get("effectiveness_ratio", 0.5)),
            lifecycle_years=int(c_data.get("lifecycle_years", 3))
        )
        # Kontrol kataloğa kaydedilir
        manager.register_control(control)
    # Risk öğeleri döngüyle eklenir
    for r_data in data.get("risks", []):
        # Strateji enum değeri çözümlenir
        strat_str = r_data.get("treatment_strategy", "MITIGATE")
        # Strateji enum nesnesi alınır
        strategy = RiskTreatmentStrategy[strat_str]
        # Risk öğesi nesnesi inşa edilir
        risk = RiskItem(
            risk_id=r_data["risk_id"],
            title=r_data["title"],
            description=r_data.get("description", ""),
            asset_name=r_data["asset_name"],
            asset_value=float(r_data.get("asset_value", 100000.0)),
            exposure_factor=float(r_data.get("exposure_factor", 0.5)),
            annualized_rate_of_occurrence=float(r_data.get("annualized_rate_of_occurrence", 1.0)),
            likelihood=int(r_data.get("likelihood", 3)),
            impact=int(r_data.get("impact", 3)),
            treatment_strategy=strategy,
            executive_sign_off=bool(r_data.get("executive_sign_off", False)),
            sign_off_notes=r_data.get("sign_off_notes", "")
        )
        # Risk envantere kaydedilir
        manager.register_risk(risk)
        # Riskin uygulanacak kontrol kimlikleri atanır
        for cid in r_data.get("assigned_control_ids", []):
            # Kontrol riske atanır
            manager.assign_control_to_risk(risk.risk_id, cid)
    # Tamamlanan yönetici nesnesi döndürülür
    return manager


def handle_evaluate(args: argparse.Namespace) -> int:
    """Risk değerlendirmesi komutunu çalıştırır."""
    try:
        # Model JSON dosyasından yüklenir
        manager = load_model_from_json(args.config)
        # İstenen çıktı formatına göre işlenir
        if args.format == "markdown":
            # Markdown raporu üretilir
            report = manager.generate_executive_report()
            # Ekrana yazdırılır
            print(report)
        elif args.format == "json":
            # JSON sözlüğü dışa aktarılır
            summary = manager.export_summary_dict()
            # Ekrana girintili JSON basılır
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        else:
            # Standart metin özeti basılır
            print(f"=== {manager.organization_name} Risk Değerlendirme Özeti ===")
            print(f"Tanımlı Risk Sayısı: {len(manager.risks)}")
            print(f"Tanımlı Kontrol Sayısı: {len(manager.controls_catalog)}")
            # Her bir riskin özet skorları yazdırılır
            for r_id, r in manager.risks.items():
                print(f"[{r_id}] {r.title} | Doğal: {r.get_inherent_score()} ({r.get_inherent_level().value}) "
                      f"-> Artık: {r.get_residual_score()} ({r.get_residual_level().value}) | ROSI: %{r.calculate_rosi():.1f}")
            # Yönetişim kontrolü yapılır
            passed, violations = manager.validate_corporate_risk_governance()
            if passed:
                print("\n[+] Yönetişim Durumu: BAŞARILI (Riskler tolerans sınırları içinde).")
            else:
                print(f"\n[-] Yönetişim Uyarısı: {len(violations)} adet ihlal tespit edildi!")
        # Eğer zorunlu doğrulama istendiyse ve ihlal varsa sıfır dışı dönülür
        if args.enforce:
            manager.enforce_readiness()
        # Başarılı çıkış kodu
        return 0
    except RiskAppetiteExceededError as rae:
        # Risk iştahı aşıldığında hata basılır
        print(f"[!] HATA: {rae}", file=sys.stderr)
        # Hata çıkış kodu döndürülür
        return 2
    except Exception as exc:
        # Genel istisna yakalanır
        print(f"[-] BEKLENMEYEN HATA: {exc}", file=sys.stderr)
        # Hata kodu döndürülür
        return 1


def handle_rosi(args: argparse.Namespace) -> int:
    """Hızlı ROSI ve finansal kayıp hesaplaması yapar."""
    # Varlık değeri alınır
    asset_val = args.asset_value
    # Maruz kalma faktörü alınır
    ef = args.ef
    # Yıllık gerçekleşme oranı alınır
    aro = args.aro
    # Kontrol maliyeti alınır
    cost = args.cost
    # Kontrol etkinliği alınır
    eff = args.effectiveness
    # SLE hesaplanır
    sle = asset_val * ef
    # Doğal ALE hesaplanır
    inherent_ale = sle * aro
    # Artık ALE hesaplanır
    residual_ale = inherent_ale * (1.0 - eff)
    # Önlenen kayıp hesaplanır
    mitigated = inherent_ale - residual_ale
    # Net tasarruf hesaplanır
    net_benefit = mitigated - cost
    # ROSI yüzdesi hesaplanır
    rosi = (net_benefit / cost * 100.0) if cost > 0 else 0.0
    # Sonuçlar ekrana yazdırılır
    print("=== Finansal Risk ve ROSI Analizi ===")
    print(f"Tekil Kayıp Beklentisi (SLE): ${sle:,.2f}")
    print(f"Doğal Yıllık Kayıp Beklentisi (Inherent ALE): ${inherent_ale:,.2f}")
    print(f"Artık Yıllık Kayıp Beklentisi (Residual ALE): ${residual_ale:,.2f}")
    print(f"Önlenen Yıllık Kayıp: ${mitigated:,.2f}")
    print(f"Yıllık Kontrol Yatırımı: ${cost:,.2f}")
    print(f"Net Tasarruf / Kazanç: ${net_benefit:,.2f}")
    print(f"Yatırım Getirisi (ROSI): %{rosi:,.2f}")
    # Başarılı kod döndürülür
    return 0


def main() -> None:
    """Komut satırı ana giriş noktası."""
    # Ana ayrıştırıcı oluşturulur
    parser = argparse.ArgumentParser(description="Kurumsal Risk Skorlama ve Kontrol Seçimi CLI Aracı")
    # Alt komutlar için subparser tanımlanır
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")
    # 1. 'evaluate' komutu
    eval_parser = subparsers.add_parser("evaluate", help="Risk modelini ve kontrolleri değerlendir")
    eval_parser.add_argument("config", help="Risk ve kontrol yapılandırma JSON dosya yolu")
    eval_parser.add_argument("--format", choices=["text", "markdown", "json"], default="text", help="Çıktı formatı")
    eval_parser.add_argument("--enforce", action="store_true", help="Risk iştahı aşıldığında hata fırlat")
    # 2. 'rosi' komutu
    rosi_parser = subparsers.add_parser("rosi", help="Hızlı SLE/ALE ve ROSI hesapla")
    rosi_parser.add_argument("--asset-value", type=float, required=True, help="Varlık değeri ($)")
    rosi_parser.add_argument("--ef", type=float, required=True, help="Maruz kalma faktörü (0.0 - 1.0)")
    rosi_parser.add_argument("--aro", type=float, required=True, help="Yıllık gerçekleşme oranı (ARO)")
    rosi_parser.add_argument("--cost", type=float, required=True, help="Kontrol yıllık maliyeti ($)")
    rosi_parser.add_argument("--effectiveness", type=float, required=True, help="Kontrol etkinlik oranı (0.0 - 1.0)")
    # Argümanlar ayrıştırılır
    args = parser.parse_args()
    # Komut seçimine göre yönlendirme yapılır
    if args.command == "evaluate":
        sys.exit(handle_evaluate(args))
    elif args.command == "rosi":
        sys.exit(handle_rosi(args))
    else:
        parser.print_help()
        sys.exit(1)


# Betik doğrudan çalıştırıldığında main() çağrılır
if __name__ == "__main__":
    main()
