# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 18 / Gün 120: STRIDE Tehdit Modelleme ve DREAD Risk Analiz CLI Aracı.
Sistem mimarisi üzerinde DFD bileşenlerini modeller, tehditleri türetir
ve tedbir (Mitigation) yeterliliğini denetler.
"""

# Komut satırı argümanları ayrıştırması için argparse kütüphanesi
import argparse
# JSON veri işleme için json modülü
import json
# Çıkış kodları için sys modülü
import sys
# Dosya işlemleri için os modülü
import os

# Çekirdek STRIDE motorunun içe aktarılması
from uygulama.stride_threat_engine import (
    STRIDEThreatEngine,
    ElementType,
    STRIDECategory,
    DREADScore,
    STRIDEModelingSecurityError
)


def build_sample_architecture_engine() -> STRIDEThreatEngine:
    """Örnek bir modern e-ticaret / ödeme mimarisi modeli inşa eder."""
    engine = STRIDEThreatEngine(system_name="Global Payment Gateway")

    # 1. DFD Elemanları Tanımlanır
    # Dış Varlık: Kullanıcı Tarayıcısı (Internet Güven Bölgesi)
    engine.add_element("E1_BROWSER", "Kullanıcı Web Tarayıcısı", ElementType.EXTERNAL_ENTITY, "Internet")
    # Süreç: API Ağ Geçidi (DMZ Güven Bölgesi)
    engine.add_element("P1_APIGW", "Ters Vekil API Ağ Geçidi", ElementType.PROCESS, "DMZ")
    # Süreç: Ödeme İşleme Mikroservisi (İç Kurumsal Ağ)
    engine.add_element("P2_PAYMENT_SVC", "Ödeme Mikroservisi", ElementType.PROCESS, "Intranet")
    # Veri Deposu: Kredi Kartı ve Bakiye Veritabanı (Güvenli Çekirdek)
    engine.add_element("D1_CARD_DB", "Kredi Kartı Veritabanı", ElementType.DATA_STORE, "Secure_Core")

    # 2. Veri Akışları Tanımlanır
    # Internet -> DMZ (Güven Sınırı Aşımı Var)
    engine.add_data_flow("F1_USER_REQ", "HTTPS Ödeme İsteği", "E1_BROWSER", "P1_APIGW", "HTTPS/TLS1.3")
    # DMZ -> Intranet (Güven Sınırı Aşımı Var)
    engine.add_data_flow("F2_INTERNAL_RPC", "gRPC Ödeme Doğrulama", "P1_APIGW", "P2_PAYMENT_SVC", "mTLS/gRPC")
    # Intranet -> Secure_Core (Güven Sınırı Aşımı Var)
    engine.add_data_flow("F3_DB_QUERY", "Şifreli SQL Sorgusu", "P2_PAYMENT_SVC", "D1_CARD_DB", "TLS-TDS")

    return engine


def handle_model_system(args: argparse.Namespace) -> int:
    """Mimari modeli analiz eder ve tehdit modelini ekrana döker."""
    engine = build_sample_architecture_engine()

    # Tüm elemanlar için STRIDE tehditleri türetilir
    total_threats = 0
    for e_id in engine.elements:
        th_list = engine.generate_threats_for_element(e_id)
        total_threats += len(th_list)

    # Güven sınırı aşan akışlar için tehditler türetilir
    boundary_threats = engine.analyze_trust_boundary_flows()
    total_threats += len(boundary_threats)

    print("=" * 75)
    print(f"[+] STRIDE Tehdit Modellemesi Başarıyla Çalıştırıldı: {engine.system_name}")
    print(f"Toplam DFD Elemanı  : {len(engine.elements)}")
    print(f"Toplam Veri Akışı   : {len(engine.data_flows)}")
    print(f"Türetilen Tehdit    : {total_threats}")
    print("=" * 75)

    # Tedbirler uygulanırsa
    if args.apply_mitigations:
        print("[*] Standart Güvenlik Tedbirleri (Mitigations) Uygulanıyor...")
        for t_id, threat in list(engine.threats.items()):
            default_mits = engine.DEFAULT_MITIGATIONS.get(threat.category, ["Genel Güvenlik Kalkanı"])
            engine.apply_mitigation(t_id, default_mits[0])
        print("[+] Tüm tehditlere onaylı güvenlik tedbirleri başarıyla işlendi.")

    # Canlıya geçiş denetimi
    try:
        engine.validate_security_readiness()
        print("\n[+] GÜVENLİK HAZIRLIK DURUMU: READY (Canlıya Geçiş Onaylandı)")
        return 0
    except STRIDEModelingSecurityError as err:
        print(f"\n[-] GÜVENLİK HAZIRLIK DURUMU: BLOCKED (Eksik Tedbirler Var)\n{err}")
        return 1 if not args.ignore_errors else 0


def handle_eval_dread(args: argparse.Namespace) -> int:
    """Belirtilen DREAD puanlarını hesaplar ve ciddiyet analizi yapar."""
    try:
        dread = DREADScore(
            damage=args.d,
            reproducibility=args.r,
            exploitability=args.e,
            affected_users=args.a,
            discoverability=args.disc
        )
        score = dread.calculate_risk_score()
        severity = dread.get_severity()

        print("=" * 70)
        print(f"[*] DREAD Risk Değerlendirme Analizi")
        print(f"Hasar Potansiyeli (Damage)         : {dread.damage} / 10")
        print(f"Tekrarlanabilirlik (Reprod.)       : {dread.reproducibility} / 10")
        print(f"İstismar Kolaylığı (Exploitability): {dread.exploitability} / 10")
        print(f"Etkilenen Kullanıcılar (Affected)  : {dread.affected_users} / 10")
        print(f"Keşfedilebilirlik (Discoverability): {dread.discoverability} / 10")
        print("-" * 70)
        print(f"[!] Toplam Risk Skoru              : {score:.1f} / 10.0")
        print(f"[!] Risk Seviyesi                  : {severity}")
        print("=" * 70)
        return 0
    except STRIDEModelingSecurityError as err:
        print(f"[-] DREAD Hata: {err}")
        return 1


def main() -> None:
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="NIST & Microsoft STRIDE Tehdit Modelleme ve DREAD Analiz CLI Aracı"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 'model' alt komutu
    model_parser = subparsers.add_parser("model", help="Örnek sistem üzerinde STRIDE analizi çalıştır")
    model_parser.add_argument("--apply-mitigations", action="store_true", help="Varsayılan tedbirleri otomatik uygula")
    model_parser.add_argument("--ignore-errors", action="store_true", help="Hata durumunda çıkış kodunu 0 yap")

    # 'dread' alt komutu
    dread_parser = subparsers.add_parser("dread", help="DREAD risk skoru hesapla")
    dread_parser.add_argument("-d", type=int, required=True, help="Damage (1-10)")
    dread_parser.add_argument("-r", type=int, required=True, help="Reproducibility (1-10)")
    dread_parser.add_argument("-e", type=int, required=True, help="Exploitability (1-10)")
    dread_parser.add_argument("-a", type=int, required=True, help="Affected Users (1-10)")
    dread_parser.add_argument("-disc", type=int, required=True, help="Discoverability (1-10)")

    args = parser.parse_args()
    if args.command == "model":
        sys.exit(handle_model_system(args))
    elif args.command == "dread":
        sys.exit(handle_eval_dread(args))


if __name__ == "__main__":
    main()
