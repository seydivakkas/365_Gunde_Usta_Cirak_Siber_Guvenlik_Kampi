# -*- coding: utf-8 -*-
"""
Uç Nokta Risk Panosu ve Güvenlik Duruşu Yönetimi CLI Arayüzü (Mini Proje 21)
Hafta 22 / Gün 153

Bu CLI aracı; kurumsal uç nokta telemetri dosyalarını okur, çok vektörlü risk analizi
çalıştırır, terminalde zengin ASCII panosu çizer, tekil cihaz detaylarını görüntüler
ve otomatik PowerShell iyileştirme betikleri üretir.
"""

import argparse
import json
import sys
import os

# Üst dizindeki paketi içe aktarabilmek için yolu ekler
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.endpoint_risk_dashboard import (
    EndpointTelemetry,
    EndpointRiskEngine,
    FleetRiskDashboard,
    RiskBand,
)


def load_fleet_telemetry(file_path: str):
    """JSON dosyasından kurumsal filo telemetri listesini yükler."""
    # Dosyanın varlığı kontrol edilir
    if not os.path.exists(file_path):
        # Dosya yoksa FileNotFoundError fırlatılır
        raise FileNotFoundError(f"Filo envanter dosyası bulunamadı: {file_path}")

    # Dosya UTF-8 olarak açılır ve JSON içeriği okunur
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Telemetri nesneleri listesi oluşturulur
    telemetry_list = []
    # Her bir ham kayıt EndpointTelemetry nesnesine dönüştürülür
    for item in data:
        telemetry = EndpointTelemetry(
            hostname=item["hostname"],
            ip_address=item["ip_address"],
            operating_system=item["operating_system"],
            department=item["department"],
            is_critical_asset=item.get("is_critical_asset", False),
            edr_installed=item.get("edr_installed", True),
            edr_running=item.get("edr_running", True),
            tamper_protection=item.get("tamper_protection", True),
            signatures_age_hours=item.get("signatures_age_hours", 6),
            app_control_mode=item.get("app_control_mode", "Enforce"),
            unapproved_executables_detected=item.get("unapproved_executables_detected", 0),
            disk_encrypted=item.get("disk_encrypted", True),
            tpm_version=item.get("tpm_version", "2.0"),
            pcr_binding_valid=item.get("pcr_binding_valid", True),
            recovery_key_escrowed=item.get("recovery_key_escrowed", True),
            last_backup_hours_ago=item.get("last_backup_hours_ago", 12),
            backup_immutable=item.get("backup_immutable", True),
            last_restore_tested=item.get("last_restore_tested", True),
            cis_compliance_percentage=float(item.get("cis_compliance_percentage", 95.0)),
            unauthorized_local_admins=item.get("unauthorized_local_admins", 0),
            uac_or_aslr_active=item.get("uac_or_aslr_active", True),
            critical_cves=item.get("critical_cves", 0),
            high_cves=item.get("high_cves", 0),
            days_since_os_patch=item.get("days_since_os_patch", 10),
        )
        telemetry_list.append(telemetry)

    # Hazırlanan liste döndürülür
    return telemetry_list


def handle_scan_fleet(args):
    """Tüm filoyu tarar ve özet risk panosunu terminale basar."""
    # Filo envanteri yüklenir
    telemetry_list = load_fleet_telemetry(args.fleet)
    # Risk motoru örneği oluşturulur
    engine = EndpointRiskEngine()
    # Filo değerlendirmesi gerçekleştirilir
    dashboard = engine.assess_fleet(telemetry_list)

    # ASCII panosu üretilir ve konsola basılır
    report_text = engine.generate_ascii_dashboard_report(dashboard)
    print(report_text)

    # Eğer çıktı dosyası belirtilmişse JSON olarak kaydedilir
    if args.output:
        # JSON sözlüğüne dönüştürülür
        dict_data = engine.export_dashboard_to_dict(dashboard)
        # Hedef dizin oluşturulur
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        # JSON dosyasına yazılır
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(dict_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Pano JSON verisi başarıyla kaydedildi: {args.output}")


def handle_host_detail(args):
    """Belirli bir ana bilgisayarın derinlemesine güvenlik dökümünü basar."""
    # Filo envanteri yüklenir
    telemetry_list = load_fleet_telemetry(args.fleet)
    # Aranan ana bilgisayar bulunur
    target = None
    for h in telemetry_list:
        if h.hostname.lower() == args.host.lower():
            target = h
            break

    # Cihaz bulunamazsa hata basılır
    if not target:
        print(f"[-] Hata: '{args.host}' adlı uç nokta envanterde bulunamadı.")
        sys.exit(1)

    # Risk motoru ile tekil cihaz değerlendirilir
    engine = EndpointRiskEngine()
    assessment = engine.assess_host(target)

    # Terminal çıktısı biçimlendirilir
    print("=" * 70)
    print(f" UÇ NOKTA DERİN GÜVENLİK ANALİZİ: {assessment.hostname}")
    print("=" * 70)
    print(f" IP Adresi         : {assessment.ip_address}")
    print(f" İşletim Sistemi   : {assessment.operating_system}")
    print(f" Departman         : {assessment.department}")
    print(f" Kritik Varlık     : {'EVET' if assessment.is_critical else 'HAYIR'}")
    print(f" Risk Skoru        : {assessment.risk_score} / 100 ({assessment.risk_band.value})")
    print(f" Güvenlik Duruşu   : {assessment.posture_score} / 100")
    print("-" * 70)
    print(" VEKTÖR CEZA PUANI DAĞILIMI:")
    print(f"   * EDR & Telemetri Cezası     : {assessment.vector_scores.edr_penalty:>5.1f} / 100")
    print(f"   * Disk Şifreleme & TPM       : {assessment.vector_scores.disk_encryption_penalty:>5.1f} / 100")
    print(f"   * Yedekleme Güvenliği        : {assessment.vector_scores.backup_penalty:>5.1f} / 100")
    print(f"   * CIS Sıkılaştırma & Sapma   : {assessment.vector_scores.hardening_penalty:>5.1f} / 100")
    print(f"   * Zafiyet & Yama Durumu      : {assessment.vector_scores.vulnerability_penalty:>5.1f} / 100")
    print(f"   * Uygulama Kontrolü          : {assessment.vector_scores.app_control_penalty:>5.1f} / 100")
    print("-" * 70)
    print(" TESPİT EDİLEN BULGULAR:")
    if assessment.findings:
        for f in assessment.findings:
            print(f"   [-] {f}")
    else:
        print("   [+] Herhangi bir güvenlik açığı tespit edilmedi.")
    print("-" * 70)
    print(" ÖNERİLEN İYİLEŞTİRME ADIMLARI:")
    if assessment.remediations:
        for r in assessment.remediations:
            print(f"   [!] {r}")
    else:
        print("   [+] Sistem en iyi güvenlik uygulamalarıyla tam uyumlu.")
    print("=" * 70)


def handle_export_remediation(args):
    """Kritik riskli uç noktalar için PowerShell düzeltme betiği üretir."""
    # Filo envanteri yüklenir
    telemetry_list = load_fleet_telemetry(args.fleet)
    # Risk motoru başlatılır
    engine = EndpointRiskEngine()
    # Filo değerlendirilir
    dashboard = engine.assess_fleet(telemetry_list)
    # Düzeltme betiği üretilir
    script = engine.generate_prioritized_remediation_script(dashboard)

    # Dosyaya veya konsola basılır
    if args.output_script:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_script)), exist_ok=True)
        with open(args.output_script, "w", encoding="utf-8") as f:
            f.write(script)
        print(f"[+] Otomatik iyileştirme betiği üretildi: {args.output_script}")
    else:
        print(script)


def main():
    """CLI giriş noktası ve argüman ayrıştırıcısı."""
    # Ana argüman ayrıştırıcı tanımlanır
    parser = argparse.ArgumentParser(
        description="Kurumsal Uç Nokta Risk Panosu ve Güvenlik Duruşu Yönetimi (Mini Proje 21)"
    )
    # Alt komutlar oluşturulur
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # scan-fleet komutu
    scan_parser = subparsers.add_parser("scan-fleet", help="Tüm filoyu tara ve risk panosu üret")
    scan_parser.add_argument("--fleet", required=True, help="Filo telemetri JSON dosya yolu")
    scan_parser.add_argument("--output", help="Panonun kaydedileceği JSON dosya yolu")

    # host-detail komutu
    host_parser = subparsers.add_parser("host-detail", help="Belirli bir uç noktanın detaylı risk analizini göster")
    host_parser.add_argument("--fleet", required=True, help="Filo telemetri JSON dosya yolu")
    host_parser.add_argument("--host", required=True, help="Detayı incelenecek ana bilgisayar adı")

    # export-remediation komutu
    rem_parser = subparsers.add_parser("export-remediation", help="Riskli uç noktalar için PowerShell iyileştirme betiği üret")
    rem_parser.add_argument("--fleet", required=True, help="Filo telemetri JSON dosya yolu")
    rem_parser.add_argument("--output-script", help="Kaydedilecek PowerShell betik dosya yolu (.ps1)")

    # Argümanlar ayrıştırılır
    args = parser.parse_args()

    # Komut seçilmediyse yardım mesajı gösterilir
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # İlgili fonksiyon çağrılır
    if args.command == "scan-fleet":
        handle_scan_fleet(args)
    elif args.command == "host-detail":
        handle_host_detail(args)
    elif args.command == "export-remediation":
        handle_export_remediation(args)


if __name__ == "__main__":
    # Ana fonksiyon çalıştırılır
    main()
