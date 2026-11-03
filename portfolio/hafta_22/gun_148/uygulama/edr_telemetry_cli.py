"""
Gün 148: EDR ve AV Uç Nokta Telemetri CLI Yönetim Aracı
=======================================================
Bu araç; uç noktalardan toplanan çekirdek ve kullanıcı alanı telemetri
olaylarını (Process, Memory, Network, Registry) analiz eder, geleneksel AV
ve davranışsal EDR alarmlarını MITRE ATT&CK eşleşmeleriyle ekrana basar
ve otomatik PowerShell müdahale betikleri üretir.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

import argparse
import json
import sys
import os

# Güvenlik motoru bileşenlerini içe aktar
from edr_telemetry_engine import (
    EDRTelemetryEngine,
    TelemetryEvent,
    EventType,
    DetectionType
)


def run_analyze(args: argparse.Namespace) -> int:
    """Telemetri dosyasını okur, EDR ve AV analizini icra eder."""
    if not os.path.exists(args.dosya):
        print(f"[!] HATA: Telemetri dosyası bulunamadı: {args.dosya}", file=sys.stderr)
        return 1

    with open(args.dosya, "r", encoding="utf-8") as fp:
        raw_data = json.load(fp)

    events: list[TelemetryEvent] = []
    for ev_dict in raw_data.get("events", []):
        events.append(TelemetryEvent(
            event_id=ev_dict["event_id"],
            timestamp=ev_dict["timestamp"],
            event_type=EventType(ev_dict["event_type"]),
            pid=ev_dict["pid"],
            process_name=ev_dict["process_name"],
            parent_pid=ev_dict["parent_pid"],
            parent_name=ev_dict["parent_name"],
            command_line=ev_dict["command_line"],
            user=ev_dict["user"],
            details=ev_dict.get("details", {})
        ))

    files_to_scan = raw_data.get("files", [])

    engine = EDRTelemetryEngine()
    summary = engine.process_telemetry_batch(events, files_to_scan)

    print("=" * 70)
    print("KURUMSAL EDR VE AV TELEMETRİ GÜVENLİK DENETİM RAPORU")
    print("=" * 70)
    print(f"Toplam Telemetri Olayı   : {summary.total_events_processed}")
    print(f"Statik AV İmzası Tespiti : {summary.av_detections_count}")
    print(f"Davranışsal EDR Tespiti  : {summary.edr_detections_count}")
    print(f"Toplam Üretilen Alarm    : {summary.total_alerts_count}")
    print(f"Sonlandırılacak Süreçler : {summary.killed_pids}")
    print(f"Karantinaya Alınan Dosya : {summary.quarantined_files}")
    print(f"Uç Nokta Ağ İzolasyonu   : {'GEREKLİ (EVET)' if summary.isolated_hosts else 'HAYIR'}")
    print("-" * 70)
    print(f"Uç Nokta Güvenlik Puanı  : {summary.security_score:.1f} / 100")
    durum_str = "TEMİZ VE GÜVENLİ" if summary.total_alerts_count == 0 else "TEHDİT YAKALANDI / MÜDAHALE GEREKLİ"
    print(f"Sistem Durumu            : {durum_str}")
    print("=" * 70)

    if summary.alerts:
        print("\n[!] TESPİT EDİLEN TEHDİT ALARMLARI VE MITRE ATT&CK EŞLEŞMELERİ:")
        for idx, al in enumerate(summary.alerts, 1):
            sev_badge = f"[{al.severity.value}]"
            tur_badge = f"[{al.detection_type.value}]"
            print(f"  {idx}. {sev_badge:<10} {tur_badge:<15} {al.rule_id} -> {al.title}")
            print(f"     MITRE Taktik/Teknik: {al.mitre_tactic} | {al.mitre_technique}")
            print(f"     Süreç / PID        : {al.process_name} (PID: {al.culprit_pid})")
            print(f"     Ayrıntı            : {al.details}")
            print(f"     Tavsiye Müdahale   : {al.recommended_action.value}")
    else:
        print("\n[+] Harika! İncelenen telemetri akışında hiçbir zararlı davranış veya AV imzası bulunamadı.")

    if args.cikis_json:
        out_dict = {
            "toplam_olay": summary.total_events_processed,
            "av_tespit_sayisi": summary.av_detections_count,
            "edr_tespit_sayisi": summary.edr_detections_count,
            "toplam_alarm": summary.total_alerts_count,
            "oldurulen_pidler": summary.killed_pids,
            "karantinaya_alinan_dosyalar": summary.quarantined_files,
            "ag_izolasyonu": summary.isolated_hosts,
            "guvenlik_puani": summary.security_score,
            "mitre_kapsami": summary.mitre_coverage,
            "alarmlar": [
                {
                    "alarm_id": a.alert_id,
                    "tespit_turu": a.detection_type.value,
                    "kural_id": a.rule_id,
                    "baslik": a.title,
                    "onem": a.severity.value,
                    "mitre_teknik": a.mitre_technique,
                    "pid": a.culprit_pid,
                    "surec": a.process_name,
                    "detay": a.details,
                    "mudahale": a.recommended_action.value
                }
                for a in summary.alerts
            ]
        }
        with open(args.cikis_json, "w", encoding="utf-8") as fp:
            json.dump(out_dict, fp, ensure_ascii=False, indent=2)
        print(f"\n[+] Denetim raporu JSON olarak kaydedildi: {args.cikis_json}")

    if args.uret_remediation:
        ps1_code = engine.generate_response_powershell(summary)
        with open(args.uret_remediation, "w", encoding="utf-8") as fp:
            fp.write(ps1_code)
        print(f"[+] Otomatik PowerShell müdahale betiği üretildi: {args.uret_remediation}")

    return 0 if summary.total_alerts_count == 0 else 2


def main() -> None:
    """Ana CLI komut yönlendirici."""
    parser = argparse.ArgumentParser(
        description="Gün 148: Kurumsal EDR ve AV Telemetri Güvenlik ve Müdahale Aracı",
        epilog="Örnek: python edr_telemetry_cli.py analyze ornek_veri/clean_system_telemetry.json"
    )

    subparsers = parser.add_subparsers(dest="command", help="Yürütülecek alt komut")

    # Analyze alt komutu
    analyze_parser = subparsers.add_parser("analyze", help="Uç nokta telemetri akışını EDR/AV kurallarıyla analiz eder")
    analyze_parser.add_argument("dosya", help="Telemetri JSON dosyası yolu")
    analyze_parser.add_argument("--cikis-json", help="Analiz raporunu JSON dosyası olarak kaydet")
    analyze_parser.add_argument("--uret-remediation", help="Otomatik PowerShell müdahale betiği üret")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "analyze":
        sys.exit(run_analyze(args))


if __name__ == "__main__":
    main()
