# -*- coding: utf-8 -*-
"""
OWASP Top 10 Haritası ve Web Zafiyet Değerlendirme CLI Aracı
Hafta 23 / Gün 156 - Aşama 7 (Web Güvenliği)

Bu araç; kurumsal web uygulama profillerini okur, 10 OWASP kategorisi üzerinden
denetim çalıştırır, CWE eşleştirmelerini açıklar ve Markdown formatında
önceliklendirilmiş zafiyet iyileştirme yol haritası üretir.
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.owasp_mapper_engine import (
    AppSecurityProfile,
    OwaspMapperEngine,
    OwaspCategory,
)


def load_app_spec(file_path: str) -> AppSecurityProfile:
    """JSON dosyasından uygulama güvenlik profilini yükler."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Uygulama şartname dosyası bulunamadı: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return AppSecurityProfile(
        app_name=data["app_name"],
        version=data.get("version", "1.0.0"),
        environment=data.get("environment", "Production"),
        has_rbac_authz_middleware=data.get("has_rbac_authz_middleware", True),
        idor_prevention_active=data.get("idor_prevention_active", True),
        tls_minimum_version=data.get("tls_minimum_version", "TLSv1.3"),
        passwords_hashed_with_argon2_or_bcrypt=data.get("passwords_hashed_with_argon2_or_bcrypt", True),
        sensitive_data_encrypted_at_rest=data.get("sensitive_data_encrypted_at_rest", True),
        uses_parameterized_queries=data.get("uses_parameterized_queries", True),
        output_encoding_for_xss=data.get("output_encoding_for_xss", True),
        has_threat_model=data.get("has_threat_model", True),
        has_rate_limiting=data.get("has_rate_limiting", True),
        debug_mode_disabled=data.get("debug_mode_disabled", True),
        default_credentials_changed=data.get("default_credentials_changed", True),
        security_headers_enforced=data.get("security_headers_enforced", True),
        outdated_dependencies_count=int(data.get("outdated_dependencies_count", 0)),
        has_automated_sca_scanning=data.get("has_automated_sca_scanning", True),
        mfa_enforced_for_admin=data.get("mfa_enforced_for_admin", True),
        brute_force_lockout_active=data.get("brute_force_lockout_active", True),
        insecure_deserialization_prevented=data.get("insecure_deserialization_prevented", True),
        ci_cd_pipeline_signed=data.get("ci_cd_pipeline_signed", True),
        centralized_audit_logging_active=data.get("centralized_audit_logging_active", True),
        security_event_alerting_latency_minutes=int(data.get("security_event_alerting_latency_minutes", 5)),
        ssrf_url_validation_allowlist_active=data.get("ssrf_url_validation_allowlist_active", True),
        cloud_metadata_blocked=data.get("cloud_metadata_blocked", True),
    )


def handle_map_app(args):
    """Uygulamayı OWASP Top 10 haritasına göre değerlendirir."""
    profile = load_app_spec(args.spec)
    engine = OwaspMapperEngine()
    report = engine.evaluate_profile(profile)

    ascii_rep = engine.generate_ascii_dashboard(report)
    print(ascii_rep)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        dict_data = engine.export_report_to_dict(report)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(dict_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] OWASP Haritalama Raporu JSON olarak kaydedildi: {args.output}")


def handle_map_cwe(args):
    """Verilen CWE kimliğini OWASP kategorisiyle eşleştirir."""
    engine = OwaspMapperEngine()
    cwe_id = int(args.cwe)
    mapping = engine.map_cwe(cwe_id)

    if not mapping:
        print(f"[-] Hata: CWE-{cwe_id} veritabanında bulunamadı.")
        sys.exit(1)

    print("=" * 70)
    print(f" CWE -> OWASP EŞLEŞTİRME: CWE-{mapping.cwe_id}")
    print("=" * 70)
    print(f" Zafiyet Adı         : {mapping.cwe_name}")
    print(f" OWASP Kategorisi    : {mapping.category.value}")
    print(f" Risk Seviyesi       : {mapping.severity.value}")
    print(f" Açıklama            : {mapping.description}")
    print(f" Standart İyileştirme : {mapping.mitigation}")
    print("=" * 70)


def handle_generate_roadmap(args):
    """Önceliklendirilmiş Markdown iyileştirme yol haritası üretir."""
    profile = load_app_spec(args.spec)
    engine = OwaspMapperEngine()
    report = engine.evaluate_profile(profile)

    lines = [
        f"# OWASP Top 10 Zafiyet İyileştirme Yol Haritası: {report.app_name}",
        f"\n**Genel Uyumluluk Puanı:** %{report.overall_compliance_score} / 100",
        f"**Durum:** {'UYUMLU (GECTI)' if report.is_compliant else 'RİSKLİ (İYİLEŞTİRME GEREKLİ)'}\n",
        "---",
        "## 1. Yönetici Özeti",
        f"{report.executive_summary}\n",
        "---",
        "## 2. Kategori Bazlı Risk Durumu",
        "| Kategori | Tanım | Skor | Durum |",
        "| :--- | :--- | :---: | :---: |",
    ]

    for code, sc in sorted(report.category_scores.items()):
        lines.append(f"| {code} | {sc.category.value} | %{sc.score} | {sc.status} |")

    lines.append("\n---")
    lines.append("## 3. Öncelikli İyileştirme Eylemleri")
    if report.high_priority_remediations:
        for idx, rem in enumerate(report.high_priority_remediations, 1):
            lines.append(f"{idx}. **[Acil]** {rem}")
    else:
        lines.append("*Tebrikler! Yüksek öncelikli herhangi bir güvenlik açığı bulunmamaktadır.*")

    lines.append("\n---")
    lines.append("*Rapor Oluşturulma: OWASP Top 10:2025 Güvenlik Standartları Referans Alınmıştır.*")

    md_content = "\n".join(lines)
    if args.output_md:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_md)), exist_ok=True)
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"[+] İyileştirme yol haritası Markdown olarak kaydedildi: {args.output_md}")
    else:
        print(md_content)


def main():
    """CLI giriş noktası."""
    parser = argparse.ArgumentParser(description="OWASP Top 10 Haritalama ve Zafiyet Analiz Aracı")
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # map-app komutu
    map_parser = subparsers.add_parser("map-app", help="Uygulama şartnamesini OWASP Top 10 ile değerlendir")
    map_parser.add_argument("--spec", required=True, help="Uygulama güvenlik profili JSON dosya yolu")
    map_parser.add_argument("--output", help="Raporun kaydedileceği JSON dosya yolu")

    # map-cwe komutu
    cwe_parser = subparsers.add_parser("map-cwe", help="CWE ID'sini ilgili OWASP kategorisiyle eşleştir")
    cwe_parser.add_argument("--cwe", required=True, type=int, help="CWE numarası (örn. 89, 79, 918)")

    # generate-roadmap komutu
    road_parser = subparsers.add_parser("generate-roadmap", help="Zafiyet iyileştirme yol haritası Markdown üret")
    road_parser.add_argument("--spec", required=True, help="Uygulama güvenlik profili JSON dosya yolu")
    road_parser.add_argument("--output-md", help="Kaydedilecek Markdown dosya yolu (.md)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "map-app":
        handle_map_app(args)
    elif args.command == "map-cwe":
        handle_map_cwe(args)
    elif args.command == "generate-roadmap":
        handle_generate_roadmap(args)


if __name__ == "__main__":
    main()
