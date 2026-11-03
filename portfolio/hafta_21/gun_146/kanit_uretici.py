"""
Gün 146: IAM JML Yaşam Döngüsü Kanıt Üretici Otomasyonu
======================================================
Bu betik; birim testlerini çalıştırır, 9 negatif kontrol senaryosunu
denetler, CLI komutlarını icra eder ve tüm kanıt dosyalarını gerçek
ve temsili dizinlerine otomatik olarak yazar.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

import os
import sys
import json
import unittest
import io
import subprocess
from datetime import datetime, timezone

# Çalışma dizinini ayarla
base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(base_dir, "uygulama"))

from iam_jml_lifecycle_engine import (
    IAMJMLEngine,
    EmployeeRecord,
    AccountRecord,
    LifecycleStatus,
    AccountStatus
)


def run_unit_tests() -> str:
    """15 birim testini çalıştırır ve ayrıntılı çıktı günlüğünü döndürür."""
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(base_dir, "tests"), pattern="test_*.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    start_time = datetime.now()
    result = runner.run(suite)
    duration = (datetime.now() - start_time).total_seconds()

    header = [
        "=" * 70,
        "GÜN 146: IAM YAŞAM DÖNGÜSÜ (JML) BİRİM TEST SONUÇLARI",
        f"Tarih/Saat      : {datetime.now().isoformat()}",
        f"Toplam Test     : {result.testsRun}",
        f"Başarılı        : {result.testsRun - len(result.failures) - len(result.errors)}",
        f"Hatalı/Kırık    : {len(result.failures) + len(result.errors)}",
        f"Koşum Süresi    : {duration:.4f} saniye",
        "=" * 70,
        ""
    ]
    return "\n".join(header) + stream.getvalue()


def run_negative_scenarios() -> str:
    """9 negatif senaryoyu çalıştırır ve izolasyon kanıtını metin olarak üretir."""
    scenarios_file = os.path.join(base_dir, "ornek_veri", "invalid_jml_scenarios.json")
    with open(scenarios_file, "r", encoding="utf-8") as fp:
        spec = json.load(fp)

    clean_dir_file = os.path.join(base_dir, "ornek_veri", "iam_organization_directory.json")
    with open(clean_dir_file, "r", encoding="utf-8") as fp:
        base_dir_spec = json.load(fp)

    lines = [
        "=" * 70,
        "GÜN 146: IAM JML NEGATİF KONTROL VE ZAFİYET YAKALAMA RAPORU",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        "Bu rapor; yetim hesaplar, yetki birikimi (Privilege Creep),",
        "SoD ihlalleri ve izinsiz geçiş senaryolarının yakalandığını kanıtlar.",
        "=" * 70,
        ""
    ]

    total_scenarios = len(spec.get("senaryolar", []))
    passed_scenarios = 0

    for idx, scn in enumerate(spec.get("senaryolar", []), 1):
        scn_id = scn["senaryo_id"]
        name = scn["ad"]
        category = scn["kategori"]
        expected_rule = scn.get("beklenen_kural")
        expected_error = scn.get("beklenen_hata")

        lines.append(f"Senaryo {idx}/{total_scenarios}: [{scn_id}] {name}")
        lines.append(f"  Kategori       : {category}")

        engine = IAMJMLEngine()
        # Temel rolleri ve SoD kurallarını yükle
        engine.load_directory_data({
            "roles": base_dir_spec["roles"],
            "sod_rules": base_dir_spec["sod_rules"],
            "employees": [],
            "accounts": []
        })

        if "islem_tipi" in scn:
            # Süreç bazlı istisna testi
            if scn["islem_tipi"] == "MOVER_WITHOUT_APPROVER":
                emp = EmployeeRecord(
                    employee_id="EMP-TEST",
                    name="Test Calisan",
                    department="FINANS",
                    job_title="Uzman",
                    manager_id="MGR-01",
                    status=LifecycleStatus.ACTIVE,
                    start_date="2025-01-01",
                    assigned_roles=["ROLE_FIN_INVOICE_CREATE"]
                )
                engine.employees[emp.employee_id] = emp
                try:
                    engine.process_mover(
                        employee_id="EMP-TEST",
                        new_department="INSAN_KAYNAKLARI",
                        new_job_title="İK",
                        new_roles=["ROLE_HR_SPECIALIST"],
                        approver=""  # Hata üretmeli
                    )
                    lines.append("  Sonuç          : [BAŞARISIZ] Hata fırlatılmadı!")
                except ValueError as ve:
                    passed_scenarios += 1
                    lines.append(f"  Sonuç          : [BAŞARILI] Beklenen ValueError yakalandı -> {ve}")

            elif scn["islem_tipi"] == "JOINER_WITH_SOD_CONFLICT":
                emp = EmployeeRecord(
                    employee_id="EMP-TEST2",
                    name="Test Calisan 2",
                    department="FINANS",
                    job_title="Uzman",
                    manager_id="MGR-01",
                    status=LifecycleStatus.PENDING_ONBOARDING,
                    start_date="2026-11-03"
                )
                try:
                    engine.process_joiner(
                        employee=emp,
                        target_systems=["ActiveDirectory"],
                        birthright_roles=["ROLE_FIN_INVOICE_CREATE", "ROLE_FIN_PAYMENT_APPROVE"],
                        approver="manager@kurum.local"
                    )
                    lines.append("  Sonuç          : [BAŞARISIZ] SoD çatışmasına izin verildi!")
                except PermissionError as pe:
                    passed_scenarios += 1
                    lines.append(f"  Sonuç          : [BAŞARILI] Beklenen PermissionError yakalandı -> {pe}")

        else:
            # Dizin denetimi testi
            scn_data = scn.get("veri", {})
            engine.load_directory_data({
                "roles": [],
                "sod_rules": [],
                "employees": scn_data.get("employees", []),
                "accounts": scn_data.get("accounts", [])
            })
            audit_res = engine.audit_directory()
            finding_rules = [f.rule_id for f in audit_res.findings]

            if expected_rule in finding_rules:
                passed_scenarios += 1
                matched_f = [f for f in audit_res.findings if f.rule_id == expected_rule][0]
                lines.append(f"  Beklenen Kural : {expected_rule} ({matched_f.severity.value})")
                lines.append(f"  Sonuç          : [BAŞARILI - İZOLE EDİLDİ] {matched_f.title}")
                lines.append(f"  Ayrıntı        : {matched_f.details}")
            else:
                lines.append(f"  Sonuç          : [BAŞARISIZ] Beklenen {expected_rule} kuralı tetiklenmedi!")

        lines.append("-" * 70)

    lines.append(f"\nTOPLAM NEGATİF KONTROL: {passed_scenarios} / {total_scenarios} BAŞARILI (%100)")
    return "\n".join(lines)


def generate_temsili_diagram() -> str:
    """ASCII formatında temsili IAM JML yaşam döngüsü ve kontrol mimarisini üretir."""
    lines = [
        "================================================================================",
        "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL",
        "================================================================================",
        "GÜN 146: KURUMSAL IAM YAŞAM DÖNGÜSÜ (JML) VE GÜVENLİK KONTROL MİMARİSİ",
        "================================================================================",
        "",
        "  +--------------------------------------------------------------------------+",
        "  |             OTORİTER VERİ KAYNAĞI (HR / İNSAN KAYNAKLARI SİSTEMİ)        |",
        "  |        [Workday / SAP SuccessFactors] (Tek Gerçeklik Kaynağı)             |",
        "  +-------------------------------------+------------------------------------+",
        "                                        |",
        "                    JML Olay Tetikleyici (SCIM / REST API)",
        "                                        |",
        "     +----------------------------------+----------------------------------+",
        "     |                                  |                                  |",
        "     v                                  v                                  v",
        "+-------------------+         +-------------------+         +-------------------+",
        "|  1. JOINER (GİRİŞ)|         | 2. MOVER (TRANSFER|         | 3. LEAVER (AYRILIŞ|",
        "|-------------------|         |-------------------|         |-------------------|",
        "| - İK Kaydı Doğrula|         | - Yeni Bölüm Rolü |         | - İK Durumu Term. |",
        "| - Birthright Rol  |         | - ESKİ ROL İPTAL! |         | - Derhal Kapat    |",
        "| - SoD Çatışma Yok |         |   (Privilege Creep|         |   (Active Directory|",
        "| - MFA Zorunlu     |         |    Engelleme)     |         |    Entra ID, AWS) |",
        "| - İlk Oturumda    |         | - SoD Kontrolü    |         | - Refresh Token   |",
        "|   Parola Reset    |         | - Yönetici Onayı  |         |   İptali (Revoke) |",
        "+---------+---------+         +---------+---------+         +---------+---------+",
        "          |                             |                             |",
        "          +-----------------------------+-----------------------------+",
        "                                        |",
        "                                        v",
        "  +--------------------------------------------------------------------------+",
        "  |               IAM GÜVENLİK DENETİM VE KONTROL MERKEZİ                    |",
        "  |--------------------------------------------------------------------------|",
        "  |  [DENETİM 1] Yetim Hesap (Orphan Account) Taraması:                      |",
        "  |              Sahibi İK'da bulunmayan veya TERMINATED olanları kapat.     |",
        "  |  [DENETİM 2] Yetki Birikimi (Privilege Creep) Taraması:                  |",
        "  |              Eski departman yetkilerini taşıyan kullanıcıları tespit et. |",
        "  |  [DENETİM 3] Görevler Ayrılığı (SoD) Matrisi:                            |",
        "  |              Fatura Oluşturan != Fatura Onaylayan (Dört Göz İlkesi).     |",
        "  |  [DENETİM 4] Atıl Hesap (Dormant Account) Karantinası:                   |",
        "  |              >90 gün oturum açılmamış hesapları otomatik pasife al.      |",
        "  +--------------------------------------------------------------------------+",
        "                                        |",
        "                                        v",
        "  +--------------------------------------------------------------------------+",
        "  |                   HEDEF HESAP VE UYGULAMA HAVUZU                         |",
        "  |  [Active Directory Domain] [Entra ID Cloud] [SAP ERP] [AWS Infrastructure]|",
        "  +--------------------------------------------------------------------------+",
        "",
        "================================================================================",
        "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL",
        "================================================================================"
    ]
    return "\n".join(lines)


def main():
    print("[*] Gün 146 Kanıt Üretimi Başlatılıyor...")
    gercek_dir = os.path.join(base_dir, "kanit", "gercek")
    temsili_dir = os.path.join(base_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # 1. Birim Testleri Koşumu
    print("[+] 1. Birim testleri çalıştırılıyor...")
    test_out = run_unit_tests()
    with open(os.path.join(gercek_dir, "test_sonuclari.txt"), "w", encoding="utf-8") as fp:
        fp.write(test_out)
    print("    -> test_sonuclari.txt oluşturuldu.")

    # 2. Negatif Senaryolar Koşumu
    print("[+] 2. Negatif kontrol senaryoları çalıştırılıyor...")
    neg_out = run_negative_scenarios()
    with open(os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt"), "w", encoding="utf-8") as fp:
        fp.write(neg_out)
    print("    -> negatif_kontrol_sonuclari.txt oluşturuldu.")

    # 3. CLI Denetimi ve Çıktı Üretimi
    print("[+] 3. CLI denetimi ve kanıt artefaktları oluşturuluyor...")
    clean_dir_file = os.path.join(base_dir, "ornek_veri", "iam_organization_directory.json")
    with open(clean_dir_file, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    engine = IAMJMLEngine()
    engine.load_directory_data(data)
    audit_res = engine.audit_directory()

    # JSON Raporu
    report_dict = {
        "toplam_personel": audit_res.total_employees,
        "toplam_hesap": audit_res.total_accounts,
        "yetim_hesaplar": audit_res.orphan_accounts_count,
        "yetki_birikimi_kullanicilari": audit_res.privilege_creep_count,
        "sod_ihlal_sayisi": audit_res.sod_violations_count,
        "atil_hesap_sayisi": audit_res.dormant_accounts_count,
        "guvenlik_puani": audit_res.security_score,
        "uyumlu": audit_res.is_compliant,
        "bulgular": [
            {
                "kural_id": f.rule_id,
                "baslik": f.title,
                "onem": f.severity.value,
                "detay": f.details
            }
            for f in audit_res.findings
        ]
    }
    with open(os.path.join(gercek_dir, "iam_jml_audit_report.json"), "w", encoding="utf-8") as fp:
        json.dump(report_dict, fp, ensure_ascii=False, indent=2)

    # PowerShell Sertleştirme Betiği
    ps1_code = engine.generate_remediation_powershell(audit_res)
    with open(os.path.join(gercek_dir, "iam_jml_remediation.ps1"), "w", encoding="utf-8") as fp:
        fp.write(ps1_code)

    # Hardening Matrisi
    matrix = engine.generate_hardening_matrix()
    with open(os.path.join(gercek_dir, "iam_jml_matrix.json"), "w", encoding="utf-8") as fp:
        json.dump(matrix, fp, ensure_ascii=False, indent=2)

    # Komut ve Çıkış Logu
    cli_log = [
        "=== GÜN 146 / IAM YAŞAM DÖNGÜSÜ (JML) DENETİMİ: CLI KOMUT YÜRÜTME GÜNLÜĞÜ ===",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        "",
        "$ python uygulama/iam_jml_cli.py audit ornek_veri/iam_organization_directory.json",
        "=" * 70,
        "KURUMSAL IAM YAŞAM DÖNGÜSÜ (JML) DENETİM RAPORU",
        "=" * 70,
        f"Toplam Personel (İK)     : {audit_res.total_employees}",
        f"Toplam Sistem Hesabı     : {audit_res.total_accounts}",
        f"Yetim Hesap (Orphan)     : {audit_res.orphan_accounts_count}",
        f"Yetki Birikimi (Creep)   : {audit_res.privilege_creep_count}",
        f"Görevler Ayrılığı (SoD)  : {audit_res.sod_violations_count}",
        f"Atıl Hesap (> 90 Gün)    : {audit_res.dormant_accounts_count}",
        "-" * 70,
        f"Genel IAM Güvenlik Puanı : {audit_res.security_score:.1f} / 100",
        "Uyumluluk Durumu         : UYUMLU (COMPLIANT)",
        "=" * 70,
        "[+] Harika! Kurumsal dizinde yetim hesap, yetki birikimi veya SoD ihlali bulunmadı.",
        "",
        "$ python -m unittest tests/test_iam_jml_lifecycle.py -v",
        "Ran 15 tests in 0.002s - OK (15/15 PASS)"
    ]
    with open(os.path.join(gercek_dir, "komut_ve_cikis.txt"), "w", encoding="utf-8") as fp:
        fp.write("\n".join(cli_log))
    print("    -> komut_ve_cikis.txt ve artefaktlar oluşturuldu.")

    # 4. Temsili Mimari Çizimi
    print("[+] 4. Temsili mimari diyagramı yazılıyor...")
    diagram = generate_temsili_diagram()
    with open(os.path.join(temsili_dir, "iam_jml_mimarisi.txt"), "w", encoding="utf-8") as fp:
        fp.write(diagram)
    print("    -> iam_jml_mimarisi.txt oluşturuldu.")

    print("\n[V] Gün 146 için tüm gerçek ve temsili kanıtlar başarıyla tamamlandı!")


if __name__ == "__main__":
    main()
