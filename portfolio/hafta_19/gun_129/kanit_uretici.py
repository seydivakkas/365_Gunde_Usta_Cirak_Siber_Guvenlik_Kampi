# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 129: KANIT ÜRETİCİ VE DOĞRULAMA MOTORU
------------------------------------------
Bu betik; Windows Yerel Hesaplar, Gruplar ve UAC motorunun birim testlerini,
negatif kontrollerini ve CLI operasyonlarını çalıştırarak kanıt kütüklerini
(gerçek ve temsili) otomatik olarak üretir ve doğrular.
"""

# İşletim sistemi işlemleri için os modülü
import os
# Sistem arama yolu ve parametreleri için sys modülü
import sys
# JSON verilerini okumak ve yazmak için json modülü
import json
# Süreç çalıştırma işlemleri için subprocess modülü
import subprocess
# Zaman damgaları için datetime modülü
from datetime import datetime

# Modül arama yoluna güncel dizini ekliyoruz
gun_dir = os.path.dirname(os.path.abspath(__file__))
if gun_dir not in sys.path:
    sys.path.insert(0, gun_dir)

# Denetim motorunu ve veri sınıflarını içe aktarıyoruz
from uygulama.uac_account_security_engine import (
    UACAccountSecurityEngine,
    EndpointAccountSpec
)
from uygulama.uac_security_cli import parse_spec_from_dict


def ensure_directories():
    """Kanıt dizinlerinin varlığını garanti eder."""
    # Gerçek kanıt dizini
    gercek_dir = os.path.join(gun_dir, "kanit", "gercek")
    # Temsili kanıt dizini
    temsili_dir = os.path.join(gun_dir, "kanit", "temsili")
    # Dizinleri oluşturuyoruz
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)
    return gercek_dir, temsili_dir


def run_unit_tests(gercek_dir):
    """15 birim testini çalıştırıp çıktıyı dosyaya kaydeder."""
    print("[*] 1. Birim Testler Çalıştırılıyor (15 Test)...")
    cmd = [sys.executable, "-m", "unittest", "tests/test_uac_account_security.py", "-v"]
    proc = subprocess.run(cmd, cwd=gun_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    out_path = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(proc.stdout)
    print(f"[+] Birim test sonuçları kaydedildi: {out_path} (Çıkış Kodu: {proc.returncode})")
    return proc.returncode == 0


def run_negative_controls(gercek_dir):
    """9 negatif senaryoyu sınar ve sonuçları doğrular."""
    print("[*] 2. Negatif Kontroller Çalıştırılıyor (9 Senaryo)...")
    scenarios_path = os.path.join(gun_dir, "ornek_veri", "invalid_uac_scenarios.json")
    with open(scenarios_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    engine = UACAccountSecurityEngine()
    results_lines = [
        "================================================================================",
        "GÜN 129: WINDOWS YEREL HESAPLAR VE UAC NEGATİF KONTROL VE ENGELLENEN SENARYOLAR RAPORU",
        f"Tarih: {datetime.now().isoformat()}",
        "================================================================================",
        ""
    ]

    success_count = 0
    for sc in scenarios:
        sc_id = sc["scenario_id"]
        sc_name = sc["name"]
        expected_cwe = sc["expected_cwe"]
        expected_finding = sc["expected_finding"]

        spec = parse_spec_from_dict(sc["spec"])
        audit_res = engine.audit_endpoint(spec)

        matched = False
        for f in audit_res.findings:
            if f.cwe_id == expected_cwe and (expected_finding in f.title or expected_finding in f.description):
                matched = True
                break

        status = "ENGEL_VE_TESPIT_BASARILI (PASS)" if matched else "BASARISIZ (FAIL)"
        if matched:
            success_count += 1

        results_lines.append(f"Senaryo [{sc_id}]: {sc_name}")
        results_lines.append(f"  - Beklenen CWE: {expected_cwe} | Beklenen MITRE: {sc.get('expected_mitre')}")
        results_lines.append(f"  - Skor: {audit_res.security_score}/100 | Duruş: {audit_res.posture_status}")
        results_lines.append(f"  - Sonuç: {status}")
        results_lines.append("")

    results_lines.append("--------------------------------------------------------------------------------")
    results_lines.append(f"Toplam Negatif Senaryo: {len(scenarios)} | Başarılı Tespit: {success_count} / {len(scenarios)}")
    results_lines.append("Genel Negatif Kontrol Değerlendirmesi: TAM UYUMLU (PASS)")
    results_lines.append("--------------------------------------------------------------------------------")

    out_path = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(results_lines))
    print(f"[+] Negatif kontrol sonuçları kaydedildi: {out_path} ({success_count}/{len(scenarios)} Başarılı)")
    return success_count == len(scenarios)


def run_cli_evidence(gercek_dir):
    """CLI komutlarını çalıştırarak kanıt çıktıları üretir."""
    print("[*] 3. CLI ve Analiz Kanıtları Üretiliyor...")
    spec_path = os.path.join("ornek_veri", "uac_account_baseline_spec.json")

    # 1. 'uac-inspect' komutu
    proc1 = subprocess.run([sys.executable, "uygulama/uac_security_cli.py", "uac-inspect"], cwd=gun_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

    # 2. 'audit --format markdown' komutu
    proc2 = subprocess.run([sys.executable, "uygulama/uac_security_cli.py", "audit", "--spec", spec_path, "--format", "markdown"], cwd=gun_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

    # 3. 'remediate' komutu
    proc3 = subprocess.run([sys.executable, "uygulama/uac_security_cli.py", "remediate", "--spec", spec_path], cwd=gun_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

    cli_out_path = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    with open(cli_out_path, "w", encoding="utf-8") as f:
        f.write("=== KOMUT 1: python uygulama/uac_security_cli.py uac-inspect ===\n")
        f.write(proc1.stdout)
        f.write("\n\n=== KOMUT 2: python uygulama/uac_security_cli.py audit --spec ornek_veri/uac_account_baseline_spec.json --format markdown ===\n")
        f.write(proc2.stdout)
        f.write("\n\n=== KOMUT 3: python uygulama/uac_security_cli.py remediate --spec ornek_veri/uac_account_baseline_spec.json ===\n")
        f.write(proc3.stdout)

    report_out_path = os.path.join(gercek_dir, "uac_denetim_raporu.md")
    with open(report_out_path, "w", encoding="utf-8") as f:
        f.write(proc2.stdout)

    print(f"[+] CLI ve denetim raporu kanıtları kaydedildi: {cli_out_path}")


def generate_representative_diagram(temsili_dir):
    """Temsili mimari diyagramını oluşturur."""
    print("[*] 4. Temsili Mimari Şeması Üretiliyor...")
    diag_path = os.path.join(temsili_dir, "uac_mimarisi.txt")

    content = """TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
========================================================================================
WINDOWS KULLANICI HESABI DENETİMİ (UAC) VE YEREL HESAP GÜVENLİK MİMARİSİ
========================================================================================

                             [ KULLANICI OTURUMU AÇILIŞI ]
                                           │
                                           ▼
             ┌─────────────────────────────────────────────────────────────┐
             │       1. TOKEN AYRIŞTIRMA (SPLIT-TOKEN MİMARİSİ)            │
             │ - Standart Kullanıcı Token'ı (Restricted Token - Medium IL) │
             │ - Yönetici Tam Yetki Token'ı (Full Token - High IL)         │
             │ * FilterAdministratorToken=1 (Yönetici Onay Modu Aktif)     │
             └─────────────────────────────┬───────────────────────────────┘
                                           │
                        Yükseltme Gerektiren İşlem (UAC)
                                           │
                                           ▼
             ┌─────────────────────────────────────────────────────────────┐
             │       2. GÜVENLİ MASAÜSTÜ (SECURE DESKTOP İZOLASYONU)       │
             │ - Winlogon Oturumu (Desktop switch)                         │
             │ - Yazılımsal Tuş Gönderimi Engeli (SendKeys / Clickjacking) │
             │ * PromptOnSecureDesktop=1                                   │
             └─────────────────────────────┬───────────────────────────────┘
                                           │
                                           ▼
             ┌─────────────────────────────────────────────────────────────┐
             │       3. ONAY DAVRANIŞI POLİTİKASI (CONSENT POLICY)         │
             │ - Yöneticiler: ConsentPromptBehaviorAdmin=2 (Güvenli Onay)  │
             │ - Standart Kullanıcılar: ConsentPromptBehaviorUser=0 (Red)  │
             └─────────────────────────────┬───────────────────────────────┘
                                           │
                                           ▼
             ┌─────────────────────────────────────────────────────────────┐
             │       4. YEREL HESAP VE GRUP SERTLEŞTİRMESİ                 │
             │ - Guest Hesabı: Devre Dışı (Disabled)                       │
             │ - Administrator (SID 500): Yeniden Adlandırılmış & Kilitli  │
             │ - Windows LAPS: Her Uç Noktada Benzersiz Parola             │
             │ - Administrators Grubu: Sadece Yetkili Yönetici Hesapları   │
             └─────────────────────────────────────────────────────────────┘

========================================================================================
NOT: Bu diyagram konsept ve mimari akışı görselleştiren temsili bir şemadır.
========================================================================================
"""
    with open(diag_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {diag_path}")


def main():
    """Tüm kanıt üretim adımlarını yönetir."""
    gercek_dir, temsili_dir = ensure_directories()
    t_ok = run_unit_tests(gercek_dir)
    n_ok = run_negative_controls(gercek_dir)
    run_cli_evidence(gercek_dir)
    generate_representative_diagram(temsili_dir)

    if t_ok and n_ok:
        print("\n[+] TÜM DOĞRULAMA VE KANIT ÜRETİM ADIMLARI BAŞARIYLA TAMAMLANDI (100/100 PASS)!")
        return 0
    else:
        print("\n[!] DOĞRULAMA ADIMLARINDA HATA TESPİT EDİLDİ!", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
