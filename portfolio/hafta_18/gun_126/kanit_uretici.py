# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 126 KANIT ÜRETİCİ (Aşama 5 Kalite Özeti ve Kabul Raporlayıcısı)
-------------------------------------------------------------------
Bu betik; Aşama 5 birim testlerini, 9 negatif kontrol senaryosunu,
CLI araçlarını ve mimari diyagramlarını çalıştırarak kanıt dosyalarını üretir.
"""

# İşletim sistemi ve dizin işlemleri için os modülü
import os
# Sistem parametreleri ve modül arama yolu için sys modülü
import sys
# Yapılandırılmış verileri ayrıştırmak ve kaydetmek için json modülü
import json
# Zaman damgaları ve denetim kayıtları için datetime modülü
from datetime import datetime
# Testleri otomasyon ile çalıştırmak için unittest modülü
import unittest
# Test çıktılarını bellekte yakalamak için io modülü
import io

# Betiğin bulunduğu dizini alıyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Modül yolu listesine ekliyoruz
if CURRENT_DIR not in sys.path:
    # Arama yoluna dahil ediyoruz
    sys.path.insert(0, CURRENT_DIR)

# Uygulama dizinini de modül arama yoluna dahil ediyoruz
APP_DIR = os.path.join(CURRENT_DIR, "uygulama")
# Eğer yolda yoksa ekliyoruz
if APP_DIR not in sys.path:
    # Uygulama klasörünü ekliyoruz
    sys.path.insert(0, APP_DIR)

# Çekirdek motor sınıflarını içe aktarıyoruz
from stage5_quality_engine import (
    Stage5QualityAuditor,
    CryptographicComponentSpec,
    ArchitecturalControlSpec,
    StageAcceptanceDecision
)


def run_unit_tests(output_path: str) -> bool:
    """15 Birim testi çalıştırır ve çıktısını test_sonuclari.txt dosyasına kaydeder."""
    # Test yükleyicisini kuruyoruz
    loader = unittest.TestLoader()
    # tests klasöründeki testleri keşfediyoruz
    suite = loader.discover(os.path.join(CURRENT_DIR, "tests"), pattern="test_*.py")
    # Çıktıyı yakalamak için metin tamponu oluşturuyoruz
    stream = io.StringIO()
    # Ayrıntılı koşucuyu yapılandırıyoruz
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Test paketini yürütüyoruz
    result = runner.run(suite)
    # Koşu metnini alıyoruz
    output_text = stream.getvalue()

    # Rapor metnini biçimlendiriyoruz
    report = (
        "======================================================================\n"
        "GÜN 126: AŞAMA 5 KALİTE ÖZETİ VE KABUL - BİRİM TEST RAPORU\n"
        f"Tarih/Saat: {datetime.now().isoformat()}\n"
        "Standartlar: NIST SP 800-131A, NIST SP 800-57, NIST SP 800-160\n"
        "======================================================================\n\n"
        f"Çalıştırılan Test Sayısı: {result.testsRun}\n"
        f"Hata Sayısı (Errors): {len(result.errors)}\n"
        f"Başarısızlık Sayısı (Failures): {len(result.failures)}\n"
        f"Genel Durum: {'BAŞARILI (100% PASS)' if result.wasSuccessful() else 'BAŞARISIZ'}\n\n"
        "------------------- AYRINTILI TEST ÇIKTISI -------------------\n"
        f"{output_text}\n"
    )

    # Kanıt dosyasına UTF-8 olarak yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni kaydediyoruz
        f.write(report)

    # Başarı durumunu döndürüyoruz
    return result.wasSuccessful()


def run_negative_controls(output_path: str) -> int:
    """9 Negatif kontrol senaryosunu çalıştırır ve kanıt kaydeder."""
    # Senaryo dosyasının yolunu belirliyoruz
    scenarios_file = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_stage5_scenarios.json")
    # Dosyayı okuyoruz
    with open(scenarios_file, "r", encoding="utf-8") as f:
        # Veriyi yüklüyoruz
        scenarios_data = json.load(f)

    # Senaryolar listesini alıyoruz
    scenarios = scenarios_data.get("senaryolar", [])
    # Kanıt tamponunu oluşturuyoruz
    lines = [
        "======================================================================",
        "GÜN 126: AŞAMA 5 NEGATİF KONTROL VE HATA ENJEKSİYON TESTLERİ",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        f"Toplam Senaryo: {len(scenarios)}",
        "======================================================================\n"
    ]

    # Başarılı senaryo sayacı
    passed_count = 0
    # Denetçi motorunu başlatıyoruz
    auditor = Stage5QualityAuditor("Negatif Test Denetçisi")

    # Her senaryoyu sırayla inceliyoruz
    for sc in scenarios:
        # Senaryo kimliği
        sid = sc.get("id")
        # Senaryo başlığı
        title = sc.get("baslik")
        # Beklenen CWE kodu
        expected_cwe = sc.get("beklenen_cwe")
        # Başarı bayrağı
        success = False
        # Gözlemlenen mesaj
        observed_msg = ""

        # Kriptografik bileşen senaryosu mu?
        if "bilesen" in sc:
            # Bileşen verisini alıyoruz
            b = sc["bilesen"]
            # Kripto şartname nesnesi oluşturuyoruz
            comp = CryptographicComponentSpec(
                component_name=b.get("component_name", "Test Bileşeni"),
                cipher_or_hash_algorithm=b.get("algorithm", "MD5"),
                key_or_digest_bits=int(b.get("key_bits", 128)),
                mode_of_operation=b.get("mode"),
                random_source=b.get("random_source", "CSPRNG")
            )
            # Değerlendiriyoruz
            score, findings, cwes = auditor.evaluate_crypto_suite([comp])
            # Beklenen CWE tespit edildi mi?
            if expected_cwe in cwes:
                # Başarılı sayıyoruz
                success = True
                # Açıklamayı kaydediyoruz
                observed_msg = f"Beklenen {expected_cwe} zafiyeti başarıyla tespit edildi (Puan: {score}/100). Bulgu: {findings[0] if findings else ''}"
            else:
                # Başarısızlık mesajı
                observed_msg = f"Beklenen {expected_cwe} bulunamadı! Alınan CWE listesi: {cwes}"

        # Mimari kontrol senaryosu mu?
        elif "mimari" in sc:
            # Mimari verisini alıyoruz
            m = sc["mimari"]
            # Mimari şartname nesnesi oluşturuyoruz
            arch = ArchitecturalControlSpec(
                control_name=m.get("control_name", "Test Mimari"),
                defense_layers_covered=m.get("layers", []),
                control_types=m.get("control_types", []),
                default_deny_enforced=bool(m.get("default_deny", True)),
                fail_secure_on_outage=bool(m.get("fail_secure", True)),
                static_sod_enforced=bool(m.get("sod_enforced", True)),
                wildcard_permissions_allowed=bool(m.get("wildcard_allowed", False)),
                log_masking_enabled=bool(m.get("log_masking", True))
            )
            # Değerlendiriyoruz
            score_a, findings_a, cwes_a = auditor.evaluate_architectural_controls(arch)
            # Yönetişim kontrolünü de ekliyoruz
            score_g, findings_g, cwes_g = auditor.evaluate_governance_and_evidence(arch, True, True)
            # Toplam CWE listesi
            total_cwes = set(cwes_a + cwes_g)
            # Beklenen CWE bulundu mu?
            if expected_cwe in total_cwes:
                # Başarılı sayıyoruz
                success = True
                # Açıklamayı kaydediyoruz
                all_finds = findings_a + findings_g
                observed_msg = f"Beklenen {expected_cwe} mimari zafiyeti başarıyla tespit edildi. Bulgu: {all_finds[0] if all_finds else ''}"
            else:
                # Başarısızlık mesajı
                observed_msg = f"Beklenen {expected_cwe} bulunamadı! Alınan CWE listesi: {total_cwes}"

        # Başarı durumunu işliyoruz
        if success:
            # Sayacı artırıyoruz
            passed_count += 1
            # Başarılı satırı ekliyoruz
            lines.append(f"[{sid}] {title} ({expected_cwe}) -> PASS")
            # Ayrıntıyı ekliyoruz
            lines.append(f"   Ayrıntı: {observed_msg}\n")
        else:
            # Başarısız satırı ekliyoruz
            lines.append(f"[{sid}] {title} ({expected_cwe}) -> FAIL")
            # Hata ayrıntısını ekliyoruz
            lines.append(f"   Hata: {observed_msg}\n")

    # Genel özet bilgilerini ekliyoruz
    lines.append("----------------------------------------------------------------------")
    lines.append(f"TOPLAM: {len(scenarios)} | BAŞARILI: {passed_count} | BAŞARISIZ: {len(scenarios) - passed_count}")
    lines.append(f"SONUÇ: {'100% PASS' if passed_count == len(scenarios) else 'BAŞARISIZLIK MEVCUT'}")
    lines.append("======================================================================")

    # Kanıt dosyasına yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Satırları birleştirip kaydediyoruz
        f.write("\n".join(lines))

    # Başarılı geçen senaryo sayısını döndürüyoruz
    return passed_count


def generate_architecture_diagram(output_path: str):
    """ASCII formatında temsili mimari kalite diyagramını üretir (Zorunlu banner ile)."""
    # Diyagram metnini biçimlendiriyoruz
    diagram = (
        "======================================================================\n"
        "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "======================================================================\n"
        "GÜN 126: AŞAMA 5 KALİTE DEĞERLENDİRME VE KABUL MİMARİSİ\n"
        "Standartlar: NIST SP 800-131A, NIST SP 800-57, NIST SP 800-160, Saltzer-Schroeder\n"
        "----------------------------------------------------------------------\n\n"
        "      +-------------------------------------------------------------+\n"
        "      |             KURUMSAL SİSTEM VE MİMARİ ŞARTNAMESİ            |\n"
        "      +-------------------------------------------------------------+\n"
        "                                     |\n"
        "                                     v\n"
        "      +-------------------------------------------------------------+\n"
        "      |         AŞAMA 5 KALİTE VE KABUL DENETÇİSİ MOTORU            |\n"
        "      +-------------------------------------------------------------+\n"
        "         |                              |                         |\n"
        "         | 1. Kriptografi (%40)         | 2. Mimari (%40)         | 3. Yönetişim (%20)\n"
        "         v                              v                         v\n"
        "   +--------------+              +---------------+         +--------------+\n"
        "   | AES-256-GCM  |              | Saltzer-      |         | CWE-532 Log  |\n"
        "   | SHA-256/384  |              | Schroeder     |         | Maskeleme    |\n"
        "   | PBKDF2 100k+ |              | Default-Deny  |         | 15 Birim Test|\n"
        "   | CSPRNG       |              | Fail-Secure   |         | 9 Negatif    |\n"
        "   | Constant-Time|              | Statik SoD    |         | Kanıt        |\n"
        "   +--------------+              +---------------+         +--------------+\n"
        "         |                              |                         |\n"
        "         +------------------------------+-------------------------+\n"
        "                                     |\n"
        "                                     v\n"
        "      +-------------------------------------------------------------+\n"
        "      |                AĞIRLIKLI SKORLAMA VE KARAR                  |\n"
        "      |    Skor = (0.40 * Kripto) + (0.40 * Mimari) + (0.20 * Kanıt) |\n"
        "      +-------------------------------------------------------------+\n"
        "                    |                                 |\n"
        "                    | (Skor >= 85 & No Blocker)       | (Skor < 85 veya Blocker)\n"
        "                    v                                 v\n"
        "      +---------------------------+     +---------------------------+\n"
        "      |  STAGE_5_ACCEPTED (PASS)  |     |   STAGE_5_HOLD (DÜZELTME) |\n"
        "      |  Kalite Sertifikası Onayı |     |   CWE İyileştirme Planı   |\n"
        "      +---------------------------+     +---------------------------+\n"
    )

    # Dosyaya kaydediyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni diske yazıyoruz
        f.write(diagram)


def generate_analysis_report(output_path: str):
    """Kapsamlı Aşama 5 kalite denetim raporunu JSON olarak üretir."""
    # Şartname dosyasını okuyoruz
    spec_path = os.path.join(CURRENT_DIR, "ornek_veri", "sample_crypto_architecture_spec.json")
    # Dosyayı açıyoruz
    with open(spec_path, "r", encoding="utf-8") as f:
        # Veriyi alıyoruz
        spec_data = json.load(f)

    # Kripto bileşenlerini oluşturuyoruz
    crypto_components = [
        CryptographicComponentSpec(
            component_name=c["component_name"],
            cipher_or_hash_algorithm=c["algorithm"],
            key_or_digest_bits=c["key_bits"],
            mode_of_operation=c.get("mode"),
            pbkdf2_iterations=c.get("iterations"),
            random_source=c.get("random_source", "CSPRNG"),
            uses_constant_time_compare=c.get("constant_time", True)
        )
        for c in spec_data.get("kriptografik_bilesenler", [])
    ]

    # Mimari şartnameyi oluşturuyoruz
    m = spec_data.get("mimari_kontroller", {})
    # Nesneyi başlatıyoruz
    arch_spec = ArchitecturalControlSpec(
        control_name=m.get("control_name", "Kurumsal Mimari"),
        defense_layers_covered=m.get("layers", []),
        control_types=m.get("control_types", []),
        default_deny_enforced=m.get("default_deny", True),
        fail_secure_on_outage=m.get("fail_secure", True),
        static_sod_enforced=m.get("sod_enforced", True),
        wildcard_permissions_allowed=m.get("wildcard_allowed", False),
        log_masking_enabled=m.get("log_masking", True)
    )

    # Denetçi motorunu başlatıyoruz
    auditor = Stage5QualityAuditor("Aşama 5 Kalite Heyeti")
    # Tam denetimi icra ediyoruz
    result = auditor.perform_full_stage5_audit(
        target_system_name=spec_data.get("sistem_adi", "Hedef Sistem"),
        crypto_specs=crypto_components,
        arch_spec=arch_spec,
        has_executable_tests=True,
        has_negative_controls=True
    )

    # JSON rapor içeriğini hazırlıyoruz
    full_report = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Görüntüleme ve eğitim amaçlıdır.",
        "rapor_tarihi": datetime.now().isoformat(),
        "audit_id": result.audit_id,
        "asama": "Aşama 5 (Kriptografi ve Mimari Kalite Özeti)",
        "hedef_sistem": result.target_system_name,
        "skorlar": {
            "kriptografi_skoru": result.crypto_score,
            "mimari_skoru": result.architecture_score,
            "yonetisim_ve_kanit_skoru": result.governance_score,
            "genel_kalite_skoru": result.overall_quality_score
        },
        "karar": result.decision.value,
        "bulgular": result.critical_findings,
        "cwe_ihlalleri": result.cwe_violations,
        "standart_uyumluluklari": [
            "NIST SP 800-131A (Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths)",
            "NIST SP 800-57 (Recommendation for Key Management)",
            "NIST SP 800-160 (Systems Security Engineering: Trustworthy Secure by Design)",
            "Saltzer-Schroeder (1975) The Protection of Information in Computer Systems"
        ]
    }

    # Dosyaya JSON olarak yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Girintili olarak kaydediyoruz
        json.dump(full_report, f, ensure_ascii=False, indent=2)


def run_cli_commands(output_path: str):
    """CLI komutlarını çalıştırır ve çıktısını komut_ve_cikis.txt dosyasına kaydeder."""
    # CLI betiğini içe aktarıyoruz
    from stage5_cli import main as cli_main

    # Şartname dosyasının yolunu alıyoruz
    spec_file = os.path.join(CURRENT_DIR, "ornek_veri", "sample_crypto_architecture_spec.json")

    # Çıktı tamponunu hazırlıyoruz
    cli_outputs = [
        "======================================================================",
        "GÜN 126: CLI ETKİLEŞİM VE YÖNETİM KOMUTLARI KANITI",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        "======================================================================\n"
    ]

    # Çalıştırılacak komut senaryoları
    commands = [
        ("Kriptografik Algoritma Doğrulama (AES-256-GCM)", ["verify-crypto", "--algorithm", "AES-256-GCM", "--key-bits", "256", "--mode", "GCM"]),
        ("Zayıf Kriptografik Algoritma Doğrulama (MD5)", ["verify-crypto", "--algorithm", "MD5", "--key-bits", "128"]),
        ("Tam Aşama 5 Denetimi ve Kalite Sertifikası", ["audit", spec_file, "--format", "markdown"])
    ]

    # Her komutu icra ediyoruz
    for desc, args in commands:
        # Başlık ekliyoruz
        cli_outputs.append(f"--- KOMUT: python stage5_cli.py {' '.join(args)} ({desc}) ---")
        # Tamponları oluşturuyoruz
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        # Eski akışları saklıyoruz
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        # Yeni tamponlara yönlendiriyoruz
        sys.stdout = stdout_buf
        sys.stderr = stderr_buf
        try:
            # Komutu çağırıyoruz
            cli_main(args)
        except SystemExit:
            # sys.exit yakalanır
            pass
        finally:
            # Eski akışları geri yüklüyoruz
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        # Çıktıyı alıyoruz
        cmd_out = stdout_buf.getvalue() + stderr_buf.getvalue()
        # Çıktı satırlarına ekliyoruz
        cli_outputs.append(cmd_out)
        # Ayraç ekliyoruz
        cli_outputs.append("----------------------------------------------------------------------\n")

    # Kanıt dosyasına yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni kaydediyoruz
        f.write("\n".join(cli_outputs))


def main():
    """Ana kanıt üretici akışı."""
    # Gerçek ve temsili kanıt klasörleri
    gercek_dir = os.path.join(CURRENT_DIR, "kanit", "gercek")
    temsili_dir = os.path.join(CURRENT_DIR, "kanit", "temsili")

    # Klasörlerin varlığını garanti ediyoruz
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # 1. Birim testleri çalıştırıyoruz
    unit_ok = run_unit_tests(os.path.join(gercek_dir, "test_sonuclari.txt"))
    print(f"[+] Birim Testler Tamamlandı: {'BAŞARILI' if unit_ok else 'BAŞARISIZ'}")

    # 2. Negatif kontrol senaryolarını yürütüyoruz
    neg_passed = run_negative_controls(os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt"))
    print(f"[+] Negatif Kontrol Senaryoları Tamamlandı: {neg_passed}/9 Senaryo Başarılı")

    # 3. Temsili mimari diyagramını oluşturuyoruz
    generate_architecture_diagram(os.path.join(temsili_dir, "asama5_kalite_mimarisi.txt"))
    print("[+] Temsili Mimari Diyagramı Oluşturuldu.")

    # 4. Kapsamlı analiz raporunu oluşturuyoruz
    generate_analysis_report(os.path.join(gercek_dir, "asama5_kalite_denetim_raporu.json"))
    print("[+] Aşama 5 Kalite Denetim Raporu Oluşturuldu.")

    # 5. CLI etkileşimlerini kaydediyoruz
    run_cli_commands(os.path.join(gercek_dir, "komut_ve_cikis.txt"))
    print("[+] CLI Çıktıları Kaydedildi.")

    # Bitiş bildirimi
    print("[***] GÜN 126 TÜM KANIT DOSYALARI BAŞARIYLA ÜRETİLDİ! [***]")


# Betik doğrudan çalıştırıldığında main çağrılır
if __name__ == "__main__":
    main()
