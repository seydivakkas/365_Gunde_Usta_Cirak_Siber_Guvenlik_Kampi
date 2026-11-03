# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Windows Hizmet Güvenliği Birim Testleri (15 Adet Kapsamlı Test).

Bu test takımı, Windows Service Control Manager (SCM), SDDL tabanlı servis DACL izinleri,
tırnaksız servis yolları (CWE-428), zayıf binary izinleri (CWE-732), en az ayrıcalık ihlalleri
(CWE-250) ve CIS Benchmark uyumluluğunu en ince ayrıntısına kadar doğrular.
"""

# Birim test çerçevesi için standart unittest modülü içe aktarılıyor
import unittest
# Dosya ve dizin yolu manipülasyonları için standart os modülü içe aktarılıyor
import os
# Sistem arama yollarını düzenlemek için standart sys modülü içe aktarılıyor
import sys

# Test edilen uygulamanın modüllerine erişebilmek için üst dizin yola eklenir
current_dir = os.path.dirname(os.path.abspath(__file__))
# Bir üst seviyedeki gün dizini tespit edilir
parent_dir = os.path.dirname(current_dir)
# Arama yoluna eklenir
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Denetim motoru ve veri modelleri içe aktarılır
try:
    # Paket yolu üzerinden içe aktarma denenir
    from uygulama.windows_service_security_engine import (
        WindowsServiceSecurityEngine,
        WindowsServiceSpec,
        ServiceDaclEntry,
    )
except ImportError:
    # Alternatif doğrudan arama yolu üzerinden içe aktarma
    sys.path.insert(0, os.path.join(parent_dir, "uygulama"))
    from windows_service_security_engine import (
        WindowsServiceSecurityEngine,
        WindowsServiceSpec,
        ServiceDaclEntry,
    )


class TestWindowsServiceSecurity(unittest.TestCase):
    """Windows hizmet güvenliği denetim motoru için 15 testten oluşan test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz bir motor örneği oluşturur."""
        # Yeni bir denetim motoru nesnesi başlatılır
        self.engine = WindowsServiceSecurityEngine()

    def test_01_secure_baseline_service(self) -> None:
        """Test 01: Güvenli temel servis tam puan (100.0) almalı ve sıfır zafiyet üretmelidir."""
        # Güvenli bir Windows hizmet spesifikasyonu hazırlanır
        svc = WindowsServiceSpec(
            service_name="W32Time",
            display_name="Windows Time",
            image_path='"C:\\Windows\\system32\\svchost.exe" -k LocalService',
            start_type="Automatic",
            run_as_account="NT AUTHORITY\\LocalService",
            sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)",
            binary_permissions={"BUILTIN\\Users": ["ReadAndExecute"]},
            is_third_party=False,
        )
        # Servis denetimden geçirilir
        vulns = self.engine.evaluate_service(svc)
        # Zafiyet listesi boş olmalıdır
        self.assertEqual(len(vulns), 0)
        # Envanter denetimi sonucu kontrol edilir
        report = self.engine.audit_service_inventory([svc])
        # Güvenlik puanı 100.0 olmalıdır
        self.assertEqual(report["security_score"], 100.0)
        # Durum SECURE olmalıdır
        self.assertEqual(report["system_status"], "SECURE")

    def test_02_detect_unquoted_service_path_with_spaces(self) -> None:
        """Test 02: Boşluk içeren ve tırnaksız servis yolu CWE-428 zafiyeti üretmelidir."""
        # Boşluk içeren ve tırnaksız servis yolu tanımlanır
        raw_path = "C:\\Program Files\\Enterprise Backup\\engine.exe -daemon"
        # Fonksiyon doğrudan çağrılır
        is_unquoted, hijack_paths = self.engine.detect_unquoted_service_path(raw_path)
        # Zafiyetli bayrağı True dönmelidir
        self.assertTrue(is_unquoted)
        # Potansiyel tuzak yollar arasında Program.exe bulunmalıdır
        self.assertIn("C:\\Program.exe", hijack_paths)

    def test_03_quoted_service_path_with_spaces_is_safe(self) -> None:
        """Test 03: Çift tırnak içine alınmış boşluklu yol güvenli kabul edilmelidir."""
        # Çift tırnak içine alınmış servis yolu tanımlanır
        safe_path = '"C:\\Program Files\\Enterprise Backup\\engine.exe" -daemon'
        # Fonksiyon çağrılır
        is_unquoted, hijack_paths = self.engine.detect_unquoted_service_path(safe_path)
        # Zafiyet olmamalıdır
        self.assertFalse(is_unquoted)
        # Tuzak yollar listesi boş olmalıdır
        self.assertEqual(len(hijack_paths), 0)

    def test_04_path_without_spaces_is_safe(self) -> None:
        """Test 04: Boşluk içermeyen yollar tırnaksız olsa dahi CWE-428 oluşturmaz."""
        # Boşluksuz yol tanımlanır
        no_space_path = "C:\\Windows\\system32\\svchost.exe"
        # Fonksiyon çağrılır
        is_unquoted, hijack_paths = self.engine.detect_unquoted_service_path(no_space_path)
        # Boşluk olmadığı için zafiyetli değildir
        self.assertFalse(is_unquoted)
        # Aday liste boş olmalıdır
        self.assertEqual(len(hijack_paths), 0)

    def test_05_weak_dacl_change_config_builtin_users(self) -> None:
        """Test 05: BUILTIN\\Users grubuna SERVICE_CHANGE_CONFIG (DC) verilmesi CWE-732 üretmelidir."""
        # Düşük yetkili gruba DC hakkı veren SDDL tanımlanır
        weak_sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;DC;;;BU)"
        # SDDL ayrıştırılır
        entries = self.engine.parse_sddl_dacl(weak_sddl)
        # En az bir tehlikeli ACE bulunmalıdır
        has_dangerous = any(e.is_dangerous for e in entries)
        self.assertTrue(has_dangerous)

    def test_06_weak_dacl_write_dac_everyone(self) -> None:
        """Test 06: Everyone (WD) grubuna WRITE_DAC (WD) verilmesi kritik zafiyet oluşturmalıdır."""
        # Everyone grubuna izin manipülasyon hakkı veren SDDL
        weak_sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;WD;;;WD)"
        # SDDL ayrıştırılır
        entries = self.engine.parse_sddl_dacl(weak_sddl)
        # Tehlikeli ACE varlığı kontrol edilir
        dangerous_entries = [e for e in entries if e.is_dangerous]
        self.assertGreaterEqual(len(dangerous_entries), 1)
        # Hata açıklaması kontrol edilir
        self.assertIn("WRITE_DAC", dangerous_entries[0].danger_reason)

    def test_07_sddl_parser_decodes_standard_rights(self) -> None:
        """Test 07: SDDL ayrıştırıcı standart harf kodlarını insan okunabilir haklara dönüştürmelidir."""
        # SY için temel haklar içeren SDDL
        sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"
        # Fonksiyon çağrılır
        entries = self.engine.parse_sddl_dacl(sddl)
        # Bir giriş olmalıdır
        self.assertEqual(len(entries), 1)
        # Haklar arasında SERVICE_QUERY_CONFIG ve SERVICE_START bulunmalıdır
        self.assertIn("SERVICE_QUERY_CONFIG", entries[0].rights)
        self.assertIn("SERVICE_START", entries[0].rights)

    def test_08_weak_binary_file_permissions_users_modify(self) -> None:
        """Test 08: Servis binary dosyasında Users Modify izni CWE-732 / T1574.010 üretmelidir."""
        # Zayıf izin sözlüğü
        perms = {"BUILTIN\\Users": ["Modify", "Write"]}
        # Denetim fonksiyonu çağrılır
        is_weak, reason = self.engine.check_weak_binary_permissions(perms)
        # Zayıf olduğu tespit edilmelidir
        self.assertTrue(is_weak)
        # Açıklama metni kontrol edilir
        self.assertIn("yazma/değiştirme yetkisi", reason)

    def test_09_weak_binary_file_permissions_everyone_write(self) -> None:
        """Test 09: Everyone grubunun ikili dosyaya Write izni olması kritik zafiyet olmalıdır."""
        # Zayıf izin sözlüğü
        perms = {"Everyone": ["Write"]}
        # Fonksiyon çağrılır
        is_weak, reason = self.engine.check_weak_binary_permissions(perms)
        # Zayıf olduğu doğrulanır
        self.assertTrue(is_weak)

    def test_10_safe_binary_permissions(self) -> None:
        """Test 10: Standart ReadAndExecute izinleri zayıf dosya izni olarak işaretlenmemelidir."""
        # Güvenli izinler
        perms = {
            "NT AUTHORITY\\SYSTEM": ["FullControl"],
            "BUILTIN\\Administrators": ["FullControl"],
            "BUILTIN\\Users": ["ReadAndExecute"],
        }
        # Fonksiyon çağrılır
        is_weak, reason = self.engine.check_weak_binary_permissions(perms)
        # Güvenli olmalıdır
        self.assertFalse(is_weak)
        self.assertEqual(reason, "")

    def test_11_third_party_service_running_as_localsystem(self) -> None:
        """Test 11: Üçüncü parti servisin LocalSystem ile çalışması CWE-250 en az ayrıcalık ihlali üretmelidir."""
        # Üçüncü parti servis modeli oluşturulur
        svc = WindowsServiceSpec(
            service_name="CustomVendorSvc",
            display_name="Custom Vendor Service",
            image_path='"C:\\Vendor\\service.exe"',
            start_type="Automatic",
            run_as_account="LocalSystem",
            sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
            binary_permissions={"BUILTIN\\Users": ["ReadAndExecute"]},
            is_third_party=True,
        )
        # Değerlendirilir
        vulns = self.engine.evaluate_service(svc)
        # CWE-250 zafiyeti bulunmalıdır
        cwe_ids = [v.cwe_id for v in vulns]
        self.assertIn("CWE-250", cwe_ids)

    def test_12_cis_unnecessary_services_remote_registry(self) -> None:
        """Test 12: Aktif RemoteRegistry servisi CIS sıkılaştırma kuralını ihlal etmelidir."""
        # RemoteRegistry aktif servisi
        svc = WindowsServiceSpec(
            service_name="RemoteRegistry",
            display_name="Remote Registry",
            image_path='"C:\\Windows\\system32\\svchost.exe" -k regsvc',
            start_type="Automatic",
            run_as_account="NT AUTHORITY\\LocalService",
            sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
            binary_permissions={"BUILTIN\\Users": ["ReadAndExecute"]},
            is_third_party=False,
        )
        # Değerlendirilir
        vulns = self.engine.evaluate_service(svc)
        # CWE-16 zafiyeti olmalıdır
        cwe_ids = [v.cwe_id for v in vulns]
        self.assertIn("CWE-16", cwe_ids)

    def test_13_third_party_requesting_sedebugprivilege(self) -> None:
        """Test 13: Üçüncü parti servisin SeDebugPrivilege talep etmesi tehlikeli ayrıcalık uyarısı vermelidir."""
        # SeDebugPrivilege isteyen servis
        svc = WindowsServiceSpec(
            service_name="VendorProfiler",
            display_name="Vendor Profiler Agent",
            image_path='"C:\\Profiler\\agent.exe"',
            start_type="Automatic",
            run_as_account="NT SERVICE\\Profiler",
            sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
            binary_permissions={"BUILTIN\\Users": ["ReadAndExecute"]},
            required_privileges=["SeDebugPrivilege"],
            is_third_party=True,
        )
        # Değerlendirilir
        vulns = self.engine.evaluate_service(svc)
        # Ayrıcalık zafiyeti bulunmalıdır
        priv_vulns = [v for v in vulns if "Tehlikeli Ayrıcalık" in v.title]
        self.assertEqual(len(priv_vulns), 1)

    def test_14_powershell_remediation_generation(self) -> None:
        """Test 14: İyileştirme betiği üreticisi sc.exe ve PowerShell komutlarını doğru oluşturmalıdır."""
        # Zafiyetli bir servis
        svc = WindowsServiceSpec(
            service_name="InsecureSvc",
            display_name="Insecure Test Service",
            image_path="C:\\Program Files\\Test App\\test.exe",
            start_type="Automatic",
            run_as_account="LocalSystem",
            sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;DC;;;BU)",
            binary_permissions={"BUILTIN\\Users": ["Write"]},
            is_third_party=True,
        )
        # Denetim yapılır
        self.engine.audit_service_inventory([svc])
        # PowerShell betiği üretilir
        script = self.engine.generate_powershell_remediation_script()
        # sc config ve sc sdset komutları bulunmalıdır
        self.assertIn("sc.exe config", script)
        self.assertIn("sc.exe sdset", script)

    def test_15_end_to_end_inventory_audit_and_score(self) -> None:
        """Test 15: Çoklu servis envanteri uçtan uca denetlenip ağırlıklı skor ve durum üretilmelidir."""
        # 1 güvenli, 1 zafiyetli servis içeren liste
        services = [
            WindowsServiceSpec(
                service_name="SafeSvc",
                display_name="Safe Service",
                image_path='"C:\\Safe\\svc.exe"',
                start_type="Automatic",
                run_as_account="NT AUTHORITY\\LocalService",
                sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
                binary_permissions={"BUILTIN\\Users": ["ReadAndExecute"]},
                is_third_party=False,
            ),
            WindowsServiceSpec(
                service_name="BadSvc",
                display_name="Bad Service",
                image_path="C:\\Program Files\\Bad\\svc.exe",
                start_type="Automatic",
                run_as_account="LocalSystem",
                sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;DC;;;BU)",
                binary_permissions={"BUILTIN\\Users": ["Write"]},
                is_third_party=True,
            ),
        ]
        # Denetim icra edilir
        report = self.engine.audit_service_inventory(services)
        # 2 servis denetlenmiş olmalıdır
        self.assertEqual(report["total_services_audited"], 2)
        # Skor 100'den düşük olmalıdır
        self.assertLess(report["security_score"], 100.0)
        # Zafiyet sayısı 0'dan büyük olmalıdır
        self.assertGreater(report["total_vulnerabilities"], 0)


if __name__ == "__main__":
    unittest.main()
