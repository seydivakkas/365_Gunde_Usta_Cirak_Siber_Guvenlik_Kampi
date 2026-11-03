"""
Etik, Yasal Yetki ve Test Kapsamı Birim ve Entegrasyon Testleri
==============================================================
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Bu test paketi, Gün 003 için yazılı kapsam belgesi (RoE) kurallarını,
pozitif hedefleri/eylemleri ve negatif kontrolleri (yasaklı IP, canlı sistem,
üçüncü taraf hedef, DoS/veri silme gibi yıkıcı faaliyetler) doğrular.
"""

import os
import sys
import tempfile
import json
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))
from scope_validator import (
    EngagementScopeValidator,
    OutOfScopeTargetError,
    ExplicitlyForbiddenTargetError,
    UnauthorizedActionError,
    ForbiddenActionError,
    run_comprehensive_scope_audit
)


class TestEngagementScopeValidator(unittest.TestCase):
    def setUp(self):
        """Test için izole kapsam politikası hazırlar."""
        self.policy_data = {
            "kurum_adi": "Test Finans A.Ş.",
            "kapsam_ici_hedefler": {
                "ip_listesi": ["192.168.1.10", "192.168.1.11"],
                "cidr_bloklari": ["192.168.1.0/24"],
                "alan_adlari": ["test.local"]
            },
            "kesinlikle_kapsam_disi_hedefler": {
                "ip_listesi": ["192.168.1.1", "8.8.8.8"],
                "alan_adlari": ["canli.com"]
            },
            "izin_verilen_faaliyetler": ["PORT_SCAN", "WEB_VULN_SCAN"],
            "kesinlikle_yasaklanan_faaliyetler": ["DOS_ATTACK", "DATA_DELETION"]
        }
        self.temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8")
        json.dump(self.policy_data, self.temp_file, ensure_ascii=False)
        self.temp_file.close()
        self.validator = EngagementScopeValidator(self.temp_file.name)

    def tearDown(self):
        """Geçici dosyayı temizler."""
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    # -------------------------------------------------------------
    # 1. POZİTİF KONTROLLER: İZİNLİ HEDEF VE EYLEMLER
    # -------------------------------------------------------------
    def test_positive_allowed_ip_and_action(self):
        """Kapsam içi IP ve izinli eylemin başarıyla onaylandığını doğrular."""
        res = self.validator.authorize_execution("192.168.1.10", "PORT_SCAN")
        self.assertTrue(res)

    def test_positive_allowed_cidr_range(self):
        """Ağ bloğu (CIDR) içerisindeki geçerli bir IP'nin onaylandığını doğrular."""
        res = self.validator.authorize_execution("192.168.1.55", "WEB_VULN_SCAN")
        self.assertTrue(res)

    def test_positive_allowed_domain(self):
        """Kapsam içi alan adının onaylandığını doğrular."""
        res = self.validator.authorize_execution("test.local", "PORT_SCAN")
        self.assertTrue(res)

    # -------------------------------------------------------------
    # 2. NEGATİF KONTROLLER: YASAKLI VE KAPSAM DIŞI HEDEFLER
    # -------------------------------------------------------------
    def test_negative_explicitly_forbidden_ip(self):
        """Yasaklı IP'ye (örn. ağ geçidi veya üçüncü taraf 8.8.8.8) erişimin engellendiğini doğrular."""
        with self.assertRaises(ExplicitlyForbiddenTargetError):
            self.validator.authorize_execution("192.168.1.1", "PORT_SCAN")

        with self.assertRaises(ExplicitlyForbiddenTargetError):
            self.validator.authorize_execution("8.8.8.8", "PORT_SCAN")

    def test_negative_explicitly_forbidden_domain(self):
        """Yasaklı canlı sisteme (canli.com) erişimin engellendiğini doğrular."""
        with self.assertRaises(ExplicitlyForbiddenTargetError):
            self.validator.authorize_execution("canli.com", "WEB_VULN_SCAN")

    def test_negative_out_of_scope_target(self):
        """Listede hiç bulunmayan yabancı bir hedefin engellendiğini doğrular."""
        with self.assertRaises(OutOfScopeTargetError):
            self.validator.authorize_execution("10.0.0.99", "PORT_SCAN")

    # -------------------------------------------------------------
    # 3. NEGATİF KONTROLLER: YASAKLI VE TANIMSIZ EYLEMLER
    # -------------------------------------------------------------
    def test_negative_forbidden_action_dos(self):
        """DoS veya yıkıcı saldırı eyleminin ForbiddenActionError ile bloke edildiğini doğrular."""
        with self.assertRaises(ForbiddenActionError):
            self.validator.authorize_execution("192.168.1.10", "DOS_ATTACK")

    def test_negative_forbidden_action_data_deletion(self):
        """Veri silme eyleminin ForbiddenActionError ile bloke edildiğini doğrular."""
        with self.assertRaises(ForbiddenActionError):
            self.validator.authorize_execution("192.168.1.10", "DATA_DELETION")

    def test_negative_unauthorized_action(self):
        """Politikada tanımlanmamış eylemin UnauthorizedActionError ile bloke edildiğini doğrular."""
        with self.assertRaises(UnauthorizedActionError):
            self.validator.authorize_execution("192.168.1.10", "BILINMEYEN_EYLEM")

    # -------------------------------------------------------------
    # 4. TAM ENTEGRASYON VE MÜFREDAT KAPSAMI DENETİMİ
    # -------------------------------------------------------------
    def test_actual_curriculum_policy_audit(self):
        """Gerçek örnek veri kapsam_belgesi.json dosyasının denetimini doğrular."""
        actual_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "kapsam_belgesi.json")
        success = run_comprehensive_scope_audit(actual_path)
        self.assertTrue(success)


if __name__ == "__main__":
    unittest.main()
