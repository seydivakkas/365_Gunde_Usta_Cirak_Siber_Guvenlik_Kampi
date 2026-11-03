# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 144: Kerberos Temel Bilet Akışı Birim Test Paketi.
RFC 4120 Kerberos v5 bilet döngüsü, PAC HMAC bütünlüğü, yeniden oynatma
ve sahte bilet (Golden/Silver Ticket) kontrollerini 15 kapsamlı testle doğrular.
"""

# Python standart birim test kütüphanesi içe aktarılır.
import unittest
# Zaman ve tarih hesaplamaları için datetime modülü içe aktarılır.
import datetime
# Test edilen Kerberos motoru ve veri sınıfları içe aktarılır.
from uygulama.kerberos_ticket_flow_engine import (
    KerberosTicketFlowEngine,
    TicketType,
    EncryptionType,
    KerberosTicket,
    Authenticator,
    PACInfo,
)


class TestKerberosTicketFlow(unittest.TestCase):
    """
    Kerberos v5 bilet yaşam döngüsünü doğrulayan 15 birim testi sınıfı.
    """

    def setUp(self) -> None:
        """
        Her test öncesinde bağımsız bir test ortamı ve Kerberos motoru hazırlar.
        """
        # Etki alanı adı belirlenir.
        self.realm = "LAB.LOCAL"
        # Test motoru 300 saniyelik saat sapması eşiğiyle başlatılır.
        self.engine = KerberosTicketFlowEngine(realm=self.realm, max_clock_skew_seconds=300)
        # Test kullanıcısı ve anahtarı tanımlanır.
        self.client_user = "deniz@LAB.LOCAL"
        self.user_key = b"USER_SECRET_PASSWORD_HASH_AES256"
        self.engine.register_user(self.client_user, self.user_key, require_preauth=True)
        # Hedef servis ve anahtarı tanımlanır.
        self.spn = "cifs/storage01.lab.local"
        self.service_key = b"STORAGE_CIFS_SECRET_KEY_AES256"
        self.engine.register_service(self.spn, self.service_key)
        # Testler için referans zaman oluşturulur.
        self.base_time = datetime.datetime.now(datetime.timezone.utc)

    def test_01_successful_full_lifecycle_exchange(self) -> None:
        """
        1. Test: Tam Kerberos bilet takasının (AS -> TGS -> AP) AES-256 ile başarıyla tamamlanması.
        """
        now_str = self.base_time.isoformat()

        # 1. Aşama: AS-REQ
        tgt, sess_key, as_res = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            requested_encryption=EncryptionType.AES256_CTS_HMAC_SHA1_96,
            current_time=self.base_time
        )
        self.assertIsNotNone(tgt, "AS-REQ TGT üretmelidir")
        self.assertEqual(tgt.ticket_type, TicketType.TGT)
        self.assertTrue(any(r.is_valid and r.rule_name == "AS_EXCHANGE_SUCCESS" for r in as_res))

        # 2. Aşama: TGS-REQ
        auth_tgs = Authenticator(
            client_name=self.client_user,
            client_realm=self.realm,
            timestamp=now_str,
            cusec=1001
        )
        tgs, tgs_sess, tgs_res = self.engine.process_tgs_req(
            tgt=tgt,
            authenticator=auth_tgs,
            target_spn=self.spn,
            current_time=self.base_time
        )
        self.assertIsNotNone(tgs, "TGS-REQ servis bileti üretmelidir")
        self.assertEqual(tgs.ticket_type, TicketType.SERVICE)

        # 3. Aşama: AP-REQ
        auth_ap = Authenticator(
            client_name=self.client_user,
            client_realm=self.realm,
            timestamp=now_str,
            cusec=2002
        )
        report = self.engine.process_ap_req(
            service_ticket=tgs,
            authenticator=auth_ap,
            current_time=self.base_time
        )
        self.assertTrue(report.success, "AP-REQ doğrulaması başarılı olmalıdır")
        self.assertEqual(report.security_score, 100)
        self.assertEqual(len(report.anomalies), 0)

    def test_02_preauth_required_missing_timestamp(self) -> None:
        """
        2. Test: Ön kimlik doğrulama zorunlu olan kullanıcıda zaman damgası gönderilmezse AS-REQ reddedilmelidir.
        """
        tgt, sess_key, res = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=None,
            current_time=self.base_time
        )
        self.assertIsNone(tgt, "Ön kimlik doğrulaması eksikse TGT üretilmemelidir")
        self.assertTrue(any(r.rule_name == "PRE_AUTHENTICATION" and not r.is_valid for r in res))

    def test_03_as_req_clock_skew_exceeded(self) -> None:
        """
        3. Test: İstemci zaman damgası izin verilen 300 saniyelik saat sapmasını aşarsa AS-REQ reddedilmelidir.
        """
        skewed_time = (self.base_time - datetime.timedelta(seconds=600)).isoformat()
        tgt, sess_key, res = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=skewed_time,
            current_time=self.base_time
        )
        self.assertIsNone(tgt, "Saat sapması aşıldığında TGT verilmemelidir")
        self.assertTrue(any(r.rule_name == "CLOCK_SKEW" and not r.is_valid for r in res))

    def test_04_preauth_disabled_warning(self) -> None:
        """
        4. Test: DONT_REQ_PREAUTH bayrağı aktif kullanıcıda zafiyet uyarısı üretilmelidir.
        """
        vuln_user = "service_backup@LAB.LOCAL"
        self.engine.register_user(vuln_user, b"VULN_KEY", require_preauth=False)
        tgt, sess_key, res = self.engine.process_as_req(
            client_principal=vuln_user,
            preauth_timestamp=None,
            current_time=self.base_time
        )
        self.assertIsNotNone(tgt, "Pre-auth kapalıyken KDC TGT verir ancak zafiyet bayrağı açar")
        self.assertTrue(any(r.rule_name == "PREAUTH_VULNERABILITY" for r in res))

    def test_05_cipher_downgrade_rc4_rejected(self) -> None:
        """
        5. Test: RC4-HMAC şifreleme süiti talep edildiğinde düşürme (downgrade) saldırısı olarak reddedilmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, sess_key, res = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            requested_encryption=EncryptionType.RC4_HMAC,
            current_time=self.base_time
        )
        self.assertIsNone(tgt, "RC4-HMAC şifreleme talebi reddedilmelidir")
        self.assertTrue(any(r.rule_name == "CIPHER_SUITE_DOWNGRADE" for r in res))

    def test_06_cipher_downgrade_des_rejected(self) -> None:
        """
        6. Test: Kullanımdan kalkan DES-CBC-MD5 şifrelemesi kesinlikle reddedilmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, sess_key, res = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            requested_encryption=EncryptionType.DES_CBC_MD5,
            current_time=self.base_time
        )
        self.assertIsNone(tgt, "DES şifreleme talebi reddedilmelidir")
        self.assertTrue(any(r.rule_name == "CIPHER_SUITE_DOWNGRADE" for r in res))

    def test_07_tgs_unknown_spn_fails(self) -> None:
        """
        7. Test: Kayıtlı olmayan bir SPN için TGS-REQ yapıldığında istek reddedilmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, sess_key, _ = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            current_time=self.base_time
        )
        auth = Authenticator(
            client_name=self.client_user,
            client_realm=self.realm,
            timestamp=now_str,
            cusec=100
        )
        tgs, _, res = self.engine.process_tgs_req(
            tgt=tgt,
            authenticator=auth,
            target_spn="unknown_service/host.local",
            current_time=self.base_time
        )
        self.assertIsNone(tgs, "Bilinmeyen SPN için servis bileti üretilemez")
        self.assertTrue(any(r.rule_name == "SPN_EXISTENCE" and not r.is_valid for r in res))

    def test_08_golden_ticket_detection(self) -> None:
        """
        8. Test: Sahte TGT yükü (Golden Ticket) sunulduğunda KDC tarafından anında yakalanmalıdır.
        """
        now_str = self.base_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            current_time=self.base_time
        )
        # Saldırganın TGT imzasını tahrif etmesi simülasyonu
        tgt.encrypted_part_hash = "deadbeef1234567890abcdef"
        auth = Authenticator(
            client_name=self.client_user,
            client_realm=self.realm,
            timestamp=now_str,
            cusec=200
        )
        tgs, _, res = self.engine.process_tgs_req(
            tgt=tgt,
            authenticator=auth,
            target_spn=self.spn,
            current_time=self.base_time
        )
        self.assertIsNone(tgs, "Sahte TGT reddedilmelidir")
        self.assertTrue(any(r.rule_name == "GOLDEN_TICKET_DETECTED" for r in res))

    def test_09_expired_tgt_rejected(self) -> None:
        """
        9. Test: Süresi dolmuş TGT sunulduğunda TGS-REQ reddedilmelidir.
        """
        # Bilet 12 saat önce geçerli olarak üretilmiş olsun (TGT ömrü 10 saat)
        past_issue_time = self.base_time - datetime.timedelta(hours=12)
        past_str = past_issue_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=past_str,
            current_time=past_issue_time
        )
        now_str = self.base_time.isoformat()
        auth = Authenticator(
            client_name=self.client_user,
            client_realm=self.realm,
            timestamp=now_str,
            cusec=300
        )
        tgs, _, res = self.engine.process_tgs_req(
            tgt=tgt,
            authenticator=auth,
            target_spn=self.spn,
            current_time=self.base_time
        )
        self.assertIsNone(tgs, "Süresi dolmuş TGT reddedilmelidir")
        self.assertTrue(any(r.rule_name == "TGT_EXPIRED" for r in res))

    def test_10_authenticator_client_mismatch(self) -> None:
        """
        10. Test: Kanıtlayıcıdaki istemci ile TGT içindeki istemci uyuşmazsa TGS-REQ reddedilmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            current_time=self.base_time
        )
        # Farklı bir istemci adı gönderilir
        fake_auth = Authenticator(
            client_name="attacker@LAB.LOCAL",
            client_realm=self.realm,
            timestamp=now_str,
            cusec=400
        )
        tgs, _, res = self.engine.process_tgs_req(
            tgt=tgt,
            authenticator=fake_auth,
            target_spn=self.spn,
            current_time=self.base_time
        )
        self.assertIsNone(tgs, "İstemci uyuşmazlığında servis bileti verilmemelidir")
        self.assertTrue(any(r.rule_name == "CLIENT_PRINCIPAL_MISMATCH" for r in res))

    def test_11_tgs_replay_attack_prevention(self) -> None:
        """
        11. Test: TGS aşamasında aynı kanıtlayıcı iki kez sunulursa yeniden oynatma (Replay) olarak engellenmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            current_time=self.base_time
        )
        auth = Authenticator(
            client_name=self.client_user,
            client_realm=self.realm,
            timestamp=now_str,
            cusec=777
        )
        # İlk kullanım başarılı
        tgs1, _, _ = self.engine.process_tgs_req(tgt, auth, self.spn, self.base_time)
        self.assertIsNotNone(tgs1)

        # İkinci kullanım (Replay saldırısı) reddedilmelidir
        tgs2, _, res = self.engine.process_tgs_req(tgt, auth, self.spn, self.base_time)
        self.assertIsNone(tgs2, "Yeniden oynatılan kanıtlayıcı reddedilmelidir")
        self.assertTrue(any(r.rule_name == "REPLAY_ATTACK_DETECTED" for r in res))

    def test_12_silver_ticket_detection(self) -> None:
        """
        12. Test: Servis anahtarıyla uyuşmayan sahte servis bileti (Silver Ticket) AP-REQ'de tespit edilmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(
            client_principal=self.client_user,
            preauth_timestamp=now_str,
            current_time=self.base_time
        )
        auth_tgs = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=501)
        tgs, _, _ = self.engine.process_tgs_req(tgt, auth_tgs, self.spn, self.base_time)

        # Saldırgan servis biletinin şifreli hash değerini sahte anahtarla değiştirir
        tgs.encrypted_part_hash = "fake_service_signature_hash_value"
        auth_ap = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=502)

        report = self.engine.process_ap_req(tgs, auth_ap, self.base_time)
        self.assertFalse(report.success, "Silver ticket başarısız olmalıdır")
        self.assertIn("Silver Ticket Sahteciliği", report.anomalies)

    def test_13_pac_server_signature_tampering(self) -> None:
        """
        13. Test: Bilet içindeki PAC sunucu imzası tahrif edilirse AP-REQ'de tespit edilmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(client_principal=self.client_user, preauth_timestamp=now_str, current_time=self.base_time)
        auth_tgs = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=601)
        tgs, _, _ = self.engine.process_tgs_req(tgt, auth_tgs, self.spn, self.base_time)

        # Saldırgan PAC içine Domain Admins grubunu enjekte eder fakat imzayı güncelleyemez
        tgs.pac.group_sids.append("S-1-5-21-123456789-987654321-512")
        auth_ap = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=602)

        report = self.engine.process_ap_req(tgs, auth_ap, self.base_time)
        self.assertFalse(report.success)
        self.assertIn("PAC Sunucu İmzası Sahteciliği", report.anomalies)

    def test_14_pac_kdc_signature_tampering(self) -> None:
        """
        14. Test: PAC KDC imzası bozulursa sahte KDC bileti tespit edilmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(client_principal=self.client_user, preauth_timestamp=now_str, current_time=self.base_time)
        auth_tgs = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=701)
        tgs, _, _ = self.engine.process_tgs_req(tgt, auth_tgs, self.spn, self.base_time)

        # KDC imzası bozulur
        tgs.pac.kdc_signature = "invalid_kdc_sig_abcdef"
        auth_ap = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=702)

        report = self.engine.process_ap_req(tgs, auth_ap, self.base_time)
        self.assertFalse(report.success)
        self.assertIn("PAC KDC İmzası Sahteciliği", report.anomalies)

    def test_15_ap_req_replay_attack_prevention(self) -> None:
        """
        15. Test: AP-REQ aşamasında aynı kanıtlayıcı tekrar sunulursa sunucu tarafından engellenmelidir.
        """
        now_str = self.base_time.isoformat()
        tgt, _, _ = self.engine.process_as_req(client_principal=self.client_user, preauth_timestamp=now_str, current_time=self.base_time)
        auth_tgs = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=801)
        tgs, _, _ = self.engine.process_tgs_req(tgt, auth_tgs, self.spn, self.base_time)

        auth_ap = Authenticator(client_name=self.client_user, client_realm=self.realm, timestamp=now_str, cusec=888)
        # 1. Başarılı kullanım
        rep1 = self.engine.process_ap_req(tgs, auth_ap, self.base_time)
        self.assertTrue(rep1.success)

        # 2. Yeniden Oynatma saldırısı
        rep2 = self.engine.process_ap_req(tgs, auth_ap, self.base_time)
        self.assertFalse(rep2.success)
        self.assertIn("AP Yeniden Oynatma Saldırısı", rep2.anomalies)


if __name__ == "__main__":
    unittest.main()
