# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G082: pytest ile Güvenlik Politikası Birim Test Paketi (14 Test Fonksiyonu)
"""

# pytest test çerçevesini ve yardımcı araçlarını içeri aktarıyoruz.
import pytest
# Tip denetimi için generic tipleri içeri aktarıyoruz.
from typing import Any, Dict

# Test edilecek politika doğrulama fonksiyonlarını ve sınıflarını içeri aktarıyoruz.
from portfolio.hafta_12.gun_082.uygulama.security_policy_enforcer import (
    PolicyViolationException,
    SecurityPolicyEnforcer,
    classify_security_incident,
    evaluate_firewall_rule,
    sanitize_target_domain,
    validate_password_complexity,
)


# ==============================================================================
# PYTEST FIXTURE TANIMLARI (DETERMİNİSTİK TEST ORTAMI)
# ==============================================================================

@pytest.fixture
def policy_enforcer() -> SecurityPolicyEnforcer:
    """
    Her test için bağımsız ve izole bir SecurityPolicyEnforcer nesnesi sağlayan pytest fixture.
    """
    # 5 istek tavanı ile yeni bir yürütücü nesnesi döndürüyoruz.
    return SecurityPolicyEnforcer(max_requests_per_client=5)


@pytest.fixture
def valid_firewall_payload() -> Dict[str, Any]:
    """
    Geçerli ve standart bir güvenlik duvarı kural sözlüğü sağlayan pytest fixture.
    """
    # Standart geçerli kural sözlüğünü döndürüyoruz.
    return {
        "source_ip": "192.168.1.100",
        "dest_port": 443,
        "protocol": "TCP"
    }


# ==============================================================================
# BİRİM TESTLER VE PARAMETRİK SENARYOLAR
# ==============================================================================

@pytest.mark.security
def test_01_password_complexity_valid() -> None:
    """
    Karmaşıklık kurallarına tam uyan güçlü parolaların başarıyla onaylandığını sınar.
    """
    # Kurallara tam uyan karmaşık parola örneği.
    strong_pwd = "V3ry$ecureP@ssw0rd2026!"
    # Fonksiyonun True döndürdüğünü assert ediyoruz.
    assert validate_password_complexity(strong_pwd) is True


@pytest.mark.security
@pytest.mark.negative
@pytest.mark.parametrize("short_pwd", ["Kisa1!", "Abc!1", "123456789!A", "11Karakter!"])
def test_02_password_complexity_too_short(short_pwd: str) -> None:
    """
    12 karakterden kısa parolaların PolicyViolationException ile reddedildiğini parametrik olarak test eder.
    """
    # pytest.raises ile kural ihlali fırlatıldığını denetliyoruz.
    with pytest.raises(PolicyViolationException, match="Parola uzunluğu 12-64 karakter arasında olmalıdır"):
        # Kısa parolayı doğrulamayı deniyoruz.
        validate_password_complexity(short_pwd)


@pytest.mark.security
@pytest.mark.negative
@pytest.mark.parametrize(
    "invalid_pwd, err_snippet",
    [
        ("kucukharfveozelkarakter123!", "büyük harf"),
        ("BUYUKHARFVEOZELKARAKTER123!", "küçük harf"),
        ("HarfVeOzelKarakterVarAmaSayiYok!", "rakam"),
        ("BuyukKucukRakamVarAmaOzelYok123", "özel karakter"),
    ]
)
def test_03_password_complexity_missing_character_classes(invalid_pwd: str, err_snippet: str) -> None:
    """
    Büyük harf, küçük harf, rakam veya özel karakter eksikliklerinin reddedildiğini parametrik sınar.
    """
    # Beklenen hata mesajı kesiti ile istisnanın fırlatıldığını sınıyoruz.
    with pytest.raises(PolicyViolationException, match=err_snippet):
        # Eksik sınıflı parolayı deniyoruz.
        validate_password_complexity(invalid_pwd)


@pytest.mark.security
@pytest.mark.negative
def test_04_password_complexity_dictionary_blacklist() -> None:
    """
    Bilinen yaygın sözlük parolasının kara liste filtresiyle reddedildiğini sınar.
    """
    # Sözlükte kayıtlı yasaklı parola örneği.
    banned_pwd = "Password123!@#"
    # Kara liste ihlali fırlatıldığını sınıyoruz.
    with pytest.raises(PolicyViolationException, match="sözlük listesinde"):
        # Sözlük parolasını sınıyoruz.
        validate_password_complexity(banned_pwd)


@pytest.mark.security
@pytest.mark.parametrize(
    "score, expected_level",
    [
        (0, "LOW"),
        (39, "LOW"),
        (40, "MEDIUM"),
        (69, "MEDIUM"),
        (70, "HIGH"),
        (89, "HIGH"),
        (90, "CRITICAL"),
        (100, "CRITICAL"),
    ]
)
def test_05_classify_security_incident_boundaries(score: int, expected_level: str) -> None:
    """
    Tehdit puanı sınıflandırma sınırlarının (boundary testing) doğruluğunu parametrik olarak test eder.
    """
    # Sınıflandırma sonucunu assert ediyoruz.
    assert classify_security_incident(score) == expected_level


@pytest.mark.security
@pytest.mark.negative
@pytest.mark.parametrize("invalid_score", [-100, -1, 101, 250])
def test_06_classify_security_incident_out_of_bounds(invalid_score: int) -> None:
    """
    0-100 sınırları dışındaki değerlerin ValueError ile durdurulduğunu sınar.
    """
    # ValueError fırlatılmasını bekliyoruz.
    with pytest.raises(ValueError, match="Ciddiyet skoru 0-100 aralığında olmalıdır"):
        # Sınır dışı puanı test ediyoruz.
        classify_security_incident(invalid_score)


@pytest.mark.security
@pytest.mark.parametrize(
    "raw_domain, expected_domain",
    [
        ("example.com", "example.com"),
        ("HTTPS://SUB.DOMAIN.ORG", "sub.domain.org"),
        ("http://target-soc.internal.corp", "target-soc.internal.corp"),
        ("  api.gateway.net  ", "api.gateway.net"),
    ]
)
def test_07_sanitize_target_domain_valid(raw_domain: str, expected_domain: str) -> None:
    """
    Meşru alan adlarının protokol öneki temizlenerek küçük harfe dönüştürüldüğünü doğrular.
    """
    # Çıktının beklenen alan adına eşit olduğunu assert ediyoruz.
    assert sanitize_target_domain(raw_domain) == expected_domain


@pytest.mark.security
@pytest.mark.negative
@pytest.mark.parametrize(
    "traversal_domain",
    [
        ("target.com/../../etc/passwd"),
        ("target.com\\..\\..\\windows\\system32"),
        ("evil.com/shell.php"),
    ]
)
def test_08_sanitize_target_domain_path_traversal_raises(traversal_domain: str) -> None:
    """
    Alan adına enjekte edilen yol geçişi (Path Traversal) karakterlerinin reddedildiğini test eder.
    """
    # PolicyViolationException fırlatıldığını denetliyoruz.
    with pytest.raises(PolicyViolationException, match="geçersiz yol karakterleri"):
        # Zararlı alan adını temizlemeyi deniyoruz.
        sanitize_target_domain(traversal_domain)


@pytest.mark.security
@pytest.mark.negative
def test_09_sanitize_target_domain_null_byte_raises() -> None:
    """
    Alan adı dizesindeki null-byte (\x00) zehirleme karakterinin engellendiğini doğrular.
    """
    # Null-byte içeren alan adı girdisi.
    null_domain = "target.corp\x00.attacker.com"
    # Null-byte ihlali fırlatıldığını sınıyoruz.
    with pytest.raises(PolicyViolationException, match="geçersiz null-byte"):
        # Temizlemeyi deniyoruz.
        sanitize_target_domain(null_domain)


@pytest.mark.security
def test_10_evaluate_firewall_rule_valid(valid_firewall_payload: Dict[str, Any]) -> None:
    """
    Geçerli bir güvenlik duvarı kuralının fixture üzerinden doğrulanarak True döndüğünü test eder.
    """
    # Kural doğrulamasının True olduğunu assert ediyoruz.
    assert evaluate_firewall_rule(valid_firewall_payload) is True


@pytest.mark.security
@pytest.mark.negative
@pytest.mark.parametrize("invalid_port", [0, 65536, 70000, -1, "80"])
def test_11_evaluate_firewall_rule_invalid_port(valid_firewall_payload: Dict[str, Any], invalid_port: Any) -> None:
    """
    1-65535 aralığı dışındaki veya tamsayı olmayan portların reddedildiğini parametrik olarak test eder.
    """
    # Kural sözlüğündeki portu geçersiz değerle güncelliyoruz.
    bad_rule = dict(valid_firewall_payload)
    # Port değerini atıyoruz.
    bad_rule["dest_port"] = invalid_port
    # PolicyViolationException fırlatılmasını bekliyoruz.
    with pytest.raises(PolicyViolationException, match="Hedef port 1-65535 aralığında"):
        # Kuralı sınıyoruz.
        evaluate_firewall_rule(bad_rule)


@pytest.mark.security
@pytest.mark.negative
def test_12_evaluate_firewall_rule_invalid_ip(valid_firewall_payload: Dict[str, Any]) -> None:
    """
    Geçersiz veya bozuk IPv4 adreslerinin PolicyViolationException ile engellendiğini sınar.
    """
    # Bozuk IP içeren kural kopyası oluşturuyoruz.
    bad_rule = dict(valid_firewall_payload)
    # Geçersiz IP atıyoruz.
    bad_rule["source_ip"] = "999.888.777.666"
    # Kural ihlali fırlatılmasını bekliyoruz.
    with pytest.raises(PolicyViolationException, match="Geçersiz kaynak IPv4 adresi"):
        # Kuralı sınıyoruz.
        evaluate_firewall_rule(bad_rule)


@pytest.mark.security
@pytest.mark.negative
def test_13_enforcer_rate_limiting_fixture(policy_enforcer: SecurityPolicyEnforcer) -> None:
    """
    pytest fixture nesnesi üzerinden istemci başına 5 istek limitinin aşıldığında engellendiğini sınar.
    """
    # Saldırgan IP'si tanımlıyoruz.
    client_ip = "198.51.100.77"
    # İzin verilen 5 isteği başarıyla yürütüyoruz.
    for _ in range(5):
        # 5 geçerli istek yapıyoruz.
        policy_enforcer.execute_policy_check(client_ip, "SEVERITY_CLASSIFICATION", 50)
    # 6. istekte hız sınırı aşımı fırlatıldığını denetliyoruz.
    with pytest.raises(PolicyViolationException, match="İstemci hız sınırı eşiği aşıldı"):
        # Eşik üstü isteği yapmayı deniyoruz.
        policy_enforcer.execute_policy_check(client_ip, "SEVERITY_CLASSIFICATION", 50)


@pytest.mark.security
def test_14_enforcer_audit_log_recording(policy_enforcer: SecurityPolicyEnforcer) -> None:
    """
    Başarılı politika kontrollerinin denetim günlüğüne (audit_log) kaydedildiğini doğrular.
    """
    # Meşru IP tanımlıyoruz.
    ip = "10.0.0.1"
    # Parola kontrolü yürütüyoruz.
    policy_enforcer.execute_policy_check(ip, "PASSWORD_POLICY", "Sup3r_Str0ng_P@ssword2026!")
    # Denetim günlüğünde 1 kayıt bulunduğunu assert ediyoruz.
    assert len(policy_enforcer.audit_log) == 1
    # Kaydedilen politikanın adını sınıyoruz.
    assert policy_enforcer.audit_log[0]["policy"] == "PASSWORD_POLICY"
    # Kaydedilen IP'nin doğruluğunu sınıyoruz.
    assert policy_enforcer.audit_log[0]["client_ip"] == ip
