# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G084: Mini Proje 11: Test Edilen Güvenlik Log Aracı birim testleri (pytest).
Bu test paketi; dosya yolu sınırlandırması, log enjeksiyonu önleme, hassas veri maskeleme,
ağ IP doğrulaması, kaba kuvvet ve SQL enjeksiyonu tespit algoritmalarını doğrular.
"""

from pathlib import Path  # Dosya sistemi yollari icin Path modulu ice aktarilir
import pytest  # pytest test cercevesi ice aktarilir

from portfolio.hafta_12.gun_084.uygulama.tested_security_log_tool import (  # Uygulama modulleri ice aktarilir
    BruteForceDetectedException,  # Kaba kuvvet istisnasi
    InvalidIpAddressException,  # Gecersiz IP istisnasi
    LogContentSanitizer,  # Log arindirici
    LogInjectionAttemptException,  # Log enjeksiyon istisnasi
    LogLineLengthLimitException,  # Uzunluk siniri istisnasi
    NetworkValidator,  # Ag dogrulayici
    NullByteForbiddenException,  # Null byte istisnasi
    SecureLogPathResolver,  # Yol cozucu
    SecurityAlertLevel,  # Alarm seviyesi enum degeri
    SecurityPathTraversalException,  # Path traversal istisnasi
    SqlInjectionDetectedException,  # SQLi istisnasi
    SymlinkViolationException,  # Symlink istisnasi
    TestedSecurityLogTool,  # Façade ana motor
    ThreatDetectionEngine,  # Tehdit tespit motoru
)


@pytest.mark.security
def test_01_resolve_valid_log_path(base_test_dir: Path, sample_jsonl_path: Path) -> None:
    """Izin verilen dizin icerisindeki gecerli log dosyasinin basariyla cozuldugunu dogrular."""
    rel_path = "ornek_veri/raw_access_logs.jsonl"  # Goreceli yol belirlenir
    cozulmus = SecureLogPathResolver.resolve_log_path(rel_path, base_test_dir)  # Yol cozulur
    assert cozulmus.exists() is True  # Dosyanin var oldugu dogrulanir
    assert cozulmus == sample_jsonl_path.resolve()  # Mutlak hedefin esitligi kontrol edilir


@pytest.mark.security
@pytest.mark.negative
def test_02_path_traversal_detection(base_test_dir: Path) -> None:
    """Kok dizin disina cikmaya calisan path traversal saldirilarinin engellendigini dogrular."""
    saldiri_yolu = "../../windows/system32/cmd.exe"  # Dizin atlama yolu
    with pytest.raises(SecurityPathTraversalException, match="Path Traversal Engellendi"):  # Istisna beklenir
        SecureLogPathResolver.resolve_log_path(saldiri_yolu, base_test_dir)  # Cozumleme denenir


@pytest.mark.security
@pytest.mark.negative
def test_03_symlink_violation_detection(tmp_path: Path) -> None:
    """Sembolik bag (symlink) ile guvenlik sinirini baypas etme girisiminin engellendigini test eder."""
    dis_hedef = tmp_path / "secret.txt"  # Dis hedef dosya
    dis_hedef.write_text("sensitivedata", encoding="utf-8")  # Dosyaya veri yazilir
    
    guvenli_dizin = tmp_path / "safe_dir"  # Guvenli temel dizin
    guvenli_dizin.mkdir()  # Dizin olusturulur
    symlink_dosya = guvenli_dizin / "link_to_secret.log"  # Sembolik bag yolu
    
    try:  # Windows ortaminda symlink yetkisi kontrol edilir
        symlink_dosya.symlink_to(dis_hedef)  # Sembolik bag olusturulur
        with pytest.raises(SymlinkViolationException, match="Sembolik bag erisimi"):  # Istisna beklenir
            SecureLogPathResolver.resolve_log_path(str(symlink_dosya), guvenli_dizin)  # Cozumleme denenir
    except (OSError, NotImplementedError):  # Eger OS symlink izin vermezse test basarili sayilir
        pytest.skip("Isletim sistemi symlink olusturma yetkisine izin vermiyor.")  # Test atlanir


@pytest.mark.security
@pytest.mark.negative
def test_04_null_byte_in_path_rejection(base_test_dir: Path) -> None:
    """Dosya yoluna eklenen null byte (0x00) karakterinin guvenlikle reddedildigini dogrular."""
    zararli_yol = "ornek_veri/raw_access_logs.jsonl\x00.exe"  # Null byte iceren yol
    with pytest.raises(NullByteForbiddenException, match="null byte"):  # Istisna beklenir
        SecureLogPathResolver.resolve_log_path(zararli_yol, base_test_dir)  # Denenir


def test_05_crlf_log_injection_neutralization() -> None:
    """CRLF enjeksiyonunun normal modda boslukla degistirilerek log bolunmesinin engellendigini test eder."""
    zararli_satir = "User login successful\r\n[CRITICAL] ADMIN PASSWORD CHANGED"  # CRLF iceren satir
    temiz = LogContentSanitizer.sanitize_line(zararli_satir, strict=False)  # Normal modda temizlenir
    assert "\r" not in temiz  # \r karakteri kalmamali
    assert "\n" not in temiz  # \n karakteri kalmamali
    assert "User login successful [CRITICAL] ADMIN PASSWORD CHANGED" in temiz  # Tek satira indirgenmeli


@pytest.mark.security
@pytest.mark.negative
def test_06_crlf_log_injection_strict_rejection() -> None:
    """Kati (strict) modda CRLF enjeksiyonunun derhal LogInjectionAttemptException firlattigini test eder."""
    zararli_satir = "User login\nFAKE_LOG"  # \n iceren satir
    with pytest.raises(LogInjectionAttemptException, match="Log Injection"):  # Istisna beklenir
        LogContentSanitizer.sanitize_line(zararli_satir, strict=True)  # Kati modda cagrilir


@pytest.mark.parametrize(
    "raw_input,expected_masked",
    [
        ("Payment 4532-1122-3344-5566 processed", "Payment ****-****-****-5566 processed"),
        ("Card 1234 5678 9876 5432 charged", "Card ****-****-****-5432 charged"),
        ("No card present here", "No card present here"),
    ]
)
def test_07_sensitive_data_redaction_credit_card(raw_input: str, expected_masked: str) -> None:
    """Kredi karti numaralarinin son 4 hane haric dogru maskelendigini test eder."""
    sonuc = LogContentSanitizer.sanitize_line(raw_input)  # Maskeleme fonksiyonu cagrilir
    assert sonuc == expected_masked  # Beklenen maskeli cikti teyit edilir


@pytest.mark.parametrize(
    "raw_input,expected_fragment",
    [
        ("User login password=MySuperPass123! token=123", "password=***REDACTED***"),
        ("Access key AKIAIOSFODNN7EXAMPLE used", "AKIA***REDACTED***"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig", "Bearer [REDACTED_JWT]"),
    ]
)
def test_08_sensitive_data_redaction_credentials(raw_input: str, expected_fragment: str) -> None:
    """Parola, AWS anahtari ve JWT tokenlarinin loglarda maskelendigini dogrular."""
    sonuc = LogContentSanitizer.sanitize_line(raw_input)  # Temizleme fonksiyonu cagrilir
    assert expected_fragment in sonuc  # Maskelenmis parca ciktida yer almali


@pytest.mark.parametrize(
    "valid_ip",
    [
        "192.168.1.1",
        "10.0.0.254",
        "127.0.0.1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "::1",
    ]
)
def test_09_network_validator_ipv4_and_ipv6(valid_ip: str) -> None:
    """IPv4 ve IPv6 adreslerinin standart formatta basariyla dogrulandigini test eder."""
    dogrulanmis = NetworkValidator.validate_ip(valid_ip)  # Dogrulama fonksiyonu cagrilir
    assert isinstance(dogrulanmis, str)  # Ciktinin metin oldugu dogrulanir
    assert len(dogrulanmis) > 0  # Bos olmadigi dogrulanir


@pytest.mark.security
@pytest.mark.negative
@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.999.999.999",
        "abc.def.ghi.jkl",
        "192.168.1.300",
        "",
        "not_an_ip",
    ]
)
def test_10_network_validator_invalid_ip(invalid_ip: str) -> None:
    """Hatali IP adreslerinin InvalidIpAddressException ile reddedildigini dogrular."""
    with pytest.raises(InvalidIpAddressException):  # Istisna beklenir
        NetworkValidator.validate_ip(invalid_ip)  # Dogrulama denenir


@pytest.mark.security
def test_11_threat_detection_brute_force() -> None:
    """Kaba kuvvet giris denemelerinde esik asildiginda CRITICAL seviyede alarm olustugunu dogrular."""
    engine = ThreatDetectionEngine(brute_force_threshold=3)  # Esik 3 olarak ayarlanir
    ip = "10.0.0.50"  # Hedef saldirgan IP
    endpoint = "/api/v1/auth/login"  # Giris ucnoktasi

    # Ilk 2 deneme esigin altindadir, kaba kuvvet alarmi uretilmez
    alarms1 = engine.evaluate_entry(ip, endpoint, 401, "curl", "fail 1")  # 1. deneme
    alarms2 = engine.evaluate_entry(ip, endpoint, 401, "curl", "fail 2")  # 2. deneme
    assert not any(a.alert_type == "AUTHENTICATION_BRUTE_FORCE" for a in alarms1)  # Alarm yok
    assert not any(a.alert_type == "AUTHENTICATION_BRUTE_FORCE" for a in alarms2)  # Alarm yok

    # 3. deneme esige ulasir ve CRITICAL alarm tetiklenir
    alarms3 = engine.evaluate_entry(ip, endpoint, 401, "curl", "fail 3")  # 3. deneme
    brute_alarms = [a for a in alarms3 if a.alert_type == "AUTHENTICATION_BRUTE_FORCE"]  # Alarmlar filtrelenir
    assert len(brute_alarms) == 1  # Tam 1 kaba kuvvet alarmi uretilmis olmali
    assert brute_alarms[0].alert_level == SecurityAlertLevel.CRITICAL  # Seviye CRITICAL olmali


@pytest.mark.security
def test_12_threat_detection_sql_injection() -> None:
    """Istek parametrelerinde SQL enjeksiyonu tespit edildiginde alarm uretildigini dogrular."""
    engine = ThreatDetectionEngine()  # Motor ornegi
    endpoint = "/api/v1/users?id=1' UNION SELECT username, password FROM users--"  # SQLi parametresi
    alarmlar = engine.evaluate_entry("192.168.1.1", endpoint, 200, "Mozilla", "query error")  # Analiz yapilir
    sqli_alarms = [a for a in alarmlar if a.alert_type == "SQL_INJECTION_ATTEMPT"]  # SQLi alarmlari
    assert len(sqli_alarms) == 1  # 1 adet SQLi alarmi bulunmali
    assert sqli_alarms[0].alert_level == SecurityAlertLevel.CRITICAL  # Kritik seviye


def test_13_process_sample_jsonl_file_end_to_end(log_tool: TestedSecurityLogTool, sample_jsonl_path: Path) -> None:
    """Ornek raw_access_logs.jsonl dosyasinin uctan uca basariyla islendigini ve ozet metrikleri dogrular."""
    entries, summary = log_tool.process_log_file(str(sample_jsonl_path))  # Dosya islenir
    assert summary.toplam_islenen == 8  # Toplam 8 satir olmali
    assert summary.toplam_gecerli == 8  # Tum satirlar basariyla ayrastirilmis olmali
    assert summary.toplam_reddedilen == 0  # Reddedilen 0 olmali
    assert summary.toplam_alarm_sayisi > 0  # Tehditler alarm uretmis olmali
    assert "10.0.0.15" in summary.ip_istatistikleri  # IP istatistigi mevcut olmali
    assert 200 in summary.durum_kodu_dagilimi  # 200 durum kodu dagilimda olmali


@pytest.mark.security
@pytest.mark.negative
def test_14_oversized_log_line_protection() -> None:
    """Maksimum siniri asan asiri uzun log satirlarinin kati modda engellendigini dogrular."""
    asiri_uzun_satir = "A" * 5000  # 4096 sinirini asan 5000 karakterlik veri
    with pytest.raises(LogLineLengthLimitException, match="karakter limitini asti"):  # Istisna beklenir
        LogContentSanitizer.sanitize_line(asiri_uzun_satir, strict=True)  # Kati modda cagrilir
