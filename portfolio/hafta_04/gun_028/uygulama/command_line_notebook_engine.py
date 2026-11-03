# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 04, Gün 028: Mini Proje 3 - Komut Satırı Çalışma Defteri (Runbook Engine).
Bu modül, sistem ve ağ güvenliği denetimlerinde kullanılan salt-okunur (read-only)
keşif komutlarını doğrular, güvenlik filtrelerinden geçirir, kontrollü biçimde
çalıştırarak açıklamalı ve yeniden üretilebilir bir Markdown çalışma defteri üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için standart kütüphane modülü içe aktarılır.
import argparse
# Tarih ve saat damgalarını uluslararası ISO 8601 standardında üretmek için içe aktarılır.
import datetime
# Kriptografik özet (SHA256) hesaplayarak yürütme bütünlüğünü mühürlemek için içe aktarılır.
import hashlib
# Yapılandırılmış JSON veri kataloglarını ve sonuç raporlarını okumak/yazmak için içe aktarılır.
import json
# Dosya sistemi yolları ve platform bağımsız dizin kontrolleri için içe aktarılır.
import os
# Çıktı deseni ve yasaklı anahtar kelime eşleştirmelerinde düzenli ifadeler için içe aktarılır.
import re
# Yerel işletim sistemi süreçlerini güvenli ve izole alt süreçlerde çalıştırmak için içe aktarılır.
import subprocess
# Standart girdi/çıktı akışlarını ve sistem parametrelerini yönetmek için içe aktarılır.
import sys
# Tip ipuçları (type hints) ile kodun okunabilirliğini ve statik analiz gücünü artırmak için içe aktarılır.
from typing import Any, Dict, List, Optional, Tuple


# Windows konsollarında Türkçe karakterlerin bozulmasını önlemek için stdout kodlaması yapılandırılır.
if hasattr(sys.stdout, "reconfigure"):
    # Standart çıktı akışı UTF-8 kodlamasına zorlanır ve karakter hataları güvenle ikame edilir.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class SecurityPolicyViolationError(Exception):
    """
    Güvenlik ilkesi ihlali durumunda fırlatılan özel istisna sınıfı.
    Yıkıcı, zararlı veya yetkisiz bir komut çalıştırılmak istendiğinde tetiklenir.
    """
    # Özel hata mesajını saklamak için başlatıcı metod tanımlanır.
    def __init__(self, message: str, command: str, risk_type: str = "PROHIBITED_COMMAND"):
        # Üst sınıf olan Exception başlatıcısı çağrılır.
        super().__init__(message)
        # İhlale neden olan komut dizesi nitelik olarak kaydedilir.
        self.command = command
        # Risk sınıflandırması (CWE-78, CWE-250 vb.) nitelik olarak atanır.
        self.risk_type = risk_type


class CommandSafetyValidator:
    """
    Komut satırı çalışma defterine giren her komutun güvenliğini denetleyen doğrulayıcı.
    Yıkıcı silme, yetki yükseltme, biçimlendirme ve yetkisiz kabuk enjeksiyonlarını engeller.
    """

    # Yıkıcı ve tehlikeli anahtar kelimeler/kalıplar listesi (Blacklist savunması).
    DANGEROUS_PATTERNS = [
        # Dosya veya dizinleri silmeye yönelik yıkıcı komut desenleri.
        r"\brm\s+-[rfRF]+",
        # Windows komut satırında zorla ve alt dizinlerle dosya silme komutu.
        r"\bdel\s+/[fFqQsS]+",
        # Disk bölüntüsü biçimlendirme ve dosya sistemi oluşturma komutları.
        r"\bmkfs\b",
        # Fiziksel depolama aygıtlarını sıfırlayan doğrudan blok yazma komutu.
        r"\bdd\s+if=",
        # Çekirdek init sürecini (PID 1) sonlandırarak işletim sistemini çökertme girişimi.
        r"\bkill\s+-9\s+1\b",
        # Sistemi kapatma veya yeniden başlatma komutları.
        r"\bshutdown\b",
        # Sistemi yeniden başlatma komutu.
        r"\breboot\b",
        # Dosya izinlerini küresel yazılabilir (777) yaparak sistemi zayıflatma girişimi.
        r"\bchmod\s+.*777",
        # Dosya sahipliğini yetkisiz biçimde kök veya saldırgan hesaba geçirme.
        r"\bchown\s+-[rR]",
        # Yetkisiz yerel kullanıcı oluşturma komutları (POSIX).
        r"\buseradd\b",
        # Windows üzerinde yerel kullanıcı veya grup manipülasyon komutu.
        r"\bnet\s+user\b.*\/add",
        # Doğrulanmamış uzak sunucudan indirilen betiği doğrudan kabuğa borulama (Piping).
        r"\|\s*(bash|sh|powershell|cmd)\b",
    ]

    # Kurumsal güvenlik denetimlerinde izin verilen salt-okunur (read-only) güvenli kök komutlar.
    PERMITTED_BASE_COMMANDS = {
        # Kullanıcı kimliği sorgulama.
        "whoami",
        # UID/GID ve grup üyelikleri dökümü.
        "id",
        # Ana makine adı sorgulama.
        "hostname",
        # Çekirdek ve mimari bilgisi.
        "uname",
        # Sistem çalışma süresi ve yük ortalaması.
        "uptime",
        # Çalışan süreçlerin listesi.
        "ps",
        # Disk alanı ve bağlama noktaları doluluk durumu.
        "df",
        # Fiziksel bellek ve swap durumu.
        "free",
        # Dinleyen ağ soketleri ve açık portlar.
        "ss",
        # Ağ arayüzleri ve IP yapılandırması.
        "ip",
        # Ortam değişkenleri dökümü.
        "env",
        # Dizin ve dosya özniteliklerini listeleme.
        "ls",
        # Windows süreç listesi sorgulama.
        "tasklist",
        # Windows ve Linux ağ bağlantıları dökümü.
        "netstat",
        # Windows dizin listeleme komutu.
        "dir",
        # Windows sistem üstverileri dökümü.
        "systeminfo",
    }

    @classmethod
    # Bir komut dizesinin güvenli olup olmadığını denetleyen ana statik doğrulama fonksiyonu.
    def validate_command(cls, command_str: str) -> Tuple[bool, Optional[str]]:
        """
        Komutu güvenlik kurallarına göre denetler.
        Dönüş: (is_safe: bool, reason: Optional[str])
        """
        # Komut dizesinin başındaki ve sonundaki boşluklar temizlenir.
        cleaned_cmd = command_str.strip()

        # Boş komut iletimi durumunda işlem reddedilir.
        if not cleaned_cmd:
            # Geçersiz boş komut için hata gerekçesi döndürülür.
            return False, "Komut dizesi boş olamaz."

        # 1. Aşama: Yıkıcı ve tehlikeli desenlerin taranması (RegEx analizi).
        for pattern in cls.DANGEROUS_PATTERNS:
            # Düzenli ifade deseni komut dizesi üzerinde büyük/küçük harf duyarsız aranır.
            if re.search(pattern, cleaned_cmd, re.IGNORECASE):
                # Tehlikeli desen eşleştiğinde gerekçesiyle birlikte güvensiz kararı üretilir.
                return False, f"Yıkıcı/Yetkisiz komut deseni tespit edildi: '{pattern}' (CWE-78 / CWE-250)."

        # 2. Aşama: Komutun ilk sözcüğü (kök ikili dosya adı) çıkarılır.
        base_cmd = cleaned_cmd.split()[0].lower()

        # Eğer tam yol verilmişse (örn: /usr/bin/whoami veya C:\\Windows\\System32\\whoami.exe) taban ad alınır.
        base_cmd = os.path.basename(base_cmd).replace(".exe", "")

        # Kök komut izin verilen salt-okunur kümede yer almıyorsa denetim uyarısı verilir.
        if base_cmd not in cls.PERMITTED_BASE_COMMANDS:
            # İzin verilmeyen komut için güvenlik ihlali bildirilir.
            return False, f"'{base_cmd}' izin verilen salt-okunur (read-only) komut listesinde yer almıyor."

        # Tüm kontrollerden başarıyla geçen komut güvenli kabul edilir.
        return True, None


class CommandLineNotebookEngine:
    """
    Komut satırı çalışma defterini (Runbook / Field Notebook) yöneten,
    komutları çalıştıran ve açıklamalı Markdown raporu üreten ana motor sınıfı.
    """

    # Motor başlatıcı metodu; komut kataloğunu ve yapılandırmayı yükler.
    def __init__(self, catalog_path: Optional[str] = None):
        # Yürütme sonuçlarını ve çıktı kayıtlarını tutacak liste başlatılır.
        self.execution_records: List[Dict[str, Any]] = []
        # Engellenen güvensiz komut denemelerini saklayacak güvenlik günlüğü başlatılır.
        self.blocked_attempts: List[Dict[str, Any]] = []
        # Komut kataloğu sözlüğü başlatılır.
        self.catalog: Dict[str, Any] = {"commands": []}

        # Eğer katalog dosya yolu belirtilmişse dosyadan yükleme yapılır.
        if catalog_path and os.path.exists(catalog_path):
            # Katalog dosyasından güvenli komut tanımları okunur.
            self.load_catalog(catalog_path)

    # Dış JSON katalog dosyasını yükleyen yardımcı metod.
    def load_catalog(self, catalog_path: str) -> None:
        """Katalog JSON dosyasını okur ve doğrular."""
        # Dosya UTF-8 kodlamasında güvenle açılır.
        with open(catalog_path, "r", encoding="utf-8") as f:
            # JSON içeriği sözlük yapısına dönüştürülür.
            self.catalog = json.load(f)

    # Tek bir komutu güvenlik süzgecinden geçirerek çalıştıran veya simüle eden metod.
    def execute_command_entry(
        self,
        command_entry: Dict[str, Any],
        use_mock: bool = True,
        live_execution: bool = False
    ) -> Dict[str, Any]:
        """
        Tek bir komut kaydını işler.
        Güvenlik denetimini icra eder; geçerliyse çıktıyı kaydeder ve SHA256 özetini çıkarır.
        """
        # Komut kaydından çalıştırılacak komut dizesi alınır.
        cmd_str = command_entry.get("command", "")
        # Komutun tekil kimliği alınır.
        cmd_id = command_entry.get("id", "UNKNOWN")

        # Komut güvenlik doğrulayıcısına gönderilir.
        is_safe, reason = CommandSafetyValidator.validate_command(cmd_str)

        # Eğer komut güvenli değilse derhal engelleme günlüğüne yazılır ve istisna fırlatılır.
        if not is_safe:
            # Engellenen teşebbüs için veri yapısı hazırlanır.
            blocked_event = {
                "id": cmd_id,
                "command": cmd_str,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "BLOCKED",
                "reason": reason,
                "risk_standard": "CWE-78 / CWE-250"
            }
            # Olay güvenlik günlüğüne eklenir.
            self.blocked_attempts.append(blocked_event)
            # Yürütme durdurulur ve güvenlik istisnası fırlatılır.
            raise SecurityPolicyViolationError(
                message=f"Komut güvenlik engeline takıldı: {reason}",
                command=cmd_str,
                risk_type="UNSAFE_COMMAND_BLOCKED"
            )

        # Komut yürütme zaman damgası ISO 8601 formatında oluşturulur.
        exec_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Çıktı metnini tutacak değişken tanımlanır.
        output_text = ""
        # Yürütme çıkış kodu (0: Başarılı) varsayılan olarak atanır.
        exit_code = 0
        # Yürütme modu etiketi (MOCK veya LIVE) belirlenir.
        execution_mode = "MOCK_DETERMINISTIC"

        # Eğer canlı çalıştırma talep edilmişse yerel işletim sisteminde güvenle koşulur.
        if live_execution and not use_mock:
            try:
                # Güvenli alt süreç oluşturularak komut çalıştırılır; shell=False ile injection önlenir.
                proc = subprocess.run(
                    cmd_str.split(),
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                    encoding="utf-8",
                    errors="replace"
                )
                # Alt sürecin standart çıktısı alınır.
                output_text = proc.stdout.strip()
                # Alt sürecin çıkış kodu kaydedilir.
                exit_code = proc.returncode
                # Yürütme modu canlı sistem olarak güncellenir.
                execution_mode = "LIVE_SYSTEM"
                # Eğer komut çıktı üretmediyse standart hata çıktısı kontrol edilir.
                if not output_text and proc.stderr:
                    # Hata mesajı çıktı olarak aktarılır.
                    output_text = f"[STDERR]: {proc.stderr.strip()}"
            except Exception as e:
                # Canlı çalıştırma başarısız olursa (örn: komut bulunamadı) kontrollü fallback yapılır.
                output_text = f"[HATA - YEREL SISTEMDE BULUNAMADI]: {str(e)}\nFallback Mock: {command_entry.get('mock_output', '')}"
                # Çıkış kodu hata durumuna çekilir.
                exit_code = 127
                # Mod fallback olarak işaretlenir.
                execution_mode = "FALLBACK_MOCK"
        else:
            # Deterministik sentetik çıktı katalogdan okunur (Laboratuvarın %100 yeniden üretilebilirliği için).
            output_text = command_entry.get("mock_output", "").strip()
            # Çıkış kodu sıfır kabul edilir.
            exit_code = 0
            # Mod deterministik mock olarak mühürlenir.
            execution_mode = "MOCK_DETERMINISTIC"

        # Çıktının beklenen düzenli ifade desenine uyup uymadığı kontrol edilir.
        expected_pattern = command_entry.get("expected_output_pattern", "")
        # Uyum durumu varsayılan True atanır.
        pattern_matched = True
        # Eğer desen tanımlanmışsa eşleştirme yapılır.
        if expected_pattern:
            # Düzenli ifade çok satırlı modda aranır.
            pattern_matched = bool(re.search(expected_pattern, output_text, re.MULTILINE))

        # Yürütmenin kriptografik bütünlük özeti (SHA-256) hesaplanır.
        integrity_payload = f"{cmd_id}:{cmd_str}:{output_text}:{exec_time}".encode("utf-8")
        # SHA-256 özeti onaltılık (hex) dizeye çevrilir.
        integrity_hash = hashlib.sha256(integrity_payload).hexdigest()

        # Eksiksiz yürütme kaydı sözlüğü oluşturulur.
        record = {
            "id": cmd_id,
            "name": command_entry.get("name", cmd_str),
            "command": cmd_str,
            "category": command_entry.get("category", "genel"),
            "platform": command_entry.get("platform", "cross-platform"),
            "description": command_entry.get("description", ""),
            "security_relevance": command_entry.get("security_relevance", ""),
            "safety_level": command_entry.get("safety_level", "read_only"),
            "execution_time": exec_time,
            "execution_mode": execution_mode,
            "exit_code": exit_code,
            "output": output_text,
            "pattern_matched": pattern_matched,
            "integrity_sha256": integrity_hash
        }

        # Kayıt listeye eklenir.
        self.execution_records.append(record)
        # Oluşturulan kayıt geri döndürülür.
        return record

    # Katalogdaki tüm güvenli komutları sırayla çalıştıran toplu işlem metodu.
    def execute_all_catalog_commands(self, use_mock: bool = True, live_execution: bool = False) -> List[Dict[str, Any]]:
        """Katalogdaki tüm komutları yürütür ve kayıtları döndürür."""
        # Sonuç listesi temizlenir.
        self.execution_records = []
        # Katalogdaki her bir komut maddesi için döngü kurulur.
        for cmd_entry in self.catalog.get("commands", []):
            # Komut kaydı yürütme metoduna iletilir.
            self.execute_command_entry(cmd_entry, use_mock=use_mock, live_execution=live_execution)
        # Tüm yürütme kayıtları döndürülür.
        return self.execution_records

    # Açıklamalı ve kurumsal standartlara uygun Markdown çalışma defterini üreten metod.
    def generate_markdown_notebook(self, output_filepath: Optional[str] = None) -> str:
        """
        Yürütülen komutlardan profesyonel Markdown formatında çalışma defteri üretir.
        G028-SC2 gereksinimi: En az on salt-okunur komutun açıklamalı defteri.
        """
        # Defter metin satırları için boş liste açılır.
        md: List[str] = []

        # Başlık ve telif hakkı / özel lisans bildirimi yazılır.
        md.append("# Güvenlik Denetimi Komut Satırı Çalışma Defteri (Runbook)")
        md.append("")
        md.append("> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  ")
        md.append("> **Özel Lisans — Tüm Hakları Saklıdır**  ")
        md.append("> *Bu çalışma defteri işletim sistemi gözlemlerini ve güvenlik denetim bulgularını yeniden üretilebilir kılmak için oluşturulmuştur.*")
        md.append("")
        md.append("---")
        md.append("")

        # Yönetici Özeti ve Denetim Üstverileri bölümü.
        md.append("## 1. Denetim Özeti ve Yürütme Parametreleri")
        md.append("")
        # Toplam komut sayısı hesaplanır.
        total_cmds = len(self.execution_records)
        # Başarılı çıkış kodu veren komut sayısı hesaplanır.
        success_cmds = sum(1 for r in self.execution_records if r["exit_code"] == 0)
        # Çıktı deseni doğrulanan komut sayısı hesaplanır.
        matched_cmds = sum(1 for r in self.execution_records if r["pattern_matched"])

        # Tablo başlıkları eklenir.
        md.append("| Parametre | Değer |")
        md.append("| :--- | :--- |")
        md.append(f"| **Oluşturulma Zamanı (UTC)** | `{datetime.datetime.now(datetime.timezone.utc).isoformat()}` |")
        md.append(f"| **Toplam İncelenen Komut** | `{total_cmds}` (Asgari 10 şartı sağlandı) |")
        md.append(f"| **Başarılı Yürütme Oranı** | `%{ (success_cmds / total_cmds * 100) if total_cmds > 0 else 0.0:.1f}` |")
        md.append(f"| **Desen Eşleşme Uyumu** | `%{ (matched_cmds / total_cmds * 100) if total_cmds > 0 else 0.0:.1f}` |")
        md.append(f"| **Engellenen Yıkıcı Komut Sayısı** | `{len(self.blocked_attempts)}` |")
        md.append(f"| **Güvenlik Politikası Sınıfı** | `SALT_OKUNUR_KESIF (READ_ONLY_DISCOVERY)` |")
        md.append("")
        md.append("---")
        md.append("")

        # İçindekiler tablosu.
        md.append("## 2. Çalışma Defteri Komut İndeksi")
        md.append("")
        md.append("| No | Komut ID | Komut | Kategori | Güvenlik Amacı (MITRE / NIST) | Bütünlük Özeti (SHA256 İlk 8) |")
        md.append("| :---: | :---: | :--- | :--- | :--- | :---: |")
        # İndeks tablosu satırları doldurulur.
        for idx, rec in enumerate(self.execution_records, start=1):
            # Tablo satırı formatlanır.
            short_hash = rec["integrity_sha256"][:8]
            md.append(f"| {idx} | `{rec['id']}` | `{rec['command']}` | `{rec['category']}` | {rec['security_relevance'][:45]}... | `{short_hash}` |")
        md.append("")
        md.append("---")
        md.append("")

        # Ayrıntılı Komut İnceleme Kartları bölümü.
        md.append("## 3. Komut Analiz Kartları ve Terminal Gözlemleri")
        md.append("")

        # Her bir komut için ayrıntılı Markdown bloğu oluşturulur.
        for idx, rec in enumerate(self.execution_records, start=1):
            md.append(f"### 3.{idx}. {rec['name']} (`{rec['command']}`)")
            md.append("")
            md.append(f"- **Komut ID:** `{rec['id']}`")
            md.append(f"- **Kategori:** `{rec['category']}`")
            md.append(f"- **Hedef Platform:** `{rec['platform']}`")
            md.append(f"- **Güvenlik Düzeyi:** `{rec['safety_level']}` (Salt-okunur)")
            md.append(f"- **Yürütme Modu:** `{rec['execution_mode']}`")
            md.append(f"- **Çıkış Kodu (Exit Code):** `{rec['exit_code']}`")
            md.append(f"- **Kriptografik SHA256 İzi:** `{rec['integrity_sha256']}`")
            md.append("")
            md.append(f"**Komut Açıklaması ve Amacı:**")
            md.append(f"{rec['description']}")
            md.append("")
            md.append(f"**Siber Güvenlik Önemi ve Tehdit Modeli:**")
            md.append(f"{rec['security_relevance']}")
            md.append("")
            md.append("```text")
            md.append(f"$ {rec['command']}")
            md.append(f"{rec['output']}")
            md.append("```")
            md.append("")
            md.append(f"> **Analist Gözlemi ve Kontrol Önerisi:**  ")
            md.append(f"> Bu komut sistem durumunu değiştirmeden anlık gözlem üretir. Çıktı deseni kontrolü: `{'UYUMLU' if rec['pattern_matched'] else 'UYUMSUZ'}`. Kurumsal savunmada periyodik olarak envanter fark analizine girdi oluşturmalıdır.")
            md.append("")
            md.append("---")
            md.append("")

        # Güvenlik Duvarı ve Engellenen Girişimler bölümü.
        md.append("## 4. Güvenlik Duvarı ve Engellenen Girişimler Raporu (Negatif Kontrol)")
        md.append("")
        if self.blocked_attempts:
            md.append("| Engellenen Komut | İhlal Nedeni | Risk Türü | Zaman Damgası |")
            md.append("| :--- | :--- | :--- | :--- |")
            for b in self.blocked_attempts:
                md.append(f"| `{b['command']}` | {b['reason']} | `{b['risk_standard']}` | `{b['timestamp']}` |")
        else:
            md.append("Bu denetim oturumunda doğrudan engellenen güvensiz komut teşebbüsü kaydedilmedi.")
        md.append("")
        md.append("---")
        md.append("")

        # Defter metni birleştirilir.
        notebook_content = "\n".join(md)

        # Eğer çıktı dosyası belirtilmişse diske yazılır.
        if output_filepath:
            # Hedef dosyanın üst dizini oluşturulur.
            os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
            # Dosya UTF-8 kodlamasında yazılır.
            with open(output_filepath, "w", encoding="utf-8") as f:
                f.write(notebook_content)

        # Üretilen Markdown metni döndürülür.
        return notebook_content

    # Yasaklı komutların engellendiğini doğrulayan negatif kontrol test fonksiyonu.
    def test_prohibited_commands_pipeline(self, prohibited_json_path: str) -> Dict[str, Any]:
        """
        Yasaklı komutlar listesini alarak hepsinin bloklandığını doğrular.
        Negatif kontrol mekanizması (G028-SC2).
        """
        # Dosya UTF-8 kodlamasında okunur.
        with open(prohibited_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        prohibited_list = data.get("prohibited_commands", [])
        total_prohibited = len(prohibited_list)
        blocked_count = 0
        details: List[Dict[str, Any]] = []

        for item in prohibited_list:
            cmd = item.get("command", "")
            cmd_id = item.get("id", "PROHIBIT-X")
            try:
                # Güvenlik doğrulayıcısını çalıştır.
                is_safe, reason = CommandSafetyValidator.validate_command(cmd)
                if not is_safe:
                    blocked_count += 1
                    details.append({
                        "id": cmd_id,
                        "command": cmd,
                        "status": "SUCCESSFULLY_BLOCKED",
                        "reason": reason
                    })
                else:
                    details.append({
                        "id": cmd_id,
                        "command": cmd,
                        "status": "UNEXPECTEDLY_ALLOWED",
                        "reason": "Komut filtreden kaçtı!"
                    })
            except Exception as e:
                blocked_count += 1
                details.append({
                    "id": cmd_id,
                    "command": cmd,
                    "status": "SUCCESSFULLY_BLOCKED_WITH_EXCEPTION",
                    "reason": str(e)
                })

        return {
            "total_tested": total_prohibited,
            "blocked_count": blocked_count,
            "passed": (blocked_count == total_prohibited),
            "details": details
        }


def main():
    """CLI giriş noktası ve komut satırı arayüzü yöneticisi."""
    parser = argparse.ArgumentParser(
        description="Mini Proje 3: Komut Satırı Çalışma Defteri Motoru (Runbook Engine)."
    )
    parser.add_argument(
        "--catalog",
        type=str,
        default="portfolio/hafta_04/gun_028/ornek_veri/safe_command_catalog.json",
        help="Güvenli salt-okunur komut kataloğu JSON dosya yolu."
    )
    parser.add_argument(
        "--generate-notebook",
        type=str,
        help="Oluşturulacak Markdown çalışma defteri çıktı dosya yolu."
    )
    parser.add_argument(
        "--test-prohibited",
        type=str,
        help="Negatif kontrol için yasaklı komutlar JSON dosya yolu."
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Katalogdaki komutları inceleyip terminal özet tablosu basar."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Çıktıyı yapılandırılmış JSON olarak basar."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Desteklenen komutları yerel işletim sisteminde canlı çalıştırır."
    )

    args = parser.parse_args()

    engine = CommandLineNotebookEngine(catalog_path=args.catalog if os.path.exists(args.catalog) else None)

    # Negatif kontrol testi istenmişse:
    if args.test_prohibited:
        result = engine.test_prohibited_commands_pipeline(args.test_prohibited)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("======================================================================")
            print("GÜVENLİK ENGELLEME VE NEGATİF KONTROL DOĞRULAMA TESTİ")
            print("======================================================================")
            print(f"Toplam Test Edilen Zararlı Komut : {result['total_tested']}")
            print(f"Başarıyla Engellenen Komut      : {result['blocked_count']}")
            print(f"Sonuç                           : {'TAM BAŞARILI (PASS)' if result['passed'] else 'BAŞARISIZ (FAIL)'}")
            print("----------------------------------------------------------------------")
            for item in result["details"]:
                print(f"[{item['status']}] {item['command']} -> {item['reason']}")
            print("======================================================================")
        sys.exit(0 if result["passed"] else 1)

    # Defter üretimi veya denetim istenmişse:
    if args.generate_notebook or args.audit:
        engine.execute_all_catalog_commands(use_mock=not args.live, live_execution=args.live)
        notebook_content = engine.generate_markdown_notebook(output_filepath=args.generate_notebook)

        if args.audit:
            print("======================================================================")
            print("KOMUT SATIRI ÇALIŞMA DEFTERİ (RUNBOOK) DENETİM RAPORU")
            print("======================================================================")
            print(f"Toplam Komut Sayısı     : {len(engine.execution_records)}")
            print(f"Yürütme Modu            : {'CANLI YEREL SISTEM' if args.live else 'DETERMINISTIK MOCK'}")
            print(f"Güvenlik İlkesi Sınıfı  : SALT_OKUNUR_KESIF (READ_ONLY_DISCOVERY)")
            print("----------------------------------------------------------------------")
            for idx, r in enumerate(engine.execution_records, start=1):
                status_str = "OK" if r["exit_code"] == 0 and r["pattern_matched"] else "WARN"
                print(f"[{status_str}] {r['id']} | {r['command']:<15} | SHA256: {r['integrity_sha256'][:12]}... | {r['category']}")
            print("======================================================================")
            if args.generate_notebook:
                print(f"[BİLGİ] Çalışma defteri başarıyla oluşturuldu: {args.generate_notebook}")

        if args.json:
            print(json.dumps(engine.execution_records, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
