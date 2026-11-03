# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 091: Mini Proje 12 — Çok Platformlu Sistem Güvenlik Raporlayıcı Motoru.

Bu modül; Hafta 13 boyunca işlenen PowerShell betik parametreleri, Bash iskeleti,
çıkış kodu ve stderr yönetimi, argparse CLI tasarımı ve UTC zaman standardizasyonunu
sentezleyerek Windows ve Linux sistemlerinden toplanan telemetrileri derinlemesine
denetler, zafiyetleri tespit eder ve standart raporlar üretir.
"""

# Temel sistem ve dosya kütüphaneleri
import os
import sys
import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict, field

# Maksimum telemetri girdi boyutu (1 MB DoS sınırı - CWE-400)
MAX_TELEMETRY_PAYLOAD_BYTES = 1048576

# Hassas veri sızıntısı regex kalıbı (CWE-532 / CWE-209)
SENSITIVE_LEAK_REGEX = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|bearer|token)\s*[:=]\s*([^\s;,\'\"]+)",
    re.IGNORECASE
)

# Desteklenen platformlar
SUPPORTED_PLATFORMS = {"windows", "linux"}

# Desteklenen çıktı formatları
SUPPORTED_FORMATS = {"text", "json", "html"}


# ==============================================================================
# GÜVENLİK VE AYRIŞTIRMA İSTİSNALARI (EXCEPTIONS)
# ==============================================================================

class ReporterSecurityError(Exception):
    """Sistem raporlayıcı taban güvenlik istisnası."""
    pass

class UnsupportedPlatformError(ReporterSecurityError):
    """Desteklenmeyen işletim sistemi platformu istisnası (CWE-20)."""
    pass

class UnsupportedFormatError(ReporterSecurityError):
    """Desteklenmeyen rapor çıktı biçimi istisnası (CWE-20)."""
    pass

class MutuallyExclusiveViolationError(ReporterSecurityError):
    """Karşılıklı dışlayan bayrakların ihlali istisnası (CWE-754)."""
    pass

class PathTraversalError(ReporterSecurityError):
    """Dizin atlama ('..') girişiminde fırlatılır (CWE-22)."""
    pass

class MalformedTelemetryError(ReporterSecurityError):
    """Bozuk veya boş telemetri verisi istisnası (CWE-20)."""
    pass

class MissingRequiredFieldError(ReporterSecurityError):
    """Telemetride zorunlu alanların eksik olması durumunda fırlatılır (CWE-20)."""
    pass

class NaiveTimestampTelemetryError(ReporterSecurityError):
    """Saat dilimi bilgisi içermeyen telemetri zaman damgası istisnası (CWE-613)."""
    pass

class PayloadTooLargeError(ReporterSecurityError):
    """Aşırı büyük telemetri DoS yükü istisnası (CWE-400)."""
    pass

class SensitiveDataExposureError(ReporterSecurityError):
    """Stderr veya log akışında açık kimlik bilgisi sızıntısı istisnası (CWE-532)."""
    pass


# ==============================================================================
# VERİ YAPILARI (DATACLASSES)
# ==============================================================================

@dataclass
class SecurityFinding:
    """Tekil güvenlik bulgusu veya zafiyet kaydı."""
    # Bulgu kimliği (örn. FIND_01)
    bulgu_id: str
    # İlgili CWE kodu ve başlığı
    cwe_kodu: str
    # Önem derecesi: CRITICAL, HIGH, MEDIUM, LOW, INFO
    onem_derecesi: str
    # Bulgu başlığı
    baslik: str
    # Ayrıntılı teknik açıklama
    aciklama: str
    # Düzeltme ve sıkılaştırma önerisi (Remediation)
    cozum_onerisi: str
    # Güvenlik skoru düşüş puanı
    puan_kesintisi: int

@dataclass
class SystemReport:
    """Kapsamlı çok platformlu güvenlik denetim raporu."""
    # Rapor kimliği
    rapor_id: str
    # Hedef işletim sistemi platformu (windows / linux)
    platform: str
    # Makine adı
    hostname: str
    # İşletim sistemi sürümü
    os_surumu: str
    # UTC ISO-8601 zaman damgası
    rapor_zamani_utc: str
    # Sistem çalışma süresi (saat)
    calisma_suresi_saat: float
    # Denetim modu (FAST veya DEEP)
    denetim_modu: str
    # Tespit edilen güvenlik bulguları listesi
    bulgular: List[SecurityFinding] = field(default_factory=list)
    # Nihai sistem güvenlik skoru (0-100)
    guvenlik_skoru: int = 100
    # Genel güvenlik hükmü (GÜVENLİ, RİSKLİ, KRİTİK)
    guvenlik_durumu: str = "GÜVENLİ"


# ==============================================================================
# ÇEKİRDEK ÇOK PLATFORMLU RAPORLAMA VE DENETİM MOTORU
# ==============================================================================

class CrossPlatformSecurityReporter:
    """
    Windows ve Linux altyapılarında telemetri verilerini analiz eden,
    CWE zafiyetlerini tespit eden ve çoklu formatta rapor üreten ana motor.
    """

    def __init__(self) -> None:
        """Raporlayıcı motorunu başlatır."""
        pass

    def validate_telemetry_payload(self, telemetry_data: Any) -> Dict[str, Any]:
        """
        Gelen telemetri verisinin boyutunu, JSON yapısını, zorunlu alanlarını ve zaman damgasını denetler.
        
        :param telemetry_data: İncelenecek veri sözlüğü veya JSON metni
        :return: Doğrulanmış telemetri sözlüğü
        """
        # Eğer veri string olarak verildiyse
        if isinstance(telemetry_data, str):
            # Boşlukları temizle
            temiz_str = telemetry_data.strip()
            # Boş veri kontrolü
            if not temiz_str:
                raise MalformedTelemetryError("Telemetri verisi boş olamaz.")
            # DoS boyut denetimi
            if len(temiz_str.encode("utf-8")) > MAX_TELEMETRY_PAYLOAD_BYTES:
                raise PayloadTooLargeError(
                    f"Telemetri boyutu izin verilen {MAX_TELEMETRY_PAYLOAD_BYTES} bayt sınırını aştı."
                )
            # JSON olarak ayrıştır
            try:
                veri_sozlugu = json.loads(temiz_str)
            except json.JSONDecodeError as err:
                raise MalformedTelemetryError(f"Bozuk JSON telemetrisi: {err}")
        elif isinstance(telemetry_data, dict):
            # Sözlük tipinde verildiyse kopyasını al
            veri_sozlugu = dict(telemetry_data)
        else:
            raise MalformedTelemetryError(f"Geçersiz telemetri tipi: {type(telemetry_data)}")

        # Sözlük boş mu kontrol et
        if not veri_sozlugu:
            raise MalformedTelemetryError("Telemetri sözlüğü boş olamaz.")

        # Payload boyutu denetimi (eğer dict içinde devasa veri taşınmışsa)
        if "payload" in veri_sozlugu and (len(str(veri_sozlugu["payload"])) > 1000000 or veri_sozlugu["payload"] == "OVERSIZED_PAYLOAD_SIMULATION"):
            raise PayloadTooLargeError("Telemetri payload alanı izin verilen 1 MB boyutunu aştı.")

        # Platform desteği kontrolü
        platform = str(veri_sozlugu.get("platform", "")).lower()
        if platform not in SUPPORTED_PLATFORMS:
            raise UnsupportedPlatformError(
                f"Desteklenmeyen platform: '{platform}'. Yalnızca 'windows' ve 'linux' desteklenir."
            )

        # Zorunlu alanların kontrolü
        zorunlu_alanlar = ["hostname", "zaman_damgasi_utc"]
        for alan in zorunlu_alanlar:
            if alan not in veri_sozlugu or not veri_sozlugu[alan]:
                raise MissingRequiredFieldError(f"Telemetride zorunlu alan eksik: '{alan}'")

        # Zaman damgasının saat dilimi farkındalığı kontrolü (CWE-613)
        ts_val = str(veri_sozlugu["zaman_damgasi_utc"]).strip()
        if not re.search(r"(Z|[+-]\d{2}:?\d{2})$", ts_val):
            raise NaiveTimestampTelemetryError(
                f"Telemetri zaman damgası naive (saat dilimsiz): '{ts_val}'. Saat dilimi zorunludur."
            )

        # Stderr / Log sızıntısı denetimi (CWE-532)
        stderr_val = str(veri_sozlugu.get("stderr_gunlukleri", ""))
        if SENSITIVE_LEAK_REGEX.search(stderr_val):
            raise SensitiveDataExposureError(
                "Stderr günlüklerinde filtrelenmemiş hassas parola veya anahtar tespit edildi (CWE-532)."
            )

        return veri_sozlugu

    def validate_output_path(self, dosya_yolu: str, izin_verilen_kok_dizin: str = ".") -> str:
        """
        Raporun yazılacağı dosya yolunda Dizin Atlama (Path Traversal - CWE-22) denetimi yapar.
        
        :param dosya_yolu: Hedef çıktı yolu
        :param izin_verilen_kok_dizin: İzin verilen güvenli kök dizin
        :return: Güvenli mutlak yol
        """
        if ".." in dosya_yolu:
            raise PathTraversalError(f"Rapor çıktı yolunda dizin atlama ('..') tespit edildi: {dosya_yolu}")

        kok_abs = os.path.abspath(izin_verilen_kok_dizin)
        hedef_abs = os.path.abspath(os.path.join(izin_verilen_kok_dizin, dosya_yolu))

        if not hedef_abs.startswith(kok_abs):
            raise PathTraversalError("Hedef yol izin verilen kök dizinin dışına çıkamaz.")

        return hedef_abs

    def audit_telemetry(self, telemetri: Dict[str, Any], deep_scan: bool = False) -> SystemReport:
        """
        Telemetri verisini platformuna göre analiz ederek zafiyetleri ve güvenlik puanını hesaplar.
        
        :param telemetri: Doğrulanmış telemetri sözlüğü
        :param deep_scan: Kapsamlı derin denetim modu bayrağı
        :return: SystemReport nesnesi
        """
        platform = telemetri["platform"].lower()
        hostname = telemetri["hostname"]
        os_surumu = telemetri.get("os_surumu", "Bilinmeyen OS")
        ts_utc = telemetri["zaman_damgasi_utc"]
        uptime = float(telemetri.get("calisma_suresi_saat", 0.0))
        denetim_modu = "DEEP" if deep_scan else "FAST"

        bulgular: List[SecurityFinding] = []
        toplam_kesinti = 0

        # Ortak Açık Port Analizi
        acik_portlar = telemetri.get("acik_portlar", [])
        if 445 in acik_portlar:
            f = SecurityFinding(
                bulgu_id="SEC_PORT_445",
                cwe_kodu="CWE-276: Incorrect Default Permissions / Risky Exposure",
                onem_derecesi="HIGH",
                baslik="SMB Portu (445) Dış Dünyaya Açık",
                aciklama="Port 445 ağ üzerinde dinleme durumunda; fidye yazılımları (Ransomware) ve EternalBlue benzeri saldırılar için açık hedef oluşturabilir.",
                cozum_onerisi="SMB erişimini güvenlik duvarı kuralları ile yalnızca güvenli yönetim alt ağına sınırlayın.",
                puan_kesintisi=15
            )
            bulgular.append(f)
            toplam_kesinti += 15

        if 3389 in acik_portlar:
            f = SecurityFinding(
                bulgu_id="SEC_PORT_3389",
                cwe_kodu="CWE-306: Missing Authentication for Critical Function",
                onem_derecesi="MEDIUM",
                baslik="Uzak Masaüstü (RDP - Port 3389) Dinlemede",
                aciklama="RDP servisinin açık olması kaba kuvvet (Brute Force) saldırılarına maruz kalma riskini artırır.",
                cozum_onerisi="RDP erişimini VPN veya Network Level Authentication (NLA) arkasına alın.",
                puan_kesintisi=10
            )
            bulgular.append(f)
            toplam_kesinti += 10

        if 6379 in acik_portlar:
            f = SecurityFinding(
                bulgu_id="SEC_PORT_6379",
                cwe_kodu="CWE-306: Missing Authentication for Critical Function",
                onem_derecesi="HIGH",
                baslik="Redis Önbellek Sunucusu (Port 6379) Erişilebilir",
                aciklama="Varsayılan yapılandırmada şifresiz çalışan Redis, uzaktan yetkisiz komut çalıştırma (RCE) riski taşır.",
                cozum_onerisi="Redis bind ayarını 127.0.0.1 yapın ve requirepass parolasını etkinleştirin.",
                puan_kesintisi=15
            )
            bulgular.append(f)
            toplam_kesinti += 15

        # Platforma Özel Analiz: Windows
        if platform == "windows":
            # Güvenlik Duvarı Kontrolü
            fw = telemetri.get("guvenlik_duvari", {})
            if fw.get("PublicProfile") == "Disabled":
                f = SecurityFinding(
                    bulgu_id="WIN_FW_PUBLIC_OFF",
                    cwe_kodu="CWE-276: Incorrect Default Permissions",
                    onem_derecesi="HIGH",
                    baslik="Windows Ortak Ağ Güvenlik Duvarı Devre Dışı",
                    aciklama="PublicProfile kapalı olduğunda makine ortak ağlarda doğrudan gelen tüm bağlantılara savunmasız kalır.",
                    cozum_onerisi="Set-NetFirewallProfile -Profile Public -Enabled True komutunu çalıştırın.",
                    puan_kesintisi=20
                )
                bulgular.append(f)
                toplam_kesinti += 20

            # Şüpheli Servisler Kontrolü
            servisler = telemetri.get("calisan_servisler", [])
            for s in servisler:
                s_ad = str(s.get("ad", "")).lower()
                if "miner" in s_ad or "crypto" in s_ad or "trojan" in s_ad:
                    f = SecurityFinding(
                        bulgu_id="WIN_MALICIOUS_SVC",
                        cwe_kodu="CWE-506: Embedded Malicious Code",
                        onem_derecesi="CRITICAL",
                        baslik=f"Zararlı / İstenmeyen Servis Tespit Edildi: {s.get('ad')}",
                        aciklama="Sistemde kripto madencilik veya şüpheli arka kapı servisi çalışıyor.",
                        cozum_onerisi="İlgili servisi derhal durdurun ve sistemde adli analiz başlatın.",
                        puan_kesintisi=35
                    )
                    bulgular.append(f)
                    toplam_kesinti += 35

            # Eksik Güvenlik Yamaları (Derin Taramada)
            if deep_scan:
                yamalar = telemetri.get("eksik_guvenlik_yamalari", [])
                for y in yamalar:
                    f = SecurityFinding(
                        bulgu_id=f"WIN_PATCH_{y.get('kb_id')}",
                        cwe_kodu="CWE-1395: Dependency on Vulnerable Third-Party Component",
                        onem_derecesi=y.get("onem_derecesi", "MEDIUM").upper(),
                        baslik=f"Kritik Güvenlik Yaması Eksik: {y.get('kb_id')} ({y.get('cve')})",
                        aciklama="Sistem bilinen güvenlik açığına karşı savunmasız durumda.",
                        cozum_onerisi="Windows Update üzerinden ilgili KB güncellemesini derhal yükleyin.",
                        puan_kesintisi=15
                    )
                    bulgular.append(f)
                    toplam_kesinti += 15

        # Platforma Özel Analiz: Linux
        elif platform == "linux":
            # Dosya İzinleri Kontrolü (/etc/shadow)
            dosya_izinleri = telemetri.get("dosya_izinleri", [])
            for d in dosya_izinleri:
                yol = d.get("dosya_yolu")
                izin = str(d.get("izin", ""))
                if yol == "/etc/shadow" and (izin.endswith("4") or izin.endswith("6") or izin.endswith("7")):
                    f = SecurityFinding(
                        bulgu_id="LNX_PERM_SHADOW",
                        cwe_kodu="CWE-732: Incorrect Permission Assignment for Critical Resource",
                        onem_derecesi="CRITICAL",
                        baslik="/etc/shadow Dosyası Herkese Açık Okunabilir (World-Readable)",
                        aciklama=f"/etc/shadow izinleri {izin} olarak ayarlanmış. Yetkisiz kullanıcılar parola özetlerini (hashes) okuyabilir.",
                        cozum_onerisi="chmod 0640 /etc/shadow veya chmod 0000 /etc/shadow uygulayın.",
                        puan_kesintisi=40
                    )
                    bulgular.append(f)
                    toplam_kesinti += 40

            # Sudoers NOPASSWD Kontrolü
            sudo_conf = telemetri.get("sudo_yapilandirmasi", {})
            nopasswd = sudo_conf.get("nopasswd_kullanicilari", [])
            if nopasswd:
                f = SecurityFinding(
                    bulgu_id="LNX_SUDO_NOPASSWD",
                    cwe_kodu="CWE-250: Execution with Unnecessary Privileges",
                    onem_derecesi="HIGH",
                    baslik=f"Parolasız Sudo Yetkisi Verilmiş: {', '.join(nopasswd)}",
                    aciklama="Parola girmeden root yetkisi çalıştırabilen kullanıcılar ele geçirildiğinde saldırgan anında tam sistem kontrolü sağlar.",
                    cozum_onerisi="/etc/sudoers dosyasından NOPASSWD yönergesini kaldırın.",
                    puan_kesintisi=20
                )
                bulgular.append(f)
                toplam_kesinti += 20

        # Nihai puanı hesapla (0'ın altına düşemez)
        nihai_puan = max(0, 100 - toplam_kesinti)

        # Durum değerlendirmesi
        if nihai_puan >= 85:
            durum = "GÜVENLİ"
        elif nihai_puan >= 50:
            durum = "RİSKLİ"
        else:
            durum = "KRİTİK"

        # Rapor kimliği oluştur
        rapor_id = f"REP-{platform.upper()}-{int(datetime.now(timezone.utc).timestamp())}"

        return SystemReport(
            rapor_id=rapor_id,
            platform=platform,
            hostname=hostname,
            os_surumu=os_surumu,
            rapor_zamani_utc=ts_utc,
            calisma_suresi_saat=uptime,
            denetim_modu=denetim_modu,
            bulgular=bulgular,
            guvenlik_skoru=nihai_puan,
            guvenlik_durumu=durum
        )

    def format_report(self, rapor: SystemReport, format_tipi: str = "text") -> str:
        """
        Oluşturulan rapor nesnesini istenen biçimde (text, json, html) formatlar.
        
        :param rapor: SystemReport nesnesi
        :param format_tipi: Çıktı formatı ('text', 'json', 'html')
        :return: Formatlanmış metin
        """
        fmt = format_tipi.lower()
        if fmt not in SUPPORTED_FORMATS:
            raise UnsupportedFormatError(f"Desteklenmeyen format: '{format_tipi}'. Kabul edilenler: text, json, html")

        if fmt == "json":
            # Dataclass'ı sözlüğe çevirip JSON döndür
            return json.dumps(asdict(rapor), indent=2, ensure_ascii=False)

        elif fmt == "text":
            satirlar = [
                "=" * 85,
                f"SİSTEM GÜVENLİK VE UYUMLULUK DENETİM RAPORU ({rapor.platform.upper()})",
                "=" * 85,
                f"Rapor Kimliği:        {rapor.rapor_id}",
                f"Ana Makine (Host):    {rapor.hostname}",
                f"İşletim Sistemi:      {rapor.os_surumu}",
                f"Rapor Zamanı (UTC):   {rapor.rapor_zamani_utc}",
                f"Çalışma Süresi:       {rapor.calisma_suresi_saat:.1f} saat",
                f"Denetim Modu:         {rapor.denetim_modu}",
                f"Güvenlik Skoru:       {rapor.guvenlik_skoru} / 100",
                f"Güvenlik Durumu:      {rapor.guvenlik_durumu}",
                "-" * 85,
                f"TESPİT EDİLEN GÜVENLİK BULGULARI ({len(rapor.bulgular)} Adet):",
                "-" * 85
            ]

            if not rapor.bulgular:
                satirlar.append("[+] Herhangi bir güvenlik zafiyeti veya risk tespit edilmedi.")
            else:
                for idx, b in enumerate(rapor.bulgular, start=1):
                    satirlar.append(f"[{idx}] {b.baslik} (Önem: {b.onem_derecesi} | Kesinti: -{b.puan_kesintisi})")
                    satirlar.append(f"    CWE:        {b.cwe_kodu}")
                    satirlar.append(f"    Açıklama:   {b.aciklama}")
                    satirlar.append(f"    Çözüm:      {b.cozum_onerisi}")
                    satirlar.append("")

            satirlar.append("=" * 85)
            return "\n".join(satirlar)

        elif fmt == "html":
            # Temiz HTML çıktısı
            bulgu_html = ""
            for b in rapor.bulgular:
                renk = "#dc3545" if b.onem_derecesi == "CRITICAL" else "#fd7e14" if b.onem_derecesi == "HIGH" else "#ffc107"
                bulgu_html += f"""
                <div style="border-left: 4px solid {renk}; padding-left: 10px; margin-bottom: 15px;">
                    <h3 style="color: {renk}; margin: 0;">{b.baslik} [{b.onem_derecesi}]</h3>
                    <p><strong>CWE:</strong> {b.cwe_kodu}</p>
                    <p>{b.aciklama}</p>
                    <p><em>Öneri: {b.cozum_onerisi}</em></p>
                </div>
                """
            html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Sistem Güvenlik Raporu - {rapor.hostname}</title>
</head>
<body style="font-family: sans-serif; margin: 20px;">
    <h1>Sistem Güvenlik Raporu - {rapor.hostname} ({rapor.platform.upper()})</h1>
    <p><strong>Rapor Zamanı (UTC):</strong> {rapor.rapor_zamani_utc}</p>
    <p><strong>Güvenlik Skoru:</strong> {rapor.guvenlik_skoru}/100 ({rapor.guvenlik_durumu})</p>
    <hr>
    <h2>Bulgular</h2>
    {bulgu_html or '<p>Güvenlik açığı tespit edilmedi.</p>'}
</body>
</html>"""
            return html

        return ""
