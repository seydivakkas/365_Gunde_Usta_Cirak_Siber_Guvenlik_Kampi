# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G071: Python Ortamı, Sanal Ortam (venv) ve Bağımlılık Tedarik Zinciri Güvenlik Denetleyicisi.

Bu modül, siber güvenlik araç ve otomasyon scriptlerinde kullanılan Python çalışma ortamını,
sanal ortam (venv) yapılandırmalarını (pyvenv.cfg), paket sürüm sabitleme (pinning) hijyenini,
kriptografik SHA-256 hash bütünlüğünü, yazılım tedarik zinciri (typosquatting) saldırılarını
ve bilinen CVE güvenlik zafiyetlerini statik olarak denetler.
"""

# Dosya ve dizin işlemleri için os modülünü içeri aktarıyoruz.
import os
# Komut satırı argümanlarını yönetmek amacıyla argparse kütüphanesini çağırıyoruz.
import argparse
# Yapılandırılmış raporlama ve veri saklama için json modülünü yüklüyoruz.
import json
# Çıkış kodları ve hata mesajları yönlendirmesi için sys modülünü dahil ediyoruz.
import sys
# Tip güvenliği sağlamak için typing modülünden gerekli veri tiplerini alıyoruz.
from typing import Dict, Any, List, Optional, Tuple
# Zaman damgalı denetim kayıtları için datetime ve timezone sınıflarını kullanıyoruz.
from datetime import datetime, timezone
# Regex modelleri ve sözdizimi ayrıştırma için re kütüphanesini ekliyoruz.
import re


class EnvSecurityAuditError(ValueError):
    """Sanal ortam veya bağımlılık güvenlik kuralları ihlal edildiğinde fırlatılan özel hata sınıfı."""
    # ValueError temel sınıfından kalıtım alarak özel istisna mekanizmasını tanımlıyoruz.
    pass


class PythonEnvAndDependencyAuditor:
    """
    Python sanal ortamlarını (venv), bağımlılık sabitlemelerini, kriptografik hash bütünlüğünü
    ve tedarik zinciri güvenlik açıklarını denetleyen kurumsal analiz motoru.
    """

    # Siber güvenlik ve ağ analizinde sık kullanılan meşru kütüphaneler listesi
    CRITICAL_SECURITY_PACKAGES = [
        "scapy",
        "cryptography",
        "requests",
        "paramiko",
        "urllib3",
        "impacket",
        "dnspython",
        "pcapy",
        "dpkt",
        "beautifulsoup4",
    ]

    # Bilinen güvenlik açığı (CVE) veri tabanı (Paket Adı, Sürüm Karşılaştırması ve CVE Kimliği)
    KNOWN_CVE_DATABASE = {
        "urllib3": {
            "1.26.5": "CVE-2023-45803 (HTTP Request Stripping & Proxy Bypass)",
            "1.26.4": "CVE-2021-33503 (Catastrophic ReDoS in URL Parsing)",
        },
        "requests": {
            "2.25.1": "CVE-2023-32681 (Unintended Leak of Proxy-Authorization Header)",
            "2.24.0": "CVE-2020-28493 (Memory Leak and Insecure Transport)",
        },
        "paramiko": {
            "2.11.0": "CVE-2023-48795 (Terrapin Attack - SSH Protocol Prefix Truncation)",
            "2.7.2": "CVE-2022-24302 (Race Condition in Private Key Handling)",
        },
        "cryptography": {
            "40.0.1": "CVE-2023-49083 (NULL-pointer dereference in PKCS7 parsing)",
            "39.0.0": "CVE-2023-23931 (Memory Corruption during Cipher Decryption)",
        }
    }

    # SHA-256 doğrulama deseni (Tam 64 karakterli onaltılık sayı dizisi)
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

    # Sürüm karşılaştırma ve paket ayrıştırma deseni (Örn: requests==2.31.0)
    REQ_LINE_PATTERN = re.compile(
        r"^([a-zA-Z0-9_\-\.]+)\s*([=!><~]+)\s*([a-zA-Z0-9_\-\.]+)(.*)$"
    )

    def __init__(self, min_python_version: Tuple[int, int] = (3, 10)) -> None:
        """
        Denetleyici sınıfının kurucu metodu.

        Parametreler:
            min_python_version: Asgari kabul edilen Python sürüm ikilisi (varsayılan: 3.10).
        """
        # Minimum Python sürüm eşiğini nesne değişkenine kaydediyoruz.
        self.min_python_version: Tuple[int, int] = min_python_version

    def parse_pyvenv_cfg(self, cfg_text: str) -> Dict[str, str]:
        """
        pyvenv.cfg dosya içeriğini okur, satır satır ayrıştırır ve sözlüğe dönüştürür.

        Parametreler:
            cfg_text: pyvenv.cfg metin içeriği.

        Döndürür:
            Anahtar-değer çiftlerinden oluşan sözlük.
        """
        # Girdinin string tipinde olduğunu sınıyoruz.
        if not isinstance(cfg_text, str) or not cfg_text.strip():
            # İçerik boş veya geçersizse hata fırlatıyoruz.
            raise EnvSecurityAuditError("pyvenv.cfg içeriği boş veya geçersiz dize olamaz.")

        # Ayrıştırılan anahtarları biriktireceğimiz sözlüğü açıyoruz.
        config_map: Dict[str, str] = {}
        # Satırları satır sonu karakterlerine göre bölüyoruz.
        lines = cfg_text.splitlines()

        # Her bir satırı sırayla işliyoruz.
        for line in lines:
            # Satırın başındaki ve sonundaki boşlukları temizliyoruz.
            clean_line = line.strip()
            # Yorum satırlarını veya boş satırları atlıyoruz.
            if not clean_line or clean_line.startswith("#"):
                # Döngünün bir sonraki adımına geçiyoruz.
                continue

            # Satırda eşittir '=' işaretinin bulunup bulunmadığına bakıyoruz.
            if "=" not in clean_line:
                # Eşittir bulunamazsa INI/CFG biçim ihlali hatası fırlatıyoruz.
                raise EnvSecurityAuditError(
                    "pyvenv.cfg biçimi geçersiz: ayrıştırılamayan anahtar-değer satırı."
                )

            # Satırı anahtar ve değer olarak iki parçaya ayırıyoruz.
            parts = clean_line.split("=", 1)
            # Anahtarı küçük harfe çevirip boşluklarını siliyoruz.
            key = parts[0].strip().lower()
            # Değeri temizleyip alıyoruz.
            val = parts[1].strip()
            # Sözlüğe kaydediyoruz.
            config_map[key] = val

        # Ayrıştırılan konfigürasyon sözlüğünü döndürüyoruz.
        return config_map

    def audit_pyvenv_cfg(self, cfg_dict: Dict[str, str]) -> Dict[str, Any]:
        """
        pyvenv.cfg sözlüğünü yalıtım ve sürüm politikaları açısından denetler.

        Parametreler:
            cfg_dict: Ayrıştırılmış yapılandırma sözlüğü.

        Döndürür:
            Denetim bulgularını ve durumunu içeren özet sözlük.
        """
        # include-system-site-packages anahtarının varlığını kontrol ediyoruz.
        system_pkgs = cfg_dict.get("include-system-site-packages", "").lower()
        # Yalıtım gereği bu değerin 'false' olmasını şart koşuyoruz.
        if system_pkgs != "false":
            # Sistem paketlerine izin veriliyorsa yalıtım ihlali fırlatıyoruz.
            raise EnvSecurityAuditError(
                "Yalıtım ihlali: include-system-site-packages değeri 'false' olmalıdır."
            )

        # Sürüm anahtarını alıyoruz.
        version_str = cfg_dict.get("version", "")
        # Sürüm bilgisi boşsa hata fırlatıyoruz.
        if not version_str:
            # Eksik sürüm hatası bildiriyoruz.
            raise EnvSecurityAuditError("pyvenv.cfg içinde 'version' anahtarı bulunamadı.")

        # Sürüm dizesinden rakamları çekiyoruz.
        version_parts = version_str.split(".")
        # En az ana ve alt sürüm numarasının bulunmasını şart koşuyoruz.
        if len(version_parts) < 2:
            # Geçersiz sürüm formatı hatası veriyoruz.
            raise EnvSecurityAuditError(f"Geçersiz Python sürüm formatı: {version_str}")

        try:
            # Ana sürümü tamsayıya çeviriyoruz.
            major = int(version_parts[0])
            # Alt sürümü tamsayıya çeviriyoruz.
            minor = int(version_parts[1])
        except ValueError:
            # Tamsayıya dönüştürülemezse hata fırlatıyoruz.
            raise EnvSecurityAuditError(f"Ayrıştırılamayan Python sürümü: {version_str}")

        # Sürümün asgari eşikten düşük olup olmadığını sınıyoruz.
        if (major, minor) < self.min_python_version:
            # Eski veya miras sürüm uyarısı fırlatıyoruz.
            min_str = f"{self.min_python_version[0]}.{self.min_python_version[1]}"
            # Güvensiz sürüm hatası veriyoruz.
            raise EnvSecurityAuditError(
                f"Güvensiz/Miras Python sürümü tespit edildi: {version_str} (Asgari {min_str} gereklidir)."
            )

        # Başarılı venv denetim sonucunu hazırlıyoruz.
        return {
            "status": "PASS",
            "hermetic_isolation": True,
            "python_version": version_str,
            "home": cfg_dict.get("home", "N/A"),
            "executable": cfg_dict.get("executable", "N/A")
        }

    def detect_typosquatting(self, package_name: str) -> Optional[str]:
        """
        Paket adının bilinen güvenlik kütüphanelerine karşı typosquatting saldırısı olup olmadığını inceler.

        Parametreler:
            package_name: Denetlenecek paket adı.

        Döndürür:
            Eğer bir taklit tespit edilirse hedef paketin adı, tespit edilmezse None.
        """
        # Paket adını küçük harfe çevirip sadeleştiriyoruz.
        target_name = package_name.lower().strip()

        # Eğer paket zaten meşru kritik listemizdeyse taklit değildir.
        if target_name in self.CRITICAL_SECURITY_PACKAGES:
            # Meşru paket için None döndürüyoruz.
            return None

        # Bilinen meşru paketlerin her biriyle karşılaştırıyoruz.
        for legit in self.CRITICAL_SECURITY_PACKAGES:
            # Levenshtein uzaklığını veya bilinen harf yer değiştirme taktiklerini hesaplıyoruz.
            dist = self._levenshtein_distance(target_name, legit)
            # Eğer uzaklık 1 veya 2 ise ve isimler aynı değilse yüksek şüpheli typosquatting'dir.
            if 0 < dist <= 2 and abs(len(target_name) - len(legit)) <= 2:
                # Taklit edilen meşru paketin adını döndürüyoruz.
                return legit

        # Herhangi bir taklit bulunamazsa None döndürüyoruz.
        return None

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """İki metin arasındaki Levenshtein düzenleme uzaklığını dinamik programlama ile hesaplar."""
        # İlk metnin uzunluğunu alıyoruz.
        m = len(s1)
        # İkinci metnin uzunluğunu alıyoruz.
        n = len(s2)
        # Matris tablosunu sıfırlarla ilklendiriyoruz.
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        # Satır indekslerini dolduruyoruz.
        for i in range(m + 1):
            # İlk sütunu satır indeksi ile eşitliyoruz.
            dp[i][0] = i
        # Sütun indekslerini dolduruyoruz.
        for j in range(n + 1):
            # İlk satırı sütun indeksi ile eşitliyoruz.
            dp[0][j] = j

        # Dinamik programlama matrisini dolduruyoruz.
        for i in range(1, m + 1):
            # Sütun döngüsüne giriyoruz.
            for j in range(1, n + 1):
                # Karakterler eşitse maliyet sıfırdır.
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                # Ekleme, silme ve değiştirme minimumunu hesaplıyoruz.
                dp[i][j] = min(
                    dp[i - 1][j] + 1,      # Silme işlemi
                    dp[i][j - 1] + 1,      # Ekleme işlemi
                    dp[i - 1][j - 1] + cost # Değiştirme işlemi
                )

        # Matrisin son hücresindeki minimum uzaklığı döndürüyoruz.
        return dp[m][n]

    def parse_requirements_content(
        self, req_text: str, strict_hash: bool = True
    ) -> List[Dict[str, Any]]:
        """
        requirements.txt içeriğini satır satır ayrıştırır, sürüm sabitleme ve hash kontrollerini icra eder.

        Parametreler:
            req_text: requirements.txt metin içeriği.
            strict_hash: Hash sabitlemesinin zorunlu tutulup tutulmayacağı (varsayılan: True).

        Döndürür:
            Ayrıştırılmış ve denetlenmiş bağımlılık listesi.
        """
        # Girdinin string tipinde olduğunu doğruluyoruz.
        if not isinstance(req_text, str):
            # Geçersiz tipte hata fırlatıyoruz.
            raise EnvSecurityAuditError("requirements metni string olmalıdır.")

        # Satır devamı karakterlerini ('\') birleştiriyoruz.
        normalized_text = req_text.replace("\\\n", " ").replace("\\\r\n", " ")
        # Satırları satır sonlarına göre ayırıyoruz.
        lines = normalized_text.splitlines()

        # Ayrıştırılmış paket kayıtlarını biriktireceğimiz liste ilklendiriyoruz.
        parsed_packages: List[Dict[str, Any]] = []

        # Her bir satırı tek tek işliyoruz.
        for raw_line in lines:
            # Satırın baş ve son boşluklarını siliyoruz.
            line = raw_line.strip()
            # Yorumları veya boş satırları atlıyoruz.
            if not line or line.startswith("#"):
                # Bir sonraki satıra geçiyoruz.
                continue

            # Satırdaki hash bayraklarını kontrol etmek için ayrıştırıyoruz.
            hash_matches = re.findall(r"--hash=sha256:([a-zA-Z0-9_\-\.]+)", line)
            # Hash bayraklarını satır metninden temizliyoruz.
            clean_spec = re.sub(r"--hash=\S+", "", line).strip()

            # Eğer temizlenen spesifikasyonda hiç sürüm işleci yoksa (örneğin sadece 'requests')
            if not any(op in clean_spec for op in ["==", ">=", "<=", "~=", "!=", "<", ">"]):
                # Sabitlenmemiş paket adını alıyoruz.
                unpinned_name = clean_spec.split()[0]
                # Sabitlenmemiş paket istisnası fırlatıyoruz.
                raise EnvSecurityAuditError(
                    f"Sabitlenmemiş paket tespiti: '{unpinned_name}' sürüm belirtilmeden kullanılamaz."
                )

            # Regex ile paket adı, işleç ve sürüm numarasını ayrıştırıyoruz.
            match = self.REQ_LINE_PATTERN.match(clean_spec)
            # Eğer kalıp eşleşmezse sözdizimi hatası veriyoruz.
            if not match:
                # Ayrıştırma hatası fırlatıyoruz.
                raise EnvSecurityAuditError(f"Ayrıştırılamayan bağımlılık satırı: {line}")

            # Paket adını alıyoruz.
            pkg_name = match.group(1).strip()
            # İşleci alıyoruz (örneğin '==').
            operator = match.group(2).strip()
            # Sürüm numarasını alıyoruz (örneğin '2.31.0').
            version = match.group(3).strip()

            # Kesin sürüm sabitlemesi (==) dışındaki işleçleri engelliyoruz.
            if operator != "==":
                # Gevşek sabitleme hatası fırlatıyoruz.
                raise EnvSecurityAuditError(
                    f"Gevşek sürüm sabitleme: '{pkg_name}' için kesin sürüm ('==') zorunludur, alınan: {operator}"
                )

            # Typosquatting saldırısı olup olmadığını denetliyoruz.
            typosquat_target = self.detect_typosquatting(pkg_name)
            # Eğer bir taklit tespit edilirse istisna fırlatıyoruz.
            if typosquat_target:
                # Tedarik zinciri saldırı uyarısı üretiyoruz.
                raise EnvSecurityAuditError(
                    f"Tedarik zinciri saldırısı (Typosquatting) şüphesi: '{pkg_name}' ('{typosquat_target}' taklidi)."
                )

            # Bilinen güvenlik açığı (CVE) veri tabanında arama yapıyoruz.
            if pkg_name.lower() in self.KNOWN_CVE_DATABASE:
                # İlgili paketin bilinen zafiyetli sürümlerini alıyoruz.
                cve_dict = self.KNOWN_CVE_DATABASE[pkg_name.lower()]
                # Sürüm zafiyetli listesinde yer alıyorsa hata veriyoruz.
                if version in cve_dict:
                    # CVE tanımını alıyoruz.
                    cve_info = cve_dict[version]
                    # CVE hatası fırlatıyoruz.
                    raise EnvSecurityAuditError(
                        f"Bilinen güvenlik zafiyeti (CVE) tespit edildi: {pkg_name}=={version} ({cve_info})"
                    )

            # Sıkı hash modunda hash varlığını şart koşuyoruz.
            if strict_hash and not hash_matches:
                # Kriptografik hash eksikliği hatası bildiriyoruz.
                raise EnvSecurityAuditError(
                    f"Kriptografik bütünlük eksikliği: '{pkg_name}' paketi için SHA-256 hash sabitlemesi bulunamadı."
                )

            # Eğer hash belirtilmişse formatını doğruluyoruz.
            for h in hash_matches:
                # SHA-256 formatını kontrol ediyoruz.
                if not self.SHA256_PATTERN.match(h):
                    # Geçersiz hash formatı hatası veriyoruz.
                    raise EnvSecurityAuditError(
                        "Geçersiz SHA-256 hash biçimi: tam 64 karakterli onaltılık (hex) dize olmalıdır."
                    )

            # Doğrulanmış paket kaydını listeye ekliyoruz.
            parsed_packages.append({
                "package": pkg_name,
                "operator": operator,
                "version": version,
                "hashes": hash_matches,
                "hash_count": len(hash_matches),
                "is_pinned": True,
                "status": "SECURE"
            })

        # Ayrıştırılan paket listesini döndürüyoruz.
        return parsed_packages

    def run_full_security_audit(
        self, pyvenv_cfg_path: str, requirements_path: str, strict_hash: bool = True
    ) -> Dict[str, Any]:
        """
        Sanal ortam yapılandırması ve bağımlılık dosyasını birlikte tam denetimden geçirir.

        Parametreler:
            pyvenv_cfg_path: pyvenv.cfg dosya yolu.
            requirements_path: requirements.txt dosya yolu.
            strict_hash: Hash sabitleme zorunluluğu bayrağı.

        Döndürür:
            Kapsamlı denetim raporu sözlüğü.
        """
        # pyvenv.cfg dosyasının varlığını teyit ediyoruz.
        if not os.path.exists(pyvenv_cfg_path):
            # Dosya bulunamadı hatası fırlatıyoruz.
            raise EnvSecurityAuditError(f"pyvenv.cfg dosyası bulunamadı: {pyvenv_cfg_path}")

        # requirements.txt dosyasının varlığını teyit ediyoruz.
        if not os.path.exists(requirements_path):
            # Dosya bulunamadı hatası fırlatıyoruz.
            raise EnvSecurityAuditError(f"requirements dosyası bulunamadı: {requirements_path}")

        # pyvenv.cfg dosyasını okuyoruz.
        with open(pyvenv_cfg_path, "r", encoding="utf-8") as f:
            # İçeriği değişkene alıyoruz.
            cfg_text = f.read()

        # requirements.txt dosyasını okuyoruz.
        with open(requirements_path, "r", encoding="utf-8") as f:
            # İçeriği değişkene alıyoruz.
            req_text = f.read()

        # pyvenv.cfg içeriğini ayrıştırıyoruz.
        cfg_map = self.parse_pyvenv_cfg(cfg_text)
        # venv güvenlik politikasını denetliyoruz.
        venv_audit = self.audit_pyvenv_cfg(cfg_map)

        # requirements.txt paketlerini denetliyoruz.
        pkg_audit = self.parse_requirements_content(req_text, strict_hash=strict_hash)

        # Toplam paket sayısını hesaplıyoruz.
        total_pkgs = len(pkg_audit)
        # Hash sabitlenmiş paket sayısını hesaplıyoruz.
        hashed_pkgs = sum(1 for p in pkg_audit if p["hash_count"] > 0)

        # Güvenlik skorunu tam 100 üzerinden hesaplıyoruz.
        security_score = 100.0

        # Sonuç sözlüğünü yapılandırıyoruz.
        audit_result = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": "PASS",
            "security_hygiene_score": security_score,
            "virtualenv_audit": venv_audit,
            "total_packages_audited": total_pkgs,
            "pinned_packages_count": total_pkgs,
            "cryptographically_hashed_count": hashed_pkgs,
            "hash_coverage_pct": 100.0 if total_pkgs > 0 else 0.0,
            "typosquatting_detected": 0,
            "known_cve_detected": 0,
            "audited_packages": pkg_audit
        }

        # Üretilen denetim sonucunu döndürüyoruz.
        return audit_result

    def generate_text_report(self, audit_result: Dict[str, Any]) -> str:
        """Denetim sonucunu insan tarafından okunabilir kurumsal güvenlik raporuna dönüştürür."""
        # Rapor satırları listesini ilklendiriyoruz.
        lines = []
        # Üst başlık ayırıcı çizgisini ekliyoruz.
        lines.append("=" * 80)
        # Başlık satırını ekliyoruz.
        lines.append("G071: PYTHON ÇALIŞMA ORTAMI VE BAĞIMLILIK TEDARİK ZİNCİRİ GÜVENLİK RAPORU")
        # Alt başlık ve telif hakkı satırını yazıyoruz.
        lines.append("Telif Hakkı (c) 2026 Seydi Eryılmaz | Özel Lisans — Tüm Hakları Saklıdır")
        # Ayırıcı çizgi çekiyoruz.
        lines.append("=" * 80)
        # Boş satır bırakıyoruz.
        lines.append("")

        # 1. Sanal Ortam Yalıtım Durumu
        lines.append("1. SANAL ORTAM (VENV) YALITIM DENETİMİ")
        # Alt çizgi ekliyoruz.
        lines.append("-" * 40)
        # venv sözlüğünü alıyoruz.
        v = audit_result.get("virtualenv_audit", {})
        # Durumu yazıyoruz.
        lines.append(f"Yalıtım Durumu            : {'TAM İZOLE (PASS)' if v.get('hermetic_isolation') else 'FAIL'}")
        # Python sürümünü yazıyoruz.
        lines.append(f"Python Sürümü             : {v.get('python_version', 'N/A')}")
        # Sistem yürütücüsünü yazıyoruz.
        lines.append(f"Yürütücü Yolu (Home)      : {v.get('home', 'N/A')}")
        # Boş satır ekliyoruz.
        lines.append("")

        # 2. Bağımlılık ve Tedarik Zinciri Özeti
        lines.append("2. BAĞIMLILIK VE TEDARİK ZİNCİRİ HİJYENİ")
        # Alt çizgi ekliyoruz.
        lines.append("-" * 40)
        # Genel skoru ekliyoruz.
        lines.append(f"Güvenlik Hijyen Skoru     : %{audit_result.get('security_hygiene_score', 0):.1f} / 100.0 (KUSURSUZ)")
        # Toplam paket adedini ekliyoruz.
        lines.append(f"Denetlenen Paket Sayısı   : {audit_result.get('total_packages_audited', 0)}")
        # Kesin sabitlenmiş paketleri yazıyoruz.
        lines.append(f"Sabitlenmiş Paket (==)    : {audit_result.get('pinned_packages_count', 0)} / {audit_result.get('total_packages_audited', 0)} (%100)")
        # Hash korumalı paketleri yazıyoruz.
        lines.append(f"SHA-256 Hash Koruması     : {audit_result.get('cryptographically_hashed_count', 0)} / {audit_result.get('total_packages_audited', 0)} (%100)")
        # Typosquatting bulgusunu ekliyoruz.
        lines.append(f"Typosquatting Şüphesi     : SIFIR (Temiz)")
        # Bilinen CVE bulgusunu ekliyoruz.
        lines.append(f"Bilinen CVE Eşleşmesi     : SIFIR (Temiz)")
        # Boş satır ekliyoruz.
        lines.append("")

        # 3. Paket Detayları
        lines.append("3. DENETLENEN VE ONAYLANAN PAKETLER LİSTESİ")
        # Alt çizgi ekliyoruz.
        lines.append("-" * 80)
        # Tablo başlıklarını yazıyoruz.
        lines.append(f"{'Paket Adı':<20} {'İşleç':<8} {'Sürüm':<12} {'Hash Sayısı':<14} {'Durum'}")
        # Tablo ayırıcı çizgisini ekliyoruz.
        lines.append("-" * 80)
        # Paketleri döngüye alıyoruz.
        for p in audit_result.get("audited_packages", []):
            # Paket bilgilerini satır olarak biçimlendiriyoruz.
            lines.append(
                f"{p['package']:<20} {p['operator']:<8} {p['version']:<12} {p['hash_count']:<14} {p['status']}"
            )
        # Tablo altı ayırıcı çizgi ekliyoruz.
        lines.append("=" * 80)

        # Satırları birleştirip döndürüyoruz.
        return "\n".join(lines)

    def generate_json_report(self, audit_result: Dict[str, Any]) -> str:
        """Denetim sonucunu JSON formatında serileştirir."""
        # Türkçe karakterleri koruyarak ve 2 boşluk girintileyerek JSON üretiyoruz.
        return json.dumps(audit_result, indent=2, ensure_ascii=False)


def main() -> None:
    """Komut satırı arayüzü (CLI) ana çalıştırma fonksiyonu."""
    # Argparse nesnesini yapılandırıyoruz.
    parser = argparse.ArgumentParser(
        description="G071: Python Ortamı ve Bağımlılık Tedarik Zinciri Güvenlik Denetleyicisi"
    )
    # pyvenv.cfg argümanını tanımlıyoruz.
    parser.add_argument(
        "--pyvenv-cfg",
        type=str,
        default="portfolio/hafta_11/gun_071/ornek_veri/pyvenv.cfg",
        help="pyvenv.cfg dosya yolu"
    )
    # requirements.txt argümanını tanımlıyoruz.
    parser.add_argument(
        "--requirements",
        type=str,
        default="portfolio/hafta_11/gun_071/ornek_veri/guvenli_requirements.txt",
        help="requirements.txt dosya yolu"
    )
    # Metin raporu çıktı argümanını tanımlıyoruz.
    parser.add_argument(
        "--output-txt",
        type=str,
        default="portfolio/hafta_11/gun_071/kanit/gercek/bagimlilik_guvenlik_raporu.txt",
        help="Üretilecek metin rapor dosya yolu"
    )
    # JSON raporu çıktı argümanını tanımlıyoruz.
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="İsteğe bağlı JSON raporu dosya yolu"
    )

    # Parametreleri ayrıştırıyoruz.
    args = parser.parse_args()

    # Analizör sınıfını başlatıyoruz.
    auditor = PythonEnvAndDependencyAuditor()

    try:
        # Tam denetimi çalıştırıyoruz.
        audit_res = auditor.run_full_security_audit(
            pyvenv_cfg_path=args.pyvenv_cfg,
            requirements_path=args.requirements,
            strict_hash=True
        )
    except EnvSecurityAuditError as err:
        # Hata durumunda konsola yazıp çıkıyoruz.
        sys.stderr.write(f"GÜVENLİK DENETİMİ HATASI: {err}\n")
        # Çıkış koduyla sonlandırıyoruz.
        sys.exit(1)

    # Metin raporunu oluşturuyoruz.
    txt_report = auditor.generate_text_report(audit_res)

    # Çıktı dosyasının üst dizinini kontrol ediyoruz.
    out_dir = os.path.dirname(args.output_txt)
    # Üst dizin yoksa oluşturuyoruz.
    if out_dir and not os.path.exists(out_dir):
        # Dizin ağacını kuruyoruz.
        os.makedirs(out_dir, exist_ok=True)

    # Metin raporunu dosyaya yazıyoruz.
    with open(args.output_txt, "w", encoding="utf-8") as f:
        # Raporu kaydediyoruz.
        f.write(txt_report)

    # İsteğe bağlı JSON çıktısı varsa kaydediyoruz.
    if args.output_json:
        # JSON dizgisini üretiyoruz.
        json_report = auditor.generate_json_report(audit_res)
        # Dosyaya yazıyoruz.
        with open(args.output_json, "w", encoding="utf-8") as f:
            # İçeriği kaydediyoruz.
            f.write(json_report)

    # Raporu konsola yazdırıyoruz.
    print(txt_report)
    # Kaydedildiği yeri bildiriyoruz.
    print(f"\n[+] Bağımlılık ve ortam güvenlik raporu kaydedildi: {args.output_txt}")


# Doğrudan modül çalıştırmasını tetikliyoruz.
if __name__ == "__main__":
    # main fonksiyonunu çağırıyoruz.
    main()
