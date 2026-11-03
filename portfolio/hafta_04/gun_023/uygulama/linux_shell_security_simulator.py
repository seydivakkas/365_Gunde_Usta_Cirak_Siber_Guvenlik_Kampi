# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar yalnızca görüntüleme ve eğitim amaçlıdır.
# Siber Güvenlik 365 Gün Müfredatı - Gün 023 (Linux Terminali ve Kabuk)

"""Linux Kabuk ve Terminal Güvenlik Simülatörü (Linux Shell Security Simulator).

Bu modül, POSIX standartlarındaki temel kabuk komutlarını (pwd, cd, ls, cat, head)
simüle eder; göreceli yol zafiyetlerini (CWE-426), dizin aşımı girişimlerini (CWE-22)
ve PATH ortam değişkeni manipülasyonlarını güvenlik perspektifinden denetler.
"""

# Komut satırı argümanları ve sistem işlevleri için sys modülü içe aktarılır.
import sys
# Dosya yolları ve ortam değişkenleri denetimi için os modülü içe aktarılır.
import os
# JSON formatında sanal dosya sistemi ve kural yükleme için json modülü içe aktarılır.
import json
# POSIX uyumlu yol sadeleştirme ve mutlak yol hesaplama için posixpath modülü içe aktarılır.
import posixpath
# Tip güvenliği ve statik kod analizi için tip ipuçları içe aktarılır.
from typing import Dict, List, Any, Optional, Tuple


class LinuxShellSecuritySimulator:
    """Linux kabuk mimarisini ve temel komutlarını güvenlik kurallarıyla simüle eden sınıf."""

    def __init__(self,
                 fs_data: Optional[Dict[str, Any]] = None,
                 rules_data: Optional[Dict[str, Any]] = None) -> None:
        """Sanal dosya sistemi ve güvenlik kuralları ile kabuk simülatörünü başlatır.

        Args:
            fs_data: Sanal dizin ve dosyaları içeren yapılandırılmış sözlük.
            rules_data: Güvenlik denetim eşikleri ve kurallarını içeren sözlük.
        """
        # Güvenlik kuralları atanır veya varsayılanlar yüklenir.
        self.rules = rules_data or self._get_default_rules()
        # Sanal dosya sistemi yüklenir veya varsayılan temel ağaç oluşturulur.
        self.fs = fs_data or self._get_default_filesystem()
        # Başlangıç çalışma dizini belirlenir (varsayılan: /home/analyst).
        self.cwd: str = "/home/analyst" if "/home/analyst" in self._get_directory_paths() else "/"
        # Yürütülen komutların ve denetim bulgularının geçmiş listesi tutulur.
        self.history: List[Dict[str, Any]] = []

    def _get_default_rules(self) -> Dict[str, Any]:
        """Varsayılan güvenlik ve yol denetim kurallarını döndürür."""
        # Standart POSIX ve CWE kurallarını içeren sözlük oluşturulur ve döndürülür.
        return {
            "desteklenen_temel_komutlar": ["pwd", "cd", "ls", "cat", "head"],
            "tehlikeli_yol_kaliplari": ["../", "..\\", "/../", "../../"],
            "guvensiz_path_dizinleri": [".", "", "/tmp", "/var/tmp", "/dev/shm"]
        }

    def _get_default_filesystem(self) -> Dict[str, Any]:
        """Bağımsız testler için varsayılan sanal Linux dosya sistemini döndürür."""
        # Çekirdek dizinleri ve örnek dosyaları içeren sanal ağaç tanımlanır.
        return {
            "kok_dizin": "/",
            "dizinler": [
                {"yol": "/", "izin": "0755", "sahip": "root:root"},
                {"yol": "/etc", "izin": "0755", "sahip": "root:root"},
                {"yol": "/var", "izin": "0755", "sahip": "root:root"},
                {"yol": "/var/log", "izin": "0750", "sahip": "root:adm"},
                {"yol": "/home", "izin": "0755", "sahip": "root:root"},
                {"yol": "/home/analyst", "izin": "0750", "sahip": "analyst:analyst"},
                {"yol": "/tmp", "izin": "1777", "sahip": "root:root"}
            ],
            "dosyalar": [
                {
                    "yol": "/etc/passwd",
                    "izin": "0644",
                    "sahip": "root:root",
                    "icerik": "root:x:0:0:root:/root:/bin/bash\nanalyst:x:1000:1000:Analist:/home/analyst:/bin/bash"
                },
                {
                    "yol": "/etc/shadow",
                    "izin": "0640",
                    "sahip": "root:shadow",
                    "icerik": "root:$6$rounds=500000$salt$hash:19800:0:99999:7:::\nanalyst:$6$rounds=500000$salt2$hash2:19800:0:90:7:::"
                },
                {
                    "yol": "/var/log/auth.log",
                    "izin": "0640",
                    "sahip": "root:adm",
                    "icerik": "Oct 27 01:10:01 srv sshd[100]: Accepted publickey for analyst\nOct 27 01:15:00 srv sudo: analyst : COMMAND=/bin/cat /etc/passwd\nOct 27 01:20:00 srv sshd[105]: Failed password for invalid user admin"
                },
                {
                    "yol": "/home/analyst/notes.txt",
                    "izin": "0600",
                    "sahip": "analyst:analyst",
                    "icerik": "Not 1: Göreli yol kullanımı zafiyete yol açabilir.\nNot 2: Mutlak yol her zaman tercih edilmelidir."
                }
            ]
        }

    def _get_directory_paths(self) -> List[str]:
        """Sanal dosya sistemindeki tüm dizin yollarının listesini döndürür."""
        # Dizin listesinden sadece yol alanları ayıklanır.
        return [d["yol"] for d in self.fs.get("dizinler", [])]

    def _get_file_paths(self) -> List[str]:
        """Sanal dosya sistemindeki tüm dosya yollarının listesini döndürür."""
        # Dosya listesinden sadece yol alanları ayıklanır.
        return [f["yol"] for f in self.fs.get("dosyalar", [])]

    def resolve_path(self, target_path: str) -> str:
        """Verilen göreli veya mutlak yolu mevcut çalışma dizinine (cwd) göre mutlak yola dönüştürür.

        Args:
            target_path: Çözümlenecek göreceli veya mutlak dosya/dizin yolu.

        Returns:
            Normalleştirilmiş POSIX mutlak dosya yolu.
        """
        # Hedef yol boşsa mevcut çalışma dizini döndürülür.
        if not target_path or target_path == ".":
            # Mevcut dizin döndürülür.
            return self.cwd

        # Eğer yol '/' ile başlamıyorsa göreceli yoldur; mevcut dizine eklenir.
        if not target_path.startswith("/"):
            # Mevcut dizin ile hedef yol posix standartlarında birleştirilir.
            combined = posixpath.join(self.cwd, target_path)
        else:
            # Zaten mutlak yoldur.
            combined = target_path

        # '.' ve '..' gibi göreceli referanslar normalleştirilir (çözümlenir).
        normalized = posixpath.normpath(combined)
        # Kök dizin kontrolü: Boş kaldıysa '/' olarak düzeltilir.
        return normalized if normalized else "/"

    def pwd(self) -> str:
        """Mevcut çalışma dizinini (Print Working Directory) döndürür."""
        # self.cwd niteliği doğrudan döndürülür.
        return self.cwd

    def cd(self, target_path: str) -> str:
        """Çalışma dizinini hedef yola değiştirir.

        Args:
            target_path: Geçiş yapılacak hedef dizin yolu.

        Raises:
            FileNotFoundError: Hedef dizin sanal dosya sisteminde yoksa fırlatılır.
            NotADirectoryError: Hedef yol bir dizin değil de dosyaysa fırlatılır.
        """
        # Hedef yol mutlak formata dönüştürülür.
        resolved = self.resolve_path(target_path)

        # Hedefin bir dosya olup olmadığı kontrol edilir.
        if resolved in self._get_file_paths():
            # Dosyaya cd yapılamaz hatası fırlatılır.
            raise NotADirectoryError(f"Hedef bir dizin değil, dosyadır: {resolved}")

        # Hedefin kayıtlı dizinler arasında olup olmadığı kontrol edilir.
        if resolved not in self._get_directory_paths():
            # Dizin bulunamadı hatası fırlatılır.
            raise FileNotFoundError(f"Dizin bulunamadı: {resolved}")

        # Çalışma dizini güncellenir.
        self.cwd = resolved
        # Yeni dizin yolu döndürülür.
        return self.cwd

    def ls(self, target_path: Optional[str] = None) -> List[Dict[str, str]]:
        """Hedef dizinin içeriğini (dosya ve alt dizinler) listeler.

        Args:
            target_path: Listelenecek dizin; belirtilmezse mevcut dizin (cwd) kullanılır.

        Returns:
            Dizin içeriğindeki öğelerin türü, izinleri, sahibi ve adını içeren liste.
        """
        # Hedef dizin belirlenir.
        dest_dir = self.resolve_path(target_path) if target_path else self.cwd

        # Dizin varlığı kontrol edilir.
        if dest_dir not in self._get_directory_paths():
            # Dizin yoksa hata fırlatılır.
            raise FileNotFoundError(f"Listelenecek dizin bulunamadı: {dest_dir}")

        # Sonuç listesi başlatılır.
        entries: List[Dict[str, str]] = []

        # 1. Alt dizinler taranır.
        for d in self.fs.get("dizinler", []):
            # Yol okunur.
            p = d["yol"]
            # Kendi kendisi atlanır.
            if p == dest_dir:
                continue
            # Hedef dizinin doğrudan bir alt öğesi mi kontrol edilir.
            parent = posixpath.dirname(p)
            # Üst dizin eşleşiyorsa eklenir.
            if parent == dest_dir:
                # İsim ayıklanır.
                base_name = posixpath.basename(p)
                # Dizin girdisi listeye kaydedilir.
                entries.append({
                    "tur": "DIR",
                    "isim": base_name,
                    "izin": d.get("izin", "0755"),
                    "sahip": d.get("sahip", "root:root"),
                    "tam_yol": p
                })

        # 2. Dosyalar taranır.
        for f in self.fs.get("dosyalar", []):
            # Dosya yolu okunur.
            fp = f["yol"]
            # Üst dizini alınır.
            parent = posixpath.dirname(fp)
            # Hedef dizinin içindeki dosya ise eklenir.
            if parent == dest_dir:
                # Dosya taban adı alınır.
                base_name = posixpath.basename(fp)
                # Dosya girdisi eklenir.
                entries.append({
                    "tur": "FILE",
                    "isim": base_name,
                    "izin": f.get("izin", "0644"),
                    "sahip": f.get("sahip", "root:root"),
                    "tam_yol": fp
                })

        # Listeyi isme göre sıralayarak döndürür.
        return sorted(entries, key=lambda x: x["isim"])

    def cat(self, target_path: str) -> str:
        """Belirtilen dosyanın tam içeriğini döndürür.

        Args:
            target_path: Okunacak dosyanın yolu.

        Raises:
            FileNotFoundError: Dosya yoksa fırlatılır.
            IsADirectoryError: Yol bir dizini gösteriyorsa fırlatılır.
        """
        # Yol mutlak formata dönüştürülür.
        resolved = self.resolve_path(target_path)

        # Yol dizin ise hata fırlatılır.
        if resolved in self._get_directory_paths():
            # Dizin okunamayacağı için IsADirectoryError üretilir.
            raise IsADirectoryError(f"Dizin içeriği cat ile okunamaz: {resolved}")

        # Dosyalar taranır.
        for f in self.fs.get("dosyalar", []):
            # Dosya yolu eşleşiyor mu kontrol edilir.
            if f["yol"] == resolved:
                # Dosya içeriği döndürülür.
                return f.get("icerik", "")

        # Eşleşen dosya yoksa FileNotFoundError fırlatılır.
        raise FileNotFoundError(f"Dosya bulunamadı: {resolved}")

    def head(self, target_path: str, n: int = 5) -> str:
        """Belirtilen dosyanın ilk 'n' satırını döndürür.

        Args:
            target_path: Okunacak dosyanın yolu.
            n: Döndürülecek satır sayısı (varsayılan: 5).

        Returns:
            Dosyanın ilk n satırından oluşan metin.
        """
        # Dosya içeriği cat ile tam okunur.
        content = self.cat(target_path)
        # Satırlara ayrıştırılır.
        lines = content.splitlines()
        # İlk n satır alınır ve birleştirilir.
        return "\n".join(lines[:n])

    def audit_path_traversal(self, raw_input_path: str) -> Dict[str, Any]:
        """Göreceli yoldaki dizin aşımı (Path Traversal - CWE-22) risklerini analiz eder.

        Args:
            raw_input_path: Kullanıcı veya betik tarafından sağlanan ham yol parametresi.

        Returns:
            Risk seviyesi ve CWE eşleşmesini içeren güvenlik analizi sözlüğü.
        """
        # Şüpheli dizin aşımı kalıpları kontrol edilir.
        has_traversal = any(p in raw_input_path for p in self.rules.get("tehlikeli_yol_kaliplari", []))
        # Çözümlenmiş mutlak yol hesaplanır.
        resolved = self.resolve_path(raw_input_path)

        # Eğer tehlikeli kalıp varsa YÜKSEK risk atanır.
        if has_traversal:
            # Traversal bulgusu döndürülür.
            return {
                "girdi_yol": raw_input_path,
                "cozumlenen_yol": resolved,
                "risk_seviyesi": "YUKSEK",
                "zafiyet": "Dizin Aşımı Riski (CWE-22 Path Traversal)",
                "aciklama": "Göreceli yolda '../../' kullanımı üst dizinlerdeki yetkisiz dosyalara erişim tehlikesi taşır."
            }

        # Temiz yol sonucu döndürülür.
        return {
            "girdi_yol": raw_input_path,
            "cozumlenen_yol": resolved,
            "risk_seviyesi": "TEMIZ",
            "zafiyet": None,
            "aciklama": "Güvenli ve standart yol kullanımı."
        }

    def audit_path_environment(self, path_env_string: str) -> Dict[str, Any]:
        """PATH ortam değişkeninin bütünlüğünü ve güvensiz arama dizinlerini (CWE-426) denetler.

        Args:
            path_env_string: İncelenecek PATH değişkeni metni (örn. '/usr/bin:/bin:.').

        Returns:
            Bulunan güvensiz dizinleri ve güvenlik değerlendirmesini içeren sözlük.
        """
        # Yollar iki nokta üst üste ':' ile bölünür.
        dirs = path_env_string.split(":")
        # Güvensiz dizinleri toplayacak liste başlatılır.
        insecure_found = []
        # Karalistedeki güvensiz dizinler alınır.
        blacklist = self.rules.get("guvensiz_path_dizinleri", [".", "", "/tmp"])

        # Her bir PATH bileşeni incelenir.
        for idx, d in enumerate(dirs):
            # Boş öğe veya '.' doğrudan mevcut dizin anlamına gelir.
            if d in blacklist or d == "" or d == ".":
                # Güvensiz giriş kaydedilir.
                insecure_found.append({
                    "pozisyon": idx,
                    "dizin": d if d else "BOŞ (Mevcut Dizin)",
                    "tehdit": "Mevcut dizindeki truva atı (Trojan) ikilisinin sistem komutu yerine çalıştırılması (CWE-426)"
                })

        # Risk seviyesi belirlenir: Güvensiz dizin varsa KRİTİK, yoksa GÜVENLİ.
        risk = "KRITIK" if insecure_found else "GUVENLI"

        # Analiz raporu döndürülür.
        return {
            "toplam_path_dizini_sayisi": len(dirs),
            "guvensiz_girdi_sayisi": len(insecure_found),
            "risk_seviyesi": risk,
            "bulgular": insecure_found,
            "oneri": "PATH değişkeninden '.' ve '/tmp' dizinlerini kaldırın; yalnızca güvenli sistem dizinlerini tutun."
        }

    def run_full_lab_workflow(self) -> Dict[str, Any]:
        """Soru bankası G023-SC2 gereğince 5 temel komutu (pwd, ls, cd, cat, head) sıralı yürütür.

        Returns:
            Adım adım komut çıktılarını ve güvenlik doğrulamasını içeren laboratuvar raporu.
        """
        # Adım çıktılarını tutacak sözlük tanımlanır.
        workflow_results: Dict[str, Any] = {}

        # 1. Başlangıç çalışma dizini (pwd)
        workflow_results["1_adim_pwd_baslangic"] = self.pwd()

        # 2. Mevcut dizini listeleme (ls)
        workflow_results["2_adim_ls_mevcut"] = self.ls()

        # 3. Dizin değiştirme (cd /var/log)
        workflow_results["3_adim_cd_hedef"] = self.cd("/var/log")

        # 4. Yeni dizini doğrulama (pwd)
        workflow_results["4_adim_pwd_yeni"] = self.pwd()

        # 5. Log dosyasının ilk satırlarını okuma (head auth.log -n 3)
        workflow_results["5_adim_head_log"] = self.head("auth.log", n=3)

        # 6. Dosyanın tam içeriğini okuma (cat /home/analyst/notes.txt)
        workflow_results["6_adim_cat_notes"] = self.cat("/home/analyst/notes.txt")

        # 7. Sistem yapılandırmasını inceleme (head /etc/passwd -n 2)
        workflow_results["7_adim_head_passwd"] = self.head("/etc/passwd", n=2)

        # Tamamlanan iş akışı döndürülür.
        return workflow_results


def main() -> None:
    """Komut satırı arayüzünü (CLI) yönetir."""
    # Windows konsolunda UTF-8 çıktı desteği garanti altına alınır.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # Argümanlar taranır.
    args = sys.argv[1:]

    # Dosya yolları için değişkenler tanımlanır.
    fs_path = None
    # Kurallar dosyası yolu tanımlanır.
    rules_path = None
    # JSON çıktı bayrağı tanımlanır.
    json_mode = "--json" in args
    # Laboratuvar iş akışı bayrağı kontrol edilir.
    run_lab = "--lab" in args

    # Argüman döngüsü
    for i in range(len(args)):
        # --filesystem bayrağı
        if args[i] == "--filesystem" and i + 1 < len(args):
            fs_path = args[i + 1]
        # --rules bayrağı
        elif args[i] == "--rules" and i + 1 < len(args):
            rules_path = args[i + 1]

    # Sanal dosya sistemi yüklenir (varsa)
    fs_data = None
    if fs_path and os.path.exists(fs_path):
        with open(fs_path, "r", encoding="utf-8") as fp:
            fs_data = json.load(fp)

    # Kurallar yüklenir (varsa)
    rules_data = None
    if rules_path and os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as fp:
            rules_data = json.load(fp)

    # Simülatör motoru başlatılır.
    sim = LinuxShellSecuritySimulator(fs_data=fs_data, rules_data=rules_data)

    # Laboratuvar modu yürütülür (--lab)
    if run_lab or len(args) == 0:
        lab_results = sim.run_full_lab_workflow()

        # JSON çıktısı istendiyse ekrana basılır.
        if json_mode:
            print(json.dumps(lab_results, indent=2, ensure_ascii=False))
            return

        # Okunabilir terminal çıktısı basılır.
        print("=" * 72)
        print("GÜN 023: LİNUX KABUK VE TERMİNAL GÜVENLİK LABORATUVARI (G023-SC2)")
        print("=" * 72)
        print(f"1. Adım [pwd] Başlangıç Çalışma Dizini : {lab_results['1_adim_pwd_baslangic']}")
        print(f"2. Adım [ls]  Mevcut Dizin İçeriği     : {len(lab_results['2_adim_ls_mevcut'])} öğe listelendi")
        for item in lab_results['2_adim_ls_mevcut']:
            print(f"       -> [{item['tur']}] {item['isim']} ({item['izin']}, Sahip: {item['sahip']})")
        print(f"3. Adım [cd]  Hedefe Geçiş             : {lab_results['3_adim_cd_hedef']}")
        print(f"4. Adım [pwd] Yeni Çalışma Dizini      : {lab_results['4_adim_pwd_yeni']}")
        print("-" * 72)
        print("5. Adım [head] auth.log İlk 3 Satırı:")
        for line in lab_results['5_adim_head_log'].splitlines():
            print(f"   | {line}")
        print("-" * 72)
        print("6. Adım [cat] Güvenlik Notları:")
        for line in lab_results['6_adim_cat_notes'].splitlines():
            print(f"   | {line}")
        print("-" * 72)
        print("7. Adım [head] /etc/passwd İlk 2 Satırı:")
        for line in lab_results['7_adim_head_passwd'].splitlines():
            print(f"   | {line}")
        print("=" * 72)
        print("POSIX Standart Komutları ve Yol Güvenliği Başarıyla Doğrulandı.")
        print("=" * 72)


# Doğrudan modül yürütme kontrolü
if __name__ == "__main__":
    main()
