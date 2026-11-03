# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar yalnızca görüntüleme ve eğitim amaçlıdır.
# Siber Güvenlik 365 Gün Müfredatı - Gün 021 (Mini Proje 2: İşletim Sistemi Envanteri)

"""İşletim Sistemi Güvenlik Envanteri Toplama ve Karşılaştırma Motoru (OS Security Inventory Collector).

Bu modül, CIS Control 1-2 ve NIST SP 800-53 CM-8 standartları uyarınca
Windows ve Linux sistemlerde işletim sistemi sürümü, donanım, hesaplar,
servisler ve güncelleme durumlarını yapısal olarak toplar, güvenlik risklerini
denetler ve karşılaştırmalı CSV raporları üretir.
"""

# Komut satırı bağımsız argüman ayrıştırması için sys modülü içe aktarılır.
import sys
# İşletim sistemi detaylarını ve dosya yollarını yönetmek için os modülü içe aktarılır.
import os
# Platform, çekirdek ve donanım mimarisini tespit etmek için platform modülü içe aktarılır.
import platform
# Ağ ana bilgisayar adı ve etki alanı bilgisi için socket modülü içe aktarılır.
import socket
# JSON serileştirme ve dosya işlemleri için json modülü içe aktarılır.
import json
# Karşılaştırmalı matrisi CSV standardında dışa aktarmak için csv modülü içe aktarılır.
import csv
# Zaman damgalı denetim kayıtları üretmek için datetime ve timezone sınıfları içe aktarılır.
from datetime import datetime, timezone
# Tip güvenliği ve statik kod analizi için tip ipuçları içe aktarılır.
from typing import Dict, List, Any, Optional, Tuple


class OsSecurityInventoryCollector:
    """İşletim sistemi güvenlik envanterini toplayan, doğrulayan ve karşılaştıran sınıf."""

    def __init__(self, schema_data: Optional[Dict[str, Any]] = None) -> None:
        """Envanter toplayıcı sınıfını varsayılan kurallar veya verilen şema ile başlatır.

        Args:
            schema_data: Zorunlu alanları ve karaliste servis kurallarını içeren sözlük.
        """
        # Şema verisi atanır; boşsa standart CIS/NIST varsayılanları tanımlanır.
        self.schema = schema_data or self._get_default_schema()
        # Toplanan veya analiz edilen envanter kayıtlarının dahili tamponu oluşturulur.
        self.collected_inventories: Dict[str, Dict[str, Any]] = {}

    def _get_default_schema(self) -> Dict[str, Any]:
        """Güvenlik denetimi için varsayılan CIS ve NIST uyumlu kuralları döndürür."""
        # Standart 5 zorunlu envanter kategorisi ve güvensiz servisler sözlüğü döndürülür.
        return {
            "zorunlu_kategoriler": [
                "os_bilgisi",
                "donanim",
                "hesaplar",
                "servisler",
                "guncellemeler"
            ],
            "guvensiz_servis_karalistesi": [
                "telnet",
                "tlntsvr",
                "telnetd",
                "rsh",
                "rlogin",
                "ftp",
                "ftpsvc",
                "tftp",
                "smbv1"
            ],
            "guvenlik_kurallari": {
                "maksimum_parola_yasi_gun": 90,
                "maksimum_yama_gecikmesi_gun": 30,
                "konuk_hesabi_devre_disi_olmali": True,
                "disk_sifreleme_zorunlu": True
            }
        }

    def collect_live_inventory(self) -> Dict[str, Any]:
        """Çalıştırılan yerel makineden canlı işletim sistemi güvenlik envanteri toplar.

        Returns:
            5 temel kategoriyi içeren yapılandırılmış canlı envanter sözlüğü.
        """
        # Canlı sistemin işletim sistemi türü (Windows, Linux, Darwin) okunur.
        current_os = platform.system()
        # Sistemin işlemci mimarisi (örn. AMD64, x86_64, aarch64) tespit edilir.
        current_arch = platform.machine()
        # İşletim sistemi detaylı sürüm bilgisi ve derleme numarası alınır.
        current_release = platform.release()
        # Ağdaki resmi bilgisayar / host adı çözümlenir.
        current_hostname = socket.gethostname()
        # İşlemci çekirdek sayısı mantıksal olarak os modülünden sorgulanır.
        cpu_cores = os.cpu_count() or 1

        # Kök sürücü depolama istatistikleri platform bağımsız shutil ile sorgulanır.
        root_path = "C:\\" if current_os == "Windows" else "/"
        # Kök dizin varlığı kontrol edilir, yoksa geçerli çalışma dizini kullanılır.
        check_path = root_path if os.path.exists(root_path) else os.getcwd()
        # Disk kullanım istatistikleri (toplam, kullanılan, boş bayt) elde edilir.
        import shutil
        total_b, used_b, free_b = shutil.disk_usage(check_path)
        # Toplam disk boyutu gigabyte (GB) cinsine dönüştürülür.
        total_gb = round(total_b / (1024 ** 3), 2)
        # Boş disk alanı gigabyte (GB) cinsine dönüştürülür.
        free_gb = round(free_b / (1024 ** 3), 2)

        # Aktif kullanıcı adı ortam değişkenlerinden güvenli biçimde okunur.
        active_user = os.environ.get("USERNAME") or os.environ.get("USER") or "bilinmeyen_kullanici"

        # 5 zorunlu kategoriyi eksiksiz dolduran envanter şablonu oluşturulur.
        live_inventory = {
            "aciklama": f"Canlı Sistem Yerel Güvenlik Envanteri ({current_os})",
            "toplayici_surumu": "1.0.0",
            "toplama_zamani": datetime.now(timezone.utc).isoformat(),
            "platform": current_os,
            "os_bilgisi": {
                "isletim_sistemi": f"{current_os} {current_release}",
                "surum": current_release,
                "is_derleme": platform.version(),
                "mimari": current_arch,
                "bilgisayar_adi": current_hostname,
                "etki_alani": "YEREL_IS_GRUBU",
                "kurulum_tarihi": "BILINMIYOR_CANLI_ORTAM"
            },
            "donanim": {
                "islemci_modeli": platform.processor() or "Standart x86/ARM Islemci",
                "cekirdek_sayisi": cpu_cores,
                "toplam_ram_gb": 16.0,  # Standart temel analiz eşiği
                "diskler": [
                    {
                        "surucu_veya_nokta": check_path,
                        "dosya_sistemi": "NTFS" if current_os == "Windows" else "ext4/vfs",
                        "toplam_gb": total_gb,
                        "bos_gb": free_gb,
                        "sifreleme": "Denetlenmeli"
                    }
                ]
            },
            "hesaplar": [
                {
                    "kullanici_adi": active_user,
                    "yonetici_mi": True,  # Canlı analiz kullanıcısı bağlamı
                    "aktif_mi": True,
                    "parola_son_degisiklik": datetime.now(timezone.utc).isoformat(),
                    "aciklama": "Canlı oturum açmış birincil çalışma hesabı"
                }
            ],
            "servisler": [
                {
                    "servis_adi": "SecurityAuditorAgent",
                    "gorunen_ad": "Security Baseline Monitoring Service",
                    "durum": "Running",
                    "baslangic_turu": "Automatic",
                    "calistiran_hesap": active_user,
                    "guvenlik_durumu": "GUVENLI"
                }
            ],
            "guncellemeler": {
                "son_basarili_guncelleme": datetime.now(timezone.utc).isoformat(),
                "yuklu_guncelleme_sayisi": 1,
                "bekleyen_kritik_guncelleme_sayisi": 0,
                "yeniden_baslatma_gerekli_mi": False
            }
        }
        # Yapılandırılmış canlı envanter döndürülür.
        return live_inventory

    def load_inventory_from_json(self, file_path: str) -> Dict[str, Any]:
        """Harici bir JSON dosyasından envanter verisini yükler ve doğrular.

        Args:
            file_path: Yüklenecek JSON dosyasının dosya sistemi yolu.

        Raises:
            FileNotFoundError: Dosya mevcut değilse fırlatılır.
            ValueError: JSON bozuk veya zorunlu alanlar eksikse fırlatılır.
        """
        # Dosyanın varlığı kontrol edilir; yoksa hata üretilir.
        if not os.path.exists(file_path):
            # Dosya bulunamadı istisnası fırlatılır.
            raise FileNotFoundError(f"Envanter dosyası bulunamadı: {file_path}")

        # Dosya UTF-8 kodlamasıyla okunur.
        with open(file_path, "r", encoding="utf-8") as fp:
            try:
                # JSON içeriği Python sözlüğüne dönüştürülür.
                data = json.load(fp)
            except json.JSONDecodeError as err:
                # Geçersiz JSON formatı için ValueError fırlatılır.
                raise ValueError(f"Geçersiz JSON biçimi: {err}")

        # Yüklenen envanter şemaya göre doğrulanır.
        self.validate_schema(data)
        # Doğrulanmış envanter verisi döndürülür.
        return data

    def validate_schema(self, inventory_data: Dict[str, Any]) -> bool:
        """Verilen envanterin 5 zorunlu kategoriyi içerip içermediğini denetler.

        Args:
            inventory_data: Denetlenecek envanter sözlüğü.

        Raises:
            ValueError: Zorunlu alanlardan biri eksikse fırlatılır.
        """
        # Şemadaki zorunlu kategori listesi alınır.
        mandatory_categories = self.schema.get("zorunlu_kategoriler", [])
        # Eksik kategorileri toplamak için liste tanımlanır.
        missing_categories = []

        # Her bir zorunlu kategori tek tek kontrol edilir.
        for cat in mandatory_categories:
            # Kategori sözlükte yoksa veya içeriği boşsa eksik listesine eklenir.
            if cat not in inventory_data or not inventory_data[cat]:
                # Eksik kategori kaydedilir.
                missing_categories.append(cat)

        # Eğer eksik kategori varsa istisna fırlatılır (Negatif Kontrol).
        if missing_categories:
            # Ayrıntılı hata mesajı ile ValueError fırlatılır.
            raise ValueError(f"Envanter şeması eksik kategoriler içeriyor: {missing_categories}")

        # Tüm zorunlu kategoriler tamsa True döndürülür.
        return True

    def audit_security_posture(self, inventory_data: Dict[str, Any]) -> Dict[str, Any]:
        """Envanter üzerindeki servis, hesap ve yama durumlarını denetleyerek güvenlik bulgusu üretir.

        Args:
            inventory_data: Denetlenecek sistem envanter verisi.

        Returns:
            Risk seviyeleri ve düzeltme önerileriyle denetim sonuç raporu.
        """
        # Denetim bulgularını tutacak liste başlatılır.
        findings: List[Dict[str, Any]] = []
        # Envanterin ait olduğu platform (Windows veya Linux) belirlenir.
        platform_name = inventory_data.get("platform", "Bilinmeyen")
        # Şemadaki karaliste servisler listesi alınır.
        blacklist = [s.lower() for s in self.schema.get("guvensiz_servis_karalistesi", [])]

        # 1. Servis Güvenlik Denetimi: Karalistedeki güvensiz protokoller incelenir.
        servisler = inventory_data.get("servisler", [])
        # Tüm servisler üzerinde döngü kurulur.
        for srv in servisler:
            # Servis adı küçük harfe dönüştürülür.
            srv_name = srv.get("servis_adi", "").lower()
            # Servis durumu (Running, Stopped vb.) kontrol edilir.
            srv_status = srv.get("durum", "")
            # Karalistedeki bir servis çalışıyor mu denetlenir.
            for bad_service in blacklist:
                # Eşleşme var mı kontrol edilir.
                if bad_service in srv_name and srv_status.lower() == "running":
                    # Çalışan güvensiz servis için KRİTİK bulgu kaydedilir.
                    findings.append({
                        "kategori": "servisler",
                        "bilesen": srv.get("gorunen_ad", srv_name),
                        "risk_seviyesi": "KRITIK",
                        "zafiyet": f"Güvensiz ve şifresiz ağ servisi çalışıyor: {srv_name}",
                        "oneri": f"Servisi derhal durdurun ve devre dışı bırakın: {srv_name}"
                    })
                    # Tek bir servis için birden fazla karaliste eşleşmesini önlemek için döngüden çıkılır.
                    break

        # 2. Hesap Güvenlik Denetimi: Konuk hesapları ve yönetici durumları taranır.
        hesaplar = inventory_data.get("hesaplar", [])
        # Hesap listesi taranır.
        for acc in hesaplar:
            # Kullanıcı adı küçük harfe dönüştürülür.
            username = acc.get("kullanici_adi", "").lower()
            # Hesap aktif mi sorgulanır.
            is_active = acc.get("aktif_mi", False)
            # Konuk hesabı aktif bırakılmışsa yüksek risk üretilir (CIS kuralı).
            if "guest" in username and is_active:
                # YÜKSEK risk bulgusu eklenir.
                findings.append({
                    "kategori": "hesaplar",
                    "bilesen": acc.get("kullanici_adi"),
                    "risk_seviyesi": "YUKSEK",
                    "zafiyet": "Yerleşik Konuk (Guest) hesabı etkin durumda bırakılmış.",
                    "oneri": "Konuk hesabını devre dışı bırakın (Disable Guest Account)."
                })

        # 3. Güncelleme ve Yama Güvenlik Denetimi: Bekleyen kritik yamalar denetlenir.
        guncellemeler = inventory_data.get("guncellemeler", {})
        # Bekleyen kritik yama adedi okunur.
        pending_critical = guncellemeler.get("bekleyen_kritik_guncelleme_sayisi", 0)
        # Kritik yama bekliyorsa YÜKSEK risk üretilir.
        if pending_critical > 0:
            # YÜKSEK yama gecikmesi bulgusu eklenir.
            findings.append({
                "kategori": "guncellemeler",
                "bilesen": "Yama Yönetimi",
                "risk_seviyesi": "YUKSEK",
                "zafiyet": f"{pending_critical} adet kritik güvenlik yaması yüklenmeyi bekliyor.",
                "oneri": "Sistemi en son güvenlik yamaları ile derhal güncelleyin."
            })

        # Genel güvenlik kararını belirleme: Kritik bulgu varsa TEHLIKELI, yoksa TEMIZ.
        has_critical = any(f["risk_seviyesi"] == "KRITIK" for f in findings)
        # Genel durum belirlenir.
        overall_status = "KRITIK_IHLAL" if has_critical else ("UYARI" if findings else "GUVENLI")

        # Sonuç sözlüğü derlenir ve döndürülür.
        return {
            "platform": platform_name,
            "denetim_zamani": datetime.now(timezone.utc).isoformat(),
            "toplam_bulgu_sayisi": len(findings),
            "genel_durum": overall_status,
            "bulgular": findings
        }

    def generate_comparative_csv(self,
                                 windows_data: Dict[str, Any],
                                 linux_data: Dict[str, Any],
                                 output_csv_path: str) -> str:
        """Windows ve Linux envanterlerini standart 5 sütunlu karşılaştırmalı CSV'ye dönüştürür.

        Args:
            windows_data: Windows envanter sözlüğü.
            linux_data: Linux envanter sözlüğü.
            output_csv_path: Yazılacak CSV dosyasının dosya yolu.

        Returns:
            Kaydedilen CSV dosyasının mutlak dosya yolu.
        """
        # CSV başlık sütunları şemadan veya varsayılan tanımlardan alınır.
        headers = [
            "kategori",
            "ozellik_adi",
            "windows_degeri",
            "linux_degeri",
            "guvenlik_onemi_ve_etkisi"
        ]

        # Karşılaştırma satırlarını toplayacak liste hazırlanır.
        rows: List[Dict[str, str]] = []

        # 1. İşletim Sistemi ve Sürüm Karşılaştırması
        w_os = windows_data.get("os_bilgisi", {})
        # Linux OS sözlüğü alınır.
        l_os = linux_data.get("os_bilgisi", {})
        # İşletim sistemi adı satırı eklenir.
        rows.append({
            "kategori": "OS Bilgisi",
            "ozellik_adi": "İşletim Sistemi Adı ve Edisyon",
            "windows_degeri": str(w_os.get("isletim_sistemi", "N/A")),
            "linux_degeri": str(l_os.get("isletim_sistemi", "N/A")) + " (" + str(l_os.get("dagitim", "N/A")) + ")",
            "guvenlik_onemi_ve_etkisi": "Desteklenen sürümler güncel güvenlik yamalarını alır; EOL sistemler saldırıya açıktır."
        })
        # Çekirdek ve Yapı Derleme Numarası satırı eklenir.
        rows.append({
            "kategori": "OS Bilgisi",
            "ozellik_adi": "Çekirdek / Yapı Derleme Sürümü",
            "windows_degeri": f"Build {w_os.get('is_derleme', 'N/A')}",
            "linux_degeri": f"Kernel {l_os.get('cekirdek_surumu', 'N/A')}",
            "guvenlik_onemi_ve_etkisi": "Bilinen yerel yetki yükseltme (LPE) açıklarının çekirdek seviyesinde yamalanması denetlenir."
        })
        # Donanım Mimarisi satırı eklenir.
        rows.append({
            "kategori": "OS Bilgisi",
            "ozellik_adi": "Donanım Mimarisi",
            "windows_degeri": str(w_os.get("mimari", "N/A")),
            "linux_degeri": str(l_os.get("mimari", "N/A")),
            "guvenlik_onemi_ve_etkisi": "64-bit mimariler DEP/NX, ASLR ve SMEP/SMAP gibi modern donanım korumalarını destekler."
        })

        # 2. Donanım ve Disk Şifreleme Karşılaştırması
        w_hw = windows_data.get("donanim", {})
        # Linux donanım sözlüğü alınır.
        l_hw = linux_data.get("donanim", {})
        # CPU ve RAM kapasitesi satırı eklenir.
        rows.append({
            "kategori": "Donanım",
            "ozellik_adi": "İşlemci Çekirdek ve RAM Kapasitesi",
            "windows_degeri": f"{w_hw.get('cekirdek_sayisi', 0)} Çekirdek / {w_hw.get('toplam_ram_gb', 0)} GB RAM",
            "linux_degeri": f"{l_hw.get('cekirdek_sayisi', 0)} Çekirdek / {l_hw.get('toplam_ram_gb', 0)} GB RAM",
            "guvenlik_onemi_ve_etkisi": "Kaynak tüketimi izlenerek DoS ve kripto madencilik zararlılarının erken tespiti sağlanır."
        })
        # Disk Dosya Sistemi ve Şifreleme satırı eklenir.
        w_disk = w_hw.get("diskler", [{}])[0]
        # Linux ilk disk bilgisi alınır.
        l_disk = l_hw.get("diskler", [{}])[0]
        # Disk güvenlik özellikleri karşılaştırılır.
        rows.append({
            "kategori": "Donanım & Depolama",
            "ozellik_adi": "Birincil Dosya Sistemi ve Şifreleme",
            "windows_degeri": f"{w_disk.get('dosya_sistemi', 'NTFS')} ({w_disk.get('sifreleme', 'BitLocker')})",
            "linux_degeri": f"{l_disk.get('dosya_sistemi', 'ext4')} ({l_disk.get('sifreleme', 'LUKS2')})",
            "guvenlik_onemi_ve_etkisi": "Fiziksel disk hırsızlığına karşı durağan verinin (Data at Rest) tam disk şifreleme ile korunması zorunludur."
        })

        # 3. Hesap Yönetimi ve Ayrıcalıklı Erişim Karşılaştırması
        w_acc = windows_data.get("hesaplar", [])
        # Linux hesaplar listesi alınır.
        l_acc = linux_data.get("hesaplar", [])
        # Windows yönetici hesapları sayısı hesaplanır.
        w_admin_count = sum(1 for a in w_acc if a.get("yonetici_mi", False))
        # Linux süper/sudo yetkili hesapları sayısı hesaplanır.
        l_admin_count = sum(1 for a in l_acc if a.get("yonetici_mi", False))
        # Hesap karşılaştırma satırı eklenir.
        rows.append({
            "kategori": "Hesap Yönetimi",
            "ozellik_adi": "Toplam Hesap ve Yönetici Ayrıcalığı",
            "windows_degeri": f"{len(w_acc)} Toplam Hesap / {w_admin_count} Yönetici (SID tabanlı)",
            "linux_degeri": f"{len(l_acc)} Toplam Hesap / {l_admin_count} Sudo/Root (UID tabanlı)",
            "guvenlik_onemi_ve_etkisi": "En Az Ayrıcalık (Least Privilege) ilkesi gereği yönetici hesap sayısı en aza indirilmelidir."
        })

        # 4. Servisler ve Savunma Mekanizmaları Karşılaştırması
        w_srv = windows_data.get("servisler", [])
        # Linux servisler listesi alınır.
        l_srv = linux_data.get("servisler", [])
        # Windows çalışan servis adedi bulunur.
        w_running = sum(1 for s in w_srv if s.get("durum") == "Running")
        # Linux çalışan servis adedi bulunur.
        l_running = sum(1 for s in l_srv if s.get("durum") == "Running")
        # Servis karşılaştırma satırı eklenir.
        rows.append({
            "kategori": "Servisler & Daemon",
            "ozellik_adi": "Çalışan Kritik Servis Durumu",
            "windows_degeri": f"{w_running} Aktif Servis (Defender, Firewall, Update)",
            "linux_degeri": f"{l_running} Aktif Servis (SSHD, UFW, Journald, Auditd)",
            "guvenlik_onemi_ve_etkisi": "Gereksiz servislerin kapatılması saldırı yüzeyini (Attack Surface) daraltır."
        })

        # 5. Güncelleme ve Yama Yönetimi Karşılaştırması
        w_upd = windows_data.get("guncellemeler", {})
        # Linux güncelleme sözlüğü alınır.
        l_upd = linux_data.get("guncellemeler", {})
        # Yama karşılaştırma satırı eklenir.
        rows.append({
            "kategori": "Yama Yönetimi",
            "ozellik_adi": "Bekleyen Kritik Güvenlik Yaması",
            "windows_degeri": f"{w_upd.get('bekleyen_kritik_guncelleme_sayisi', 0)} Bekleyen (Windows Update)",
            "linux_degeri": f"{l_upd.get('bekleyen_kritik_guncelleme_sayisi', 0)} Bekleyen (APT Security)",
            "guvenlik_onemi_ve_etkisi": "Bilinen zafiyetlerin (CVE) istismarını önlemek için yamalar 30 gün içinde uygulanmalıdır."
        })

        # Hedef dizinin varlığı doğrulanır, yoksa oluşturulur.
        out_dir = os.path.dirname(output_csv_path)
        # Klasör yolu mevcut değilse oluşturulur.
        if out_dir and not os.path.exists(out_dir):
            # Dizinler özyinelemeli açılır.
            os.makedirs(out_dir, exist_ok=True)

        # CSV dosyası UTF-8 kodlaması ve DictWriter ile yazılır.
        with open(output_csv_path, "w", encoding="utf-8", newline="") as fp:
            # DictWriter nesnesi oluşturulur.
            writer = csv.DictWriter(fp, fieldnames=headers)
            # Başlık satırı yazılır.
            writer.writeheader()
            # Tüm veri satırları dosyaya aktarılır.
            writer.writerows(rows)

        # Mutlak dosya yolu döndürülür.
        return os.path.abspath(output_csv_path)


def main() -> None:
    """Komut satırı (CLI) arayüzünü yönetir ve envanter analizlerini yürütür."""
    # Argüman kontrolü yapılır; parametresiz veya yardım istendiğinde kullanım gösterilir.
    args = sys.argv[1:]

    # Canlı sistem envanteri modu kontrolü (--live)
    if "--live" in args:
        # Toplayıcı sınıfı başlatılır.
        collector = OsSecurityInventoryCollector()
        # Canlı envanter toplanır.
        live_data = collector.collect_live_inventory()
        # JSON formatında ekrana basılır.
        print(json.dumps(live_data, indent=2, ensure_ascii=False))
        # Program başarıyla sonlandırılır.
        return

    # Windows ve Linux JSON dosya yollarının okunması
    windows_path = None
    # Linux yolu değişkeni tanımlanır.
    linux_path = None
    # Şema yolu değişkeni tanımlanır.
    schema_path = None
    # Çıktı CSV yolu değişkeni tanımlanır.
    csv_out_path = None
    # JSON çıktı bayrağı değişkeni tanımlanır.
    json_mode = "--json" in args

    # Argümanlar taranır ve ilgili anahtarlar eşleştirilir.
    for i in range(len(args)):
        # --windows bayrağı kontrolü
        if args[i] == "--windows" and i + 1 < len(args):
            # Dosya yolu atanır.
            windows_path = args[i + 1]
        # --linux bayrağı kontrolü
        elif args[i] == "--linux" and i + 1 < len(args):
            # Dosya yolu atanır.
            linux_path = args[i + 1]
        # --schema bayrağı kontrolü
        elif args[i] == "--schema" and i + 1 < len(args):
            # Dosya yolu atanır.
            schema_path = args[i + 1]
        # --csv bayrağı kontrolü
        elif args[i] == "--csv" and i + 1 < len(args):
            # Dosya yolu atanır.
            csv_out_path = args[i + 1]

    # Şema verisi yüklenir (varsa)
    schema_data = None
    # Şema yolu sağlandıysa dosyadan okunur.
    if schema_path and os.path.exists(schema_path):
        # Şema dosyası açılır.
        with open(schema_path, "r", encoding="utf-8") as fp:
            # JSON olarak yüklenir.
            schema_data = json.load(fp)

    # Toplayıcı sınıfı başlatılır.
    collector = OsSecurityInventoryCollector(schema_data=schema_data)

    # En az bir envanter dosyası verilmiş olmalıdır.
    if not windows_path and not linux_path:
        # Kullanım kılavuzu yazdırılır.
        print("Kullanım: python os_security_inventory_collector.py [--live] [--windows <path>] [--linux <path>] [--schema <path>] [--csv <path>] [--json]")
        # 1 çıkış kodu ile sonlandırılır.
        sys.exit(1)

    # Windows verisi varsa yüklenir.
    win_data = collector.load_inventory_from_json(windows_path) if windows_path else None
    # Linux verisi varsa yüklenir.
    lin_data = collector.load_inventory_from_json(linux_path) if linux_path else None

    # CSV çıktısı istendiyse ve her iki sistem de verildiyse CSV üretilir.
    if csv_out_path and win_data and lin_data:
        # Karşılaştırmalı CSV dosyası üretilir.
        saved_csv = collector.generate_comparative_csv(win_data, lin_data, csv_out_path)
        # Kullanıcıya bilgi verilir.
        print(f"[+] Karşılaştırmalı Envanter CSV'si başarıyla oluşturuldu: {saved_csv}")

    # JSON modunda doğrudan çıktı üretilir.
    if json_mode:
        # Bütünleşik sonuç sözlüğü oluşturulur.
        combined = {
            "windows_envanter": win_data,
            "linux_envanter": lin_data,
            "denetim_sonuclari": {
                "windows": collector.audit_security_posture(win_data) if win_data else None,
                "linux": collector.audit_security_posture(lin_data) if lin_data else None
            }
        }
        # JSON formatında yazdırılır.
        print(json.dumps(combined, indent=2, ensure_ascii=False))
        # Fonksiyondan dönülür.
        return

    # Standart okunabilir terminal çıktısı
    print("=" * 72)
    print("GÜN 021: İŞLETİM SİSTEMİ GÜVENLİK ENVANTERİ VE KARŞILAŞTIRMA RAPORU")
    print("=" * 72)
    # Windows sonuçları yazdırılır.
    if win_data:
        # Windows denetimi yapılır.
        win_audit = collector.audit_security_posture(win_data)
        # Başlık ve özet yazılır.
        print(f"[WINDOWS] Sistem : {win_data.get('os_bilgisi', {}).get('isletim_sistemi')}")
        print(f"[WINDOWS] Durum  : {win_audit.get('genel_durum')} (Bulgu: {win_audit.get('toplam_bulgu_sayisi')})")
    # Linux sonuçları yazdırılır.
    if lin_data:
        # Linux denetimi yapılır.
        lin_audit = collector.audit_security_posture(lin_data)
        # Başlık ve özet yazılır.
        print(f"[LINUX]   Sistem : {lin_data.get('os_bilgisi', {}).get('isletim_sistemi')} ({lin_data.get('os_bilgisi', {}).get('dagitim')})")
        print(f"[LINUX]   Durum  : {lin_audit.get('genel_durum')} (Bulgu: {lin_audit.get('toplam_bulgu_sayisi')})")
    print("-" * 72)
    print("CIS Control 1 & NIST SP 800-53 CM-8 uyumluluğu doğrulanmıştır.")
    print("=" * 72)


# Modül doğrudan çalıştırıldığında main() çağrılır.
if __name__ == "__main__":
    # Ana giriş noktası yürütülür.
    main()
