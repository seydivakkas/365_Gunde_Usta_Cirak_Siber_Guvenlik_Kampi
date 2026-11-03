# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 009: Windows Üzerinde Laboratuvar Hazırlığı
Uygulama: Windows Güvenlik Laboratuvarı Kurulum ve Doğrulama Motoru (Windows Lab Provisioner)

Bu araç; Windows 11/10 ortamında siber güvenlik laboratuvarı kurulurken:
1. Windows Sandbox (.wsb) izolasyon ve dosya eşleme kurallarını,
2. Hyper-V Sanal Anahtar (vSwitch: Private/Internal vs External) ağ sınırlarını,
3. Windows Defender Antivirüs Dışlama (Exclusion Hijacking) zafiyetlerini,
4. Sanallaştırma Tabanlı Güvenlik (VBS / HVCI) ve WSL2 kalkanlarını
BSI/CIS ve Microsoft Security Baseline standartlarında denetler ve güvenli .wsb profilleri üretir.
"""

# Temel sistem ve veri işleme kütüphaneleri içe aktarılıyor
import os
import sys
import json
import argparse
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Tuple


class WindowsLabValidationError(Exception):
    """
    Windows laboratuvar yapılandırma dosyası şema, veri tipi veya
    güvenlik sınır kurallarına uymadığında fırlatılan özel hata sınıfı.
    """
    pass


class WindowsLabProvisioner:
    """
    Windows Güvenlik Laboratuvarı Kurulum, Denetim ve Güvenli Profil Üretim Motoru.
    """

    # Windows Defender dışlamalarında asla izin verilmeyecek tehlikeli kök dizinler listesi
    YASAKLI_DEFENDER_DISLAMA_YOLLARI = [
        "c:\\", "c:/", "c:\\users", "c:/users", "c:\\users\\",
        "c:\\windows", "c:/windows", "c:\\windows\\temp", "%temp%",
        "c:\\temp", "c:/temp", "c:\\programdata", "c:/programdata"
    ]

    def __init__(self, yapilandirma_dosya_yolu: str):
        """
        Denetleyici sınıf başlatıcısı.
        
        Args:
            yapilandirma_dosya_yolu: İncelenecek Windows laboratuvar yapılandırma JSON dosyası.
        """
        # Dosya yolunu sınıf değişkeni olarak kaydet
        self.dosya_yolu = yapilandirma_dosya_yolu
        # Bellekte tutulacak yapılandırma verisi için başlangıç değeri
        self.yapilandirma_verisi: Dict[str, Any] = {}
        # Dosyayı oku ve sözdizimsel geçerliliği doğrula
        self.yapilandirmayi_yukle()

    def yapilandirmayi_yukle(self) -> None:
        """
        Yapılandırma dosyasını diskten okur ve JSON sözdizimini doğrular.
        """
        # 1. Dosyanın fiziksel varlığını kontrol et
        if not os.path.exists(self.dosya_yolu):
            raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {self.dosya_yolu}")

        # 2. Dosyayı UTF-8 olarak aç ve JSON formatında ayrıştır
        try:
            with open(self.dosya_yolu, "r", encoding="utf-8") as dosya:
                self.yapilandirma_verisi = json.load(dosya)
        except json.JSONDecodeError as json_hatasi:
            raise WindowsLabValidationError(f"Geçersiz JSON sözdizimi: {str(json_hatasi)}")

        # 3. Kök nesnenin geçerliliğini ve 'laboratuvar_profilleri' anahtarını kontrol et
        if not isinstance(self.yapilandirma_verisi, dict) or "laboratuvar_profilleri" not in self.yapilandirma_verisi:
            raise WindowsLabValidationError("Yapılandırma dosyası geçerli bir 'laboratuvar_profilleri' listesi içermelidir.")

        # 4. Profil listesinin dizi tipinde olduğunu kontrol et
        if not isinstance(self.yapilandirma_verisi["laboratuvar_profilleri"], list):
            raise WindowsLabValidationError("'laboratuvar_profilleri' alanı bir dizi (list) olmalıdır.")

    def denetle_laboratuvar_profili(self, lab: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tek bir Windows laboratuvar yapılandırma profilini kapsamlı olarak inceler.
        
        Args:
            lab: İncelenecek laboratuvar profili sözlüğü.
            
        Returns:
            Denetim bulguları, ceza puanları, güvenlik skoru ve nihai karar.
        """
        # Zorunlu alanların mevcudiyetini kontrol et
        self._dogrula_lab_semasi(lab)

        # Bulguları depolamak için dinamik liste
        bulgular: List[Dict[str, Any]] = []

        # 1. Sanallaştırma ve Çekirdek Güvenliği (VBS / HVCI) Denetimi
        bulgular.extend(self._denetle_vbs_ve_sanallastirma(lab))

        # 2. Windows Sandbox İzolasyon ve Dosya Eşleme Denetimi (.wsb)
        bulgular.extend(self._denetle_windows_sandbox(lab))

        # 3. Hyper-V Sanal Anahtar (vSwitch) ve Ağ Yayılma Denetimi
        bulgular.extend(self._denetle_hyper_v_vswitch(lab))

        # 4. Windows Defender Dışlama (Exclusion Hijacking) Güvenlik Denetimi
        bulgular.extend(self._denetle_defender_dislamalari(lab))

        # 5. WSL2 Altyapı ve Konak Dosya Sistemi İzolasyon Denetimi
        bulgular.extend(self._denetle_wsl2_altyapisi(lab))

        # Puanlama ve risk seviyesi tayini
        skor, risk_derecesi = self._hesapla_guvenlik_skoru(bulgular)

        return {
            "lab_id": lab.get("lab_id"),
            "lab_adi": lab.get("lab_adi"),
            "guvenlik_derecesi": lab.get("guvenlik_derecesi"),
            "skor": skor,
            "risk_derecesi": risk_derecesi,
            "toplam_bulgu_sayisi": len(bulgular),
            "bulgular": bulgular
        }

    def _dogrula_lab_semasi(self, lab: Dict[str, Any]) -> None:
        """
        Profil sözlüğünde bulunması gereken zorunlu anahtarları doğrular.
        """
        zorunlu_alanlar = [
            "lab_id", "lab_adi", "hedef_rol", "guvenlik_derecesi",
            "sanallastirma_ve_vbs", "windows_sandbox",
            "hyper_v_ag_anahtarlari", "defender_dislama_politikasi", "wsl2_altyapisi"
        ]
        for alan in zorunlu_alanlar:
            if alan not in lab:
                raise WindowsLabValidationError(f"Laboratuvar profilinde zorunlu '{alan}' alanı eksik!")

    def _denetle_vbs_ve_sanallastirma(self, lab: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Sanallaştırma Tabanlı Güvenlik (VBS) ve Bellek Bütünlüğü (HVCI) durumunu denetler.
        """
        bulgular = []
        vbs_bilgisi = lab.get("sanallastirma_ve_vbs", {})

        # KONTROL 1: Hyper-V Sanallaştırma Altyapısı
        # Hyper-V kapalıysa Windows Sandbox ve WSL2 çalışamaz.
        if not vbs_bilgisi.get("hyper_v_etkin", False):
            bulgular.append({
                "kategori": "CEKIRDEK_SANALLASTIRMA",
                "seviye": "KRITIK",
                "ceza_puani": 35,
                "baslik": "Hyper-V Sanallaştırma Altyapısı Devre Dışı",
                "detay": "Hyper-V etkinleştirilmeden Windows Sandbox ve Tip-1 donanım mikro-izolasyonu çalıştırılamaz.",
                "cozum": "Windows Özellikleri menüsünden veya 'Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All' komutuyla Hyper-V'yi açın."
            })

        # KONTROL 2: VBS (Virtualization-Based Security)
        # VBS, Windows çekirdeğinin kritik parçalarını (LSASS vb.) donanımsal güvenli alana (Trustlet) alır.
        if not vbs_bilgisi.get("vbs_etkin", False):
            bulgular.append({
                "kategori": "CEKIRDEK_SANALLASTIRMA",
                "seviye": "YUKSEK",
                "ceza_puani": 20,
                "baslik": "Sanallaştırma Tabanlı Güvenlik (VBS) Kapalı",
                "detay": "VBS kapalıyken çekirdek bellek alanı doğrudan saldırılara açıktır; Credential Guard gibi korumalar çalışmaz.",
                "cozum": "Grup İlkesi (GPO) veya Çekirdek Yalıtım ayarlarından VBS'i etkinleştirin."
            })

        # KONTROL 3: HVCI (Hypervisor-Protected Code Integrity)
        # HVCI, çekirdek modunda imzasız veya zararlı sürücülerin (BYOVD saldırıları) yüklenmesini engeller.
        if not vbs_bilgisi.get("hvci_etkin", False):
            bulgular.append({
                "kategori": "CEKIRDEK_SANALLASTIRMA",
                "seviye": "ORTA",
                "ceza_puani": 15,
                "baslik": "Bellek Bütünlüğü (HVCI) Koruması Kapalı",
                "detay": "Zararlı bir çekirdek sürücüsü (rootkit) sisteme sızabilir ve Ring 0 yetkisi elde edebilir.",
                "cozum": "Windows Güvenliği -> Cihaz Güvenliği -> Çekirdek Yalıtım -> Bellek Bütünlüğü'nü açın."
            })

        return bulgular

    def _denetle_windows_sandbox(self, lab: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Windows Sandbox (.wsb) yapılandırmasındaki ağ izolasyonu ve dosya eşleme izinlerini denetler.
        """
        bulgular = []
        wsb = lab.get("windows_sandbox", {})
        ag_ayari = wsb.get("networking", "Default")
        vgpu = wsb.get("v_gpu", "Default")
        baglananlar = wsb.get("baglanan_klasorler", [])

        # KONTROL 1: Sandbox Ağ İzolasyonu
        # Sandbox analiz ortamında 'Disable' olmalıdır. 'Default' olursa dış internete ve yerel ağa bağlanır!
        if ag_ayari.lower() != "disable":
            bulgular.append({
                "kategori": "WINDOWS_SANDBOX",
                "seviye": "KRITIK",
                "ceza_puani": 35,
                "baslik": "Windows Sandbox Ağ İzolasyonu Açık Değil (Networking != Disable)",
                "detay": f"Sandbox ağ ayarı '{ag_ayari}' olarak bırakılmış. Zararlı yazılım C2 sunucularına veri sızdırabilir veya yerel ağdaki cihazlara saldırabilir.",
                "cozum": ".wsb yapılandırma dosyasında <Networking>Disable</Networking> tanımlayın."
            })

        # KONTROL 2: Eşlenen Klasörler ve Yazma İzinleri (Mapped Folders)
        for klasor in baglananlar:
            konak = klasor.get("konak_yolu", "").lower()
            salt_okunur = klasor.get("salt_okunur", False)

            # Konak sistemin kök dizini (C:\) veya kullanıcı dizini Sandbox'a bağlanmışsa FELAKET!
            if konak in ["c:\\", "c:/", "c:\\users", "c:/users", "c:\\windows", "c:/windows"]:
                bulgular.append({
                    "kategori": "WINDOWS_SANDBOX",
                    "seviye": "FELAKET",
                    "ceza_puani": 50,
                    "baslik": f"Sandbox'a Kritik Konak Dizini Bağlanmış: {klasor.get('konak_yolu')}",
                    "detay": "Konak işletim sisteminin kritik dizini Sandbox içine taşınmıştır. Fidye yazılımı konak dosyalarını doğrudan şifreleyebilir.",
                    "cozum": "Yalnızca 'C:\\Guvenli_Lab\\Numuneler' gibi izole ve geçici bir klasörü bağlayın."
                })

            # Eğer klasör salt-okunur (ReadOnly) değilse, Sandbox içindeki zararlı konak dosyalarını değiştirebilir!
            if not salt_okunur:
                bulgular.append({
                    "kategori": "WINDOWS_SANDBOX",
                    "seviye": "KRITIK",
                    "ceza_puani": 30,
                    "baslik": f"Sandbox Eşlenen Klasörde Yazma İzni Açık: {klasor.get('konak_yolu')}",
                    "detay": "Sandbox içindeki zararlı yazılım konak klasöründeki dosyaları bozabilir veya konak sisteme zararlı yazabilir.",
                    "cozum": ".wsb dosyasında <ReadOnly>true</ReadOnly> tanımlayın."
                })

        # KONTROL 3: Sanal GPU (vGPU) İzolasyonu
        # Analiz ortamında vGPU zafiyet yüzeyini artırır
        if vgpu.lower() == "enable":
            bulgular.append({
                "kategori": "WINDOWS_SANDBOX",
                "seviye": "DUSUK",
                "ceza_puani": 10,
                "baslik": "Sandbox vGPU Donanım Hızlandırma Açık",
                "detay": "Grafik sürücüsü zafiyetleri üzerinden Sandbox kaçış (escape) riski oluşabilir.",
                "cozum": "<VGpu>Disable</VGpu> olarak ayarlayın."
            })

        return bulgular

    def _denetle_hyper_v_vswitch(self, lab: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hyper-V sanal anahtarlarının (vSwitch) fiziksel ağa yayılma (Lateral Movement) riskini denetler.
        """
        bulgular = []
        anahtarlar = lab.get("hyper_v_ag_anahtarlari", [])

        for vsw in anahtarlar:
            tip = vsw.get("anahtar_tipi", "").lower()
            fiziksel = vsw.get("fiziksel_ag_kartina_bagli", False)
            promisc = vsw.get("promiscuous_mode", "Deny").lower()

            # KONTROL 1: External (Dış / Köprülenmiş) Sanal Anahtar
            # Güvenlik laboratuvarında External vSwitch asla kullanılmamalıdır!
            if tip == "external" or fiziksel is True:
                bulgular.append({
                    "kategori": "HYPER_V_VSWITCH",
                    "seviye": "KRITIK",
                    "ceza_puani": 40,
                    "baslik": f"Tehlikeli External vSwitch Tespit Edildi: {vsw.get('anahtar_adi')}",
                    "detay": "Sanal anahtar doğrudan fiziksel yerel ağ kartına köprülenmiştir. Laboratuvardaki zararlı ağa yayılabilir.",
                    "cozum": "Anahtar tipini 'Internal' veya 'Private' (Hava Boşluklu - AirGapped) yapın."
                })

            # KONTROL 2: Promiscuous Mod İzni
            if promisc in ["allow_all", "allow_vms", "true"]:
                bulgular.append({
                    "kategori": "HYPER_V_VSWITCH",
                    "seviye": "YUKSEK",
                    "ceza_puani": 25,
                    "baslik": f"vSwitch Üzerinde Promiscuous Mod İzinli: {vsw.get('anahtar_adi')}",
                    "detay": "Sanal makineler birbirinin ağ paketlerini koklayabilir (Virtual Network Sniffing).",
                    "cozum": "Promiscuous mod ayarını kesinlikle 'Deny' yapın."
                })

        return bulgular

    def _denetle_defender_dislamalari(self, lab: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Windows Defender antivirüs dışlama listesini denetler (Exclusion Hijacking önleme).
        """
        bulgular = []
        defender = lab.get("defender_dislama_politikasi", {})
        dislananlar = defender.get("dislanan_klasorler", [])
        acl = defender.get("acl_guvenlik_dogrulamasi", {})

        # KONTROL 1: Yasaklı Geniş Dizin Dışlamaları
        for yol in dislananlar:
            temiz_yol = yol.strip().lower()
            if temiz_yol in self.YASAKLI_DEFENDER_DISLAMA_YOLLARI:
                bulgular.append({
                    "kategori": "DEFENDER_EXCLUSION",
                    "seviye": "FELAKET",
                    "ceza_puani": 50,
                    "baslik": f"Ölümcül Defender Dışlaması Tanımlı: {yol}",
                    "detay": f"Kritik işletim sistemi veya kullanıcı dizini ({yol}) virüs taramasından muaf tutulmuştur. Saldırganlar zararlıyı doğrudan buraya yazıp Defender'ı atlatır (Exclusion Hijacking).",
                    "cozum": "Geniş dışlamayı derhal kaldırın. Yalnızca sıkı izinlere sahip 'C:\\Guvenli_Lab\\Araclar' gibi izole bir alt klasörü dışlayın."
                })

        # KONTROL 2: Dışlanan Klasörün Erişim Denetim Listesi (ACL) İzinleri
        # Eğer standart kullanıcılar dışlama klasörüne dosya yazabiliyorsa, saldırgan zararlısını buraya atar!
        if not acl.get("standart_kullanici_yazma_engeli", False):
            bulgular.append({
                "kategori": "DEFENDER_EXCLUSION",
                "seviye": "YUKSEK",
                "ceza_puani": 25,
                "baslik": "Dışlanan Klasörde Standart Kullanıcı Yazma İzni Var",
                "detay": "Yetkisiz veya kısıtlı bir kullanıcı (ya da zararlı betik) taranmayan bu dizine dosya yazabilir ve algılanmadan çalıştırabilir.",
                "cozum": "Klasör ACL ayarlarında sadece 'Administrators' ve 'SYSTEM' gruplarına Tam Yetki (Full Control) verin; 'Users' grubunun yazma iznini kaldırın."
            })

        return bulgular

    def _denetle_wsl2_altyapisi(self, lab: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        WSL2 Linux alt sisteminin yapılandırmasını ve konak Windows diskine erişim modunu denetler.
        """
        bulgular = []
        wsl = lab.get("wsl2_altyapisi", {})
        surum = wsl.get("wsl_surumu", 2)
        mnt_c = wsl.get("mnt_c_erisim_modu", "ReadOnly").lower()

        # KONTROL 1: WSL Sürümü (WSL1 vs WSL2)
        # WSL1 konak Windows çekirdeğini paylaşır (daha zayıf izolasyon), WSL2 bağımsız Hyper-V mikro VM'inde çalışır.
        if surum == 1:
            bulgular.append({
                "kategori": "WSL_IZOLASYONU",
                "seviye": "ORTA",
                "ceza_puani": 15,
                "baslik": "WSL1 Kullanılıyor (Eski Mimari / Paylaşılan Çekirdek)",
                "detay": "WSL1 doğrudan konak çekirdeğiyle sistem çağrısı çevirisi yapar. WSL2 ise Hyper-V tabanlı gerçek Linux çekirdeği ile tam izolasyon sağlar.",
                "cozum": "'wsl --set-version <dagitim> 2' komutuyla WSL2 mimarisine geçiş yapın."
            })

        # KONTROL 2: /mnt/c Otomatik Bağlantısı ve Yazma İzni
        # WSL içinden Windows diski tam yetkiyle (ReadWrite) bağlanmışsa, Linux içindeki zararlı Windows dosyalarını şifreleyebilir.
        if mnt_c in ["full_readwrite", "write", "rw"]:
            bulgular.append({
                "kategori": "WSL_IZOLASYONU",
                "seviye": "ORTA",
                "ceza_puani": 15,
                "baslik": "WSL2 İçinde /mnt/c Sürücüsü Yazma İzniyle Bağlı",
                "detay": "Linux ortamında çalışan bir zararlı veya sızma testi aracı, konak Windows dosya sistemindeki dosyalara doğrudan yazabilir.",
                "cozum": "/etc/wsl.conf dosyasında [automount] options = 'ro' tanımlayarak Windows diskini salt-okunur bağlayın."
            })

        return bulgular

    def _hesapla_guvenlik_skoru(self, bulgular: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Ceza puanlarını düşerek nihai güvenlik skorunu hesaplar.
        """
        toplam_ceza = sum(b.get("ceza_puani", 0) for b in bulgular)
        skor = max(0, 100 - toplam_ceza)

        if skor >= 90:
            risk = "GÜVENLİ (SERTLEŞTİRİLMİŞ LABORATUVAR)"
        elif skor >= 70:
            risk = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        elif skor >= 40:
            risk = "YÜKSEK RİSK (TEHLİKELİ ORTAM)"
        else:
            risk = "KRİTİK FELAKET (ACİL MÜDAHALE GEREKLİ)"

        return skor, risk

    def denetle_tumunu(self) -> List[Dict[str, Any]]:
        """
        Tüm laboratuvar profillerini sırayla denetler.
        """
        sonuclar = []
        for lab in self.yapilandirma_verisi.get("laboratuvar_profilleri", []):
            sonuc = self.denetle_laboratuvar_profili(lab)
            sonuclar.append(sonuc)
        return sonuclar

    def urete_guvenli_wsb_dosyasi(self, lab_id: str, cikis_dizin_yolu: str) -> str:
        """
        Denetlenen laboratuvar profili için BSL-4 seviyesinde tam izole Windows Sandbox (.wsb) XML dosyası üretir.
        
        Args:
            lab_id: Hedef laboratuvar ID'si.
            cikis_dizin_yolu: Üretilen .wsb dosyasının kaydedileceği klasör.
            
        Returns:
            Üretilen .wsb dosyasının tam dosya yolu.
        """
        # Belirtilen lab_id'ye sahip profili bul
        hedef_lab = None
        for lab in self.yapilandirma_verisi.get("laboratuvar_profilleri", []):
            if lab.get("lab_id") == lab_id:
                hedef_lab = lab
                break

        if not hedef_lab:
            raise WindowsLabValidationError(f"Laboratuvar profili bulunamadı: {lab_id}")

        wsb_ayarlari = hedef_lab.get("windows_sandbox", {})
        dosya_adi = wsb_ayarlari.get("profil_adi", f"{lab_id}.wsb")
        tam_yol = os.path.join(cikis_dizin_yolu, dosya_adi)

        # XML kök düğümünü oluştur
        kok = ET.Element("Configuration")

        # 1. vGPU ayarı
        vgpu = ET.SubElement(kok, "VGpu")
        vgpu.text = wsb_ayarlari.get("v_gpu", "Disable")

        # 2. Ağ İzolasyonu (Networking) - Güvenli standart: Disable
        ag = ET.SubElement(kok, "Networking")
        ag.text = wsb_ayarlari.get("networking", "Disable")

        # 3. Eşlenen Klasörler (MappedFolders)
        baglananlar = wsb_ayarlari.get("baglanan_klasorler", [])
        if baglananlar:
            eslenen_klasorler = ET.SubElement(kok, "MappedFolders")
            for k in baglananlar:
                tek_klasor = ET.SubElement(eslenen_klasorler, "MappedFolder")
                konak_yol = ET.SubElement(tek_klasor, "HostFolder")
                konak_yol.text = k.get("konak_yolu", "")
                salt = ET.SubElement(tek_klasor, "ReadOnly")
                salt.text = "true" if k.get("salt_okunur", True) else "false"

        # 4. Bellek Sınırı (MemoryInMB)
        bellek = ET.SubElement(kok, "MemoryInMB")
        bellek.text = str(wsb_ayarlari.get("bellek_siniri_mb", 4096))

        # XML ağacını biçimlendir ve dosyaya kaydet
        agac = ET.ElementTree(kok)
        ET.indent(agac, space="  ", level=0)
        agac.write(tam_yol, encoding="utf-8", xml_declaration=True)

        return tam_yol

    def rapor_olustur_metin(self, sonuclar: List[Dict[str, Any]]) -> str:
        """
        Denetim sonuçlarını terminalde insan tarafından okunabilir zengin rapor formatında biçimlendirir.
        """
        satirlar = []
        satirlar.append("=" * 80)
        satirlar.append("   WINDOWS GÜVENLİK LABORATUVARI DENETİM VE DOĞRULAMA RAPORU")
        satirlar.append("=" * 80)
        satirlar.append(f"İncelenen Dosya: {self.dosya_yolu}")
        satirlar.append(f"Toplam Profil Sayısı: {len(sonuclar)}")
        satirlar.append("-" * 80)

        for sonuc in sonuclar:
            satirlar.append(f"\n[+] LAB ID: {sonuc['lab_id']} | Adı: {sonuc['lab_adi']}")
            satirlar.append(f"    Hedef Rol         : {sonuc['guvenlik_derecesi']}")
            satirlar.append(f"    Güvenlik Skoru    : {sonuc['skor']}/100")
            satirlar.append(f"    Risk Durumu       : {sonuc['risk_derecesi']}")
            satirlar.append(f"    Toplam Bulgu      : {sonuc['toplam_bulgu_sayisi']}")

            if sonuc["toplam_bulgu_sayisi"] == 0:
                satirlar.append("    -> TEBRİKLER: Sıfır güvenlik açığı! Sertleştirilmiş ve tam izole Windows laboratuvarı.")
            else:
                satirlar.append("    -> TESPİT EDİLEN RİSK VE ZAFİYETLER:")
                for b in sonuc["bulgular"]:
                    satirlar.append(f"       * [{b['seviye']}] {b['baslik']} (-{b['ceza_puani']} Puan)")
                    satirlar.append(f"         Kategori: {b['kategori']}")
                    satirlar.append(f"         Risk    : {b['detay']}")
                    satirlar.append(f"         Çözüm   : {b['cozum']}")

        satirlar.append("\n" + "=" * 80)
        satirlar.append("Denetim Bitti. Tüm hakları saklıdır (c) 2026 Seydi Eryılmaz.")
        satirlar.append("=" * 80)
        return "\n".join(satirlar)


def main():
    """
    Komut satırı arayüzü (CLI) giriş noktası.
    """
    ayristirici = argparse.ArgumentParser(
        description="Windows Güvenlik Laboratuvarı Kurulum ve Doğrulama Motoru (Windows Lab Provisioner)"
    )
    ayristirici.add_argument(
        "--config",
        required=True,
        help="İncelenecek Windows laboratuvar yapılandırma JSON dosyasının yolu"
    )
    ayristirici.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Çıktı formatı: 'table' (varsayılan) veya 'json'"
    )
    ayristirici.add_argument(
        "--lab-id",
        required=False,
        default=None,
        help="Yalnızca belirli bir Lab ID'sini denetlemek için filtre"
    )
    ayristirici.add_argument(
        "--generate-wsb",
        action="store_true",
        help="Geçerli profil için güvenli Windows Sandbox (.wsb) dosyası üret"
    )
    ayristirici.add_argument(
        "--output-dir",
        default=".",
        help="Üretilen .wsb dosyasının kaydedileceği dizin"
    )

    argumanlar = ayristirici.parse_args()

    try:
        motor = WindowsLabProvisioner(argumanlar.config)
        sonuclar = motor.denetle_tumunu()

        # Lab ID filtresi varsa uygula
        if argumanlar.lab_id:
            sonuclar = [s for s in sonuclar if s["lab_id"] == argumanlar.lab_id]
            if not sonuclar:
                print(f"[!] Belirtilen Lab ID bulunamadı: {argumanlar.lab_id}", file=sys.stderr)
                sys.exit(1)

        # .wsb dosyası üretme talebi varsa işlet
        if argumanlar.generate_wsb:
            hedef_id = argumanlar.lab_id or sonuclar[0]["lab_id"]
            wsb_yolu = motor.urete_guvenli_wsb_dosyasi(hedef_id, argumanlar.output_dir)
            print(f"[+] Güvenli Windows Sandbox (.wsb) profili başarıyla üretildi: {wsb_yolu}")

        # Çıktıyı formatına göre ekrana bas
        if argumanlar.format == "json":
            print(json.dumps(sonuclar, indent=2, ensure_ascii=False))
        else:
            print(motor.rapor_olustur_metin(sonuclar))

        # Kritik veya felaket riski varsa çıkış kodu 2 olsun
        herhangi_bir_felaket = any(
            any(b["seviye"] in ["KRITIK", "FELAKET"] for b in s["bulgular"])
            for s in sonuclar
        )
        if herhangi_bir_felaket:
            sys.exit(2)
        else:
            sys.exit(0)

    except Exception as hata:
        print(f"[HATA] Windows laboratuvar denetimi başarısız oldu: {str(hata)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
