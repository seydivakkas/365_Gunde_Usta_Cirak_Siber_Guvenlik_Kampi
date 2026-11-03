# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 008: Sanallaştırmanın Güvenlikteki Rolü
Uygulama: Sanal Makine Güvenlik ve İzolasyon Denetleyicisi (VM Security Auditor)

Bu araç; sanallaştırma katmanında (Hypervisor, Donanım Emülasyonu, Sanal Ağ ve Misafir Entegrasyonları)
güvenlik sınırlarını, sanal makineden konak sisteme sızma (VM Escape) risklerini, ağ yayılma vektörlerini
ve zararlı yazılım analiz ortamlarının sertleştirme durumunu BSI/CIS standartlarında denetler.
"""

# Standart kütüphane modülleri içe aktarılıyor
import os
import sys
import json
import argparse
from typing import Dict, List, Any, Tuple


class VMSecurityValidationError(Exception):
    """
    Sanal makine yapılandırma profili şema, veri tipi veya mantıksal
    tutarsızlık içerdiğinde fırlatılan özel kural dışı durum (exception) sınıfı.
    """
    pass


class VMSecurityAuditor:
    """
    Sanal Makine Güvenlik ve İzolasyon Denetim Motoru.
    Verilen JSON yapılandırma profilini derinlemesine inceleyerek
    izolasyon açıklarını, VM Escape vektörlerini ve Evasion (Anti-VM) zaaflarını tespit eder.
    """

    # Bilinen sanallaştırma sağlayıcılarına ait varsayılan MAC adresi OUI önekleri (Evasion tespiti için)
    BILINEN_HYPERVISOR_MAC_ONEKLERI = {
        "08:00:27": "Oracle VirtualBox",
        "00:05:69": "VMware ESXi / Workstation",
        "00:0c:29": "VMware Workstation / Server",
        "00:50:56": "VMware Enterprise",
        "00:15:5d": "Microsoft Hyper-V",
        "52:54:00": "QEMU / KVM (Sertleştirilebilir)"
    }

    def __init__(self, profil_dosya_yolu: str):
        """
        Denetleyici sınıf başlatıcısı.
        
        Args:
            profil_dosya_yolu: İncelenecek sanal makine güvenlik profili JSON dosyasının yolu.
        """
        # Dosya yolunu sınıf değişkenine ata
        self.profil_dosya_yolu = profil_dosya_yolu
        # Henüz yüklenmemiş profil verisi için alan aç
        self.profil_verisi: Dict[str, Any] = {}
        # Yükleme fonksiyonunu çağırarak dosya varlığını ve JSON geçerliliğini doğrula
        self.profili_yukle()

    def profili_yukle(self) -> None:
        """
        Profil dosyasını diskten okur, JSON sözdizimini doğrular ve temel şema yapısını kontrol eder.
        """
        # 1. Dosyanın disk üzerinde fiziksel olarak var olup olmadığını doğrula
        if not os.path.exists(self.profil_dosya_yolu):
            # Dosya bulunamazsa açık ve net bir hata fırlat
            raise FileNotFoundError(f"Profil dosyası bulunamadı: {self.profil_dosya_yolu}")

        # 2. Dosyayı güvenli bir şekilde UTF-8 karakter kodlamasıyla oku
        try:
            with open(self.profil_dosya_yolu, "r", encoding="utf-8") as dosya:
                # JSON içeriğini Python sözlük nesnesine ayrıştır
                self.profil_verisi = json.load(dosya)
        except json.JSONDecodeError as json_hatasi:
            # Geçersiz JSON sözdizimi durumunda doğrulama hatası fırlat
            raise VMSecurityValidationError(f"Geçersiz JSON sözdizimi: {str(json_hatasi)}")

        # 3. Kök nesnenin bir sözlük olduğunu ve 'profiller' anahtarını içerdiğini doğrula
        if not isinstance(self.profil_verisi, dict) or "profiller" not in self.profil_verisi:
            raise VMSecurityValidationError("Profil dosyası geçerli bir kök 'profiller' listesi içermelidir.")

        # 4. 'profiller' alanının liste olduğunu doğrula
        if not isinstance(self.profil_verisi["profiller"], list):
            raise VMSecurityValidationError("'profiller' alanı bir dizi (list) olmalıdır.")

    def denetle_vm(self, vm: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tek bir sanal makinenin tüm güvenlik parametrelerini denetler ve kapsamlı bulgu raporu döner.
        
        Args:
            vm: İncelenecek tekil sanal makine yapılandırma sözlüğü.
            
        Returns:
            Denetim sonuçları, bulunan riskler, güvenlik skoru ve nihai karar.
        """
        # Zorunlu alanların mevcudiyetini doğrula
        self._dogrula_vm_semasi(vm)

        # Bulguları saklamak için kategoriye dayalı liste oluştur
        bulgular: List[Dict[str, Any]] = []

        # 1. Ağ İzolasyonu Denetimi (Bridged, Promiscuous, Internet)
        bulgular.extend(self._denetle_ag_izolasyonu(vm))

        # 2. Hypervisor Escape (Sanal Makineden Kaçış) Vektörleri Denetimi (Pano, Sürükle-Bırak, Paylaşılan Klasör, 3D GPU)
        bulgular.extend(self._denetle_hypervisor_escape(vm))

        # 3. Dayanıklılık, İmmutability ve Kurtarma Denetimi (Snapshot, Rollback, Disk Modu)
        bulgular.extend(self._denetle_kurtarma_politikasi(vm))

        # 4. Anti-VM ve Tespitten Kaçınma (Evasion) Analizi (MAC, CPUID, BIOS)
        bulgular.extend(self._denetle_anti_vm_gizleme(vm))

        # Elde edilen bulgular doğrultusunda güvenlik skorunu ve risk derecesini hesapla
        skor, risk_derecesi = self._hesapla_guvenlik_skoru(bulgular)

        # Sonuç sözlüğünü yapılandır ve geri döndür
        return {
            "vm_id": vm.get("vm_id"),
            "vm_adi": vm.get("vm_adi"),
            "guvenlik_seviyesi": vm.get("guvenlik_seviyesi"),
            "skor": skor,
            "risk_derecesi": risk_derecesi,
            "toplam_bulgu_sayisi": len(bulgular),
            "bulgular": bulgular
        }

    def _dogrula_vm_semasi(self, vm: Dict[str, Any]) -> None:
        """
        Sanal makine sözlüğünün zorunlu anahtarları içerip içermediğini kontrol eder.
        """
        zorunlu_alanlar = [
            "vm_id", "vm_adi", "hypervisor_turu", "guvenlik_seviyesi",
            "donanim_yapilandirmasi", "ag_yapilandirmasi",
            "entegrasyon_ozellikleri", "dayaniklilik_ve_kurtarma"
        ]
        # Her bir zorunlu alanı döngü ile kontrol et
        for alan in zorunlu_alanlar:
            if alan not in vm:
                # Eksik alan tespit edildiğinde şema hatası fırlat
                raise VMSecurityValidationError(f"VM yapılandırmasında zorunlu '{alan}' alanı eksik!")

    def _denetle_ag_izolasyonu(self, vm: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Sanal makinenin ağ adaptörü türünü ve ağ sınırlarını denetler.
        Zararlı yazılımın fiziksel ağa sızmasını (lateral movement) önleme kontrolü.
        """
        bulgular = []
        ag = vm.get("ag_yapilandirmasi", {})
        adaptor = ag.get("adaptor_tipi", "")
        promisc = ag.get("promiscuous_mode", "Deny")
        internet = ag.get("internet_erisim_izni", False)
        seviye = vm.get("guvenlik_seviyesi", "")

        # KONTROL 1: Köprülenmiş (Bridged) Ağ Adaptörü
        # Köprülenmiş mod, VM'i doğrudan fiziksel yerel ağa (LAN) dahil eder.
        # Bir fidye yazılımı veya solucan (worm) analiz edilirken Bridged mod ölümcül bir hatadır!
        if adaptor.lower() == "bridged":
            bulgular.append({
                "kategori": "AG_IZOLASYONU",
                "seviye": "KRITIK",
                "ceza_puani": 40,
                "baslik": "Köprülenmiş (Bridged) Ağ Adaptörü Açık",
                "detay": "VM doğrudan fiziksel yerel ağa bağlıdır. Zararlı yazılım konak işletim sistemine ve kurum içi sunuculara yayılabilir (Lateral Movement).",
                "cozum": "Adaptör tipini 'Internal_Isolated' veya 'Host_Only' olarak değiştirin."
            })

        # KONTROL 2: Promiscuous (Karmaşık / Her Şeyi Dinleme) Modu
        # Bu mod açık olduğunda sanal makine sanal anahtardaki (vSwitch) diğer tüm VM'lerin trafiğini koklayabilir (Sniffing).
        if promisc.lower() in ["allow_all", "allow_vms", "true"]:
            bulgular.append({
                "kategori": "AG_IZOLASYONU",
                "seviye": "YUKSEK",
                "ceza_puani": 25,
                "baslik": "Ağ Adaptöründe Promiscuous Mod İzinli",
                "detay": "Sanal makine diğer izole sanal makinelerin ağ paketlerini koklayabilir (Virtual Network Sniffing).",
                "cozum": "Promiscuous mod ayarını kesinlikle 'Deny' (Reddet) yapın."
            })

        # KONTROL 3: Kritik Karantina VM'inde Doğrudan İnternet Çıkışı
        if seviye == "KRITIK_IZOLE" and internet is True:
            bulgular.append({
                "kategori": "AG_IZOLASYONU",
                "seviye": "KRITIK",
                "ceza_puani": 35,
                "baslik": "İzole Analiz Makinesinde Açık İnternet Erişimi",
                "detay": "Karantina altındaki zararlı yazılım C2 (Komuta Kontrol) sunucularıyla iletişim kurabilir ve dışarıya veri sızdırabilir.",
                "cozum": "İnternet erişim iznini 'false' yapın; gerekiyorsa trafiği sahte yanıtlayan INetSim / FakeNet gibi yerel simülatörlere yönlendirin."
            })

        return bulgular

    def _denetle_hypervisor_escape(self, vm: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Misafir işletim sisteminden konak işletim sistemine geçiş (Hypervisor Escape)
        sağlayabilecek zafiyet yüzeylerini (Pano, Sürükle-Bırak, Paylaşılan Klasör, 3D GPU) denetler.
        """
        bulgular = []
        entegrasyon = vm.get("entegrasyon_ozellikleri", {})
        donanim = vm.get("donanim_yapilandirmasi", {})

        pano = entegrasyon.get("pano_paylasimi", "Disabled")
        surukle = entegrasyon.get("surukle_birak", "Disabled")
        paylasilan_klasorler = entegrasyon.get("paylasilan_klasorler", [])
        gpu_3d = donanim.get("hizlandirma_3d", False)

        # KONTROL 1: Çift Yönlü Pano Paylaşımı (Bidirectional Clipboard)
        # Panodan konak sisteme veri aktarımı, bellek taşması zafiyetleri (CVE-2019-0836 vb.) ile konak kod yürütmeye yol açabilir.
        if pano.lower() in ["bidirectional", "guesttohost"]:
            bulgular.append({
                "kategori": "HYPERVISOR_ESCAPE",
                "seviye": "KRITIK",
                "ceza_puani": 30,
                "baslik": "Konak Yönünde Pano Paylaşımı Açık (Clipboard Leak/Escape)",
                "detay": "Misafir işletim sistemindeki zararlı yazılım, panodaki hassas verileri (parolalar, tokenlar) çalabilir veya pano ayrıştırma açıklarıyla konakta kod çalıştırabilir.",
                "cozum": "Pano paylaşımını 'Disabled' (Devre Dışı) durumuna getirin."
            })

        # KONTROL 2: Sürükle ve Bırak (Drag and Drop)
        if surukle.lower() in ["bidirectional", "guesttohost"]:
            bulgular.append({
                "kategori": "HYPERVISOR_ESCAPE",
                "seviye": "KRITIK",
                "ceza_puani": 30,
                "baslik": "Konak Yönünde Sürükle-Bırak Açık (Drag & Drop Escape)",
                "detay": "Zararlı yazılım sahte IPC çağrıları ile konak işletim sisteminin başlangıç klasörüne veya masaüstüne zararlı dosya enjekte edebilir.",
                "cozum": "Sürükle-bırak entegrasyonunu 'Disabled' yapın."
            })

        # KONTROL 3: Paylaşılan Klasörler (Shared Folders) ve Yazma İzni
        # Konak sistemin kök dizini (C:\, /, /home) VM ile paylaşılırsa, fidye yazılımı konağı şifreler!
        for klasor in paylasilan_klasorler:
            konak_yolu = klasor.get("konak_yolu", "").lower()
            yetki = klasor.get("erisim_yetkisi", "").lower()
            if konak_yolu in ["c:\\", "c:/", "/", "/root", "/home"] or yetki in ["readwrite", "full"]:
                bulgular.append({
                    "kategori": "HYPERVISOR_ESCAPE",
                    "seviye": "FELAKET",
                    "ceza_puani": 50,
                    "baslik": f"Güvensiz Paylaşılan Klasör Tanımlı: {klasor.get('klasor_adi')}",
                    "detay": f"Konak sistemin kritik dizini ({klasor.get('konak_yolu')}) yazma izniyle misafire açılmıştır. Bir fidye yazılımı doğrudan konak sistemi şifreleyebilir.",
                    "cozum": "Paylaşılan klasörleri tamamen kaldırın; test dosyası aktarımı gerekiyorsa salt-okunur (ReadOnly) izole geçici klasör kullanın."
                })

        # KONTROL 4: 3D Donanım Hızlandırma (GPU Emülasyonu)
        # Hypervisor'ların 3D grafik emülasyon kodları (OpenGL/DirectX wrapper) tarihsel olarak en çok sıfır-gün (zero-day) çıkan zafiyet kaynağıdır.
        if gpu_3d is True:
            bulgular.append({
                "kategori": "HYPERVISOR_ESCAPE",
                "seviye": "ORTA",
                "ceza_puani": 15,
                "baslik": "3D Grafik Donanım Hızlandırma Açık",
                "detay": "Hypervisor grafik sürücüsü emülasyon katmanı, geçmişte birçok VM Escape (sanal makineden kaçış) zafiyetine sahne olmuştur.",
                "cozum": "Analiz ve test sanal makinelerinde 3D hızlandırmayı devre dışı bırakın."
            })

        return bulgular

    def _denetle_kurtarma_politikasi(self, vm: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Sanal makinenin temiz durumunu koruma, anlık görüntü (Snapshot) alma ve geri yükleme (Rollback) kabiliyetini denetler.
        """
        bulgular = []
        kurtarma = vm.get("dayaniklilik_ve_kurtarma", {})
        politika = kurtarma.get("anlik_goruntu_politikasi", "").lower()
        disk_modu = kurtarma.get("disk_calisma_modu", "").lower()
        rollback = kurtarma.get("otomatik_rollback_aktif", False)

        # KONTROL 1: Anlık Görüntü (Snapshot) Eksikliği
        if politika in ["yok", "none", "tanimsiz", ""]:
            bulgular.append({
                "kategori": "KURTARMA_VE_KALICILIK",
                "seviye": "YUKSEK",
                "ceza_puani": 25,
                "baslik": "Anlık Görüntü (Snapshot) Politikası Tanımsız",
                "detay": "Zararlı analiz edildikten sonra sistem orijinal temiz taban çizgisine (baseline) geri döndürülemez; analiz ortamı kirlenir.",
                "cozum": "Analiz öncesi 'Clean_Baseline' anlık görüntüsü alınmalı ve her analiz sonrası geri yükleme zorunlu kılınmalıdır."
            })

        # KONTROL 2: Kalıcı (Persistent) Disk Modu
        if disk_modu in ["persistent", "kalici"]:
            bulgular.append({
                "kategori": "KURTARMA_VE_KALICILIK",
                "seviye": "ORTA",
                "ceza_puani": 15,
                "baslik": "Disk Modu Kalıcı (Persistent) Olarak Ayarlanmış",
                "detay": "Misafir işletim sisteminde yapılan değişiklikler kalıcı diske yazılmaktadır. Kapatıp açma sırasında sistem temizlenmez.",
                "cozum": "Disk modunu 'Non_Persistent' veya 'Immutable' (Değiştirilemez) yapın."
            })

        # KONTROL 3: Otomatik Geri Alma (Auto-Rollback) Kapalı
        if rollback is False and vm.get("guvenlik_seviyesi") == "KRITIK_IZOLE":
            bulgular.append({
                "kategori": "KURTARMA_VE_KALICILIK",
                "seviye": "ORTA",
                "ceza_puani": 10,
                "baslik": "Otomatik Rollback Devre Dışı",
                "detay": "Zararlı analiz oturumu sonlandığında sanal makinenin otomatik olarak temiz snapshot'a dönmesi garanti edilmemiştir.",
                "cozum": "Otomatik rollback mekanizmasını 'true' olarak yapılandırın."
            })

        return bulgular

    def _denetle_anti_vm_gizleme(self, vm: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Zararlı yazılımların sanal ortamı tespit ederek kendilerini gizlemesini (Evasion)
        engellemeye yönelik sertleştirme tedbirlerini denetler.
        """
        bulgular = []
        ag = vm.get("ag_yapilandirmasi", {})
        mac = ag.get("mac_adresi", "").lower()
        anti_vm = vm.get("anti_vm_gizleme", {})

        # KONTROL 1: Bilinen Hypervisor MAC Öneki Tespiti
        # Zararlı yazılım ilk iş olarak ağ kartının ilk 3 baytına (OUI) bakar.
        # Örneğin 08:00:27 VirtualBox olduğunu hemen ele verir.
        for onek, saglayici in self.BILINEN_HYPERVISOR_MAC_ONEKLERI.items():
            if mac.startswith(onek.lower()):
                # Eğer QEMU/KVM değilse ve maskeleme yapılmamışsa uyar
                if "VirtualBox" in saglayici or "VMware" in saglayici or "Hyper-V" in saglayici:
                    bulgular.append({
                        "kategori": "ANTI_VM_EVASION",
                        "seviye": "ORTA",
                        "ceza_puani": 10,
                        "baslik": f"Açık Sanallaştırma MAC Adresi: {mac.upper()} ({saglayici})",
                        "detay": "Gelişmiş zararlı yazılımlar bu MAC önekini gördüğü anda sanal ortamda olduğunu anlayıp uyku moduna geçer (Evasion).",
                        "cozum": "MAC adresini fiziksel bir üreticiye (ör. Intel, Realtek) ait OUI ile maskeleyin (MAC Spoofing)."
                    })
                break

        # KONTROL 2: CPUID Hypervisor Bayrağı Gizleme Eksikliği
        if anti_vm.get("cpuid_hypervisor_flag_gizli") is False:
            bulgular.append({
                "kategori": "ANTI_VM_EVASION",
                "seviye": "DUSUK",
                "ceza_puani": 5,
                "baslik": "CPUID Hypervisor Varlığı Gizlenmemiş",
                "detay": "Zararlı yazılım CPUID komutunun 31. bitine (Hypervisor Present Bit) bakarak sanallaştırmayı anında tespit edebilir.",
                "cozum": "Hypervisor ayarlarından CPUID hypervisor bayrağını maskeleyin (ör. KVM'de 'hv_vendor_id' veya VBox'ta 'cpuidset')."
            })

        return bulgular

    def _hesapla_guvenlik_skoru(self, bulgular: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Tespit edilen güvenlik açıklarının ceza puanlarını toplayarak 100 üzerinden nihai skor üretir.
        """
        toplam_ceza = sum(b.get("ceza_puani", 0) for b in bulgular)
        # Taban puan 100'dür, cezalar düşülür, skor sıfırın altına inemez
        skor = max(0, 100 - toplam_ceza)

        # Skora göre risk derecesini belirle
        if skor >= 90:
            risk = "GÜVENLİ (SERTLEŞTİRİLMİŞ)"
        elif skor >= 70:
            risk = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        elif skor >= 40:
            risk = "YÜKSEK RİSK (TEHLİKELİ)"
        else:
            risk = "KRİTİK FELAKET (ACİL MÜDAHALE)"

        return skor, risk

    def denetle_tumunu(self) -> List[Dict[str, Any]]:
        """
        Profil dosyasındaki tüm sanal makineleri sırayla denetler.
        """
        sonuclar = []
        for vm in self.profil_verisi.get("profiller", []):
            sonuc = self.denetle_vm(vm)
            sonuclar.append(sonuc)
        return sonuclar

    def rapor_olustur_metin(self, sonuclar: List[Dict[str, Any]]) -> str:
        """
        Denetim sonuçlarını terminalde insan tarafından okunabilir zengin tablo formatında biçimlendirir.
        """
        satirlar = []
        satirlar.append("=" * 80)
        satirlar.append("   SANAL MAKİNE GÜVENLİK VE İZOLASYON DENETİM RAPORU (VM SECURITY AUDITOR)")
        satirlar.append("=" * 80)
        satirlar.append(f"İncelenen Dosya: {self.profil_dosya_yolu}")
        satirlar.append(f"Toplam Profil Sayısı: {len(sonuclar)}")
        satirlar.append("-" * 80)

        for sonuc in sonuclar:
            satirlar.append(f"\n[+] VM ID: {sonuc['vm_id']} | Adı: {sonuc['vm_adi']}")
            satirlar.append(f"    Güvenlik Seviyesi : {sonuc['guvenlik_seviyesi']}")
            satirlar.append(f"    Güvenlik Skoru    : {sonuc['skor']}/100")
            satirlar.append(f"    Risk Durumu       : {sonuc['risk_derecesi']}")
            satirlar.append(f"    Toplam Bulgu      : {sonuc['toplam_bulgu_sayisi']}")

            if sonuc["toplam_bulgu_sayisi"] == 0:
                satirlar.append("    -> TEBRİKLER: Sıfır güvenlik açığı! Tam izole ve sertleştirilmiş profil.")
            else:
                satirlar.append("    -> TESPİT EDİLEN RİSK VE ZAFİYETLER:")
                for b in sonuc["bulgular"]:
                    satirlar.append(f"       * [{b['seviye']}] {b['baslik']} (-{b['ceza_puani']} Puan)")
                    satirlar.append(f"         Risk : {b['detay']}")
                    satirlar.append(f"         Çözüm: {b['cozum']}")

        satirlar.append("\n" + "=" * 80)
        satirlar.append("Denetim Bitti. Tüm hakları saklıdır (c) 2026 Seydi Eryılmaz.")
        satirlar.append("=" * 80)
        return "\n".join(satirlar)


def main():
    """
    Komut satırı arayüzü (CLI) giriş noktası.
    """
    ayristirici = argparse.ArgumentParser(
        description="Sanal Makine Güvenlik ve İzolasyon Denetleyicisi (VM Security Auditor)"
    )
    ayristirici.add_argument(
        "--profile",
        required=True,
        help="İncelenecek VM profili JSON dosyasının yolu"
    )
    ayristirici.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Çıktı formatı: 'table' (varsayılan) veya 'json'"
    )
    ayristirici.add_argument(
        "--vm-id",
        required=False,
        default=None,
        help="Yalnızca belirli bir VM ID'sini denetlemek için filtre"
    )

    argumanlar = ayristirici.parse_args()

    try:
        denetleyici = VMSecurityAuditor(argumanlar.profile)
        sonuclar = denetleyici.denetle_tumunu()

        # Eğer belirli bir VM ID filtresi verilmişse sadece onu filtrele
        if argumanlar.vm_id:
            sonuclar = [s for s in sonuclar if s["vm_id"] == argumanlar.vm_id]
            if not sonuclar:
                print(f"[!] Belirtilen VM ID bulunamadı: {argumanlar.vm_id}", file=sys.stderr)
                sys.exit(1)

        # İstenen formata göre ekrana yazdır
        if argumanlar.format == "json":
            print(json.dumps(sonuclar, indent=2, ensure_ascii=False))
        else:
            print(denetleyici.rapor_olustur_metin(sonuclar))

        # Eğer kritik/felaket seviyesinde risk varsa çıkış kodu 2 olsun, aksi halde 0
        herhangi_bir_felaket = any(
            any(b["seviye"] in ["KRITIK", "FELAKET"] for b in s["bulgular"])
            for s in sonuclar
        )
        if herhangi_bir_felaket:
            sys.exit(2)
        else:
            sys.exit(0)

    except Exception as hata:
        print(f"[HATA] Denetim başarısız oldu: {str(hata)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
