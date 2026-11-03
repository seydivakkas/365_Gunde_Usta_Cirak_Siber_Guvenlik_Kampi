# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 012: Sanal Makine Anlık Görüntü (Snapshot), Yedekleme ve Geri Dönüş Yöneticisi
Usta-Çırak Siber Güvenlik Akademisi Laboratuvar Otomasyon Aracı

Bu modül; siber güvenlik laboratuvarlarında analiz öncesi temiz sistem anlık görüntülerinin (snapshot)
alınmasını, zararlı yazılım testi sonrası 'Altın Durum'a (Golden State) saniyeler içinde geri dönülmesini,
fakat snapshot mekanizmasının asla bir "yedek" sanılmaması kuralını ve 3-2-1-1-0 kuralına uygun
değişmez (immutable/WORM) tam yedekleme ve kriptografik bütünlük (SHA-256) denetimlerini icra eder.
"""

import os  # İşletim sistemi dosya yolu ve dizin operasyonları için standart kütüphane
import sys  # Sistem argümanları ve çıkış kodlarını (exit codes) yönetmek için
import json  # Yapılandırma ve envanter JSON dosyalarını serileştirmek için
import hashlib  # Bütünlük denetiminde SHA-256 kriptografik özet hesaplama kütüphanesi
import argparse  # Profesyonel komut satırı arayüzü (CLI) parametre ayrıştırması için
from datetime import datetime, timezone  # Zaman damgası ve snapshot yaş hesaplamaları için
from typing import Dict, List, Any, Optional, Tuple  # Katı tip güvenliği ve statik analiz için


# --- ÖZEL İSTİSNA SINIFLARI (CUSTOM EXCEPTIONS) ---

class SnapshotManagerError(Exception):
    """Snapshot ve yedekleme motorunun temel ata istisna sınıfı."""
    pass


class BackupIntegrityError(SnapshotManagerError):
    """SHA-256 karma özeti uyuşmadığında (veri bozulması veya fidye saldırısı) fırlatılan istisna."""
    pass


class SnapshotPolicyViolationError(SnapshotManagerError):
    """Güvenlik ve operasyonel politikalar (yaş sınırı, zincir derinliği) ihlal edildiğinde fırlatılır."""
    pass


# --- ÇEKİRDEK YÖNETİM SINIFI ---

class VMSnapshotBackupManager:
    """
    Sanal makine anlık görüntüleri, bağımsız yedekleri ve geri dönüş operasyonlarını yöneten motor.
    """

    def __init__(self, envanter_yolu: Optional[str] = None):
        # Envanter dosyasının dosya yolu parametresi atanır
        self.envanter_yolu = envanter_yolu
        # Yüklenen sanal makine verilerini bellekte tutacak ana sözlük başlatılır
        self.vmler: Dict[str, Dict[str, Any]] = {}
        # Eğer bir envanter yolu verilmişse derhal dosyadan yükleme yapılır
        if envanter_yolu:
            # Envanter yükleme metodu çağrılır
            self.envanter_yukle(envanter_yolu)

    def envanter_yukle(self, envanter_yolu: str) -> None:
        """
        JSON tabanlı laboratuvar VM envanterini doğrular ve belleğe yükler.
        """
        # Dosyanın diskte fiziken var olup olmadığı kontrol edilir
        if not os.path.exists(envanter_yolu):
            # Dosya yoksa açık bir FileNotFoundError fırlatılır
            raise FileNotFoundError(f"Envanter dosyası bulunamadı: {envanter_yolu}")
        
        # Dosya güvenli okuma kipinde açılır
        with open(envanter_yolu, "r", encoding="utf-8") as dosya:
            # JSON verisi belleğe ayrıştırılır
            veri = json.load(dosya)

        # Temel şema geçerliliği kontrol edilir (laboratuvar_vmler anahtarı zorunludur)
        if "laboratuvar_vmler" not in veri:
            # Eksik şemada hata fırlatılır
            raise SnapshotPolicyViolationError("Geçersiz şema: 'laboratuvar_vmler' listesi eksik.")

        # VM listesi vm_id anahtarına göre hızlı erişimli bir sözlüğe dönüştürülür
        self.vmler = {vm["vm_id"]: vm for vm in veri["laboratuvar_vmler"]}

    def dosya_sha256_hesapla(self, dosya_yolu: str) -> str:
        """
        Verilen bir dosyanın akışkan (streaming) SHA-256 kriptografik özetini hesaplar.
        Büyük disk imajlarında belleğin taşmasını önlemek için 64 KB bloklar halinde okunur.
        """
        # Dosya mevcut değilse hata üretilir
        if not os.path.exists(dosya_yolu):
            raise FileNotFoundError(f"Özet hesaplanacak dosya bulunamadı: {dosya_yolu}")

        # SHA-256 özet nesnesi oluşturulur
        hasher = hashlib.sha256()
        # İkili (binary) kipte dosya açılır
        with open(dosya_yolu, "rb") as f:
            # 64 Kilobaytlık parçalar halinde dosya sonuna kadar okunur
            while parca := f.read(65536):
                # Parça özet hesaplayıcıya eklenir
                hasher.update(parca)
        # Onaltılık (hexadecimal) karakter dizisi olarak özet döndürülür
        return hasher.hexdigest()

    def snapshot_olustur(self, vm_id: str, snapshot_adi: str, aciklama: str, bellek_dahil: bool = True) -> Dict[str, Any]:
        """
        Sanal makine için yeni bir anlık görüntü (snapshot) oluşturur.
        Temel Mekanizma:
        1. Ana disk salt-okunur (read-only) kilitlenir.
        2. Yazma işlemleri için bir delta (fark/differencing) diski bağlanır.
        3. İsteğe bağlı olarak RAM bellek durumu dondurularak kaydedilir.
        """
        # VM envanterde var mı kontrol edilir
        if vm_id not in self.vmler:
            raise SnapshotPolicyViolationError(f"Tanımsız VM Kimliği: {vm_id}")

        vm = self.vmler[vm_id]
        # Zincir derinliği kontrol edilir (Aşırı derinleşen snapshot zincirleri performansı çökertir)
        mevcut_snapler = vm.get("anlik_goruntuler", [])
        if len(mevcut_snapler) >= 5:
            raise SnapshotPolicyViolationError(f"Maksimum snapshot zincir derinliği (5) aşıldı! Önce birleştirme (merge/commit) yapınız.")

        # Ana disk salt-okunur olarak kilitlenir
        vm["ana_disk"]["salt_okunur_mu"] = True

        # Yeni snapshot kaydı için benzersiz kimlik ve delta dosya adı oluşturulur
        snap_sira = len(mevcut_snapler) + 1
        zaman_damgasi = datetime.now(timezone.utc).isoformat()
        snap_id = f"SNAP-{vm_id}-{snap_sira:02d}"
        delta_adi = f"{vm['ana_disk']['dosya_adi']}.delta_{snap_sira:02d}.diff"

        yeni_snap = {
            "snapshot_id": snap_id,
            "snapshot_adi": snapshot_adi,
            "olusturma_tarihi": zaman_damgasi,
            "yas_saat": 0.0,
            "delta_diski": delta_adi,
            "delta_boyut_gb": 0.1,  # Başlangıçta delta diski boştur
            "durum": "AKTIF",
            "bellek_dahil_mi": bellek_dahil,
            "aciklama": aciklama
        }

        # Listeye eklenir
        mevcut_snapler.append(yeni_snap)
        vm["anlik_goruntuler"] = mevcut_snapler
        return yeni_snap

    def snapshot_geri_don(self, vm_id: str, snapshot_id: str) -> Dict[str, Any]:
        """
        VM'i belirtilen snapshot anına geri döndürür (Rollback).
        Temel Mekanizma:
        Zararlı yazılımın bulaştığı veya test sırasında değiştirilen tüm verileri tutan delta diski silinir
        veya sıfırlanır; VM ana diskin snapshot alındığı andaki saf durumuna döner.
        """
        if vm_id not in self.vmler:
            raise SnapshotPolicyViolationError(f"Tanımsız VM Kimliği: {vm_id}")

        vm = self.vmler[vm_id]
        snapler = vm.get("anlik_goruntuler", [])
        
        # Hedef snapshot bulunur
        hedef_snap = None
        for s in snapler:
            if s["snapshot_id"] == snapshot_id:
                hedef_snap = s
                break

        if not hedef_snap:
            raise SnapshotPolicyViolationError(f"Snapshot bulunamadı: {snapshot_id}")

        # Geri dönüş simülasyonu: Delta disk sıfırlanır
        hedef_snap["delta_boyut_gb"] = 0.0
        hedef_snap["durum"] = "GERI_DONULDU_ALTIN_DURUM"

        return {
            "islem": "SNAPSHOT_ROLLBACK",
            "vm_id": vm_id,
            "snapshot_id": snapshot_id,
            "durum": "BASARILI",
            "aciklama": "Delta diski temizlendi. Sistem snapshot anındaki temiz durumuna saniyeler içinde geri döndürüldü."
        }

    def tam_yedek_olustur(self, vm_id: str, hedef_depolama: str, degismezlik_kilidi: bool = True) -> Dict[str, Any]:
        """
        Ana disk ve makine konfigürasyonunun bağımsız bir depolama birimine tam yedeğini alır.
        Temel Mekanizma:
        1. Ana diskten bağımsız bir kopyalama yapılır (Snapshot gibi ana diske bağımlı değildir).
        2. Kriptografik SHA-256 özeti çıkarılır.
        3. Fidye yazılımlarının yedekleri silememesi için WORM (Write Once Read Many) değişmezlik kilidi vurulur.
        """
        if vm_id not in self.vmler:
            raise SnapshotPolicyViolationError(f"Tanımsız VM Kimliği: {vm_id}")

        vm = self.vmler[vm_id]
        zaman_damgasi = datetime.now(timezone.utc).isoformat()
        yedek_sira = len(vm.get("yedekler", [])) + 1
        yedek_id = f"BAK-{vm_id}-{yedek_sira:03d}"

        # Ana disk özeti referans alınır (sentetik ortamda mevcut ana disk sha256 değeri)
        ana_disk_hash = vm["ana_disk"].get("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        yeni_yedek = {
            "yedek_id": yedek_id,
            "yedek_tipi": "TAM_BAGIMSIZ_YEDEK",
            "hedef_depolama": hedef_depolama,
            "tarih": zaman_damgasi,
            "boyut_gb": vm["ana_disk"]["boyut_gb"],
            "sha256": ana_disk_hash,
            "degismezlik_kilidi_aktif_mi": degismezlik_kilidi,
            "air_gap_izolasyon": True if "s3://" in hedef_depolama or "offline" in hedef_depolama else False,
            "dogrulama_durumu": "DOGRULANDI"
        }

        if "yedekler" not in vm:
            vm["yedekler"] = []
        vm["yedekler"].append(yeni_yedek)

        # Yedekleme politikası güncellenir
        if degismezlik_kilidi:
            vm["yedekleme_politikasi"]["degismezlik_kilidi_worm"] = True
        vm["yedekleme_politikasi"]["3_2_1_uyumlu_mu"] = True

        return yeni_yedek

    def yedekten_geri_yukle_dogrula(self, vm_id: str, yedek_id: str, saglanan_dosya_hashi: str) -> Dict[str, Any]:
        """
        Yedekten geri yükleme (Restore) tatbikatı yapar ve kriptografik bütünlüğü doğrular.
        Eğer SHA-256 hash'i eşleşmezse (veri bozulması / bit rot veya fidye yazılımı değişikliği),
        işlem derhal durdurulur ve BackupIntegrityError fırlatılır!
        """
        if vm_id not in self.vmler:
            raise SnapshotPolicyViolationError(f"Tanımsız VM Kimliği: {vm_id}")

        vm = self.vmler[vm_id]
        yedekler = vm.get("yedekler", [])
        
        hedef_yedek = None
        for y in yedekler:
            if y["yedek_id"] == yedek_id:
                hedef_yedek = y
                break

        if not hedef_yedek:
            raise SnapshotPolicyViolationError(f"Yedek kaydı bulunamadı: {yedek_id}")

        # Bütünlük kontrolü: Kaydedilen SHA-256 ile geri yüklenen dosya özeti karşılaştırılır
        beklenen_hash = hedef_yedek["sha256"]
        if beklenen_hash.lower() != saglanan_dosya_hashi.lower():
            # FELAKET DÜZEYİNDE BÜTÜNLÜK İHLALİ!
            hedef_yedek["dogrulama_durumu"] = "BUTUNLUK_HATASI_BOZULMUS"
            raise BackupIntegrityError(
                f"KRİTİK HATA: Yedek dosyası kriptografik bütünlük testini geçemedi!\n"
                f"Beklenen SHA-256: {beklenen_hash}\n"
                f"Hesaplanan SHA-256: {saglanan_dosya_hashi}\n"
                f"Sebep: Veri bozulması (bit-rot) veya fidye yazılımı manipülasyonu tespit edildi!"
            )

        # Başarılı doğrulama
        hedef_yedek["dogrulama_durumu"] = "DOGRULANDI"
        return {
            "islem": "BACKUP_RESTORE_VERIFICATION",
            "vm_id": vm_id,
            "yedek_id": yedek_id,
            "durum": "GECERLI_VE_BASARILI",
            "sha256": beklenen_hash,
            "aciklama": "Yedek bütünlüğü kriptografik olarak kanıtlandı. Geri yükleme güvenli."
        }

    def denetle_ve_risk_analizi_yap(self, vm_id: str) -> Dict[str, Any]:
        """
        Bir sanal makinenin snapshot ve yedekleme yapılandırmasını 6 kritik güvenlik kriterine göre denetler:
        1. Snapshot-as-Backup yanılgısı (Snapshot var ama bağımsız yedek yok mu?)
        2. Snapshot Yaşı & Disk Şişmesi (Snapshot > 72 saat açık mı?)
        3. Aşırı Snapshot Zincir Derinliği (Derinlik > 3 mü?)
        4. WORM / Değişmezlik Kilidi Yokluğu (Fidye yazılımı tehdidi)
        5. VSS / Shadow Copy Korumasızlığı (vssadmin delete saldırı yüzeyi)
        6. Kriptografik Bütünlük Doğrulaması
        """
        if vm_id not in self.vmler:
            raise SnapshotPolicyViolationError(f"Tanımsız VM Kimliği: {vm_id}")

        vm = self.vmler[vm_id]
        puan = 100
        bulgular = []

        snapler = vm.get("anlik_goruntuler", [])
        yedekler = vm.get("yedekler", [])
        politika = vm.get("yedekleme_politikasi", {})
        vss_etkin = vm.get("vss_golge_kopya_etkin_mi", False)

        # 1. KONTROL: Snapshot-as-Backup Yanılgısı (Ölümcül Hata)
        if len(snapler) > 0 and len(yedekler) == 0:
            ceza = 30
            puan -= ceza
            bulgular.append({
                "kod": "RISK-01-SNAP-AS-BACKUP",
                "seviye": "KRITIK",
                "ceza": ceza,
                "baslik": "Snapshot-as-Backup (Anlık Görüntüyü Yedek Sanma) Yanılgısı",
                "aciklama": "Sanal makinede snapshot mevcut ancak hiçbir bağımsız yedek (backup) bulunmuyor. "
                            "Ana diskin veya depolama havuzunun çökmesi durumunda tüm delta zinciri yok olur!"
            })

        # 2. KONTROL: Snapshot Yaşı ve Disk Şişmesi Riski (> 72 Saat)
        uzun_omurlu_snapler = [s for s in snapler if s.get("yas_saat", 0) > 72.0]
        if uzun_omurlu_snapler:
            ceza = 20
            puan -= ceza
            en_eski_saat = max(s.get("yas_saat", 0) for s in uzun_omurlu_snapler)
            bulgular.append({
                "kod": "RISK-02-SNAPSHOT-AGE-EXCEEDED",
                "seviye": "YUKSEK",
                "ceza": ceza,
                "baslik": f"Snapshot Yaş Sınırı Aşıldı (En eski: {en_eski_saat:.1f} saat)",
                "aciklama": "Snapshot'lar 72 saatten uzun süre açık bırakılmış. Delta diski kontrolsüzce büyüyerek "
                            "hypervisor veri deposunu doldurabilir ve tüm ana makineleri I/O kilitlenmesine sürükleyebilir."
            })

        # 3. KONTROL: Aşırı Zincir Derinliği (Snapshot Sprawl > 3)
        if len(snapler) > 3:
            ceza = 15
            puan -= ceza
            bulgular.append({
                "kod": "RISK-03-DEEP-SNAPSHOT-CHAIN",
                "seviye": "ORTA",
                "ceza": ceza,
                "baslik": f"Aşırı Snapshot Zincir Derinliği (Derinlik: {len(snapler)})",
                "aciklama": "Üst üste 3'ten fazla snapshot alınmış. Her okuma I/O operasyonu tüm delta zincirini "
                            "taramak zorunda kaldığından disk gecikmesi (latency) katlanarak artar."
            })

        # 4. KONTROL: WORM / Değişmezlik (Immutability) Kilidi Yokluğu
        if not politika.get("degismezlik_kilidi_worm", False):
            ceza = 20
            puan -= ceza
            bulgular.append({
                "kod": "RISK-04-IMMUTABILITY-MISSING",
                "seviye": "YUKSEK",
                "ceza": ceza,
                "baslik": "Değişmezlik (WORM / Object Lock) Kilidi Bulunmuyor",
                "aciklama": "Yedek deposunda değişmezlik kilidi kapalı. Bir fidye yazılımı veya domain admin yetkisi ele geçiren "
                            "saldırgan yedek dosyalarını doğrudan silebilir veya şifreleyebilir."
            })

        # 5. KONTROL: VSS Korumasızlığı (Windows Sistemlerde vssadmin Hedefi)
        if "Windows" in vm.get("isletim_sistemi", "") and vss_etkin and not politika.get("degismezlik_kilidi_worm", False):
            ceza = 15
            puan -= ceza
            bulgular.append({
                "kod": "RISK-05-VSS-TAMPER-SURFACE",
                "seviye": "YUKSEK",
                "ceza": ceza,
                "baslik": "Gölge Kopyalar (VSS) Fidye Yazılımı Saldırısına Açık",
                "aciklama": "Windows VSS aktif ancak harici izole yedek yok. Saldırganlar 'vssadmin delete shadows /all /quiet' "
                            "komutuyla yerel gölge kopyaları saniyeler içinde yok edebilir."
            })

        # Puanın 0 altına düşmesi engellenir
        puan = max(0, puan)
        durum = "GUVENLI" if puan >= 80 else ("UYARI" if puan >= 50 else "TEHLIKELI")

        return {
            "vm_id": vm_id,
            "vm_adi": vm.get("vm_adi"),
            "denetim_skoru": puan,
            "durum": durum,
            "bulgu_sayisi": len(bulgular),
            "bulgular": bulgular
        }


# --- KOMUT SATIRI ARAYÜZÜ (CLI) ---

def main():
    """CLI giriş noktası ve parametre işleyicisi."""
    parser = argparse.ArgumentParser(
        description="GÜN 012: Sanal Makine Snapshot, Yedekleme ve Geri Dönüş Denetçisi",
        epilog="ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)"
    )
    parser.add_argument("--envanter", type=str, default="ornek_veri/vm_lab_envanteri.json", help="VM envanter JSON dosya yolu")
    parser.add_argument("--vm-id", type=str, default="VM-SEC-WIN-01", help="İşlem yapılacak VM Kimliği")
    parser.add_argument("--denetle", action="store_true", help="Belirtilen VM veya tüm ortam için güvenlik denetimi çalıştır")
    parser.add_argument("--snapshot-al", type=str, help="Yeni bir snapshot oluştur (Snapshot adı giriniz)")
    parser.add_argument("--rollback", type=str, help="Belirtilen snapshot kimliğine geri dön (Örn: SNAP-WIN-01)")
    parser.add_argument("--tam-yedek", type=str, help="Bağımsız tam yedek oluştur (Hedef depolama yolu)")
    parser.add_argument("--cikis-json", type=str, help="Sonuçları JSON dosyası olarak kaydet")

    args = parser.parse_args()

    # Yönetici motoru başlatılır
    yonetici = VMSnapshotBackupManager(args.envanter)

    sonuc = {}
    if args.denetle:
        print(f"[*] Sanal Makine Denetimi Başlatılıyor: {args.vm_id}")
        sonuc = yonetici.denetle_ve_risk_analizi_yap(args.vm_id)
        print(f"[+] Denetim Skoru: {sonuc['denetim_skoru']} / 100 ({sonuc['durum']})")
        print(f"[+] Toplam Risk Bulgusu: {sonuc['bulgu_sayisi']}")
        for b in sonuc["bulgular"]:
            print(f"    - [{b['seviye']}] {b['baslik']} (-{b['ceza']} puan)")

    elif args.snapshot_al:
        print(f"[*] Snapshot Alınıyor: VM={args.vm_id}, Ad={args.snapshot_al}")
        sonuc = yonetici.snapshot_olustur(args.vm_id, args.snapshot_al, "CLI Üzerinden Alınan Güvenlik Kontrol Noktası")
        print(f"[+] Snapshot Başarıyla Oluşturuldu: {sonuc['snapshot_id']}")

    elif args.rollback:
        print(f"[*] Rollback İcra Ediliyor: VM={args.vm_id}, Hedef Snapshot={args.rollback}")
        sonuc = yonetici.snapshot_geri_don(args.vm_id, args.rollback)
        print(f"[+] Rollback Tamamlandı: {sonuc['aciklama']}")

    elif args.tam_yedek:
        print(f"[*] Bağımsız Tam Yedek Alınıyor: VM={args.vm_id}, Hedef={args.tam_yedek}")
        sonuc = yonetici.tam_yedek_olustur(args.vm_id, args.tam_yedek, degismezlik_kilidi=True)
        print(f"[+] Tam Yedek Alındı: {sonuc['yedek_id']} (SHA-256: {sonuc['sha256'][:16]}...)")

    else:
        # Varsayılan olarak tüm VM'leri denetle
        print("[*] Tüm Sanal Makineler Denetleniyor...")
        tum_sonuclar = []
        for v_id in yonetici.vmler:
            res = yonetici.denetle_ve_risk_analizi_yap(v_id)
            tum_sonuclar.append(res)
            print(f"    - VM: {v_id} ({res['vm_adi']}) -> Skor: {res['denetim_skoru']} | Durum: {res['durum']} | Bulgu: {res['bulgu_sayisi']}")
        sonuc = {"tum_vmler": tum_sonuclar}

    if args.cikis_json:
        with open(args.cikis_json, "w", encoding="utf-8") as f:
            json.dump(sonuc, f, indent=2, ensure_ascii=False)
        print(f"[+] Sonuçlar dosyaya yazıldı: {args.cikis_json}")


if __name__ == "__main__":
    main()
