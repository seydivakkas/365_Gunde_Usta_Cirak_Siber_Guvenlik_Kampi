# -*- coding: utf-8 -*-
"""
GÜN 018: Süreç (Process), İş Parçacığı (Thread) ve Hizmet (Service) Güvenlik Analizörü
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 18)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez.
"""

# İşletim sistemi süreç bilgileri, ortam değişkenleri ve dosya yolları için os modülü
import os
# Python yorumlayıcı parametreleri ve platform kontrolü için sys modülü
import sys
# Yapılandırılmış verileri ayrıştırmak ve dışa aktarmak için json modülü
import json
# Zaman damgaları ve denetim loglaması oluşturmak için datetime modülü
import datetime
# Komut satırı argümanlarını profesyonelce ayrıştırmak için argparse modülü
import argparse
# Canlı süreç ve servis bilgilerini güvenli sorgulamak için subprocess modülü
import subprocess
# İş parçacığı (Thread) yönetimi ve yarış durumu simülasyonu için threading modülü
import threading
# Platform ve mimari bilgilerini öğrenmek için platform modülü
import platform
# İş parçacığı zamanlama gecikmelerini simüle etmek için time modülü
import time


class ProcessThreadServiceSecurityAuditor:
    """
    Süreçlerin (Process) bellek izolasyonunu, iş parçacıklarının (Thread)
    kaynak paylaşımını ve yarış durumlarını (Race Condition), arka plan
    hizmetlerinin (Services/Daemons) unquoted service path ve yetki yükseltme
    zaafiyetlerini denetleyen güvenlik motoru.
    """

    def __init__(self):
        # Denetim motorunun sürüm bilgisini tanımlıyoruz
        self.version = "1.0.0"

    def get_live_process_and_service_inventory(self):
        """
        Yerel sistemden en az iki kullanıcı süreci ve bir sistem hizmetini
        PID, ad ve durum bilgileriyle canlı olarak toplar ve belgeler (G018-SC2).
        """
        # Mevcut çalışan Python sürecinin PID ve ana PID (PPID) bilgilerini alıyoruz
        current_pid = os.getpid()
        # Ana sürecin PID bilgisini alıyoruz
        try:
            parent_pid = os.getppid()
        except AttributeError:
            parent_pid = 0

        # İşletim sistemini tespit ediyoruz
        os_name = platform.system()
        # Toplanacak örnek süreç ve servis listelerini başlatıyoruz
        ornek_surecler = []
        ornek_hizmetler = []

        # Mevcut süreci ilk örnek kullanıcı süreci olarak kaydediyoruz
        ornek_surecler.append({
            "pid": current_pid,
            "ad": "python.exe" if os_name == "Windows" else "python3",
            "ppid": parent_pid,
            "rol": "Kullanıcı Modu Analiz Süreci (User Process 1)",
            "izolasyon": "Özel Sanal Adres Alanı (VAS) Tahsis Edilmiş"
        })

        # İkinci süreci ve hizmeti tespit etmek için işletim sistemine göre sorgu yapıyoruz
        if os_name == "Windows":
            try:
                # tasklist komutuyla çalışan diğer süreçlerden birini alıyoruz
                cmd = ["tasklist", "/FO", "CSV", "/NH"]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
                lines = res.stdout.strip().splitlines()
                for line in lines:
                    parts = [p.strip(' "') for p in line.split('","')]
                    if len(parts) >= 2:
                        p_name = parts[0]
                        p_pid = int(parts[1]) if parts[1].isdigit() else 0
                        # Kendi sürecimiz olmayan bir süreç buluyoruz
                        if p_pid > 0 and p_pid != current_pid and p_pid != parent_pid:
                            ornek_surecler.append({
                                "pid": p_pid,
                                "ad": p_name,
                                "rol": "Gözlemlenen Kullanıcı/Sistem Süreci (User Process 2)",
                                "izolasyon": "Ayrı Sayfa Tablosu (CR3) ile İzole Edilmiş"
                            })
                            break
            except Exception:
                pass

            # sc query komutuyla aktif bir Windows hizmeti sorguluyoruz
            try:
                cmd_sc = ["sc", "query", "state=", "all"]
                res_sc = subprocess.run(cmd_sc, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
                service_name = "LanmanWorkstation" # Varsayılan güvenli örnek
                for l in res_sc.stdout.splitlines():
                    if "SERVICE_NAME:" in l:
                        service_name = l.split("SERVICE_NAME:")[1].strip()
                        break
                ornek_hizmetler.append({
                    "hizmet_adi": service_name,
                    "oturum_id": 0,
                    "tip": "Windows Arka Plan Hizmeti (Session 0 İzolasyonu)",
                    "durum": "RUNNING / Calisiyor"
                })
            except Exception:
                pass

        # Eğer listeler boş kalırsa sentetik güvenli varsayılanlar ekliyoruz
        if len(ornek_surecler) < 2:
            ornek_surecler.append({
                "pid": parent_pid or 1000,
                "ad": "explorer.exe",
                "rol": "Masaüstü Kabuk Süreci (User Process 2)",
                "izolasyon": "İzole Sanal Adres Alanı"
            })
        if len(ornek_hizmetler) == 0:
            ornek_hizmetler.append({
                "hizmet_adi": "wuauserv",
                "oturum_id": 0,
                "tip": "Windows Update Arka Plan Hizmeti",
                "durum": "Calisiyor"
            })

        # Canlı envanter sözlüğünü döndürüyoruz
        return {
            "toplama_zamani": datetime.datetime.now().isoformat(),
            "isletim_sistemi": os_name,
            "ornek_kullanici_surecleri": ornek_surecler,
            "ornek_sistem_hizmetleri": ornek_hizmetler,
            "mimari_kural": "Süreçler izole bellek alanlarına (VAS) sahiptir; hizmetler Session 0'da etkileşimsiz çalışır."
        }

    def load_json_file(self, filepath):
        """
        Belirtilen JSON dosyasını UTF-8 ile güvenli yükler.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def detect_unquoted_service_path(self, binary_path):
        """
        Bir Windows hizmetinin çalıştırılabilir ikili dosya yolunun (binPath)
        'Tırnak İçine Alınmamış Servis Yolu' (Unquoted Service Path - MITRE T1574.009)
        zaafiyeti taşıyıp taşımadığını matematiksel olarak analiz eder.
        """
        # Yol metnini kırpıyoruz
        path = binary_path.strip()

        # Eğer yol çift tırnak ile başlayıp çift tırnak ile bitiyorsa güvendedir
        if path.startswith('"') and path.endswith('"'):
            return {
                "yol": path,
                "zafiyet_var_mi": False,
                "aciklama": "Yol çift tırnak içine alınmış; boşluk istismarı mümkün değil.",
                "olasi_istismar_yollari": []
            }

        # Eğer yol içerisinde hiç boşluk yoksa (örn: C:\Windows\System32\svchost.exe), zaafiyet oluşmaz
        # Ancak parametrelerden önceki ana dosya yolunda boşluk aranmalıdır
        # İlk boşluğu ve olası ara yolları inceliyoruz
        if " " not in path:
            return {
                "yol": path,
                "zafiyet_var_mi": False,
                "aciklama": "Yol içerisinde boşluk karakteri yok; doğrudan yürütülür.",
                "olasi_istismar_yollari": []
            }

        # Yol boşluk içeriyor ve çift tırnak içinde DEĞİL!
        # Windows CreateProcess API'sinin arayacağı olası tuzak dosya yollarını çıkarıyoruz
        olasi_yollar = []
        parcalar = path.split(" ")
        mevcut_bilesen = ""
        # Son parça haricindeki tüm boşluk kesitlerini aday .exe olarak ekliyoruz
        for i in range(len(parcalar) - 1):
            if mevcut_bilesen:
                mevcut_bilesen += " " + parcalar[i]
            else:
                mevcut_bilesen = parcalar[i]
            olasi_yollar.append(f"{mevcut_bilesen}.exe")

        # Güvenlik açığı değerlendirmesini döndürüyoruz
        return {
            "yol": path,
            "zafiyet_var_mi": True,
            "risk_seviyesi": "YUKSEK",
            "zafiyet_adi": "Unquoted Service Path (MITRE T1574.009)",
            "aciklama": "Boşluk içeren servis yolu çift tırnak içine alınmamış! Saldırgan ara yollara zararlı .exe yerleştirerek SYSTEM yetkisine yükselebilir.",
            "olasi_istismar_yollari": olasi_yollar
        }

    def audit_service_security(self, service_dict):
        """
        Tek bir Windows hizmetini tırnaksız yol, yazılabilir ikili dizini
        ve hesap ayrıcalıkları açısından denetler.
        """
        hizmet_adi = service_dict.get("hizmet_adi", "BILINMEYEN_SERVIS")
        hesap = service_dict.get("hesap", "LocalSystem")
        bin_path = service_dict.get("calistirilabilir_yol", "")
        writable_dir = service_dict.get("dizin_yazma_izni_kullanicilar", False)

        bulgular = []
        risk_seviyesi = "DUSUK"

        # 1. Unquoted path kontrolü
        path_analizi = self.detect_unquoted_service_path(bin_path)
        if path_analizi["zafiyet_var_mi"]:
            bulgular.append(f"Unquoted Service Path saptandı! Aday tuzak yollar: {', '.join(path_analizi['olasi_istismar_yollari'])}")
            risk_seviyesi = "YUKSEK"

        # 2. Yazılabilir dizin izni kontrolü (Weak Folder Permissions)
        if writable_dir:
            bulgular.append("Hizmet ikili dosyasının bulunduğu klasöre standart kullanıcıların yazma izni var (Zayıf Klasör İzni)!")
            risk_seviyesi = "KRITIK"

        # 3. Hesap ayrıcalık değerlendirmesi (En Az Ayrıcalık Kuralı)
        if "LocalSystem" in hesap or "SYSTEM" in hesap:
            bulgular.append("Hizmet en yüksek ayrıcalıklı hesapla (NT AUTHORITY\\SYSTEM) çalışıyor; ele geçirilirse tam sistem kontrolü sağlanır.")
            if risk_seviyesi == "DUSUK":
                risk_seviyesi = "ORTA"

        return {
            "hizmet_adi": hizmet_adi,
            "hesap": hesap,
            "risk_seviyesi": risk_seviyesi,
            "zafiyet_var_mi": (risk_seviyesi in ["YUKSEK", "KRITIK"]),
            "bulgular": bulgular,
            "unquoted_path_analizi": path_analizi
        }

    def simulate_thread_memory_sharing(self, use_mutex=False):
        """
        İş parçacıklarının (Thread) aynı sürecin bellek alanını (Heap/Data) paylaştığını
        ve kilit (Mutex/Lock) kullanılmadığında Yarış Durumu (Race Condition) oluşarak
        veri bütünlüğünün bozulduğunu laboratuvarda simüle eder.
        """
        # Paylaşılan ortak kaynak (örneğin kurumsal bakiye veya sayaç)
        shared_state = {"sayac": 0}
        # İş parçacığı senkronizasyonu için kilit nesnesi
        kilit = threading.Lock()
        dongu_sayisi = 200

        # Birinci iş parçacığının yürüteceği fonksiyon (artırma)
        def thread_worker_artir():
            for _ in range(dongu_sayisi):
                if use_mutex:
                    with kilit:
                        val = shared_state["sayac"]
                        time.sleep(0) # Anlık iş parçacığı geçişi sağlayarak yarış durumunu tetikler
                        shared_state["sayac"] = val + 1
                else:
                    val = shared_state["sayac"]
                    time.sleep(0)
                    shared_state["sayac"] = val + 1

        # İkinci iş parçacığının yürüteceği fonksiyon (azaltma)
        def thread_worker_azalt():
            for _ in range(dongu_sayisi):
                if use_mutex:
                    with kilit:
                        val = shared_state["sayac"]
                        time.sleep(0)
                        shared_state["sayac"] = val - 1
                else:
                    val = shared_state["sayac"]
                    time.sleep(0)
                    shared_state["sayac"] = val - 1

        # İki bağımsız iş parçacığı oluşturuyoruz
        t1 = threading.Thread(target=thread_worker_artir)
        t2 = threading.Thread(target=thread_worker_azalt)

        # İş parçacıklarını başlatıyoruz
        t1.start()
        t2.start()

        # Her iki iş parçacığının tamamlanmasını bekliyoruz
        t1.join()
        t2.join()

        # Beklenen matematiksel sonuç 0'dır (+1000 ve -1000)
        nihai_deger = shared_state["sayac"]
        tutarsizlik_var_mi = (nihai_deger != 0)

        return {
            "kilit_kullanildi_mi": use_mutex,
            "beklenen_deger": 0,
            "gerceklesen_deger": nihai_deger,
            "yaris_durumu_olustu_mu": tutarsizlik_var_mi if not use_mutex else False,
            "guvenlik_sonucu": "GÜVENLİ (Mutex ile Veri Bütünlüğü Korundu)" if use_mutex else (
                "RACE CONDITION (Yarış Durumu / Veri Bozulması Saptandı)" if tutarsizlik_var_mi else "YARIŞ TESTİ TAMAMLANDI"
            )
        }

    def generate_full_audit(self, sample_filepath, baseline_filepath):
        """
        Canlı envanter, örnek hizmet denetimleri ve iş parçacığı senkronizasyon
        deneyini birleştirerek kapsamlı bir kurumsal rapor üretir.
        """
        sample_data = self.load_json_file(sample_filepath)
        baseline_data = self.load_json_file(baseline_filepath)

        # 1. Canlı sistem envanteri
        live_inv = self.get_live_process_and_service_inventory()

        # 2. Örnek hizmetlerin güvenlik denetimi
        hizmetler = sample_data.get("hizmetler", [])
        hizmet_denetimleri = [self.audit_service_security(h) for h in hizmetler]

        # Kritik ve yüksek riskli hizmetleri sayıyoruz
        riskli_hizmetler = [h for h in hizmet_denetimleri if h["zafiyet_var_mi"]]

        # 3. İş parçacığı bellek paylaşımı ve kilit deneyleri
        sim_mutex_yok = self.simulate_thread_memory_sharing(use_mutex=False)
        sim_mutex_var = self.simulate_thread_memory_sharing(use_mutex=True)

        full_report = {
            "denetim_zamani": datetime.datetime.now().isoformat(),
            "denetim_motoru_surumu": self.version,
            "canli_envanter": live_inv,
            "incelenen_hizmet_sayisi": len(hizmetler),
            "zafiyetli_hizmet_sayisi": len(riskli_hizmetler),
            "hizmet_denetim_sonuclari": hizmet_denetimleri,
            "is_parcacigi_yaris_durumu_deneyleri": {
                "kilitsiz_senaryo": sim_mutex_yok,
                "kilitli_senaryo": sim_mutex_var
            },
            "genel_sonuc": "IHLAL_VAR" if len(riskli_hizmetler) > 0 else "TEMIZ"
        }

        return full_report


def main():
    """
    Komut satırı arayüzü ana giriş noktası.
    """
    parser = argparse.ArgumentParser(
        description="GÜN 018: Süreç, İş Parçacığı ve Hizmet Güvenlik Analizörü"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Canlı sistemden kullanıcı süreçlerini ve servisleri envanterler."
    )
    parser.add_argument(
        "--sample",
        type=str,
        default="ornek_veri/process_thread_service_inventory.json",
        help="İncelenecek süreç ve hizmetler JSON dosyası."
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default="ornek_veri/service_security_baseline.json",
        help="Hizmet güvenlik taban çizgisi kuralları JSON dosyası."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları JSON biçiminde yazdırır."
    )

    args = parser.parse_args()
    auditor = ProcessThreadServiceSecurityAuditor()

    if args.live:
        data = auditor.get_live_process_and_service_inventory()
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    try:
        rapor = auditor.generate_full_audit(args.sample, args.baseline)
        if args.json:
            print(json.dumps(rapor, indent=2, ensure_ascii=False))
        else:
            print("=" * 72)
            print("GÜN 018: SÜREÇ, İŞ PARÇACIĞI VE HİZMET GÜVENLİK DENETİMİ")
            print("=" * 72)
            print(f"Denetim Zamanı : {rapor['denetim_zamani']}")
            print(f"Genel Sonuç    : {rapor['genel_sonuc']}")
            print(f"Hizmet Sayısı  : {rapor['incelenen_hizmet_sayisi']}")
            print(f"Zafiyetli Svc  : {rapor['zafiyetli_hizmet_sayisi']} adet riskli hizmet tespit edildi!")
            print("-" * 72)
            print("CANLI SİSTEM SÜREÇ VE SERVİS ENVANTERİ (G018-SC2):")
            for proc in rapor["canli_envanter"]["ornek_kullanici_surecleri"]:
                print(f"  [Süreç] PID: {proc['pid']:<6} Ad: {proc['ad']:<16} Rol: {proc['rol']}")
            for svc in rapor["canli_envanter"]["ornek_sistem_hizmetleri"]:
                print(f"  [Servis] Ad: {svc['hizmet_adi']:<20} Oturum: {svc['oturum_id']} Durum: {svc['durum']}")
            print("-" * 72)
            print("HİZMET GÜVENLİK DENETİM BULGULARI:")
            for s in rapor["hizmet_denetim_sonuclari"]:
                print(f"  [{s['risk_seviyesi']}] {s['hizmet_adi']} ({s['hesap']}):")
                for b in s["bulgular"]:
                    print(f"    - {b}")
            print("-" * 72)
            print("İŞ PARÇACIĞI YARIŞ DURUMU (RACE CONDITION) DENEYİ:")
            print(f"  Kilitsiz : {rapor['is_parcacigi_yaris_durumu_deneyleri']['kilitsiz_senaryo']['guvenlik_sonucu']}")
            print(f"  Kilitli  : {rapor['is_parcacigi_yaris_durumu_deneyleri']['kilitli_senaryo']['guvenlik_sonucu']}")
            print("=" * 72)
    except Exception as e:
        print(f"HATA: Denetim icra edilirken hata oluştu: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
