# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 014: Aşama 1 Kalite Özeti ve Güvenlik Temelleri Kabul Motoru (Stage 1 Capstone Auditor)
Usta-Çırak Siber Güvenlik Akademisi Laboratuvar Otomasyon Aracı

Bu modül; Aşama 01 (Gün 001 - Gün 013) boyunca inşa edilen tüm temel siber güvenlik yapı taşlarını:
1. Etik Sınırlar ve Kapsam Kuralları (RoE),
2. Varlık Envanteri ve Veri Sınıflandırması,
3. NIST CSF 2.0 Çerçevesinin 6 Temel İşlevi (Govern, Identify, Protect, Detect, Respond, Recover),
4. Sanallaştırma, Mikro-Segmentasyon ve Geri Dönüş (Rollback) Mimarisi,
5. CRAAP Kaynak Doğrulaması ve Zehirli PoC Kalkanı
ilkelerini tek bir kanıt zincirine (chain of evidence) bağlar ve 'Bir güvenlik önlemini tek başına
eksiksiz savunma sanma' yanılgısını denetleyerek kurumsal Aşama 1 Kabul Raporu üretir.
"""

import os  # Dosya ve dizin yolu denetimleri için standart kütüphane
import sys  # Sistem parametreleri ve hata çıkış kodları için
import json  # Laboratuvar kabul dosyasını ve denetim rubriğini ayrıştırmak için
import hashlib  # Bütünlük kanıt zincirinde SHA-256 kriptografik özet hesaplama
import argparse  # Profesyonel komut satırı arayüzü (CLI) parametre ayrıştırması için
from datetime import datetime, timezone  # Zaman damgası ve kabul tarihi oluşturma kütüphanesi
from typing import Dict, List, Any, Optional, Tuple  # Katı tip güvenliği ve statik doğrulama için


# --- ÖZEL İSTİSNA SINIFLARI (CUSTOM EXCEPTIONS) ---

class Stage1AuditError(Exception):
    """Aşama 1 denetim motorunun temel ata istisna sınıfı."""
    pass


class EthicalBoundaryViolationError(Stage1AuditError):
    """Etik sınırlar (RoE) ihlal edildiğinde veya yetkisiz üretim teması tespit edildiğinde fırlatılır (STOP)."""
    pass


class SingleMeasureFallacyError(Stage1AuditError):
    """'Bir güvenlik önlemini tek başına eksiksiz savunma sanma' yanılgısı tespit edildiğinde fırlatılır."""
    pass


class IncompleteChainOfEvidenceError(Stage1AuditError):
    """Kanıt zincirinde amaç, kapsam, varlık veya geri dönüş belgelerinden biri eksik olduğunda fırlatılır."""
    pass


# --- ÇEKİRDEK DENETİM VE KABUL MOTORU ---

class Stage1SecurityAuditor:
    """
    Aşama 1 güvenlik temelleri laboratuvar projelerini NIST CSF 2.0 ve RoE kapsamında denetleyen motor.
    """

    def __init__(self, dosya_yolu: Optional[str] = None):
        # Laboratuvar proje dosyası yolu atanır
        self.dosya_yolu = dosya_yolu
        # Bellekte tutulacak proje sözlüğü başlatılır
        self.projeler: Dict[str, Dict[str, Any]] = {}
        if dosya_yolu:
            self.dosya_yukle(dosya_yolu)

    def dosya_yukle(self, dosya_yolu: str) -> None:
        """
        JSON tabanlı Aşama 1 laboratuvar dosyasını doğrular ve belleğe yükler.
        """
        if not os.path.exists(dosya_yolu):
            raise FileNotFoundError(f"Aşama 1 laboratuvar kabul dosyası bulunamadı: {dosya_yolu}")

        with open(dosya_yolu, "r", encoding="utf-8") as f:
            veri = json.load(f)

        if "laboratuvar_projeleri" not in veri:
            raise Stage1AuditError("Geçersiz şema: 'laboratuvar_projeleri' listesi eksik.")

        self.projeler = {p["proje_id"]: p for p in veri["laboratuvar_projeleri"]}

    def denetle_laboratuvar_projesi(self, proje_id: str) -> Dict[str, Any]:
        """
        Belirtilen laboratuvar projesini 5 temel sütun ve NIST CSF 2.0 altı işlevine göre denetler:
        Toplam Puan: 100
        1. Etik RoE ve Kapsam Sınırları (20 Puan)
        2. Varlık Envanteri ve Sınıflandırma (15 Puan)
        3. NIST CSF 2.0 Altı İşlevi (40 Puan - Her işlev ~6.66 puan)
        4. Sanallaştırma ve Geri Dönüş Güvencesi (15 Puan)
        5. Kaynak Doğrulama ve CRAAP Güvenilirliği (10 Puan)
        """
        if proje_id not in self.projeler:
            raise Stage1AuditError(f"Tanımsız Proje Kimliği: {proje_id}")

        proje = self.projeler[proje_id]
        puan = 100.0
        bulgular = []
        kanit_zinciri = {}

        # 1. SÜTUN: ETİK ROE VE KAPSAM KONTROLÜ (20 Puan)
        roe = proje.get("etik_roe_kapsami", {})
        yazili_onay = roe.get("yazili_onay_var_mi", False)
        uretim_temas = roe.get("uretim_sistem_etkilesimi", False)
        dis_ag_erisim = roe.get("dis_ag_erisim_izni", False)
        hedef_ip = roe.get("hedef_ip_araligi", "")

        if not yazili_onay or uretim_temas or dis_ag_erisim or hedef_ip == "0.0.0.0/0":
            # ETİK İHLAL: Bu durum doğrudan STOP koşuludur!
            puan -= 40.0
            bulgular.append({
                "kod": "CRIT-01-ETIK-ROE-IHLALI",
                "seviye": "FELAKET_DURDURMA",
                "ceza": 40.0,
                "aciklama": "Yazılı onay eksik veya üretim sistemlerine / tüm internete açık yetkisiz test kapsamı tespit edildi! (Etik İhlal = STOP)"
            })
            kanit_zinciri["etik_roe"] = "GECERSIZ_VE_IHLALLI"
        else:
            kanit_zinciri["etik_roe"] = f"ONAYLI_KAPSAM ({hedef_ip})"

        # 2. SÜTUN: VARLIK ENVANTERİ VE VERİ SINIFLANDIRMASI (15 Puan)
        varlik = proje.get("varlik_envanteri_ve_siniflandirma", {})
        varlik_sayisi = varlik.get("toplam_varlik_sayisi", 0)
        sahip_tanimli = varlik.get("sahip_ve_sorumlular_belirlenmis_mi", False)

        if varlik_sayisi == 0 or not sahip_tanimli:
            puan -= 15.0
            bulgular.append({
                "kod": "WARN-02-EKSIK-VARLIK-ENVANTERI",
                "seviye": "YUKSEK",
                "ceza": 15.0,
                "aciklama": "Varlık envanteri tutulmamış veya kritik varlık sahipleri atanmamış. Korumak istediğin varlığı bilmeden güvenlik sağlayamazsın!"
            })
            kanit_zinciri["varlik_envanteri"] = "TANIMSIZ"
        else:
            kanit_zinciri["varlik_envanteri"] = f"{varlik_sayisi} Varlık Kayıtlı ve Sınıflandırılmış"

        # 3. SÜTUN: NIST CSF 2.0 ALTI İŞLEVİ UYUMLULUĞU (40 Puan)
        csf = proje.get("nist_csf_2_0_uyumluluk", {})
        islevler = ["govern_yonetisim", "identify_tanimlama", "protect_koruma", "detect_tespit", "respond_mudahale", "recover_kurtarma"]
        eksik_islevler = []
        islev_puani_birim = 40.0 / 6.0  # Yaklaşık 6.666 puan

        for islev in islevler:
            degerler = csf.get(islev, {})
            # Tüm alt kriterlerin True olup olmadığı kontrol edilir
            if not all(degerler.values()) or len(degerler) == 0:
                eksik_islevler.append(islev)
                puan -= islev_puani_birim

        if eksik_islevler:
            bulgular.append({
                "kod": "WARN-03-NIST-CSF-EKSIK-ISLEVLER",
                "seviye": "KRITIK",
                "ceza": round(len(eksik_islevler) * islev_puani_birim, 2),
                "aciklama": f"NIST CSF 2.0 altı temel işlevinden eksikler tespit edildi: {', '.join(eksik_islevler)}"
            })
        kanit_zinciri["nist_csf_2_0"] = f"6 İşlevden {6 - len(eksik_islevler)}'si Eksiksiz Tamamlandı"

        # 4. KONTROL: 'BİR GÜVENLİK ÖNLEMİNİ TEK BAŞINA EKSİKSİZ SAVUNMA SANMA' YANILGISI
        # Örnek: Protect (güvenlik duvarı) aktif ama Recover (kurtarma/yedek) veya Detect (tespit/log) yoksa
        protect_aktif = all(csf.get("protect_koruma", {}).values()) if csf.get("protect_koruma") else False
        recover_aktif = all(csf.get("recover_kurtarma", {}).values()) if csf.get("recover_kurtarma") else False
        detect_aktif = all(csf.get("detect_tespit", {}).values()) if csf.get("detect_tespit") else False

        if protect_aktif and (not recover_aktif or not detect_aktif or varlik_sayisi == 0):
            puan -= 20.0
            bulgular.append({
                "kod": "CRIT-04-TEK-ONLEME-GUVENME-YANILGISI",
                "seviye": "FELAKET",
                "ceza": 20.0,
                "aciklama": "Ölümcül Tuzak: Yalnızca güvenlik duvarına/korumaya güvenilmiş fakat kurtarma (recover) veya tespit (detect) ihmal edilmiş!"
            })

        # 5. SÜTUN: KAYNAK DOĞRULAMA VE CRAAP GÜVENİLİRLİĞİ (10 Puan)
        kaynak_bilgisi = proje.get("kaynak_dogrulama", {})
        craap_ortalamasi = kaynak_bilgisi.get("craap_skor_ortalamasi", 0.0)
        resmi_advisory = kaynak_bilgisi.get("resmi_nvd_ve_vendor_advisory_kullanimi", False)

        if craap_ortalamasi < 80.0 or not resmi_advisory:
            puan -= 10.0
            bulgular.append({
                "kod": "WARN-05-DOGRULANMAMIS-KAYNAK-KULLANIMI",
                "seviye": "ORTA",
                "ceza": 10.0,
                "aciklama": "Araştırmalarda kullanılan kaynakların CRAAP güvenilirlik skoru yetersiz (<80) veya resmî bülten teyidi eksik."
            })
            kanit_zinciri["kaynak_dogrulama"] = f"YETERRSIZ (CRAAP: {craap_ortalamasi:.1f})"
        else:
            kanit_zinciri["kaynak_dogrulama"] = f"DOGRULANMIS (CRAAP: {craap_ortalamasi:.1f})"

        # Puan sınırlandırması
        puan = max(0.0, min(100.0, round(puan, 2)))
        durum = "ASAMA_1_KABUL_PASS" if puan >= 80.0 else ("KOSULLU_TELAFİ" if puan >= 50.0 else "REDDEDILDI_TEHLIKELI")

        # Kriptografik kabul sertifikası özeti (SHA-256)
        sertifika_metni = f"{proje_id}-{puan}-{durum}-{kanit_zinciri.get('etik_roe')}"
        sertifika_hash = hashlib.sha256(sertifika_metni.encode("utf-8")).hexdigest()

        return {
            "proje_id": proje_id,
            "proje_basligi": proje.get("proje_basligi"),
            "denetim_puani": puan,
            "durum": durum,
            "kabul_edildi_mi": puan >= 80.0,
            "kanit_zinciri": kanit_zinciri,
            "kriptografik_sertifika_sha256": sertifika_hash,
            "bulgu_sayisi": len(bulgular),
            "bulgular": bulgular
        }


# --- KOMUT SATIRI ARAYÜZÜ (CLI) ---

def main():
    """CLI giriş noktası ve parametre işleyicisi."""
    parser = argparse.ArgumentParser(
        description="GÜN 014: Aşama 1 Kalite Özeti ve Güvenlik Temelleri Kabul Motoru",
        epilog="ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)"
    )
    parser.add_argument("--dosya", type=str, default="ornek_veri/asama_01_laboratuvar_dosyasi.json", help="Laboratuvar proje dosyası yolu")
    parser.add_argument("--proje-id", type=str, default="LAB-SEC-GOLDEN-01", help="Denetlenecek Proje Kimliği")
    parser.add_argument("--denetle", action="store_true", help="Belirtilen projenin Aşama 1 kabul denetimini çalıştır")
    parser.add_argument("--tumunu-denetle", action="store_true", help="Tüm laboratuvar projelerini topluca denetle")
    parser.add_argument("--cikis-json", type=str, help="Sonuçları JSON dosyası olarak kaydet")

    args = parser.parse_args()

    auditor = Stage1SecurityAuditor(args.dosya)
    sonuc = {}

    if args.denetle:
        print(f"[*] Aşama 1 Kabul Denetimi Başlatılıyor: Proje={args.proje_id}")
        sonuc = auditor.denetle_laboratuvar_projesi(args.proje_id)
        print(f"[+] Denetim Skoru: {sonuc['denetim_puani']} / 100 ({sonuc['durum']})")
        print(f"[+] Kriptografik Kanıt Zinciri: {sonuc['kriptografik_sertifika_sha256'][:16]}...")
        print(f"[+] Bulgu Sayısı: {sonuc['bulgu_sayisi']}")
        for b in sonuc["bulgular"]:
            print(f"    - [{b['seviye']}] {b['kod']}: {b['aciklama']} (-{b['ceza']}p)")

    elif args.tumunu_denetle:
        print("[*] Tüm Aşama 1 Laboratuvar Projeleri Denetleniyor...")
        raporlar = []
        for p_id in auditor.projeler:
            res = auditor.denetle_laboratuvar_projesi(p_id)
            raporlar.append(res)
            print(f"    - Proje: {p_id} -> Puan: {res['denetim_puani']} | Durum: {res['durum']} | Kabul: {res['kabul_edildi_mi']}")
        sonuc = {"tum_asama_1_projeleri": raporlar}

    else:
        # Varsayılan: Altın projeyi denetle
        sonuc = auditor.denetle_laboratuvar_projesi(args.proje_id)
        print(f"[+] Aşama 1 Kabul Kararı: {sonuc['durum']} (Puan: {sonuc['denetim_puani']})")

    if args.cikis_json:
        with open(args.cikis_json, "w", encoding="utf-8") as f:
            json.dump(sonuc, f, indent=2, ensure_ascii=False)
        print(f"[+] Sonuçlar dosyaya kaydedildi: {args.cikis_json}")


if __name__ == "__main__":
    main()
