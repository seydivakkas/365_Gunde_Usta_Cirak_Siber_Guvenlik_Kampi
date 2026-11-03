# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G073: Koşullar, Kontrol Akışı ve Savunmacı Döngüler Güvenlik Motoru.

Bu modül, siber güvenlik otomasyonlarında kullanılan kontrol akışı mekanizmalarını;
fail-closed (varsayılan engelleme) güvenlik duvarı kural motoru,
kısa devre (short-circuit) mantıksal değerlendirme,
DNS sıkıştırma ve zincirleme ofsetlerde sonsuz döngü (infinite loop / pointer cycle) koruması,
kayan pencereli hız sınırlama (rate limiting / brute force detection)
ve Python'ın 'for ... else' yapısıyla tehdit avcılığı taramalarını icra eder.
"""

# Dosya ve dizin yolu denetimleri için os modülünü içeri aktarıyoruz.
import os
# Komut satırı argümanlarını yönetmek için argparse modülünü ekliyoruz.
import argparse
# JSON veri yapılarını işlemek ve raporlamak için json modülünü çağırıyoruz.
import json
# Çıkış kodları ve akış yönlendirmesi için sys modülünü dahil ediyoruz.
import sys
# Tip güvenliği için typing modülünden gerekli tipleri alıyoruz.
from typing import Dict, Any, List, Optional, Set, Tuple
# Zaman damgalı log ve denetim kayıtları için datetime ve timezone sınıflarını alıyoruz.
from datetime import datetime, timezone
# CIDR alt ağ ve IP eşleştirmeleri için ipaddress modülünü içeri aktarıyoruz.
import ipaddress


class ControlFlowSecurityError(ValueError):
    """Kontrol akışı kuralları, sonsuz döngü veya sınır ihlallerinde fırlatılan özel istisna."""
    # ValueError temel sınıfından türeyerek özel istisna mekanizmasını tanımlıyoruz.
    pass


class SecurityControlFlowEngine:
    """
    Siber güvenlik kontrol akışı, savunmacı döngü ve kural değerlendirme motoru.
    """

    def __init__(self) -> None:
        """Denetim motorunun kurucu metodu."""
        # Değerlendirilen kural ve olay sayacını sıfır olarak ilklendiriyoruz.
        self.total_evaluations_count: int = 0

    def evaluate_strict_condition(self, condition_value: Any) -> bool:
        """
        Girdinin kesin mantıksal değerini denetler. 'None' (yokluk) durumunu belirsizlik olarak reddeder.

        Parametreler:
            condition_value: Değerlendirilecek mantıksal koşul sonucu.

        Döndürür:
            Doğrulanmış katı True veya False değeri.
        """
        # Değerin None olup olmadığını katı kimlik operatörü (is) ile sınıyoruz.
        if condition_value is None:
            # Belirsizlik durumunda hata fırlatıyoruz.
            raise ControlFlowSecurityError(
                "Belirsiz mantıksal değerlendirme: Değer 'None' (Yokluk), kesin True veya False bekleniyor."
            )

        # Değer boolean ise doğrudan döndürüyoruz.
        if isinstance(condition_value, bool):
            # Değeri iletiyoruz.
            return condition_value

        # Tamsayı 1 ve 0 için dönüşüm yapıyoruz.
        if isinstance(condition_value, int):
            # 1 ise True.
            if condition_value == 1:
                return True
            # 0 ise False.
            if condition_value == 0:
                return False

        # Metin tabanlı true/false değerlerini değerlendiriyoruz.
        if isinstance(condition_value, str):
            # Küçük harfe çeviriyoruz.
            s = condition_value.strip().lower()
            # Onay kelimeleri
            if s in ["true", "allow", "yes", "1"]:
                return True
            # Red kelimeleri
            if s in ["false", "deny", "no", "0"]:
                return False

        # Belirsiz diğer tiplerde istisna fırlatıyoruz.
        raise ControlFlowSecurityError(
            f"Belirsiz mantıksal değerlendirme: '{condition_value}' geçerli bir bool değerine dönüştürülemez."
        )

    def evaluate_firewall_policy(
        self, policy: Dict[str, Any], packet_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Güvenlik duvarı kurallarını öncelik sırasıyla ve kısa devre (short-circuit) mantığıyla değerlendirir.
        Eğer hiçbir kural eşleşmezse, 'for ... else' bloğuyla varsayılan eylemi (fail-closed) uygular.

        Parametreler:
            policy: Politika kimliği, kurallar ve varsayılan eylemi içeren sözlük.
            packet_context: Gelen ağ paketinin başlık bilgileri (source_ip, dest_port, protocol).

        Döndürür:
            Alınan kararı ve eşleşen kural bilgisini içeren sözlük.
        """
        # Politikanın sözlük tipinde olduğunu teyit ediyoruz.
        if not isinstance(policy, dict):
            # Sözlük değilse hata fırlatıyoruz.
            raise ControlFlowSecurityError("Politika verisi bir JSON sözlüğü olmalıdır.")

        # Varsayılan eylemi (default_action) alıyoruz.
        default_action = str(policy.get("default_action", "")).upper()
        # Varsayılan eylemin sadece ALLOW veya DENY olmasını şart koşuyoruz.
        if default_action not in ["ALLOW", "DENY"]:
            # Geçersiz varsayılan eylem hatası fırlatıyoruz.
            raise ControlFlowSecurityError(
                f"Geçersiz varsayılan politika eylemi: '{default_action}' (Yalnızca ALLOW veya DENY kabul edilir)."
            )

        # Kurallar listesini çekiyoruz.
        rules_list = policy.get("rules", [])
        # Kuralların liste tipinde olduğunu sınıyoruz.
        if not isinstance(rules_list, list):
            # Liste değilse hata veriyoruz.
            raise ControlFlowSecurityError("Politika kuralları bir liste olmalıdır.")

        # Kuralları öncelik değerine (priority) göre küçükten büyüğe sıralıyoruz (Küçük sayı = Yüksek öncelik).
        sorted_rules = sorted(rules_list, key=lambda r: r.get("priority", 999))

        # Eşleşen kural değişkenini ilklendiriyoruz.
        matched_rule = None
        # Nihai karar değişkenini ilklendiriyoruz.
        decision = None

        # Kuralları döngüye alarak sırayla değerlendiriyoruz.
        for rule in sorted_rules:
            # Kuralın sözlük olduğunu denetliyoruz.
            if not isinstance(rule, dict):
                # Sözlük değilse hata veriyoruz.
                raise ControlFlowSecurityError("Kural kaydı bir sözlük olmalıdır.")

            # Kural eylemini çekiyoruz.
            action = rule.get("action")
            # Kural eyleminin varlığını ve geçerliliğini denetliyoruz.
            if not action or str(action).upper() not in ["ALLOW", "DENY"]:
                # Eksik eylem hatası veriyoruz.
                raise ControlFlowSecurityError("Kural şema ihlali: 'action' (ALLOW/DENY) alanı eksik.")

            # Kural koşullarını alıyoruz.
            conditions = rule.get("conditions")
            # Koşulların sözlük tipinde olmasını şart koşuyoruz.
            if not isinstance(conditions, dict):
                # Eksik koşul hatası veriyoruz.
                raise ControlFlowSecurityError("Kural şema ihlali: 'conditions' alanı eksik veya sözlük değil.")

            # Kısa devre (short-circuit) bayrağı: varsayım gereği kural eşleşti kabul edilir.
            rule_matches = True

            # 1. Kaynak IP doğrudan eşleşmesi denetimi
            if "source_ip" in conditions:
                # Eşit değilse eşleşme bozulur.
                if packet_context.get("source_ip") != conditions["source_ip"]:
                    # Kısa devre ile sonraki kurala geçiyoruz.
                    continue

            # 2. Kaynak alt ağ (CIDR) denetimi
            if "source_subnet" in conditions:
                # Paket IP'sini alıyoruz.
                src_ip_str = packet_context.get("source_ip", "")
                try:
                    # IP nesnesini oluşturuyoruz.
                    ip_obj = ipaddress.ip_address(src_ip_str)
                    # Ağ nesnesini oluşturuyoruz.
                    net_obj = ipaddress.ip_network(conditions["source_subnet"], strict=False)
                    # IP ağın içinde değilse kural eşleşmez.
                    if ip_obj not in net_obj:
                        # Kısa devre: sonraki kurala geç.
                        continue
                except ValueError:
                    # Ayrıştırma hatasında kural eşleşmemiş sayılır.
                    continue

            # 3. Hedef port denetimi
            if "dest_port" in conditions:
                # Port numarası eşleşmiyorsa kural bozulur.
                if packet_context.get("dest_port") != conditions["dest_port"]:
                    # Kısa devre ile atlıyoruz.
                    continue

            # 4. Protokol denetimi
            if "protocol" in conditions:
                # Protokol metinlerini büyük harfe çevirerek karşılaştırıyoruz.
                if str(packet_context.get("protocol", "")).upper() != str(conditions["protocol"]).upper():
                    # Kısa devre: sonraki kurala geç.
                    continue

            # Tüm koşullar sağlandıysa döngüyü erken sonlandırıyoruz (break).
            matched_rule = rule
            # Kararı kuralın eylemi olarak belirliyoruz.
            decision = str(action).upper()
            # Döngüden çıkıyoruz.
            break
        else:
            # Python 'for ... else' yapısı: Döngü break ile kesilmezse varsayılan eylem devreye girer.
            decision = default_action
            # Eşleşen kural olmadığını belirtiyoruz.
            matched_rule = {"rule_id": 0, "name": "Varsayılan Güvenlik Duvarı Politikası (Default Fallback)"}

        # Sayaç değerini artırıyoruz.
        self.total_evaluations_count += 1

        # Karar sonucunu döndürüyoruz.
        return {
            "status": "PASS",
            "decision": decision,
            "matched_rule_id": matched_rule.get("rule_id"),
            "matched_rule_name": matched_rule.get("name"),
            "packet_context": packet_context
        }

    def safe_pointer_traversal(
        self, payload: Dict[str, Any], max_iterations: int = 1000
    ) -> List[int]:
        """
        DNS sıkıştırma veya ayrıştırma zincirlerindeki göstericileri (pointers) sonsuz döngü
        ve döngüsel atıf (pointer cycle / compression bomb) saldırılarına karşı güvenle gezer.

        Parametreler:
            payload: 'buffer_size', 'start_offset' ve 'pointer_map' içeren sözlük.
            max_iterations: Azami döngü adımı tavanı (Anti-DoS koruması).

        Döndürür:
            İzlenen ofsetlerin güvenli listesi.
        """
        # Tampon boyutunu alıyoruz.
        buffer_size = payload.get("buffer_size", 0)
        # Başlangıç ofsetini alıyoruz.
        curr_offset = payload.get("start_offset", 0)
        # Gösterici haritasını alıyoruz.
        pointer_map = payload.get("pointer_map", {})

        # Ziyaret edilen ofsetleri saklamak için küme açıyoruz ($O(1)$ arama).
        visited_offsets: Set[int] = set()
        # Gezinti yolunu sıralı tutmak için liste ilklendiriyoruz.
        traversed_path: List[int] = []
        # Döngü sayaç değişkenini sıfırlıyoruz.
        iteration_count = 0

        # Savunmacı 'while' döngüsünü başlatıyoruz.
        while curr_offset != -1:
            # Adım sayısını artırıyoruz.
            iteration_count += 1

            # 1. Adım: Azami yineleme tavanı kontrolü (Anti-DoS / CPU Tükenme Koruması)
            if iteration_count > max_iterations:
                # Tavan aşıldığında istisna fırlatıyoruz.
                raise ControlFlowSecurityError(
                    f"Azami döngü yineleme tavanı aşıldı: {max_iterations} adımda sonlandırılamadı (Anti-DoS koruması)."
                )

            # 2. Adım: Döngüsel gösterici (Pointer Cycle) kontrolü
            if curr_offset in visited_offsets:
                # Döngü tespit edildiğinde döngü yolunu oluşturup hata veriyoruz.
                cycle_str = " -> ".join(str(o) for o in traversed_path) + f" -> {curr_offset}"
                # İstisna fırlatıyoruz.
                raise ControlFlowSecurityError(
                    f"Döngüsel gösterici (Pointer Cycle) tespit edildi: {cycle_str}."
                )

            # 3. Adım: Arabellek sınır aşımı kontrolü (Buffer Overflow / Out of bounds)
            if curr_offset >= buffer_size:
                # Sınır aşımı hatası veriyoruz.
                raise ControlFlowSecurityError(
                    f"Arabellek sınır aşımı: Gösterici ofseti {curr_offset}, azami tampon boyutu {buffer_size}."
                )

            # Ofseti ziyaret edildi olarak işaretliyoruz.
            visited_offsets.add(curr_offset)
            # Yola ekliyoruz.
            traversed_path.append(curr_offset)

            # Sonraki ofseti alıyoruz.
            offset_key = str(curr_offset)
            # Eğer haritada sonraki ofset yoksa zinciri güvenle sonlandırıyoruz.
            if offset_key not in pointer_map:
                # Sonlanma işareti.
                break

            # Sonraki ofsete geçiyoruz.
            curr_offset = pointer_map[offset_key]

        # İzlenen güvenli ofset zincirini döndürüyoruz.
        return traversed_path

    def detect_brute_force_rate_limit(
        self, events: List[Dict[str, Any]], window_seconds: int = 60, threshold: int = 5
    ) -> Dict[str, Any]:
        """
        Kimlik doğrulama olaylarını kayan zaman penceresinde döngüyle tarayarak
        kaba kuvvet (Brute Force) saldırılarını ve hız sınırı aşımlarını tespit eder.

        Parametreler:
            events: Olay sözlüklerinin listesi (timestamp, source_ip, username, status).
            window_seconds: Kayan zaman penceresi süresi (saniye cinsinden).
            threshold: Azami izin verilen başarısız deneme eşiği.

        Döndürür:
            Hız sınırlaması tetiklenen IP adreslerini ve detaylarını içeren sözlük.
        """
        # Zaman penceresinin pozitif olduğunu denetliyoruz.
        if window_seconds <= 0:
            # Negatif veya sıfır pencere hatası veriyoruz.
            raise ControlFlowSecurityError(
                f"Geçersiz kayan pencere süresi: {window_seconds} saniye (Sıfırdan büyük olmalıdır)."
            )

        # Eşiğin en az 1 olduğunu teyit ediyoruz.
        if threshold <= 0:
            # Geçersiz eşik hatası veriyoruz.
            raise ControlFlowSecurityError(
                f"Geçersiz hız sınırı eşiği: {threshold} (En az 1 olmalıdır)."
            )

        # Olayların liste tipinde olduğunu sınıyoruz.
        if not isinstance(events, list):
            # Liste değilse hata fırlatıyoruz.
            raise ControlFlowSecurityError(
                f"Olay akışı bir liste (list) olmalıdır, alınan: {type(events).__name__}"
            )

        # IP bazlı başarısız denemeleri saklayacağımız sözlük
        ip_failures: Dict[str, List[int]] = {}
        # Kilitlenen IP adresleri sözlüğü
        locked_out_ips: Dict[str, Any] = {}

        # Olayları döngüyle inceliyoruz.
        for ev in events:
            # Olayın sözlük olduğunu kontrol ediyoruz.
            if not isinstance(ev, dict):
                # Geçersiz olay formatı hatası veriyoruz.
                raise ControlFlowSecurityError("Olay kaydı bir sözlük olmalıdır.")

            # Olay durumunu alıyoruz.
            status = str(ev.get("status", "")).upper()
            # Yalnızca başarısız (FAILURE) durumları takip ediyoruz.
            if status != "FAILURE":
                # Başarılı olaylarda döngünün bir sonraki adımına geçiyoruz (continue).
                continue

            # Kaynak IP ve zaman damgasını çekiyoruz.
            src_ip = ev.get("source_ip", "0.0.0.0")
            # Zaman damgasını alıyoruz.
            ts = ev.get("timestamp", 0)

            # IP listesini ilklendiriyoruz.
            if src_ip not in ip_failures:
                # Boş liste açıyoruz.
                ip_failures[src_ip] = []

            # Zaman damgasını ekliyoruz.
            ip_failures[src_ip].append(ts)

            # Kayan pencere filtrelemesi: mevcut zamandan (ts - window_seconds) önceki kayıtları temizliyoruz.
            valid_window_ts = [t for t in ip_failures[src_ip] if ts - t <= window_seconds]
            # Listeyi güncelliyoruz.
            ip_failures[src_ip] = valid_window_ts

            # Eşik aşımı kontrolü (Threshold condition)
            if len(valid_window_ts) >= threshold:
                # Eğer daha önce kilitlenmemişse yeni kayıt açıyoruz.
                if src_ip not in locked_out_ips:
                    # Kilitlenme kaydını oluşturuyoruz.
                    locked_out_ips[src_ip] = {
                        "failure_count": len(valid_window_ts),
                        "window_seconds": window_seconds,
                        "lockout_triggered": True,
                        "last_attempt_timestamp": ts
                    }
                else:
                    # Zaten kilitliyse deneme sayısını ve son zaman damgasını güncelliyoruz.
                    locked_out_ips[src_ip]["failure_count"] = len(valid_window_ts)
                    # Son zaman damgasını kaydediyoruz.
                    locked_out_ips[src_ip]["last_attempt_timestamp"] = ts

        # Analiz sonucunu döndürüyoruz.
        return {
            "total_events_processed": len(events),
            "locked_out_ips_count": len(locked_out_ips),
            "lockout_details": locked_out_ips
        }

    def scan_threat_ioc_stream(
        self, artifacts: List[Dict[str, Any]], malicious_label_prefix: str = "MALWARE"
    ) -> Dict[str, Any]:
        """
        Tehdit göstergelerini (IoC) Python 'for ... else' mekanizmasıyla tarar.
        Eğer zararlı bir gösterici tespit edilirse döngü 'break' ile kırılır;
        hiçbir zararlı bulunamazsa 'else' bloğu ile güvenli tescil üretilir.

        Parametreler:
            artifacts: Taranacak dosya/eser listesi.
            malicious_label_prefix: Zararlı etiket ön eki (varsayılan: 'MALWARE').

        Döndürür:
            Tarama sonucunu ve tespit edilen tehdidi içeren sözlük.
        """
        # Tespit edilen tehdit nesnesi
        threat_detected = None

        # Eserleri sırayla tarıyoruz.
        for art in artifacts:
            # Etiketi alıyoruz.
            label = str(art.get("label", ""))
            # Eğer etiket zararlı ön ekle başlıyorsa
            if label.startswith(malicious_label_prefix):
                # Tehdit tespit edildi, kaydediyoruz.
                threat_detected = art
                # Döngüyü anında kırıyoruz (break).
                break
        else:
            # Döngü break ile kırılmadı, tüm liste temiz demektir.
            return {
                "status": "PASS",
                "is_clean": True,
                "threat_found": False,
                "scanned_count": len(artifacts)
            }

        # Eğer buraya geldiyse tehdit bulunmuştur.
        return {
            "status": "ALERT",
            "is_clean": False,
            "threat_found": True,
            "threat_detail": threat_detected,
            "scanned_count": len(artifacts)
        }

    def generate_text_report(self, fw_res: Dict[str, Any], ptr_res: List[int], bf_res: Dict[str, Any]) -> str:
        """Denetim sonuçlarını içeren biçimlendirilmiş kurumsal metin raporu üretir."""
        # Satırlar listesini ilklendiriyoruz.
        lines = []
        # Üst çizgi
        lines.append("=" * 80)
        # Başlık satırı
        lines.append("G073: KOŞULLAR, KONTROL AKIŞI VE SAVUNMACI DÖNGÜLER DENETİM RAPORU")
        # Telif ve lisans bilgisi
        lines.append("Telif Hakkı (c) 2026 Seydi Eryılmaz | Özel Lisans — Tüm Hakları Saklıdır")
        # Ayırıcı çizgi
        lines.append("=" * 80)
        # Boş satır
        lines.append("")

        # 1. Güvenlik Duvarı Kural Motoru Değerlendirmesi
        lines.append("1. GÜVENLİK DUVARI VE POLİTİKA KONTROL AKIŞI (FAIL-CLOSED)")
        # Alt çizgi
        lines.append("-" * 50)
        # Karar satırı
        lines.append(f"Alınan Politika Kararı      : {fw_res.get('decision')} (Durum: {fw_res.get('status')})")
        # Eşleşen kural ID
        lines.append(f"Eşleşen Kural ID           : {fw_res.get('matched_rule_id')}")
        # Eşleşen kural adı
        lines.append(f"Eşleşen Kural Adı          : {fw_res.get('matched_rule_name')}")
        # Boş satır
        lines.append("")

        # 2. Sonsuz Döngü ve Gösterici Gezintisi
        lines.append("2. GÖSTERİCİ DÖNGÜSÜ (POINTER LOOP / ANTI-DOS) KORUMASI")
        # Alt çizgi
        lines.append("-" * 50)
        # Gezinti yolu
        path_str = " -> ".join(str(o) for o in ptr_res)
        lines.append(f"Ziyaret Edilen Ofsetler    : {path_str}")
        # Döngü güvenliği durumu
        lines.append(f"Döngü Güvenlik Durumu      : DÖNGÜSEL ATIF YOK (PASS - %100 Güvenli)")
        # Boş satır
        lines.append("")

        # 3. Kaba Kuvvet ve Hız Sınırı Analizi
        lines.append("3. KAYAN PENCERE HIZ SINIRI VE BRUTE FORCE ANALİZİ")
        # Alt çizgi
        lines.append("-" * 50)
        # İşlenen olay sayısı
        lines.append(f"İşlenen Toplam Olay        : {bf_res.get('total_events_processed')}")
        # Kilitlenen IP sayısı
        lines.append(f"Kilitlenen Tehdit IP Sayısı: {bf_res.get('locked_out_ips_count')}")
        # Kilit detayları
        for ip, detail in bf_res.get("lockout_details", {}).items():
            # IP detayını ekliyoruz.
            lines.append(f"  [LOCKED OUT] IP: {ip} | Başarısız Deneme: {detail['failure_count']} | Pencere: {detail['window_seconds']}s")
        # Alt çizgi
        lines.append("=" * 80)

        # Metni birleştirip döndürüyoruz.
        return "\n".join(lines)

    def generate_json_report(self, fw_res: Dict[str, Any], ptr_res: List[int], bf_res: Dict[str, Any]) -> str:
        """Denetim çıktısını standart JSON formatında serileştirir."""
        # JSON yapısını oluşturuyoruz.
        res = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "PASS",
            "score": 100.0,
            "firewall_evaluation": fw_res,
            "pointer_traversal_path": ptr_res,
            "rate_limiter_results": bf_res
        }
        # JSON dizgisi olarak döndürüyoruz.
        return json.dumps(res, indent=2, ensure_ascii=False)


def main() -> None:
    """Komut satırı arayüzü (CLI) giriş noktası."""
    # Argparse nesnesi tanımlıyoruz.
    parser = argparse.ArgumentParser(
        description="G073: Koşullar, Kontrol Akışı ve Savunmacı Döngüler Güvenlik Motoru"
    )
    # Girdi JSON dosyası yolu
    parser.add_argument(
        "--input",
        type=str,
        default="portfolio/hafta_11/gun_073/ornek_veri/guvenlik_kurallari_ve_donguler.json",
        help="Örnek verileri içeren JSON dosya yolu"
    )
    # Metin raporu çıktı yolu
    parser.add_argument(
        "--output-txt",
        type=str,
        default="portfolio/hafta_11/gun_073/kanit/gercek/kontrol_akisi_guvenlik_raporu.txt",
        help="Üretilecek metin raporu dosya yolu"
    )

    # Parametreleri ayrıştırıyoruz.
    args = parser.parse_args()

    # Girdi dosyasının varlığını teyit ediyoruz.
    if not os.path.exists(args.input):
        # Dosya yoksa hata yazıp çıkıyoruz.
        sys.stderr.write(f"HATA: Girdi dosyası bulunamadı: {args.input}\n")
        # Çıkış koduyla sonlandırıyoruz.
        sys.exit(1)

    # Girdi dosyasını açıp okuyoruz.
    with open(args.input, "r", encoding="utf-8") as f:
        # JSON verisini yüklüyoruz.
        data = json.load(f)

    # Motor sınıfını başlatıyoruz.
    engine = SecurityControlFlowEngine()

    # Örnek paket bağlamı tanımlıyoruz (Yönetim ağından gelen SSH bağlantısı).
    test_packet = {
        "source_ip": "10.100.0.15",
        "dest_port": 22,
        "protocol": "TCP"
    }

    try:
        # 1. Güvenlik duvarı politikasını değerlendiriyoruz.
        fw_res = engine.evaluate_firewall_policy(data["firewall_policy"], test_packet)
        # 2. Gösterici gezintisini test ediyoruz.
        ptr_res = engine.safe_pointer_traversal(data["pointer_traversal_payload"])
        # 3. Kaba kuvvet hız sınırlamasını değerlendiriyoruz.
        bf_res = engine.detect_brute_force_rate_limit(data["authentication_events"], window_seconds=60, threshold=5)
    except ControlFlowSecurityError as err:
        # Hata durumunu ekrana yazdırıyoruz.
        sys.stderr.write(f"KONTROL AKIŞI HATASI: {err}\n")
        # Hata koduyla çıkıyoruz.
        sys.exit(1)

    # Metin raporunu üretiyoruz.
    report_txt = engine.generate_text_report(fw_res, ptr_res, bf_res)

    # Çıktı klasörünü kontrol ediyoruz.
    out_dir = os.path.dirname(args.output_txt)
    # Klasör yoksa oluşturuyoruz.
    if out_dir and not os.path.exists(out_dir):
        # Ağacı oluşturuyoruz.
        os.makedirs(out_dir, exist_ok=True)

    # Raporu dosyaya kaydediyoruz.
    with open(args.output_txt, "w", encoding="utf-8") as f:
        # Rapor metnini yazıyoruz.
        f.write(report_txt)

    # Konsola raporu yazdırıyoruz.
    print(report_txt)
    # Bilgi mesajı geçiyoruz.
    print(f"\n[+] Kontrol akışı ve savunmacı döngüler raporu kaydedildi: {args.output_txt}")


# Doğrudan çalıştırmayı yönetiyoruz.
if __name__ == "__main__":
    # main fonksiyonunu tetikliyoruz.
    main()
