# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 075: Listeler, Sözlükler ve Kümeler (Data Structures in Cyber Security: Lists, Dicts & Sets)
Bu modül, siber güvenlikte veri yapılarının zaman karmaşıklığını (O(1) vs O(N)),
küme cebri ile tehdit istihbaratı korelasyonunu, güvenli derin sözlük gezintisini
ve liste iterasyonunda in-place mutasyon tuzaklarına karşı savunmacı mekanizmaları uygular.
"""

# Koleksiyon tipleri ve yardımcı yapılar için collections içe aktarılır
import collections
# IP adresi sözdizimsel ve mantıksal doğrulama için standart kütüphane içe aktarılır
import ipaddress
# JSON veri okuma ve yapılandırma için json modülü içe aktarılır
import json
# Dosya ve sistem yolu işlemleri için os modülü içe aktarılır
import os
# Performans ve arama kıyaslaması için time modülü içe aktarılır
import time
# Kapsamlı tip ipuçları (type hints) için typing modülü içe aktarılır
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


class SecurityDataStructuresEngine:
    """
    Siber güvenlikte listeler, sözlükler ve kümelerin güvenli,
    yüksek performanslı ve savunmacı kullanımını sağlayan analiz motoru.
    """

    # DoS ve bellek tükenmesini (Memory Exhaustion) engellemek için koleksiyon tavanı
    MAX_COLLECTION_LIMIT: int = 50000

    def __init__(self) -> None:
        """
        Güvenlik veri yapıları motoru başlatıcısı; temel istatistikleri tanımlar.
        """
        # Motorun hazır olduğunu belirten bayrak
        self.is_ready: bool = True
        # Gerçekleştirilen küme cebri işlemlerinin adedi
        self.set_operation_count: int = 0

    def correlate_threat_feeds(
        self,
        feed_a: Iterable[str],
        feed_b: Iterable[str],
        whitelist: Optional[Iterable[str]] = None
    ) -> Dict[str, Any]:
        """
        Küme Cebri (Set Algebra) ile çoklu tehdit beslemelerini korele eden fonksiyon.
        Kesişim (Intersection), Birleşim (Union) ve Fark (Difference) kullanarak
        yüksek güvenilirlikli tehditleri filtreler ve beyaz liste temizliği uygular.
        """
        # Girdilerin None olup olmadığı doğrulanır
        if feed_a is None or feed_b is None:
            # None girdi durumunda TypeError fırlatılır
            raise TypeError("Tehdit beslemeleri (feed_a ve feed_b) None olamaz.")

        # Beslemelerin küme (set) formatına güvenli dönüştürülmesi
        set_a = self._sanitize_and_build_ip_set(feed_a, "feed_a")
        set_b = self._sanitize_and_build_ip_set(feed_b, "feed_b")

        # Beyaz liste kümesi hazırlanır; verilmediyse boş küme atanır
        if whitelist is not None:
            whitelist_set = self._sanitize_and_build_ip_set(whitelist, "whitelist")
        else:
            whitelist_set = set()

        # [KÜME İŞLEMİ 1: KESİŞİM (Intersection &)]: Her iki beslemede de ortak olan kritik tehditler
        common_threats = set_a.intersection(set_b)

        # [KÜME İŞLEMİ 2: FARK (Difference -)]: Ortak tehditlerden beyaz listedeki IP'lerin düşürülmesi
        high_confidence_threats = common_threats.difference(whitelist_set)

        # [KÜME İŞLEMİ 3: BİRLEŞİM (Union |)]: Tüm tekil tehditlerin birleşik kümesi
        all_unique_threats = (set_a.union(set_b)).difference(whitelist_set)

        # [KÜME İŞLEMİ 4: YALNIZCA A BESLEMESİ]: Feed A'ya özgü tehditler
        exclusive_feed_a = set_a.difference(set_b).difference(whitelist_set)

        # [KÜME İŞLEMİ 5: YALNIZCA B BESLEMESİ]: Feed B'ye özgü tehditler
        exclusive_feed_b = set_b.difference(set_a).difference(whitelist_set)

        # [KÜME İŞLEMİ 6: BASTIRILAN MEŞRU ADRESLER]: Tehdit listelerine karışmış beyaz liste adresleri
        suppressed_whitelist_hits = (set_a.union(set_b)).intersection(whitelist_set)

        # İşlem sayacını güncelleriz
        self.set_operation_count += 1

        # Sıralı ve yapılandırılmış analiz raporunu döndürürüz
        return {
            "high_confidence_threats": sorted(list(high_confidence_threats)),
            "high_confidence_count": len(high_confidence_threats),
            "all_unique_threats_count": len(all_unique_threats),
            "exclusive_to_feed_a_count": len(exclusive_feed_a),
            "exclusive_to_feed_b_count": len(exclusive_feed_b),
            "suppressed_whitelist_hits": sorted(list(suppressed_whitelist_hits)),
            "suppressed_whitelist_count": len(suppressed_whitelist_hits)
        }

    def _sanitize_and_build_ip_set(self, raw_collection: Iterable[Any], feed_name: str) -> Set[str]:
        """
        Verilen koleksiyondaki IP adreslerini doğrular, sınır aşımını denetler ve set oluşturur.
        """
        # Koleksiyonun iterable olup olmadığı kontrol edilir
        if not isinstance(raw_collection, (list, tuple, set)):
            # İzin verilmeyen tipte TypeError fırlatılır
            raise TypeError(f"{feed_name} bir koleksiyon (list/set/tuple) olmalıdır.")

        # Bellek taşması koruması (DoS / CWE-400): Koleksiyon boyutu sınanır
        if len(raw_collection) > self.MAX_COLLECTION_LIMIT:
            # Boyut tavanı aşıldığında istisna üretilir
            raise OverflowError(f"{feed_name} için maksimum eleman sınırı aşıldı: {len(raw_collection)}")

        # Temiz ve doğrulanmış IP'lerin toplanacağı yerel küme
        sanitized_set: Set[str] = set()

        # Her bir girdi satırı iterasyona alınır
        for item in raw_collection:
            # Girdinin string olup olmadığı denetlenir
            if not isinstance(item, str):
                # Hashlenemeyen veya geçersiz tiplerde TypeError üretilir
                raise TypeError(f"{feed_name} içinde geçersiz eleman tipi: {type(item)}")

            # Dizenin kenar boşlukları temizlenir
            clean_ip = item.strip()
            try:
                # ipaddress modülü ile katı IPv4 doğrulaması yapılır
                ipaddress.IPv4Address(clean_ip)
                # Geçerli IP adresi kümeye $O(1)$ sürede eklenir
                sanitized_set.add(clean_ip)
            except ValueError:
                # Malforme IP tespit edilirse güvenlik gereği ValueError fırlatılır
                raise ValueError(f"{feed_name} içinde malforme IP adresi tespit edildi: {clean_ip}")

        # Doğrulanmış küme döndürülür
        return sanitized_set

    def safe_deep_dict_get(
        self,
        data: Dict[str, Any],
        key_path: List[str],
        default: Any = None
    ) -> Any:
        """
        İç içe (nested) sözlüklerde KeyError, AttributeError veya TypeError üretmeden
        savunmacı gezinti sağlayan güvenli okuma fonksiyonu.
        """
        # Ana veri nesnesinin sözlük olduğu doğrulanır
        if not isinstance(data, dict):
            # Sözlük değilse varsayılan değer döner
            return default

        # Yol listesinin geçerli olup olmadığı kontrol edilir
        if not isinstance(key_path, list):
            # Geçersiz yol tanımında varsayılan döner
            return default

        # Gezinti için mevcut düğüm başlangıçta ana sözlüktür
        current_node: Any = data

        # Yol adımları tek tek yürütülür
        for step in key_path:
            # Mevcut düğümün bir sözlük olup olmadığı test edilir
            if not isinstance(current_node, dict):
                # Düğüm sözlük değilse (None veya başka tipse) güvenle varsayılan döndürülür
                return default

            # Sözlükten anahtar güvenli .get() metodu ile çekilir
            current_node = current_node.get(step)
            # Eğer anahtar yoksa None döner ve bir sonraki döngüde güvenli çıkış yapılır
            if current_node is None:
                # Aranan yol bulunamadığında varsayılan değer döner
                return default

        # Yolun sonuna başarıyla ulaşıldıysa bulunan değer döndürülür
        return current_node

    def defensive_filter_ioc_list(
        self,
        ioc_list: List[str],
        filter_prefix: str
    ) -> List[str]:
        """
        İterasyon sırasında liste üzerinde in-place silme (remove/pop) yapıldığında
        ortaya çıkan eleman atlama (Skipping Elements) mantık hatasını engelleyen
        savunmacı liste filtreleme fonksiyonu (List Comprehension).
        """
        # Girdinin liste tipinde olduğu kontrol edilir
        if not isinstance(ioc_list, list):
            # Liste değilse TypeError fırlatılır
            raise TypeError("ioc_list parametresi bir Python listesi (list) olmalıdır.")

        # Orijinal listeyi mutasyona uğratmadan, yeni ve filtrelenmiş bir liste üretilir
        filtered_results = [
            ioc for ioc in ioc_list
            if isinstance(ioc, str) and not ioc.startswith(filter_prefix)
        ]

        # Güvenli filtrelenmiş liste döndürülür
        return filtered_results

    def safe_set_ingest(self, raw_items: Iterable[Any]) -> Set[Any]:
        """
        Hashlenemeyen (unhashable) mutable nesneleri (list, dict) kümeye eklerken
        oluşan TypeError'ı önleyen, savunmacı küme dönüştürücü.
        """
        # Hedef küme tanımlanır
        safe_set: Set[Any] = set()

        # Her bir girdi tek tek incelenir
        for item in raw_items:
            # Girdi değiştirilebilir bir liste ise sabit tuple'a dönüştürülür
            if isinstance(item, list):
                # Tuple hashable olduğu için güvenle eklenebilir
                safe_set.add(tuple(item))
            elif isinstance(item, dict):
                # Sözlük ise sıralı anahtar-değer çiftlerinden oluşan tuple'a dönüştürülür
                safe_set.add(tuple(sorted(item.items())))
            else:
                try:
                    # Hashable nesneler doğrudan eklenir
                    safe_set.add(item)
                except TypeError:
                    # Beklenmeyen unhashable nesnelerde hata fırlatılır
                    raise TypeError(f"Hashlenemeyen nesne tespit edildi: {type(item)}")

        # Güvenli küme döndürülür
        return safe_set

    def detect_rule_shadowing(
        self,
        rule_pairs: List[Tuple[str, Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """
        Sözlük oluşturulurken aynı kural anahtarının tekrar tanımlanmasıyla
        oluşan kural gölgeleme (Rule Shadowing / Collision) zafiyetini tespit eder.
        """
        # Anahtar kullanım sıklığını sayacak sayaç sözlüğü
        key_counts: Dict[str, int] = collections.defaultdict(int)
        # Çakışma yaşanan anahtarların listesi
        conflicts: List[str] = []

        # Tüm kural çiftleri taranır
        for rule_key, _ in rule_pairs:
            # Anahtarın görülme sıklığı 1 artırılır
            key_counts[rule_key] += 1
            # Eğer anahtar birden fazla kez görüldüyse çakışma listesine kaydedilir
            if key_counts[rule_key] == 2:
                conflicts.append(rule_key)

        # Çakışma durumu raporlanır
        has_shadowing = len(conflicts) > 0
        return {
            "has_rule_shadowing": has_shadowing,
            "conflicting_rules": conflicts,
            "total_unique_rules": len(key_counts)
        }

    def benchmark_lookup_performance(self, element_count: int = 10000) -> Dict[str, float]:
        """
        Siber güvenlikte N elemanlı koleksiyonda O(1) Küme araması ile
        O(N) Liste aramasının işlem süresi farkını kanıtlayan mikro-kıyaslama.
        """
        # N elemanlı sıralı dize listesi ve kümesi oluşturulur
        test_list = [f"ioc_{i}.threat.local" for i in range(element_count)]
        test_set = set(test_list)

        # Aranacak hedef (listenin en sonundaki eleman: en kötü durum senaryosu)
        target = f"ioc_{element_count - 1}.threat.local"

        # 1. Liste üzerinde arama süresi ölçülür (O(N) karmaşıklık)
        t_start_list = time.perf_counter()
        _ = target in test_list
        t_end_list = time.perf_counter()
        list_lookup_seconds = t_end_list - t_start_list

        # 2. Küme üzerinde arama süresi ölçülür (O(1) ortalama karmaşıklık)
        t_start_set = time.perf_counter()
        _ = target in test_set
        t_end_set = time.perf_counter()
        set_lookup_seconds = t_end_set - t_start_set

        # Süre sonuçları sözlük olarak döndürülür
        return {
            "list_lookup_seconds": list_lookup_seconds,
            "set_lookup_seconds": set_lookup_seconds,
            "element_count": float(element_count)
        }

    def generate_security_report(self, sample_data_path: str) -> Dict[str, Any]:
        """
        Örnek veri setini okuyarak küme korelasyonu ve güvenli sözlük gezintisi
        testlerini koşturan ve rapor üreten ana doğrulama metodu.
        """
        # Dosya varlığı kontrol edilir
        if not os.path.exists(sample_data_path):
            raise FileNotFoundError(f"Örnek veri dosyası bulunamadı: {sample_data_path}")

        # JSON verisi okunur
        with open(sample_data_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 1. Küme Korelasyon Analizi
        feed_otx = data["tehdit_kaynaklari"]["feed_otx"]
        feed_misp = data["tehdit_kaynaklari"]["feed_misp"]
        whitelist = data["tehdit_kaynaklari"]["beyaz_liste"]
        correlation_result = self.correlate_threat_feeds(feed_otx, feed_misp, whitelist)

        # 2. Güvenli Derin Gezinti Testi
        config = data.get("derin_yapilandirma", {})
        bpf_filter = self.safe_deep_dict_get(config, ["network", "filters", "bpf"], "default_bpf")
        max_pps = self.safe_deep_dict_get(config, ["network", "filters", "rate_limit", "max_pps"], 0)

        # 3. Kural Çakışma Testi
        rule_pairs = [
            ("RULE_01", {"action": "DROP"}),
            ("RULE_02", {"action": "LOG"}),
            ("RULE_01", {"action": "ALLOW"})  # Kasıtlı çakışma
        ]
        shadowing_res = self.detect_rule_shadowing(rule_pairs)

        # 4. Kıyaslama Testi
        bench_res = self.benchmark_lookup_performance(element_count=5000)

        # Kapsamlı rapor oluşturulur
        report: Dict[str, Any] = {
            "title": "G075: Veri Yapıları Güvenlik ve Performans Raporu",
            "correlation_summary": correlation_result,
            "deep_dict_resolution": {
                "bpf_filter": bpf_filter,
                "max_pps": max_pps
            },
            "rule_shadowing_detected": shadowing_res["has_rule_shadowing"],
            "conflicting_rules": shadowing_res["conflicting_rules"],
            "benchmark_summary": bench_res,
            "status": "ALL_STRUCTURES_VERIFIED"
        }

        return report


if __name__ == "__main__":
    # Test veri yolu belirlenir
    sample_file = os.path.join(
        os.path.dirname(__file__),
        "..",
        "ornek_veri",
        "tehdit_istihbarat_veri_yapilari.json"
    )

    # Motor çalıştırılır ve çıktı yazdırılır
    engine = SecurityDataStructuresEngine()
    gen_report = engine.generate_security_report(sample_file)
    print(json.dumps(gen_report, indent=2, ensure_ascii=False))
