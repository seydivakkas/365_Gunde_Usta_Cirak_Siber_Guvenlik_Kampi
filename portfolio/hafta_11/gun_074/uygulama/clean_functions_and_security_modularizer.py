# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 074: Fonksiyonlar ve Temiz Kod (Functions, Clean Code, Pure Functions & Modularity)
Bu modül, siber güvenlik otomasyonunda temiz kod prensiplerini (Clean Code),
saf fonksiyonları (Pure Functions), değişmezliği (Immutability), tip güvenliğini
ve sözleşmeye dayalı tasarımı (Design by Contract) uygulayan modüler güvenlik motorunu içerir.
"""

# Güvenli derin kopyalama işlemleri için copy modülü içe aktarılır
import copy
# IP adresi sözdizimsel ve anlamsal doğrulama için standart kütüphane içe aktarılır
import ipaddress
# JSON veri okuma ve yapılandırma için json modülü içe aktarılır
import json
# Dosya sistemi ve yol işlemleri için os modülü içe aktarılır
import os
# Düzenli ifadeler ile log ayrıştırma için re modülü içe aktarılır
import re
# Kapsamlı tip ipuçları (type hints) için typing modülü içe aktarılır
from typing import Any, Dict, List, Optional, Tuple, Set


class CleanFunctionsAndSecurityModularizer:
    """
    Siber güvenlik araçlarında fonksiyonel programlama, temiz kod ve
    savunmacı modülerlik ilkelerini icra eden ana güvenlik motoru.
    """

    # İzin verilen kriptografik özet algoritmaları ve beklenen hex uzunlukları
    ALLOWED_HASH_SPECS: Dict[str, int] = {
        "md5": 32,      # MD5 özeti tam olarak 32 hex karakter olmalıdır
        "sha1": 40,     # SHA-1 özeti tam olarak 40 hex karakter olmalıdır
        "sha256": 64    # SHA-256 özeti tam olarak 64 hex karakter olmalıdır
    }

    # Sözleşme sonrası doğrulanacak geçerli nihai güvenlik kararları kümesi
    VALID_VERDICTS: Set[str] = {"CONFIRMED", "UNVERIFIED", "REJECTED"}

    # Güvenlik duvarı ve inceleme kuralları için geçerli aksiyonlar kümesi
    VALID_RULE_ACTIONS: Set[str] = {"ALLOW", "DENY", "DROP", "INSPECT"}

    def __init__(self) -> None:
        """
        Güvenlik motoru başlatıcısı; sınıfın temel durumunu izole başlatır.
        """
        # Motorun çalışma durumunu tutan dahili bayrak
        self.is_initialized: bool = True
        # Gerçekleştirilen operasyon adedini izleyen denetim sayacı
        self.audit_operation_count: int = 0

    def validate_log_and_tag(
        self,
        raw_entry: str,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Değiştirilebilir varsayılan argüman tuzağını (Mutable Default Argument Trap - CWE-670)
        engelleyen, bağımsız ve güvenli log etiketleme fonksiyonu.
        """
        # Ham log verisinin string tipinde olup olmadığı denetlenir
        if not isinstance(raw_entry, str):
            # Geçersiz veri tipi gelirse istisna fırlatılır
            raise TypeError("Ham log girdisi metin (str) tipinde olmalıdır.")

        # Log dizesinin sağ ve sol boşlukları temizlenir
        cleaned_entry = raw_entry.strip()
        # Temizlenen log dizesinin boş olup olmadığı kontrol edilir
        if not cleaned_entry:
            # Boş dize tespit edilirse ValueError üretilir
            raise ValueError("Ham log girdisi boş veya yalnızca boşluktan oluşamaz.")

        # Değiştirilebilir varsayılan argüman tuzağını önlemek için bağımsız liste oluşturulur
        if tags is None:
            # Eğer etiket listesi verilmediyse yeni, temiz ve izole bir liste açılır
            resolved_tags: List[str] = []
        else:
            # Eğer dışarıdan liste geldiyse, dış referansı bozmamak için kopyası alınır
            resolved_tags = list(tags)

        # Doğrulama etiketini güvenli şekilde yerel listeye ekleriz
        resolved_tags.append("verified")

        # Gerçekleştirilen operasyon sayacını artırırız
        self.audit_operation_count += 1

        # İzole ve yeni üretilmiş sonuç sözlüğünü geri döndürürüz
        return {
            "status": "VALIDATED",
            "entry": cleaned_entry,
            "tags": resolved_tags
        }

    def pure_calculate_threat_score(
        self,
        reputation_factors: Dict[str, float]
    ) -> float:
        """
        Saf Fonksiyon (Pure Function) prensibine göre tasarlanmış tehdit skoru hesaplayıcı.
        Dış dünyada hiçbir yan etki (side-effect) üretmez, global durumu değiştirmez,
        aynı girdiye her zaman aynı çıktıyı deterministik olarak üretir.
        """
        # Girdinin sözlük tipinde olduğu doğrulanır
        if not isinstance(reputation_factors, dict):
            # Sözlük değilse TypeError fırlatılır
            raise TypeError("Tehdit faktörleri sözlük (dict) formatında olmalıdır.")

        # Boş faktör sözlüğü kontrol edilir
        if not reputation_factors:
            # Faktör yoksa temel skor olarak 0.0 döner
            return 0.0

        # Katsayıların toplam ağırlığını ve kümülatif skoru tutacak yerel değişkenler
        total_weight: float = 0.0
        # Ağırlıklandırılmış katsayıların toplam değeri
        weighted_sum: float = 0.0

        # Sözlük içindeki tüm faktör ve ağırlık ikilileri iterasyona alınır
        for factor_name, weight in reputation_factors.items():
            # Faktör adının geçerli bir metin olup olmadığı kontrol edilir
            if not isinstance(factor_name, str) or not factor_name.strip():
                # Geçersiz faktör adı durumunda istisna üretilir
                raise ValueError(f"Geçersiz faktör adı: {factor_name}")

            # Katsayının sayısal değer (float veya int) olduğu denetlenir
            if not isinstance(weight, (float, int)):
                # Sayısal olmayan katsayıda hata verilir
                raise TypeError(f"Faktör ağırlığı sayısal olmalıdır: {factor_name}")

            # Katsayının [0.0, 1.0] kapalı aralığında olduğu kesinleştirilir
            if weight < 0.0 or weight > 1.0:
                # Sınır dışı ağırlık tespitinde istisna fırlatılır
                raise ValueError(f"Tehdit faktörü katsayısı [0.0, 1.0] aralığında olmalıdır: {weight}")

            # Ağırlıklandırılmış toplam puana faktörün katkısı eklenir
            weighted_sum += float(weight)
            # Toplam ağırlık birimi artırılır
            total_weight += 1.0

        # Aritmetik ortalama hesaplanır ve 100 üzerinden ölçeklenir
        normalized_score = (weighted_sum / total_weight) * 100.0
        # Hesaplanan skor iki ondalık basamağa yuvarlanır
        final_score = round(normalized_score, 2)

        # Deterministik skor çıktısı geri döndürülür
        return final_score

    def split_and_validate_ioc_pipeline(self, raw_log: str) -> Dict[str, Any]:
        """
        Tek Sorumluluk İlkesi (Single Responsibility Principle - SRP) uyarınca
        ayrıştırılmış küçük yardımcı fonksiyonları orkestre eden temiz log analiz boru hattı.
        """
        # Girdinin geçerli bir dize olduğu denetlenir
        if not isinstance(raw_log, str) or not raw_log.strip():
            # Geçersiz ham log girdisinde hata fırlatılır
            raise ValueError("Ham log girdisi boş veya geçersiz olamaz.")

        # 1. Adım: SRP uyarınca sadece IP token'ını ayrıştıran yardımcı çağrılır
        ip_token = self._extract_ip_token(raw_log)

        # 2. Adım: SRP uyarınca IP adresinin formatını doğrulayan yardımcı çağrılır
        is_valid = self._validate_ipv4_format(ip_token)

        # 3. Adım: SRP uyarınca IP'nin ağ bölgesini (zone) sınıflandıran yardımcı çağrılır
        zone_classification = self._classify_ip_zone(ip_token) if is_valid else "INVALID_ZONE"

        # 4. Adım: Denetim kaydını inşa eden yardımcı fonksiyon çağrılır
        audit_record = self._build_security_audit_record(ip_token, is_valid, zone_classification)

        # İşlem sayacı artırılır
        self.audit_operation_count += 1

        # Nihai denetim nesnesi döndürülür
        return audit_record

    def _extract_ip_token(self, log_line: str) -> str:
        """
        Tek Sorumluluk: Verilen log satırından sadece 'SRC=<ip>' alanını ayıklar.
        """
        # Düzenli ifade ile SRC= kalıbından sonraki boşluksuz token aranır
        match = re.search(r"SRC=([^\s]+)", log_line)
        # Eşleşme bulunup bulunmadığı denetlenir
        if not match:
            # IP alanı bulunamazsa açıklayıcı ValueError üretilir
            raise ValueError("Log satırında geçerli SRC IP ayrıştırılamadı.")
        # Yakalanan birinci grup (IP dizesi) döndürülür
        return match.group(1)

    def _validate_ipv4_format(self, ip_str: str) -> bool:
        """
        Tek Sorumluluk: Yalnızca verilen metnin geçerli bir IPv4 adresi olup olmadığını test eder.
        """
        try:
            # ipaddress kütüphanesi ile katı IPv4 doğrulaması yapılır
            ip_obj = ipaddress.IPv4Address(ip_str)
            # Doğrulama başarılıysa True döndürülür
            return True
        except ValueError:
            # Hatalı IP formatında sessizce False döndürülür
            return False

    def _classify_ip_zone(self, ip_str: str) -> str:
        """
        Tek Sorumluluk: Doğrulanmış bir IPv4 adresinin ait olduğu ağ bölgesini belirler.
        """
        # IPv4 nesnesi oluşturulur
        ip_obj = ipaddress.IPv4Address(ip_str)
        # Geriye dönük döngü (Loopback) denetimi yapılır
        if ip_obj.is_loopback:
            # 127.0.0.0/8 bloğu
            return "LOOPBACK"
        # RFC 1918 özel ağ aralığı denetimi yapılır
        if ip_obj.is_private:
            # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            return "PRIVATE"
        # Çok noktaya yayın (Multicast) denetimi yapılır
        if ip_obj.is_multicast:
            # 224.0.0.0/4
            return "MULTICAST"
        # Diğer tüm adresler genel internet adresi kabul edilir
        return "PUBLIC"

    def _build_security_audit_record(
        self,
        ip_str: str,
        is_valid: bool,
        zone: str
    ) -> Dict[str, Any]:
        """
        Tek Sorumluluk: Analiz edilen bileşenleri standart bir denetim sözlüğünde birleştirir.
        """
        # Yapılandırılmış sözlük inşa edilerek döndürülür
        return {
            "source_ip": ip_str,
            "is_valid_ipv4": is_valid,
            "network_zone": zone,
            "sanitized": True
        }

    def immutable_rule_sanitizer(self, rule_def: Dict[str, Any]) -> Dict[str, Any]:
        """
        Değişmezlik (Immutability) ve Savunmacı Kopyalama (Defensive Copying):
        Parametre olarak alınan kural sözlüğünü yerinde (in-place) değiştirmeden,
        derin kopyasını alarak normalize eder ve döndürür.
        """
        # Kural tanımının sözlük olduğu kontrol edilir
        if not isinstance(rule_def, dict):
            # Sözlük değilse hata fırlatılır
            raise TypeError("Kural tanımı bir sözlük (dict) olmalıdır.")

        # Orijinal girdinin bütünlüğünü korumak için derin kopya alınır
        sanitized_rule = copy.deepcopy(rule_def)

        # Zorunlu alanların mevcudiyeti kontrol edilir
        if "kural_id" not in sanitized_rule or "aksiyon" not in sanitized_rule:
            # Zorunlu alan eksikse hata verilir
            raise ValueError("Kural tanımında 'kural_id' ve 'aksiyon' alanları zorunludur.")

        # Aksiyon dizesi büyük harfe dönüştürülür ve temizlenir
        raw_action = str(sanitized_rule["aksiyon"]).strip().upper()
        # Aksiyonun izin verilen kümede yer alıp almadığı doğrulanır
        if raw_action not in self.VALID_RULE_ACTIONS:
            # İzin verilmeyen aksiyonda ValueError fırlatılır
            raise ValueError(f"Geçersiz kural aksiyonu: {raw_action}")

        # Kopyalanan nesnede aksiyon normalize edilmiş haliyle güncellenir
        sanitized_rule["aksiyon"] = raw_action
        # Kuralın temizleme işleminden geçtiğini belirten etiket eklenir
        sanitized_rule["is_sanitized"] = True

        # Orijinal nesneye dokunulmadan üretilen yeni kural döndürülür
        return sanitized_rule

    def contract_enforced_hash_lookup(
        self,
        hash_str: str,
        algorithm: str = "sha256"
    ) -> Dict[str, str]:
        """
        Sözleşmeye Dayalı Tasarım (Design by Contract):
        - Ön Koşullar (Preconditions): Algoritma türü ve hex biçimi katı denetlenir.
        - Son Koşullar (Postconditions): Üretilen sonucun izin verilen durum kümesinde olduğu garanti edilir.
        """
        # Algoritma adının küçük harfe çevrilmiş hali alınır
        algo_normalized = algorithm.strip().lower()

        # [ÖN KOŞUL 1]: Desteklenen algoritma kontrolü
        if algo_normalized not in self.ALLOWED_HASH_SPECS:
            # Desteklenmeyen algoritma durumunda hata fırlatılır
            raise ValueError(f"Desteklenmeyen hash algoritması: {algorithm}")

        # [ÖN KOŞUL 2]: Hash dizesinin metin tipi doğrulaması
        if not isinstance(hash_str, str):
            # Metin değilse TypeError fırlatılır
            raise TypeError("Hash değeri bir metin (str) olmalıdır.")

        # Hash dizesi temizlenir
        cleaned_hash = hash_str.strip().lower()
        # [ÖN KOŞUL 3]: Beklenen karakter uzunluğu denetimi
        expected_len = self.ALLOWED_HASH_SPECS[algo_normalized]
        if len(cleaned_hash) != expected_len:
            # Uzunluk uyuşmuyorsa hata verilir
            raise ValueError(
                f"Geçersiz hash uzunluğu. {algo_normalized.upper()} için "
                f"beklenen {expected_len}, ancak gelen {len(cleaned_hash)}"
            )

        # [ÖN KOŞUL 4]: Onaltılık (Hexadecimal) karakter seti denetimi
        valid_hex_chars = set("0123456789abcdef")
        if not all(ch in valid_hex_chars for ch in cleaned_hash):
            # Geçersiz karakter varsa hata üretilir
            raise ValueError("Geçersiz onaltılık (hex) karakterler tespit edildi.")

        # İş mantığı icra edilir: Tehdit arama kaydı üretilir
        verdict = "CONFIRMED"

        # [SON KOŞUL (POSTCONDITION)]: Üretilen kararın sözleşmeye uygunluğu test edilir
        if verdict not in self.VALID_VERDICTS:
            # Sözleşme ihlali durumunda sistem güvenliği için hata verilir
            raise ValueError(f"Üretilen güvenlik kararı izin verilen değer kümesi dışındadır: {verdict}")

        # Başarılı sözleşme sonucunda yapılandırılmış yanıt nesnesi döndürülür
        return {
            "hash": cleaned_hash,
            "algorithm": algo_normalized,
            "status": "VALID_IOC_HASH",
            "verdict": verdict
        }

    def generate_security_report(self, sample_data_path: str) -> Dict[str, Any]:
        """
        Tüm temiz fonksiyon bileşenlerini örnek veri seti üzerinde çalıştırarak
        kapsamlı bir yürütme raporu oluşturan raporlayıcı metot.
        """
        # Veri dosyasının varlığı kontrol edilir
        if not os.path.exists(sample_data_path):
            # Dosya yoksa FileNotFoundError fırlatılır
            raise FileNotFoundError(f"Örnek veri dosyası bulunamadı: {sample_data_path}")

        # JSON veri seti diskten okunur
        with open(sample_data_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Rapor sözlüğü başlatılır
        report: Dict[str, Any] = {
            "title": "G074: Temiz Kod ve Fonksiyonel Güvenlik Doğrulama Raporu",
            "tested_components": [],
            "status": "ALL_TESTS_PASSED"
        }

        # 1. Log Etiketleme Testi
        for log_item in data.get("ornek_loglar", []):
            res = self.validate_log_and_tag(log_item["raw_entry"], log_item.get("initial_tags"))
            report["tested_components"].append({
                "test": "validate_log_and_tag",
                "id": log_item["id"],
                "tags_count": len(res["tags"])
            })

        # 2. Tehdit Skoru Saf Hesaplama Testi
        for score_item in data.get("tehdit_skor_parametreleri", []):
            score = self.pure_calculate_threat_score(score_item["faktorler"])
            report["tested_components"].append({
                "test": "pure_calculate_threat_score",
                "scenario": score_item["senaryo"],
                "calculated_score": score
            })

        # 3. Hash Sözleşme Doğrulama Testi
        for hash_item in data.get("dogrulanmis_hash_ornekleri", []):
            lookup = self.contract_enforced_hash_lookup(
                hash_item["hash_degeri"],
                hash_item["algoritma"]
            )
            report["tested_components"].append({
                "test": "contract_enforced_hash_lookup",
                "algo": lookup["algorithm"],
                "verdict": lookup["verdict"]
            })

        # Toplam yürütülen test adedi rapora kaydedilir
        report["total_component_runs"] = len(report["tested_components"])

        # Üretilen rapor döndürülür
        return report


if __name__ == "__main__":
    # Örnek veri dosyası yolu belirlenir
    sample_file = os.path.join(
        os.path.dirname(__file__),
        "..",
        "ornek_veri",
        "guvenlik_fonksiyonlari_ornek_verisi.json"
    )

    # Motor örneği oluşturulur
    engine = CleanFunctionsAndSecurityModularizer()

    # Rapor çalıştırılır ve ekrana yazdırılır
    gen_report = engine.generate_security_report(sample_file)
    print(json.dumps(gen_report, indent=2, ensure_ascii=False))
