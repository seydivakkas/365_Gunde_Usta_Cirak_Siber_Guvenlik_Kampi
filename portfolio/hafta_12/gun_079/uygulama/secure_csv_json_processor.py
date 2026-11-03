# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G079: CSV ve JSON Veri İşleme Modülü (Secure CSV and JSON Processing Engine)

Bu modül; siber güvenlik araçlarında ve SIEM besleme boru hatlarında sıklıkla kullanılan
CSV ve JSON formatlarındaki verileri, enjeksiyon (CWE-1236), anahtar çarpışması (JSON Hijacking),
derin özyineleme (JSON Bomb DoS) ve bellek taşması risklerine karşı matematiksel ve
savunmacı yöntemlerle ayrıştırır, doğrular ve güvenle depolar.
"""

# CSV dosya ayrıştırma ve yazma işlemleri için Python standart kütüphanesini içeri aktarıyoruz.
import csv
# JSON serileştirme ve ayrıştırma motoru için standart kütüphaneyi içeri aktarıyoruz.
import json
# Dosya sistemi yolları ve nesne yönelimli yol kontrolü için Path sınıfını içeri aktarıyoruz.
from pathlib import Path
# Tip ipuçları ve statik tip denetimi için gerekli generic tipleri içeri aktarıyoruz.
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class FormulaInjectionWarning(Exception):
    """
    CSV alanlarında formül yürütme (DDE/Formula Injection) riski taşıyan karakterler tespit edildiğinde fırlatılan özel kural uyarısı.
    """
    # Özel istisna sınıfının gövdesini tanımlıyoruz.
    pass


class SecureCsvProcessor:
    """
    CSV verilerini Formula Injection (CWE-1236), sütun sayısı tutarsızlığı ve
    aşırı büyük alan boyutu (DoS) saldırılarına karşı koruyan güvenlik sınıfı.
    """

    # Excel ve LibreOffice Calc üzerinde formül yürütmeyi tetikleyen tehlikeli başlangıç karakterleri kümesi.
    DANGEROUS_FORMULA_PREFIXES: Tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")

    def __init__(self, max_field_size_bytes: int = 65536, max_rows: int = 50000) -> None:
        """
        Güvenli CSV işlemcisini yapılandırır ve güvenlik tavan sınırlarını belirler.
        """
        # Tek bir CSV hücresinin sahip olabileceği azami bayt sınırını belirliyoruz (Varsayılan: 64 KB).
        self.max_field_size_bytes = max_field_size_bytes
        # İşlenebilecek azami satır sayısını belirleyerek bellek tükenmesi DoS saldırılarını engelliyoruz.
        self.max_rows = max_rows

    def has_formula_injection_risk(self, cell_value: str) -> bool:
        """
        Verilen hücre değerinin Excel formül enjeksiyonu riski taşıyıp taşımadığını tespit eder.
        """
        # Girdi bir dize değilse veya boşsa formül riski bulunmaz.
        if not isinstance(cell_value, str) or not cell_value:
            # Risk olmadığını belirten False değerini döndürüyoruz.
            return False
        # Hücre değerinin başındaki boşlukları kırparak kontrol ediyoruz.
        stripped_val = cell_value.lstrip()
        # Kırpılmış değer boşsa formül riski yoktur.
        if not stripped_val:
            # Boş dize için False döndürüyoruz.
            return False
        # Değerin ilk karakterinin tehlikeli formül tetikleyicilerinden biri olup olmadığını sınıyoruz.
        return stripped_val.startswith(self.DANGEROUS_FORMULA_PREFIXES)

    def sanitize_csv_cell(self, cell_value: str) -> str:
        """
        Hücre değerini nötralize eder; formül tetikleyicisi varsa başına tek tırnak (') ekler.
        """
        # Değer dize tipinde değilse aynen koruyoruz.
        if not isinstance(cell_value, str):
            # Dize olmayan değeri geri döndürüyoruz.
            return str(cell_value)
        # Değerde formül enjeksiyonu riski olup olmadığını denetliyoruz.
        if self.has_formula_injection_risk(cell_value):
            # Hücrenin başına tek tırnak ekleyerek Excel'in bunu düz metin olarak görmesini sağlıyoruz.
            return f"'{cell_value}"
        # Risk taşımıyorsa orijinal dizeyi döndürüyoruz.
        return cell_value

    def read_csv_safely(
        self,
        csv_file_path: Path,
        expected_headers: Optional[List[str]] = None,
        delimiter: str = ","
    ) -> List[Dict[str, str]]:
        """
        CSV dosyasını katı sütun sayısı denetimi, alan boyutu tavanı ve null-byte kontrolü ile güvenle okur.
        """
        # Dosya yolunu Path nesnesi olarak doğruluyoruz.
        resolved_path = Path(csv_file_path).resolve()
        # Hedef dosyanın fiziksel varlığını sınıyoruz.
        if not resolved_path.is_file():
            # Dosya bulunamazsa açıkça FileNotFoundError fırlatıyoruz.
            raise FileNotFoundError(f"Okunacak CSV dosyası bulunamadı: {resolved_path}")

        # Çözümlenen satır kayıtlarını tutacağımız listeyi başlatıyoruz.
        records: List[Dict[str, str]] = []

        # Dosyayı açıkça UTF-8 ve evrensel yeni satır desteği ile açıyoruz.
        with open(resolved_path, mode="r", encoding="utf-8", newline="", errors="strict") as f:
            # Standart CSV okuyucusunu güvenli parametrelerle başlatıyoruz.
            reader = csv.reader(f, delimiter=delimiter)
            # Başlık satırını güvenle okuyoruz.
            try:
                # İlk satırı başlık olarak çekiyoruz.
                headers = next(reader)
            # Dosya tamamen boşsa StopIteration yakalanır.
            except StopIteration:
                # Boş liste döndürerek güvenle çıkıyoruz.
                return []

            # Başlık satırında null-byte veya aşırı uzunluk kontrolü yapıyoruz.
            for h in headers:
                # Başlıkta null byte varsa veri zehirlenmesine karşı durduruyoruz.
                if "\x00" in h:
                    # Null byte tespitinde ValueError fırlatıyoruz.
                    raise ValueError(f"CSV başlık alanında geçersiz null-byte bulundu: {repr(h)}")
                # Başlık uzunluğu belirlenen alanı aşıyorsa reddediyoruz.
                if len(h.encode("utf-8")) > self.max_field_size_bytes:
                    # Tavan aşımında ValueError fırlatıyoruz.
                    raise ValueError(f"CSV başlık alanı azami boyutu aşıyor: {len(h)} bayt")

            # Beklenen başlıklar verilmişse tam eşleşme kontrolü yapıyoruz.
            if expected_headers is not None and headers != expected_headers:
                # Başlıklar uyuşmuyorsa açıkça ValueError fırlatıyoruz.
                raise ValueError(f"CSV başlıkları beklenen şema ile uyuşmuyor. Beklenen: {expected_headers}, Alınan: {headers}")

            # Başlık sütun sayısını kaydediyoruz.
            expected_column_count = len(headers)
            # Satır sayacını başlatıyoruz.
            row_count = 0

            # Veri satırlarını tek tek güvenle dolaşıyoruz.
            for row_index, row in enumerate(reader, start=2):
                # Satır sayacını artırıyoruz.
                row_count += 1
                # Azami satır sayısı tavanını kontrol ederek DoS saldırısını engelliyoruz.
                if row_count > self.max_rows:
                    # Sınır aşıldığında açıkça ValueError fırlatıyoruz.
                    raise ValueError(f"CSV dosyası izin verilen azami satır sayısını ({self.max_rows}) aştı.")

                # Sütun sayısı tutarsızlığını denetliyoruz.
                if len(row) != expected_column_count:
                    # Sütun sayısı uyuşmazlığında format bozulması veya enjeksiyon şüphesiyle hata fırlatıyoruz.
                    raise ValueError(
                        f"Satır {row_index} sütun sayısı uyumsuzluğu: {len(row)} sütun bulundu, beklenen: {expected_column_count}"
                    )

                # Satırdaki her bir hücreyi güvenlik süzgecinden geçiriyoruz.
                row_dict: Dict[str, str] = {}
                # Başlık ve hücre ikililerini eşleştiriyoruz.
                for col_name, cell_raw in zip(headers, row):
                    # Hücrede null-byte varsa zehirlenme gerekçesiyle reddediyoruz.
                    if "\x00" in cell_raw:
                        # Hata fırlatarak akışı kesiyoruz.
                        raise ValueError(f"Satır {row_index}, sütun '{col_name}' içinde null-byte bulundu.")
                    # Hücre boyutu tavanını kontrol ediyoruz.
                    if len(cell_raw.encode("utf-8")) > self.max_field_size_bytes:
                        # Aşırı büyük hücre durumunda bellek koruması hatası veriyoruz.
                        raise ValueError(f"Satır {row_index}, sütun '{col_name}' hücre boyutu sınırını aştı.")
                    # Hücreyi sözlüğe ekliyoruz.
                    row_dict[col_name] = cell_raw

                # Doğrulanmış satırı kayıtlar listesine ekliyoruz.
                records.append(row_dict)

        # Doğrulanmış kayıt listesini döndürüyoruz.
        return records

    def write_csv_safely(
        self,
        output_file_path: Path,
        headers: List[str],
        rows: List[Dict[str, Any]],
        neutralize_formulas: bool = True
    ) -> int:
        """
        Verileri CSV dosyasına formül enjeksiyonu nötralizasyonu ve güvenli tırnaklama ile yazar.
        """
        # Çıktı yolunu doğruluyoruz.
        resolved_output = Path(output_file_path).resolve()
        # Hedef dizinin varlığını güvenceye alıyoruz.
        resolved_output.parent.mkdir(parents=True, exist_ok=True)

        # Yazılan satır sayısını takip ediyoruz.
        written_count = 0

        # Dosyayı güvenle UTF-8 olarak açıyoruz.
        with open(resolved_output, mode="w", encoding="utf-8", newline="", errors="strict") as f:
            # Standart CSV sözlük yazıcısını başlatıyoruz.
            writer = csv.DictWriter(f, fieldnames=headers, quoting=csv.QUOTE_MINIMAL)
            # Başlık satırını yazıyoruz.
            writer.writeheader()

            # Her bir veri satırını dönüyoruz.
            for row in rows:
                # Temizlenmiş satır sözlüğü oluşturuyoruz.
                sanitized_row: Dict[str, Any] = {}
                # Belirlenen başlıklara göre satır alanlarını işliyoruz.
                for col in headers:
                    # Kolon değerini alıyoruz, yoksa boş dize koyuyoruz.
                    val = row.get(col, "")
                    # Nötralizasyon aktifse ve değer dize ise formül denetimi yapıyoruz.
                    if neutralize_formulas and isinstance(val, str):
                        # Hücreyi formül enjeksiyonuna karşı nötralize ediyoruz.
                        sanitized_row[col] = self.sanitize_csv_cell(val)
                    # Aksi halde değeri aynen koruyoruz.
                    else:
                        # Değeri satıra atıyoruz.
                        sanitized_row[col] = val
                # Nötralize edilmiş satırı dosyaya yazıyoruz.
                writer.writerow(sanitized_row)
                # Yazılan satır adedini artırıyoruz.
                written_count += 1

        # Yazılan satır adedini döndürüyoruz.
        return written_count


class SecureJsonProcessor:
    """
    JSON verilerini anahtar çarpışması (Duplicate Key Collision), derin özyineleme (JSON Bomb),
    null-byte zehirlenmesi ve şema uyumsuzluklarına karşı koruyan güvenlik sınıfı.
    """

    def __init__(self, max_payload_bytes: int = 5242880, max_depth: int = 15) -> None:
        """
        Güvenli JSON işlemcisini azami bayt (Varsayılan: 5 MB) ve azami derinlik sınırlarıyla yapılandırır.
        """
        # Azami JSON yükü boyutunu kaydediyoruz.
        self.max_payload_bytes = max_payload_bytes
        # Azami nesne iç içe geçme derinliğini kaydediyoruz.
        self.max_depth = max_depth

    @staticmethod
    def _enforce_no_duplicate_keys(ordered_pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        """
        JSON nesnesi yüklenirken aynı anahtarın birden fazla geçmesini engelleyen katı kanca (hook).
        """
        # Sonuç sözlüğünü hazırlıyoruz.
        result_dict: Dict[str, Any] = {}
        # Gelen anahtar-değer ikililerini sırayla inceliyoruz.
        for key, value in ordered_pairs:
            # Anahtar sözlükte zaten mevcutsa çarpışma saldırısı tespit edilmiştir.
            if key in result_dict:
                # İkincil anahtarla yetki aşımını önlemek için ValueError fırlatıyoruz.
                raise ValueError(f"JSON nesnesinde mükerrer anahtar (duplicate key collision) tespit edildi: '{key}'")
            # Anahtarı sözlüğe kaydediyoruz.
            result_dict[key] = value
        # Benzersiz anahtarlarla oluşturulmuş sözlüğü döndürüyoruz.
        return result_dict

    def _validate_structure_recursively(self, node: Any, current_depth: int = 1) -> None:
        """
        JSON veri ağacını derinlik aşımı ve dize içi null-byte varlığı yönünden özyinelemeli denetler.
        """
        # Mevcut derinliğin azami izin verilen sınırı aşıp aşmadığını denetliyoruz.
        if current_depth > self.max_depth:
            # Aşırı derinlik durumunda JSON Bomb DoS koruması fırlatıyoruz.
            raise ValueError(f"JSON veri yapısı izin verilen azami derinliği ({self.max_depth}) aştı. Mevcut: {current_depth}")

        # Düğüm bir sözlükse her anahtar ve değeri denetliyoruz.
        if isinstance(node, dict):
            # Sözlük öğelerini geziyoruz.
            for k, v in node.items():
                # Anahtar metninde null-byte olup olmadığını sınıyoruz.
                if isinstance(k, str) and "\x00" in k:
                    # Null-byte bulunursa ValueError fırlatıyoruz.
                    raise ValueError(f"JSON nesne anahtarında null-byte bulundu: {repr(k)}")
                # Alt düğümü özyinelemeli olarak derinlik 1 artırarak sınıyoruz.
                self._validate_structure_recursively(v, current_depth + 1)
        # Düğüm bir listeyse her elemanı denetliyoruz.
        elif isinstance(node, list):
            # Liste elemanlarını geziyoruz.
            for item in node:
                # Alt elemanı derinlik 1 artırarak özyinelemeli sınıyoruz.
                self._validate_structure_recursively(item, current_depth + 1)
        # Düğüm bir dize ise null-byte kontrolü yapıyoruz.
        elif isinstance(node, str):
            # Dize içeriğinde null-byte varlığını denetliyoruz.
            if "\x00" in node:
                # Null-byte tespit edilirse açıkça ValueError fırlatıyoruz.
                raise ValueError(f"JSON dize değerinde geçersiz null-byte bulundu: {repr(node)}")

    def parse_json_safely(self, raw_json_str: str) -> Any:
        """
        Ham JSON dizesini yük boyutu, mükerrer anahtar, derinlik ve null-byte kontrolleriyle güvenle ayrıştırır.
        """
        # Girdinin dize olduğunu teyit ediyoruz.
        if not isinstance(raw_json_str, str):
            # Dize değilse TypeError fırlatıyoruz.
            raise TypeError(f"Ayrıştırılacak JSON verisi dize (str) olmalıdır, alınan: {type(raw_json_str).__name__}")

        # Ham dize bayt uzunluğunun tavanı aşıp aşmadığını denetliyoruz.
        payload_bytes = len(raw_json_str.encode("utf-8"))
        # Boyut sınırını kontrol ediyoruz.
        if payload_bytes > self.max_payload_bytes:
            # Sınır aşıldığında DoS savunması fırlatıyoruz.
            raise ValueError(f"JSON veri yükü izin verilen azami boyutu ({self.max_payload_bytes} bayt) aştı: {payload_bytes} bayt")

        # JSON ayrıştırma işlemini mükerrer anahtar engelleyici kanca ile gerçekleştiriyoruz.
        try:
            # json.loads fonksiyonunu katı hook ile çağırıyoruz.
            parsed_data = json.loads(raw_json_str, object_pairs_hook=self._enforce_no_duplicate_keys)
        # JSON sözdizim hatası yakalanırsa.
        except json.JSONDecodeError as decode_err:
            # Format bozukluğunu açıklayıcı ValueError ile yeniden sarmalıyoruz.
            raise ValueError(f"JSON sözdizimi geçersiz veya bozuk: {decode_err}") from decode_err

        # Ayrıştırılan veri yapısının derinlik ve null-byte denetimini yapıyoruz.
        self._validate_structure_recursively(parsed_data, current_depth=1)

        # Doğrulanmış ve temizlenmiş veriyi döndürüyoruz.
        return parsed_data

    def validate_schema(self, data: Dict[str, Any], schema_spec: Dict[str, type]) -> bool:
        """
        Sözlük verisinin verilen şema tanımlarına (zorunlu alanlar ve tipler) uygunluğunu denetler.
        """
        # Verinin bir sözlük olduğunu sınıyoruz.
        if not isinstance(data, dict):
            # Sözlük değilse TypeError fırlatıyoruz.
            raise TypeError("Şema doğrulaması için veri bir sözlük (dict) olmalıdır.")

        # Şemadaki her zorunlu alan ve beklenen tipi kontrol ediyoruz.
        for field_name, expected_type in schema_spec.items():
            # Zorunlu alan veride yoksa hata fırlatıyoruz.
            if field_name not in data:
                # Eksik alan durumunda ValueError fırlatıyoruz.
                raise ValueError(f"JSON verisinde zorunlu alan eksik: '{field_name}'")
            # Değerin tipini kontrol ediyoruz.
            val = data[field_name]
            # Değer beklenen tipin örneği değilse hata fırlatıyoruz.
            if not isinstance(val, expected_type):
                # Tip uyumsuzluğunda TypeError fırlatıyoruz.
                raise TypeError(
                    f"'{field_name}' alanı için tip uyumsuzluğu: Beklenen {expected_type.__name__}, alınan {type(val).__name__}"
                )

        # Tüm alanlar geçerliyse True döndürüyoruz.
        return True

    def serialize_safely(self, data: Any, indent: int = 2) -> str:
        """
        Python veri yapısını güvenli ve standartlaştırılmış JSON dizesine dönüştürür.
        """
        # Veri yapısını ayrıştırma öncesi derinlik kontrolünden geçiriyoruz.
        self._validate_structure_recursively(data, current_depth=1)
        # UTF-8 karakterleri koruyarak ve girintili biçimde serileştiriyoruz.
        return json.dumps(data, indent=indent, ensure_ascii=False)


class SecurityDataIngestionEngine:
    """
    Tehdit istihbaratı ve güvenlik olay kayıtlarını CSV ve JSON kaynaklarından
    entegre şekilde alan, doğrulayan, nötralize eden ve adli rapor üreten üst düzey motor.
    """

    def __init__(self, csv_processor: Optional[SecureCsvProcessor] = None, json_processor: Optional[SecureJsonProcessor] = None) -> None:
        """
        Ingestion motorunu CSV ve JSON işlemcileriyle başlatır.
        """
        # CSV işlemcisini başlatıyoruz veya varsayılan oluşturuyoruz.
        self.csv_proc = csv_processor if csv_processor is not None else SecureCsvProcessor()
        # JSON işlemcisini başlatıyoruz veya varsayılan oluşturuyoruz.
        self.json_proc = json_processor if json_processor is not None else SecureJsonProcessor()

    def process_threat_feed_csv(self, file_path: Path) -> Dict[str, Any]:
        """
        Tehdit istihbaratı CSV dosyasını okur, formül risklerini sayar ve güvenli kayıtları özetler.
        """
        # Beklenen şema başlıklarını tanımlıyoruz.
        expected_cols = ["timestamp", "indicator_ip", "threat_score", "malware_family", "action_taken"]
        # CSV dosyasını güvenle okuyoruz.
        raw_records = self.csv_proc.read_csv_safely(file_path, expected_headers=expected_cols)

        # Riskli hücre sayacını başlatıyoruz.
        formula_risk_count = 0
        # Güvenli kayıt listesini başlatıyoruz.
        sanitized_records: List[Dict[str, str]] = []

        # Her satırı inceliyoruz.
        for rec in raw_records:
            # Temizlenmiş satır sözlüğü oluşturuyoruz.
            clean_rec: Dict[str, str] = {}
            # Hücreleri dönüyoruz.
            for k, v in rec.items():
                # Formül riski varsa sayacı artırıyoruz.
                if self.csv_proc.has_formula_injection_risk(v):
                    # Risk sayacını 1 artırıyoruz.
                    formula_risk_count += 1
                # Değeri nötralize ederek ekliyoruz.
                clean_rec[k] = self.csv_proc.sanitize_csv_cell(v)
            # Listeye ekliyoruz.
            sanitized_records.append(clean_rec)

        # Özet istatistik sözlüğünü döndürüyoruz.
        return {
            "toplam_kayit": len(sanitized_records),
            "tespit_edilen_formula_riski": formula_risk_count,
            "kayitlar": sanitized_records
        }

    def process_security_events_json(self, raw_json_str: str) -> Dict[str, Any]:
        """
        Güvenlik olayları JSON dizesini ayrıştırır, şemasını doğrular ve yüksek tehditleri filtreler.
        """
        # JSON verisini güvenle ayrıştırıyoruz.
        parsed = self.json_proc.parse_json_safely(raw_json_str)

        # Kök nesnenin bir sözlük olduğunu doğruluyoruz.
        if not isinstance(parsed, dict):
            # Sözlük değilse ValueError fırlatıyoruz.
            raise ValueError("Kök JSON nesnesi sözlük olmalıdır.")

        # Olay listesini alıyoruz.
        events = parsed.get("security_events", [])
        # Olay şema kurallarını tanımlıyoruz.
        event_schema = {
            "event_id": str,
            "source_ip": str,
            "threat_score": int,
            "severity": str,
            "is_blocked": bool
        }

        # Yüksek riskli olayları toplayacağımız listeyi başlatıyoruz.
        high_severity_events: List[Dict[str, Any]] = []

        # Her olayı şemaya göre denetliyoruz.
        for ev in events:
            # Olayın şemaya uygunluğunu sınıyoruz.
            self.json_proc.validate_schema(ev, event_schema)
            # Tehdit skoru 70 ve üzerindekileri yüksek riskli olarak ayırıyoruz.
            if ev["threat_score"] >= 70:
                # Listeye ekliyoruz.
                high_severity_events.append(ev)

        # Analiz özet raporunu döndürüyoruz.
        return {
            "toplam_olay": len(events),
            "kritik_ve_yuksek_olay_sayisi": len(high_severity_events),
            "filtrelenen_olaylar": high_severity_events
        }


# Modül doğrudan çalıştırıldığında test ve kanıt üretim akışını başlatıyoruz.
if __name__ == "__main__":
    # Konsola başlangıç başlığını yazdırıyoruz.
    print("[+] G079: CSV ve JSON Veri İşleme Motoru Başlatılıyor...")

    # Örnek veri yollarını belirliyoruz.
    base_dir = Path(__file__).resolve().parent.parent
    # CSV örnek dosya yolunu alıyoruz.
    csv_sample_path = base_dir / "ornek_veri" / "sample_threat_feed.csv"
    # JSON örnek dosya yolunu alıyoruz.
    json_sample_path = base_dir / "ornek_veri" / "sample_security_events.json"

    # Veri işleme motorunu başlatıyoruz.
    engine = SecurityDataIngestionEngine()

    # CSV tehdit beslemesini işliyoruz.
    csv_result = engine.process_threat_feed_csv(csv_sample_path)
    # Konsola CSV sonuç özetini yazdırıyoruz.
    print(f"[+] CSV İşlendi: {csv_result['toplam_kayit']} kayıt, {csv_result['tespit_edilen_formula_riski']} formül riski nötralize edildi.")

    # JSON dosyasını okuyoruz.
    with open(json_sample_path, "r", encoding="utf-8") as f:
        # JSON içeriğini yüklüyoruz.
        json_content = f.read()

    # JSON olaylarını işliyoruz.
    json_result = engine.process_security_events_json(json_content)
    # Konsola JSON analiz özetini yazdırıyoruz.
    print(f"[+] JSON İşlendi: {json_result['toplam_olay']} olaydan {json_result['kritik_ve_yuksek_olay_sayisi']} adedi kritik/yüksek tehdit.")

    # Adli kanıt raporunun kaydedileceği yolu belirliyoruz.
    report_output_path = base_dir / "kanit" / "gercek" / "guvenli_veri_isleme_raporu.txt"
    # Rapor dosyasını yazma modunda açıyoruz.
    with open(report_output_path, "w", encoding="utf-8") as rf:
        # Rapor başlığını yazıyoruz.
        rf.write("=== G079 GÜVENLİ CSV VE JSON İŞLEME VE ADLİ DENETİM RAPORU ===\n")
        # CSV istatistiklerini yazıyoruz.
        rf.write(f"Toplam CSV Tehdit Kaydı: {csv_result['toplam_kayit']}\n")
        # Nötralize edilen formül sayısını yazıyoruz.
        rf.write(f"Nötralize Edilen Formül Enjeksiyonu: {csv_result['tespit_edilen_formula_riski']}\n")
        # JSON istatistiklerini yazıyoruz.
        rf.write(f"Toplam JSON Güvenlik Olayı: {json_result['toplam_olay']}\n")
        # Kritik olay sayısını yazıyoruz.
        rf.write(f"Kritik ve Yüksek Tehdit Skoru Taşıyan Olaylar: {json_result['kritik_ve_yuksek_olay_sayisi']}\n")
        # Başarılı tamamlanma notunu yazıyoruz.
        rf.write("Durum: Bütünlük ve Güvenlik Süzgeçleri Başarıyla Doğrulandı (PASS)\n")

    # Tamamlanma bildirimini konsola basıyoruz.
    print(f"[+] Güvenlik analiz raporu kaydedildi: {report_output_path}")
