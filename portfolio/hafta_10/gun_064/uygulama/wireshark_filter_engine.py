# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G064: Hafta 10 Gün 64 - Wireshark Görüntüleme Filtresi Sözdizimi ve Ayrıştırma Motoru.
Bu modül, Wireshark standartlarındaki görüntüleme filtrelerini (display filter)
sözcüksel analiz (lexer) ve sözdizim ağacı (AST) ile işleyip ağ paketlerine uygular.
"""

# Düzenli ifadeler ve desen eşleme için re modülü içe aktarılır
import re
# Karmaşık tipler ve tip ipuçları için typing modülü içe aktarılır
from typing import Dict, List, Any, Optional, Tuple, Union, Set
# Yapılandırılmış sınıflar için dataclass içe aktarılır
from dataclasses import dataclass, field


# Temel Wireshark filtreleme istisnası
class WiresharkFilterError(Exception):
    """Wireshark filtre motorundaki tüm genel hataların temel sınıfıdır."""
    # Üst sınıf metodu boş geçilir
    pass


# Sözdizim hatası istisnası
class FilterSyntaxError(WiresharkFilterError):
    """Filtre ifadesinde parantez dengesizliği veya gramer hatası olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Tanımsız alan hatası istisnası
class UnknownFieldError(WiresharkFilterError):
    """Desteklenmeyen veya protokol şemasında yer almayan bir alan sorgulandığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Veri tipi uyuşmazlığı istisnası
class FilterTypeError(WiresharkFilterError):
    """Sayısal bir alana metin veya uyumsuz bir karşılaştırma uygulandığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bayt dilimleme taşma istisnası
class SliceOutOfBoundsError(WiresharkFilterError):
    """Bayt dilimleme aralığı geçersiz olduğunda veya veri boyutunu aştığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz düzenli ifade istisnası
class RegexFilterError(WiresharkFilterError):
    """'matches' operatörüne verilen regex deseni bozuk olduğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Boş filtre girdisi istisnası
class EmptyFilterError(WiresharkFilterError):
    """Filtre dizgesi boş veya sadece boşluklardan oluştuğunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Geçersiz karşılaştırma operatörü istisnası
class InvalidOperatorError(WiresharkFilterError):
    """Desteklenmeyen veya hatalı bir mantıksal/karşılaştırma operatörü kullanıldığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bozuk paket verisi istisnası
class MalformedPacketError(WiresharkFilterError):
    """Filtrelenecek paket nesnesi geçersiz veya sözlük tipinde olmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Sözcüksel analiz (tokenizasyon) hatası istisnası
class FilterTokenizeError(WiresharkFilterError):
    """Tırnak kapatılmaması veya ayrıştırılamayan semboller durumunda fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Desteklenen protokol alanları ve beklenen veri tipleri kayıt defteri
SUPPORTED_FIELDS: Dict[str, type] = {
    "frame.number": int,
    "frame.len": int,
    "frame.time_epoch": float,
    "ip.src": str,
    "ip.dst": str,
    "ip.proto": int,
    "ip.addr": str,  # Takma alan (ip.src veya ip.dst)
    "tcp.srcport": int,
    "tcp.dstport": int,
    "tcp.port": int,  # Takma alan (tcp.srcport veya tcp.dstport)
    "tcp.flags.syn": int,
    "tcp.flags.ack": int,
    "tcp.flags.reset": int,
    "tcp.flags.fin": int,
    "tcp.window_size": int,
    "tcp.payload_hex": str,
    "tcp.payload": str,  # Takma alan (tcp.payload_hex)
    "http.request.method": str,
    "http.request.uri": str,
    "http.user_agent": str,
    "http.body": str,
    "http": str,  # Takma alan (tüm http yükü)
    "udp.srcport": int,
    "udp.dstport": int,
    "udp.port": int,  # Takma alan
    "dns.flags.response": int,
    "dns.qry.name": str,
    "dns.qry.name.len": int,
    "dns.qry.type": int,
    "ssh.protocol": str,
    "tls.handshake.type": int,
    "tls.handshake.version": str,
    "tls.handshake.extensions_server_name": str,
    "icmp.type": int,
    "icmp.code": int
}


# Sözdizim ağacı (AST) temel düğüm sınıfı
class ASTNode:
    """Wireshark soyut sözdizim ağacının soyut temel sınıfıdır."""
    # Düğüm değerlendirme soyut metodu
    def evaluate(self, packet: Dict[str, Any]) -> bool:
        """Verilen ayrıştırılmış paket üzerinde düğüm kuralını işletir."""
        # Alt sınıflarca uygulanmalıdır
        raise NotImplementedError("evaluate() alt sınıfta uygulanmalıdır.")


# Karşılaştırma düğümü (Field Comparison)
@dataclass
class ComparisonNode(ASTNode):
    """Tekil bir alanın değerle karşılaştırılmasını temsil eder (örn: ip.src == '10.0.0.1')."""
    # Karşılaştırılacak alan adı
    field_name: str
    # Karşılaştırma operatörü (==, !=, >, <, >=, <=, contains, matches, in)
    operator: str
    # Karşılaştırılacak hedef değer veya değerler listesi
    target_value: Any
    # Varsa bayt dilimleme aralığı (başlangıç, uzunluk)
    slice_range: Optional[Tuple[int, int]] = None

    # Düğümü paket üzerinde değerlendiren metot
    def evaluate(self, packet: Dict[str, Any]) -> bool:
        """Alan değerini paketten çeker ve operatör mantığına göre karşılaştırır."""
        # Paket içeriğinde doğrudan alan arama veya takma alan kontrolü
        actual_val = self._extract_field_value(packet)
        # Değer pakette bulunamazsa kural eşleşmez
        if actual_val is None:
            # False döndürülür
            return False

        # Bayt dilimleme varsa işletilir
        if self.slice_range is not None:
            # Dilimleme aralığı başlangıç ve uzunluk olarak ayrılır
            start, length = self.slice_range
            # Gerçek değer dizgiye çevrilir
            val_str = str(actual_val)
            # Değer tamamen boşsa (bu pakette alan mevcut değilse) eşleşmez
            if not val_str:
                # Eşleşme yok
                return False
            # Değer mevcut fakat dilimleme sınır aşımı denetimi yapılır
            if start + length > len(val_str):
                # Dilimleme sınır taşması hatası fırlatılır
                raise SliceOutOfBoundsError(f"Bayt dilimleme boyutu ({start}:{length}) alan uzunluğunu ({len(val_str)}) aşıyor!")
            # Hedef dilim çıkarılır
            actual_val = val_str[start:start + length]

        # Operatör eşleştirme mantığı
        op = self.operator.lower()
        # Eşitlik operatörü
        if op in ("==", "eq"):
            # Değerlerin eşitliği kontrol edilir
            return actual_val == self.target_value
        # Eşitsizlik operatörü
        elif op in ("!=", "ne"):
            # Değerlerin eşit olmadığı kontrol edilir
            return actual_val != self.target_value
        # Büyüktür operatörü
        elif op in (">", "gt"):
            # Büyüklük kontrolü
            return actual_val > self.target_value
        # Küçüktür operatörü
        elif op in ("<", "lt"):
            # Küçüklük kontrolü
            return actual_val < self.target_value
        # Büyük veya eşittir
        elif op in (">=", "ge"):
            # Büyük eşit kontrolü
            return actual_val >= self.target_value
        # Küçük veya eşittir
        elif op in ("<=", "le"):
            # Küçük eşit kontrolü
            return actual_val <= self.target_value
        # İçerir (contains) operatörü
        elif op == "contains":
            # Metin içi arama yapılır
            return str(self.target_value).lower() in str(actual_val).lower()
        # Düzenli ifade (matches) operatörü
        elif op == "matches":
            # Regex deseni aranır
            try:
                # Desen paketteki değer üzerinde aranır
                return bool(re.search(str(self.target_value), str(actual_val)))
            # Bozuk regex hatası yakalanır
            except re.error as err:
                # Regex hatası fırlatılır
                raise RegexFilterError(f"Geçersiz regex ifadesi '{self.target_value}': {err}")
        # Küme içi üyelik (in) operatörü
        elif op == "in":
            # Hedef küme veya liste içinde varlık denetlenir
            if isinstance(self.target_value, (list, set, tuple)):
                # Listede mi bakılır
                return actual_val in self.target_value
            # Tekil değerle eşitlik denetlenir
            return actual_val == self.target_value
        # Tanımsız operatör
        else:
            # Operatör hatası fırlatılır
            raise InvalidOperatorError(f"Desteklenmeyen operatör: {self.operator}")

    # Paketten alan değerini çeken yardımcı metot
    def _extract_field_value(self, packet: Dict[str, Any]) -> Any:
        """Takma alanları (ip.addr, tcp.port) ve doğrudan alanları paketten çeker."""
        # 1. Takma alan: ip.addr (ip.src veya ip.dst)
        if self.field_name == "ip.addr":
            # Kaynak veya hedef IP kontrol edilir
            src = packet.get("ip.src")
            dst = packet.get("ip.dst")
            # İki adresten biri hedef değerle eşleşiyorsa o adres döner
            if src == self.target_value or (self.operator == "contains" and str(self.target_value) in str(src)):
                # Kaynak döner
                return src
            # Hedef döner
            return dst

        # 2. Takma alan: tcp.port (tcp.srcport veya tcp.dstport)
        if self.field_name == "tcp.port":
            # Kaynak ve hedef portlar alınır
            src_p = packet.get("tcp.srcport")
            dst_p = packet.get("tcp.dstport")
            # Hedef port ile eşleşme denetlenir
            if src_p == self.target_value:
                # Kaynak döner
                return src_p
            # Hedef döner
            return dst_p

        # 3. Takma alan: http (tüm http alanlarının birleşimi)
        if self.field_name == "http":
            # Tüm http ile başlayan alanların metinleri birleştirilir
            http_parts = [str(v) for k, v in packet.items() if k.startswith("http")]
            # Birleştirilmiş metin döndürülür
            return " ".join(http_parts)

        # 4. Takma alan: tcp.payload (tcp.payload_hex)
        if self.field_name == "tcp.payload":
            # Hex payload döner
            return packet.get("tcp.payload_hex", "")

        # 5. Standart doğrudan alan
        return packet.get(self.field_name)


# Mantıksal ikili düğüm (Logical Binary Node: AND / OR)
@dataclass
class LogicalBinaryNode(ASTNode):
    """İki alt ifadenin AND (&&) veya OR (||) ile bağlanmasını temsil eder."""
    # Mantıksal operatör ("&&" veya "||")
    operator: str
    # Sol alt düğüm
    left: ASTNode
    # Sağ alt düğüm
    right: ASTNode

    # Düğüm değerlendirme metodu
    def evaluate(self, packet: Dict[str, Any]) -> bool:
        """Sol ve sağ dalları mantıksal operatör kuralına göre değerlendirir."""
        # VE mantığı (AND)
        if self.operator in ("&&", "and"):
            # Kısa devre değerlendirmesi (sol False ise sağ çalıştırılmaz)
            return self.left.evaluate(packet) and self.right.evaluate(packet)
        # VEYA mantığı (OR)
        elif self.operator in ("||", "or"):
            # Kısa devre değerlendirmesi (sol True ise sağ çalıştırılmaz)
            return self.left.evaluate(packet) or self.right.evaluate(packet)
        # Geçersiz operatör durumu
        else:
            # Hata fırlatılır
            raise InvalidOperatorError(f"Geçersiz mantıksal ikili operatör: {self.operator}")


# Mantıksal DEĞİL düğümü (Logical NOT Node: !)
@dataclass
class LogicalNotNode(ASTNode):
    """Bir ifadenin mantıksal tersini alır (! veya not)."""
    # Tersine çevrilecek alt düğüm
    operand: ASTNode

    # Düğüm değerlendirme metodu
    def evaluate(self, packet: Dict[str, Any]) -> bool:
        """Alt ifadenin doğruluk değerinin tersini döndürür."""
        # Değer tersine çevrilir
        return not self.operand.evaluate(packet)


# Wireshark filtre ayrıştırma ve değerlendirme motoru
class WiresharkFilterEngine:
    """Wireshark görüntüleme filtrelerini derleyen, denetleyen ve paketleri süzen ana motor."""

    # Sınıf başlatıcı
    def __init__(self) -> None:
        # Desteklenen alan sözlüğü yerel referansa bağlanır
        self.supported_fields = SUPPORTED_FIELDS

    # Filtre metnini sözcük birimlerine (token) ayıran metot
    def tokenize(self, filter_str: str) -> List[str]:
        """Filtre dizgesini parantezler, operatörler, dizgiler ve alanlara ayırır."""
        # Filtre metninin boşlukları temizlenir
        cleaned = filter_str.strip()
        # Boş filtre denetimi
        if not cleaned:
            # Boş filtre istisnası fırlatılır
            raise EmptyFilterError("Filtre ifadesi boş bırakılamaz.")

        # Ayrıştırılan tokenlar listesi
        tokens: List[str] = []
        # Karakter indeksi işaretçisi
        i = 0
        # Metin uzunluğu
        n = len(cleaned)

        # Karakter bazlı sözcük tarayıcı döngüsü
        while i < n:
            # Boşluk karakterleri atlanır
            if cleaned[i].isspace():
                # İndeks bir artırılır
                i += 1
                # Döngüye devam edilir
                continue

            # Çift tırnaklı metin sabiti yakalama
            if cleaned[i] == '"':
                # Bitiş tırnağı aranır
                end_idx = cleaned.find('"', i + 1)
                # Tırnak kapatılmamışsa hata fırlatılır
                if end_idx == -1:
                    # Kapatılmamış tırnak hatası
                    raise FilterTokenizeError(f"Kapatılmamış çift tırnak bulundu: {cleaned[i:]}")
                # Tırnak içindeki metin alınır
                token = cleaned[i:end_idx + 1]
                # Listeye eklenir
                tokens.append(token)
                # İndeks güncellenir
                i = end_idx + 1
                # Döngü devam eder
                continue

            # Tek karakterlik parantezler
            if cleaned[i] in ("(", ")"):
                # Parantez token olarak eklenir
                tokens.append(cleaned[i])
                # İndeks artırılır
                i += 1
                # Devam edilir
                continue

            # Üç karakterlik geçersiz operatör denetimi (örn: ===)
            if cleaned[i:i + 3] == "===":
                # Geçersiz operatör hatası fırlatılır
                raise InvalidOperatorError("Geçersiz operatör: '===' Wireshark sözdiziminde desteklenmez.")

            # İki karakterlik operatörler (==, !=, >=, <=, &&, ||)
            two_char = cleaned[i:i + 2]
            # Eşleşme kontrolü
            if two_char in ("==", "!=", ">=", "<=", "&&", "||"):
                # Token eklenir
                tokens.append(two_char)
                # İki karakter ilerlenir
                i += 2
                # Devam edilir
                continue

            # Tek karakterlik operatörler (!, >, <)
            if cleaned[i] in ("!", ">", "<"):
                # Token eklenir
                tokens.append(cleaned[i])
                # İndeks artırılır
                i += 1
                # Devam edilir
                continue

            # Küme tanımlayıcıları ({ ve })
            if cleaned[i] in ("{", "}"):
                # Token eklenir
                tokens.append(cleaned[i])
                # İndeks artırılır
                i += 1
                # Devam edilir
                continue

            # Kelime veya sayısal sabit yakalama
            match = re.match(r"[A-Za-z0-9_.:/\[\]-]+", cleaned[i:])
            # Eşleşme bulunduysa
            if match:
                # Eşleşen metin alınır
                word = match.group(0)
                # Listeye eklenir
                tokens.append(word)
                # Uzunluk kadar ilerlenir
                i += len(word)
            else:
                # Beklenmeyen karakter hatası
                raise FilterTokenizeError(f"Beklenmeyen karakter algılandı: '{cleaned[i]}'")

        # Üretilen tokenlar döndürülür
        return tokens

    # Parantez dengesini doğrulayan yardımcı metot
    @staticmethod
    def validate_parentheses(tokens: List[str]) -> None:
        """Açılan ve kapanan parantezlerin dengesini kontrol eder."""
        # Parantez derinliği sayacı
        balance = 0
        # Tokenlar taranır
        for tok in tokens:
            # Açılış parantezi
            if tok == "(":
                # Sayaç artırılır
                balance += 1
            # Kapanış parantezi
            elif tok == ")":
                # Sayaç azaltılır
                balance -= 1
                # Negatife düşerse kapanış fazlası vardır
                if balance < 0:
                    # Hata fırlatılır
                    raise FilterSyntaxError("Dengesiz parantez: Açılmamış kapanış parantezi ')' bulundu.")
        # Döngü sonunda sayaç sıfır değilse açılış fazlası vardır
        if balance != 0:
            # Dengesiz parantez hatası
            raise FilterSyntaxError(f"Dengesiz parantez: {balance} adet kapatılmamış parantez '(' var.")

    # Token listesinden AST inşa eden özyinelemeli ayrıştırıcı (Recursive Descent Parser)
    def parse(self, tokens: List[str]) -> ASTNode:
        """Token dizisini mantıksal öncelik sırasına göre AST düğümlerine dönüştürür."""
        # Parantez denetimi işletilir
        self.validate_parentheses(tokens)
        # Parse işlemini başlatan yardımcı çağrı
        node, remaining = self._parse_or(tokens)
        # Kalan beklenmeyen token varsa hata verilir
        if remaining:
            # Fazlalık token hatası
            raise FilterSyntaxError(f"Ayrıştırılamayan artık tokenlar: {remaining}")
        # Kök düğüm döndürülür
        return node

    # OR seviyesi ayrıştırma metodu
    def _parse_or(self, tokens: List[str]) -> Tuple[ASTNode, List[str]]:
        """Mantıksal OR (||, or) ifadelerini ayrıştırır."""
        # Sol dal AND seviyesinden alınır
        left, rem = self._parse_and(tokens)
        # Kalan tokenlar OR ile devam ettiği sürece bağlanır
        while rem and rem[0].lower() in ("||", "or"):
            # Operatör tokenı alınır
            op = rem[0]
            # Sağ dal AND seviyesinden çözülür
            right, rem = self._parse_and(rem[1:])
            # Sol dal yeni ikili mantık düğümü olarak güncellenir
            left = LogicalBinaryNode(operator=op, left=left, right=right)
        # Düğüm ve kalan tokenlar döndürülür
        return left, rem

    # AND seviyesi ayrıştırma metodu
    def _parse_and(self, tokens: List[str]) -> Tuple[ASTNode, List[str]]:
        """Mantıksal AND (&&, and) ifadelerini ayrıştırır."""
        # Sol dal NOT seviyesinden alınır
        left, rem = self._parse_not(tokens)
        # Kalan tokenlar AND ile devam ettiği sürece bağlanır
        while rem and rem[0].lower() in ("&&", "and"):
            # Operatör alınır
            op = rem[0]
            # Sağ dal NOT seviyesinden çözülür
            right, rem = self._parse_not(rem[1:])
            # Sol dal güncellenir
            left = LogicalBinaryNode(operator=op, left=left, right=right)
        # Düğüm ve kalan tokenlar döndürülür
        return left, rem

    # NOT seviyesi ayrıştırma metodu
    def _parse_not(self, tokens: List[str]) -> Tuple[ASTNode, List[str]]:
        """Mantıksal NOT (!, not) ifadelerini ayrıştırır."""
        # Boş token kontrolü
        if not tokens:
            # Eksik ifade hatası
            raise FilterSyntaxError("Beklenmeyen ifade sonu (boş token).")
        # İlk token NOT ise
        if tokens[0].lower() in ("!", "not"):
            # Sağındaki ifade çözülür
            operand, rem = self._parse_not(tokens[1:])
            # LogicalNotNode döndürülür
            return LogicalNotNode(operand=operand), rem
        # Değilse atomik ifadeye geçilir
        return self._parse_primary(tokens)

    # Birincil (parantez içi veya karşılaştırma) ayrıştırma metodu
    def _parse_primary(self, tokens: List[str]) -> Tuple[ASTNode, List[str]]:
        """Parantezli ifadeleri veya tekil karşılaştırma bloklarını ayrıştırır."""
        # Boş kontrolü
        if not tokens:
            # Hata verilir
            raise FilterSyntaxError("İfade eksik veya beklenmedik şekilde bitti.")

        # Parantez açılışı ise
        if tokens[0] == "(":
            # İçerideki ifade OR seviyesinden çözülür
            node, rem = self._parse_or(tokens[1:])
            # Kapanış parantezi kontrol edilir
            if not rem or rem[0] != ")":
                # Kapanış eksikliği hatası
                raise FilterSyntaxError("Kapanış parantezi ')' bulunamadı.")
            # Parantez atlanarak düğüm ve kalan döner
            return node, rem[1:]

        # Karşılaştırma bloğu: [alan] [operatör] [değer]
        return self._parse_comparison(tokens)

    # Karşılaştırma bloğunu ayrıştıran metot
    def _parse_comparison(self, tokens: List[str]) -> Tuple[ComparisonNode, List[str]]:
        """Alan adı, operatör ve hedef değeri ayrıştırır ve tip denetimi yapar."""
        # En az 3 token beklenir (örn: ip.src == "10.0.0.1")
        if len(tokens) < 3:
            # Yetersiz token hatası
            raise FilterSyntaxError(f"Geçersiz karşılaştırma sözdizimi: {' '.join(tokens)}")

        # İlk token alan adı veya dilimlenmiş alandır
        raw_field = tokens[0]
        # Operatör tokenı
        raw_op = tokens[1]
        # Değer tokenı
        raw_val = tokens[2]
        # Kalan tokenlar
        rem = tokens[3:]

        # Bayt dilimleme denetimi (örn: tcp.payload[0:4])
        slice_range: Optional[Tuple[int, int]] = None
        clean_field = raw_field
        # Köşeli parantez varsa dilim ayrıştırılır
        if "[" in raw_field and raw_field.endswith("]"):
            # Alan ve dilim parçalanır
            base_field, slice_str = raw_field[:-1].split("[", 1)
            # Temiz alan adı atanır
            clean_field = base_field
            # İki nokta ile ayrılan aralık alınır
            if ":" in slice_str:
                # Başlangıç ve uzunluk parçalanır
                s_parts = slice_str.split(":")
                # Sayıya çevrilir
                start = int(s_parts[0])
                length = int(s_parts[1])
                # Dilim aralığı saklanır
                slice_range = (start, length)
            else:
                # Hatalı dilim biçimi
                raise SliceOutOfBoundsError(f"Geçersiz dilim formatı: '{slice_str}' (beklenen: start:length)")

        # Desteklenen alan adı denetimi
        if clean_field not in self.supported_fields:
            # Bilinmeyen alan hatası fırlatılır
            raise UnknownFieldError(f"Desteklenmeyen veya tanımlanmamış protokol alanı: '{clean_field}'")

        # Geçerli operatörler kümesi
        valid_ops = {"==", "!=", ">", "<", ">=", "<=", "eq", "ne", "gt", "lt", "ge", "le", "contains", "matches", "in"}
        # Operatör denetimi
        if raw_op.lower() not in valid_ops:
            # Geçersiz operatör hatası
            raise InvalidOperatorError(f"Geçersiz karşılaştırma operatörü: '{raw_op}'")

        # Hedef değer tip dönüştürme ve doğrulama
        expected_type = self.supported_fields[clean_field]
        # Metin tırnaklarının temizlenmesi
        parsed_val: Any = raw_val
        # Çift tırnak varsa metin sabiti
        if raw_val.startswith('"') and raw_val.endswith('"'):
            # Tırnaklar atılır
            parsed_val = raw_val[1:-1]
        # Tip doğrulaması
        if expected_type == int:
            # Tırnaklı string girilmişse tip hatası
            if raw_val.startswith('"') and not raw_val[1:-1].isdigit():
                # Tip uyuşmazlığı hatası
                raise FilterTypeError(f"'{clean_field}' alanı sayısal (int) tipte olmalıdır, metin girilemez: {raw_val}")
            # Sayıya çevrilir
            try:
                # Tamsayıya dönüştürülür
                parsed_val = int(parsed_val)
            # Sayı olamıyorsa tip hatası
            except ValueError:
                # Tip hatası fırlatılır
                raise FilterTypeError(f"'{clean_field}' alanı için geçersiz tamsayı değeri: {raw_val}")

        # Karşılaştırma düğümü örneği oluşturulur
        node = ComparisonNode(
            field_name=clean_field,
            operator=raw_op,
            target_value=parsed_val,
            slice_range=slice_range
        )
        # Düğüm ve kalan tokenlar döndürülür
        return node, rem

    # Filtre dizgesini doğrudan derleyip AST üreten kolaylık metodu
    def compile_filter(self, filter_str: str) -> ASTNode:
        """Verilen filtre dizesini sözcüksel ve anlamsal olarak analiz edip AST düğümünü döner."""
        # Tokenlara ayırır
        tokens = self.tokenize(filter_str)
        # AST inşa eder
        return self.parse(tokens)

    # Tek bir paketi derlenmiş filtreye göre değerlendiren metot
    def evaluate_packet(self, packet: Dict[str, Any], ast_root: ASTNode) -> bool:
        """Verilen paketi AST kök düğümü üzerinden süzgeçten geçirir."""
        # Paket tipi sözlük olmalıdır
        if not isinstance(packet, dict):
            # Bozuk paket istisnası fırlatılır
            raise MalformedPacketError("Paket verisi geçerli bir sözlük (dict) olmalıdır.")
        # Düğümün evaluate fonksiyonu çağrılır
        return ast_root.evaluate(packet)

    # Paket listesini filtre dizgesiyle süzen toplu metot
    def filter_packets(self, packets: List[Dict[str, Any]], filter_str: str) -> List[Dict[str, Any]]:
        """Verilen paket havuzunda filtreyi koşturur ve uyuşan paketleri listeler."""
        # Paket listesi tipi doğrulanır
        if not isinstance(packets, list):
            # Paket bozuk hatası
            raise MalformedPacketError("Paket havuzu bir liste (list) olmalıdır.")
        # Filtre AST'si derlenir
        ast_root = self.compile_filter(filter_str)
        # Eşleşen paketler listesi
        matched: List[Dict[str, Any]] = []
        # Her paket için test edilir
        for pkt in packets:
            # Paket değerlendirilir
            if self.evaluate_packet(pkt, ast_root):
                # Eşleşenler arasına eklenir
                matched.append(pkt)
        # Sonuç döndürülür
        return matched

    # Siber tehdit avcılığı (Threat Hunting) profillerini koşturan metot
    def run_threat_hunting_profile(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ağ trafiğinde önceden tanımlanmış siber saldırı kalıplarını Wireshark filtreleriyle tarar."""
        # Önceden tanımlanmış kritik güvenlik filtreleri
        threat_rules = {
            "SYN_FLOOD_VEYA_TARAMA": "tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "PORT_TARAMA_RST_YANITI": "tcp.flags.reset == 1",
            "ACIK_METIN_KIMLIK_BILGISI": 'http.request.method == "POST" && (http contains "password" || http contains "auth")',
            "DNS_TUNELLEME_SIZINTISI": "dns.qry.name.len > 40 && dns.flags.response == 0",
            "SIFIR_PENCERE_KILITLENMESI": "tcp.window_size == 0 && tcp.flags.reset == 0"
        }

        # Sonuç raporu sözlüğü
        results: Dict[str, Any] = {
            "toplam_paket": len(packets),
            "bulgular": {},
            "guvenlik_uyarilari": []
        }

        # Her kural koşturulur
        for rule_name, filter_expr in threat_rules.items():
            # Filtre koşturulur
            matched_pkts = self.filter_packets(packets, filter_expr)
            # Sayı ve eşleşen paket numaraları kaydedilir
            results["bulgular"][rule_name] = {
                "filtre": filter_expr,
                "eslesen_paket_sayisi": len(matched_pkts),
                "paket_numaralari": [p.get("frame.number") for p in matched_pkts]
            }
            # Tehdit tespit edildiyse uyarı üretilir
            if matched_pkts:
                # Uyarı listesine eklenir
                results["guvenlik_uyarilari"].append(
                    f"TEHDİT TESPİTİ [{rule_name}]: {len(matched_pkts)} paket yakalandı! Filtre: {filter_expr}"
                )

        # Rapor döndürülür
        return results
