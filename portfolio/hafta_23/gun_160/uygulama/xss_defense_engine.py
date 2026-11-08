# -*- coding: utf-8 -*-
"""
Gün 160: XSS Türleri ve Savunma Motoru (xss_defense_engine.py)

Bu modül; Reflected, Stored ve DOM-based XSS saldırı vektörlerini derinlemesine
analiz eden, kaynak (source) ve havuz (sink) akışlarını tespit eden, katı allowlist
tabanlı HTML temizleme (sanitization), bağlama duyarlı çıktı kodlama (context-aware encoding)
ve CSP Seviye 3 (Content Security Policy) politikası üreten kurumsal bir savunma motorudur.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import re  # Düzenli ifadeler ile zararlı örüntü taraması için re modülü dahil edilir
import html  # Standart HTML varlık kaçış işlemleri için html modülü dahil edilir
import secrets  # Kriptografik güvenli CSP nonce üretimi için secrets modülü dahil edilir
import urllib.parse  # URL ayrıştırma ve bileşen kodlama için urllib.parse dahil edilir
from enum import Enum  # Güçlü tip güvenliği sağlayan numaralandırma sınıfı dahil edilir
from typing import Dict, List, Optional, Tuple, Any, Set  # Tip ipuçları için gerekli sınıflar dahil edilir
from html.parser import HTMLParser  # Güvenli HTML ayrıştırma ve arındırma için HTMLParser sınıfı dahil edilir


class XSSType(str, Enum):
    """XSS saldırı türlerini temsil eden numaralandırma."""
    REFLECTED = "REFLECTED_XSS"  # Kullanıcı girdisinin doğrudan HTTP yanıtında yansıtıldığı tür
    STORED = "STORED_XSS"  # Zararlı kodun veritabanı veya oturumda kalıcı saklandığı tür
    DOM_BASED = "DOM_BASED_XSS"  # İstemci tarafı JavaScript betiğinin DOM havuzunu güvensiz güncellediği tür
    MUTATION_XSS = "MUTATION_XSS"  # Tarayıcı HTML parser mutasyonundan yararlanan bypass türü


class XSSSeverity(str, Enum):
    """XSS zafiyet ciddiyet seviyesi."""
    CRITICAL = "CRITICAL"  # Oturum çalma veya uzaktan yetkisiz işlem tetikleyen kritik seviye
    HIGH = "HIGH"  # Sayfa içeriğini bütünüyle tahrif eden veya kimlik avı yapan yüksek seviye
    MEDIUM = "MEDIUM"  # Kısıtlı etki alanına sahip DOM manipülasyonu
    LOW = "LOW"  # Düşük etkili yansıma veya bilgi sızıntısı


class XSSFinding:
    """Tespit edilen bir XSS zafiyeti veya atağını tutan veri modeli."""
    def __init__(self, xss_type: XSSType, severity: XSSSeverity, pattern: str, description: str, matched_text: str):
        self.xss_type: XSSType = xss_type  # Tespit edilen XSS sınıflandırması kaydedilir
        self.severity: XSSSeverity = severity  # Zafiyetin risk derecesi kaydedilir
        self.pattern: str = pattern  # Eşleşen tehdit kuralı veya imza kimliği kaydedilir
        self.description: str = description  # Teknik açıklama ve zafiyet detayı kaydedilir
        self.matched_text: str = matched_text  # Girdi içerisindeki zararlı kod parçası kaydedilir

    def to_dict(self) -> Dict[str, Any]:
        """Bulguyu sözlük yapısına dönüştürür."""
        return {
            "xss_type": self.xss_type.value,  # XSS türü dize olarak aktarılır
            "severity": self.severity.value,  # Ciddiyet dize olarak aktarılır
            "pattern": self.pattern,  # İmzalı desen adı aktarılır
            "description": self.description,  # Açıklama metni aktarılır
            "matched_text": self.matched_text[:120]  # Eşleşen tehlikeli metin sınırlanarak aktarılır
        }


class XSSPayloadDetector:
    """Girdilerde XSS saldırı vektörlerini tespit eden analiz katmanı."""

    # Script etiketi kalıpları
    SCRIPT_TAG_PATTERN = re.compile(r"<\s*script[^>]*>.*?(<\s*/\s*script\s*>|$)", re.IGNORECASE | re.DOTALL)
    # Inline olay dinleyicisi kalıpları (onload, onerror, onclick, onfocus vs.)
    EVENT_HANDLER_PATTERN = re.compile(r"\bon\w+\s*=\s*(?:'[^']*'|\"[^\"]*\"|[^\s>]+)", re.IGNORECASE)
    # Sözde protokol kalıpları (javascript:, vbscript:, data:text/html)
    PSEUDO_PROTOCOL_PATTERN = re.compile(r"(javascript|vbscript|data\s*:\s*text/html)\s*:", re.IGNORECASE)
    # SVG ve MathML vektörleri
    SVG_MATH_PATTERN = re.compile(r"<\s*(svg|math)[^>]*>.*?(<\s*/\s*\1\s*>|$)", re.IGNORECASE | re.DOTALL)
    # Tehlikeli gömme etiketleri (iframe, object, embed, applet, base, link, style)
    DANGEROUS_TAGS_PATTERN = re.compile(r"<\s*(iframe|object|embed|applet|base|link|meta|style|form|input)[^>]*>", re.IGNORECASE)
    # DOM Clobbering denemeleri (id veya name üzerinden window/document özelliklerini gölgeleme)
    DOM_CLOBBERING_PATTERN = re.compile(r"<(?:form|input|a|img)\s+[^>]*(?:id|name)\s*=\s*['\"](?:location|document|window|cookie|nodeName)['\"]", re.IGNORECASE)

    def analyze(self, raw_input: str) -> List[XSSFinding]:
        """Ham metni tarayarak bulunan XSS göstergelerini döndürür."""
        findings: List[XSSFinding] = []  # Tespit edilen bulguları depolamak için boş liste başlatılır
        
        # 1. Script etiketi kontrolü
        script_matches = self.SCRIPT_TAG_PATTERN.findall(raw_input)  # Script etiketleri taranır
        if script_matches or re.search(r"<\s*script", raw_input, re.IGNORECASE):  # Eğer script etiketi mevcutsa
            matched = re.search(r"<\s*script[^>]*>", raw_input, re.IGNORECASE)  # İlk eşleşen etiket konumu yakalanır
            match_txt = matched.group(0) if matched else "<script>"  # Eşleşen parça belirlenir
            findings.append(XSSFinding(
                XSSType.REFLECTED,  # Reflected türü olarak işaretlenir
                XSSSeverity.CRITICAL,  # Betik çalıştırma kritik seviyededir
                "SCRIPT_TAG_INJECTION",  # İmza kimliği atanır
                "Doğrudan <script> etiketi enjeksiyonu tespit edildi.",  # Açıklama atanır
                match_txt  # Eşleşen parça kaydedilir
            ))

        # 2. Inline Event Handler kontrolü (onerror, onload vs.)
        ev_matches = self.EVENT_HANDLER_PATTERN.findall(raw_input)  # Olay yakalayıcılar aranır
        for ev in ev_matches:  # Bulunan her olay yakalayıcı incelenir
            findings.append(XSSFinding(
                XSSType.STORED,  # Genellikle kaydedilen içeriklerde karşılaşılan tür
                XSSSeverity.HIGH,  # Yüksek ciddiyet seviyesi atanır
                "INLINE_EVENT_HANDLER",  # İmza kimliği atanır
                f"HTML inline olay dinleyicisi bulundu: {ev[:40]}",  # Açıklama oluşturulur
                ev  # Zararlı kod parçası kaydedilir
            ))

        # 3. Sözde protokol kontrolü (javascript: vb.)
        proto_matches = self.PSEUDO_PROTOCOL_PATTERN.finditer(raw_input)  # Sözde protokoller taranır
        for proto in proto_matches:  # Eşleşen protokoller listelenir
            findings.append(XSSFinding(
                XSSType.REFLECTED,  # Yansıyan veya DOM tabanlı istismar
                XSSSeverity.HIGH,  # Yüksek ciddiyet
                "DANGEROUS_PSEUDO_PROTOCOL",  # İmza adı
                f"Tehlikeli sözde protokol tespit edildi: {proto.group(0)}",  # Açıklama
                proto.group(0)  # Eşleşen protokol kaydedilir
            ))

        # 4. SVG ve MathML enjeksiyonu kontrolü
        svg_match = self.SVG_MATH_PATTERN.search(raw_input)  # SVG/MathML aranır
        if svg_match:  # Bulunması halinde
            findings.append(XSSFinding(
                XSSType.MUTATION_XSS,  # Parser mutasyonlarında sıkça kullanılır
                XSSSeverity.HIGH,  # Yüksek ciddiyet
                "SVG_MATHML_INJECTION",  # İmza adı
                "SVG veya MathML tabanlı kod yürütme vektörü bulundu.",  # Açıklama
                svg_match.group(0)[:80]  # Eşleşme kaydedilir
            ))

        # 5. Tehlikeli HTML etiketleri (iframe, object, base vb.)
        dang_matches = self.DANGEROUS_TAGS_PATTERN.findall(raw_input)  # Tehlikeli etiketler aranır
        for dtag in dang_matches:  # Her etiket için
            findings.append(XSSFinding(
                XSSType.REFLECTED,  # Reflected XSS
                XSSSeverity.MEDIUM,  # Orta ciddiyet
                "DANGEROUS_HTML_TAG",  # İmza adı
                f"Güvensiz HTML etiketi tespit edildi: <{dtag}>",  # Açıklama
                dtag  # Etiket kaydedilir
            ))

        # 6. DOM Clobbering denemesi
        clobber_match = self.DOM_CLOBBERING_PATTERN.search(raw_input)  # Clobbering denemesi aranır
        if clobber_match:  # Eşleşme varsa
            findings.append(XSSFinding(
                XSSType.DOM_BASED,  # DOM manipülasyonu
                XSSSeverity.MEDIUM,  # Orta ciddiyet
                "DOM_CLOBBERING_ATTEMPT",  # İmza adı
                "DOM nesnelerini gölgeleme (DOM Clobbering) girişimi saptandı.",  # Açıklama
                clobber_match.group(0)  # Kod parçası kaydedilir
            ))

        return findings  # Tespit edilen bulgu listesi döndürülür


class DOMXSSAnalyzer:
    """İstemci tarafı JavaScript kodunda Source-Sink akışlarını inceleyen statik analizci."""

    # Tehlikeli veri kaynakları (Sources)
    DOM_SOURCES: Set[str] = {
        "location.search", "location.hash", "location.href", "location.pathname",
        "document.URL", "document.documentURI", "document.referrer", "window.name",
        "document.cookie", "localStorage.getItem", "sessionStorage.getItem"
    }

    # Yürütücü ve tehlikeli DOM havuzları (Sinks)
    DOM_SINKS: Set[str] = {
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "eval", "setTimeout", "setInterval", "Function", "script.src", "iframe.src"
    }

    def analyze_script(self, js_code: str) -> List[Dict[str, Any]]:
        """JavaScript kodundaki güvensiz Source -> Sink akışlarını tespit eder."""
        taint_flows: List[Dict[str, Any]] = []  # Tespit edilen akışlar listesi oluşturulur
        tainted_vars: Dict[str, str] = {}  # Kirletilmiş değişken adı ve kaynak eşlemesi tutulur
        
        # Kod satırlarına ayrıştırılır
        lines = js_code.splitlines()  # Satır bazında inceleme için ayrıştırma yapılır
        for line_no, line in enumerate(lines, start=1):  # Her satır numarasıyla döngüye alınır
            clean_line = line.strip()  # Satır başı ve sonu boşlukları temizlenir
            if not clean_line or clean_line.startswith("//"):  # Boş veya yorum satırları atlanır
                continue  # Sıradaki satıra geçilir
            
            # Değişken ataması analizi (let/var/const x = source)
            assign_match = re.search(r"(?:let|var|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+)", clean_line)  # Atama kalıbı aranır
            if assign_match:  # Atama bulunduysa
                var_name = assign_match.group(1)  # Değişken adı yakalanır
                expr = assign_match.group(2)  # Atanan ifade yakalanır
                for src in self.DOM_SOURCES:  # Tanımlı kaynaklar taranır
                    if src in expr:  # İfadede kaynak varsa
                        tainted_vars[var_name] = src  # Değişken kirli (tainted) olarak işaretlenir
            
            # Kaynak kontrolü (doğrudan satırda geçenler)
            found_sources = [src for src in self.DOM_SOURCES if src in clean_line]  # Satırdaki doğrudan kaynaklar aranır
            for tvar, tsrc in tainted_vars.items():  # Kirli değişkenler taranır
                if re.search(r"\b" + re.escape(tvar) + r"\b", clean_line):  # Değişken bu satırda kullanılmışsa
                    if tsrc not in found_sources:  # Kaynak henüz eklenmemişse
                        found_sources.append(tsrc)  # Kaynak listeye eklenir
            
            # Havuz kontrolü
            found_sinks = [snk for snk in self.DOM_SINKS if snk in clean_line]  # Satırdaki havuzlar aranır
            
            if found_sources and found_sinks:  # Hem kaynak hem havuz birleştiyse
                taint_flows.append({
                    "line_number": line_no,  # Satır numarası kaydedilir
                    "source": found_sources,  # Kullanılan kaynaklar kaydedilir
                    "sink": found_sinks,  # Tehlikeli havuz kaydedilir
                    "code_snippet": clean_line,  # İlgili kod parçası kaydedilir
                    "is_direct_flow": True,  # Doğrudan akış olduğu işaretlenir
                    "risk": "CRITICAL_DOM_XSS"  # Kritik seviye risk atanır
                })
            elif found_sinks:  # Yalnızca havuz varsa (potansiyel zafiyet)
                taint_flows.append({
                    "line_number": line_no,  # Satır numarası kaydedilir
                    "source": [],  # Kaynak açıkça tespit edilmedi
                    "sink": found_sinks,  # Havuz kaydedilir
                    "code_snippet": clean_line,  # Kod parçası kaydedilir
                    "is_direct_flow": False,  # Dolaylı kullanım
                    "risk": "SUSPICIOUS_SINK_USAGE"  # Şüpheli havuz kullanımı atanır
                })
        
        return taint_flows  # Analiz sonuçları döndürülür


class StrictHTMLSanitizer(HTMLParser):
    """
    Katı allowlist (beyaz liste) tabanlı HTML arındırıcı.
    Yalnızca güvenli etiketleri ve nitelikleri kabul eder;
    tüm tehlikeli script, iframe, gömülü nesne ve olay dinleyicilerini ayıklar.
    """

    ALLOWED_TAGS = {"p", "b", "i", "u", "em", "strong", "a", "ul", "ol", "li", "code", "pre", "span", "br", "hr"}  # İzinli etiketler kümesi
    ALLOWED_ATTRS = {"href", "title", "class", "target", "rel"}  # İzinli nitelikler kümesi
    SAFE_SCHEMES = {"http", "https", "mailto"}  # İzinli güvenli URL şemaları

    def __init__(self):
        super().__init__()  # Üst sınıf HTMLParser başlatılır
        self.reset()  # Ayrıştırıcı durum bayrakları sıfırlanır
        self.fed: List[str] = []  # Temizlenmiş HTML parçacıklarını tutacak liste
        self.stripped_tags_count: int = 0  # Ayıklanan tehlikeli etiket sayısı sayacı
        self.stripped_attrs_count: int = 0  # Ayıklanan tehlikeli nitelik sayısı sayacı

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        """Açılış etiketlerini denetler ve allowlist'e göre filtreler."""
        tag_lower = tag.lower()  # Etiket küçük harfe dönüştürülür
        if tag_lower in self.ALLOWED_TAGS:  # Etiket izinli listede yer alıyorsa
            valid_attrs: List[str] = []  # Geçerli nitelikler listesi oluşturulur
            for attr_name, attr_value in attrs:  # Nitelikler tek tek taranır
                attr_lower = attr_name.lower()  # Nitelik adı küçük harfe çevrilir
                if attr_lower.startswith("on"):  # Olay yakalayıcı ise (onclick vb.)
                    self.stripped_attrs_count += 1  # Ayıklama sayacı artırılır
                    continue  # Tehlikeli olay yakalayıcı atlanır
                if attr_lower in self.ALLOWED_ATTRS:  # İzinli nitelikler listesinde ise
                    val = attr_value or ""  # Nitelik değeri boşluktan korunur
                    # href kontrolü: zararlı şemaları (javascript:) engelle
                    if attr_lower == "href":  # Link adresi kontrolü
                        parsed_url = urllib.parse.urlparse(val)  # URL ayrıştırılır
                        scheme = parsed_url.scheme.lower()  # URL şeması elde edilir
                        if scheme and scheme not in self.SAFE_SCHEMES:  # Güvensiz şema ise
                            self.stripped_attrs_count += 1  # Sayacı artır
                            continue  # javascript: linki çöpe atılır
                    # Değeri güvenli kaçış ile ekle
                    escaped_val = html.escape(val, quote=True)  # Değer HTML kaçışına tabi tutulur
                    valid_attrs.append(f'{attr_lower}="{escaped_val}"')  # Güvenli nitelik formatlanır
                else:  # İzin verilmeyen nitelik ise
                    self.stripped_attrs_count += 1  # Sayacı artır
            
            attrs_str = (" " + " ".join(valid_attrs)) if valid_attrs else ""  # Nitelikler dizesi hazırlanır
            self.fed.append(f"<{tag_lower}{attrs_str}>")  # Güvenli açılış etiketi arabelleğe eklenir
        else:  # Yasaklı etiket ise (script, iframe vb.)
            self.stripped_tags_count += 1  # Ayıklanan etiket sayacı artırılır

    def handle_endtag(self, tag: str):
        """Kapanış etiketlerini denetler."""
        tag_lower = tag.lower()  # Etiket küçük harfe dönüştürülür
        if tag_lower in self.ALLOWED_TAGS:  # İzinli etiket ise
            self.fed.append(f"</{tag_lower}>")  # Güvenli kapanış etiketi eklenir

    def handle_data(self, data: str):
        """Metin verilerini güvenli bir şekilde arabelleğe aktarır."""
        escaped_data = html.escape(data, quote=False)  # Düz metin kaçıştan geçirilir
        self.fed.append(escaped_data)  # Arabelleğe kaydedilir

    def handle_entityref(self, name: str):
        """HTML varlık referanslarını aktarır."""
        self.fed.append(f"&{name};")  # Güvenli varlık eklenir

    def handle_charref(self, name: str):
        """Karakter referanslarını aktarır."""
        self.fed.append(f"&#{name};")  # Karakter referansı eklenir

    def get_clean_html(self) -> str:
        """Arındırılmış temiz HTML çıktısını döndürür."""
        return "".join(self.fed)  # Liste parçaları birleştirilerek metin üretilir


class ContextAwareEncoder:
    """Farklı tarayıcı yürütme bağlamlarına göre özelleşmiş çıktı kodlayıcı."""

    @staticmethod
    def encode_for_html_body(value: str) -> str:
        """HTML gövde bağlamı için kodlama (<, >, &, \", ')."""
        return html.escape(value, quote=True)  # Standart HTML kaçışı uygulanır

    @staticmethod
    def encode_for_html_attribute(value: str) -> str:
        """HTML nitelik bağlamı için alfanümerik olmayan karakterleri onaltılık HTML varlığına dönüştürür."""
        encoded = []  # Karakter listesi başlatılır
        for char in value:  # Karakterler taranır
            if char.isalnum() or char in ("-", "_", ".", ":"):  # Güvenli karakterler
                encoded.append(char)  # Doğrudan eklenir
            else:  # Özel ve tehlikeli karakterler
                encoded.append(f"&#x{ord(char):02X};")  # Onaltılık varlık koduna dönüştürülür
        return "".join(encoded)  # Birleşik dize döndürülür

    @staticmethod
    def encode_for_javascript_string(value: str) -> str:
        """JavaScript dize literali bağlamı için Unicode kaçışı (\\uXXXX) uygular."""
        encoded = []  # Parçacık listesi başlatılır
        for char in value:  # Her karakter için
            if char.isalnum() or char in (" ", "_", "-", "."):  # Güvenli alfanümerik
                encoded.append(char)  # Aynen eklenir
            else:  # Tırnaklar, ters bölü ve kontrol karakterleri
                encoded.append(f"\\u{ord(char):04x}")  # 4 haneli Unicode kaçış kodu üretilir
        return "".join(encoded)  # Kaçış yapılmış dize döndürülür

    @staticmethod
    def encode_for_uri_component(value: str) -> str:
        """URL parametreleri için RFC 3986 standartlarında percent-encoding uygular."""
        return urllib.parse.quote(value, safe="")  # Tüm özel karakterler yüzde kodlamasına dönüştürülür


class CSPPolicyBuilder:
    """Content Security Policy Seviye 3 uyumlu güvenlik politikası üreten ve denetleyen sınıf."""

    def __init__(self):
        self.directives: Dict[str, List[str]] = {
            "default-src": ["'self'"],  # Varsayılan kaynak yalnızca kendi alan adı
            "script-src": ["'strict-dynamic'"],  # Dinamik script yükleme koruması
            "object-src": ["'none'"],  # Flash/ActiveX gibi gömülü eklentileri tamamen yasakla
            "base-uri": ["'none'"],  # <base> etiketi ile alan adı hijacking saldırılarını engelle
            "frame-ancestors": ["'none'"],  # Clickjacking saldırılarına karşı iframe içerisine almayı engelle
            "require-trusted-types-for": ["'script'"]  # DOM XSS'e karşı Trusted Types zorunluluğu
        }
        self.current_nonce: Optional[str] = None  # Üretilen nonce değerini tutar

    def generate_nonce(self) -> str:
        """Kriptografik güvenli 128-bitlik Base64 nonce üretir."""
        self.current_nonce = secrets.token_urlsafe(16)  # 128-bit güvenli rastgele anahtar üretilir
        return self.current_nonce  # Üretilen nonce dizesi döndürülür

    def build_header(self, nonce: Optional[str] = None) -> str:
        """CSP HTTP başlık değerini derler."""
        use_nonce = nonce or self.current_nonce or self.generate_nonce()  # Kullanılacak nonce seçilir
        directives_copy = {k: list(v) for k, v in self.directives.items()}  # Yönerge sözlüğü kopyalanır
        
        # script-src yönergesine nonce eklenir
        script_sources = [f"'nonce-{use_nonce}'"] + directives_copy.get("script-src", [])  # Nonce başa eklenir
        directives_copy["script-src"] = script_sources  # Güncellenmiş liste atanır
        
        policy_parts = []  # Politika dizgisi parçaları
        for directive, sources in directives_copy.items():  # Tüm yönergeler döngüye alınır
            policy_parts.append(f"{directive} {' '.join(sources)}")  # Yönerge ve kaynakları birleştirilir
            
        return "; ".join(policy_parts)  # Noktalı virgül ile birleştirilmiş nihai başlık döndürülür

    def audit_policy(self, policy_str: str) -> List[str]:
        """Verilen bir CSP politikasındaki zayıflıkları ve riskli yönergeleri denetler."""
        weaknesses: List[str] = []  # Tespit edilen güvenlik zafiyetleri listesi
        
        # 'unsafe-inline' denetimi
        if "'unsafe-inline'" in policy_str and "'nonce-" not in policy_str:  # Nonce olmadan unsafe-inline varsa
            weaknesses.append("YÜKSEK RİSK: 'unsafe-inline' kullanılmış ve nonce koruması yok.")
            
        # 'unsafe-eval' denetimi
        if "'unsafe-eval'" in policy_str:  # eval() izni verilmişse
            weaknesses.append("YÜKSEK RİSK: 'unsafe-eval' aktif, dinamik kod çalıştırmaya izin veriyor.")
            
        # Wildcard (*) denetimi
        if "default-src *" in policy_str or "script-src *" in policy_str:  # Joker karakter varsa
            weaknesses.append("KRİTİK RİSK: Joker karakter (*) kullanılarak tüm kaynaklara izin verilmiş.")
            
        # object-src 'none' eksikliği
        if "object-src 'none'" not in policy_str:  # object-src 'none' yoksa
            weaknesses.append("ORTA RİSK: 'object-src 'none'' eksik, Flash/Plugin enjeksiyonuna açık.")
            
        # base-uri eksikliği
        if "base-uri" not in policy_str:  # base-uri kısıtlaması yoksa
            weaknesses.append("ORTA RİSK: 'base-uri' tanımlanmamış, <base> tag hijacking riski var.")
            
        return weaknesses  # Denetim bulguları döndürülür


class XSSDefenseEngine:
    """Tüm XSS tespit, temizleme ve bağlamsal kodlama yeteneklerini birleştiren merkezi motor."""

    def __init__(self):
        self.detector = XSSPayloadDetector()  # XSS imza tarayıcısı başlatılır
        self.dom_analyzer = DOMXSSAnalyzer()  # DOM analiz modülü başlatılır
        self.csp_builder = CSPPolicyBuilder()  # CSP politika üreticisi başlatılır

    def inspect_and_defend(self, raw_input: str, context: str = "html_body") -> Dict[str, Any]:
        """
        Girdiyi inceler, tehlikeli XSS unsurlarını tespit eder,
        seçilen bağlama göre temizlenmiş ve kodlanmış güvenli çıktıyı üretir.
        """
        # 1. Tehdit tespiti
        findings = self.detector.analyze(raw_input)  # Ham girdi taranır
        is_safe = len(findings) == 0  # Bulgu yoksa güvenlidir
        
        # 2. Katı HTML temizliği (Sanitization)
        sanitizer = StrictHTMLSanitizer()  # Temizleyici nesnesi oluşturulur
        sanitizer.feed(raw_input)  # Girdi beslenir
        sanitized_html = sanitizer.get_clean_html()  # Arındırılmış çıktı alınır
        
        # 3. Bağlama göre kodlama (Context-Aware Encoding)
        if context == "html_attribute":  # Nitelik bağlamı
            encoded_output = ContextAwareEncoder.encode_for_html_attribute(raw_input)  # Nitelik kodlaması
        elif context == "javascript":  # JS bağlamı
            encoded_output = ContextAwareEncoder.encode_for_javascript_string(raw_input)  # JS Unicode kodlaması
        elif context == "uri_param":  # URL parametresi
            encoded_output = ContextAwareEncoder.encode_for_uri_component(raw_input)  # Percent encoding
        else:  # Varsayılan HTML gövdesi
            encoded_output = ContextAwareEncoder.encode_for_html_body(raw_input)  # HTML gövde kaçışı

        # 4. Güvenlik skoru hesaplama (100 üzerinden)
        score = 100.0  # Başlangıç tam puan
        for f in findings:  # Her bulgu için ceza puanı düşülür
            if f.severity == XSSSeverity.CRITICAL:  # Kritik bulgular
                score -= 40.0  # 40 puan düşürülür
            elif f.severity == XSSSeverity.HIGH:  # Yüksek bulgular
                score -= 25.0  # 25 puan düşürülür
            elif f.severity == XSSSeverity.MEDIUM:  # Orta bulgular
                score -= 15.0  # 15 puan düşürülür
            else:  # Düşük bulgular
                score -= 5.0  # 5 puan düşürülür
        score = max(0.0, score)  # Sıfırın altına inmesi engellenir

        # 5. Sonuç sözlüğü derlenir
        return {
            "input_length": len(raw_input),  # Girdi uzunluğu
            "is_safe": is_safe,  # Güvenlik bayrağı
            "security_score": score,  # Güvenlik puanı
            "findings_count": len(findings),  # Bulgu sayısı
            "findings": [f.to_dict() for f in findings],  # Bulgular listesi
            "sanitized_html": sanitized_html,  # Temizlenmiş HTML
            "encoded_output": encoded_output,  # Kodlanmış güvenli çıktı
            "context_used": context,  # Kullanılan bağlam adı
            "stripped_tags": sanitizer.stripped_tags_count,  # Ayıklanan etiket adedi
            "stripped_attrs": sanitizer.stripped_attrs_count  # Ayıklanan nitelik adedi
        }
