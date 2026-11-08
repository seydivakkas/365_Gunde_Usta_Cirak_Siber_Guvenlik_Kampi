# -*- coding: utf-8 -*-
"""
Gün 160: XSS Savunma Motoru Birim Testleri (test_xss_defense.py)

Bu modül, XSS tespit motoru, bağlamsal kodlayıcı, katı HTML arındırıcı,
CSP politika üreticisi ve DOM XSS analizcisini 15 kapsamlı test senaryosuyla doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # İşletim sistemi yol ve ortam işlemleri için os modülü dahil edilir
import sys  # Sistem yolu manipülasyonu için sys modülü dahil edilir
import unittest  # Birim test çerçevesi için unittest modülü dahil edilir

# Test edilecek modül dizininin sys.path içerisine eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Mevcut test dosyasının bulunduğu dizin alınır
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama dizininin mutlak yolu oluşturulur
if app_dir not in sys.path:  # Uygulama dizini sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # En başa eklenerek içe aktarma önceliği sağlanır

# Test edilecek sınıfların içe aktarılması
from xss_defense_engine import (  # xss_defense_engine modülünden gerekli sınıflar çağrılır
    XSSDefenseEngine,  # Merkezi XSS savunma motoru
    XSSType,  # XSS türleri enum sınıfı
    XSSSeverity,  # Ciddiyet dereceleri enum sınıfı
    XSSPayloadDetector,  # Yük analiz ve tespit sınıfı
    DOMXSSAnalyzer,  # DOM XSS analizcisi
    StrictHTMLSanitizer,  # Katı HTML temizleyicisi
    ContextAwareEncoder,  # Bağlamsal kodlayıcı
    CSPPolicyBuilder  # CSP politika derleyicisi
)


class TestXSSDefenseEngine(unittest.TestCase):
    """XSS savunma motoru için 15 fonksiyonel birim test paketi."""

    def setUp(self):
        """Her birim test öncesinde temiz motor örnekleri oluşturulur."""
        self.engine = XSSDefenseEngine()  # Ana savunma motoru başlatılır
        self.detector = XSSPayloadDetector()  # İmza dedektörü başlatılır
        self.dom_analyzer = DOMXSSAnalyzer()  # DOM analizcisi başlatılır
        self.csp_builder = CSPPolicyBuilder()  # CSP üreticisi başlatılır

    def test_01_reflected_script_tag_detection(self):
        """1. Test: Klasik <script> etiketi enjeksiyonunun tespitini doğrular."""
        payload = "<script>alert('Reflected XSS')</script>"  # Yansıyan saldırı yükü
        findings = self.detector.analyze(payload)  # Yük taranır
        self.assertGreaterEqual(len(findings), 1)  # En az bir bulgu saptanmalıdır
        self.assertEqual(findings[0].pattern, "SCRIPT_TAG_INJECTION")  # İmza adı doğrulanır
        self.assertEqual(findings[0].severity, XSSSeverity.CRITICAL)  # Kritik ciddiyet doğrulanır

    def test_02_stored_inline_event_handler_detection(self):
        """2. Test: Kalıcı saklanan inline olay dinleyicisi (onerror) tespitini doğrular."""
        payload = "<img src='invalid_image.png' onerror='alert(document.cookie)'>"  # Olay dinleyicili görsel yükü
        findings = self.detector.analyze(payload)  # Yük analiz edilir
        matched_patterns = [f.pattern for f in findings]  # Eşleşen desen listesi çıkarılır
        self.assertIn("INLINE_EVENT_HANDLER", matched_patterns)  # Olay yakalayıcı imzası doğrulanır

    def test_03_pseudo_protocol_javascript_detection(self):
        """3. Test: javascript: sözde protokolü ile zararlı link enjeksiyonunu doğrular."""
        payload = "<a href='javascript:stealTokens()'>Hediye Çeki</a>"  # Sözde protokol yükü
        findings = self.detector.analyze(payload)  # Yük analiz edilir
        matched_patterns = [f.pattern for f in findings]  # Tespit edilen desenler
        self.assertIn("DANGEROUS_PSEUDO_PROTOCOL", matched_patterns)  # Sözde protokol imzası doğrulanır

    def test_04_svg_onload_mutation_detection(self):
        """4. Test: SVG/MathML tabanlı mutasyon ve kod yürütme vektörünü doğrular."""
        payload = "<svg onload=alert(1)>"  # SVG onload yükü
        findings = self.detector.analyze(payload)  # Yük taranır
        matched_patterns = [f.pattern for f in findings]  # Eşleşen desenler
        self.assertIn("SVG_MATHML_INJECTION", matched_patterns)  # SVG enjeksiyon imzası doğrulanır

    def test_05_dangerous_tag_iframe_object(self):
        """5. Test: iframe ve object gibi gömme etiketlerinin tespitini doğrular."""
        payload = "<iframe src='https://malicious-phishing.org'></iframe>"  # iframe yükü
        findings = self.detector.analyze(payload)  # Yük taranır
        matched_patterns = [f.pattern for f in findings]  # Desenler alınır
        self.assertIn("DANGEROUS_HTML_TAG", matched_patterns)  # Tehlikeli etiket imzası doğrulanır

    def test_06_dom_clobbering_attempt_detection(self):
        """6. Test: DOM Clobbering ile document.cookie/window özelliklerini gölgeleme denemesini doğrular."""
        payload = "<form id='location'><input name='href' value='https://attacker.com'></form>"  # Clobbering yükü
        findings = self.detector.analyze(payload)  # Yük analiz edilir
        matched_patterns = [f.pattern for f in findings]  # Desen listesi
        self.assertIn("DOM_CLOBBERING_ATTEMPT", matched_patterns)  # DOM clobbering tespit edilmelidir

    def test_07_clean_input_evaluation(self):
        """7. Test: Zararsız metin girdisinin tam puan (100) almasını ve güvenli işaretlenmesini doğrular."""
        clean_text = "Kurumsal siber güvenlik stratejisi ve mimari ilkeleri."  # Masum girdi
        result = self.engine.inspect_and_defend(clean_text)  # Motor ile incelenir
        self.assertTrue(result["is_safe"])  # Güvenli olarak işaretlenmelidir
        self.assertEqual(result["security_score"], 100.0)  # Puan 100 olmalıdır
        self.assertEqual(result["findings_count"], 0)  # Bulgu sayısı 0 olmalıdır

    def test_08_strict_html_sanitizer_allowed_tags(self):
        """8. Test: İzinli etiketlerin (b, i, p) korunurken yasaklı etiketlerin (script) ayıklandığını doğrular."""
        dirty_html = "<p>Giriş metni <b>kalın</b> ve <script>alert(1)</script> bitiş.</p>"  # Karışık HTML
        sanitizer = StrictHTMLSanitizer()  # Temizleyici başlatılır
        sanitizer.feed(dirty_html)  # Girdi beslenir
        clean_output = sanitizer.get_clean_html()  # Çıktı alınır
        self.assertIn("<p>", clean_output)  # p etiketi bulunmalıdır
        self.assertIn("<b>kalın</b>", clean_output)  # b etiketi korunmalıdır
        self.assertNotIn("<script>", clean_output)  # script etiketi tamamen silinmelidir

    def test_09_strict_html_sanitizer_event_stripping(self):
        """9. Test: İzin verilen etiketlerdeki zararlı onclick/onmouseover niteliklerinin yok edildiğini doğrular."""
        dirty_html = "<b onclick='alert(1)' title='test'>Vurgu</b>"  # Olay yakalayıcılı kalın etiket
        sanitizer = StrictHTMLSanitizer()  # Temizleyici başlatılır
        sanitizer.feed(dirty_html)  # Girdi ayrıştırılır
        clean_output = sanitizer.get_clean_html()  # Temiz HTML elde edilir
        self.assertNotIn("onclick", clean_output)  # onclick niteliği temizlenmiş olmalıdır
        self.assertIn('title="test"', clean_output)  # title güvenli niteliği korunmalıdır

    def test_10_strict_html_sanitizer_javascript_href_blocked(self):
        """10. Test: Link etiketindeki javascript: protokolünün arındırıcı tarafından engellendiğini doğrular."""
        dirty_html = "<a href='javascript:alert(document.domain)'>Tıkla</a>"  # Zararlı link
        sanitizer = StrictHTMLSanitizer()  # Temizleyici başlatılır
        sanitizer.feed(dirty_html)  # Girdi ayrıştırılır
        clean_output = sanitizer.get_clean_html()  # Sonuç çıktısı
        self.assertNotIn("javascript:", clean_output)  # javascript şeması kaldırılmalıdır

    def test_11_context_encoder_html_body(self):
        """11. Test: HTML gövde bağlamında özel karakterlerin kaçışını doğrular."""
        unsafe = "<div class='user'>Ali & Veli \"Test\"</div>"  # Güvensiz karakterler
        encoded = ContextAwareEncoder.encode_for_html_body(unsafe)  # HTML kaçışı uygulanır
        self.assertNotIn("<div", encoded)  # Küçüktür karakteri kaçırılmalıdır (&lt;)
        self.assertIn("&lt;div", encoded)  # Kaçış varlığı doğrulanır
        self.assertIn("&amp;", encoded)  # Ve işareti kaçırılmalıdır

    def test_12_context_encoder_html_attribute(self):
        """12. Test: HTML nitelik bağlamında alfanümerik olmayan karakterlerin onaltılık varlığa dönüştüğünü doğrular."""
        unsafe = "user' onfocus='alert(1)"  # Nitelik kırıcı girdi
        encoded = ContextAwareEncoder.encode_for_html_attribute(unsafe)  # Nitelik kodlaması
        self.assertNotIn("'", encoded)  # Tek tırnak bulunmamalıdır
        self.assertIn("&#x27;", encoded.lower())  # Onaltılık varlık var olmalıdır

    def test_13_context_encoder_javascript_unicode(self):
        """13. Test: JavaScript dize bağlamında Unicode kaçış kodlamasını (\\uXXXX) doğrular."""
        unsafe = "'; alert(1); //"  # JS dize kırıcı yük
        encoded = ContextAwareEncoder.encode_for_javascript_string(unsafe)  # JS Unicode kodlama
        self.assertIn("\\u0027", encoded)  # Tek tırnak Unicode olarak kaçırılmalıdır
        self.assertIn("\\u003b", encoded)  # Noktalı virgül Unicode olarak kaçırılmalıdır

    def test_14_csp_policy_builder_and_nonce(self):
        """14. Test: CSP Seviye 3 başlığının doğru nonce ve katı yönergelerle derlendiğini doğrular."""
        nonce = self.csp_builder.generate_nonce()  # Nonce üretilir
        header = self.csp_builder.build_header(nonce)  # Başlık derlenir
        self.assertIn(f"'nonce-{nonce}'", header)  # Üretilen nonce başlıkta yer almalıdır
        self.assertIn("object-src 'none'", header)  # object-src none bulunmalıdır
        self.assertIn("base-uri 'none'", header)  # base-uri none bulunmalıdır
        self.assertIn("require-trusted-types-for 'script'", header)  # Trusted types bulunmalıdır

    def test_15_dom_xss_taint_flow_detection(self):
        """15. Test: JavaScript betiğinde Source -> Sink doğrudan akışının tespitini doğrular."""
        vulnerable_js = "let query = location.search;\ndocument.getElementById('content').innerHTML = query;"  # Zafiyetli JS
        flows = self.dom_analyzer.analyze_script(vulnerable_js)  # Kod analiz edilir
        self.assertGreaterEqual(len(flows), 1)  # Akış tespit edilmiş olmalıdır
        self.assertTrue(flows[0]["is_direct_flow"])  # Doğrudan akış olduğu doğrulanmalıdır
        self.assertIn("innerHTML", flows[0]["sink"])  # innerHTML havuzu yakalanmalıdır


if __name__ == "__main__":  # Doğrudan çağrıldığında
    unittest.main()  # Birim testler icra edilir
