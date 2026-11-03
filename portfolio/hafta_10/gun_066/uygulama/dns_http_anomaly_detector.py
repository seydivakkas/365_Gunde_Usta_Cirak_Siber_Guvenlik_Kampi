# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G066: Hafta 10 Gün 66 - DNS ve HTTP Anomali İşaretleri Tespit Motoru.
Bu modül, DNS (DGA, tünelleme, amplifikasyon, Fast Flux) ve HTTP (Request Smuggling,
CRLF enjeksiyonu, Path Traversal, otomatik tarayıcılar) protokollerindeki güvenlik
anomalilerini istatistiksel, kural tabanlı ve imza yöntemleriyle tespit eder.
"""

# Düzenli ifadeler ile örüntü eşleme için re modülü içe aktarılır
import re
# Matematiksel ve entropi hesaplamaları için math kütüphanesi içe aktarılır
import math
# URL kod çözme işlemleri için urllib.parse modülü içe aktarılır
import urllib.parse
# Veri yapıları ve tip ipuçları için typing modülünden tipler içe aktarılır
from typing import Dict, List, Any, Optional, Tuple, Set
# Veri sınıfları oluşturmak için dataclass dekoratörü içe aktarılır
from dataclasses import dataclass, field


# Temel anomali tespit istisnası
class AnomalyDetectionError(Exception):
    """Anomali tespit motorunda oluşan tüm güvenlik istisnalarının üst sınıfıdır."""
    # Üst sınıf metodu boş geçilir
    pass


# DGA alan adı hatası istisnası
class DGAAnomalyError(AnomalyDetectionError):
    """Algoritmik olarak türetilmiş (DGA) zararlı alan adı tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# DNS tünelleme hatası istisnası
class DNSTunnelingError(AnomalyDetectionError):
    """DNS sorguları üzerinden veri kaçırma (tünelleme) tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# DNS amplifikasyon hatası istisnası
class DNSAmplificationError(AnomalyDetectionError):
    """Yüksek yanıt/istek büyütme oranına sahip DNS yansıtma saldırısı tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# HTTP Request Smuggling hatası istisnası
class HTTPRequestSmugglingError(AnomalyDetectionError):
    """Content-Length ve Transfer-Encoding başlık çatışması tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# HTTP CRLF başlık enjeksiyonu hatası istisnası
class HeaderInjectionError(AnomalyDetectionError):
    """HTTP başlıklarında veya URI parametrelerinde CRLF karakter enjeksiyonu tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Dizin geçişi (Path Traversal) hatası istisnası
class PathTraversalError(AnomalyDetectionError):
    """Dizin dışına çıkma ve hassas dosya okuma girişimleri tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Zararlı tarayıcı imzası hatası istisnası
class MaliciousScannerError(AnomalyDetectionError):
    """Otomatik saldırı tarayıcısı (sqlmap, nikto, vb.) User-Agent imzası yakalandığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Bozuk kayıt nesnesi hatası istisnası
class MalformedRecordError(AnomalyDetectionError):
    """İncelenecek telemetri veya kayıt nesnesi geçerli bir sözlük tipinde olmadığında fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Fast Flux C2 anomali hatası istisnası
class FastFluxAnomalyError(AnomalyDetectionError):
    """Düşük TTL ve yüksek IP çeşitliliğine sahip Fast Flux botnet C2 tespit edildiğinde fırlatılır."""
    # Üst sınıf metodu boş geçilir
    pass


# Tekil bir anomali bulgusunu temsil eden veri sınıfı
@dataclass
class AnomalyFinding:
    """Tespit edilen bir siber güvenlik anomalisinin ayrıntılarını tutar."""
    # Anomali kodu / tanımlayıcısı
    anomali_kodu: str
    # Protokol kategorisi (DNS veya HTTP)
    kategori: str
    # Tehlike seviyesi (DUSUK, ORTA, YUKSEK, KRITIK)
    onem_derecesi: str
    # Anomali açıklaması
    aciklama: str
    # İlişkili kayıt kimliği
    kayit_id: str
    # Tespit göstergeleri ve teknik metrikler
    gostergeler: Dict[str, Any] = field(default_factory=dict)


# DNS ve HTTP anomali tespit motoru ana sınıfı
class DNSHTTPAnomalyDetector:
    """DNS ve HTTP protokol olaylarını derinlemesine inceleyen siber anomali motoru."""

    # Sınıf başlatıcı metot
    def __init__(self) -> None:
        # Bilinen saldırı tarayıcısı User-Agent regex kalıpları
        self.scanner_signatures = [
            r"sqlmap",
            r"nikto",
            r"gobuster",
            r"dirbuster",
            r"nmap",
            r"wpscan",
            r"nessus",
            r"masscan",
            r"acunetix"
        ]
        # Şüpheli üst düzey alan adları (TLD)
        self.suspicious_tlds = {".top", ".xyz", ".biz", ".cc", ".ru", ".tk"}

    # Şannon bilgi entropisini hesaplayan statik metot
    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Verilen dizginin Şannon bilgi entropisini (bit cinsinden) hesaplar."""
        # Metin boş ise entropi sıfırdır
        if not text:
            # Sıfır döner
            return 0.0
        # Karakter frekansları hesaplanır
        length = len(text)
        # Olasılıklar listesi oluşturulur
        probabilities = [text.count(c) / length for c in set(text)]
        # Entropi toplam formülü işletilir: -sum(p * log2(p))
        return -sum(p * math.log2(p) for p in probabilities)

    # Sessiz harf oranını hesaplayan statik metot (DGA tespiti için)
    @staticmethod
    def calculate_consonant_ratio(text: str) -> float:
        """Metindeki sessiz harflerin toplam alfabetik karakterlere oranını hesaplar."""
        # Yalnızca harfler filtrelenir ve küçültülür
        letters = [c.lower() for c in text if c.isalpha()]
        # Harf yoksa sıfır döner
        if not letters:
            # Sıfır değeri
            return 0.0
        # Sesli harfler kümesi
        vowels = set("aeiou")
        # Sessiz harf sayısı sayılır
        consonants = sum(1 for c in letters if c not in vowels)
        # Oran hesaplanır ve döndürülür
        return consonants / len(letters)

    # DNS kayıtlarını inceleyen analiz metodu
    def analyze_dns_record(self, record: Dict[str, Any], raise_on_detection: bool = False) -> List[AnomalyFinding]:
        """Tek bir DNS kaydını DGA, tünelleme, amplifikasyon ve Fast Flux açısından tarar."""
        # Kayıt nesnesinin sözlük tipinde olduğu denetlenir
        if not isinstance(record, dict):
            # Bozuk kayıt nesnesi hatası fırlatılır
            raise MalformedRecordError("DNS kayıt verisi geçerli bir sözlük (dict) olmalıdır.")

        # Bulgular listesi başlatılır
        findings: List[AnomalyFinding] = []
        # Kayıt kimliği alınır
        rec_id = str(record.get("kayit_id", "BILINMEYEN_DNS"))
        # Sorgulanan alan adı alınır
        domain = str(record.get("alan_adi", "")).lower()
        # Sorgu tipi (A, TXT, ANY, vb.)
        qtype = str(record.get("sorgu_tipi", "A")).upper()
        # TTL süresi
        ttl = int(record.get("ttl", 300))
        # İstek boyutu
        req_size = int(record.get("istek_boyutu", 40))
        # Yanıt boyutu
        resp_size = int(record.get("yanit_boyutu", 60))
        # Çözümlenen IP adresleri listesi
        resolved_ips = record.get("cozulmus_ipler", [])

        # Alan adı etiketlere ayrılır (örn: subdomain.domain.tld)
        labels = domain.split(".")
        # Kök alt etiket alınır (genelde DGA burada gerçekleşir)
        main_label = labels[0] if labels else domain

        # Alt etiket uzunluğu hesaplanır
        label_len = len(main_label)
        # Tünelleme tespit bayrağı başlatılır
        is_tunneling = False

        # 1. DNS Tünelleme ve Veri Kaçırma (Data Exfiltration) Tespiti
        # 45 karakterden uzun sorgular veya TXT tipinde Base64 benzeri uzun alt etiketler
        if len(domain) > 45 or (qtype == "TXT" and label_len > 25):
            # Tünelleme bayrağı doğru yapılır
            is_tunneling = True
            # Bulgu nesnesi oluşturulur
            finding = AnomalyFinding(
                anomali_kodu="DNS_TUNELLEME_SIZINTISI",
                kategori="DNS",
                onem_derecesi="KRITIK",
                aciklama=f"DNS tünelleme ile veri sızdırma girişimi tespit edildi: '{domain}' (Uzunluk: {len(domain)}, Tip: {qtype})",
                kayit_id=rec_id,
                gostergeler={"alan_adi": domain, "toplam_uzunluk": len(domain), "sorgu_tipi": qtype}
            )
            # Listeye eklenir
            findings.append(finding)
            # Hata fırlatma kontrolü
            if raise_on_detection:
                # DNS tünelleme istisnası fırlatılır
                raise DNSTunnelingError(finding.aciklama)

        # 2. DGA (Domain Generation Algorithm) Tespiti
        # Tünelleme amaçlı yük taşımayan standart sorgularda algoritmik alan adı taranır
        if not is_tunneling:
            # Entropi hesaplanır
            entropy = self.calculate_shannon_entropy(main_label)
            # Sessiz harf oranı hesaplanır
            consonant_ratio = self.calculate_consonant_ratio(main_label)
            # DGA eşik kriterleri: Yüksek entropi (>= 3.4), uzunluk (>= 12) ve yüksek sessiz harf (>= 0.65)
            if label_len >= 12 and entropy >= 3.4 and consonant_ratio >= 0.65:
                # Bulgu nesnesi oluşturulur
                finding = AnomalyFinding(
                    anomali_kodu="DGA_ALAN_ADI_TESPITI",
                    kategori="DNS",
                    onem_derecesi="KRITIK",
                    aciklama=f"Algoritmik zararlı alan adı (DGA) tespit edildi: '{domain}' (Entropi: {entropy:.2f}, Sessiz Oranı: {consonant_ratio:.2f})",
                    kayit_id=rec_id,
                    gostergeler={"alan_adi": domain, "entropi": round(entropy, 3), "sessiz_orani": round(consonant_ratio, 3)}
                )
                # Listeye eklenir
                findings.append(finding)
                # Hata fırlatma bayrağı aktifse derhal fırlatılır
                if raise_on_detection:
                    # DGA istisnası fırlatılır
                    raise DGAAnomalyError(finding.aciklama)

        # 3. DNS Amplification (Yansıtma ve Büyütme DoS) Tespiti
        # Yanıt boyutu istek boyutunun 25 katından büyükse veya ANY sorgusu ile 2048 baytı aşıyorsa
        amp_factor = resp_size / max(1, req_size)
        # Büyütme eşik denetimi
        if amp_factor >= 25.0 or (qtype == "ANY" and resp_size >= 2048):
            # Bulgu oluşturulur
            finding = AnomalyFinding(
                anomali_kodu="DNS_AMPLIFICATION_SALDIRISI",
                kategori="DNS",
                onem_derecesi="YUKSEK",
                aciklama=f"DNS Amplification DoS saldırı paterni: İstek {req_size}B -> Yanıt {resp_size}B (Büyütme Oranı: {amp_factor:.1f}x)",
                kayit_id=rec_id,
                gostergeler={"istek_bayt": req_size, "yanit_bayt": resp_size, "buyutme_orani": round(amp_factor, 1)}
            )
            # Listeye eklenir
            findings.append(finding)
            # Hata fırlatma denetimi
            if raise_on_detection:
                # Amplifikasyon hatası fırlatılır
                raise DNSAmplificationError(finding.aciklama)

        # 4. Fast Flux Botnet C2 Tespiti
        # TTL çok düşükse (<= 30 sn) ve tek sorguda 5 veya daha fazla farklı IP dönüyorsa
        if ttl <= 30 and len(resolved_ips) >= 5:
            # Bulgu oluşturulur
            finding = AnomalyFinding(
                anomali_kodu="FAST_FLUX_BOTNET_C2",
                kategori="DNS",
                onem_derecesi="KRITIK",
                aciklama=f"Fast Flux Botnet C2 altyapısı tespit edildi: '{domain}' (TTL: {ttl}s, Çözülen IP Sayısı: {len(resolved_ips)})",
                kayit_id=rec_id,
                gostergeler={"alan_adi": domain, "ttl": ttl, "ip_sayisi": len(resolved_ips), "ipler": resolved_ips}
            )
            # Listeye eklenir
            findings.append(finding)
            # Hata denetimi
            if raise_on_detection:
                # Fast Flux hatası fırlatılır
                raise FastFluxAnomalyError(finding.aciklama)

        # Bulgular listesi döndürülür
        return findings

    # HTTP kayıtlarını inceleyen analiz metodu
    def analyze_http_record(self, record: Dict[str, Any], raise_on_detection: bool = False) -> List[AnomalyFinding]:
        """Tek bir HTTP isteğini Request Smuggling, CRLF, Path Traversal ve tarayıcı avı için inceler."""
        # Sözlük tipi denetlenir
        if not isinstance(record, dict):
            # Bozuk kayıt nesnesi hatası fırlatılır
            raise MalformedRecordError("HTTP kayıt verisi geçerli bir sözlük (dict) olmalıdır.")

        # Bulgular listesi başlatılır
        findings: List[AnomalyFinding] = []
        # Kayıt kimliği alınır
        rec_id = str(record.get("kayit_id", "BILINMEYEN_HTTP"))
        # HTTP metodu
        method = str(record.get("metot", "GET")).upper()
        # İstek URI'si
        uri = str(record.get("uri", ""))
        # İstek başlıkları sözlüğü
        headers = record.get("basliklar", {})
        # Başlık anahtarları küçük harfe normalize edilir
        normalized_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        # İstek gövdesi
        body = str(record.get("govde", ""))

        # 1. HTTP Request Smuggling (CL.TE / TE.CL Çatışması) Tespiti
        # Hem Content-Length hem de Transfer-Encoding başlıkları aynı istekte bulunamaz (RFC 7230)
        has_cl = "content-length" in normalized_headers
        has_te = "transfer-encoding" in normalized_headers

        # Çatışma denetimi
        if has_cl and has_te:
            # Bulgu oluşturulur
            finding = AnomalyFinding(
                anomali_kodu="HTTP_REQUEST_SMUGGLING",
                kategori="HTTP",
                onem_derecesi="KRITIK",
                aciklama=f"HTTP Request Smuggling çatışması: Aynı istekte hem Content-Length ({normalized_headers.get('content-length')}) hem Transfer-Encoding ({normalized_headers.get('transfer-encoding')}) mevcut!",
                kayit_id=rec_id,
                gostergeler={"content_length": normalized_headers.get("content-length"), "transfer_encoding": normalized_headers.get("transfer_encoding")}
            )
            # Listeye eklenir
            findings.append(finding)
            # İstisna denetimi
            if raise_on_detection:
                # Smuggling hatası fırlatılır
                raise HTTPRequestSmugglingError(finding.aciklama)

        # 2. HTTP Header Injection / CRLF Bölünmesi Tespiti
        # URI parametrelerinde veya başlıklarda %0d%0a (\r\n) veya Set-Cookie enjeksiyonu denetimi
        decoded_uri = urllib.parse.unquote(uri)
        # CRLF karakterleri veya başlık bölünmesi kalıbı aranır
        if "\r\n" in uri or "%0d%0a" in uri.lower() or "\r\n" in decoded_uri or "set-cookie:" in decoded_uri.lower():
            # Bulgu oluşturulur
            finding = AnomalyFinding(
                anomali_kodu="HTTP_CRLF_ENJEKSIYONU",
                kategori="HTTP",
                onem_derecesi="YUKSEK",
                aciklama=f"HTTP Başlık Enjeksiyonu (CRLF / Response Splitting) tespit edildi: URI='{uri}'",
                kayit_id=rec_id,
                gostergeler={"ham_uri": uri, "cozulmus_uri": decoded_uri}
            )
            # Listeye eklenir
            findings.append(finding)
            # İstisna denetimi
            if raise_on_detection:
                # Header injection hatası fırlatılır
                raise HeaderInjectionError(finding.aciklama)

        # 3. HTTP Dizin Geçişi (Path Traversal / LFI) Tespiti
        # ../ veya ..\ veya URL encoded varyasyonları aranır
        traversal_patterns = [r"\.\./", r"\.\.\\", r"\.\.%2f", r"\.\.%5c", r"/etc/passwd", r"win\.ini", r"boot\.ini"]
        # Desenler taranır
        is_traversal = any(re.search(pat, uri, re.IGNORECASE) or re.search(pat, decoded_uri, re.IGNORECASE) for pat in traversal_patterns)
        # Eşleşme varsa
        if is_traversal:
            # Bulgu oluşturulur
            finding = AnomalyFinding(
                anomali_kodu="PATH_TRAVERSAL_DIZIN_GECISI",
                kategori="HTTP",
                onem_derecesi="YUKSEK",
                aciklama=f"Dizin Geçişi (Path Traversal / LFI) saldırı denemesi yakalandı: URI='{uri}'",
                kayit_id=rec_id,
                gostergeler={"uri": uri, "tespit_edilen_desen": "Dizin dışına çıkış veya sistem dosyası erişimi"}
            )
            # Listeye eklenir
            findings.append(finding)
            # İstisna denetimi
            if raise_on_detection:
                # Path traversal hatası fırlatılır
                raise PathTraversalError(finding.aciklama)

        # 4. Otomatik Zararlı Saldırı Tarayıcısı Tespiti (Scanner Detection)
        # User-Agent başlığında bilinen tarayıcı imzaları aranır
        user_agent = normalized_headers.get("user-agent", "")
        # İmzalar taranır
        for sig in self.scanner_signatures:
            # Eşleşme denetimi
            if re.search(sig, user_agent, re.IGNORECASE):
                # Bulgu oluşturulur
                finding = AnomalyFinding(
                    anomali_kodu="OTOMATIK_TARAMA_TESPITI",
                    kategori="HTTP",
                    onem_derecesi="ORTA",
                    aciklama=f"Otomatik siber saldırı tarayıcısı tespit edildi: User-Agent='{user_agent}' (İmza: {sig})",
                    kayit_id=rec_id,
                    gostergeler={"user_agent": user_agent, "eslesen_imza": sig}
                )
                # Listeye eklenir
                findings.append(finding)
                # İstisna denetimi
                if raise_on_detection:
                    # Tarayıcı hatası fırlatılır
                    raise MaliciousScannerError(finding.aciklama)
                # Döngü kırılır
                break

        # Bulgular listesi döndürülür
        return findings

    # Tüm trafik veri setini toplu analiz eden metot
    def analyze_full_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tüm DNS ve HTTP telemetrisini inceler; toplu istatistik ve adli bilişim raporu üretir."""
        # DNS kayıtları alınır
        dns_records = traffic_data.get("dns_kayitlari", [])
        # HTTP kayıtları alınır
        http_records = traffic_data.get("http_kayitlari", [])

        # Toplanan tüm bulgular listesi
        all_findings: List[AnomalyFinding] = []

        # DNS kayıtları analiz edilir
        for d in dns_records:
            # İnceleme metodu çağrılır
            f_list = self.analyze_dns_record(d, raise_on_detection=False)
            # Genel listeye eklenir
            all_findings.extend(f_list)

        # HTTP kayıtları analiz edilir
        for h in http_records:
            # İnceleme metodu çağrılır
            f_list = self.analyze_http_record(h, raise_on_detection=False)
            # Genel listeye eklenir
            all_findings.extend(f_list)

        # Önem derecesine göre sayım sözlüğü
        severity_counts = {"KRITIK": 0, "YUKSEK": 0, "ORTA": 0, "DUSUK": 0}
        # Sayımlar yapılır
        for f in all_findings:
            # Derece artırılır
            severity_counts[f.onem_derecesi] = severity_counts.get(f.onem_derecesi, 0) + 1

        # Rapor sözlüğü inşa edilir
        return {
            "toplam_dns_kaydi": len(dns_records),
            "toplam_http_kaydi": len(http_records),
            "toplam_anomali_sayisi": len(all_findings),
            "onem_dagilimi": severity_counts,
            "guvenlik_durumu": "TEMIZ" if len(all_findings) == 0 else "TEHDITLER_TESPIT_EDILDI",
            "bulgular": [
                {
                    "kod": f.anomali_kodu,
                    "kategori": f.kategori,
                    "onem": f.onem_derecesi,
                    "aciklama": f.aciklama,
                    "kayit_id": f.kayit_id,
                    "gostergeler": f.gostergeler
                }
                for f in all_findings
            ]
        }
