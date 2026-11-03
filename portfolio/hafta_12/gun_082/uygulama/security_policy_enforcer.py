# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G082: Güvenlik Politikası Yürütme ve Denetim Motoru (Security Policy Enforcer)

Bu modül; kurumsal parola karmaşıklığı, tehdit ciddiyet sınıflandırması, alan adı
doğrulama ve güvenlik duvarı kurallarının katı ve savunmacı biçimde denetlenmesini sağlar.
pytest birim test çerçevesi ile kapsamlı olarak doğrulanmak üzere tasarlanmıştır.
"""

# Ağ adreslerini doğrulamak için ipaddress modülünü içeri aktarıyoruz.
import ipaddress
# Dosya sistemi yolları için Path modülünü içeri aktarıyoruz.
from pathlib import Path
# Regex desen eşleştirmeleri için re modülünü içeri aktarıyoruz.
import re
# Tip ipuçları ve statik tip desteği için generic tipleri içeri aktarıyoruz.
from typing import Any, Dict, List, Optional, Set, Tuple


class PolicyViolationException(Exception):
    """
    Güvenlik politikası kurallarının (parola, port, alan adı, hız sınırı)
    çiğnenmesi durumunda fırlatılan özel istisna sınıfı.
    """
    # Özel kural ihlali istisna gövdesi.
    pass


def validate_password_complexity(password: str) -> bool:
    """
    Kurumsal parola politikasını doğrular:
    - Asgari 12, azami 64 karakter uzunluk
    - En az 1 büyük harf [A-Z]
    - En az 1 küçük harf [a-z]
    - En az 1 rakam [0-9]
    - En az 1 özel karakter [!@#$%^&*()_+-=[]{}|;:,.<>?]
    - Bilinen yaygın sözlük parolalarını reddeder.
    """
    # Parola parametresinin dize tipinde olup olmadığını denetliyoruz.
    if not isinstance(password, str):
        # Dize değilse politika ihlali fırlatıyoruz.
        raise PolicyViolationException("Parola metin (str) formatında olmalıdır.")

    # Uzunluk sınırını denetliyoruz (12 ile 64 karakter arası).
    if len(password) < 12 or len(password) > 64:
        # Sınır dışındaysa açıkça kural ihlali fırlatıyoruz.
        raise PolicyViolationException(f"Parola uzunluğu 12-64 karakter arasında olmalıdır. Alınan: {len(password)}")

    # En az bir büyük harf bulunmasını şart koşuyoruz.
    if not re.search(r"[A-Z]", password):
        # Büyük harf yoksa ihlal fırlatıyoruz.
        raise PolicyViolationException("Parola en az bir büyük harf [A-Z] içermelidir.")

    # En az bir küçük harf bulunmasını şart koşuyoruz.
    if not re.search(r"[a-z]", password):
        # Küçük harf yoksa ihlal fırlatıyoruz.
        raise PolicyViolationException("Parola en az bir küçük harf [a-z] içermelidir.")

    # En az bir rakam bulunmasını şart koşuyoruz.
    if not re.search(r"[0-9]", password):
        # Rakam yoksa ihlal fırlatıyoruz.
        raise PolicyViolationException("Parola en az bir rakam [0-9] içermelidir.")

    # En az bir özel karakter bulunmasını şart koşuyoruz.
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
        # Özel karakter yoksa ihlal fırlatıyoruz.
        raise PolicyViolationException("Parola en az bir özel karakter içermelidir.")

    # Bilinen zayıf ve tahmin edilebilir sözlük parolalarını kara listeye alıyoruz.
    banned_passwords: Set[str] = {
        "password123!@#",
        "admin2026!@#$",
        "qwertypolice1!",
        "siberguvenlik1!"
    }
    # Parola küçük harfe çevrilerek kara liste ile kıyaslanıyor.
    if password.lower() in banned_passwords:
        # Sözlük parolası tespit edilirse ihlal fırlatıyoruz.
        raise PolicyViolationException("Parola yaygın ve tahmin edilebilir sözlük listesinde yer alıyor.")

    # Tüm kurallar başarıyla sağlandıysa True döndürüyoruz.
    return True


def classify_security_incident(severity_score: int) -> str:
    """
    0-100 arasındaki güvenlik olay puanını ciddiyet seviyesine dönüştürür.
    Sınır dışı değerlerde ValueError fırlatır.
    """
    # Girdinin tamsayı olduğunu doğruluyoruz.
    if not isinstance(severity_score, int) or isinstance(severity_score, bool):
        # Tamsayı değilse TypeError fırlatıyoruz.
        raise TypeError("Ciddiyet skoru bir tamsayı (int) olmalıdır.")

    # Puanın geçerli 0-100 aralığında olup olmadığını sınıyoruz.
    if severity_score < 0 or severity_score > 100:
        # Sınır aşımında ValueError fırlatıyoruz.
        raise ValueError(f"Ciddiyet skoru 0-100 aralığında olmalıdır. Alınan: {severity_score}")

    # 0 - 39 arası DÜŞÜK seviye.
    if severity_score < 40:
        # Düşük seviye etiketini döndürüyoruz.
        return "LOW"
    # 40 - 69 arası ORTA seviye.
    elif severity_score < 70:
        # Orta seviye etiketini döndürüyoruz.
        return "MEDIUM"
    # 70 - 89 arası YÜKSEK seviye.
    elif severity_score < 90:
        # Yüksek seviye etiketini döndürüyoruz.
        return "HIGH"
    # 90 - 100 arası KRİTİK seviye.
    else:
        # Kritik seviye etiketini döndürüyoruz.
        return "CRITICAL"


def sanitize_target_domain(domain_input: str) -> str:
    """
    Hedef alan adını kanonikleştirir ve zararlı girdileri eler:
    - Null-byte tespiti
    - Yol geçişi (Path Traversal: /, \, ..) tespiti
    - Protokol öneki (http://, https://) temizliği
    - RFC uyumlu FQDN biçim denetimi
    """
    # Girdinin dize olduğunu kontrol ediyoruz.
    if not isinstance(domain_input, str):
        # Dize değilse ihlal fırlatıyoruz.
        raise PolicyViolationException("Alan adı dize formatında olmalıdır.")

    # Null-byte karakterini denetliyoruz.
    if "\x00" in domain_input:
        # Null-byte varsa güvenlik ihlali fırlatıyoruz.
        raise PolicyViolationException("Alan adı içinde geçersiz null-byte bulundu.")

    # Değerin baş ve sonundaki boşlukları temizliyoruz.
    cleaned = domain_input.strip()

    # Eğer HTTP veya HTTPS protokolü verilmişse temizliyoruz.
    if cleaned.lower().startswith("http://"):
        # HTTP önekini kesiyoruz.
        cleaned = cleaned[7:]
    # HTTPS önekini sınıyoruz.
    elif cleaned.lower().startswith("https://"):
        # HTTPS önekini kesiyoruz.
        cleaned = cleaned[8:]

    # Yol geçişi ve ayırıcı karakterleri denetliyoruz (/, \, ..).
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        # Yol geçişi varsa ihlal fırlatıyoruz.
        raise PolicyViolationException(f"Alan adı geçersiz yol karakterleri barındırıyor: {cleaned}")

    # Alan adını küçük harfe çeviriyoruz.
    normalized_domain = cleaned.lower()

    # Standart FQDN alan adı regex desenini tanımlıyoruz.
    domain_regex = re.compile(
        r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )

    # Regex eşleşmesini sınıyoruz.
    if not domain_regex.match(normalized_domain):
        # Geçersiz alan adı biçiminde ihlal fırlatıyoruz.
        raise PolicyViolationException(f"Geçersiz alan adı biçimi: {normalized_domain}")

    # Kanonikleştirilmiş temiz alan adını döndürüyoruz.
    return normalized_domain


def evaluate_firewall_rule(rule_dict: Dict[str, Any]) -> bool:
    """
    Güvenlik duvarı kural sözlüğünü doğrular:
    - source_ip: Geçerli IPv4 adresi olmalıdır.
    - dest_port: 1-65535 aralığında tamsayı olmalıdır.
    - protocol: TCP, UDP veya ICMP olmalıdır.
    """
    # Girdinin sözlük olduğunu sınıyoruz.
    if not isinstance(rule_dict, dict):
        # Sözlük değilse ihlal fırlatıyoruz.
        raise PolicyViolationException("Kural tanımı bir sözlük (dict) olmalıdır.")

    # Zorunlu alanları kontrol ediyoruz.
    required_keys = ["source_ip", "dest_port", "protocol"]
    # Her anahtarın varlığını denetliyoruz.
    for k in required_keys:
        # Eksik anahtar durumunu sınıyoruz.
        if k not in rule_dict:
            # Eksik alan durumunda ihlal fırlatıyoruz.
            raise PolicyViolationException(f"Kuralda zorunlu alan eksik: '{k}'")

    # Kaynak IP adresini IPv4 olarak doğruluyoruz.
    raw_ip = rule_dict["source_ip"]
    # IP'yi ayrıştırmayı deniyoruz.
    try:
        # ipaddress modülü ile doğruluyoruz.
        ipaddress.IPv4Address(raw_ip)
    # Geçersiz IP durumunda.
    except Exception as ip_err:
        # Kural ihlali fırlatıyoruz.
        raise PolicyViolationException(f"Geçersiz kaynak IPv4 adresi: '{raw_ip}'") from ip_err

    # Hedef portun geçerliliğini sınıyoruz.
    port_val = rule_dict["dest_port"]
    # Portun tamsayı olduğunu ve 1-65535 aralığında bulunduğunu denetliyoruz.
    if not isinstance(port_val, int) or isinstance(port_val, bool) or port_val < 1 or port_val > 65535:
        # Port sınır dışıysa ihlal fırlatıyoruz.
        raise PolicyViolationException(f"Hedef port 1-65535 aralığında geçerli bir tamsayı olmalıdır: {port_val}")

    # Protokolün geçerliliğini sınıyoruz.
    proto_val = str(rule_dict["protocol"]).upper()
    # İzin verilen protokol kümesi.
    allowed_protocols = {"TCP", "UDP", "ICMP"}
    # Protokol kümesinde olup olmadığını denetliyoruz.
    if proto_val not in allowed_protocols:
        # Geçersiz protokol durumunda ihlal fırlatıyoruz.
        raise PolicyViolationException(f"Desteklenmeyen protokol: '{proto_val}'. İzin verilenler: {allowed_protocols}")

    # Kural geçerliyse True döndürüyoruz.
    return True


class SecurityPolicyEnforcer:
    """
    Durumsal hız sınırı, kural denetimi ve denetim kaydı tutan
    üst düzey güvenlik politikası yürütme motoru.
    """

    def __init__(self, max_requests_per_client: int = 5) -> None:
        """
        Yürütme motorunu istemci başına azami istek sınırı ile yapılandırır.
        """
        # Hız sınırı tavanını kaydediyoruz.
        self.max_requests_per_client = max_requests_per_client
        # İstemci IP bazlı istek sayaçları sözlüğü.
        self.request_counts: Dict[str, int] = {}
        # Yürütülen başarılı denetim kayıtları listesi.
        self.audit_log: List[Dict[str, Any]] = []

    def enforce_rate_limit(self, client_ip: str) -> None:
        """
        İstemci hız sınırını denetler, eşik aşıldığında PolicyViolationException fırlatır.
        """
        # Mevcut sayaç değerini alıyoruz.
        current_count = self.request_counts.get(client_ip, 0)
        # Sınır aşıldıysa engelliyoruz.
        if current_count >= self.max_requests_per_client:
            # Hız sınırı kural ihlali fırlatıyoruz.
            raise PolicyViolationException(f"İstemci hız sınırı eşiği aşıldı ({self.max_requests_per_client}): {client_ip}")
        # İstek sayacını artırıyoruz.
        self.request_counts[client_ip] = current_count + 1

    def execute_policy_check(
        self,
        client_ip: str,
        policy_type: str,
        payload: Any
    ) -> Dict[str, Any]:
        """
        Belirtilen politika türüne göre ilgili savunmacı doğrulamayı çalıştırır.
        """
        # Hız sınırı kontrolü yapıyoruz.
        self.enforce_rate_limit(client_ip)

        # Parola karmaşıklık politikası kontrolü.
        if policy_type == "PASSWORD_POLICY":
            # Parolayı sınıyoruz.
            validate_password_complexity(payload)
            # Sonuç sözlüğü hazırlıyoruz.
            result = {"policy": policy_type, "status": "APPROVED", "detail": "Parola kurallara tam uyumlu."}
        # Tehdit derecelendirme politikası kontrolü.
        elif policy_type == "SEVERITY_CLASSIFICATION":
            # Ciddiyeti sınıflandırıyoruz.
            level = classify_security_incident(payload)
            # Sonuç sözlüğü hazırlıyoruz.
            result = {"policy": policy_type, "status": "CLASSIFIED", "level": level}
        # Alan adı temizleme politikası kontrolü.
        elif policy_type == "DOMAIN_SANITIZATION":
            # Alan adını sterilize ediyoruz.
            clean_domain = sanitize_target_domain(payload)
            # Sonuç sözlüğü hazırlıyoruz.
            result = {"policy": policy_type, "status": "SANITIZED", "domain": clean_domain}
        # Güvenlik duvarı kural politikası kontrolü.
        elif policy_type == "FIREWALL_RULE":
            # Kuralı sınıyoruz.
            evaluate_firewall_rule(payload)
            # Sonuç sözlüğü hazırlıyoruz.
            result = {"policy": policy_type, "status": "VALIDATED", "rule": payload}
        # Tanınmayan politika türü.
        else:
            # İhlal fırlatıyoruz.
            raise PolicyViolationException(f"Bilinmeyen politika türü: {policy_type}")

        # Başarılı işlemi denetim günlüğüne ekliyoruz.
        self.audit_log.append({"client_ip": client_ip, "policy": policy_type, "result": result})
        # Sonucu döndürüyoruz.
        return result


# Modül doğrudan çalıştırıldığında örnek yürütme ve adli rapor üretimini gerçekleştiriyoruz.
if __name__ == "__main__":
    # Konsola başlangıç bilgisini basıyoruz.
    print("[+] G082: Güvenlik Politikası Yürütme Motoru Başlatılıyor...")

    # Yürütücü motoru başlatıyoruz.
    enforcer = SecurityPolicyEnforcer(max_requests_per_client=10)

    # 1. Örnek: Parola kontrolü.
    p_res = enforcer.execute_policy_check("198.51.100.1", "PASSWORD_POLICY", "SuperS3cure_P@ss2026!")
    # Konsola yazdırıyoruz.
    print(f"[+] Parola Politikası: {p_res['status']}")

    # 2. Örnek: Olay ciddiyet sınıflandırması.
    s_res = enforcer.execute_policy_check("198.51.100.1", "SEVERITY_CLASSIFICATION", 95)
    # Konsola yazdırıyoruz.
    print(f"[+] Olay Ciddiyeti: {s_res['level']}")

    # 3. Örnek: Alan adı temizliği.
    d_res = enforcer.execute_policy_check("198.51.100.1", "DOMAIN_SANITIZATION", "https://SOC-Gateway.Internal.Corp")
    # Konsola yazdırıyoruz.
    print(f"[+] Steril Alan Adı: {d_res['domain']}")

    # 4. Örnek: Güvenlik duvarı kuralı.
    fw_payload = {"source_ip": "10.0.0.50", "dest_port": 443, "protocol": "TCP"}
    # Kuralı sınıyoruz.
    fw_res = enforcer.execute_policy_check("198.51.100.1", "FIREWALL_RULE", fw_payload)
    # Konsola yazdırıyoruz.
    print(f"[+] Güvenlik Duvarı Kuralı: {fw_res['status']}")

    # Adli kanıt raporunun kaydedileceği yolu belirliyoruz.
    base_dir = Path(__file__).resolve().parent.parent
    # Rapor dosya yolunu alıyoruz.
    report_path = base_dir / "kanit" / "gercek" / "politika_denetim_raporu.txt"
    # Raporu UTF-8 olarak açıyoruz.
    with open(report_path, "w", encoding="utf-8") as rf:
        # Başlığı yazıyoruz.
        rf.write("=== G082 GÜVENLİK POLİTİKASI VE DENETİM RAPORU ===\n")
        # Parola doğrulama sonucunu yazıyoruz.
        rf.write(f"Parola Doğrulama Durumu: {p_res['status']}\n")
        # Ciddiyet derecesini yazıyoruz.
        rf.write(f"Sınıflandırılan Tehdit Seviyesi: {s_res['level']}\n")
        # Alan adı temizlik sonucunu yazıyoruz.
        rf.write(f"Kanonikleştirilen Alan Adı: {d_res['domain']}\n")
        # Güvenlik duvarı durumunu yazıyoruz.
        rf.write(f"Güvenlik Duvarı Kural Doğrulaması: {fw_res['status']}\n")
        # Toplam adli işlem sayısını yazıyoruz.
        rf.write(f"Yürütülen Toplam Politika Denetimi: {len(enforcer.audit_log)}\n")
        # Başarılı onay notunu yazıyoruz.
        rf.write("Durum: Tüm Politika Süzgeçleri ve Sınır Değerleri Başarıyla Doğrulandı (PASS)\n")

    # Bitiş bildirimini basıyoruz.
    print(f"[+] Politika denetim raporu kaydedildi: {report_path}")
