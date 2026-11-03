# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
Mini Proje 6: Ağ Adresleme Çalışma Kitabı ve Güvenlik Denetim Motoru Birim Testleri
Bu test paketi IPv4/IPv6 alt ağ hesaplamalarını, çakışma tespitlerini,
konak atanabilirlik kurallarını ve güvenlik denetim mekanizmalarını doğrular.
"""

# Birim testi doğrulamaları ve iddia (assertion) kontrolleri için pytest kütüphanesi
import pytest
# Dosya yolu çözümleme ve varlık kontrolleri için os modülü
import os
# Modül import yollarını yönetmek için sys modülü
import sys
# JSON verilerini okuma ve ayrıştırma için json modülü
import json

# Test dosyasının bulunduğu mutlak dizini alır
current_dir = os.path.dirname(os.path.abspath(__file__))
# Uygulama kaynak kod dizini yolunu oluşturur
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
# Uygulama dizini henüz Python yolunda kayıtlı değilse listeye ekler
if app_dir not in sys.path:
    # İlk sıraya ekleyerek doğrudan import edilmesini sağlar
    sys.path.insert(0, app_dir)

# Test edilecek alt ağ hesaplayıcı ve çalışma kitabı sınıflarını içe aktarır
from network_addressing_workbook import (
    # Özel doğrulama istisnası
    WorkbookValidationError,
    # IPv4 matematiksel alt ağ hesaplayıcısı
    IPv4SubnetCalculator,
    # IPv6 alt ağ ve EUI-64 motoru
    IPv6SubnetCalculator,
    # Ağ çalışma kitabı ve denetim motoru
    NetworkAddressingWorkbook,
)


def test_ipv4_subnet_calculator_standard_24():
    """Standart bir /24 alt ağın (C sınıfı eşdeğeri) adresleme matematiğini test eder."""
    # /24 IPv4 alt ağ hesaplayıcı nesnesi oluşturulur
    calc = IPv4SubnetCalculator("192.168.10.0/24")
    # Ağ adresi 192.168.10.0 olmalıdır
    assert calc.network_address == "192.168.10.0"
    # Alt ağ maskesi 255.255.255.0 olmalıdır
    assert calc.netmask == "255.255.255.0"
    # Joker maskesi 0.0.0.255 olmalıdır
    assert calc.wildcard_mask == "0.0.0.255"
    # Yayın adresi 192.168.10.255 olmalıdır
    assert calc.broadcast_address == "192.168.10.255"
    # İlk kullanılabilir host IP'si 192.168.10.1 olmalıdır
    assert calc.first_usable == "192.168.10.1"
    # Son kullanılabilir host IP'si 192.168.10.254 olmalıdır
    assert calc.last_usable == "192.168.10.254"
    # Toplam adres sayısı 256 olmalıdır
    assert calc.total_addresses == 256
    # Kullanılabilir host sayısı (256 - 2) 254 olmalıdır
    assert calc.usable_hosts == 254


def test_ipv4_subnet_calculator_supernet_23():
    """Genişletilmiş /23 süpernet (supernetting) hesaplamasını test eder."""
    # /23 IPv4 alt ağ hesaplayıcısı (iki adet /24 birleşimi)
    calc = IPv4SubnetCalculator("192.168.30.0/23")
    # Ağ adresi 192.168.30.0 olmalıdır
    assert calc.network_address == "192.168.30.0"
    # Alt ağ maskesi 255.255.254.0 olmalıdır
    assert calc.netmask == "255.255.254.0"
    # Yayın adresi 192.168.31.255 olmalıdır
    assert calc.broadcast_address == "192.168.31.255"
    # İlk kullanılabilir host 192.168.30.1 olmalıdır
    assert calc.first_usable == "192.168.30.1"
    # Son kullanılabilir host 192.168.31.254 olmalıdır
    assert calc.last_usable == "192.168.31.254"
    # Toplam adres 512 olmalıdır
    assert calc.total_addresses == 512
    # Kullanılabilir host sayısı 510 olmalıdır
    assert calc.usable_hosts == 510


def test_ipv4_point_to_point_31():
    """RFC 3021 nokta-nokta (point-to-point) /31 alt ağ kuralını test eder."""
    # Yönlendiriciler arası /31 bağlantı ağı
    calc = IPv4SubnetCalculator("10.0.0.0/31")
    # Ağ adresi 10.0.0.0
    assert calc.network_address == "10.0.0.0"
    # Yayın adresi 10.0.0.1
    assert calc.broadcast_address == "10.0.0.1"
    # Toplam adres 2
    assert calc.total_addresses == 2
    # /31 istisnası gereği kullanılabilir host sayısı da 2 olmalıdır (-2 kuralı uygulanmaz)
    assert calc.usable_hosts == 2
    # Her iki IP de geçerli host kabul edilir
    assert calc.is_usable_host_ip("10.0.0.0") is True
    # İkinci IP de geçerli kabul edilir
    assert calc.is_usable_host_ip("10.0.0.1") is True


def test_ipv4_single_host_32():
    """Tekil host (/32 loopback veya rota hedefi) hesaplamasını test eder."""
    # /32 tekil IP ağı
    calc = IPv4SubnetCalculator("10.255.255.1/32")
    # Ağ adresi kendisidir
    assert calc.network_address == "10.255.255.1"
    # Toplam adres 1'dir
    assert calc.total_addresses == 1
    # Kullanılabilir host sayısı 1'dir
    assert calc.usable_hosts == 1
    # Bu IP kullanılabilir kabul edilir
    assert calc.is_usable_host_ip("10.255.255.1") is True


def test_ipv4_contains_ip_and_usable_check():
    """IP adresi sınır kontrollerini ve konak atanabilirlik kurallarını test eder."""
    # /24 alt ağ nesnesi
    calc = IPv4SubnetCalculator("172.16.20.0/24")
    # Ağ sınırları içindeki IP True dönmelidir
    assert calc.contains_ip("172.16.20.100") is True
    # Ağ sınırları dışındaki IP False dönmelidir
    assert calc.contains_ip("172.16.21.100") is False
    # Ağ adresi (172.16.20.0) konaklara atanamaz (False)
    assert calc.is_usable_host_ip("172.16.20.0") is False
    # Yayın adresi (172.16.20.255) konaklara atanamaz (False)
    assert calc.is_usable_host_ip("172.16.20.255") is False
    # Normal bir konak IP'si (172.16.20.50) kullanılabilir (True)
    assert calc.is_usable_host_ip("172.16.20.50") is True


def test_ipv4_subnet_overlap_detection():
    """İki alt ağın adres uzayında birbiriyle çakışma durumunu test eder."""
    # Birinci alt ağ: 192.168.30.0/23 (192.168.30.0 - 192.168.31.255)
    calc1 = IPv4SubnetCalculator("192.168.30.0/23")
    # İkinci alt ağ: 192.168.31.0/24 (bu aralığın içinde yer alır)
    calc2 = IPv4SubnetCalculator("192.168.31.0/24")
    # Üçüncü alt ağ: 192.168.32.0/24 (tamamen bağımsız aralık)
    calc3 = IPv4SubnetCalculator("192.168.32.0/24")
    
    # calc1 ile calc2 çakışmalıdır (True)
    assert calc1.overlaps_with(calc2) is True
    # calc2 ile calc1 simetrik olarak çakışmalıdır (True)
    assert calc2.overlaps_with(calc1) is True
    # calc1 ile calc3 çakışmamalıdır (False)
    assert calc1.overlaps_with(calc3) is False


def test_ipv6_subnet_calculator():
    """IPv6 CIDR ayrıştırma ve adres sınır kontrollerini test eder."""
    # IPv6 /64 standart alt ağ hesaplayıcısı
    calc = IPv6SubnetCalculator("2001:db8:acad:10::/64")
    # Önek uzunluğu 64 olmalıdır
    assert calc.prefix_len == 64
    # Ağ adresi doğrulanır
    assert calc.network_address == "2001:db8:acad:10::"
    # Alt ağ içindeki bir adres True döner
    assert calc.contains_ip("2001:db8:acad:10::55") is True
    # Farklı bir alt ağ adresi False döner
    assert calc.contains_ip("2001:db8:acad:20::55") is False


def test_ipv6_eui64_mac_leakage_detection():
    """IPv6 adresinde EUI-64 ile MAC adresinin ifşa edilme anomalisi testini yürütür."""
    # Bilinen bir MAC adresi: 00:50:56:A1:00:01
    # OUI: 00-50-56 -> ilk bayt 0x00 ^ 0x02 = 0x02 -> 0250:56ff:fea1:0001
    mac_val = "00:50:56:A1:00:01"
    # EUI-64 ile türetilmiş sızdıran IPv6 adresi
    leaking_ipv6 = "2001:db8:acad:10:0250:56ff:fea1:0001"
    # Güvenli, rastgele gizlilik uzantılı IPv6 adresi
    random_ipv6 = "2001:db8:acad:10:8431:9a7f:4211:bcde"
    
    # Sızdıran adres için True dönmelidir
    assert IPv6SubnetCalculator.is_eui64_mac_leakage(leaking_ipv6, mac_val) is True
    # Rastgele adres için False dönmelidir
    assert IPv6SubnetCalculator.is_eui64_mac_leakage(random_ipv6, mac_val) is False


def test_workbook_load_from_json_and_initial_audit():
    """Temel topoloji dosyasının yüklenmesini ve başlangıçta sıfır hata olmasını test eder."""
    # Örnek dosya yolunu belirler
    json_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_topology_workbook.json")
    # Çalışma kitabı nesnesini oluşturur
    wb = NetworkAddressingWorkbook("Test Ağ Çalışma Kitabı")
    # Dosyadan yükler
    wb.load_from_json(json_path)
    
    # 4 adet alt ağ yüklenmiş olmalıdır
    assert len(wb.alt_aglar) == 4
    # 8 adet cihaz yüklenmiş olmalıdır
    assert len(wb.cihazlar) == 8
    # Başlangıç denetiminde hiçbir çakışma ve anomali bulunmamalıdır
    bulgular = wb.run_audits()
    # Bulgu sayısı sıfır olmalıdır
    assert len(bulgular) == 0


def test_audit_overlapping_subnets():
    """Çakışan alt ağ tanımının denetim motoru tarafından tespitini test eder."""
    # Yeni çalışma kitabı oluşturur
    wb = NetworkAddressingWorkbook()
    # Birinci alt ağ: 10.0.0.0/16
    wb.add_subnet({"alt_ag_id": "NET-A", "vlan_id": 10, "ipv4_cidr": "10.0.0.0/16"})
    # İkinci alt ağ: 10.0.5.0/24 (Birincinin içine gömülü)
    wb.add_subnet({"alt_ag_id": "NET-B", "vlan_id": 20, "ipv4_cidr": "10.0.5.0/24"})
    
    # Denetimi koşar
    bulgular = wb.run_audits()
    # En az bir bulgu bulunmalıdır
    assert len(bulgular) == 1
    # Bulgunun kategorisi CAKISAN_ALT_AG olmalıdır
    assert bulgular[0]["kategori"] == "CAKISAN_ALT_AG"
    # Seviyesi KRITIK olmalıdır
    assert bulgular[0]["seviye"] == "KRITIK"


def test_audit_gateway_out_of_subnet():
    """Varsayılan ağ geçidinin alt ağ dışında olması durumunu test eder."""
    # Yeni çalışma kitabı oluşturur
    wb = NetworkAddressingWorkbook()
    # 192.168.1.0/24 ağı tanımlanır ancak ağ geçidi 10.0.0.1 verilir
    wb.add_subnet({
        "alt_ag_id": "NET-ERR-GW",
        "vlan_id": 10,
        "ipv4_cidr": "192.168.1.0/24",
        "varsayilan_ag_gecidi": "10.0.0.1"
    })
    # Denetim koşulur
    bulgular = wb.run_audits()
    # Hata tespit edilmiş olmalıdır
    assert len(bulgular) == 1
    # Kategori GECERSIZ_AG_GECIDI olmalıdır
    assert bulgular[0]["kategori"] == "GECERSIZ_AG_GECIDI"


def test_audit_unusable_ip_assignment():
    """Ağ adresi veya yayın adresi atanmış konakların tespitini test eder."""
    # Çalışma kitabı oluşturulur
    wb = NetworkAddressingWorkbook()
    # 172.16.10.0/24 alt ağı eklenir
    wb.add_subnet({"alt_ag_id": "NET-10", "vlan_id": 10, "ipv4_cidr": "172.16.10.0/24"})
    # Ağ adresine sahip cihaz eklenir (172.16.10.0)
    wb.add_device({
        "cihaz_id": "DEV-NETID",
        "konak_adi": "host-netid",
        "alt_ag_id": "NET-10",
        "ipv4": "172.16.10.0",
        "mac": "00:50:56:AA:BB:01"
    })
    # Yayın adresine sahip cihaz eklenir (172.16.10.255)
    wb.add_device({
        "cihaz_id": "DEV-BCAST",
        "konak_adi": "host-bcast",
        "alt_ag_id": "NET-10",
        "ipv4": "172.16.10.255",
        "mac": "00:50:56:AA:BB:02"
    })
    # Denetim koşulur
    bulgular = wb.run_audits()
    # 2 adet KULLANILAMAZ_IP_ATAMASI bulunmalıdır
    unusable_findings = [b for b in bulgular if b["kategori"] == "KULLANILAMAZ_IP_ATAMASI"]
    # Tam iki adet olmalıdır
    assert len(unusable_findings) == 2


def test_audit_duplicate_ip_and_mac():
    """IP ve MAC adresi çakışması (duplicate conflict) denetimini test eder."""
    # Çalışma kitabı oluşturulur
    wb = NetworkAddressingWorkbook()
    # Alt ağ eklenir
    wb.add_subnet({"alt_ag_id": "NET-DUP", "vlan_id": 10, "ipv4_cidr": "10.10.10.0/24"})
    # Birinci cihaz eklenir
    wb.add_device({
        "cihaz_id": "DEV-A",
        "konak_adi": "host-a",
        "alt_ag_id": "NET-DUP",
        "ipv4": "10.10.10.50",
        "mac": "00:50:56:11:22:33"
    })
    # İkinci cihaz: Aynı IP ve aynı MAC ile eklenir
    wb.add_device({
        "cihaz_id": "DEV-B",
        "konak_adi": "host-b",
        "alt_ag_id": "NET-DUP",
        "ipv4": "10.10.10.50",
        "mac": "00:50:56:11:22:33"
    })
    # Denetim koşulur
    bulgular = wb.run_audits()
    # Kategori adlarını toplar
    kategoriler = [b["kategori"] for b in bulgular]
    # Hem IP_CAKISMASI bulunmalıdır
    assert "IP_CAKISMASI" in kategoriler
    # Hem de MAC_CAKISMASI bulunmalıdır
    assert "MAC_CAKISMASI" in kategoriler


def test_markdown_report_generation():
    """Markdown rapor oluşturma fonksiyonunun eksiksiz tablo ve içerik ürettiğini test eder."""
    # Çalışma kitabı oluşturulur
    wb = NetworkAddressingWorkbook("Rapor Testi")
    # Alt ağ eklenir
    wb.add_subnet({"alt_ag_id": "NET-01", "vlan_id": 10, "ad": "Yonetim", "ipv4_cidr": "10.1.1.0/24"})
    # Cihaz eklenir
    wb.add_device({
        "cihaz_id": "DEV-01",
        "konak_adi": "gateway-01",
        "alt_ag_id": "NET-01",
        "ipv4": "10.1.1.1",
        "mac": "00:50:56:01:02:03"
    })
    # Denetim koşulur
    wb.run_audits()
    # Rapor üretilir
    md = wb.generate_markdown_report()
    
    # Rapor başlığı içermelidir
    assert "# 📊 Rapor Testi" in md
    # Özel lisans uyarısını içermelidir
    assert "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR" in md
    # Alt ağ tablosunu içermelidir
    assert "## 1. Alt Ağ ve VLSM Adresleme Planı" in md
    # Cihaz envanter tablosunu içermelidir
    assert "## 2. Cihaz ve Uç Nokta Envanteri" in md
    # Temiz ağ bildirimini içermelidir
    assert "Denetim Başarılı" in md
