# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Audit ve Journal Güvenliği Uygulama Modülü
Bu modül, Linux çekirdeği denetim çatısı (auditd) kurallarını, dosya izleme tetikleyicilerini,
sistem çağrısı (syscall) filtrelerini ve systemd journald kalıcı loglama/mühürleme (Forward Secure Sealing)
politikalarını CIS Linux Benchmark Section 4.1 ve 4.2 standartlarında denetler.
"""

# Modül sürüm bilgisi tanımlanır
__version__ = "1.0.0"
# Modül yazar bilgisi tanımlanır
__author__ = "Seydi Eryılmaz (@seydivakkas)"
