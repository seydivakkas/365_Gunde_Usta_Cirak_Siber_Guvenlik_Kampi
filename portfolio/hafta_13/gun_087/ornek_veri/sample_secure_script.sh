#!/usr/bin/env bash
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Katı Yürütme Kipi (Strict Mode):
# -e: Herhangi bir komut sıfır dışı çıkarsa derhal betiği durdurur.
# -u: Tanımsız (unset) bir değişken çağrıldığında hata verip durur.
# -o pipefail: Boru hattındaki (pipeline) ara komutların hatasını gizlemez, son koda aktarır.
set -euo pipefail

# Dahili Alan Ayırıcı (IFS - Internal Field Separator):
# Yalnızca yeni satır ve sekme karakterlerini ayırıcı kabul eder, boşlukla kelime bölünmesini önler.
IFS=$'\n\t'

# Hata ve Çıkış Yakalama İşleyicisi (Trap & Cleanup Handler):
# Betik sonlandığında veya beklenmeyen bir hata oluştuğunda kaynakları temizler.
cleanup() {
    local exit_code="${1:-0}"  # Çıkış kodu yerel değişkene atanır
    local line_no="${2:-unknown}"  # Hatanın oluştuğu satır numarası
    if [[ "${exit_code}" -ne 0 ]]; then  # Sıfır dışı hata durumu kontrolü
        echo "[HATA] Betik ${line_no}. satırda beklenmeyen bir hata ile sonlandı (Kod: ${exit_code})" >&2  # Hata mesajı
    fi
}
trap 'cleanup "$?" "$LINENO"' EXIT  # EXIT ve ERR sinyallerinde cleanup fonksiyonu tetiklenir

# Ana Görev Fonksiyonu
main() {
    local target_dir="${1:-/tmp/guvenli_dizin}"  # Parametre çift tırnak ile varsayılana bağlanır
    local log_prefix="AUDIT_LOG"  # Sabit önek çift tırnakla tanımlanır

    # Dizin atlama ve boşluk güvenliği için tüm değişkenler daima çift tırnak içinde genişletilir
    if [[ -d "${target_dir}" ]]; then  # Dizin varlığı güvenli test edilir
        echo "[+] Hedef dizin doğrulandı: ${target_dir}"  # Bilgilendirme çıktısı
    else
        echo "[-] Dizin bulunamadı, oluşturuluyor: ${target_dir}"  # Durum bildirimi
        mkdir -p "${target_dir}"  # Güvenli dizin oluşturma
    fi

    # Güvenli argüman listeleme: "$@" kullanımı kelime bölünmesini (word splitting) önler
    for arg in "${@}"; do  # Tüm parametreler tek tek güvenle gezilir
        echo "[ARG] Parametre: ${arg}"  # Argüman ekrana yazdırılır
    done
}

# Fonksiyon çağrısı güvenli argüman aktarımı ile başlatılır
main "${@}"
