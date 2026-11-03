#!/usr/bin/env bash
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# ==============================================================================
# G088: Kurumsal Güvenli Çıkış Kodu ve stderr Yönetimi Uygulama Modülü
# Bu betik; komut çıkış kodlarını (exit status) standartlara uygun denetler,
# boru hattı ara hatalarını (PIPESTATUS) yakalar ve stderr akışına gizli veri sızdırmaz.
# ==============================================================================

# Katı Yürütme Kipi
set -euo pipefail

# Standart Çıkış Kodu Sabitleri
readonly STATUS_OK=0              # İşlem başarılı
readonly STATUS_ERR_PARAM=1       # Eksik veya hatalı parametre
readonly STATUS_ERR_NOT_FOUND=2   # Hedef dosya veya komut bulunamadı
readonly STATUS_ERR_PIPELINE=3    # Boru hattı filtreleme hatası

# Güvenli Hata Yazma Fonksiyonu (stderr Yönlendirmeli)
log_stderr() {
    local level="${1:-HATA}"  # Log seviyesi
    shift  # Seviye parametresini kaydır
    local message="${*}"  # Geriye kalan tüm argümanlar mesajdır

    # Hassas veri maskeleme (Parola veya token sızıntısı engelleme)
    local sanitized_msg
    sanitized_msg="$(echo "${message}" | sed -E 's/(password|passwd|token|secret)[:=][^ ]+/\1:***REDACTED***/gi')"

    # Standart hata akışına (2 / stderr) zaman damgalı çıktı verilir
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [${level}] ${sanitized_msg}" >&2
}

# Çıkış Yakalama ve Temizlik Fonksiyonu
cleanup_exit() {
    local exit_status="${1:-0}"  # Çıkış kodu yakalanır
    local failed_line="${2:-unknown}"  # Hata oluşan satır numarası

    if [[ "${exit_status}" -ne 0 ]]; then  # Hata varsa
        log_stderr "KRİTİK" "Betik satır ${failed_line} üzerinde sonlandı (Durum Kodu: ${exit_status})"
    fi
}
trap 'cleanup_exit "$?" "$LINENO"' EXIT  # EXIT sinyaline trap bağlanır

# Ana Fonksiyon
main() {
    local input_file="${1:-}"  # İlk argüman alınır

    if [[ -z "${input_file}" ]]; then  # Parametre yoksa
        log_stderr "HATA" "Hedef dosya yolu belirtilmedi. Kullanım: ${0} <dosya_yolu>"
        exit "${STATUS_ERR_PARAM}"
    fi

    if [[ ! -f "${input_file}" ]]; then  # Dosya mevcut değilse
        log_stderr "UYARI" "Dosya mevcut değil, sentetik denetim yapılıyor: ${input_file}"
    fi

    # Güvenli Boru Hattı Denetimi: PIPESTATUS Analizi
    echo "G088 Denetim Verisi - Standart Cikis" | grep "G088" > /dev/null
    local pipe_res=("${PIPESTATUS[@]}")  # PIPESTATUS dizisi kaydedilir

    for st in "${pipe_res[@]}"; do  # Her aşama denetlenir
        if [[ "${st}" -ne 0 ]]; then  # Sıfır dışı kod varsa
            log_stderr "HATA" "Boru hattı ara adımı çöktü (Durum: ${st})"
            exit "${STATUS_ERR_PIPELINE}"
        fi
    done

    # Standart çıktı akışına (1 / stdout) yapısal başarı bildirimi
    echo "STATUS=SUCCESS;EXIT_CODE=${STATUS_OK};TARGET=${input_file}"
    exit "${STATUS_OK}"
}

# Güvenli Giriş Noktası
main "${@}"
