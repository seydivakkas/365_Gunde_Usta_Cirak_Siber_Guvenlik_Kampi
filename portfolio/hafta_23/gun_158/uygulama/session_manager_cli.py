# -*- coding: utf-8 -*-
"""
Oturum Yönetimi ve Süresi CLI Yönetim Aracı
Hafta 23 / Gün 158 - Aşama 7 (Web Güvenliği)

Bu araç; kurumsal HTTP oturumlarının oluşturulmasını, zaman aşımlarını (Idle & Absolute),
oturum sabitleme korumasını (Fixation/Rotation), kullanıcı bazlı iptal süreçlerini
ve yaşam döngüsü istatistiklerini komut satırından yönetir.
"""

import argparse
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.session_manager_engine import (
    SessionManagerEngine,
    SessionPolicy,
    SessionState
)


def handle_create(args):
    """Yeni bir kullanıcı oturumu oluşturur."""
    engine = SessionManagerEngine()
    session = engine.create_session(
        user_id=args.user_id,
        username=args.username,
        role=args.role,
        client_ip=args.ip,
        user_agent=args.user_agent
    )
    print("=" * 75)
    print(" YENİ KURUMSAL GÜVENLİ OTURUM OLUŞTURULDU")
    print("=" * 75)
    print(f" Oturum Kimliği (ID)   : {session.session_id}")
    print(f" Kullanıcı Adı         : {session.username} (ID: {session.user_id})")
    print(f" Yetki Rolü            : {session.role}")
    print(f" İstemci IP            : {session.client_ip}")
    print(f" Tarayıcı (User-Agent) : {session.user_agent}")
    print(f" Durum                 : {session.state.value}")
    print("=" * 75)


def handle_validate(args):
    """Mevcut bir oturumu doğrular ve zaman aşımı/güvenlik kontrollerini çalıştırır."""
    engine = SessionManagerEngine()
    # Simüle edilmiş oturum ekleme
    now = time.time()
    s = engine.create_session(
        user_id="usr_100",
        username="test_user",
        role="User",
        client_ip=args.registered_ip if args.registered_ip else args.ip,
        user_agent=args.registered_ua if args.registered_ua else args.user_agent,
        current_time=now - args.elapsed_seconds
    )
    
    # Doğrulama isteğini çalıştırma
    res = engine.validate_session(
        session_id=s.session_id,
        client_ip=args.ip,
        user_agent=args.user_agent,
        current_time=now
    )
    print("=" * 75)
    print(" OTURUM DOĞRULAMA SONUCU")
    print("=" * 75)
    print(f" Oturum Kimliği   : {res.session_id}")
    print(f" Geçerli mi?      : {'EVET (Geçerli)' if res.is_valid else 'HAYIR (Geçersiz)'}")
    print(f" Durum            : {res.status.value}")
    print(f" Gerekçe          : {res.reason}")
    print(f" Rotasyon Gerekli : {'EVET' if res.requires_rotation else 'HAYIR'}")
    if res.new_session_id:
        print(f" Yeni Oturum ID   : {res.new_session_id}")
    print("=" * 75)


def handle_elevate(args):
    """Ayrıcalık yükseltme ve oturum sabitleme korumasını gösterir."""
    engine = SessionManagerEngine()
    s = engine.create_session(
        user_id="usr_admin_cand",
        username="semih_usta",
        role="User",
        client_ip="192.168.1.50",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    old_id = s.session_id
    elevated = engine.elevate_privilege(old_id, new_role=args.new_role)
    print("=" * 75)
    print(" AYRICALIK YÜKSELTME VE OTURUM SABİTLEME (FIXATION) KALKANI")
    print("=" * 75)
    print(f" Eski Oturum Kimliği  : {old_id} (İPTAL EDİLDİ)")
    print(f" Yeni Oturum Kimliği  : {elevated.session_id} (AKTİF)")
    print(f" Yeni Rol             : {elevated.role}")
    print(f" Rotasyon Sayısı      : {elevated.rotation_count}")
    print(" OWASP Kuralı         : Yetki değiştiğinde oturum kimliği zorla yenilendi!")
    print("=" * 75)


def handle_audit(args):
    """Oturum yaşam döngüsü ve politika raporu üretir."""
    policy = SessionPolicy()
    if args.policy_file and os.path.exists(args.policy_file):
        with open(args.policy_file, "r", encoding="utf-8") as f:
            p_data = json.load(f)
            policy = SessionPolicy(**p_data)

    engine = SessionManagerEngine(policy=policy)
    
    # Temsili oturumlar oluşturma
    now = time.time()
    engine.create_session("u1", "ali", "Admin", "10.0.0.1", "Chrome", current_time=now)
    engine.create_session("u2", "ayse", "User", "10.0.0.2", "Firefox", current_time=now - 1200) # Idle time-out
    
    # Raporu üretme
    ascii_out = engine.generate_ascii_lifecycle()
    print(ascii_out)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        stats = engine.audit_lifecycle()
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Oturum denetim raporu kaydedildi: {args.output}")


def main():
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Kurumsal Web Oturum Yönetimi ve Süresi CLI Aracı (Gün 158)"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Alt komutlar")

    # 1. create
    p_create = subparsers.add_parser("create", help="Yeni oturum açar")
    p_create.add_argument("--user-id", default="usr_001", help="Kullanıcı ID")
    p_create.add_argument("--username", default="seydi_admin", help="Kullanıcı adı")
    p_create.add_argument("--role", default="Admin", help="Kullanıcı rolü")
    p_create.add_argument("--ip", default="192.168.1.100", help="İstemci IP adresi")
    p_create.add_argument("--user-agent", default="Mozilla/5.0 Chrome/130.0", help="Tarayıcı User-Agent")

    # 2. validate
    p_val = subparsers.add_parser("validate", help="Oturum doğrular")
    p_val.add_argument("--ip", default="192.168.1.100", help="İstek yapan IP")
    p_val.add_argument("--user-agent", default="Mozilla/5.0 Chrome/130.0", help="İstek yapan User-Agent")
    p_val.add_argument("--registered-ip", help="Kayıtlı IP (uyuşmazlık simülasyonu)")
    p_val.add_argument("--registered-ua", help="Kayıtlı UA (uyuşmazlık simülasyonu)")
    p_val.add_argument("--elapsed-seconds", type=float, default=60, help="Geçen süre (saniye)")

    # 3. elevate
    p_elevate = subparsers.add_parser("elevate", help="Yetki yükseltir ve ID yeniler")
    p_elevate.add_argument("--new-role", default="SuperAdmin", help="Yeni rol")

    # 4. audit
    p_audit = subparsers.add_parser("audit", help="Oturum yaşam döngüsü denetim panosu basar")
    p_audit.add_argument("--policy-file", help="JSON politika dosyası yolu")
    p_audit.add_argument("--output", help="Çıktı JSON dosya yolu")

    args = parser.parse_args()

    if args.subcommand == "create":
        handle_create(args)
    elif args.subcommand == "validate":
        handle_validate(args)
    elif args.subcommand == "elevate":
        handle_elevate(args)
    elif args.subcommand == "audit":
        handle_audit(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
