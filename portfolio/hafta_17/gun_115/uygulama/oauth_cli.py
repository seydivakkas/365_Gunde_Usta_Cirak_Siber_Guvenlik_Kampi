# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 115: OAuth 2.0 ve OpenID Connect (OIDC) Komut Satırı Arayüzü (OAuth CLI).

Bu araç, RFC 6749 ve RFC 7636 (PKCE) akışını baştan sona simüle etmek,
yetkilendirme kodu üretmek, belirteç takası yapmak ve korumalı API'lere erişmek için kullanılır.
"""

# Komut satırı argümanları için argparse içe aktarılır
import argparse
# JSON serileştirme ve formatlama için json içe aktarılır
import json
# Çıkış kodları ve akış kontrolü için sys içe aktarılır
import sys
# Dosya yolları için os içe aktarılır
import os
# Kriptografik güvenli rastgele dizgiler için secrets içe aktarılır
import secrets
# URL ayrıştırma için parse_qs ve urlparse içe aktarılır
from urllib.parse import urlparse, parse_qs

# Bulunduğumuz dizin Python arama yoluna eklenir (bağımsız çalışma standardı)
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# oauth2_oidc_engine modülünden gerekli sınıflar içe aktarılır
from oauth2_oidc_engine import (
    OAuth2AuthorizationServer,
    OAuth2ResourceServer,
    OIDCClientRelyingParty,
    PKCEHelper,
    JWTHelper,
    OAuthSecurityError
)


def build_demo_environment() -> Tuple[OAuth2AuthorizationServer, OAuth2ResourceServer, OIDCClientRelyingParty]:
    """Standart test ve gösterim ortamı kurar."""
    idp_secret = "SiberIdPGizliAnahtar2026!HS256"
    auth_server = OAuth2AuthorizationServer(
        issuer_url="https://idp.siber.local",
        token_secret=idp_secret
    )
    resource_server = OAuth2ResourceServer(auth_server)
    client_rp = OIDCClientRelyingParty(
        client_id="finans_portal_app",
        expected_issuer="https://idp.siber.local",
        idp_secret=idp_secret
    )

    # İstemci kaydı
    auth_server.register_client(
        client_id="finans_portal_app",
        client_secret="FinansGizliAnahtari!2026",
        redirect_uris=["https://portal.siber.local/callback"],
        allowed_scopes=["openid", "profile", "read:profile", "read:reports"],
        client_type="confidential"
    )

    return auth_server, resource_server, client_rp


def cmd_akisi_baslat(args) -> None:
    """PKCE çifti, state ve nonce üreterek /authorize istek parametrelerini hazırlar."""
    code_verifier = PKCEHelper.generate_code_verifier()
    code_challenge = PKCEHelper.compute_code_challenge_s256(code_verifier)
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    print("=" * 70)
    print("OAUTH 2.0 PKCE VE OIDC YETKİLENDİRME BAŞLATICI")
    print("=" * 70)
    print(f"İstemci Kimliği (client_id)     : {args.client_id}")
    print(f"Yönlendirme Adresi (redirect_uri): {args.redirect_uri}")
    print(f"Kapsam (Scope)                  : {args.scope}")
    print(f"Kriptografik State (CSRF)       : {state}")
    print(f"OIDC Nonce (Replay Savunması)   : {nonce}")
    print(f"PKCE code_verifier (Gizli)      : {code_verifier}")
    print(f"PKCE code_challenge (S256)      : {code_challenge}")
    print("\n[BİLGİ] Bu parametrelerle /authorize uç noktasına gidilmelidir.")


def cmd_tam_akis(args, auth_server: OAuth2AuthorizationServer, res_server: OAuth2ResourceServer, client_rp: OIDCClientRelyingParty) -> None:
    """Uçtan uca başarılı yetkilendirme, belirteç takası ve API çağrısı simülasyonu."""
    print("=== OAUTH 2.0 + OIDC PKCE UÇTAN UCA AKIŞ TESTİ ===\n")

    # 1. Aşama: İstemci PKCE, state ve nonce üretir
    verifier = PKCEHelper.generate_code_verifier()
    challenge = PKCEHelper.compute_code_challenge_s256(verifier)
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    # 2. Aşama: /authorize çağrısı yapılır
    redirect_uri = "https://portal.siber.local/callback"
    callback_url = auth_server.authorize_endpoint(
        client_id="finans_portal_app",
        redirect_uri=redirect_uri,
        response_type="code",
        scope="openid profile read:profile read:reports",
        state=state,
        code_challenge=challenge,
        code_challenge_method="S256",
        nonce=nonce,
        authenticated_user=args.kullanici
    )
    print(f"1. Yetkilendirme Başarılı. Yönlendirme URL'i:\n   {callback_url}\n")

    # Callback URL'den code ve state ayrıştırılır
    parsed = urlparse(callback_url)
    qs = parse_qs(parsed.query)
    auth_code = qs["code"][0]
    ret_state = qs["state"][0]

    # İstemci state kontrolü yapar (CSRF Savunması)
    if ret_state != state:
        print("[HATA] CSRF State Uyuşmazlığı!")
        sys.exit(1)

    # 3. Aşama: /token çağrısı ile kod ve code_verifier takas edilir
    tokens = auth_server.token_endpoint(
        grant_type="authorization_code",
        client_id="finans_portal_app",
        client_secret="FinansGizliAnahtari!2026",
        code=auth_code,
        redirect_uri=redirect_uri,
        code_verifier=verifier
    )
    print("2. Belirteç Takası Başarılı (/token):")
    print(f"   Access Token: {tokens['access_token'][:16]}... (Bearer)")
    print(f"   Kapsam      : {tokens['scope']}")
    print(f"   ID Token    : {tokens['id_token'][:30]}... (JWT)\n")

    # İstemci ID Token'ı ve Nonce'ı doğrular
    id_claims = client_rp.verify_callback_and_id_token(
        callback_state=ret_state,
        original_state=state,
        id_token_jwt=tokens["id_token"],
        original_nonce=nonce
    )
    print("3. OIDC ID Token Doğrulandı:")
    print(f"   Issuer (iss) : {id_claims['iss']}")
    print(f"   Subject (sub): {id_claims['sub']}")
    print(f"   Audience(aud): {id_claims['aud']}")
    print(f"   Nonce        : {id_claims['nonce']}\n")

    # 4. Aşama: Resource Server API Çağrısı
    auth_hdr = f"Bearer {tokens['access_token']}"
    profile = res_server.get_user_profile(auth_hdr)
    reports = res_server.get_confidential_reports(auth_hdr)
    print("4. Korumalı Kaynak Sunucusuna (Resource Server) Erişim Başarılı:")
    print(f"   Profil Bilgisi: {json.dumps(profile, ensure_ascii=False)}")
    print(f"   Rapor Bilgisi : {json.dumps(reports, ensure_ascii=False)}")
    print("\n[TAMAMLANDI] Tüm OAuth 2.0 ve OIDC güvenlik kontrolleri başarıyla geçti.")


def main():
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="OAuth 2.0 ve OpenID Connect (OIDC) Referans CLI Aracı"
    )
    subparsers = parser.add_subparsers(dest="komut", help="Yürütülecek işlem")

    # 'akisi-baslat' alt komutu
    p_baslat = subparsers.add_parser("akisi-baslat", help="PKCE ve State parametrelerini üret")
    p_baslat.add_argument("--client-id", default="finans_portal_app", help="İstemci kimliği")
    p_baslat.add_argument("--redirect-uri", default="https://portal.siber.local/callback", help="Yönlendirme adresi")
    p_baslat.add_argument("--scope", default="openid profile read:profile", help="Talep edilen kapsamlar")

    # 'tam-akis' alt komutu
    p_akis = subparsers.add_parser("tam-akis", help="Uçtan uca OAuth 2.0 PKCE ve OIDC akışını simüle et")
    p_akis.add_argument("--kullanici", default="seydi_kullanici", help="Oturum açan kullanıcı adı")

    args = parser.parse_args()
    auth_server, res_server, client_rp = build_demo_environment()

    if args.komut == "akisi-baslat":
        cmd_akisi_baslat(args)
    elif args.komut == "tam-akis":
        cmd_tam_akis(args, auth_server, res_server, client_rp)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
