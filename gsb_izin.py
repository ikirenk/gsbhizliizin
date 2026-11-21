#!/usr/bin/env python3
"""
GSB Biz (KYK) Otomatik Yurt İzin Talebi Scripti

Akış:
1. giris.gsb.gov.tr -> giris.turkiye.gov.tr OAuth2 akışını başlatır.
2. e-Devlet jCryption (CryptoServlet RSA + CryptoJS AES-256-CBC) el sıkışmasını yapar.
3. TC Kimlik No (encTridField) ve Şifre (encEgpField) alanlarını şifreleyip gönderir.
4. SMS / 2FA doğrulaması istenirse kullanıcıdan kodu ister ve onaylar; OAuth2 SaveScope adımını geçer.
5. biz.gsb.gov.tr/edevlet?token=... üzerinden gelen token'ı VerifyToken ile Bearer JWT'ye çevirir.
6. KYK/OgrenciDetay ve KYK/IzinGunSayisi bilgilerini çeker, KYK/IzinTalepKaydet ile izin talebi oluşturur.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GSB_LOGIN_URL = "https://giris.gsb.gov.tr/?appid=F9611508-EE31-4A1F-8C79-C289C0C47218"
GSB_API_BASE = "https://gsbbizapi.gsb.gov.tr"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
)


def evp_bytes_to_key(passphrase: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16) -> tuple[bytes, bytes]:
    """CryptoJS / OpenSSL EVP_BytesToKey (MD5, 1 iterasyon) anahtar ve IV türetme."""
    dtot = b""
    d = b""
    while len(dtot) < key_len + iv_len:
        d = hashlib.md5(d + passphrase + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len : key_len + iv_len]


def cryptojs_aes_encrypt(plaintext: str, passphrase: str) -> str:
    """CryptoJS.AES.encrypt(plaintext, passphrase) uyumlu OpenSSL Salted__ AES-256-CBC şifreleme."""
    salt = os.urandom(8)
    key, iv = evp_bytes_to_key(passphrase.encode("utf-8"), salt)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(b"Salted__" + salt + ct).decode("ascii")


def cryptojs_aes_decrypt(b64_ciphertext: str, passphrase: str) -> bytes:
    """CryptoJS.AES.decrypt(b64_ciphertext, passphrase) uyumlu şifre çözme."""
    raw = base64.b64decode(b64_ciphertext)
    if not raw.startswith(b"Salted__"):
        raise ValueError("Geçersiz CryptoJS ciphertext (Salted__ başlığı yok)")
    salt = raw[8:16]
    ct = raw[16:]
    key, iv = evp_bytes_to_key(passphrase.encode("utf-8"), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def rsa_encrypt_b64(plaintext: str, public_key_str: str) -> str:
    """JSEncrypt.encrypt() uyumlu RSA PKCS#1 v1.5 şifreleme (PEM veya ham Base64 DER)."""
    key_str = public_key_str.strip()
    if "-----BEGIN" in key_str:
        pub_key = serialization.load_pem_public_key(key_str.encode("utf-8"))
    else:
        pub_key = serialization.load_der_public_key(base64.b64decode(key_str))
    encrypted = pub_key.encrypt(plaintext.encode("utf-8"), asym_padding.PKCS1v15())
    return base64.b64encode(encrypted).decode("ascii")


def _extract_jcryption_params(html: str, page_url: str) -> tuple[str, str, str | None]:
    """e-Devlet giriş HTML'inden CryptoServlet URL'lerini ve cryptoKeyId değerini çıkarır."""
    key_id_match = re.search(r'var\s+cryptoKeyId\s*=\s*["\']([^"\']+)["\']', html)
    crypto_key_id = key_id_match.group(1) if key_id_match else None

    auth_match = re.search(
        r'\$\.jCryption\.authenticate\([^,]+,\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']',
        html,
    )
    if auth_match:
        gen_url = urljoin(page_url, auth_match.group(1))
        hs_raw = auth_match.group(2)
        if crypto_key_id and hs_raw.endswith("cryptoKeyId="):
            hs_raw += crypto_key_id
        hs_url = urljoin(page_url, hs_raw)
    else:
        gen_url = urljoin(page_url, "CryptoServlet?generateKeyPair=true")
        hs_url = urljoin(
            page_url,
            f"CryptoServlet?handshake=true&cryptoKeyId={crypto_key_id}"
            if crypto_key_id
            else "CryptoServlet?handshake=true",
        )
    return gen_url, hs_url, crypto_key_id


def _extract_form_data(form: Any) -> dict[str, str]:
    """BeautifulSoup form elemanındaki tüm input değerlerini sözlüğe alır."""
    data: dict[str, str] = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        inp_type = (inp.get("type") or "text").lower()
        if inp_type in ("checkbox", "radio") and not inp.has_attr("checked"):
            continue
        data[name] = inp.get("value") or ""
    return data


def _extract_error_message(soup: BeautifulSoup) -> str | None:
    for selector in (
        ".errorContainer",
        ".form-error .form-note",
        ".warningContainer",
        "#errorText",
        ".alert-danger",
        ".alert-warning",
        ".error-message",
    ):
        el = soup.select_one(selector)
        if el:
            txt = " ".join(el.get_text(" ", strip=True).split())
            if txt:
                return txt
    return None


def _summarize_page(soup: BeautifulSoup) -> str:
    title = soup.title.get_text(strip=True) if soup.title else "(yok)"
    err = _extract_error_message(soup)
    forms_info = []
    for idx, f in enumerate(soup.find_all("form")):
        inputs = [
            f"{i.get('name') or i.get('id')}[{i.get('type') or 'text'}]"
            for i in f.find_all(["input", "button"])
        ]
        forms_info.append(f"form#{idx}(action={f.get('action')}, fields={inputs})")
    return f"title={title!r}, err={err!r}, forms={forms_info}"


def login_edevlet_for_gsb(tc: str, password: str) -> str:
    """e-Devlet üzerinden GSB Biz'e giriş yapar ve biz.gsb.gov.tr/edevlet?token=... değerini döndürür."""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        }
    )

    print("[1/5] GSB -> e-Devlet yönlendirmesi başlatılıyor...")
    resp = session.get(GSB_LOGIN_URL, allow_redirects=True, timeout=30)
    resp.raise_for_status()

    if "biz.gsb.gov.tr/edevlet" in resp.url:
        token = parse_qs(urlparse(resp.url).query).get("token", [None])[0]
        if token:
            return token

    soup = BeautifulSoup(resp.text, "lxml")
    login_form = soup.find("form", id="loginForm") or soup.find("form", attrs={"name": "sifreGirisForm"})
    if not login_form:
        raise RuntimeError(f"e-Devlet giriş formu bulunamadı (URL: {resp.url})")

    # 2. jCryption RSA + AES el sıkışması
    print("[2/5] e-Devlet CryptoServlet (jCryption RSA+AES) el sıkışması yapılıyor...")
    gen_url, hs_url, crypto_key_id = _extract_jcryption_params(resp.text, resp.url)

    kp_resp = session.get(gen_url, headers={"X-Requested-With": "XMLHttpRequest"}, timeout=30)
    kp_resp.raise_for_status()
    public_key = kp_resp.json()["publickey"]

    # e-Devlet JS'i rastgele bir parola üretip AES anahtarı olarak kullanır
    aes_passphrase = secrets.token_hex(16)
    encrypted_aes_key = rsa_encrypt_b64(aes_passphrase, public_key)

    hs_resp = session.post(
        hs_url,
        data={"key": encrypted_aes_key},
        headers={"X-Requested-With": "XMLHttpRequest"},
        timeout=30,
    )
    hs_resp.raise_for_status()
    challenge = hs_resp.json().get("challenge")
    if challenge:
        # challenge değeri sunucunun AES anahtarımızı doğruladığını gösterir
        _ = cryptojs_aes_decrypt(challenge, aes_passphrase)

    # 3. TC ve Şifre'yi CryptoJS AES-256-CBC ile şifrele
    form_data = _extract_form_data(login_form)
    form_data["tridField"] = ""
    form_data["egpField"] = ""
    form_data["encTridField"] = cryptojs_aes_encrypt(tc, aes_passphrase)
    form_data["encEgpField"] = cryptojs_aes_encrypt(password, aes_passphrase)
    if crypto_key_id:
        form_data["cryptoKeyId"] = crypto_key_id
    form_data.setdefault("actionName", "giris")
    form_data["submitButton"] = "Giriş Yap"

    post_url = urljoin(resp.url, login_form.get("action") or resp.url)
    print("[3/5] Şifrelenmiş TC ve şifre gönderiliyor...")
    resp = session.post(post_url, data=form_data, allow_redirects=True, timeout=30)
    resp.raise_for_status()

    # 4. Olası ara adımlar: SMS OTP doğrulaması ve OAuth2 SaveScope onayı
    for _ in range(6):
        if "biz.gsb.gov.tr/edevlet" in resp.url:
            token = parse_qs(urlparse(resp.url).query).get("token", [None])[0]
            if token:
                return token

        soup = BeautifulSoup(resp.text, "lxml")

        # OAuth2 izin onay sayfası (AuthorizationController -> SaveScope)
        save_scope_link = soup.find("a", href=re.compile(r"SaveScope"))
        if save_scope_link:
            resp = session.get(urljoin(resp.url, save_scope_link["href"]), allow_redirects=True, timeout=30)
            resp.raise_for_status()
            continue

        scope_form = soup.find("form", action=re.compile(r"SaveScope"))
        if scope_form:
            s_data = _extract_form_data(scope_form)
            s_data["btn"] = "Onayla"
            resp = session.get(
                urljoin(resp.url, scope_form["action"]),
                params=s_data,
                allow_redirects=True,
                timeout=30,
            )
            resp.raise_for_status()
            continue

        # Hata kontrolü
        err = _extract_error_message(soup)
        if err and any(w in err.lower() for w in ("hatalı", "yanlış", "doğrulama", "hata", "bloke", "güvenlik")):
            raise RuntimeError(f"e-Devlet giriş hatası: {err}")

        # SMS / OTP doğrulama formu tespiti
        forms = soup.find_all("form")
        if not forms:
            break

        handled = False
        for form in forms:
            f_data = _extract_form_data(form)
            otp_input = None
            for inp in form.find_all("input"):
                name = inp.get("name") or ""
                inp_type = (inp.get("type") or "text").lower()
                if inp_type in ("hidden", "submit", "button", "checkbox", "radio"):
                    continue
                if name and name != "currentPageToken" and re.search(
                    r"(sms|otp|kod|code|dogrulama|pin|token)", name, re.I
                ):
                    otp_input = inp
                    break

            if otp_input:
                otp_name = otp_input["name"]
                sms_code = input(f"\n[!] e-Devlet SMS doğrulama kodunu girin ({otp_name}): ").strip()
                f_data[otp_name] = sms_code
                submit_btn = form.find("button", attrs={"type": "submit"}) or form.find(
                    "input", attrs={"type": "submit"}
                )
                if submit_btn and submit_btn.get("name"):
                    f_data[submit_btn["name"]] = submit_btn.get("value") or "Devam Et"
                action_url = urljoin(resp.url, form.get("action") or resp.url)
                resp = session.post(action_url, data=f_data, allow_redirects=True, timeout=30)
                resp.raise_for_status()
                handled = True
                break

            # Eğer SMS göndermeden önceki ara onay formuysa (ör. "SMS Kodu Gönder" butonu)
            send_sms_btn = form.find("button", string=re.compile(r"(SMS|Kod|Gönder|Devam|Onayla)", re.I))
            if not send_sms_btn:
                send_sms_btn = form.find("input", attrs={"type": "submit", "value": re.compile(r"(SMS|Kod|Gönder|Devam|Onayla)", re.I)})
            if send_sms_btn:
                if send_sms_btn.get("name"):
                    f_data[send_sms_btn["name"]] = send_sms_btn.get("value") or send_sms_btn.get_text(strip=True)
                action_url = urljoin(resp.url, form.get("action") or resp.url)
                resp = session.post(action_url, data=f_data, allow_redirects=True, timeout=30)
                resp.raise_for_status()
                handled = True
                break

            # Sadece hidden alanlardan oluşan (JS ile otomatik gönderilen) ara form
            visible_inputs = [
                i for i in form.find_all("input")
                if (i.get("type") or "text").lower() != "hidden"
            ]
            if not visible_inputs and "currentPageToken" in f_data and "actionName" in f_data:
                if "ajaxOtpBaslangicKontrol" in resp.text:
                    session.get(
                        urljoin(resp.url, "/Giris/sifreGiris?actionName=ajaxOtpBaslangicKontrol"),
                        headers={"X-Requested-With": "XMLHttpRequest"},
                        timeout=30,
                    )
                print(f"[*] Ara form gönderiliyor (actionName={f_data.get('actionName')})...")
                action_url = urljoin(resp.url, form.get("action") or resp.url)
                resp = session.post(action_url, data=f_data, allow_redirects=True, timeout=30)
                resp.raise_for_status()
                handled = True
                break

        if not handled:
            break

    if "biz.gsb.gov.tr/edevlet" in resp.url:
        token = parse_qs(urlparse(resp.url).query).get("token", [None])[0]
        if token:
            return token

    soup = BeautifulSoup(resp.text, "lxml")
    raise RuntimeError(f"GSB e-Devlet dönüş token'ı alınamadı. Son URL: {resp.url} | {_summarize_page(soup)}")


class GsbBizClient:
    """gsbbizapi.gsb.gov.tr API istemcisi."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Origin": "https://biz.gsb.gov.tr",
                "Referer": "https://biz.gsb.gov.tr/",
            }
        )
        self.jwt_token: str | None = None

    def verify_token(self, edevlet_token: str) -> dict[str, Any]:
        print("[4/5] GSB API VerifyToken ile Bearer JWT alınıyor...")
        resp = self.session.post(
            f"{GSB_API_BASE}/Account/VerifyToken",
            json={"token": edevlet_token},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        jwt = data.get("token") or data.get("data", {}).get("token")
        if not jwt:
            raise RuntimeError(f"VerifyToken yanıtında JWT bulunamadı: {data}")
        self.jwt_token = jwt
        self.session.headers["Authorization"] = f"Bearer {jwt}"
        return data

    def get_ogrenci_detay(self) -> dict[str, Any]:
        resp = self.session.get(f"{GSB_API_BASE}/KYK/OgrenciDetay", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_izin_gun_sayisi(self) -> dict[str, Any]:
        resp = self.session.get(f"{GSB_API_BASE}/KYK/IzinGunSayisi", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_izin_talep_listesi(self) -> dict[str, Any]:
        resp = self.session.get(f"{GSB_API_BASE}/KYK/IzinTalepListesi", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def izin_talep_kaydet(
        self,
        baslangic_iso: str,
        bitis_iso: str,
        telefon: str,
        evci_id: str,
        aciklama: str = "İzinli",
    ) -> dict[str, Any]:
        payload = {
            "baslangic": baslangic_iso,
            "bitis": bitis_iso,
            "aciklama": aciklama,
            "telefon": telefon,
            "evciId": evci_id,
        }
        resp = self.session.post(
            f"{GSB_API_BASE}/KYK/IzinTalepKaydet",
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()


def _extract_evci_addresses(ogrenci_detay: dict[str, Any]) -> list[dict[str, str]]:
    """OgrenciDetay JSON yanıtından evci adres listesini (id, adres) döndürür."""
    data = ogrenci_detay.get("data", ogrenci_detay)
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
        data = data["data"]
    evci_list = data.get("ogrencI_IZINLER_EVCI") or []
    result: list[dict[str, str]] = []
    for item in evci_list:
        if isinstance(item, dict) and item.get("id"):
            result.append({"id": str(item["id"]), "adres": str(item.get("adres") or item["id"])})
    return result


def _extract_phone(ogrenci_detay: dict[str, Any]) -> str | None:
    """OgrenciDetay JSON yanıtından telefon bilgisini bulmaya çalışır."""
    raw = json.dumps(ogrenci_detay, ensure_ascii=False)
    tel_match = re.search(r'"(?:telefon|irtibattel|cepTel|gsm)"\s*:\s*"(0?5\d{9})"', raw, re.I)
    return tel_match.group(1) if tel_match else None


def _to_gsb_iso_date(date_str: str) -> str:
    """YYYY-MM-DD tarihini GSB API'nin beklediği YYYY-MM-DDT00:00:00.000Z formatına çevirir."""
    dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT00:00:00.000Z")


def main() -> int:
    parser = argparse.ArgumentParser(description="GSB Biz (KYK) Yurt İzin Talebi Otomasyonu")
    parser.add_argument("--tc", default=os.getenv("GSB_TC"), help="T.C. Kimlik Numarası (verilmezse sorulur)")
    parser.add_argument("--password", default=os.getenv("GSB_EDEVLET_SIFRE"), help="e-Devlet şifresi (verilmezse gizli sorulur)")
    parser.add_argument("--baslangic", help="İzin başlangıç tarihi (YYYY-MM-DD, varsayılan: bugün)")
    parser.add_argument("--bitis", help="İzin bitiş tarihi (YYYY-MM-DD, varsayılan: yarın)")
    parser.add_argument("--aciklama", default="İzinli", help="İzin açıklaması (varsayılan: İzinli)")
    parser.add_argument("--telefon", help="İrtibat telefonu (05XXXXXXXXX)")
    parser.add_argument("--evci-id", help="Evci adres ID (UUID, verilmezse listeden seçtirilir)")
    parser.add_argument("--dry-run", action="store_true", help="Giriş yapıp bilgileri alır ama IzinTalepKaydet isteği atmaz")
    args = parser.parse_args()

    today = datetime.now().date()
    baslangic_str = args.baslangic or today.strftime("%Y-%m-%d")
    bitis_str = args.bitis or (today + timedelta(days=1)).strftime("%Y-%m-%d")

    baslangic_iso = _to_gsb_iso_date(baslangic_str)
    bitis_iso = _to_gsb_iso_date(bitis_str)

    tc = (args.tc or input("T.C. Kimlik No: ")).strip()
    password = args.password or getpass.getpass(f"e-Devlet şifresi ({tc}): ")

    edevlet_token = login_edevlet_for_gsb(tc, password)
    client = GsbBizClient()
    verify_res = client.verify_token(edevlet_token)
    print(f"Giriş başarılı: {verify_res.get('fullName', 'Kullanıcı')}")

    print("[5/5] Öğrenci detayları ve izin gün sayısı alınıyor...")
    detay = client.get_ogrenci_detay()
    gun_sayisi = client.get_izin_gun_sayisi()
    print("İzin gün durumu:", json.dumps(gun_sayisi, ensure_ascii=False))

    evci_addresses = _extract_evci_addresses(detay)
    evci_id = args.evci_id
    if not evci_id:
        if not evci_addresses:
            raise RuntimeError("Kayıtlı evci adresi bulunamadı. GSB Biz üzerinden evci adresi ekleyin veya --evci-id verin.")
        print("\nKayıtlı Evci Adresleri:")
        for idx, item in enumerate(evci_addresses, start=1):
            print(f"  {idx}) {item['adres']} ({item['id']})")
        choice = int(input("Seçiminiz (numara): ").strip()) - 1
        if not (0 <= choice < len(evci_addresses)):
            raise RuntimeError("Geçersiz adres seçimi.")
        evci_id = evci_addresses[choice]["id"]

    telefon = args.telefon or _extract_phone(detay) or input("İrtibat Telefonu (05XXXXXXXXX): ").strip()
    if not telefon:
        raise RuntimeError("Telefon numarası belirtilmelidir.")

    if args.dry_run:
        print("\n[DRY-RUN] İzin talebi gönderilmedi. Gönderilecek gövde:")
        print(
            json.dumps(
                {
                    "baslangic": baslangic_iso,
                    "bitis": bitis_iso,
                    "aciklama": args.aciklama,
                    "telefon": telefon,
                    "evciId": evci_id,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    sonuc = client.izin_talep_kaydet(
        baslangic_iso=baslangic_iso,
        bitis_iso=bitis_iso,
        telefon=telefon,
        evci_id=evci_id,
        aciklama=args.aciklama,
    )
    print("\nİzin talebi sonucu:", json.dumps(sonuc, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
