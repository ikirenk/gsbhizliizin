# GSB Hızlı İzin (KYK Yurt İzin Otomasyonu)

Gençlik ve Spor Bakanlığı (`biz.gsb.gov.tr`) KYK yurt öğrencilerinin e-Devlet üzerinden hızlıca yurt izin talebi oluşturabilmesi için hazırlanmış **Android (Kotlin + Jetpack Compose)** uygulaması ve **Python CLI** aracı.

## Özellikler

- **e-Devlet OAuth2 + jCryption Entegrasyonu**:
  - `CryptoServlet` üzerinden RSA PKCS#1 v1.5 + AES-256-CBC (`Salted__` / OpenSSL `EVP_BytesToKey`) el sıkışması.
  - İnteraktif **CAPTCHA** (güvenlik kodu) ve **SMS doğrulama (2FA)** desteği.
- **Takvim Üzerinden Tarih Seçimi**: Android uygulamasında Material 3 `DateRangePicker` ile başlangıç ve bitiş tarihlerini seçme.
- **Evci Adresi Listesi**: `GET /KYK/OgrenciDetay` üzerinden kullanıcının kayıtlı evci adreslerini (`ogrencI_IZINLER_EVCI`) çekip listeden seçme.
- **Kişisel Veri İçermez**: Tüm kimlik, şifre, telefon ve token bilgileri yalnızca çalışma anında cihazda/oturumda işlenir.

---

## 1. Android Uygulaması (`android-app/`)

### Gereksinimler
- JDK 17+ (JDK 21 ile test edildi)
- Android SDK (`platforms;android-35`, `build-tools;35.0.0`, `platform-tools`)
- Gradle veya Android Studio

### Derleme (Terminal)
```bash
cd android-app
export ANDROID_HOME="$HOME/Android/Sdk"
gradle assembleDebug
```
Oluşturulan APK: `android-app/app/build/outputs/apk/debug/app-debug.apk`

Telefonunuza yüklemek için:
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## 2. Python CLI (`gsb_izin.py`)

### Kurulum
```bash
pip install -r requirements.txt
```

### Kullanım
```bash
# İnteraktif giriş (TC, şifre, SMS kodu ve evci adresi sorulur):
python3 gsb_izin.py --baslangic 2026-11-21 --bitis 2026-11-22

# Talep göndermeden test (dry-run):
python3 gsb_izin.py --baslangic 2026-11-21 --bitis 2026-11-22 --dry-run
```

---

## Teknik Akış Özeti
1. `https://giris.gsb.gov.tr/?appid=F9611508-EE31-4A1F-8C79-C289C0C47218` üzerinden e-Devlet OAuth2 oturumu başlatılır.
2. `CryptoServlet` ile RSA + AES anahtar değişimi yapılıp `encTridField` ve `encEgpField` şifrelenir.
3. Gerekirse CAPTCHA görseli ve/veya SMS OTP kodu kullanıcıdan alınır; ara onay (`SaveScope`) geçilir.
4. `biz.gsb.gov.tr/edevlet?token=...` üzerinden alınan token `POST https://gsbbizapi.gsb.gov.tr/Account/VerifyToken` ile `Bearer` JWT'ye çevrilir.
5. `GET /KYK/OgrenciDetay` ile evci adresleri ve `GET /KYK/IzinGunSayisi` ile izin durumu çekilir; `POST /KYK/IzinTalepKaydet` ile talep oluşturulur.
