package com.gsbizin.app.network

import com.gsbizin.app.crypto.EDevletCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import java.util.concurrent.TimeUnit

data class EvciAddress(
    val id: String,
    val adres: String
)

data class StudentSession(
    val jwtToken: String,
    val fullName: String,
    val evciAddresses: List<EvciAddress>,
    val defaultPhone: String,
    val leaveSummary: String
)

data class PendingOtpState(
    val currentUrl: String,
    val actionUrl: String,
    val formData: Map<String, String>,
    val otpFieldName: String
)

data class PendingCaptchaState(
    val currentUrl: String,
    val actionUrl: String,
    val formData: Map<String, String>,
    val imageBytes: ByteArray,
    val needsReEncrypt: Boolean,
    val genUrl: String?,
    val hsUrl: String?,
    val cryptoKeyId: String?
)

sealed interface LoginStepResult {
    data class NeedSmsOtp(val state: PendingOtpState) : LoginStepResult
    data class NeedCaptcha(val state: PendingCaptchaState) : LoginStepResult
    data class Success(val session: StudentSession) : LoginStepResult
}

data class LeaveResult(
    val success: Boolean,
    val message: String
)

private class InMemoryCookieJar : CookieJar {
    private val store = mutableListOf<Cookie>()

    @Synchronized
    fun clear() {
        store.clear()
    }

    @Synchronized
    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        for (c in cookies) {
            store.removeAll { it.name == c.name && it.domain == c.domain && it.path == c.path }
            if (c.expiresAt > System.currentTimeMillis()) {
                store.add(c)
            }
        }
    }

    @Synchronized
    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val now = System.currentTimeMillis()
        store.removeAll { it.expiresAt <= now }
        return store.filter { it.matches(url) }
    }
}

class GsbAuthAndApi {

    companion object {
        private const val GSB_LOGIN_URL =
            "https://giris.gsb.gov.tr/?appid=F9611508-EE31-4A1F-8C79-C289C0C47218"
        private const val GSB_API_BASE = "https://gsbbizapi.gsb.gov.tr"
        private const val USER_AGENT =
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
    }

    private val cookieJar = InMemoryCookieJar()
    private val client = OkHttpClient.Builder()
        .cookieJar(cookieJar)
        .followRedirects(true)
        .followSslRedirects(true)
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private fun baseRequest(url: String): Request.Builder =
        Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .header("Accept-Language", "tr-TR,tr;q=0.9,en-US;q=0.8")

    private fun executeGet(url: String, xhr: Boolean = false): Pair<String, String> {
        val req = baseRequest(url).apply {
            if (xhr) header("X-Requested-With", "XMLHttpRequest")
        }.build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw RuntimeException("HTTP ${resp.code}: $url")
            return resp.request.url.toString() to (resp.body?.string() ?: "")
        }
    }

    private fun executePostForm(url: String, data: Map<String, String>, xhr: Boolean = false): Pair<String, String> {
        val body = FormBody.Builder().apply {
            data.forEach { (k, v) -> add(k, v) }
        }.build()
        val req = baseRequest(url)
            .post(body)
            .apply { if (xhr) header("X-Requested-With", "XMLHttpRequest") }
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw RuntimeException("HTTP ${resp.code}: $url")
            return resp.request.url.toString() to (resp.body?.string() ?: "")
        }
    }

    suspend fun startLogin(tc: String, password: String): LoginStepResult = withContext(Dispatchers.IO) {
        cookieJar.clear()
        val (loginUrl, loginHtml) = executeGet(GSB_LOGIN_URL)
        extractTokenFromUrl(loginUrl)?.let { token ->
            return@withContext LoginStepResult.Success(verifyAndFetchStudentData(token))
        }

        val doc = Jsoup.parse(loginHtml, loginUrl)
        val loginForm = doc.selectFirst("form#loginForm, form[name=sifreGirisForm]")
            ?: throw RuntimeException("e-Devlet giriş formu bulunamadı.")

        if (doc.selectFirst("input[name=captchaField]") != null) {
            return@withContext buildCaptchaResult(doc, loginHtml, loginUrl, loginForm)
        }

        val (genUrl, hsUrl, cryptoKeyId) = extractJCryptionParams(loginHtml, loginUrl)
        val (aesPassphrase, _) = performJCryptionHandshake(genUrl, hsUrl)

        val formData = extractFormData(loginForm).toMutableMap()
        formData["tridField"] = ""
        formData["egpField"] = ""
        formData["encTridField"] = EDevletCrypto.cryptoJsAesEncrypt(tc, aesPassphrase)
        formData["encEgpField"] = EDevletCrypto.cryptoJsAesEncrypt(password, aesPassphrase)
        if (cryptoKeyId != null) formData["cryptoKeyId"] = cryptoKeyId
        formData.putIfAbsent("actionName", "giris")
        formData["submitButton"] = "Giriş Yap"

        val postUrl = resolveActionUrl(loginForm, loginUrl)
        val (nextUrl, nextHtml) = executePostForm(postUrl, formData)
        processIntermediateSteps(nextUrl, nextHtml)
    }

    suspend fun submitCaptcha(
        state: PendingCaptchaState,
        captchaCode: String,
        tc: String,
        password: String
    ): LoginStepResult = withContext(Dispatchers.IO) {
        val data = state.formData.toMutableMap()
        if (state.needsReEncrypt && state.genUrl != null && state.hsUrl != null) {
            val (aesPassphrase, _) = performJCryptionHandshake(state.genUrl, state.hsUrl)
            data["tridField"] = ""
            data["egpField"] = ""
            data["encTridField"] = EDevletCrypto.cryptoJsAesEncrypt(tc, aesPassphrase)
            data["encEgpField"] = EDevletCrypto.cryptoJsAesEncrypt(password, aesPassphrase)
            if (state.cryptoKeyId != null) data["cryptoKeyId"] = state.cryptoKeyId
            data.putIfAbsent("actionName", "giris")
            data["submitButton"] = "Giriş Yap"
        }
        data["captchaField"] = captchaCode.trim()
        val (nextUrl, nextHtml) = executePostForm(state.actionUrl, data)
        processIntermediateSteps(nextUrl, nextHtml)
    }

    private fun performJCryptionHandshake(genUrl: String, hsUrl: String): Pair<String, String> {
        val (_, kpJson) = executeGet(genUrl, xhr = true)
        val publicKey = JSONObject(kpJson).getString("publickey")

        val aesPassphrase = EDevletCrypto.randomHexKey(16)
        val encryptedAesKey = EDevletCrypto.rsaEncryptB64(aesPassphrase, publicKey)

        val (_, hsJson) = executePostForm(hsUrl, mapOf("key" to encryptedAesKey), xhr = true)
        val challenge = JSONObject(hsJson).optString("challenge", "")
        if (challenge.isNotEmpty()) {
            EDevletCrypto.cryptoJsAesDecrypt(challenge, aesPassphrase)
        }
        return aesPassphrase to publicKey
    }

    private fun buildCaptchaResult(
        doc: Document,
        html: String,
        currentUrl: String,
        form: Element
    ): LoginStepResult.NeedCaptcha {
        val captchaImg = doc.select("img").firstOrNull { img ->
            val meta = "${img.attr("src")} ${img.attr("id")} ${img.attr("class")} ${img.attr("alt")}"
            Regex("captcha", RegexOption.IGNORE_CASE).containsMatchIn(meta)
        } ?: throw RuntimeException("CAPTCHA görseli sayfada bulunamadı.")

        val src = captchaImg.attr("src")
        val imageBytes = if (src.startsWith("data:", ignoreCase = true) && src.contains("base64,")) {
            android.util.Base64.decode(src.substringAfter("base64,"), android.util.Base64.DEFAULT)
        } else {
            val imgUrl = currentUrl.toHttpUrl().resolve(src)?.toString()
                ?: throw RuntimeException("CAPTCHA görsel URL'si çözümlenemedi: $src")
            val req = baseRequest(imgUrl).build()
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) throw RuntimeException("CAPTCHA görseli indirilemedi: HTTP ${resp.code}")
                resp.body?.bytes() ?: throw RuntimeException("CAPTCHA görseli boş döndü.")
            }
        }

        val needsReEncrypt = form.selectFirst("input[name=encTridField]") != null
        val (genUrl, hsUrl, keyId) = if (needsReEncrypt) {
            extractJCryptionParams(html, currentUrl)
        } else {
            Triple(null, null, null)
        }

        return LoginStepResult.NeedCaptcha(
            PendingCaptchaState(
                currentUrl = currentUrl,
                actionUrl = resolveActionUrl(form, currentUrl),
                formData = extractFormData(form),
                imageBytes = imageBytes,
                needsReEncrypt = needsReEncrypt,
                genUrl = genUrl,
                hsUrl = hsUrl,
                cryptoKeyId = keyId
            )
        )
    }

    suspend fun submitSmsOtp(state: PendingOtpState, smsCode: String): LoginStepResult = withContext(Dispatchers.IO) {
        val data = state.formData.toMutableMap()
        data[state.otpFieldName] = smsCode.trim()
        val (nextUrl, nextHtml) = executePostForm(state.actionUrl, data)
        processIntermediateSteps(nextUrl, nextHtml)
    }

    private fun processIntermediateSteps(startUrl: String, startHtml: String): LoginStepResult {
        var currentUrl = startUrl
        var currentHtml = startHtml

        for (step in 0 until 10) {
            extractTokenFromUrl(currentUrl)?.let { token ->
                return LoginStepResult.Success(verifyAndFetchStudentData(token))
            }

            val doc = Jsoup.parse(currentHtml, currentUrl)

            // OAuth2 SaveScope link
            val saveScopeLink = doc.selectFirst("a[href*=SaveScope]")
            if (saveScopeLink != null) {
                val target = saveScopeLink.absUrl("href").ifEmpty {
                    currentUrl.toHttpUrl().resolve(saveScopeLink.attr("href")).toString()
                }
                val (u, h) = executeGet(target)
                currentUrl = u
                currentHtml = h
                continue
            }

            // OAuth2 SaveScope form
            val scopeForm = doc.selectFirst("form[action*=SaveScope]")
            if (scopeForm != null) {
                val sData = extractFormData(scopeForm).toMutableMap()
                sData["btn"] = "Onayla"
                val base = resolveActionUrl(scopeForm, currentUrl).toHttpUrl().newBuilder().apply {
                    sData.forEach { (k, v) -> addQueryParameter(k, v) }
                }.build().toString()
                val (u, h) = executeGet(base)
                currentUrl = u
                currentHtml = h
                continue
            }

            val forms = doc.select("form")
            val captchaInput = doc.selectFirst("input[name=captchaField]")
            if (captchaInput != null) {
                val captchaForm = captchaInput.closest("form") ?: forms.firstOrNull()
                if (captchaForm != null) {
                    return buildCaptchaResult(doc, currentHtml, currentUrl, captchaForm)
                }
            }

            val err = extractErrorMessage(doc)
            if (err != null && listOf("hatalı", "yanlış", "doğrulama", "hata", "bloke", "güvenlik").any {
                    err.lowercase().contains(it)
                }) {
                throw RuntimeException(err)
            }

            if (forms.isEmpty()) break

            var handled = false
            for (form in forms) {
                val fData = extractFormData(form).toMutableMap()
                val otpInput = form.select("input").firstOrNull { inp ->
                    val name = inp.attr("name")
                    val type = inp.attr("type").lowercase().ifEmpty { "text" }
                    type !in listOf("hidden", "submit", "button", "checkbox", "radio") &&
                        name.isNotEmpty() &&
                        name != "currentPageToken" &&
                        Regex("(sms|otp|kod|code|dogrulama|pin|token)", RegexOption.IGNORE_CASE).containsMatchIn(name)
                }
                if (otpInput != null) {
                    val otpName = otpInput.attr("name")
                    val submitBtn = form.selectFirst("button[type=submit], input[type=submit]")
                    if (submitBtn != null && submitBtn.hasAttr("name")) {
                        fData[submitBtn.attr("name")] = submitBtn.attr("value").ifEmpty { "Devam Et" }
                    }
                    return LoginStepResult.NeedSmsOtp(
                        PendingOtpState(
                            currentUrl = currentUrl,
                            actionUrl = resolveActionUrl(form, currentUrl),
                            formData = fData,
                            otpFieldName = otpName
                        )
                    )
                }

                // Ara SMS gönder / devam et butonu
                val sendBtn = form.select("button").firstOrNull {
                    Regex("(SMS|Kod|Gönder|Devam|Onayla)", RegexOption.IGNORE_CASE).containsMatchIn(it.text())
                } ?: form.selectFirst("input[type=submit]")?.takeIf {
                    Regex("(SMS|Kod|Gönder|Devam|Onayla)", RegexOption.IGNORE_CASE).containsMatchIn(it.attr("value"))
                }
                if (sendBtn != null) {
                    if (sendBtn.hasAttr("name")) {
                        fData[sendBtn.attr("name")] = sendBtn.attr("value").ifEmpty { sendBtn.text() }
                    }
                    val (u, h) = executePostForm(resolveActionUrl(form, currentUrl), fData)
                    currentUrl = u
                    currentHtml = h
                    handled = true
                    break
                }

                // Sadece hidden input'lardan oluşan otomatik ara form
                val visibleInputs = form.select("input").filter {
                    it.attr("type").lowercase().ifEmpty { "text" } != "hidden"
                }
                if (visibleInputs.isEmpty() && fData.containsKey("currentPageToken") && fData.containsKey("actionName")) {
                    if (currentHtml.contains("ajaxOtpBaslangicKontrol")) {
                        val ajaxUrl = currentUrl.toHttpUrl().resolve("/Giris/sifreGiris?actionName=ajaxOtpBaslangicKontrol").toString()
                        repeat(5) {
                            val (_, ajaxBody) = runCatching { executeGet(ajaxUrl, xhr = true) }.getOrDefault("" to "")
                            if (ajaxBody.contains("true", ignoreCase = true) ||
                                ajaxBody.contains("tamam", ignoreCase = true) ||
                                ajaxBody.contains("ok", ignoreCase = true)
                            ) {
                                return@repeat
                            }
                            Thread.sleep(1000)
                        }
                    }
                    val (u, h) = executePostForm(resolveActionUrl(form, currentUrl), fData)
                    currentUrl = u
                    currentHtml = h
                    handled = true
                    break
                }
            }
            if (!handled) break
        }

        extractTokenFromUrl(currentUrl)?.let { token ->
            return LoginStepResult.Success(verifyAndFetchStudentData(token))
        }
        val finalDoc = Jsoup.parse(currentHtml, currentUrl)
        throw RuntimeException("e-Devlet girişi tamamlanamadı: ${summarizePage(finalDoc)} | URL: $currentUrl")
    }

    private fun verifyAndFetchStudentData(edevletToken: String): StudentSession {
        val jsonMedia = "application/json; charset=utf-8".toMediaType()
        val verifyReq = baseRequest("$GSB_API_BASE/Account/VerifyToken")
            .header("Accept", "application/json")
            .header("Origin", "https://biz.gsb.gov.tr")
            .header("Referer", "https://biz.gsb.gov.tr/")
            .post(JSONObject().put("token", edevletToken).toString().toRequestBody(jsonMedia))
            .build()

        val verifyJson = client.newCall(verifyReq).execute().use { resp ->
            if (!resp.isSuccessful) throw RuntimeException("VerifyToken hatası: HTTP ${resp.code}")
            JSONObject(resp.body?.string() ?: "{}")
        }
        val jwt = verifyJson.optString("token").ifEmpty {
            verifyJson.optJSONObject("data")?.optString("token") ?: ""
        }
        if (jwt.isEmpty()) throw RuntimeException("GSB JWT token alınamadı.")
        val fullName = verifyJson.optString("fullName", "Öğrenci")

        val detayReq = baseRequest("$GSB_API_BASE/KYK/OgrenciDetay")
            .header("Accept", "application/json")
            .header("Authorization", "Bearer $jwt")
            .header("Origin", "https://biz.gsb.gov.tr")
            .header("Referer", "https://biz.gsb.gov.tr/")
            .build()
        val detayJson = client.newCall(detayReq).execute().use { resp ->
            if (!resp.isSuccessful) throw RuntimeException("OgrenciDetay hatası: HTTP ${resp.code}")
            JSONObject(resp.body?.string() ?: "{}")
        }

        val evciList = parseEvciAddresses(detayJson)
        val phone = Regex("\"(?:telefon|irtibattel|cepTel|gsm)\"\\s*:\\s*\"(0?5\\d{9})\"", RegexOption.IGNORE_CASE)
            .find(detayJson.toString())?.groupValues?.getOrNull(1) ?: ""

        val gunReq = baseRequest("$GSB_API_BASE/KYK/IzinGunSayisi")
            .header("Accept", "application/json")
            .header("Authorization", "Bearer $jwt")
            .header("Origin", "https://biz.gsb.gov.tr")
            .header("Referer", "https://biz.gsb.gov.tr/")
            .build()
        val gunSummary = runCatching {
            client.newCall(gunReq).execute().use { resp ->
                if (!resp.isSuccessful) "" else formatLeaveSummary(JSONObject(resp.body?.string() ?: "{}"))
            }
        }.getOrDefault("")

        return StudentSession(
            jwtToken = jwt,
            fullName = fullName,
            evciAddresses = evciList,
            defaultPhone = phone,
            leaveSummary = gunSummary
        )
    }

    suspend fun submitLeaveRequest(
        jwtToken: String,
        baslangicIso: String,
        bitisIso: String,
        telefon: String,
        evciId: String,
        aciklama: String
    ): LeaveResult = withContext(Dispatchers.IO) {
        val jsonMedia = "application/json; charset=utf-8".toMediaType()
        val payload = JSONObject().apply {
            put("baslangic", baslangicIso)
            put("bitis", bitisIso)
            put("aciklama", aciklama)
            put("telefon", telefon)
            put("evciId", evciId)
        }
        val req = baseRequest("$GSB_API_BASE/KYK/IzinTalepKaydet")
            .header("Accept", "application/json")
            .header("Authorization", "Bearer $jwtToken")
            .header("Origin", "https://biz.gsb.gov.tr")
            .header("Referer", "https://biz.gsb.gov.tr/")
            .post(payload.toString().toRequestBody(jsonMedia))
            .build()

        client.newCall(req).execute().use { resp ->
            val bodyStr = resp.body?.string() ?: "{}"
            if (!resp.isSuccessful) {
                return@withContext LeaveResult(false, "HTTP ${resp.code}: $bodyStr")
            }
            val json = JSONObject(bodyStr)
            val data = json.optJSONObject("data") ?: json
            val ok = data.optBoolean("success", json.optInt("resultType", -1) == 0)
            val msg = data.optString("message").ifEmpty { json.optString("resultMessage", bodyStr) }
            LeaveResult(ok, msg)
        }
    }

    private fun parseEvciAddresses(root: JSONObject): List<EvciAddress> {
        var obj: JSONObject? = root.optJSONObject("data") ?: root
        if (obj?.has("data") == true && obj.optJSONObject("data") != null) {
            obj = obj.optJSONObject("data")
        }
        val arr = obj?.optJSONArray("ogrencI_IZINLER_EVCI") ?: return emptyList()
        val list = mutableListOf<EvciAddress>()
        for (i in 0 until arr.length()) {
            val item = arr.optJSONObject(i) ?: continue
            val id = item.optString("id")
            val adres = item.optString("adres").ifEmpty { id }
            if (id.isNotEmpty()) list.add(EvciAddress(id, adres))
        }
        return list
    }

    private fun formatLeaveSummary(json: JSONObject): String {
        val d = json.optJSONObject("data") ?: json
        val keys = d.keys().asSequence().toList()
        if (keys.isEmpty()) return ""
        return keys.joinToString(" • ") { k -> "$k: ${d.opt(k)}" }
    }

    private fun extractTokenFromUrl(url: String): String? {
        if (!url.contains("biz.gsb.gov.tr/edevlet")) return null
        return url.toHttpUrl().queryParameter("token")?.takeIf { it.isNotEmpty() }
    }

    private fun extractJCryptionParams(html: String, pageUrl: String): Triple<String, String, String?> {
        val keyId = Regex("""var\s+cryptoKeyId\s*=\s*["']([^"']+)["']""").find(html)?.groupValues?.getOrNull(1)
        val authMatch = Regex("""\$\.jCryption\.authenticate\([^,]+,\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']""")
            .find(html)
        val base = pageUrl.toHttpUrl()
        if (authMatch != null) {
            val genUrl = base.resolve(authMatch.groupValues[1]).toString()
            var hsRaw = authMatch.groupValues[2]
            if (keyId != null && hsRaw.endsWith("cryptoKeyId=")) hsRaw += keyId
            val hsUrl = base.resolve(hsRaw).toString()
            return Triple(genUrl, hsUrl, keyId)
        }
        val genUrl = base.resolve("CryptoServlet?generateKeyPair=true").toString()
        val hsPath = if (keyId != null) "CryptoServlet?handshake=true&cryptoKeyId=$keyId" else "CryptoServlet?handshake=true"
        return Triple(genUrl, base.resolve(hsPath).toString(), keyId)
    }

    private fun extractFormData(form: Element): Map<String, String> {
        val map = linkedMapOf<String, String>()
        for (inp in form.select("input")) {
            val name = inp.attr("name")
            if (name.isEmpty()) continue
            val type = inp.attr("type").lowercase().ifEmpty { "text" }
            if (type in listOf("checkbox", "radio") && !inp.hasAttr("checked")) continue
            map[name] = inp.attr("value")
        }
        return map
    }

    private fun resolveActionUrl(form: Element, currentUrl: String): String {
        val action = form.attr("action")
        if (action.isEmpty()) return currentUrl
        return currentUrl.toHttpUrl().resolve(action)?.toString() ?: currentUrl
    }

    private fun extractErrorMessage(doc: Document): String? {
        for (sel in listOf(
            "[role=alert]",
            ".errorContainer",
            ".warningContainer",
            ".messageContainer",
            ".form-error .form-note",
            "#errorText",
            ".alert-danger",
            ".alert-warning",
            ".error",
            ".warning"
        )) {
            val el = doc.selectFirst(sel) ?: continue
            val txt = el.text().trim()
            if (txt.isNotEmpty()) return txt
        }
        return null
    }

    private fun summarizePage(doc: Document): String {
        val title = doc.title()
        val err = extractErrorMessage(doc)
        val formsInfo = doc.select("form").mapIndexed { idx, f ->
            val fields = f.select("input, button").map { el ->
                val n = el.attr("name").ifEmpty { el.attr("id") }
                val t = el.attr("type").ifEmpty { el.tagName() }
                "$n[$t]"
            }
            "form#$idx(action=${f.attr("action")}, fields=$fields)"
        }
        val bodyHint = if (err == null) {
            doc.select("main, section, .content").text().take(200)
        } else ""
        return "title='$title', err=$err, hint='$bodyHint', forms=$formsInfo"
    }
}
