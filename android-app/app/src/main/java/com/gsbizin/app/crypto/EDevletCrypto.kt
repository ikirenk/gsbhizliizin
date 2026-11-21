package com.gsbizin.app.crypto

import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object EDevletCrypto {

    private val secureRandom = SecureRandom()

    private fun evpBytesToKey(
        passphrase: ByteArray,
        salt: ByteArray,
        keyLen: Int = 32,
        ivLen: Int = 16
    ): Pair<ByteArray, ByteArray> {
        val md5 = MessageDigest.getInstance("MD5")
        val total = ByteArray(keyLen + ivLen)
        var offset = 0
        var prev = ByteArray(0)
        while (offset < total.size) {
            md5.reset()
            md5.update(prev)
            md5.update(passphrase)
            md5.update(salt)
            prev = md5.digest()
            val copyLen = minOf(prev.size, total.size - offset)
            System.arraycopy(prev, 0, total, offset, copyLen)
            offset += copyLen
        }
        return total.copyOfRange(0, keyLen) to total.copyOfRange(keyLen, keyLen + ivLen)
    }

    fun cryptoJsAesEncrypt(plaintext: String, passphrase: String): String {
        val salt = ByteArray(8).also { secureRandom.nextBytes(it) }
        val (key, iv) = evpBytesToKey(passphrase.toByteArray(StandardCharsets.UTF_8), salt)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        val encrypted = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))

        val prefix = "Salted__".toByteArray(StandardCharsets.US_ASCII)
        val result = ByteArray(prefix.size + salt.size + encrypted.size)
        System.arraycopy(prefix, 0, result, 0, prefix.size)
        System.arraycopy(salt, 0, result, prefix.size, salt.size)
        System.arraycopy(encrypted, 0, result, prefix.size + salt.size, encrypted.size)
        return Base64.encodeToString(result, Base64.NO_WRAP)
    }

    fun cryptoJsAesDecrypt(b64Ciphertext: String, passphrase: String): ByteArray {
        val raw = Base64.decode(b64Ciphertext, Base64.DEFAULT)
        val prefix = "Salted__".toByteArray(StandardCharsets.US_ASCII)
        require(raw.size > 16 && raw.copyOfRange(0, 8).contentEquals(prefix)) {
            "Geçersiz CryptoJS ciphertext"
        }
        val salt = raw.copyOfRange(8, 16)
        val ct = raw.copyOfRange(16, raw.size)
        val (key, iv) = evpBytesToKey(passphrase.toByteArray(StandardCharsets.UTF_8), salt)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(ct)
    }

    fun rsaEncryptB64(plaintext: String, publicKeyStr: String): String {
        val cleaned = publicKeyStr
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s+".toRegex(), "")
        val keyBytes = Base64.decode(cleaned, Base64.DEFAULT)
        val pubKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes))
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, pubKey)
        val encrypted = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    fun randomHexKey(bytes: Int = 16): String {
        val buf = ByteArray(bytes).also { secureRandom.nextBytes(it) }
        return buf.joinToString("") { "%02x".format(it) }
    }
}
