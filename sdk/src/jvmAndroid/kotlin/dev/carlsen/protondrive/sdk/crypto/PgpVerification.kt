package dev.carlsen.protondrive.sdk.crypto

import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import java.io.ByteArrayInputStream

actual fun verifyClearsignedMessage(armoredMessage: String, armoredPublicKey: String): ByteArray {
    try {
        val certRing = requireNotNull(PGPainless.readKeyRing().publicKeyRing(armoredPublicKey)) {
            "Failed to parse the embedded public key"
        }
        val options = ConsumerOptions.get().addVerificationCert(certRing)
        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(ByteArrayInputStream(armoredMessage.toByteArray(Charsets.UTF_8)))
            .withOptions(options)

        val cleartext = stream.use { it.readBytes() }
        if (!stream.metadata.isVerifiedSigned()) {
            throw PgpVerificationException("Signature verification failed")
        }
        return cleartext
    } catch (e: PgpVerificationException) {
        throw e
    } catch (e: Exception) {
        // Malformed armor/base64/signature all surface as opaque BouncyCastle
        // exceptions; normalize them to one type callers can rely on.
        throw PgpVerificationException("Signature verification failed: ${e.message}", e)
    }
}
