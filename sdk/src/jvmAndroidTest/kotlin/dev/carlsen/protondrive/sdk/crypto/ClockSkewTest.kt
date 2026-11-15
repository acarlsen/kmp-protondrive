package dev.carlsen.protondrive.sdk.crypto

import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import kotlin.math.abs
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * A device clock skewed from Proton's must not leak into key/signature dates or validity
 * checks once [ServerClock] has been synced (proton-sdk commit 8a44654 fixed the same problem
 * in the JS CLI). "Server" here is the real system clock; the device clock is skewed by an hour.
 */
class ClockSkewTest {

    private val server: OpenPGPCrypto = PGPainlessOpenPGPCrypto()
    private val data = "hello drive".encodeToByteArray()

    private fun skewedDeviceClock(skew: Duration) = object : Clock {
        override fun now(): Instant = Clock.System.now() + skew
    }

    /** A crypto engine on a device whose clock is off by [skew]; synced to the server clock unless [synced] is false. */
    private fun device(skew: Duration, synced: Boolean = true): OpenPGPCrypto {
        val clock = ServerClock(skewedDeviceClock(skew))
        if (synced) clock.update(Clock.System.now())
        return PGPainlessOpenPGPCrypto(clock)
    }

    private fun assertNearServerTime(date: java.util.Date, what: String) {
        val driftMs = abs(date.time - System.currentTimeMillis())
        assertTrue(driftMs < 60_000, "$what is ${driftMs}ms off server time")
    }

    @Test
    fun `device clock ahead - generated keys and their self-signatures are dated by server time`() {
        val key = device(skew = 1.hours).generateKey("pass").privateKey.secretKeys
        key.publicKeys.forEach { publicKey ->
            assertNearServerTime(publicKey.creationTime, "key creation time")
            publicKey.signatures.forEach { sig -> assertNearServerTime((sig as PGPSignature).creationTime, "self-signature") }
        }
    }

    @Test
    fun `device clock ahead - signatures are dated by server time`() {
        val crypto = device(skew = 1.hours)
        val key = crypto.generateKey("pass").privateKey
        val signature = BcPGPObjectFactory(crypto.signDetached(data, key)).nextObject()
        val created = (signature as org.bouncycastle.openpgp.PGPSignatureList)[0].creationTime
        assertNearServerTime(created, "signature creation time")
    }

    @Test
    fun `device clock ahead - other clients can verify what it signed`() {
        val crypto = device(skew = 1.hours)
        val key = crypto.generateKey("pass").privateKey
        val signature = crypto.signDetached(data, key)
        assertEquals(VerifyStatus.OK, server.verifyDetached(data, signature, listOf(key.toPublicKeyHandle())).verified)
    }

    @Test
    fun `device clock behind - verifies fresh signatures from other clients`() {
        val signer = server.generateKey("pass").privateKey
        val signature = server.signDetached(data, signer)
        val result = device(skew = -1.hours).verifyDetached(data, signature, listOf(signer.toPublicKeyHandle()))
        assertEquals(VerifyStatus.OK, result.verified)
    }

    @Test
    fun `device clock behind and unsynced - fresh signatures from other clients fail (the bug)`() {
        val signer = server.generateKey("pass").privateKey
        val signature = server.signDetached(data, signer)
        val result = device(skew = -1.hours, synced = false).verifyDetached(data, signature, listOf(signer.toPublicKeyHandle()))
        assertEquals(VerifyStatus.FAILED, result.verified)
    }

    @Test
    fun `device clock behind - encrypts to and signs with keys created at server time`() {
        val crypto = device(skew = -1.hours)
        val recipient = server.generateKey("pass").privateKey
        val ownKey = crypto.generateKey("pass").privateKey

        val armored = crypto.encryptAndSignArmored(data, listOf(recipient.toPublicKeyHandle()), ownKey)
        val decrypted = server.decryptArmoredAndVerify(armored, listOf(recipient), listOf(ownKey.toPublicKeyHandle()))

        assertContentEquals(data, decrypted.data)
        assertEquals(VerifyStatus.OK, decrypted.verified)
    }
}
