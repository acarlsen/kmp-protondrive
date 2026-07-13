package dev.carlsen.protondrive.sdk.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.pgpainless.PGPainless

/**
 * Single shared provider instance for every JCE-backed BouncyCastle operation in this source
 * set. Constructing a BouncyCastleProvider registers hundreds of algorithm entries - cheap
 * enough once, but a real cost when done per crypto call, especially on Android/ART.
 */
internal val sharedBouncyCastleProvider = BouncyCastleProvider()

actual class PrivateKeyHandle(val secretKeys: PGPSecretKeyRing, val passphrase: String) {
    /**
     * [secretKeys] with the passphrase protection stripped, unlocked at most once per handle.
     * OpenPGP keys pay an S2K key derivation (for Proton keys, generated with OpenPGP.js's
     * defaults: ~16 MB of SHA-256 hashing) every time a secret key is unlocked - per *operation*,
     * not per key, if the locked ring is handed to PGPainless each call. Listing a folder touches
     * each key several times per node, so on Android/ART (no JIT intrinsics to hide it) that
     * repeated derivation dominated everything else. All crypto operations use this ring with an
     * unprotected-keys protector instead; holding it in memory reveals nothing the handle didn't
     * already hold, since [passphrase] sits right next to it.
     */
    private val unlockedKeys: PGPSecretKeyRing by lazy {
        PGPSecretKeyRing.copyWithNewPassword(
            secretKeys,
            JcePBESecretKeyDecryptorBuilder().setProvider(sharedBouncyCastleProvider).build(passphrase.toCharArray()),
            null,
        )
    }

    /**
     * A fresh, private parse of [unlockedKeys] for exactly one crypto operation. BC's
     * PGPSignature verification mutates the signature objects *stored inside the ring* in
     * place, so a ring instance shared between concurrent operations (DriveClient decrypts
     * sibling nodes in parallel, all against the same parent key) gets its verification state
     * corrupted - observed as every binding signature "disappearing" mid-listing. Re-parsing
     * costs only packet decoding, not key derivation: the ring is already unlocked, which is
     * what makes this cheap enough to do per operation.
     */
    fun freshUnlockedKeys(): PGPSecretKeyRing = PGPSecretKeyRing(unlockedKeys.encoded, fingerprintCalculator)
}

actual class PublicKeyHandle(val publicKeys: PGPPublicKeyRing) {
    /** A fresh, private parse for one operation - same BC thread-safety trap as [PrivateKeyHandle.freshUnlockedKeys]. */
    fun freshPublicKeys(): PGPPublicKeyRing = PGPPublicKeyRing(publicKeys.encoded, fingerprintCalculator)
}

private val fingerprintCalculator = BcKeyFingerprintCalculator()

actual class SessionKeyHandle(val sessionKey: org.pgpainless.util.SessionKey) {
    actual val rawBytes: ByteArray get() = sessionKey.key
}

actual fun PrivateKeyHandle.toPublicKeyHandle(): PublicKeyHandle =
    PublicKeyHandle(PGPainless.extractCertificate(secretKeys))
