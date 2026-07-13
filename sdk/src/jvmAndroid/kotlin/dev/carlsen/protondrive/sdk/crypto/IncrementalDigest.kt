package dev.carlsen.protondrive.sdk.crypto

import java.security.MessageDigest

actual class IncrementalDigest actual constructor(algorithm: DigestAlgorithm) {
    private val delegate = MessageDigest.getInstance(
        when (algorithm) {
            DigestAlgorithm.SHA1 -> "SHA-1"
            DigestAlgorithm.SHA256 -> "SHA-256"
            DigestAlgorithm.SHA512 -> "SHA-512"
        },
    )

    actual fun update(data: ByteArray) {
        delegate.update(data)
    }

    actual fun digest(): ByteArray = delegate.digest()
}
