package dev.carlsen.protondrive.sdk.crypto

/** Cryptographically secure random byte source. */
expect class SecureRandom() {
    fun nextBytes(bytes: ByteArray)
}
