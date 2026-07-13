package dev.carlsen.protondrive.sdk.crypto

actual class SecureRandom actual constructor() {
    private val delegate = java.security.SecureRandom()

    actual fun nextBytes(bytes: ByteArray) {
        delegate.nextBytes(bytes)
    }
}
