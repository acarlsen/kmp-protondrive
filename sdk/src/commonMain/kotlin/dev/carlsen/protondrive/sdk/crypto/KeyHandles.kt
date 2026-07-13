package dev.carlsen.protondrive.sdk.crypto

/** Opaque handle to a decrypted private key. Platform-specific representation lives in the actual declaration. */
expect class PrivateKeyHandle

/** Opaque handle to a public key/certificate. Platform-specific representation lives in the actual declaration. */
expect class PublicKeyHandle

/** Opaque handle to a symmetric session key. */
expect class SessionKeyHandle {
    /** Raw session key bytes - needed to verify Drive's ContentKeyPacketSignature, which signs the plain session key rather than the encrypted packet. */
    val rawBytes: ByteArray
}

expect fun PrivateKeyHandle.toPublicKeyHandle(): PublicKeyHandle
