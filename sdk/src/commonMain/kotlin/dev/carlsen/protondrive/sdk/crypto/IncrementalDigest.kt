package dev.carlsen.protondrive.sdk.crypto

enum class DigestAlgorithm { SHA1, SHA256, SHA512 }

/** Streaming hash, for hashing data too large to hold in memory in one [ByteArray]. */
expect class IncrementalDigest(algorithm: DigestAlgorithm) {
    fun update(data: ByteArray)
    fun digest(): ByteArray
}
