package dev.carlsen.protondrive.sdk.crypto

/** The platform's default [OpenPGPCrypto] engine - used by [dev.carlsen.protondrive.sdk.ProtonDriveSdk] unless a host supplies its own. */
expect fun defaultOpenPGPCrypto(): OpenPGPCrypto

/**
 * Subset of Proton Drive's OpenPGPCrypto contract (see client/js/src/crypto/interface.ts
 * in proton-sdk) needed to validate that PGPainless/BouncyCastle can perform Drive's
 * crypto operations without Proton's native/WASM engine.
 */
interface OpenPGPCrypto {
    fun generatePassphrase(): String

    fun generateKey(passphrase: String): GeneratedKey

    fun decryptKey(armoredKey: String, passphrase: String): PrivateKeyHandle

    fun encryptAndSign(
        data: ByteArray,
        encryptionKeys: List<PublicKeyHandle>,
        signingKey: PrivateKeyHandle,
    ): ByteArray

    fun decryptAndVerify(
        data: ByteArray,
        decryptionKey: PrivateKeyHandle,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult

    fun signDetached(data: ByteArray, signingKey: PrivateKeyHandle): ByteArray

    fun verifyDetached(
        data: ByteArray,
        signature: ByteArray,
        verificationKeys: List<PublicKeyHandle>,
    ): VerifyResult

    /**
     * Decrypts only the session key from an armored PGP message, without
     * decrypting the message body - used when the same session key will be
     * reused for a later [decryptArmoredAndVerifyDetached] call (Drive's
     * NodePassphrase decryption does this: decrypt the session key once, then
     * use it to decrypt+verify the passphrase against its detached signature).
     */
    fun decryptArmoredSessionKey(armoredData: String, decryptionKeys: List<PrivateKeyHandle>): SessionKeyHandle

    /** Decrypts an armored message using an already-known [sessionKey] (no private key needed) and verifies a detached signature. */
    fun decryptArmoredAndVerifyDetached(
        armoredData: String,
        armoredSignature: String?,
        sessionKey: SessionKeyHandle,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult

    /** Decrypts an armored message directly with a private key and verifies its embedded (inline) signature - used for e.g. node name decryption. */
    fun decryptArmoredAndVerify(
        armoredData: String,
        decryptionKeys: List<PrivateKeyHandle>,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult

    /** Decrypts an armored message directly with a private key and verifies a *detached* signature - used for e.g. address key Token decryption. */
    fun decryptArmoredAndVerifyDetachedWithKey(
        armoredData: String,
        armoredSignature: String,
        decryptionKeys: List<PrivateKeyHandle>,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult

    /** Encrypts+signs (embedded/inline signature) to armored output - used for e.g. node name, hash key, and extended attributes encryption. */
    fun encryptAndSignArmored(
        data: ByteArray,
        encryptionKeys: List<PublicKeyHandle>,
        signingKey: PrivateKeyHandle,
    ): String

    /** Encrypts to armored output and produces a separate armored *detached* signature - used for e.g. node/share passphrase encryption. */
    fun encryptAndSignDetachedArmored(
        data: ByteArray,
        encryptionKeys: List<PublicKeyHandle>,
        signingKey: PrivateKeyHandle,
    ): EncryptedDetachedResult

    /**
     * Decrypts a session key from a binary PKESK-only packet (a "key packet"
     * with no accompanying encrypted data) - used for Drive's per-file
     * ContentKeyPacket. Distinct from [decryptArmoredSessionKey], which
     * expects a full armored *message*.
     */
    fun decryptSessionKey(data: ByteArray, decryptionKeys: List<PrivateKeyHandle>): SessionKeyHandle

    /**
     * Decrypts binary data using an already-known [sessionKey] (no private
     * key needed) - used for Drive's per-block file content, which (unlike
     * node/share passphrases) carries no signature of its own.
     */
    fun decryptWithSessionKey(
        data: ByteArray,
        sessionKey: SessionKeyHandle,
        verificationKeys: List<PublicKeyHandle> = emptyList(),
    ): DecryptResult

    /**
     * Verifies binary [data] against an armored detached signature - used
     * where the data itself isn't armored (a revision's manifest hash
     * buffer, or a content key packet's raw session-key bytes).
     */
    fun verifyArmoredDetached(
        data: ByteArray,
        armoredSignature: String,
        verificationKeys: List<PublicKeyHandle>,
    ): VerifyResult

    /** Produces an armored *detached* signature with no encryption - the sign-only mirror of [verifyArmoredDetached], used for e.g. a new file's ContentKeyPacketSignature (signed with the node's own key, over the plain session key bytes). */
    fun signArmoredDetached(data: ByteArray, signingKey: PrivateKeyHandle): String

    /** Generates a fresh random AES-256 session key - used as a new file's content key, later wrapped into a ContentKeyPacket via [encryptSessionKey] and reused to encrypt every block of the revision via [encryptWithSessionKey]. */
    fun generateSessionKey(): SessionKeyHandle

    /**
     * Encrypts [sessionKey] into a binary PKESK-only packet (no accompanying
     * data) targeting [encryptionKeys] - the encrypt-side mirror of
     * [decryptSessionKey], used to produce a new file's ContentKeyPacket.
     */
    fun encryptSessionKey(sessionKey: SessionKeyHandle, encryptionKeys: List<PublicKeyHandle>): ByteArray

    /**
     * Encrypts binary [data] using an already-known [sessionKey], with no
     * embedded recipient key packet - the encrypt-side mirror of
     * [decryptWithSessionKey], used to encrypt each block of a file's
     * content (every block of a revision shares the one session key wrapped
     * in its ContentKeyPacket, unlike [encryptAndSign] which generates a
     * fresh session key per call).
     */
    fun encryptWithSessionKey(data: ByteArray, sessionKey: SessionKeyHandle): ByteArray
}

data class GeneratedKey(val privateKey: PrivateKeyHandle, val armoredKey: String)

data class EncryptedDetachedResult(val armoredData: String, val armoredSignature: String)

data class DecryptResult(val data: ByteArray, val verified: VerifyStatus)

data class VerifyResult(val verified: VerifyStatus)

enum class VerifyStatus { OK, NOT_SIGNED, FAILED }
