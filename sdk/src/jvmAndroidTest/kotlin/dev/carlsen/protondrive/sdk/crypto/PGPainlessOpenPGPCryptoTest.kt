package dev.carlsen.protondrive.sdk.crypto

import dev.carlsen.protondrive.sdk.errors.DecryptionError
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Phase 1 crypto spike: proves PGPainless (pure JVM, BouncyCastle-backed) can perform
 * the OpenPGP operations Proton Drive relies on, without Proton's native/WASM crypto
 * engine. Mirrors the round-trip shape of client/js/src/crypto/driveCrypto.test.ts and
 * client/js/src/integration-tests/nodesCrypto.test.ts in proton-sdk (parent key encrypts
 * for an address key, node name/passphrase are encrypted+signed, then decrypted+verified).
 */
class PGPainlessOpenPGPCryptoTest {

    private val crypto: OpenPGPCrypto = PGPainlessOpenPGPCrypto()

    @Test
    fun `generated key can be re-decrypted from its armored form`() {
        val passphrase = crypto.generatePassphrase()
        val generated = crypto.generateKey(passphrase)

        assertTrue(generated.armoredKey.contains("BEGIN PGP PRIVATE KEY BLOCK"))

        val reloaded = crypto.decryptKey(generated.armoredKey, passphrase)
        assertEquals(
            generated.privateKey.secretKeys.publicKey.keyID,
            reloaded.secretKeys.publicKey.keyID,
        )
    }

    @Test
    fun `generated key matches Drive's ed25519Legacy shape (EdDSA_LEGACY primary, ECDH encryption subkey)`() {
        // client/js/src/crypto/openPGPCrypto.ts generates keys with
        // `type: 'ecc', curve: 'ed25519Legacy'` - a V4 key with an EdDSA-Legacy signing
        // primary key and an ECDH (Curve25519) encryption subkey. modernKeyRing() in
        // PGPainless 1.x produces exactly that combination (pre-RFC9580 v4 keys).
        val generated = crypto.generateKey(crypto.generatePassphrase())
        val keys = generated.privateKey.secretKeys.toList()

        val primaryAlgorithm = keys.first().publicKey.algorithm
        assertEquals(PublicKeyAlgorithmTags.EDDSA_LEGACY, primaryAlgorithm)

        val subkeyAlgorithm = keys.drop(1).first().publicKey.algorithm
        assertEquals(PublicKeyAlgorithmTags.ECDH, subkeyAlgorithm)
    }

    @Test
    fun `node name round-trips through encrypt-and-sign then decrypt-and-verify, like a Drive node`() {
        // Mirrors Drive's model: a parent folder key encrypts data for/signed by an
        // address key (client/js/src/integration-tests/nodesCrypto.test.ts sets up
        // parentKey + addressKey the same way).
        val addressKeyPassphrase = crypto.generatePassphrase()
        val addressKey = crypto.generateKey(addressKeyPassphrase)

        val parentKeyPassphrase = crypto.generatePassphrase()
        val parentKey = crypto.generateKey(parentKeyPassphrase)

        val parentPublicKey = parentKey.privateKey.toPublicKeyHandle()

        val nodeName = "My Document.pdf".toByteArray(Charsets.UTF_8)

        val encryptedName = crypto.encryptAndSign(
            data = nodeName,
            encryptionKeys = listOf(parentPublicKey),
            signingKey = addressKey.privateKey,
        )
        assertTrue(encryptedName.isNotEmpty())

        val addressPublicKey = addressKey.privateKey.toPublicKeyHandle()
        val result = crypto.decryptAndVerify(
            data = encryptedName,
            decryptionKey = parentKey.privateKey,
            verificationKeys = listOf(addressPublicKey),
        )

        assertContentEquals(nodeName, result.data)
        assertEquals(VerifyStatus.OK, result.verified)
    }

    @Test
    fun `decrypt-and-verify fails closed against a wrong verification key`() {
        val addressKey = crypto.generateKey(crypto.generatePassphrase())
        val impostorKey = crypto.generateKey(crypto.generatePassphrase())
        val parentKey = crypto.generateKey(crypto.generatePassphrase())
        val parentPublicKey = parentKey.privateKey.toPublicKeyHandle()

        val encrypted = crypto.encryptAndSign(
            data = "content session key wrapper".toByteArray(),
            encryptionKeys = listOf(parentPublicKey),
            signingKey = addressKey.privateKey,
        )

        val impostorPublicKey = impostorKey.privateKey.toPublicKeyHandle()
        val result = crypto.decryptAndVerify(
            data = encrypted,
            decryptionKey = parentKey.privateKey,
            verificationKeys = listOf(impostorPublicKey),
        )

        assertEquals(VerifyStatus.FAILED, result.verified)
    }

    @Test
    fun `detached signature (used for node passphrase signature) verifies correctly`() {
        // Mirrors armoredNodePassphraseSignature in nodesCrypto.test.ts: the node
        // passphrase itself is signed separately from being encrypted.
        val addressKey = crypto.generateKey(crypto.generatePassphrase())
        val addressPublicKey = addressKey.privateKey.toPublicKeyHandle()

        val nodePassphrase = crypto.generatePassphrase().toByteArray()
        val signature = crypto.signDetached(nodePassphrase, addressKey.privateKey)

        val verifyResult = crypto.verifyDetached(nodePassphrase, signature, listOf(addressPublicKey))
        assertEquals(VerifyStatus.OK, verifyResult.verified)

        val tampered = "not the passphrase".toByteArray()
        val tamperedResult = crypto.verifyDetached(tampered, signature, listOf(addressPublicKey))
        assertEquals(VerifyStatus.FAILED, tamperedResult.verified)
    }

    @Test
    fun `encryptAndSignArmored round-trips through decryptArmoredAndVerify, like a folder's hash key`() {
        // Mirrors generateHashKey in driveCrypto.ts: a folder encrypts+signs data with its own key.
        val folderKey = crypto.generateKey(crypto.generatePassphrase())
        val folderPublicKey = folderKey.privateKey.toPublicKeyHandle()

        val hashKeyMaterial = crypto.generatePassphrase().toByteArray()
        val armored = crypto.encryptAndSignArmored(hashKeyMaterial, listOf(folderPublicKey), folderKey.privateKey)
        assertTrue(armored.contains("BEGIN PGP MESSAGE"))

        val result = crypto.decryptArmoredAndVerify(armored, listOf(folderKey.privateKey), listOf(folderPublicKey))
        assertContentEquals(hashKeyMaterial, result.data)
        assertEquals(VerifyStatus.OK, result.verified)
    }

    @Test
    fun `encryptAndSignDetachedArmored round-trips through decryptArmoredAndVerifyDetachedWithKey, like a node passphrase`() {
        // Mirrors encryptPassphrase/decryptKey in driveCrypto.ts: parent encrypts a new
        // node's passphrase for itself, signed by the address key that creates the node.
        val parentKey = crypto.generateKey(crypto.generatePassphrase())
        val parentPublicKey = parentKey.privateKey.toPublicKeyHandle()
        val addressKey = crypto.generateKey(crypto.generatePassphrase())
        val addressPublicKey = addressKey.privateKey.toPublicKeyHandle()

        val passphrase = crypto.generatePassphrase().toByteArray()
        val encrypted = crypto.encryptAndSignDetachedArmored(passphrase, listOf(parentPublicKey), addressKey.privateKey)
        assertTrue(encrypted.armoredData.contains("BEGIN PGP MESSAGE"))
        assertTrue(encrypted.armoredSignature.contains("BEGIN PGP SIGNATURE"))

        val result = crypto.decryptArmoredAndVerifyDetachedWithKey(
            encrypted.armoredData,
            encrypted.armoredSignature,
            listOf(parentKey.privateKey),
            listOf(addressPublicKey),
        )
        assertContentEquals(passphrase, result.data)
        assertEquals(VerifyStatus.OK, result.verified)
    }

    @Test
    fun `encryptAndSignDetachedArmored is also readable via the session-key-first path used for real node passphrases`() {
        // The real read path (decryptArmoredSessionKey + decryptArmoredAndVerifyDetached)
        // must also work against what encryptAndSignDetachedArmored produces, since that's
        // exactly how DriveClient reads back a passphrase it (or the server) just wrote.
        val parentKey = crypto.generateKey(crypto.generatePassphrase())
        val parentPublicKey = parentKey.privateKey.toPublicKeyHandle()
        val addressKey = crypto.generateKey(crypto.generatePassphrase())
        val addressPublicKey = addressKey.privateKey.toPublicKeyHandle()

        val passphrase = crypto.generatePassphrase().toByteArray()
        val encrypted = crypto.encryptAndSignDetachedArmored(passphrase, listOf(parentPublicKey), addressKey.privateKey)

        val sessionKey = crypto.decryptArmoredSessionKey(encrypted.armoredData, listOf(parentKey.privateKey))
        val result = crypto.decryptArmoredAndVerifyDetached(
            encrypted.armoredData,
            encrypted.armoredSignature,
            sessionKey,
            listOf(addressPublicKey),
        )
        assertContentEquals(passphrase, result.data)
        assertEquals(VerifyStatus.OK, result.verified)
    }

    @Test
    fun `decryptSessionKey plus decryptWithSessionKey round-trip content the way Drive file blocks are decrypted`() {
        // Drive's real ContentKeyPacket is a bare PKESK packet (no trailing data),
        // but decryptSessionKey only ever reads the leading PGPEncryptedDataList off
        // the stream, so testing it against a normal encryptAndSign message (which
        // starts with the same PKESK packet) exercises the same code path.
        val nodeKey = crypto.generateKey(crypto.generatePassphrase())
        val nodePublicKey = nodeKey.privateKey.toPublicKeyHandle()

        val blockPlaintext = "raw file bytes, like a decrypted Drive block".toByteArray()
        val encryptedBlock = crypto.encryptAndSign(blockPlaintext, listOf(nodePublicKey), nodeKey.privateKey)

        val sessionKey = crypto.decryptSessionKey(encryptedBlock, listOf(nodeKey.privateKey))
        val result = crypto.decryptWithSessionKey(encryptedBlock, sessionKey)

        assertContentEquals(blockPlaintext, result.data)
    }

    @Test
    fun `decryptSessionKey throws when none of the given keys can decrypt it`() {
        val nodeKey = crypto.generateKey(crypto.generatePassphrase())
        val wrongKey = crypto.generateKey(crypto.generatePassphrase())
        val encryptedBlock = crypto.encryptAndSign(
            "x".toByteArray(),
            listOf(nodeKey.privateKey.toPublicKeyHandle()),
            nodeKey.privateKey,
        )

        assertFailsWith<DecryptionError> {
            crypto.decryptSessionKey(encryptedBlock, listOf(wrongKey.privateKey))
        }
    }

    @Test
    fun `verifyArmoredDetached verifies binary data against an armored detached signature, like a revision manifest`() {
        val signingKey = crypto.generateKey(crypto.generatePassphrase())
        val signingPublicKey = signingKey.privateKey.toPublicKeyHandle()
        val encryptionKey = crypto.generateKey(crypto.generatePassphrase())

        // encryptAndSignDetachedArmored's signature is over the plaintext `data` param
        // regardless of the encryption target, so its armoredSignature is exactly the
        // shape a real ManifestSignature has: an armored detached signature over raw
        // (non-armored) bytes - here, a stand-in for concatenated block hashes.
        val manifest = "block1hash|block2hash".toByteArray()
        val encrypted = crypto.encryptAndSignDetachedArmored(
            manifest,
            listOf(encryptionKey.privateKey.toPublicKeyHandle()),
            signingKey.privateKey,
        )

        val result = crypto.verifyArmoredDetached(manifest, encrypted.armoredSignature, listOf(signingPublicKey))
        assertEquals(VerifyStatus.OK, result.verified)

        val tamperedResult = crypto.verifyArmoredDetached("tampered".toByteArray(), encrypted.armoredSignature, listOf(signingPublicKey))
        assertEquals(VerifyStatus.FAILED, tamperedResult.verified)
    }

    @Test
    fun `signArmoredDetached round-trips through verifyArmoredDetached, like a new file's ContentKeyPacketSignature`() {
        val nodeKey = crypto.generateKey(crypto.generatePassphrase())
        val nodePublicKey = nodeKey.privateKey.toPublicKeyHandle()

        val sessionKeyBytes = "not a real session key but same shape".toByteArray()
        val armoredSignature = crypto.signArmoredDetached(sessionKeyBytes, nodeKey.privateKey)
        assertTrue(armoredSignature.contains("BEGIN PGP SIGNATURE"))

        val result = crypto.verifyArmoredDetached(sessionKeyBytes, armoredSignature, listOf(nodePublicKey))
        assertEquals(VerifyStatus.OK, result.verified)

        val tamperedResult = crypto.verifyArmoredDetached("tampered".toByteArray(), armoredSignature, listOf(nodePublicKey))
        assertEquals(VerifyStatus.FAILED, tamperedResult.verified)
    }

    @Test
    fun `encryptWithSessionKey round-trips through decryptWithSessionKey, like a Drive file block`() {
        // decryptWithSessionKey goes through PGPainless's own message parser (not just our
        // encode logic), so a successful round-trip here is real evidence the hand-rolled
        // packet is a well-formed OpenPGP message any compliant reader (e.g. a real Proton
        // client) could also decrypt - not just something only our own code can read back.
        val sessionKey = crypto.generateSessionKey()
        val blockPlaintext = "raw file bytes, like an uploaded Drive block".toByteArray()

        val encrypted = crypto.encryptWithSessionKey(blockPlaintext, sessionKey)
        assertTrue(encrypted.isNotEmpty())

        val result = crypto.decryptWithSessionKey(encrypted, sessionKey)
        assertContentEquals(blockPlaintext, result.data)
    }

    @Test
    fun `encryptWithSessionKey handles a block larger than the partial-packet buffer`() {
        // Exercises the partial-body-length packet framing (BCPGOutputStream's buffered
        // constructor) across multiple chunks, not just a single undersized packet.
        val sessionKey = crypto.generateSessionKey()
        val blockPlaintext = ByteArray(3 * 1024 * 1024) { (it % 256).toByte() }

        val encrypted = crypto.encryptWithSessionKey(blockPlaintext, sessionKey)
        val result = crypto.decryptWithSessionKey(encrypted, sessionKey)
        assertContentEquals(blockPlaintext, result.data)
    }

    @Test
    fun `generateSessionKey, encryptSessionKey and decryptSessionKey round-trip a new file's ContentKeyPacket`() {
        val nodeKey = crypto.generateKey(crypto.generatePassphrase())
        val nodePublicKey = nodeKey.privateKey.toPublicKeyHandle()

        val sessionKey = crypto.generateSessionKey()
        val contentKeyPacket = crypto.encryptSessionKey(sessionKey, listOf(nodePublicKey))
        assertTrue(contentKeyPacket.isNotEmpty())

        val recovered = crypto.decryptSessionKey(contentKeyPacket, listOf(nodeKey.privateKey))
        assertContentEquals(sessionKey.rawBytes, recovered.rawBytes)
        assertEquals(sessionKey.sessionKey.algorithm, recovered.sessionKey.algorithm)
    }

    @Test
    fun `detached verification works even when the signed bytes resemble an OpenPGP packet`() {
        // Session keys are random bytes, and ~6% of the time their leading bytes look like
        // a binary OpenPGP packet header. PGPainless sniffs its input stream, and without
        // ConsumerOptions.forceNonOpenPgpData() it would try to *parse* such data as a
        // message and throw MalformedOpenPgpMessageException instead of verifying - the
        // cause of a flaky failure in the pipeline test below. These fixed bytes sniff as
        // a User Attribute packet header (0xD1 = new-format packet, tag 17).
        val packetLikeSessionKeyBytes = ByteArray(32).also { bytes ->
            val hex = "d142e0b996033d825222318297960adb864381c6bc0665c59d414760487779a8"
            for (i in bytes.indices) bytes[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        val nodeKey = crypto.generateKey(crypto.generatePassphrase())
        val nodePublicKey = nodeKey.privateKey.toPublicKeyHandle()

        val armoredSignature = crypto.signArmoredDetached(packetLikeSessionKeyBytes, nodeKey.privateKey)
        val armoredResult = crypto.verifyArmoredDetached(packetLikeSessionKeyBytes, armoredSignature, listOf(nodePublicKey))
        assertEquals(VerifyStatus.OK, armoredResult.verified)

        val binarySignature = crypto.signDetached(packetLikeSessionKeyBytes, nodeKey.privateKey)
        val binaryResult = crypto.verifyDetached(packetLikeSessionKeyBytes, binarySignature, listOf(nodePublicKey))
        assertEquals(VerifyStatus.OK, binaryResult.verified)
    }

    @Test
    fun `full upload-then-download crypto pipeline round-trips a file's content`() {
        // Mirrors exactly what DriveClient.uploadFile and downloadFile do together:
        // generate a content session key, wrap it in a ContentKeyPacket for the node's own
        // key, then use that session key to encrypt/decrypt the file's blocks.
        val nodeKey = crypto.generateKey(crypto.generatePassphrase())
        val nodePublicKey = nodeKey.privateKey.toPublicKeyHandle()

        val sessionKey = crypto.generateSessionKey()
        val contentKeyPacket = crypto.encryptSessionKey(sessionKey, listOf(nodePublicKey))
        val armoredContentKeyPacketSignature = crypto.signArmoredDetached(sessionKey.rawBytes, nodeKey.privateKey)

        val blockPlaintext = "the actual file content, uploaded then downloaded".toByteArray()
        val encryptedBlock = crypto.encryptWithSessionKey(blockPlaintext, sessionKey)

        // Downloader side: starts from nothing but the node key and the two encrypted artifacts.
        val recoveredSessionKey = crypto.decryptSessionKey(contentKeyPacket, listOf(nodeKey.privateKey))
        val signatureVerify = crypto.verifyArmoredDetached(recoveredSessionKey.rawBytes, armoredContentKeyPacketSignature, listOf(nodePublicKey))
        assertEquals(VerifyStatus.OK, signatureVerify.verified)

        val decrypted = crypto.decryptWithSessionKey(encryptedBlock, recoveredSessionKey)
        assertContentEquals(blockPlaintext, decrypted.data)
    }
}
