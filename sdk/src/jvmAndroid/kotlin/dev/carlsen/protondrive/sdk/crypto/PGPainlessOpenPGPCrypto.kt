package dev.carlsen.protondrive.sdk.crypto

import dev.carlsen.protondrive.sdk.errors.DecryptionError
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.PacketTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.algorithm.EncryptionPurpose
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.decryption_verification.MessageMetadata
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets
import org.pgpainless.util.Passphrase
import org.pgpainless.util.SessionKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.Base64
import java.util.Date

/** Must be a power of 2 - see BCPGOutputStream's partial-body-length packet constructor. */
private const val PARTIAL_PACKET_BUFFER_SIZE = 1 shl 20

/**
 * Implements the Drive-relevant subset of OpenPGPCrypto using PGPainless (pure JVM,
 * BouncyCastle-backed) instead of Proton's native/WASM crypto engine. Used to validate
 * that a pure-Kotlin/JVM port of the Drive SDK is viable without native bindings.
 */
class PGPainlessOpenPGPCrypto(
    /** Source of "now" for key/signature creation and validity checks - see [ServerClock]. */
    private val serverClock: ServerClock = ServerClock(),
) : OpenPGPCrypto {

    override fun generatePassphrase(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes)
    }

    override fun generateKey(passphrase: String): GeneratedKey {
        // Same layout as PGPainless' modernKeyRing() template, but dated by the server clock -
        // a key created "in the future" (device clock ahead) is rejected by the API.
        val createdAt = now()
        val secretKeys: PGPSecretKeyRing = PGPainless.buildKeyRing()
            .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER).setKeyCreationDate(createdAt))
            .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).setKeyCreationDate(createdAt))
            .addSubkey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA).setKeyCreationDate(createdAt))
            .addUserId("Drive key")
            .setPassphrase(Passphrase.fromPassword(passphrase))
            .build()
        val armoredKey = PGPainless.asciiArmor(secretKeys)
        return GeneratedKey(PrivateKeyHandle(secretKeys, passphrase), armoredKey)
    }

    override fun decryptKey(armoredKey: String, passphrase: String): PrivateKeyHandle {
        val secretKeys = requireNotNull(PGPainless.readKeyRing().secretKeyRing(armoredKey)) {
            "Not a valid armored secret key ring"
        }
        return PrivateKeyHandle(secretKeys, passphrase)
    }

    override fun encryptAndSign(
        data: ByteArray,
        encryptionKeys: List<PublicKeyHandle>,
        signingKey: PrivateKeyHandle,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        val encryptionOptions = encryptionOptions()
        encryptionKeys.forEach { encryptionOptions.addRecipient(it.freshPublicKeys()) }

        val signingOptions = signingOptions(signingKey, detached = false)

        PGPainless.encryptAndOrSign()
            .onOutputStream(out)
            .withOptions(ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions))
            .use { stream -> stream.write(data) }

        return out.toByteArray()
    }

    override fun decryptAndVerify(
        data: ByteArray,
        decryptionKey: PrivateKeyHandle,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult {
        val options = consumerOptions()
            .addDecryptionKey(decryptionKey.freshUnlockedKeys(), unprotectedProtector)
        verificationKeys.forEach { options.addVerificationCert(it.freshPublicKeys()) }

        val decryptionStream = PGPainless.decryptAndOrVerify()
            .onInputStream(ByteArrayInputStream(data))
            .withOptions(options)

        val plaintext = decryptionStream.use { it.readBytes() }
        val metadata = decryptionStream.metadata

        val verified = when {
            verificationKeys.isEmpty() -> VerifyStatus.NOT_SIGNED
            metadata.isVerifiedSigned() -> VerifyStatus.OK
            else -> VerifyStatus.FAILED
        }
        return DecryptResult(plaintext, verified)
    }

    override fun signDetached(data: ByteArray, signingKey: PrivateKeyHandle): ByteArray {
        val out = ByteArrayOutputStream()
        val signingOptions = signingOptions(signingKey, detached = true)

        val stream = PGPainless.encryptAndOrSign()
            .onOutputStream(out)
            .withOptions(ProducerOptions.sign(signingOptions))
        stream.use { it.write(data) }

        val signature = stream.result.detachedSignatures.values.flatten().first()
        val signatureOut = ByteArrayOutputStream()
        signature.encode(signatureOut)
        return signatureOut.toByteArray()
    }

    override fun verifyDetached(
        data: ByteArray,
        signature: ByteArray,
        verificationKeys: List<PublicKeyHandle>,
    ): VerifyResult {
        // forceNonOpenPgpData: `data` is raw signed bytes, but PGPainless sniffs its
        // leading bytes and, if they happen to resemble an OpenPGP packet header
        // (~6% of random 32-byte session keys do), tries to parse them as a message
        // and throws MalformedOpenPgpMessageException instead of verifying.
        val options = consumerOptions()
            .forceNonOpenPgpData()
            .addVerificationOfDetachedSignatures(ByteArrayInputStream(signature))
        verificationKeys.forEach { options.addVerificationCert(it.freshPublicKeys()) }

        val decryptionStream = PGPainless.decryptAndOrVerify()
            .onInputStream(ByteArrayInputStream(data))
            .withOptions(options)

        decryptionStream.use { it.readBytes() }
        val metadata = decryptionStream.metadata

        val verified = if (metadata.isVerifiedSigned()) VerifyStatus.OK else VerifyStatus.FAILED
        return VerifyResult(verified)
    }

    override fun decryptArmoredSessionKey(armoredData: String, decryptionKeys: List<PrivateKeyHandle>): SessionKeyHandle {
        val options = consumerOptions()
        decryptionKeys.forEach { options.addDecryptionKey(it.freshUnlockedKeys(), unprotectedProtector) }

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(armoredData.byteInputStream(Charsets.UTF_8))
            .withOptions(options)
        stream.use { it.readBytes() }

        val sessionKey = requireNotNull(stream.metadata.sessionKey) { "No session key found in message" }
        return SessionKeyHandle(sessionKey)
    }

    override fun decryptArmoredAndVerifyDetached(
        armoredData: String,
        armoredSignature: String?,
        sessionKey: SessionKeyHandle,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult {
        val options = consumerOptions().setSessionKey(sessionKey.sessionKey)
        if (armoredSignature != null) {
            options.addVerificationOfDetachedSignatures(armoredSignature.byteInputStream(Charsets.UTF_8))
        }
        verificationKeys.forEach { options.addVerificationCert(it.freshPublicKeys()) }

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(armoredData.byteInputStream(Charsets.UTF_8))
            .withOptions(options)
        val plaintext = stream.use { it.readBytes() }

        return DecryptResult(
            plaintext,
            verificationStatus(stream.metadata, hasVerificationKeys = verificationKeys.isNotEmpty())
        )
    }

    override fun decryptArmoredAndVerify(
        armoredData: String,
        decryptionKeys: List<PrivateKeyHandle>,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult {
        val options = consumerOptions()
        decryptionKeys.forEach { options.addDecryptionKey(it.freshUnlockedKeys(), unprotectedProtector) }
        verificationKeys.forEach { options.addVerificationCert(it.freshPublicKeys()) }

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(armoredData.byteInputStream(Charsets.UTF_8))
            .withOptions(options)
        val plaintext = stream.use { it.readBytes() }

        return DecryptResult(
            plaintext,
            verificationStatus(stream.metadata, hasVerificationKeys = verificationKeys.isNotEmpty())
        )
    }

    override fun decryptArmoredAndVerifyDetachedWithKey(
        armoredData: String,
        armoredSignature: String,
        decryptionKeys: List<PrivateKeyHandle>,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult {
        val options = consumerOptions()
            .addVerificationOfDetachedSignatures(armoredSignature.byteInputStream(Charsets.UTF_8))
        decryptionKeys.forEach { options.addDecryptionKey(it.freshUnlockedKeys(), unprotectedProtector) }
        verificationKeys.forEach { options.addVerificationCert(it.freshPublicKeys()) }

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(armoredData.byteInputStream(Charsets.UTF_8))
            .withOptions(options)
        val plaintext = stream.use { it.readBytes() }

        return DecryptResult(
            plaintext,
            verificationStatus(stream.metadata, hasVerificationKeys = verificationKeys.isNotEmpty())
        )
    }

    override fun encryptAndSignArmored(
        data: ByteArray,
        encryptionKeys: List<PublicKeyHandle>,
        signingKey: PrivateKeyHandle,
    ): String {
        val out = ByteArrayOutputStream()
        val encryptionOptions = encryptionOptions()
        encryptionKeys.forEach { encryptionOptions.addRecipient(it.freshPublicKeys()) }

        val signingOptions = signingOptions(signingKey, detached = false)

        PGPainless.encryptAndOrSign()
            .onOutputStream(out)
            .withOptions(ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions).setAsciiArmor(true))
            .use { stream -> stream.write(data) }

        return out.toString("UTF8")
    }

    override fun encryptAndSignDetachedArmored(
        data: ByteArray,
        encryptionKeys: List<PublicKeyHandle>,
        signingKey: PrivateKeyHandle,
    ): EncryptedDetachedResult {
        val out = ByteArrayOutputStream()
        val encryptionOptions = encryptionOptions()
        encryptionKeys.forEach { encryptionOptions.addRecipient(it.freshPublicKeys()) }

        val signingOptions = signingOptions(signingKey, detached = true)

        val stream = PGPainless.encryptAndOrSign()
            .onOutputStream(out)
            .withOptions(ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions).setAsciiArmor(true))
        stream.use { it.write(data) }

        val signature = stream.result.detachedSignatures.values.flatten().first()
        return EncryptedDetachedResult(
            armoredData = out.toString("UTF8"),
            armoredSignature = PGPainless.asciiArmor(signature),
        )
    }

    override fun decryptSessionKey(data: ByteArray, decryptionKeys: List<PrivateKeyHandle>): SessionKeyHandle {
        // Drive's ContentKeyPacket is a bare PKESK packet with no accompanying
        // encrypted data packet. BC's PGPEncryptedDataList/PGPPublicKeyEncryptedData
        // both require a trailing data packet to follow the PKESK(s) (they throw
        // "unexpected packet in stream: null" otherwise, confirmed against a real
        // Drive account), so this reads the PublicKeyEncSessionPacket directly at
        // the BCPGInputStream level instead - matching openPGPCrypto.ts's
        // decryptSessionKey(), which has the same bare-PKESK constraint.
        val bcpgIn = BCPGInputStream(PGPUtil.getDecoderStream(ByteArrayInputStream(data)))
        val packet = bcpgIn.readPacket() as? PublicKeyEncSessionPacket
            ?: throw DecryptionError("ContentKeyPacket does not start with a public-key encrypted session key packet")

        @Suppress("DEPRECATION")
        val secretKey = decryptionKeys.firstNotNullOfOrNull { handle ->
            handle.freshUnlockedKeys().getSecretKey(packet.keyID)
        } ?: throw DecryptionError("No matching key found to decrypt session key")

        // The unlocked ring's keys carry no S2K protection, so no decryptor is needed.
        val privateKey = secretKey.extractPrivateKey(null)
        val decryptorFactory = JcePublicKeyDataDecryptorFactoryBuilder().setProvider(sharedBouncyCastleProvider).build(privateKey)
        // Deprecated in favor of recoverSessionData(PublicKeyEncSessionPacket, InputStreamPacket),
        // which needs the trailing data packet Drive's bare ContentKeyPacket doesn't have - this
        // version-aware overload is the only one that works without it.
        @Suppress("DEPRECATION")
        val sessionInfo = decryptorFactory.recoverSessionData(packet.algorithm, packet.encSessionKey, packet.version)

        // Two layout dimensions, mirroring PGPPublicKeyEncryptedData's own logic:
        // - Checksum: algorithm-based - every algorithm except native X25519/X448 appends a
        //   2-byte big-endian sum of the session key bytes.
        // - Leading symmetric-algorithm octet: *version*-based - present in v3, removed
        //   entirely in v6 (RFC 9580 moved it to the v2 SEIPD packet, which Drive's bare
        //   ContentKeyPacket doesn't have - Drive session keys are always AES-256, same
        //   assumption the X25519 branch already makes). Proton's current clients write v6
        //   PKESKs even for classic v4 curve25519Legacy node keys, so real accounts hold
        //   both flavors; misreading a v6 payload's first key byte as the algorithm octet
        //   is exactly what "checksum verification failed" on old files turned out to be.
        val hasChecksum = packet.algorithm != PublicKeyAlgorithmTags.X25519 &&
            packet.algorithm != PublicKeyAlgorithmTags.X448
        val hasAlgorithmOctet = packet.version != PublicKeyEncSessionPacket.VERSION_6

        val pgpSessionKey = if (hasChecksum) {
            val keyStart = if (hasAlgorithmOctet) 1 else 0
            var checksum = 0
            for (i in keyStart until sessionInfo.size - 2) checksum += sessionInfo[i].toInt() and 0xff
            val checksumOk = sessionInfo[sessionInfo.size - 2] == (checksum shr 8).toByte() &&
                sessionInfo[sessionInfo.size - 1] == checksum.toByte()
            // The format details (never the decrypted bytes themselves) are included because
            // new PKESK flavors have shown up in the field before - pinning down the next
            // one needs exactly these.
            if (!checksumOk) throw DecryptionError(
                "Content key packet checksum verification failed " +
                    "(PKESK v${packet.version}, public-key algorithm ${packet.algorithm}, " +
                    "session info ${sessionInfo.size} bytes)",
            )
            val algorithm = if (hasAlgorithmOctet) sessionInfo[0].toInt() and 0xff else SymmetricKeyAlgorithmTags.AES_256
            PGPSessionKey(algorithm, sessionInfo.copyOfRange(keyStart, sessionInfo.size - 2))
        } else {
            PGPSessionKey(SymmetricKeyAlgorithmTags.AES_256, sessionInfo)
        }
        return SessionKeyHandle(SessionKey(pgpSessionKey))
    }

    override fun decryptWithSessionKey(
        data: ByteArray,
        sessionKey: SessionKeyHandle,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult {
        // PGPainless 1.7.x can't decrypt v2 SEIPD (RFC 9580 AEAD) packets, and - far worse -
        // its message stream silently passes them through as if they were plaintext, so a
        // download would "succeed" and write ciphertext to disk (observed on real Drive
        // files: Proton's current clients upload blocks as SEIPDv2/AES-256/GCM, paired with
        // the v6 PKESK ContentKeyPackets [decryptSessionKey] handles). Those packets are
        // routed to a manual BC path; v1 stays on PGPainless, which also handles the
        // partial-length packets [encryptWithSessionKey] emits and inline signatures.
        if (seipdVersion(data) == SymmetricEncIntegrityPacket.VERSION_2) {
            return decryptSeipdV2WithSessionKey(data, sessionKey, verificationKeys)
        }

        val options = consumerOptions().setSessionKey(sessionKey.sessionKey)
        verificationKeys.forEach { options.addVerificationCert(it.freshPublicKeys()) }

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(ByteArrayInputStream(data))
            .withOptions(options)
        val plaintext = stream.use { it.readBytes() }

        return DecryptResult(
            plaintext,
            verificationStatus(stream.metadata, hasVerificationKeys = verificationKeys.isNotEmpty())
        )
    }

    /** The SEIPD version of [data]'s leading packet, or null if it isn't a SEIPD packet at all. */
    private fun seipdVersion(data: ByteArray): Int? = runCatching {
        (BCPGInputStream(ByteArrayInputStream(data)).readPacket() as? SymmetricEncIntegrityPacket)?.version
    }.getOrNull()

    /**
     * Decrypts a v2 SEIPD (AEAD) block directly with BC - integrity comes from the per-chunk
     * AEAD tags, verified during streaming. Inline-signature verification is not implemented
     * here: Drive signs block content via the detached manifest signature instead, and no
     * caller passes verification keys - if one ever does, the honest answer is FAILED, not a
     * silent OK.
     */
    private fun decryptSeipdV2WithSessionKey(
        data: ByteArray,
        sessionKey: SessionKeyHandle,
        verificationKeys: List<PublicKeyHandle>,
    ): DecryptResult {
        val encryptedList = BcPGPObjectFactory(data).nextObject() as? PGPEncryptedDataList
            ?: throw DecryptionError("Block does not start with an encrypted data packet")
        val encryptedData = encryptedList.extractSessionKeyEncryptedData()

        val pgpSessionKey = PGPSessionKey(sessionKey.sessionKey.algorithm.algorithmId, sessionKey.sessionKey.key)
        val clearStream = encryptedData.getDataStream(BcSessionKeyDataDecryptorFactory(pgpSessionKey))

        var packet = BcPGPObjectFactory(clearStream).nextObject()
        if (packet is PGPCompressedData) {
            packet = BcPGPObjectFactory(packet.dataStream).nextObject()
        }
        val literal = packet as? PGPLiteralData
            ?: throw DecryptionError("Decrypted block does not contain literal data (found ${packet?.let { it::class.simpleName } ?: "nothing"})")
        // Not readBytes(): BC's packet streams report a bogus available(), which readBytes()
        // uses to pre-size its buffer - OOM on a perfectly small stream. copyTo() reads with
        // a fixed-size buffer instead.
        val plaintextOut = ByteArrayOutputStream()
        literal.inputStream.copyTo(plaintextOut)
        val plaintext = plaintextOut.toByteArray()

        if (encryptedData.isIntegrityProtected && !encryptedData.verify()) {
            throw DecryptionError("Block failed its integrity check")
        }

        val verified = if (verificationKeys.isEmpty()) VerifyStatus.NOT_SIGNED else VerifyStatus.FAILED
        return DecryptResult(plaintext, verified)
    }

    override fun verifyArmoredDetached(
        data: ByteArray,
        armoredSignature: String,
        verificationKeys: List<PublicKeyHandle>,
    ): VerifyResult {
        // forceNonOpenPgpData: same misclassification hazard as verifyDetached - session
        // keys and manifests are arbitrary binary that can look like a packet header.
        val options = consumerOptions()
            .forceNonOpenPgpData()
            .addVerificationOfDetachedSignatures(armoredSignature.byteInputStream(Charsets.UTF_8))
        verificationKeys.forEach { options.addVerificationCert(it.freshPublicKeys()) }

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(ByteArrayInputStream(data))
            .withOptions(options)
        stream.use { it.readBytes() }

        val verified = if (stream.metadata.isVerifiedSigned()) VerifyStatus.OK else VerifyStatus.FAILED
        return VerifyResult(verified)
    }

    override fun signArmoredDetached(data: ByteArray, signingKey: PrivateKeyHandle): String {
        val out = ByteArrayOutputStream()
        val signingOptions = signingOptions(signingKey, detached = true)

        val stream = PGPainless.encryptAndOrSign()
            .onOutputStream(out)
            .withOptions(ProducerOptions.sign(signingOptions).setAsciiArmor(true))
        stream.use { it.write(data) }

        val signature = stream.result.detachedSignatures.values.flatten().first()
        return PGPainless.asciiArmor(signature)
    }

    override fun generateSessionKey(): SessionKeyHandle {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return SessionKeyHandle(SessionKey(PGPSessionKey(SymmetricKeyAlgorithmTags.AES_256, bytes)))
    }

    override fun encryptSessionKey(sessionKey: SessionKeyHandle, encryptionKeys: List<PublicKeyHandle>): ByteArray {
        // PublicKeyKeyEncryptionMethodGenerator.generate() builds the classic
        // [algorithm][session key][2-byte checksum] payload itself (see its
        // createSessionInfo() in BC's source) - it wants the *raw* session key
        // here, not a pre-formatted blob. Passing an already-formatted one (as
        // an earlier version of this method did) gets it wrapped a second
        // time, corrupting the result - caught via a round-trip unit test.
        val algorithm = sessionKey.sessionKey.algorithm.algorithmId
        val builder = JcePGPDataEncryptorBuilder(algorithm).setProvider(sharedBouncyCastleProvider)
        val out = ByteArrayOutputStream()
        val packetOut = BCPGOutputStream(out)
        encryptionKeys.forEach { publicKeyHandle ->
            val encryptionSubkey = PGPainless.inspectKeyRing(publicKeyHandle.freshPublicKeys())
                .getEncryptionSubkeys(EncryptionPurpose.ANY)
                .firstOrNull()
                ?: throw DecryptionError("No encryption-capable subkey found")
            val method = JcePublicKeyKeyEncryptionMethodGenerator(encryptionSubkey).setProvider(sharedBouncyCastleProvider)
            packetOut.writePacket(method.generate(builder, sessionKey.rawBytes))
        }
        return out.toByteArray()
    }

    override fun encryptWithSessionKey(data: ByteArray, sessionKey: SessionKeyHandle): ByteArray {
        // Drive's per-block content is a bare SEIPD packet encrypted with the file's shared
        // content session key - no embedded PKESK (that lives separately in the
        // ContentKeyPacket). PGPainless/BC's high-level encryption API always generates its
        // own random session key with no way to supply one, so this hand-rolls the v1 SEIPD
        // packet the same way PGPEncryptedDataGenerator does internally, but seeded with our
        // own session key via JcePGPDataEncryptorBuilder.build(ByteArray) - the mirror of
        // decryptWithSessionKey, which already reads exactly this format.
        val algorithm = sessionKey.sessionKey.algorithm.algorithmId
        val dataEncryptor = JcePGPDataEncryptorBuilder(algorithm)
            .setWithIntegrityPacket(true)
            .setProvider(sharedBouncyCastleProvider)
            .setSecureRandom(SecureRandom())
            .build(sessionKey.rawBytes)

        val out = ByteArrayOutputStream()
        val packetOut = BCPGOutputStream(out, PacketTags.SYM_ENC_INTEGRITY_PRO, ByteArray(PARTIAL_PACKET_BUFFER_SIZE))
        SymmetricEncIntegrityPacket.createVersion1Packet().encode(packetOut)

        val digestCalc = dataEncryptor.integrityCalculator
        val cOut = dataEncryptor.getOutputStream(packetOut)
        val genOut = DualOutputStream(digestCalc.getOutputStream(), cOut)

        val blockSize = dataEncryptor.blockSize
        val inLineIv = ByteArray(blockSize + 2)
        SecureRandom().nextBytes(inLineIv)
        // Repeats the last two IV bytes so the recipient can detect a bad key/corrupted
        // stream immediately, without waiting for the final MDC check - standard OpenPGP
        // v4 SEIPD quirk, mirroring PGPEncryptedDataGenerator's own behavior exactly.
        inLineIv[inLineIv.size - 1] = inLineIv[inLineIv.size - 3]
        inLineIv[inLineIv.size - 2] = inLineIv[inLineIv.size - 4]
        genOut.write(inLineIv)

        val literalOut = PGPLiteralDataGenerator().open(genOut, PGPLiteralDataGenerator.BINARY, "", data.size.toLong(), Date(0))
        literalOut.write(data)
        literalOut.close()

        val mdcOut = BCPGOutputStream(genOut, PacketTags.MOD_DETECTION_CODE, 20)
        mdcOut.finish()
        mdcOut.flush()
        cOut.write(digestCalc.digest)
        cOut.close()
        packetOut.close()

        return out.toByteArray()
    }

    /** Writes every byte to both streams - stands in for BC's TeeOutputStream, which isn't present in this project's resolved bcutil version. */
    private class DualOutputStream(private val a: OutputStream, private val b: OutputStream) : OutputStream() {
        override fun write(byte: Int) {
            a.write(byte)
            b.write(byte)
        }

        override fun write(bytes: ByteArray, off: Int, len: Int) {
            a.write(bytes, off, len)
            b.write(bytes, off, len)
        }

        override fun flush() {
            a.flush()
            b.flush()
        }
    }

    private fun now(): Date = Date(serverClock.now().toEpochMilliseconds())

    /**
     * Signatures are dated by the server clock (PGPainless otherwise stamps `new Date()`), and the
     * signing key's validity is evaluated at that same instant so a key created at server time
     * isn't considered "not yet valid" on a device whose clock is behind.
     */
    private fun signingOptions(signingKey: PrivateKeyHandle, detached: Boolean): SigningOptions {
        val createdAt = now()
        val setCreationTime = object : BaseSignatureSubpackets.Callback {
            override fun modifyHashedSubpackets(hashedSubpackets: BaseSignatureSubpackets) {
                hashedSubpackets.setSignatureCreationTime(createdAt)
            }
        }
        val options = SigningOptions.get().setEvaluationDate(createdAt)
        val keys = signingKey.freshUnlockedKeys()
        return if (detached) {
            options.addDetachedSignature(unprotectedProtector, keys, null, DocumentSignatureType.BINARY_DOCUMENT, setCreationTime)
        } else {
            options.addInlineSignature(unprotectedProtector, keys, null, DocumentSignatureType.BINARY_DOCUMENT, setCreationTime)
        }
    }

    /** Recipient keys are evaluated at server time - set before any addRecipient(), which evaluates eagerly. */
    private fun encryptionOptions(): EncryptionOptions =
        EncryptionOptions.encryptCommunications().setEvaluationDate(now())

    /**
     * PGPainless rejects signatures created after `verifyNotAfter`, which defaults to the device
     * clock - so a device running behind would fail fresh signatures from other clients. Use the
     * server clock instead, plus [FUTURE_SIGNATURE_TOLERANCE_MS] to absorb the HTTP date header's
     * whole-second resolution.
     */
    private fun consumerOptions(): ConsumerOptions =
        ConsumerOptions.get().verifyNotAfter(Date(now().time + FUTURE_SIGNATURE_TOLERANCE_MS))

    private fun verificationStatus(
        metadata: MessageMetadata,
        hasVerificationKeys: Boolean,
    ): VerifyStatus = when {
        !hasVerificationKeys -> VerifyStatus.NOT_SIGNED
        metadata.isVerifiedSigned() -> VerifyStatus.OK
        else -> VerifyStatus.FAILED
    }

    private companion object {
        const val FUTURE_SIGNATURE_TOLERANCE_MS = 60_000L

        /**
         * All PGPainless calls pass [PrivateKeyHandle.freshUnlockedKeys] (protection already
         * stripped, exactly once per handle), so no passphrase-based protector - and no
         * repeated S2K derivation - is ever needed here.
         */
        val unprotectedProtector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    }
}

actual fun defaultOpenPGPCrypto(serverClock: ServerClock): OpenPGPCrypto = PGPainlessOpenPGPCrypto(serverClock)
