package dev.carlsen.protondrive.sdk.auth

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import dev.carlsen.protondrive.sdk.crypto.PgpVerificationException
import dev.carlsen.protondrive.sdk.crypto.SecureRandom
import dev.carlsen.protondrive.sdk.crypto.bcryptHash
import dev.carlsen.protondrive.sdk.crypto.sha512
import dev.carlsen.protondrive.sdk.crypto.verifyClearsignedMessage
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Proton's modified SRP-6a implementation, ported from the reference Go
 * implementation at github.com/ProtonMail/go-srp (srp.go / hash.go), since
 * this proton-sdk repo delegates the actual SRP math to an external, non-
 * vendored package (@protontech/crypto) and doesn't contain a reference
 * implementation itself. Verified against go-srp's own committed test
 * vectors in ProtonSrpTest.kt - see that file for the "why" behind the
 * choice to self-test end-to-end rather than trust byte-exact parity alone.
 *
 * Only auth versions 3/4 (the versions all current Proton accounts use) are
 * supported; legacy versions 0-2 are intentionally not ported.
 */
@OptIn(ExperimentalEncodingApi::class)
object ProtonSrp {

    private const val BIT_LENGTH = 2048
    private const val BYTE_LENGTH = BIT_LENGTH / 8
    private val GENERATOR: BigInteger = BigInteger.fromInt(2)
    private const val BCRYPT_COST = 10

    // The PGP public key Proton uses to sign the SRP modulus, verbatim from
    // github.com/ProtonMail/go-srp's srp.go (modulusPubkey constant).
    private const val MODULUS_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\n" +
        "xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm\r\n" +
        "L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ\r\n" +
        "BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U\r\n" +
        "MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat\r\n" +
        "Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE\r\n" +
        "kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF\r\n" +
        "hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU\r\n" +
        "WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE\r\n" +
        "=Y4Mw\r\n" +
        "-----END PGP PUBLIC KEY BLOCK-----"

    data class SrpProofs(
        val clientEphemeral: String,
        val clientProof: String,
        val expectedServerProof: String,
    )

    class SrpException(message: String) : Exception(message)

    /**
     * Computes the client-side SRP proofs for a login attempt, given the
     * challenge returned by POST /core/v4/auth/info.
     *
     * @param password UTF-8 encoded login password.
     */
    fun generateProofs(
        version: Int,
        signedModulus: String,
        serverEphemeralB64: String,
        saltB64: String,
        password: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): SrpProofs {
        require(version == 3 || version == 4) { "Unsupported SRP version $version (only 3/4 are supported)" }

        val modulusRaw = verifyAndExtractModulus(signedModulus)
        val modulus = bigIntFromLe(modulusRaw)
        val serverEphemeralRaw = Base64.decode(serverEphemeralB64)
        val serverEphemeral = bigIntFromLe(serverEphemeralRaw)
        val saltRaw = Base64.decode(saltB64)

        checkParams(modulus, serverEphemeral, random)

        val hashedPassword = bigIntFromLe(hashPasswordVersion3(password, saltRaw, modulusRaw))
        val multiplier = computeMultiplier(modulus)
        val modulusMinusOne = modulus - BigInteger.ONE

        var clientSecret: BigInteger
        var clientEphemeralBytes: ByteArray
        var scramblingParam: BigInteger
        while (true) {
            val (secret, ephemeralBytes) = generateClientEphemeral(modulus, random)
            clientSecret = secret
            clientEphemeralBytes = ephemeralBytes
            scramblingParam = bigIntFromLe(expandHash(clientEphemeralBytes + serverEphemeralRaw))
            if (scramblingParam.signum() != 0) break
        }

        val base = computeBase(hashedPassword, serverEphemeral, multiplier, modulus)
        val exponent = computeExponent(scramblingParam, hashedPassword, clientSecret, modulusMinusOne)
        val sharedSecretBytes = leBytes(BYTE_LENGTH, base.modPow(exponent, modulus))

        val clientProofBytes = expandHash(clientEphemeralBytes + serverEphemeralRaw + sharedSecretBytes)
        val serverProofBytes = expandHash(clientEphemeralBytes + clientProofBytes + sharedSecretBytes)

        return SrpProofs(
            clientEphemeral = Base64.encode(clientEphemeralBytes),
            clientProof = Base64.encode(clientProofBytes),
            expectedServerProof = Base64.encode(serverProofBytes),
        )
    }

    /**
     * Derives the passphrase used to decrypt the user's private key, from the
     * login password and the (unrelated to SRP) `KeySalt` returned by
     * GET /core/v4/keys/salts.
     */
    fun computeKeyPassword(password: ByteArray, keySaltB64: String): String {
        val salt = Base64.decode(keySaltB64)
        require(salt.size == 16) { "Key salt must decode to 16 bytes, got ${salt.size}" }
        val hashed = bcryptHashString(password, salt)
        // Strip the "$2y$10$" prefix and 22-char encoded salt (29 chars total),
        // leaving the 31-char hash remainder as the key passphrase.
        return String(hashed, Charsets.US_ASCII).substring(29)
    }

    fun generateKeySalt(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return Base64.encode(bytes)
    }

    internal fun verifyAndExtractModulus(signedModulus: String): ByteArray = try {
        val cleartext = verifyClearsignedMessage(signedModulus, MODULUS_PUBLIC_KEY)
        Base64.decode(String(cleartext, Charsets.UTF_8).trim())
    } catch (e: PgpVerificationException) {
        throw SrpException("SRP modulus signature verification failed: ${e.message}")
    } catch (e: Exception) {
        // Malformed base64 in an otherwise-verified message; normalize to one type callers can rely on.
        throw SrpException("SRP modulus signature verification failed: ${e.message}")
    }

    private fun bcryptHashString(password: ByteArray, salt: ByteArray): ByteArray =
        bcryptHash(BCRYPT_COST, salt, password)

    private fun hashPasswordVersion3(password: ByteArray, rawSalt: ByteArray, modulus: ByteArray): ByteArray {
        val salt = rawSalt + "proton".toByteArray(Charsets.US_ASCII)
        val hashed = bcryptHashString(password, salt)
        return expandHash(hashed + modulus)
    }

    /** Four rounds of SHA-512 with a trailing 0/1/2/3 byte, concatenated - Proton's KDF for values wider than 512 bits. */
    private fun expandHash(data: ByteArray): ByteArray {
        val out = ByteArray(64 * 4)
        for (i in 0 until 4) {
            sha512(data + i.toByte()).copyInto(out, destinationOffset = i * 64)
        }
        return out
    }

    private fun computeMultiplier(modulus: BigInteger): BigInteger {
        val k = bigIntFromLe(expandHash(leBytes(BYTE_LENGTH, GENERATOR) + leBytes(BYTE_LENGTH, modulus))).mod(modulus)
        if (k <= BigInteger.ONE || k >= modulus - BigInteger.ONE) {
            throw SrpException("SRP multiplier is out of bounds")
        }
        return k
    }

    private fun checkParams(modulus: BigInteger, serverEphemeral: BigInteger, random: SecureRandom) {
        if (modulus.bitLength() != BIT_LENGTH) {
            throw SrpException("SRP modulus has incorrect size")
        }
        // By quadratic reciprocity, 2 is a square mod N iff N is 1 or 7 mod 8. The
        // generator 2 should generate the whole group (not just the prime-order
        // subgroup), so it must not be a square - this leaves N = 3 mod 8.
        if (!modulus.bitAt(0) || !modulus.bitAt(1) || modulus.bitAt(2)) {
            throw SrpException("SRP modulus is not 3 mod 8")
        }
        val modulusMinusOne = modulus - BigInteger.ONE
        if (serverEphemeral <= BigInteger.ONE || serverEphemeral >= modulusMinusOne) {
            throw SrpException("SRP server ephemeral is out of bounds")
        }
        val halfModulus = modulus.shr(1)
        if (!halfModulus.isProbablePrime(10, random)) {
            throw SrpException("SRP modulus is not a safe prime")
        }
        if (GENERATOR.modPow(halfModulus, modulus) != modulusMinusOne) {
            throw SrpException("SRP modulus is not prime")
        }
    }

    private fun generateClientEphemeral(modulus: BigInteger, random: SecureRandom): Pair<BigInteger, ByteArray> {
        val modulusMinusOne = modulus - BigInteger.ONE
        val lowerBound = BigInteger.fromLong((BIT_LENGTH * 2).toLong())
        var secret: BigInteger
        while (true) {
            secret = uniformRandom(modulusMinusOne, random)
            if (secret > lowerBound && secret < modulusMinusOne) break
        }
        val ephemeral = GENERATOR.modPow(secret, modulus)
        return secret to leBytes(BYTE_LENGTH, ephemeral)
    }

    private fun computeBase(hashedPassword: BigInteger, serverEphemeral: BigInteger, multiplier: BigInteger, modulus: BigInteger): BigInteger {
        val gx = GENERATOR.modPow(hashedPassword, modulus)
        return (serverEphemeral - (multiplier * gx).mod(modulus)).mod(modulus)
    }

    private fun computeExponent(scramblingParam: BigInteger, hashedPassword: BigInteger, clientSecret: BigInteger, modulusMinusOne: BigInteger): BigInteger =
        ((scramblingParam * hashedPassword).mod(modulusMinusOne) + clientSecret).mod(modulusMinusOne)

    /** Uniform random value in [0, bound) via rejection sampling (mirrors Go's crypto/rand.Int). */
    private fun uniformRandom(bound: BigInteger, random: SecureRandom): BigInteger {
        val bitLength = bound.bitLength()
        while (true) {
            val candidate = randomBigInteger(bitLength, random)
            if (candidate < bound) return candidate
        }
    }

    /** Proton's wire format is little-endian; BigInteger's byte conversions are big-endian, so byte order must be reversed both ways. */
    private fun bigIntFromLe(bytes: ByteArray): BigInteger = BigInteger.fromByteArray(bytes.reversedArray(), Sign.POSITIVE)

    private fun leBytes(byteLength: Int, value: BigInteger): ByteArray {
        require(value.signum() >= 0)
        val be = value.toByteArray()
        val magnitude = if (be.size > 1 && be[0] == 0.toByte()) be.copyOfRange(1, be.size) else be
        require(magnitude.size <= byteLength) { "Value too large to fit in $byteLength bytes" }
        val result = ByteArray(byteLength)
        for (i in magnitude.indices) {
            result[magnitude.size - i - 1] = magnitude[i]
        }
        return result
    }
}
