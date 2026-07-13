package dev.carlsen.protondrive.sdk.auth

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import dev.carlsen.protondrive.sdk.crypto.SecureRandom
import dev.carlsen.protondrive.sdk.crypto.bcryptHash
import dev.carlsen.protondrive.sdk.crypto.sha512
import dev.carlsen.protondrive.sdk.crypto.verifyClearsignedMessage
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Test-only, independently-written server side of Proton's SRP protocol,
 * ported from github.com/ProtonMail/go-srp's server.go, used to validate
 * ProtonSrp.kt end-to-end (see ProtonSrpTest). The server-side shared-secret
 * formula (S = (A * v^u)^b mod N) is structurally different from the
 * client's (S = (B - k*g^x)^(a+u*x) mod N), so agreement between the two is
 * a meaningful correctness signal even though some low-level primitives
 * (expandHash, LE/BE conversion) are necessarily duplicated here.
 */
@OptIn(ExperimentalEncodingApi::class)
class FakeSrpServer(
    private val modulus: BigInteger,
    hashedPassword: BigInteger,
    private val random: SecureRandom,
) {
    private val generator = BigInteger.fromInt(2)
    private val multiplier = computeMultiplier(modulus)
    private val verifier = generator.modPow(hashedPassword, modulus)
    private val serverSecret = uniformRandom(modulus - BigInteger.ONE, random)
    private lateinit var serverEphemeralBytes: ByteArray
    private var sharedSession: ByteArray? = null

    fun generateChallenge(): ByteArray {
        val ephemeral = ((multiplier * verifier).mod(modulus) + generator.modPow(serverSecret, modulus)).mod(modulus)
        serverEphemeralBytes = leBytes(BYTE_LENGTH, ephemeral)
        return serverEphemeralBytes
    }

    fun verifyProofs(clientEphemeralB64: String, clientProofB64: String): ByteArray {
        val clientEphemeralBytes = Base64.decode(clientEphemeralB64)
        val clientProofBytes = Base64.decode(clientProofB64)
        val clientEphemeral = bigIntFromLe(clientEphemeralBytes)

        val scramblingParam = bigIntFromLe(expandHash(clientEphemeralBytes + serverEphemeralBytes))
        val base = (clientEphemeral * verifier.modPow(scramblingParam, modulus)).mod(modulus)
        val sharedSecret = base.modPow(serverSecret, modulus)
        val sharedSecretBytes = leBytes(BYTE_LENGTH, sharedSecret)
        sharedSession = sharedSecretBytes

        val expectedClientProof = expandHash(clientEphemeralBytes + serverEphemeralBytes + sharedSecretBytes)
        check(expectedClientProof.contentEquals(clientProofBytes)) { "Client proof mismatch" }

        return expandHash(clientEphemeralBytes + clientProofBytes + sharedSecretBytes)
    }

    companion object {
        private const val BIT_LENGTH = 2048
        private const val BYTE_LENGTH = BIT_LENGTH / 8
        private const val BCRYPT_COST = 10

        fun decodeRealModulus(signedModulus: String): BigInteger {
            val cleartext = verifyClearsignedMessage(signedModulus, MODULUS_PUBLIC_KEY_FOR_TEST)
            val modulusRaw = Base64.decode(String(cleartext, Charsets.UTF_8).trim())
            return bigIntFromLe(modulusRaw)
        }

        fun hashPasswordForVerifier(password: ByteArray, rawSalt: ByteArray, modulus: BigInteger): BigInteger {
            val salt = rawSalt + "proton".toByteArray(Charsets.US_ASCII)
            val hashed = bcryptHash(BCRYPT_COST, salt, password)
            val modulusBytes = leBytes(BYTE_LENGTH, modulus)
            return bigIntFromLe(expandHash(hashed + modulusBytes))
        }

        private fun computeMultiplier(modulus: BigInteger): BigInteger =
            bigIntFromLe(expandHash(leBytes(BYTE_LENGTH, BigInteger.fromInt(2)) + leBytes(BYTE_LENGTH, modulus))).mod(modulus)

        private fun uniformRandom(bound: BigInteger, random: SecureRandom): BigInteger {
            val bitLength = bound.bitLength()
            while (true) {
                val candidate = randomBigInteger(bitLength, random)
                if (candidate < bound) return candidate
            }
        }

        private fun expandHash(data: ByteArray): ByteArray {
            val out = ByteArray(64 * 4)
            for (i in 0 until 4) {
                sha512(data + i.toByte()).copyInto(out, destinationOffset = i * 64)
            }
            return out
        }

        private fun bigIntFromLe(bytes: ByteArray): BigInteger = BigInteger.fromByteArray(bytes.reversedArray(), Sign.POSITIVE)

        private fun leBytes(byteLength: Int, value: BigInteger): ByteArray {
            val be = value.toByteArray()
            val magnitude = if (be.size > 1 && be[0] == 0.toByte()) be.copyOfRange(1, be.size) else be
            val result = ByteArray(byteLength)
            for (i in magnitude.indices) {
                result[magnitude.size - i - 1] = magnitude[i]
            }
            return result
        }

        // Duplicated from ProtonSrp (private there) - same constant, from go-srp's srp.go.
        private const val MODULUS_PUBLIC_KEY_FOR_TEST = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\n" +
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
    }
}
