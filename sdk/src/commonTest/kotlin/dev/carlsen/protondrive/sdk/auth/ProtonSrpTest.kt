package dev.carlsen.protondrive.sdk.auth

import dev.carlsen.protondrive.sdk.crypto.SecureRandom
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Verifies the Kotlin port of Proton's SRP protocol (ProtonSrp.kt).
 *
 * ProtonSrp's actual crypto engine (@protontech/crypto) is not vendored in
 * proton-sdk, so there's no source in that repo to port from directly - this
 * was ported from the public reference implementation at
 * github.com/ProtonMail/go-srp (srp.go / hash.go), fetched and read directly
 * to get the wire format (little-endian!), the expandHash KDF, and the exact
 * modular-arithmetic formulas right.
 *
 * Two complementary verification strategies are used since go-srp's own
 * TestSRPauth vector can't be replayed here: it relies on a seeded Go
 * math/rand stream for the client's random secret, which is infeasible to
 * reproduce bit-for-bit from Kotlin.
 *   1. `verifyAndExtractModulus` is deterministic (no randomness), so it's
 *      checked byte-for-byte against go-srp's real committed test vector.
 *   2. The full proof exchange is checked by implementing SRP's *server*
 *      side too (see FakeSrpServer below) using an independently-derived
 *      formula, and asserting client and fake-server agree - the same
 *      end-to-end strategy go-srp's own TestE2EFlow uses.
 */
@OptIn(ExperimentalEncodingApi::class)
class ProtonSrpTest {

    // Verbatim from github.com/ProtonMail/go-srp/srp_test.go.
    private val testModulus = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ=="

    private val testModulusClearSign = """
        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA256

        W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
        -----BEGIN PGP SIGNATURE-----
        Version: ProtonMail
        Comment: https://protonmail.com

        wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
        GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
        kvNM7qIK
        =q6vu
        -----END PGP SIGNATURE-----
    """.trimIndent()

    @Test
    fun `verifies and extracts the real Proton modulus test vector byte-for-byte`() {
        val modulusBytes = ProtonSrp.verifyAndExtractModulus(testModulusClearSign)
        assertEquals(testModulus, Base64.encode(modulusBytes))
    }

    @Test
    fun `rejects a modulus message with a tampered signature`() {
        // Flip one character inside the base64 signature body itself, not the
        // armor header/footer text, so the signature bytes actually change.
        val marker = "wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa"
        val corruptedMarker = "wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIb"
        require(testModulusClearSign.contains(marker)) { "test fixture drifted" }
        val tampered = testModulusClearSign.replace(marker, corruptedMarker)
        assertFailsWith<ProtonSrp.SrpException> { ProtonSrp.verifyAndExtractModulus(tampered) }
    }

    @Test
    fun `computeKeyPassword is deterministic and produces a 31-char ASCII passphrase`() {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }.let { Base64.encode(it) }
        val password = "correct horse battery staple".toByteArray()

        val first = ProtonSrp.computeKeyPassword(password, salt)
        val second = ProtonSrp.computeKeyPassword(password, salt)

        assertEquals(first, second)
        assertEquals(31, first.length)
        assertTrue(first.all { it.code in 33..126 })
    }

    @Test
    fun `computeKeyPassword changes with the password`() {
        val salt = Base64.encode(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val a = ProtonSrp.computeKeyPassword("password-one".toByteArray(), salt)
        val b = ProtonSrp.computeKeyPassword("password-two".toByteArray(), salt)
        assertTrue(a != b)
    }

    @Test
    fun `client proofs agree with an independently-implemented SRP server, using the real modulus`() {
        val random = SecureRandom()
        val password = "Password\nabc!!~~ä\r\n".toByteArray(Charsets.UTF_8)
        val rawSalt = ByteArray(10).also { random.nextBytes(it) }
        val saltB64 = Base64.encode(rawSalt)

        val modulus = FakeSrpServer.decodeRealModulus(testModulusClearSign)
        val hashedPassword = FakeSrpServer.hashPasswordForVerifier(password, rawSalt, modulus)
        val server = FakeSrpServer(modulus, hashedPassword, random)

        val challenge = server.generateChallenge()

        val proofs = ProtonSrp.generateProofs(
            version = 4,
            signedModulus = testModulusClearSign,
            serverEphemeralB64 = Base64.encode(challenge),
            saltB64 = saltB64,
            password = password,
            random = random,
        )

        val serverProof = server.verifyProofs(
            clientEphemeralB64 = proofs.clientEphemeral,
            clientProofB64 = proofs.clientProof,
        )

        assertEquals(proofs.expectedServerProof, Base64.encode(serverProof))
    }

    @Test
    fun `a wrong password produces a client proof the server rejects`() {
        val random = SecureRandom()
        val correctPassword = "correct-password".toByteArray()
        val wrongPassword = "wrong-password".toByteArray()
        val rawSalt = ByteArray(10).also { random.nextBytes(it) }

        val modulus = FakeSrpServer.decodeRealModulus(testModulusClearSign)
        val hashedPassword = FakeSrpServer.hashPasswordForVerifier(correctPassword, rawSalt, modulus)
        val server = FakeSrpServer(modulus, hashedPassword, random)
        val challenge = server.generateChallenge()

        val proofs = ProtonSrp.generateProofs(
            version = 4,
            signedModulus = testModulusClearSign,
            serverEphemeralB64 = Base64.encode(challenge),
            saltB64 = Base64.encode(rawSalt),
            password = wrongPassword,
            random = random,
        )

        // A real server rejects an invalid client proof outright rather than
        // returning a differing proof; FakeSrpServer mirrors that (see
        // go-srp's server.go VerifyProofs, which errors on proof mismatch).
        assertFailsWith<IllegalStateException> { server.verifyProofs(proofs.clientEphemeral, proofs.clientProof) }
    }
}
