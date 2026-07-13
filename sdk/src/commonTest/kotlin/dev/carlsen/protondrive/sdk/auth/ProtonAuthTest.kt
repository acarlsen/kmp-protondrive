package dev.carlsen.protondrive.sdk.auth

import dev.carlsen.protondrive.sdk.SdkEvents
import dev.carlsen.protondrive.sdk.apiService.DriveAPIService
import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpBlobRequest
import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpClient
import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpJsonRequest
import dev.carlsen.protondrive.sdk.apiService.ProtonDriveHttpResponse
import dev.carlsen.protondrive.sdk.crypto.SecureRandom
import dev.carlsen.protondrive.sdk.errors.ProtonDriveError
import dev.carlsen.protondrive.sdk.testing.FakeTelemetry
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Exercises ProtonAuth.loginWithPassword end-to-end against a fake
 * /core/v4/auth/info + /core/v4/auth server backed by FakeSrpServer, the
 * same real go-srp modulus test vector used in ProtonSrpTest. This is the
 * piece most likely to have "glue" bugs (wrong field/endpoint name) even
 * though the SRP math and HTTP layer are separately covered elsewhere.
 */
@OptIn(ExperimentalEncodingApi::class)
class ProtonAuthTest {

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

    private class JsonResponse(override val status: Int, private val body: JsonElement) : ProtonDriveHttpResponse {
        override val statusText: String = ""
        override val headers: Map<String, String> = emptyMap()
        override suspend fun json(): JsonElement = body
        override suspend fun bodyBytes(): ByteArray = error("not used")
    }

    /** A minimal but real Proton auth server for "testuser" / "correct-password", backed by FakeSrpServer. */
    private class FakeAuthServer(
        random: SecureRandom,
        password: String,
        private val twoFactorEnabled: Boolean = false,
    ) : ProtonDriveHttpClient {
        private val json = Json { ignoreUnknownKeys = true }
        private val rawSalt = ByteArray(10).also { random.nextBytes(it) }
        private val modulus = FakeSrpServer.decodeRealModulus(testModulusClearSignStatic)
        private val hashedPassword = FakeSrpServer.hashPasswordForVerifier(password.toByteArray(), rawSalt, modulus)
        private val server = FakeSrpServer(modulus, hashedPassword, random)
        private lateinit var challenge: ByteArray
        private var twoFactorVerified = false

        override suspend fun fetchJson(request: ProtonDriveHttpJsonRequest): ProtonDriveHttpResponse = when {
            request.url.endsWith("core/v4/auth/info") -> {
                challenge = server.generateChallenge()
                JsonResponse(
                    200,
                    json.encodeToJsonElement(
                        AuthInfoResponse(
                            code = 1000,
                            version = 4,
                            modulus = testModulusClearSignStatic,
                            serverEphemeral = Base64.encode(challenge),
                            salt = Base64.encode(rawSalt),
                            srpSession = "test-session-id",
                        ),
                    ),
                )
            }
            request.url.endsWith("core/v4/auth") -> {
                val body = json.decodeFromJsonElement<AuthRequest>(requireNotNull(request.json))
                val serverProof = server.verifyProofs(body.clientEphemeral, body.clientProof)
                JsonResponse(
                    200,
                    json.encodeToJsonElement(
                        AuthResponse(
                            code = 1000,
                            uid = "test-uid",
                            accessToken = "test-access-token",
                            refreshToken = "test-refresh-token",
                            serverProof = Base64.encode(serverProof),
                            twoFactor = if (twoFactorEnabled) 1 else 0,
                        ),
                    ),
                )
            }
            request.url.endsWith("core/v4/auth/2fa") -> {
                // Session-header attachment (x-pm-uid/Authorization) is KtorProtonDriveHttpClient's
                // job, not DriveAPIService's/ProtonAuth's, so it isn't exercised at this layer.
                val body = json.decodeFromJsonElement<TwoFactorRequest>(requireNotNull(request.json))
                if (body.twoFactorCode != "123456") {
                    JsonResponse(422, json.encodeToJsonElement(mapOf("Code" to 2028, "Error" to "Invalid verification code")))
                } else {
                    twoFactorVerified = true
                    JsonResponse(200, json.encodeToJsonElement(TwoFactorResponse(code = 1000, scope = "full")))
                }
            }
            else -> error("Unexpected request: ${request.url}")
        }

        override suspend fun fetchBlob(request: ProtonDriveHttpBlobRequest) = error("not used")
    }

    private companion object {
        // Referenced from the nested FakeAuthServer class, which can't see the outer test-instance property.
        val testModulusClearSignStatic = """
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
    }

    private fun newAuth(password: String, twoFactorEnabled: Boolean = false): ProtonAuth {
        val telemetry = FakeTelemetry()
        val httpClient = FakeAuthServer(SecureRandom(), password, twoFactorEnabled)
        val apiService = DriveAPIService(
            telemetry = telemetry,
            sdkEvents = SdkEvents(telemetry),
            httpClient = httpClient,
            baseUrl = "https://api.proton.example",
            language = "en",
        )
        return ProtonAuth(apiService)
    }

    @Test
    fun `logs in with the correct password and verifies the server proof`() = runTest {
        val auth = newAuth("correct-password")

        val result = auth.loginWithPassword("testuser", "correct-password")

        assertEquals("test-uid", result.uid)
        assertEquals("test-access-token", result.accessToken)
        assertEquals("test-refresh-token", result.refreshToken)
        assertEquals(false, result.twoFactorRequired)
    }

    @Test
    fun `reports twoFactorRequired and accepts a correct TOTP code`() = runTest {
        val auth = newAuth("correct-password", twoFactorEnabled = true)

        val result = auth.loginWithPassword("testuser", "correct-password")
        assertEquals(true, result.twoFactorRequired)

        val twoFactorResponse = auth.submitTwoFactorCode("123456")
        assertEquals(1000, twoFactorResponse.code)
    }

    @Test
    fun `rejects a wrong TOTP code`() = runTest {
        val auth = newAuth("correct-password", twoFactorEnabled = true)
        auth.loginWithPassword("testuser", "correct-password")

        assertFailsWith<Exception> { auth.submitTwoFactorCode("000000") }
    }

    @Test
    fun `a wrong password fails the login instead of silently succeeding`() = runTest {
        val auth = newAuth("correct-password")

        assertFailsWith<Exception> { auth.loginWithPassword("testuser", "wrong-password") }
    }

    @Test
    fun `deriveMailboxPassword picks the first available KeySalt`() {
        val auth = newAuth("correct-password")
        val salt = ProtonSrp.generateKeySalt()

        val keyPassword = auth.deriveMailboxPassword("correct-password", listOf(KeySalt(id = "1", keySalt = salt)))

        assertEquals(31, keyPassword.length)
    }

    @Test
    fun `deriveMailboxPassword fails clearly when no KeySalt is present`() {
        val auth = newAuth("correct-password")
        assertFailsWith<ProtonDriveError> { auth.deriveMailboxPassword("correct-password", emptyList()) }
    }
}
