package dev.carlsen.protondrive.sdk

import dev.carlsen.protondrive.sdk.account.AddressKeyProvider
import dev.carlsen.protondrive.sdk.account.ResolvedAddress
import dev.carlsen.protondrive.sdk.apiService.DriveAPIService
import dev.carlsen.protondrive.sdk.apiService.KtorProtonDriveHttpClient
import dev.carlsen.protondrive.sdk.apiService.ProtonSession
import dev.carlsen.protondrive.sdk.apiService.SessionRefreshingHttpClient
import dev.carlsen.protondrive.sdk.auth.LoginResult
import dev.carlsen.protondrive.sdk.auth.ProtonAuth
import dev.carlsen.protondrive.sdk.auth.TwoFactorResponse
import dev.carlsen.protondrive.sdk.crypto.defaultOpenPGPCrypto
import dev.carlsen.protondrive.sdk.nodes.DriveClient

private const val DEFAULT_BASE_URL = "https://drive-api.proton.me"

/** Everything a host needs to persist to resume a session later without redoing SRP login. */
data class ProtonDriveSession(
    val uid: String,
    val accessToken: String,
    val refreshToken: String?,
    val keyPassword: String,
)

/** A logged-in account ready to use: its resolved (usable) address keys, and a [driveClient] wired up to operate as them. */
data class ProtonDriveAccount(
    val addresses: List<ResolvedAddress>,
    val driveClient: DriveClient,
)

/**
 * Single entry point for a host app: owns the HTTP transport, session-refresh plumbing, PGP
 * engine, and auth/address-key bootstrapping that [DriveAPIService]/[ProtonAuth]/
 * [AddressKeyProvider]/[KtorProtonDriveHttpClient] would otherwise need wiring together by hand.
 * Sane defaults cover everything except [appVersion] - a console-logging [telemetry] and the
 * platform's [defaultOpenPGPCrypto] engine (not host-configurable - swapping PGP engines is a
 * platform concern, not a per-app one) - so a third-party app only needs to override what it
 * actually cares about.
 *
 * Session *persistence* is still the host's job, same as every class this wraps: [onSessionChanged]
 * is invoked with a fresh [ProtonDriveSession] whenever the tokens change, whether from
 * [finishLogin] or a transparent mid-session refresh triggered by an expired access token (see
 * [SessionRefreshingHttpClient]).
 */
class ProtonDriveSdk(
    appVersion: String,
    baseUrl: String = DEFAULT_BASE_URL,
    language: String = "en",
    private val telemetry: ProtonDriveTelemetry = ConsoleProtonDriveTelemetry(),
    private val onSessionChanged: (ProtonDriveSession) -> Unit = {},
    /** See [DriveClient]'s parameter of the same name - hosts on slow crypto platforms (Android) may opt out of the per-block upload self-check. */
    private val verifyBlocksBeforeUpload: Boolean = true,
) {
    private val crypto = defaultOpenPGPCrypto()

    private var session: ProtonSession? = null
    private var refreshToken: String? = null
    private var keyPassword: String? = null

    private var auth: ProtonAuth

    private val apiService = DriveAPIService(
        telemetry = telemetry,
        sdkEvents = SdkEvents(telemetry),
        httpClient = SessionRefreshingHttpClient(
            delegate = KtorProtonDriveHttpClient(appVersion = appVersion, sessionProvider = { session }),
            getRefreshToken = { refreshToken },
            refresh = { token -> auth.refreshSession(token) },
            onRefreshed = { refreshed -> applyRefreshedSession(refreshed) },
        ),
        baseUrl = baseUrl,
        language = language,
    ).also { auth = ProtonAuth(it) }

    private val addressKeyProvider = AddressKeyProvider(apiService, crypto)

    /** Attaches a previously-persisted session without validating it - prefer [restoreSession], which also resolves an account. */
    fun attachSession(session: ProtonDriveSession) {
        this.session = ProtonSession(uid = session.uid, accessToken = session.accessToken)
        this.refreshToken = session.refreshToken
        this.keyPassword = session.keyPassword
    }

    /**
     * Resumes a persisted [session]: attaches it and decrypts the account's address keys. A stale
     * access token is refreshed transparently. Returns null if the account has no usable address
     * keys (e.g. a wrong/stale [ProtonDriveSession.keyPassword]) - callers should fall back to
     * [login] in that case, same as for
     * [dev.carlsen.protondrive.sdk.errors.UnauthorizedError] (thrown when even a refresh isn't
     * possible, e.g. no/invalid refresh token).
     */
    suspend fun restoreSession(session: ProtonDriveSession): ProtonDriveAccount? {
        attachSession(session)
        return resolveAccount(session.keyPassword)
    }

    /**
     * Performs the SRP login handshake. If [LoginResult.twoFactorRequired], call
     * [submitTwoFactorCode] next; either way, call [finishLogin] afterward to derive the mailbox
     * key password and resolve the account - that doesn't happen automatically since it needs the
     * plaintext [password] again, which this class doesn't otherwise hold onto.
     */
    suspend fun login(username: String, password: String): LoginResult {
        val result = auth.loginWithPassword(username, password)
        session = ProtonSession(uid = result.uid, accessToken = result.accessToken)
        refreshToken = result.refreshToken
        return result
    }

    suspend fun submitTwoFactorCode(code: String): TwoFactorResponse = auth.submitTwoFactorCode(code)

    /**
     * Derives the mailbox key password from [password] and resolves the account, completing
     * [login]. Returns null if no address key could be decrypted with it.
     */
    suspend fun finishLogin(password: String): ProtonDriveAccount? {
        val currentSession = requireNotNull(session) { "finishLogin() called before login()" }
        val keySalts = auth.fetchKeySalts()
        val derivedKeyPassword = auth.deriveMailboxPassword(password, keySalts)
        val account = resolveAccount(derivedKeyPassword) ?: return null

        keyPassword = derivedKeyPassword
        onSessionChanged(
            ProtonDriveSession(
                uid = currentSession.uid,
                accessToken = currentSession.accessToken,
                refreshToken = refreshToken,
                keyPassword = derivedKeyPassword,
            ),
        )
        return account
    }

    suspend fun logout() = auth.logout()

    private suspend fun resolveAccount(keyPassword: String): ProtonDriveAccount? {
        val usable = addressKeyProvider.getOwnAddresses(keyPassword).filter { it.keys.isNotEmpty() }
        if (usable.isEmpty()) return null
        return ProtonDriveAccount(usable, DriveClient(apiService, crypto, usable, telemetry, verifyBlocksBeforeUpload))
    }

    private fun applyRefreshedSession(refreshed: LoginResult) {
        session = ProtonSession(uid = refreshed.uid, accessToken = refreshed.accessToken)
        refreshToken = refreshed.refreshToken
        keyPassword?.let { password ->
            onSessionChanged(
                ProtonDriveSession(
                    uid = refreshed.uid,
                    accessToken = refreshed.accessToken,
                    refreshToken = refreshed.refreshToken,
                    keyPassword = password,
                ),
            )
        }
    }
}
