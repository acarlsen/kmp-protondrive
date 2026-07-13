package dev.carlsen.protondrive.sdk.auth

import dev.carlsen.protondrive.sdk.apiService.DriveAPIService
import dev.carlsen.protondrive.sdk.errors.ProtonDriveError

/**
 * Orchestrates Proton's password login flow, mirroring authViaPassword() in
 * incubating/account/js/src/auth.ts - itself thin glue around ProtonSrp,
 * since (as that file's comments and the root README's "Scope and
 * Limitations" both note) authentication is intentionally not part of the
 * Drive SDK's own scope.
 *
 * Unlike auth.ts's `Auth` class, this does not hold session state itself:
 * [loginWithPassword] returns the new session, and the caller is expected to
 * update whatever [dev.carlsen.protondrive.apiService.KtorProtonDriveHttpClient] it
 * passed into [apiService] to start attaching that session's headers *before*
 * calling [fetchKeySalts] - matching this SDK's existing rule that session
 * management belongs to the host, not the library.
 */
class ProtonAuth(private val apiService: DriveAPIService) {

    suspend fun getAuthInfo(username: String): AuthInfoResponse =
        apiService.post("core/v4/auth/info", AuthInfoRequest(username = username))

    suspend fun submitProof(
        username: String,
        srpSession: String,
        clientEphemeral: String,
        clientProof: String,
    ): AuthResponse = apiService.post(
        "core/v4/auth",
        AuthRequest(
            username = username,
            srpSession = srpSession,
            clientEphemeral = clientEphemeral,
            clientProof = clientProof,
        ),
    )

    /** Requires an authenticated request - call only after wiring the session from [loginWithPassword] into the http client. */
    suspend fun fetchKeySalts(): List<KeySalt> =
        apiService.get<KeySaltsResponse>("core/v4/keys/salts").keySalts

    /**
     * Performs the full SRP login handshake and returns the new session.
     * Does not fetch the mailbox key password - see [deriveMailboxPassword].
     */
    suspend fun loginWithPassword(username: String, password: String): LoginResult {
        val info = getAuthInfo(username)
        val passwordBytes = password.toByteArray(Charsets.UTF_8)

        val proofs = ProtonSrp.generateProofs(
            version = info.version,
            signedModulus = info.modulus,
            serverEphemeralB64 = info.serverEphemeral,
            saltB64 = info.salt,
            password = passwordBytes,
        )

        val response = submitProof(
            username = username,
            srpSession = info.srpSession,
            clientEphemeral = proofs.clientEphemeral,
            clientProof = proofs.clientProof,
        )

        if (response.serverProof != proofs.expectedServerProof) {
            throw ProtonDriveError("SRP server proof verification failed - possible MITM or server bug")
        }

        return LoginResult(
            uid = response.uid,
            accessToken = response.accessToken,
            refreshToken = response.refreshToken,
            twoFactorRequired = (response.twoFactor ?: 0) != 0,
        )
    }

    /**
     * Submits a TOTP code (or recovery code) to elevate a session's scope
     * after [loginWithPassword] reports [LoginResult.twoFactorRequired].
     * Requires an authenticated request - wire the session from
     * [loginWithPassword] into the http client *before* calling this, same as
     * [fetchKeySalts]. FIDO2/security-key 2FA is not supported.
     */
    suspend fun submitTwoFactorCode(code: String): TwoFactorResponse =
        apiService.post("core/v4/auth/2fa", TwoFactorRequest(twoFactorCode = code))

    /**
     * Derives the passphrase needed to decrypt the user's private key. Call
     * [fetchKeySalts] with an http client already authenticated for the
     * session from [loginWithPassword], then pass the result here.
     */
    fun deriveMailboxPassword(password: String, keySalts: List<KeySalt>): String {
        val salt = keySalts.firstNotNullOfOrNull { it.keySalt }
            ?: throw ProtonDriveError("No KeySalt returned for this user")
        return ProtonSrp.computeKeyPassword(password.toByteArray(Charsets.UTF_8), salt)
    }

    /**
     * Exchanges a refresh token for a new access token, mirroring
     * refreshSessionIfPossible() in incubating/account/js/src/apiClient.ts.
     * Send this request while the *expiring* session's uid/access token are
     * still attached (same as the JS reference does) - only swap the host's
     * session holder over to the returned tokens after this succeeds. Does
     * not require [deriveMailboxPassword] to be re-run: the mailbox key
     * password is independent of the access/refresh token pair.
     */
    suspend fun refreshSession(refreshToken: String): LoginResult {
        val response = apiService.post<RefreshRequest, RefreshResponse>(
            "core/v4/auth/refresh",
            RefreshRequest(refreshToken = refreshToken),
        )
        return LoginResult(
            uid = response.uid,
            accessToken = response.accessToken,
            refreshToken = response.refreshToken ?: refreshToken,
            twoFactorRequired = false,
        )
    }

    /**
     * Revokes the session server-side. Requires an authenticated request -
     * wire the session into the http client before calling this, same as
     * [fetchKeySalts]. Does not clear any session state the host is holding
     * (e.g. a persisted session file) - that remains the host's
     * responsibility, same as everywhere else in this SDK.
     */
    suspend fun logout() {
        apiService.delete<Unit, LogoutResponse>("core/v4/auth")
    }
}
