package dev.carlsen.protondrive.sdk.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Ports the request/response shapes accountApi.ts uses for POST /core/v4/auth/info. */
@Serializable
data class AuthInfoRequest(
    @SerialName("Intent") val intent: String = "Proton",
    @SerialName("Username") val username: String,
)

@Serializable
data class AuthInfoResponse(
    @SerialName("Code") val code: Int,
    @SerialName("Version") val version: Int,
    @SerialName("Modulus") val modulus: String,
    @SerialName("ServerEphemeral") val serverEphemeral: String,
    @SerialName("Salt") val salt: String,
    @SerialName("SRPSession") val srpSession: String,
)

/** Ports the request/response shapes for POST /core/v4/auth. */
@Serializable
data class AuthRequest(
    @SerialName("Username") val username: String,
    @SerialName("SRPSession") val srpSession: String,
    @SerialName("ClientEphemeral") val clientEphemeral: String,
    @SerialName("ClientProof") val clientProof: String,
    @SerialName("PersistentCookies") val persistentCookies: Int = 1,
    @SerialName("Payload") val payload: Map<String, String> = emptyMap(),
)

@Serializable
data class AuthResponse(
    @SerialName("Code") val code: Int,
    @SerialName("UID") val uid: String,
    @SerialName("AccessToken") val accessToken: String,
    @SerialName("RefreshToken") val refreshToken: String? = null,
    @SerialName("ServerProof") val serverProof: String? = null,
    /** Deprecated alias for `2FA.Enabled`: 0=disabled, 1=OTP, 2=FIDO2, 3=both. Simpler to parse than the nested `"2FA"` object, which would need a `@SerialName` just to be a legal Kotlin identifier at all. */
    @SerialName("TwoFactor") val twoFactor: Int? = null,
)

/** Ports the request/response shapes for POST /core/v4/auth/refresh. */
@Serializable
data class RefreshRequest(
    @SerialName("ResponseType") val responseType: String = "token",
    @SerialName("GrantType") val grantType: String = "refresh_token",
    @SerialName("RefreshToken") val refreshToken: String,
)

@Serializable
data class RefreshResponse(
    @SerialName("Code") val code: Int,
    @SerialName("UID") val uid: String,
    @SerialName("AccessToken") val accessToken: String,
    @SerialName("RefreshToken") val refreshToken: String? = null,
)

/** Ports the response shape for DELETE /core/v4/auth (logout / session revocation). */
@Serializable
data class LogoutResponse(@SerialName("Code") val code: Int)

/** Ports the request/response shapes for POST /core/v4/auth/2fa (submitted after a successful password login when TwoFactor != 0). */
@Serializable
data class TwoFactorRequest(@SerialName("TwoFactorCode") val twoFactorCode: String)

@Serializable
data class TwoFactorResponse(
    @SerialName("Code") val code: Int,
    @SerialName("Scope") val scope: String? = null,
    @SerialName("Scopes") val scopes: List<String> = emptyList(),
)

/** Ports the response shape for GET /core/v4/keys/salts. */
@Serializable
data class KeySalt(
    @SerialName("ID") val id: String? = null,
    @SerialName("KeySalt") val keySalt: String? = null,
)

@Serializable
data class KeySaltsResponse(
    @SerialName("Code") val code: Int,
    @SerialName("KeySalts") val keySalts: List<KeySalt> = emptyList(),
)

data class LoginResult(
    val uid: String,
    val accessToken: String,
    val refreshToken: String?,
    /** True if a second POST /core/v4/auth/2fa call (see [dev.carlsen.protondrive.sdk.auth.ProtonAuth.submitTwoFactorCode]) is required before other endpoints will accept this session. */
    val twoFactorRequired: Boolean,
)
