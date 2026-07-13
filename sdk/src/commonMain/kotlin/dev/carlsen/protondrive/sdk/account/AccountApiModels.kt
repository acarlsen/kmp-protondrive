package dev.carlsen.protondrive.sdk.account

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Ports the shapes GET /core/v4/users returns (coreTypes.ts's User/UserKey schemas). */
@Serializable
data class UsersResponse(@SerialName("Code") val code: Int, @SerialName("User") val user: UserDto)

@Serializable
data class UserDto(
    @SerialName("ID") val id: String,
    @SerialName("Email") val email: String? = null,
    @SerialName("Keys") val keys: List<UserKeyDto> = emptyList(),
)

@Serializable
data class UserKeyDto(
    @SerialName("ID") val id: String,
    @SerialName("PrivateKey") val privateKey: String,
    @SerialName("Primary") val primary: Int,
    @SerialName("Active") val active: Int,
)

/** Ports the shapes GET /core/v4/addresses returns. */
@Serializable
data class AddressesResponse(@SerialName("Code") val code: Int, @SerialName("Addresses") val addresses: List<AddressDto> = emptyList())

@Serializable
data class AddressDto(
    @SerialName("ID") val id: String,
    @SerialName("Email") val email: String,
    @SerialName("Keys") val keys: List<AddressKeyDto> = emptyList(),
)

@Serializable
data class AddressKeyDto(
    @SerialName("ID") val id: String,
    @SerialName("PrivateKey") val privateKey: String? = null,
    /** Present for "migrated" accounts: a PGP message containing this key's real passphrase, encrypted+signed with a User Key. */
    @SerialName("Token") val token: String? = null,
    @SerialName("Signature") val signature: String? = null,
    @SerialName("Primary") val primary: Int = 0,
)
