package dev.carlsen.protondrive.sdk.account

import dev.carlsen.protondrive.sdk.apiService.DriveAPIService
import dev.carlsen.protondrive.sdk.crypto.OpenPGPCrypto
import dev.carlsen.protondrive.sdk.crypto.PrivateKeyHandle
import dev.carlsen.protondrive.sdk.crypto.PublicKeyHandle
import dev.carlsen.protondrive.sdk.crypto.VerifyStatus
import dev.carlsen.protondrive.sdk.crypto.toPublicKeyHandle
import dev.carlsen.protondrive.sdk.errors.ProtonDriveError

data class ResolvedAddress(
    val addressId: String,
    val email: String,
    /** Decrypted address private keys, primary first. Empty if none could be decrypted. */
    val keys: List<PrivateKeyHandle>,
)

/**
 * Resolves a user's address private keys, ported from
 * incubating/account/js/src/addresses.ts's getUserData()/getAddressKey().
 *
 * Two address-key protection schemes exist and are both handled, matching
 * the reference: "migrated" accounts (the common case today) protect each
 * AddressKey with a `Token` - a PGP message containing that key's real
 * passphrase, encrypted to and signed by a separate User Key - while legacy
 * accounts protect the AddressKey directly with the login-derived key
 * password. User Keys themselves are always decrypted directly with the
 * login-derived key password (see [dev.carlsen.protondrive.sdk.auth.ProtonAuth.deriveMailboxPassword]).
 */
class AddressKeyProvider(
    private val apiService: DriveAPIService,
    private val crypto: OpenPGPCrypto,
) {
    private var cachedUserKeys: List<PrivateKeyHandle>? = null

    suspend fun getOwnAddresses(userKeyPassword: String): List<ResolvedAddress> {
        val userKeys = getUserPrivateKeys(userKeyPassword)
        val userPublicKeys = userKeys.map { it.toPublicKeyHandle() }

        val response = apiService.get<AddressesResponse>("core/v4/addresses")
        return response.addresses.map { address ->
            val keys = address.keys
                .sortedByDescending { it.primary }
                .mapNotNull { key -> runCatching { resolveAddressKey(key, userKeyPassword, userKeys, userPublicKeys) }.getOrNull() }
            ResolvedAddress(addressId = address.id, email = address.email, keys = keys)
        }
    }

    suspend fun getOwnPrimaryAddress(userKeyPassword: String): ResolvedAddress {
        val addresses = getOwnAddresses(userKeyPassword)
        return addresses.firstOrNull { it.keys.isNotEmpty() }
            ?: throw ProtonDriveError("No usable address key found for this account")
    }

    private suspend fun getUserPrivateKeys(userKeyPassword: String): List<PrivateKeyHandle> {
        cachedUserKeys?.let { return it }

        val response = apiService.get<UsersResponse>("core/v4/users")
        val keys = response.user.keys
            .sortedByDescending { it.primary }
            .mapNotNull { key -> runCatching { crypto.decryptKey(key.privateKey, userKeyPassword) }.getOrNull() }

        if (keys.isEmpty()) throw ProtonDriveError("No usable User Key could be decrypted")
        cachedUserKeys = keys
        return keys
    }

    private fun resolveAddressKey(
        key: AddressKeyDto,
        userKeyPassword: String,
        userKeys: List<PrivateKeyHandle>,
        userPublicKeys: List<PublicKeyHandle>,
    ): PrivateKeyHandle {
        val privateKey = requireNotNull(key.privateKey) { "Address key ${key.id} has no PrivateKey" }

        if (key.token == null) {
            // Legacy (non-migrated) account: protected directly by the login key password.
            return crypto.decryptKey(privateKey, userKeyPassword)
        }

        val signature = requireNotNull(key.signature) { "Address key ${key.id} has a Token but no Signature" }
        val result = crypto.decryptArmoredAndVerifyDetachedWithKey(
            armoredData = key.token,
            armoredSignature = signature,
            decryptionKeys = userKeys,
            verificationKeys = userPublicKeys,
        )
        if (result.verified != VerifyStatus.OK) {
            throw ProtonDriveError("Address key ${key.id} Token signature verification failed")
        }
        val passphrase = result.data.toString(Charsets.UTF_8)
        return crypto.decryptKey(privateKey, passphrase)
    }
}
