package dev.carlsen.protondrive.cli

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/**
 * Everything the CLI needs to skip password login on the next run: the
 * uid/access/refresh tokens from [dev.carlsen.protondrive.sdk.auth.ProtonAuth.loginWithPassword]
 * (or [dev.carlsen.protondrive.sdk.auth.ProtonAuth.refreshSession]), plus the
 * mailbox key password from [dev.carlsen.protondrive.sdk.auth.ProtonAuth.deriveMailboxPassword]
 * needed to decrypt address keys again without redoing SRP.
 *
 * The SDK never touches disk or holds session state itself - persistence is
 * entirely a CLI/host concern, by design (see ProtonAuth/DriveAPIService docs).
 */
@Serializable
data class StoredSession(
    val uid: String,
    val accessToken: String,
    val refreshToken: String?,
    val keyPassword: String,
)

/**
 * Persists [StoredSession] to a file under the user's home directory. The
 * file contains the mailbox key password, which decrypts the account's
 * private keys - treat it like a credential. Restricted to owner-only
 * permissions where the filesystem supports it (POSIX; best-effort
 * elsewhere, e.g. Windows).
 */
object SessionStore {
    private val json = Json { ignoreUnknownKeys = true }
    private val file = File(System.getProperty("user.home"), ".config/kmp-protondrive/session.json")

    fun load(): StoredSession? {
        if (!file.exists()) return null
        return runCatching { json.decodeFromString<StoredSession>(file.readText()) }.getOrNull()
    }

    fun save(session: StoredSession) {
        file.parentFile?.mkdirs()
        file.writeText(json.encodeToString(session))
        runCatching { Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------")) }
    }

    fun clear() {
        file.delete()
    }
}
