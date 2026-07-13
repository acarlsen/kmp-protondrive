package dev.carlsen.protondrive.cli

import dev.carlsen.protondrive.sdk.ProtonDriveAccount
import dev.carlsen.protondrive.sdk.ProtonDriveSdk
import dev.carlsen.protondrive.sdk.ProtonDriveSession
import kotlinx.coroutines.runBlocking

private const val APP_VERSION = "external-drive-kmp@0.1.0-alpha"

fun main(args: Array<String>) = runBlocking {
    println("Proton Drive Kotlin SDK - MVP CLI (login + list files)")
    println("This is a third-party, unofficial tool - not affiliated with or endorsed by Proton.")
    println()

    // Everything but appVersion has a sane default (console telemetry, the platform's OpenPGP
    // engine) - onSessionChanged is this CLI's only real integration point, since the SDK
    // deliberately never touches disk itself.
    val sdk = ProtonDriveSdk(
        appVersion = APP_VERSION,
        onSessionChanged = { session -> SessionStore.save(session.toStoredSession()) },
    )

    if (args.contains("--logout")) {
        val stored = SessionStore.load()
        if (stored == null) {
            println("No saved session found.")
            return@runBlocking
        }
        sdk.attachSession(stored.toProtonDriveSession())
        runCatching { sdk.logout() }
            .onFailure { println("(Server-side logout failed, clearing local session anyway: ${it.message})") }
        SessionStore.clear()
        println("Logged out.")
        return@runBlocking
    }

    var account: ProtonDriveAccount? = null

    val stored = SessionStore.load()
    if (stored != null) {
        println("Restoring saved session...")

        // A stale access token is refreshed transparently by the SDK (and, if that succeeds, the
        // resumed session is already re-saved via onSessionChanged by the time this returns) -
        // this only needs to fall back to a fresh login if refreshing wasn't possible/failed.
        account = try {
            sdk.restoreSession(stored.toProtonDriveSession())
        } catch (_: Exception) {
            null
        }

        if (account != null) {
            println("Resumed saved session: ${account.addresses.joinToString { it.email }}")
        } else {
            println("Saved session is no longer usable - logging in again.")
            SessionStore.clear()
        }
    }

    if (account == null) {
        val username = prompt("Username: ")
        require(username.isNotBlank()) { "Username must not be empty - is stdin connected to a terminal?" }
        val password = promptPassword("Password: ")
        require(password.isNotBlank()) { "Password must not be empty - is stdin connected to a terminal?" }

        println("Logging in...")
        val loginResult = sdk.login(username, password)

        if (loginResult.twoFactorRequired) {
            // FIDO2/security-key 2FA isn't supported - only TOTP codes and recovery codes.
            val code = prompt("Two-factor code: ")
            require(code.isNotBlank()) { "Two-factor code must not be empty" }
            sdk.submitTwoFactorCode(code)
        }

        println("Logged in as $username (UID ${loginResult.uid.take(8)}...)")

        println("Deriving mailbox key password and decrypting address keys...")
        account = sdk.finishLogin(password)
        requireNotNull(account) { "No address keys could be decrypted for this account" }
        println("Session saved - next run will skip login (use --logout or the 'l' shortcut to clear it).")
    }

    println("Resolved ${account.addresses.size} address(es): ${account.addresses.joinToString { it.email }}")

    println("Fetching Drive root folder...")
    val driveClient = account.driveClient
    val root = driveClient.getMyFilesRoot()

    FileBrowser(driveClient, onLogout = {
        runCatching { sdk.logout() }
        SessionStore.clear()
    }).run(root)
}

private fun StoredSession.toProtonDriveSession() = ProtonDriveSession(uid, accessToken, refreshToken, keyPassword)

private fun ProtonDriveSession.toStoredSession() = StoredSession(uid, accessToken, refreshToken, keyPassword)

private fun prompt(label: String): String {
    print(label)
    return readlnOrNull()?.trim().orEmpty()
}

private fun promptPassword(label: String): String {
    val console = System.console()
    return if (console != null) {
        String(console.readPassword(label))
    } else {
        // No real console (e.g. running via `gradle run`) - fall back to visible input.
        prompt(label)
    }
}
