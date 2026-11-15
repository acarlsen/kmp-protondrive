package dev.carlsen.protondrive.sdk.crypto

import io.ktor.http.fromHttpToGmtDate
import kotlin.concurrent.Volatile
import kotlin.time.Clock
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

/**
 * Proton's notion of "now", tracked as an offset from the device clock - the Kotlin
 * counterpart of `updateServerTime`/`serverTime` in Proton's crypto layer (see proton-sdk
 * commit 8a44654, `cli/src/api/serverTimeHook.ts`).
 *
 * Without it, keys and signatures are dated by the device clock: a device clock ahead of the
 * server produces keys/signatures "from the future" that the API rejects, and a device clock
 * behind the server rejects freshly-made signatures from other clients as not-yet-valid.
 * [dev.carlsen.protondrive.sdk.apiService.KtorProtonDriveHttpClient] feeds every response's
 * `x-pm-date` (or `Date`) header in via [updateFromHeaders].
 */
class ServerClock(private val deviceClock: Clock = Clock.System) {

    @Volatile
    private var offsetMillis: Long = 0

    /** Current server time - the device clock until the first [update]. */
    fun now(): Instant = deviceClock.now() + offsetMillis.milliseconds

    fun update(serverTime: Instant) {
        offsetMillis = (serverTime - deviceClock.now()).inWholeMilliseconds
    }

    /** Updates from `x-pm-date`, falling back to `Date`; headers are matched case-insensitively. Returns whether one parsed. */
    fun updateFromHeaders(headers: Map<String, String>): Boolean {
        val serverTime = parseHttpDate(headers.headerValue("x-pm-date"))
            ?: parseHttpDate(headers.headerValue("date"))
            ?: return false
        update(serverTime)
        return true
    }

    private fun Map<String, String>.headerValue(name: String): String? =
        entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

    private fun parseHttpDate(value: String?): Instant? {
        if (value.isNullOrBlank()) return null
        return runCatching { Instant.fromEpochMilliseconds(value.fromHttpToGmtDate().timestamp) }.getOrNull()
    }
}
