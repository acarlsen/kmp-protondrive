package dev.carlsen.protondrive.sdk.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

class ServerClockTest {

    private val deviceNow = Instant.parse("2026-11-15T12:00:00Z")
    private val deviceClock = object : Clock {
        override fun now() = deviceNow
    }

    @Test
    fun `defaults to the device clock before any update`() {
        assertEquals(deviceNow, ServerClock(deviceClock).now())
    }

    @Test
    fun `x-pm-date shifts now by the observed offset`() {
        val clock = ServerClock(deviceClock)
        assertTrue(clock.updateFromHeaders(mapOf("x-pm-date" to "Sun, 15 Nov 2026 11:00:00 GMT")))
        assertEquals(deviceNow - 1.hours, clock.now())
    }

    @Test
    fun `x-pm-date wins over Date and header names are case-insensitive`() {
        val clock = ServerClock(deviceClock)
        clock.updateFromHeaders(
            mapOf(
                "Date" to "Sun, 15 Nov 2026 10:00:00 GMT",
                "X-PM-Date" to "Sun, 15 Nov 2026 13:00:00 GMT",
            ),
        )
        assertEquals(deviceNow + 1.hours, clock.now())
    }

    @Test
    fun `falls back to Date when x-pm-date is missing or unparseable`() {
        val clock = ServerClock(deviceClock)
        clock.updateFromHeaders(mapOf("x-pm-date" to "garbage", "date" to "Sun, 15 Nov 2026 14:00:00 GMT"))
        assertEquals(deviceNow + 2.hours, clock.now())
    }

    @Test
    fun `no usable header leaves the offset untouched`() {
        val clock = ServerClock(deviceClock)
        clock.update(deviceNow + 1.hours)
        assertFalse(clock.updateFromHeaders(mapOf("date" to "not a date")))
        assertEquals(deviceNow + 1.hours, clock.now())
    }
}
