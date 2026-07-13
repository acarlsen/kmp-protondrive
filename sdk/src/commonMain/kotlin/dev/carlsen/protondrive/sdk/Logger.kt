package dev.carlsen.protondrive.sdk

/** Ports interface/telemetry.ts Logger. */
interface Logger {
    fun debug(message: String)
    fun info(message: String)
    fun warn(message: String)
    fun error(message: String, error: Throwable? = null)
}

/** Marker for metric events recorded via [ProtonDriveTelemetry.recordMetric]. */
interface MetricEvent {
    val eventName: String
}

/** Ports the Telemetry<T> class in telemetry.ts. */
interface ProtonDriveTelemetry {
    fun getLogger(name: String): Logger
    fun recordMetric(event: MetricEvent)
}

/** Recorded by [dev.carlsen.protondrive.sdk.apiService.DriveAPIService] when a retry succeeds. */
data class ApiRetrySucceededEvent(
    val failedAttempts: Int,
    val url: String,
    val previousError: String?,
) : MetricEvent {
    override val eventName: String = "apiRetrySucceeded"
}
