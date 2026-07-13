package dev.carlsen.protondrive.sdk

/** Default no-setup-required [ProtonDriveTelemetry] used by [ProtonDriveSdk] unless a host supplies its own - logs to stdout/stderr, records no metrics. */
class ConsoleProtonDriveTelemetry : ProtonDriveTelemetry {
    override fun getLogger(name: String): Logger = ConsoleLogger(name)
    override fun recordMetric(event: MetricEvent) {}
}

private class ConsoleLogger(private val name: String) : Logger {
    override fun debug(message: String) {}
    override fun info(message: String) {}
    override fun warn(message: String) = println("[$name] WARN: $message")
    override fun error(message: String, error: Throwable?) {
        println("[$name] ERROR: $message${error?.let { " (${it.message})" } ?: ""}")
    }
}
