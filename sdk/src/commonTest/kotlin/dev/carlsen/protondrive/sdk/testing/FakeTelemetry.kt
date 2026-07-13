package dev.carlsen.protondrive.sdk.testing

import dev.carlsen.protondrive.sdk.Logger
import dev.carlsen.protondrive.sdk.MetricEvent
import dev.carlsen.protondrive.sdk.ProtonDriveTelemetry

class FakeLogger : Logger {
    val messages = mutableListOf<String>()
    override fun debug(message: String) { messages += "DEBUG: $message" }
    override fun info(message: String) { messages += "INFO: $message" }
    override fun warn(message: String) { messages += "WARN: $message" }
    override fun error(message: String, error: Throwable?) { messages += "ERROR: $message" }
}

class FakeTelemetry : ProtonDriveTelemetry {
    val logger = FakeLogger()
    val recordedEvents = mutableListOf<MetricEvent>()

    override fun getLogger(name: String): Logger = logger

    override fun recordMetric(event: MetricEvent) {
        recordedEvents += event
    }
}
