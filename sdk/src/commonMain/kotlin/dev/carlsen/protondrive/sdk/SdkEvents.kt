package dev.carlsen.protondrive.sdk

/** Ports internal/sdkEvents.ts. */
enum class SdkEvent {
    TransfersPaused,
    TransfersResumed,
    RequestsThrottled,
    RequestsUnthrottled,
}

class SdkEvents(telemetry: ProtonDriveTelemetry) {
    private val logger = telemetry.getLogger("sdk-events")
    private val listeners = mutableMapOf<SdkEvent, MutableList<() -> Unit>>()

    fun addListener(event: SdkEvent, callback: () -> Unit): () -> Unit {
        listeners.getOrPut(event) { mutableListOf() }.add(callback)
        return { listeners[event]?.remove(callback) }
    }

    fun transfersPaused() = emit(SdkEvent.TransfersPaused)
    fun transfersResumed() = emit(SdkEvent.TransfersResumed)
    fun requestsThrottled() = emit(SdkEvent.RequestsThrottled)
    fun requestsUnthrottled() = emit(SdkEvent.RequestsUnthrottled)

    private fun emit(event: SdkEvent) {
        val callbacks = listeners[event]
        if (callbacks.isNullOrEmpty()) {
            logger.debug("No listeners for event: $event")
            return
        }
        logger.debug("Emitting event: $event")
        callbacks.forEach { it() }
    }
}
