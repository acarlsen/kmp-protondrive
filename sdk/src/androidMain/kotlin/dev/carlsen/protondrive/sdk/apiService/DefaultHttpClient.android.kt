package dev.carlsen.protondrive.sdk.apiService

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout

internal actual fun defaultHttpClient(): HttpClient = HttpClient(OkHttp) {
    install(HttpTimeout)
}
