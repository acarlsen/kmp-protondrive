package dev.carlsen.protondrive.sdk.apiService

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.cookies.HttpCookies

internal actual fun defaultHttpClient(): HttpClient = HttpClient(CIO) {
    install(HttpTimeout)
    // Like the reference account client's shared CookieContainer: Proton sets session/anti-abuse
    // cookies on auth/info and expects them replayed on the following auth request.
    install(HttpCookies)
}
