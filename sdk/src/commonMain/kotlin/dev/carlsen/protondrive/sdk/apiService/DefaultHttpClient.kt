package dev.carlsen.protondrive.sdk.apiService

import io.ktor.client.HttpClient

/**
 * Platform-default Ktor client for [KtorProtonDriveHttpClient]: OkHttp on Android (Conscrypt
 * hardware TLS, HTTP/2, the platform-standard connection pooling), CIO on plain JVM (pure
 * Kotlin, no extra native dependencies - plenty fast for the CLI). Every actual must install
 * [io.ktor.client.plugins.HttpTimeout]: [KtorProtonDriveHttpClient] sets per-request timeouts
 * through that plugin.
 */
internal expect fun defaultHttpClient(): HttpClient
