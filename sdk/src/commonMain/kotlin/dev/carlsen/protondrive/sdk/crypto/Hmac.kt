package dev.carlsen.protondrive.sdk.crypto

expect fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
