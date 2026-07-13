package dev.carlsen.protondrive.sdk.crypto

expect fun sha1(data: ByteArray): ByteArray

expect fun sha256(data: ByteArray): ByteArray

expect fun sha512(data: ByteArray): ByteArray
