package dev.carlsen.protondrive.sdk.crypto

import java.security.MessageDigest

actual fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)

actual fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

actual fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)
