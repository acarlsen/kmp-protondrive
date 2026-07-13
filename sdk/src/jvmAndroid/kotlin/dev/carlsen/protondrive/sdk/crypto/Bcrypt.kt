package dev.carlsen.protondrive.sdk.crypto

import at.favre.lib.crypto.bcrypt.BCrypt

actual fun bcryptHash(cost: Int, salt: ByteArray, password: ByteArray): ByteArray =
    BCrypt.with(BCrypt.Version.VERSION_2Y).hash(cost, salt, password)
