package dev.carlsen.protondrive.sdk.crypto

/** Bcrypt (2y variant) password hash, returning the full `$2y$<cost>$<salt><hash>` encoded string as bytes. */
expect fun bcryptHash(cost: Int, salt: ByteArray, password: ByteArray): ByteArray
