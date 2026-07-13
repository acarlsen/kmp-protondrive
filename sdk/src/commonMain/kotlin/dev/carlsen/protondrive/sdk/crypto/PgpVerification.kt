package dev.carlsen.protondrive.sdk.crypto

class PgpVerificationException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Verifies an armored, signed-only (cleartext or inline) PGP message against a known armored
 * public key and returns the verified message body. Throws [PgpVerificationException] if the
 * key/message can't be parsed or the signature doesn't verify.
 */
expect fun verifyClearsignedMessage(armoredMessage: String, armoredPublicKey: String): ByteArray
