package dev.carlsen.protondrive.sdk.auth

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import dev.carlsen.protondrive.sdk.crypto.SecureRandom

/**
 * Pure-Kotlin helpers filling gaps in ionspin's multiplatform bignum library (no arbitrary-
 * precision-exponent modPow, no primality test) needed to port Proton's SRP implementation
 * (see ProtonSrp.kt) away from java.math.BigInteger. These are plain algorithms with no platform
 * dependency, so - unlike the crypto engine classes - they don't need expect/actual.
 */

/** Non-negative remainder (0 <= result < modulus), unlike [BigInteger.rem]/[BigInteger.remainder], which keep the dividend's sign. */
internal fun BigInteger.mod(modulus: BigInteger): BigInteger {
    val r = this.remainder(modulus)
    return if (r.signum() < 0) r.add(modulus) else r
}

/**
 * Modular exponentiation with an arbitrary-precision exponent - ionspin's bignum only exposes
 * [BigInteger.pow] with an Int/Long exponent, insufficient for SRP's ~2048-bit exponents. Uses
 * the standard square-and-multiply method, walking the exponent's bits via [ModularBigInteger].
 */
internal fun BigInteger.modPow(exponent: BigInteger, modulus: BigInteger): BigInteger {
    require(modulus.signum() > 0) { "modulus must be positive" }
    if (exponent.signum() == 0) return BigInteger.ONE.mod(modulus)

    val creator = ModularBigInteger.creatorForModulo(modulus)
    var base = creator.fromBigInteger(this.mod(modulus))
    var result = creator.ONE
    val bitLength = exponent.bitLength()
    for (i in 0 until bitLength) {
        if (exponent.bitAt(i.toLong())) {
            result *= base
        }
        base *= base
    }
    return result.toBigInteger()
}

/**
 * Miller-Rabin probabilistic primality test, mirroring java.math.BigInteger.isProbablePrime -
 * ionspin's bignum has no built-in primality test.
 */
internal fun BigInteger.isProbablePrime(certainty: Int, random: SecureRandom): Boolean {
    val n = this
    val two = BigInteger.TWO
    val three = BigInteger.fromInt(3)
    if (n < two) return false
    if (n == two || n == three) return true
    if (!n.bitAt(0)) return false

    val nMinusOne = n - BigInteger.ONE
    var d = nMinusOne
    var r = 0
    while (!d.bitAt(0)) {
        d = d.shr(1)
        r++
    }

    witnessLoop@ for (iteration in 0 until certainty) {
        // Uniform-enough witness in [2, n-2] for a probabilistic test.
        val a = randomBigInteger(n.bitLength(), random).mod(n - three) + two
        var x = a.modPow(d, n)
        if (x == BigInteger.ONE || x == nMinusOne) continue@witnessLoop

        var witnessFound = false
        for (j in 1 until r) {
            x = x.modPow(two, n)
            if (x == nMinusOne) {
                witnessFound = true
                break
            }
        }
        if (!witnessFound) return false
    }
    return true
}

/** Uniformly random non-negative value in [0, 2^bitLength) - mirrors java.math.BigInteger(int numBits, Random rnd). */
internal fun randomBigInteger(bitLength: Int, random: SecureRandom): BigInteger {
    if (bitLength <= 0) return BigInteger.ZERO
    val numBytes = (bitLength + 7) / 8
    val bytes = ByteArray(numBytes)
    random.nextBytes(bytes)
    val excessBits = numBytes * 8 - bitLength
    if (excessBits > 0) {
        bytes[0] = (bytes[0].toInt() and (0xFF ushr excessBits)).toByte()
    }
    return BigInteger.fromByteArray(bytes, Sign.POSITIVE)
}
