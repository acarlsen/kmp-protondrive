package dev.carlsen.protondrive.sdk.crypto

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Interop regression test against OpenPGP.js v5 - the engine Proton's own web client uses.
 * The fixture below was generated with openpgp@5: a curve25519 node key locked with a
 * passphrase, plus a bare-PKESK ContentKeyPacket (`openpgp.encryptSessionKey(format:
 * 'binary')`) wrapping a known session key - exactly the shape Drive stores for a file
 * uploaded through Proton's web client. Guards the "Content key packet checksum verification
 * failed" failure observed on real files uploaded by Proton's clients.
 */
class OpenPgpJsInteropTest {

    private val crypto = PGPainlessOpenPGPCrypto()

    @Test
    fun decryptsOpenPgpJsContentKeyPacket() {
        val handle = crypto.decryptKey(OPENPGP_JS_ARMORED_KEY, PASSPHRASE)
        val sessionKey = crypto.decryptSessionKey(Base64.getDecoder().decode(CONTENT_KEY_PACKET_BASE64), listOf(handle))
        assertContentEquals(Base64.getDecoder().decode(SESSION_KEY_BASE64), sessionKey.rawBytes)
    }

    /** Same shape but generated with OpenPGP.js v4.10 - what Proton's web client shipped ~2020-2022, so long-lived accounts hold files in this flavor. */
    @Test
    fun decryptsOpenPgpJsV4ContentKeyPacket() {
        val handle = crypto.decryptKey(OPENPGP_JS_V4_ARMORED_KEY, PASSPHRASE)
        val sessionKey = crypto.decryptSessionKey(Base64.getDecoder().decode(V4_CONTENT_KEY_PACKET_BASE64), listOf(handle))
        assertContentEquals(Base64.getDecoder().decode(V4_SESSION_KEY_BASE64), sessionKey.rawBytes)
    }

    /**
     * A *v6* PKESK (RFC 9580: encrypted payload is [session key][2-byte checksum] with no
     * leading algorithm octet) for the same v4 curve25519Legacy key - what Proton's current
     * clients write, observed live on real Drive files ("PKESK v6, public-key algorithm 18,
     * session info 34 bytes"). Generated with OpenPGP.js v6's packet-level API.
     */
    @Test
    fun decryptsV6ContentKeyPacketForLegacyKey() {
        val handle = crypto.decryptKey(OPENPGP_JS_ARMORED_KEY, PASSPHRASE)
        val sessionKey = crypto.decryptSessionKey(Base64.getDecoder().decode(V6_CONTENT_KEY_PACKET_BASE64), listOf(handle))
        assertContentEquals(Base64.getDecoder().decode(V6_SESSION_KEY_BASE64), sessionKey.rawBytes)
    }

    /** Same shape but generated with gopenpgp v2.10 - the engine Proton's Android/iOS apps use. */
    @Test
    fun decryptsGopenPgpContentKeyPacket() {
        val handle = crypto.decryptKey(GOPENPGP_ARMORED_KEY, PASSPHRASE)
        val sessionKey = crypto.decryptSessionKey(Base64.getDecoder().decode(GO_CONTENT_KEY_PACKET_BASE64), listOf(handle))
        assertContentEquals(Base64.getDecoder().decode(GO_SESSION_KEY_BASE64), sessionKey.rawBytes)
    }

    private companion object {
        const val PASSPHRASE = "test-passphrase-1234567890abcdef"
        const val SESSION_KEY_BASE64 = "gkx05pfDawNmH9vVUQJLt8aNJg6sXGX+QBZFGobaumM="
        const val CONTENT_KEY_PACKET_BASE64 =
            "wV4DjeX3lWXrg7oSAQdAJ/hLuX2oazT66GDXoKLsP1HjBPXxra2M5bxDUF/iICswWyMBaoJ7VwftzPIUb2SUg6RNb5NrTUBU9zhio+T3aF/52VyWu9hLP7mXt9RLZzPu"
        const val V6_SESSION_KEY_BASE64 = "aELeH6V7myEHnkmOJOyjY2k/zMdkBlm9qQZv/XnG9uc="
        const val V6_CONTENT_KEY_PACKET_BASE64 =
            "wWwGFQSeOB/vh0fZKaMAfEGN5feVZeuDuhIBB0Ca9L+A/C04zPLdVWGyFFDgz2vQwxFYYmf/thFtFgmJejCGYRpAoOu6JbcVvQQU7Zo1gmhAnFKUglgJG8eTqTxVpWWaVDGWIgInLvnrrUwN5dU="
        const val V4_SESSION_KEY_BASE64 = "YmTvDiTB5UXPK8fmxgTgpuImwGtiQ1D+5gWlpBnB4H0="
        const val V4_CONTENT_KEY_PACKET_BASE64 =
            "wV4D68PFIBrmEx8SAQdACjXl1X6gkF7QxU9Am3RX7mHkCAQPz5sFQMpyJzezOUowfTYC2XoL9xKiIum7diqY3yed+Ib1t9229mYa+CXSwLwMZ1b531j9701feMbTZDJZ"
        val OPENPGP_JS_V4_ARMORED_KEY = """
            -----BEGIN PGP PRIVATE KEY BLOCK-----
            Version: OpenPGP.js v4.10.11
            Comment: https://openpgpjs.org

            xYYEalS9hBYJKwYBBAHaRw8BAQdAzxZdOSb4Sp3E/Co+YIC1ErCatk5SbFnX
            qYQLIEBlEVD+CQMIiFeOY9JDDFLgT0+u+37V0VRFGxe4MHMUuJyLImwBOrRV
            h/xgNc5EqRw9mAwulghJZb896tpCl6IXJfB0nB5QzMHiYOMFQgusZj9MqOeB
            A80JRHJpdmUga2V5wo8EEBYKACAFAmpUvYQGCwkHCAMCBBUICgIEFgIBAAIZ
            AQIbAwIeAQAhCRBsOBC/NmOrexYhBNyhNesF03hb6K3Kumw4EL82Y6t7SUQA
            /i4bzZhhak8ofFS+lFoU11rCarGnIEMzH96t4usJcTYnAP4gQCQcW1PACSBt
            tjsyF39xbmY9Dq7mnm1YJYEQXiFNDseLBGpUvYQSCisGAQQBl1UBBQEBB0Bi
            3TAFFRRQagZNeWnBNH9u8YEb21FzWnvaqmxcGpxwFQMBCAf+CQMIxxheZ/53
            AGPgcyZHvTvsM4FPvyieiIVChO8jnu6hk4M79sGlU6Ndvg6ST/CSdio7O7n3
            aI10xAQY9n83hIe0rb2Q1wG4nZQlYOIfHIDAp8J4BBgWCAAJBQJqVL2EAhsM
            ACEJEGw4EL82Y6t7FiEE3KE16wXTeFvorcq6bDgQvzZjq3vR9AEAqAS6nLNo
            FeYbX8/Lo3SinPvB5TvICXQh8IfswMZNgrEA/1Ld8FySyaM62XFMjJNidv2t
            C3WGPCk0oNCEE2ALm78A
            =zT7K
            -----END PGP PRIVATE KEY BLOCK-----
        """.trimIndent()
        const val GO_SESSION_KEY_BASE64 = "zylkJ1cqrJYlyjdbzUSKICgd3NN9Hdk7l/YFyYw2o5o="
        const val GO_CONTENT_KEY_PACKET_BASE64 =
            "wV4DbIT+qxGZ9XsSAQdAAUG0eVEfBzsMPq+KkBTzE6FxKSJUrjBda+w3Nope3Ssw7/DnV4/Nvye9PZJzpvqNORb5/jpXVcUvrmiUz3OMFw5JIAKZydtSYr2LCYCNz2e2"
        val GOPENPGP_ARMORED_KEY = """
            -----BEGIN PGP PRIVATE KEY BLOCK-----
            Comment: https://gopenpgp.org
            Version: GopenPGP 2.10.0

            xYYEalS9HxYJKwYBBAHaRw8BAQdA8bv/f0pRenNc1pAa2kcKjZ67CFTO3BB94zOr
            cV4jmcL+CQMIz2v6mZIMYDZgX30vmpwi5oiJImel4nUVPnrA12WIkmJnR5v8WaTm
            bRPf+CS6JyWTSpJE6MLmP/rZdXRU/UREGd8uNyAFPSEvU64PcQXVfs0JRHJpdmUg
            a2V5wr8EExYIAHEFgmpUvR8DCwkHCRAXJuoVXTfwZzUUAAAAAAAcABBzYWx0QG5v
            dGF0aW9ucy5vcGVucGdwanMub3JnoqgwSLkCK0KfxE6fF3JbhQIVCAMWAAICGQEC
            mwMCHgEWIQSBHDw5n+U5YgjhI00XJuoVXTfwZwAARm4BAOc/sPKDrWtCVKnqfxww
            76lCgawHRzn4ZzJzTZ9O4huJAQD5z7Eh9HGVAXc68Hp4wjBEEVjQc1Q36vXqolpB
            ynRpDMeLBGpUvR8SCisGAQQBl1UBBQEBB0BL0biXrOQZ+r82WCTnnnvbaeKsh6vG
            VE6m+eT5omU/JgMBCgn+CQMIyodHdswU7wFg+mveydf8hIltwUEDVc/1Teb4jmhR
            aqa7WEQZ9ZRa8xac+w9CIVPpU2vPHyc38N6wneOGBEIYts2cnTMvLWhsspGixFDI
            0sKuBBgWCABgBYJqVL0fCRAXJuoVXTfwZzUUAAAAAAAcABBzYWx0QG5vdGF0aW9u
            cy5vcGVucGdwanMub3Jnf1nKqXLCkv3/0/JEYNv/AgKbDBYhBIEcPDmf5TliCOEj
            TRcm6hVdN/BnAABKwwEAq8Pg/OnGuKNh8iF6IKJqVnCILYHIcwN8zD5Z93ZMhRcB
            ANUqGPqF/ba4YrHIh3wTDTBgs464YduAyZRllivNBF4N
            =+32G
            -----END PGP PRIVATE KEY BLOCK-----
        """.trimIndent()
        val OPENPGP_JS_ARMORED_KEY = """
            -----BEGIN PGP PRIVATE KEY BLOCK-----

            xYYEalS8eBYJKwYBBAHaRw8BAQdArKjvY9vN2DA8F/Pjr3+2ZbkLExeHqhcY
            heMp/6XO3WT+CQMIiHW4vijLbu7g0dck2qdJfGmMmg1mDpj/daROYTmYrExc
            +KhVGnnH5sPT1rpyGuz7FHEg+L4TUoq1CdC4jcHsiRg9DF/WZWxTR2dmYBY2
            L80JRHJpdmUga2V5wowEEBYKAD4FgmpUvHgECwkHCAmQoGN0FAPP5ZEDFQgK
            BBYAAgECGQECmwMCHgEWIQSllf5FFLTEHv/qJsSgY3QUA8/lkQAAd1oBANCW
            m4UcVwoYulng+Or2AXVDr5+Af31JX6oRps9fagYOAQD3kVGJck/0N9AjtfNA
            y2NlT8ot9F3rA/IEVJ6EJyfaBMeLBGpUvHgSCisGAQQBl1UBBQEBB0DXTrIY
            OAgL9Yd2jpF8YqQgDlUtd/8VD7BtQmMnQ9HEYAMBCAf+CQMITxveTGHd7pPg
            OPXBGSzEKkLq7j4qCcU7k7Kvp6Vg+XZbPjmr/xYtuvVZbwclr/h9kFVZP9BI
            Het6QK2KDzxqFOVzKvAw0Y6xvS60tRsXcMJ4BBgWCgAqBYJqVLx4CZCgY3QU
            A8/lkQKbDBYhBKWV/kUUtMQe/+omxKBjdBQDz+WRAADzJAEAh2IKXSD+u+xe
            h9UjInACK4Lh12JvOQv7cAD1p9D3Ss8A/R6JhRzh9pJH1A9rvTMaaxXpazY5
            cPW97h/5sy/sUxQO
            =RuMW
            -----END PGP PRIVATE KEY BLOCK-----
        """.trimIndent()
    }
}
