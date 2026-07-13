package dev.carlsen.protondrive.sdk.crypto

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPSessionKey
import org.pgpainless.util.SessionKey
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Interop regression test for Drive content blocks in the RFC 9580 *v2 SEIPD* (AEAD) flavor
 * that Proton's current clients upload (alongside v6 PKESK ContentKeyPackets - see
 * OpenPgpJsInteropTest). Fixture generated with OpenPGP.js v6: a bare SEIPDv2 packet
 * (AES-256/GCM, no PKESK) encrypted directly with a known session key - exactly what
 * downloadFile feeds decryptWithSessionKey. Before SEIPDv2 support, these blocks were
 * silently passed through *undecrypted*, writing ciphertext to the destination file.
 */
class SeipdV2BlockTest {

    private val crypto = PGPainlessOpenPGPCrypto()

    @Test
    fun decryptsSeipdV2BlockWithSessionKey() {
        val rawKey = Base64.getDecoder().decode(SESSION_KEY_BASE64)
        val sessionKey = SessionKeyHandle(SessionKey(PGPSessionKey(SymmetricKeyAlgorithmTags.AES_256, rawKey)))
        val result = crypto.decryptWithSessionKey(Base64.getDecoder().decode(ENCRYPTED_BLOCK_BASE64), sessionKey)
        assertContentEquals(Base64.getDecoder().decode(PLAINTEXT_BASE64), result.data)
    }

    private companion object {
        const val SESSION_KEY_BASE64 = "ZiFrcMjQ2BRDrmCOORuPlYJMIqTMaut6GvH9Tql1wb4="
        val PLAINTEXT_BASE64 =
            "aGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBm" +
            "cm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBT" +
            "RUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIg" +
            "QUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJs" +
            "b2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBo" +
            "ZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZy" +
            "b20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNF" +
            "SVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBB" +
            "RUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxv" +
            "Y2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhl" +
            "bGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJv" +
            "bSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJ" +
            "UER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFF" +
            "QUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9j" +
            "ayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVs" +
            "bG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9t" +
            "IGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQ" +
            "RHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVB" +
            "RCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2Nr" +
            "IC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxs" +
            "byBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20g" +
            "YSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBE" +
            "djIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFE" +
            "IGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sg" +
            "LSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxv" +
            "IGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBh" +
            "IFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2" +
            "MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQg" +
            "YmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAt" +
            "IGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8g" +
            "ZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEg" +
            "U0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYy" +
            "IEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBi" +
            "bG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0g" +
            "aGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBm" +
            "cm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBT" +
            "RUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIg" +
            "QUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJs" +
            "b2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBo" +
            "ZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZy" +
            "b20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNF" +
            "SVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBB" +
            "RUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhlbGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxv" +
            "Y2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJvbSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIGhl" +
            "bGxvIGZyb20gYSBTRUlQRHYyIEFFQUQgYmxvY2sgLSBoZWxsbyBmcm9tIGEgU0VJUER2MiBBRUFEIGJsb2NrIC0gaGVsbG8gZnJv" +
            "bSBhIFNFSVBEdjIgQUVBRCBibG9jayAtIA=="
        val ENCRYPTED_BLOCK_BASE64 =
            "0usCCQMMWUjU5y6kdk398X0JhyBrgklahyvJJIIsgBfvTryQU21QJXVAOqmXr9/OW7qHFkkR71Xfi/mQaDEJphsl0WHrWx0NyZzI" +
            "M1WGrbfbOo6GhJOwigtuYGFNwertHoqBYXGJiMi8iVQgEPfDtsUbEBQ8S/WhzPFfg7zuJEt5D++1YvumeNNNbDUDz8sdfMROxSYk" +
            "+Ca1ELZp1jvWrwTRNsFNrQsbXgHIeIhhz4KsdTKatV/W87o8IxPrT8+PA26I7C+Wg/siq+DY/R0AB+fbCZ4XKAvL8hU1zB3JC/wf" +
            "DPJ901XAmP8enG/xm5Z1yyq3dv854oBx4aWnl1ZIHYiZseFdpnrMZEUUKEPruYiy0gWqZYMEWZP3BUEKryN0KNfGAxJltcTwMJAs" +
            "H0pedoaWnI9x1MxuEPLkBNJAqJHwnT0OFftWmCgXAy3a31RNr111Vmlv8JgWjKN30KxqqC2zr3eGut+RDiofzHv5BIE9gWDtum9Z" +
            "Ul0IthWpuxWCYubnDwqG1ze3KcaO1z+hr1KJDW4X8LghbfbaRd8xoWamDK3Lo3FPMv+h3IPiMx4R1L5M+VMxDFu2rUe1wGnsL7ft" +
            "VYbty2MuLJH6dHJsyfwVQWOKpvB5SrItfVJ8QYwnI2tUWz672/tJDg0BFXYLVTHOeAsY/fYDTK1UTfsvaTOu/oOSs9aJB4o7c6C/" +
            "KxvHah9XSKSR6du6UYKAiJ0eChPWILCsAQ4CjzYfn7/jfZKZvoKct1Hy7+O7ZaNyISAGb0Fk/pM2hzXmZn3MMXvS5+XvqppQxES/" +
            "ei6OfxUMGyg/qFXlF9INWqMZ/yViz6PqoMdCt1W3DUyK/KDQmwfV0ShdeyUuBKZBen/fO+VzBIIm6NVRb4pjE+b41d9Uzb2gC43D" +
            "23Uke64bfLV/ElO4vQFoNcjt/9bETtL5BTYbcIEQ1VnwcO207EPIdf2V/G+5AT+tRFsjXTbBrBuBfkSyrGuIzswdR1EH1I7l6XkA" +
            "aiPVGvZfK1MlY/Xlwbv85Vr60VcSN1FBAZIJ4fJDueLvz0Yvlh3gR1kH77aEz55EtU1vojC2qmX2C0QAbw0ez3YOpdJqYyScibAt" +
            "eZJujd4ch39l/k0UF0MpVhRgQhovcxPJdJGGqn6GztoQckkUIoutrwVYHqOLrOFncBcAP772D5AXjvyMV51uvZkw95nKvV9CPHVL" +
            "bgZpbyN1hvjVsaV9FA1h4w3Il2FwI1WkPkPx7LjsynnRNoYWyBg7NGkP3lFa7YHtzW0/XbGfTWt4sNERnke5CcG8bqIhBiuYLvOf" +
            "viMIA1qjfuFgFx+2yU62pbjjBtWw37uxQZ80c0wU30I2+Fx8I3GeW7lQl4B1/BeWFZQ7V8zr/USjv1t5xwtTp1iVwT6SLLUZHtnB" +
            "Albmpu/Ceuh/KnImM7pItcAvB2XzwCX941u1RhW2KMQDBXEeIwaNUwkQrHtX6wzT9eDWPIh76mkH7GP9omiki98RR+ocx8uw7zZt" +
            "TxS4ON/cXgaqBCsuE8zuuW8snGSLP7pDWh+MGK+3Jc+6Jg1WwGHggry5CRQy1wlo1ARmqLJmrpWnV8W70ncEJ+46notInoqwO3pr" +
            "EKZf4rs+u56qMC9V0pxopSD9fH3NwzT8S7L4LL8QGofQv0Z6DRw+8dLXL18X4us7FrSOTGFoU5tSAfzcHDraWI4W7SS/vQakgATj" +
            "Hc8DX5PJ3GeghwgX9iuDd1AmppTF3s3ZFzKxaWks4tYuf8WAmcPAN74u96Qyy4ngfRcgIQSBPsv1qgPOJxBcsCR0aIhZSQ4rL1xu" +
            "e1hlzHz+T2fzEXCLSAt+gfesDeTy/pPw8T0v/FqTrNT3grcEwOKcLuzacHmph8I6TZ2IdUEdza5HuObaQWZyQFgQTiI+I9o9jBmF" +
            "xsAWdalC4v8J6MaXQi6y/shNZjPnjk6ZBix6s9IYdg9FXcKYxaEgcgsLquM68HPhHfsJ81GlFPY7fDMlkrR+YgTHmVCLkYvEVYey" +
            "YV/sJLA8NROZm8BEP+WHMa7tW2UWC7uPV84bsAOoRtNtSVajCrMByu3PWTVjD8ulCYvl7DmjBl0iST4ONyS35/TMXS415Tt/F/8w" +
            "/7e6BHw98z2qXqzYtr/jC4rO2BWhlyVlhDSSGNyK6GfGPGh/auwQGkTQR+5WZmJpCFrg1TVfpKNlk+C8J3ho7kEQnPW2EcQJdE/y" +
            "Of8T7iIJH5E8t+X38V6iTiN+QC69K3HvijtZHj2fE+FQAJhWY9EzXagQrAOqPAUeFQeLzq8sBa3WwvGuBGWrs0QZ5IxG0iW/ntlW" +
            "3eaIH76KTh7CzAVzGoBbaYZ2BhlRpkSEKC3SUpdnbrqIqRJgWO5Q2huMPR3iDWzV7qqkiaXZMuIemocg8zhMFc1GPLB0hWZ4HREq" +
            "HnESrGsp3PMVCN3SjL8MhnypIA339Byq1UlLDpAD2JXwLuoaadUElWcGmovnN0QAQKbA0o4xTx+vA5BeO8cy3pAmB9du3ZRy8Vif" +
            "UTIBaqJT5c0fqsfoXGLIIhHnXIvMUVDg/9TeBsWMPE2sP/1TlboKY6bFhrWFPOlc7ZS1p1B9jUb5cnh0Yt7tteXcnMBZIA8LhDHf" +
            "I60XUURBKrfaf/fFNcLpQjAY0imYC835ms4zscIhOtSnKRtrCikMdf1oI6vfF4WnKUw6kblcjCHmA70+nBJBflVPfbvf1GELMHoJ" +
            "EL4JldpupkHL8i6zvE5JOIFVEZI/GxUXOMTVADOmuOxnIz5YLiS8R7gz/jBoIrH3BFqb/mp+D9lwXZrnNGQcVxqLi0Yuqan/QRDl" +
            "P5MZcetDiNdblmuZ8B6X+pgWYvEcDiVpQLdLiHdU3CZv87D9qxZaBjEBlviDbX/Ylh70fYAULJWcTzy9zVRI6t22qXuTt4VEd9QU" +
            "I+9Nnh0YHtHjRO+9GFa/aZBOxLzLCU0pe3fDq6aqVT03MBnPh04Y1H7EEZdp4nvUvfObC2S29qvQeC5DTe79lhVn+/mFryhBpEBZ" +
            "d7uBiFb9W30iul1zNA+tFe3dFGgbffizv5x5HdtxvWJnlLD/tKntVaVuJbUYtZurJS0sHq4PFUd0DGdDfyMQSth5eg3xhxV9yt2W" +
            "atiNJAnX2y82D7eEPT4PPqb/Q94iQ3c+ij+YUuFv2BBCqG/x4eilKkgZEYcYoOqUHzClU8Jw4HJebomG634dfnjcADbVpk6QIr6/" +
            "P9yDpS3zSBcjEAGoK9oKDEBOpZqA1W1kSSmAoJ27JQEFRssPZg21dN/rD/t6uiIme6NNkI1sM0aKI4IYISPesJu9nFGJ8DBvhjkX" +
            "oIa81lojxc0QZzPdVv9XP+kjOB58UrajxIKAkD/kK96eP3H2KqPLflr3Xa120jc2tpyTiG0uxylArvjiL81LyQz2o1+ldH29OJ+t" +
            "TU+nUsuVKm9x0n41ZANHnutY+929ahXKpfHBCelOHx0ej3Z0Qlkj5HuzbaZQmOcJaE38ob39AZmThytEgHQhum1zZoqpO9O8b8r7" +
            "9rXJxocgOD0PfABa+X/T4u21u2+oIIbwqKGrLfjc6hIGw5NE29x/2eofVqvWSX96jgJ8VL9pcFjjC8XZbw9J1HZyysMonYPrEmLW" +
            "sqYVNcsBwUraox7ZXii4jJCbitBR5wNDNXcJTP380pJ2WdYily+h2pzPFQ7T2XPGjvEcXzoG7XGGieiv9O0tkG/8CLNMDyRFhJtE" +
            "DRoCnTdau65XE3qGYGEVLUpaE5RBi0g+GdXtdT58upOUeYjXMoHTJ1Nbku1aiDNBrlZcLDdIqpVsYlUZu+VO8mDGm78fPb6TL8R3" +
            "S9eN5/kRHumO8WGi3tyfgVsJmTu+IDv9qmWCQjiWMX1svDRNTBeBb6LO/O8OarN4Qy42OPOudn6N1+5vsPVgQ9Fjo5gZmAq1tZQC" +
            "bevkwsMEYUmnr7pyRogAKIsRRo/Z0jQI+MUv8kVFTostlLH+1MDplEZWvorVb1FYSxB53kXLE8N5F7/flIhsw1PWL1N4Q7E3aLQ+" +
            "eZ33IKrmTJq+o6Q8xdsFu6lOtR7jvBlOx8u8yuBIcD/FbCOiGjAg8UIdiYjrMD5PmaFMBHLMHz9EBPGzvGm6n9de23rVZuOA8SdV" +
            "dtCTSvem552jyddvhEucJd+05Vn0Fr7nQHfIFxWuVXa5B7KQsRd7WAvGyvka6DBPGOrOJwoXjO2m9qa/wKnyrG7BkF7C5Ntb0Os2" +
            "arXGLzgnyY03/lkZuIYpFNdNtFNmEnL6HzVJ7h36ZIv055CL7oCrP/Vl8xBERQeqHTX538cBhLC3f6O27jC6Fk3FQ5sUVs8NBMqV" +
            "Q6byMol0WgMPWITfcyp0VhqQS/Nm7XtvaV/oMq/Xk1lkATe1H6IY1Uo2Ju5C0B0K/sZfmKaSuRofg8ELW71f+BkCTOmIEA329OCa" +
            "9B45/jnbaeLjVV/vnk92ATb9c0ZHAkCrkALDbOaWs3wnynaDLZXjv61QTskgEwdCDN8jwVf+9oZXp/IaqOY1L6mIlU7l6MgdYqF+" +
            "Jx8djfMVB9F0BfuphLNYBYJJXdxbg3zHj5/LNtCB7CqZMT5GSu3YZG691ZivLZ6cadKp+chsBrOq/Dxf90WtUAyVTU2K5sDtHdDg" +
            "jG0TCtGUYJ+rPgbXqV3yiD2k6R2Easi7ksuY7MSnMA=="
    }
}
