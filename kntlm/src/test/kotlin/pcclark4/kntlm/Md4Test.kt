package pcclark4.kntlm

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class Md4Test {

    @Test
    fun testMd4() {
        val input = "asdf1234"
        val md4 = Md4().digest(input.toByteArray(Charsets.UTF_8))

        // Expected hash from http://practicalcryptography.com/hashes/md4-hash/
        // b8c2feb8d151fe3a66e84d8b69c96676
        val expected = ubyteArrayOf(
                0xb8u, 0xc2u, 0xfeu, 0xb8u,
                0xd1u, 0x51u, 0xfeu, 0x3au,
                0x66u, 0xe8u, 0x4du, 0x8bu,
                0x69u, 0xc9u, 0x66u, 0x76u
        ).toByteArray()

        Assertions.assertArrayEquals(md4, expected)
    }
}