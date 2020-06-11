package pcclark4.kntlm

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Ntlm {

    private object MessageType {
        const val NEGOTIATE = 1
        const val CHALLENGE = 2
        const val AUTHENTICATE = 3
    }

    private object NegotiateFlag {
        const val EXTENDED_SESSION_SECURITY = 0b00000000_00001000_00000000_00000000
        const val ALWAYS_SIGN = 0b00000000_00000000_10000000_00000000
        const val NTLM = 0b00000000_00000000_00000010_00000000
        const val REQUEST_TARGET = 0b00000000_00000000_00000000_00000100
        const val UNICODE = 0b00000000_00000000_00000000_00000001
    }

    private object AvId {
        const val EOL = 0
        const val TIMESTAMP = 7
    }

    private class ChallengeInfo(
        val challenge: ByteArray,
        val timestamp: ULong, // LDAP time
        val targetInfo: ByteArray
    )

    private const val HMAC_MD5_ALGORITHM_NAME = "HmacMD5"
    private const val NEGOTIATE_MESSAGE_LENGTH = 16
    private const val LM_LENGTH = 24
    private const val LM_OFFSET = 88
    private const val PROOF_INPUT_LENGTH = 28

    private val SIGNATURE by lazy {
        ByteBuffer.allocate(8) // NTLM signature is 8 bytes
            .put(Charsets.US_ASCII.encode("NTLMSSP"))
            .put(0) // Null terminator
            .array()
    }

    fun getNegotiateMessage(): ByteArray {
        val flags = NegotiateFlag.EXTENDED_SESSION_SECURITY or
            NegotiateFlag.ALWAYS_SIGN or
            NegotiateFlag.NTLM or
            NegotiateFlag.REQUEST_TARGET or
            NegotiateFlag.UNICODE

        val buffer = ByteBuffer.allocate(NEGOTIATE_MESSAGE_LENGTH)
        buffer.order(ByteOrder.LITTLE_ENDIAN)
        return buffer.put(SIGNATURE)
            .putInt(MessageType.NEGOTIATE)
            .putInt(flags)
            .array()
    }

    fun getAuthenticateMessage(creds: NtlmCredentials, challengeMessage: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(500)
        buffer.order(ByteOrder.LITTLE_ENDIAN)

        buffer.put(SIGNATURE)
        buffer.putInt(MessageType.AUTHENTICATE)

        buffer.putSecurityBuffer(LM_LENGTH, LM_OFFSET)

        val ntlmV2 = generateNtlmV2(creds, challengeMessage)
        val ntlmV2Offset = LM_OFFSET + LM_LENGTH
        buffer.putSecurityBuffer(ntlmV2.size, ntlmV2Offset)

        val domainBytes = creds.domain.toByteArray(Charsets.UTF_16LE)
        val domainOffset = ntlmV2Offset + ntlmV2.size
        buffer.putSecurityBuffer(domainBytes.size, domainOffset)

        val userBytes = creds.user.toByteArray(Charsets.UTF_16LE)
        val userOffset = domainOffset + domainBytes.size
        buffer.putSecurityBuffer(userBytes.size, userOffset)

        val workstationBytes = creds.workstation.toByteArray(Charsets.UTF_16LE)
        val workstationOffset = userOffset + userBytes.size
        buffer.putSecurityBuffer(workstationBytes.size, workstationOffset)

        buffer.skip(8) // session key
        buffer.skip(4) // flags, these do not need to be sent in final authenticate message
        buffer.skip(8) // reserved
        buffer.skip(16) // mic

        // Payload
        buffer.skip(LM_LENGTH)
        buffer.put(ntlmV2)
        buffer.put(domainBytes)
        buffer.put(userBytes)
        buffer.put(workstationBytes)

        return buffer.array()
    }

    private fun parseChallengeMessage(challengeMessage: ByteArray): ChallengeInfo {
        val buffer = ByteBuffer.wrap(challengeMessage)
        buffer.order(ByteOrder.LITTLE_ENDIAN)

        var timeStamp: ULong = 0u

        val signature = ByteArray(8)
        buffer.get(signature)
        require(signature.contentEquals(SIGNATURE)) {
            "Unexpected NTLM signature"
        }

        val messageType = buffer.int
        require(messageType == MessageType.CHALLENGE) {
            "NTLM message is not a challenge message"
        }

        buffer.skip(8) // skip target name
        buffer.skip(4) // skip flags

        val challenge = ByteArray(8)
        buffer.get(challenge)

        buffer.skip(8) // reserved

        val targetInfoLen = buffer.short
        buffer.short
        val targetInfoOffset = buffer.int

        buffer.skip(8) // version

        buffer.position(targetInfoOffset)
        val targetInfoBytes = ByteArray(targetInfoLen.toInt())
        buffer.get(targetInfoBytes)

        val targetInfoBuffer = ByteBuffer.wrap(targetInfoBytes)
        targetInfoBuffer.order(ByteOrder.LITTLE_ENDIAN)

        var avId = targetInfoBuffer.short.toInt()
        while (avId != AvId.EOL) {
            val avLen = targetInfoBuffer.short
            if (avId == AvId.TIMESTAMP) {
                timeStamp = targetInfoBuffer.long.toULong()
            } else {
                targetInfoBuffer.skip(avLen.toInt())
            }

            avId = targetInfoBuffer.short.toInt()
        }

        return ChallengeInfo(challenge, timeStamp, targetInfoBytes)
    }

    private fun generateNtlmV2(creds: NtlmCredentials, challengeMessage: ByteArray): ByteArray {
        val clientNonce = ByteArray(8)
        Random(System.currentTimeMillis()).nextBytes(clientNonce)

        val v2hash = generateNtlmV2Hash(creds)
        val challengeInfo = parseChallengeMessage(challengeMessage)
        val proofInput = generateProofInput(challengeInfo.timestamp, clientNonce)
        val proof = generateNtlmProofV2(v2hash, challengeInfo.challenge, proofInput, challengeInfo.targetInfo)

        val footer = byteArrayOf(0, 0, 0, 0) // Never changes and means nothing
        return proof.plus(proofInput).plus(challengeInfo.targetInfo).plus(footer)
    }

    private fun generateNtlmV2Hash(creds: NtlmCredentials): ByteArray {
        val ntlmHash = Md4().digest(creds.password.toByteArray(Charsets.UTF_16LE))
        val userDomain = "${creds.user.toUpperCase(Locale.ROOT)}${creds.domain}"

        val md5 = Mac.getInstance(HMAC_MD5_ALGORITHM_NAME)
        md5.init(SecretKeySpec(ntlmHash, HMAC_MD5_ALGORITHM_NAME))
        val hashInput = userDomain.toByteArray(Charsets.UTF_16LE)
        return md5.doFinal(hashInput)
    }

    private fun generateProofInput(timestamp: ULong, clientNonce: ByteArray): ByteArray {
        // The header and footer never change and there's nothing about them that needs to be known other than they are
        // required
        val header = byteArrayOf(1, 1, 0, 0, 0, 0, 0, 0)
        val footer = byteArrayOf(0, 0, 0, 0)

        val buffer = ByteBuffer.allocate(PROOF_INPUT_LENGTH)
        buffer.order(ByteOrder.LITTLE_ENDIAN)

        buffer.put(header)
        buffer.putLong(timestamp.toLong())
        buffer.put(clientNonce)
        buffer.put(footer)

        return buffer.array()
    }

    private fun generateNtlmProofV2(
        v2Hash: ByteArray,
        serverChallenge: ByteArray,
        proofInput: ByteArray,
        targetInfo: ByteArray
    ): ByteArray {
        val md5 = Mac.getInstance(HMAC_MD5_ALGORITHM_NAME)
        md5.init(SecretKeySpec(v2Hash, HMAC_MD5_ALGORITHM_NAME))
        val footer = byteArrayOf(0, 0, 0, 0) // Never changes and means nothing
        val hashInput = serverChallenge.plus(proofInput).plus(targetInfo).plus(footer)
        return md5.doFinal(hashInput)
    }

    private fun ByteBuffer.putSecurityBuffer(length: Int, offset: Int) {
        putShort(length.toShort())
        putShort(length.toShort())
        putInt(offset)
    }

    private fun ByteBuffer.skip(numBytes: Int): ByteBuffer {
        return this.position(this.position() + numBytes) as ByteBuffer
    }
}