package pcclark4.kntlm

import java.util.*

object NtlmHttp {

    const val WWW_AUTH_HEADER = "WWW-Authenticate"
    const val NTLM_AUTH_OPTION = "NTLM"
    const val AUTH_HEADER = "Authorization"

    fun getNegotiateHeader(): Pair<String, String> {
        return Pair(AUTH_HEADER, "NTLM ${Base64.getEncoder().encodeToString(Ntlm.getNegotiateMessage())}")
    }

    fun getAuthenticateHeader(creds: NtlmCredentials, challengeMessageBase64: String): Pair<String, String> {
        val challengeMessage = Base64.getDecoder().decode(challengeMessageBase64)
        val authMsg = Ntlm.getAuthenticateMessage(creds, challengeMessage)
        return Pair(AUTH_HEADER, "NTLM ${Base64.getEncoder().encodeToString(authMsg)}")
    }
}