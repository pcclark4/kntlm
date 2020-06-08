package pcclark4.kntlm.sample

import okhttp3.*
import pcclark4.kntlm.NtlmCredentials
import pcclark4.kntlm.NtlmHttp

fun main() {
    print("Enter URL: ")
    val url = readLine()!!

    print("Enter domain: ")
    val domain = readLine()!!

    print("Enter username: ")
    val username = readLine()!!

    print("Enter password: ")
    val password = readLine()!!

    val credentials = NtlmCredentials(domain, username, password)

    val client = OkHttpClient.Builder()
        .authenticator(DefaultAuthenticator(credentials))
        .build()
    val request = Request.Builder().url(url).build()
    val response = client.newCall(request).execute()
    println(response)
}

class DefaultAuthenticator(private val credentials: NtlmCredentials) : Authenticator {

    override fun authenticate(route: Route?, response: Response): Request? {
        val wwwAuthHeaders = response.headers(NtlmHttp.WWW_AUTH_HEADER)
        return if (wwwAuthHeaders.isNotEmpty()) {
            if (wwwAuthHeaders.contains(NtlmHttp.NTLM_AUTH_OPTION)) {
                val negoHeader = NtlmHttp.getNegotiateHeader()
                response.request.newBuilder().header(negoHeader.first, negoHeader.second).build()
            } else {
                wwwAuthHeaders.singleOrNull()?.substring(5)?.let { challengeBase64 ->
                    val authHeader = NtlmHttp.getAuthenticateHeader(credentials, challengeBase64)
                    response.request.newBuilder().header(authHeader.first, authHeader.second).build()
                }
            }
        } else {
            null
        }
    }
}
