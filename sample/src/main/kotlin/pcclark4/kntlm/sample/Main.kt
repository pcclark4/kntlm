package pcclark4.kntlm.sample

import okhttp3.*
import pcclark4.kntlm.NtlmCredentials
import pcclark4.kntlm.NtlmHttp
import java.lang.IndexOutOfBoundsException

fun main(args: Array<String>) {
    val url = try {
        args[0]
    } catch (e: IndexOutOfBoundsException) {
        print("Enter URL: ")
        readLine()!!
    }

    val domain = try {
        args[1]
    } catch (e: IndexOutOfBoundsException) {
        print("Enter domain: ")
        readLine()!!
    }

    val username = try {
        args[2]
    } catch (e: IndexOutOfBoundsException) {
        print("Enter username: ")
        readLine()!!
    }

    val password = try {
        args[3]
    } catch (e: IndexOutOfBoundsException) {
        print("Enter password: ")
        readLine()!!
    }

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
