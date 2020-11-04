package pcclark4.kntlm.sample

import okhttp3.*
import pcclark4.kntlm.NtlmCredentials
import pcclark4.kntlm.NtlmHttp
import java.lang.IndexOutOfBoundsException
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

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

    val builder = OkHttpClient.Builder()
        .authenticator(DefaultAuthenticator(credentials))
//        .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("192.168.0.134", 8888)))

    val noCert = args.any { it == "-nocert" }
    if (noCert) {
        val trustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance("SSL")
        sslContext.init(null, arrayOf(trustManager), SecureRandom())

        builder.hostnameVerifier(HostnameVerifier { _, _ -> true})
            .sslSocketFactory(sslContext.socketFactory, trustManager)
    }

    val client = builder.build()
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
