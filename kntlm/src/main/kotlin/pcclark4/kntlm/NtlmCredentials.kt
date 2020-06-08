package pcclark4.kntlm

class NtlmCredentials(
    val domain: String,
    val user: String,
    val password: String,
    val workstation: String = "localhost"
)