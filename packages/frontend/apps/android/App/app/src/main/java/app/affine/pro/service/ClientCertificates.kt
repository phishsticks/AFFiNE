package app.affine.pro.service

import android.app.Activity
import android.content.Context
import android.security.KeyChain
import android.webkit.ClientCertRequest
import app.affine.pro.AFFiNEApp
import timber.log.Timber
import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

/**
 * TLS client certificates (mutual TLS) for self-hosted servers behind a proxy that requires
 * one, such as Cloudflare Access mTLS or nginx `ssl_verify_client`.
 *
 * Nothing changes for servers that do not ask for a certificate. When a server does ask, the
 * WebView shows Android's system certificate picker once; the chosen KeyChain alias is
 * remembered and also used by the native OkHttp clients (sign-in, GraphQL, SSE), so both
 * network paths present the same certificate. The private key stays in the Android KeyChain.
 */
object ClientCertificates {
    private const val PREFS = "client_certificates"
    private const val KEY_ALIAS = "alias"

    private val io = Executors.newSingleThreadExecutor()

    // host:port pairs the user dismissed the picker for, so it is not shown on every request.
    private val declined = ConcurrentHashMap.newKeySet<String>()

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun alias(context: Context): String? = prefs(context).getString(KEY_ALIAS, null)

    private fun saveAlias(context: Context, alias: String?) {
        prefs(context).edit().apply {
            if (alias == null) remove(KEY_ALIAS) else putString(KEY_ALIAS, alias)
        }.apply()
    }

    private fun load(context: Context, alias: String): Pair<PrivateKey, Array<X509Certificate>>? =
        try {
            val key = KeyChain.getPrivateKey(context, alias)
            val chain = KeyChain.getCertificateChain(context, alias)
            if (key != null && !chain.isNullOrEmpty()) key to chain else null
        } catch (e: Exception) {
            Timber.w(e, "[mtls] cannot load client certificate")
            null
        }

    /** Answers a WebView certificate request; must be called on the main thread. */
    fun onWebViewRequest(activity: Activity, request: ClientCertRequest) {
        val context = activity.applicationContext
        val target = "${request.host}:${request.port}"
        io.execute {
            val saved = alias(context)
            val loaded = saved?.let { load(context, it) }
            if (loaded != null) {
                request.proceed(loaded.first, loaded.second)
                return@execute
            }
            if (saved != null) saveAlias(context, null) // removed from the KeyChain
            if (target in declined) {
                request.ignore()
                return@execute
            }
            activity.runOnUiThread {
                KeyChain.choosePrivateKeyAlias(
                    activity,
                    { chosen ->
                        io.execute {
                            val picked = chosen?.let { load(context, it) }
                            if (chosen == null || picked == null) {
                                declined.add(target)
                                request.ignore()
                            } else {
                                saveAlias(context, chosen)
                                declined.remove(target)
                                request.proceed(picked.first, picked.second)
                            }
                        }
                    },
                    request.keyTypes,
                    request.principals,
                    request.host,
                    request.port,
                    saved,
                )
            }
        }
    }

    /** Default platform trust, unchanged: only the client side is added. */
    val trustManager: X509TrustManager by lazy {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        factory.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    /** Socket factory for OkHttp that presents the remembered certificate when asked. */
    val sslSocketFactory: SSLSocketFactory by lazy {
        SSLContext.getInstance("TLS").apply {
            init(arrayOf(KeyChainKeyManager), arrayOf(trustManager), null)
        }.socketFactory
    }

    private object KeyChainKeyManager : X509KeyManager {
        private fun context() = AFFiNEApp.context()

        override fun chooseClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            socket: Socket?,
        ): String? = alias(context())

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
            alias?.let { load(context(), it)?.second }

        override fun getPrivateKey(alias: String?): PrivateKey? =
            alias?.let { load(context(), it)?.first }

        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) =
            alias(context())?.let { arrayOf(it) }

        override fun chooseServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            socket: Socket?,
        ): String? = null

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = null
    }
}
