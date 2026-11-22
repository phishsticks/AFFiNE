package app.affine.pro

import android.webkit.ClientCertRequest
import android.webkit.WebResourceRequest
import android.webkit.WebView
import app.affine.pro.service.ClientCertificates
import com.getcapacitor.Bridge
import com.getcapacitor.BridgeWebViewClient

internal class AffineWebViewClient(
    private val bridge: Bridge,
    private val trustedOrigin: String?,
) : BridgeWebViewClient(bridge) {
    // Servers behind a proxy that requires a TLS client certificate (mTLS).
    override fun onReceivedClientCertRequest(view: WebView, request: ClientCertRequest) {
        val activity = bridge.activity
        if (activity == null) {
            request.ignore()
            return
        }
        ClientCertificates.onWebViewRequest(activity, request)
    }

    override fun shouldOverrideUrlLoading(
        view: WebView,
        request: WebResourceRequest,
    ): Boolean {
        val shouldOverride = super.shouldOverrideUrlLoading(view, request)
        if (!shouldOverride && request.isForMainFrame) {
            (view as? AffineEditorWebView)?.updateAndroidIMEBridge(
                request.url.toString(),
                trustedOrigin,
            )
        }
        return shouldOverride
    }
}
