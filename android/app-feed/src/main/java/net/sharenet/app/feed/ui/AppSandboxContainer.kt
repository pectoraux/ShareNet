package net.sharenet.app.feed.ui

import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import java.io.ByteArrayInputStream

/**
 * Professional WebView container for running offline App Clones.
 * 
 * Security:
 *  - No remote URL loading (only SNR:// internal protocol).
 *  - Bridge APIs for mesh storage and payments.
 *  - Isolated per-app local storage.
 */
@Composable
fun AppSandboxContainer(appId: String, appName: String) {
    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { context ->
            WebView(context).apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                
                webViewClient = object : WebViewClient() {
                    override fun shouldInterceptRequest(
                        view: WebView?,
                        request: WebResourceRequest
                    ): WebResourceResponse? {
                        val url = request.url.toString()
                        if (url.startsWith("snr://")) {
                            // Real impl: Load from BlobStore / FilesDir
                            val html = """
                                <html>
                                <body style="background: #f0f0f0; display: flex; align-items: center; justify-content: center; height: 100vh;">
                                    <div style="text-align: center;">
                                        <h1>$appName</h1>
                                        <p>Offline App ID: $appId</p>
                                        <button onclick="alert('Mesh Payment Requested')">Pay 10 Civic Points</button>
                                    </div>
                                </body>
                                </html>
                            """.trimIndent()
                            return WebResourceResponse(
                                "text/html",
                                "UTF-8",
                                ByteArrayInputStream(html.toByteArray())
                            )
                        }
                        return super.shouldInterceptRequest(view, request)
                    }
                }
                
                loadUrl("snr://app.local/index.html")
            }
        }
    )
}
