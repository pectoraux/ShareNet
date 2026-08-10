package net.sharenet.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import net.sharenet.demo.navigation.DemoNavGraph
import net.sharenet.demo.ui.theme.ShareNetDemoTheme

/**
 * Entry-point Activity for app-demo.
 *
 * Demonstrates SDK-only integration: the only ShareNet dependency is `sharenet-sdk`.
 * No internal modules (core-*) are referenced directly.
 *
 * Initialization contract:
 *  1. Call [ShareNetSdkInitializer.init] once in [onCreate] before any SDK usage.
 *  2. SDK initialization is idempotent and safe to call from the main thread.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // SDK init — real implementation delegates to net.sharenet.sdk.ShareNetSdk.
        // Stub here so the module compiles without a fully built SDK; replace the
        // body with: ShareNetSdk.init(applicationContext) when SDK is available.
        ShareNetSdkInitializer.init(applicationContext)

        setContent {
            ShareNetDemoTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DemoNavGraph()
                }
            }
        }
    }
}

/**
 * Thin shim that isolates the SDK init call.
 * In production this is a one-liner delegating to the real SDK.
 * Keeping it behind an object makes it trivial to fake in instrumented tests.
 */
object ShareNetSdkInitializer {
    @Volatile
    private var initialized = false

    fun init(context: android.content.Context) {
        if (initialized) return
        initialized = true
        // Real call (uncomment when sharenet-sdk exposes ShareNetSdk):
        // net.sharenet.sdk.ShareNetSdk.init(context)
        // Fallback stub — log so manual QA can confirm init was reached.
        android.util.Log.i("ShareNetDemo", "ShareNetSdk.init() called (stub)")
    }

    /** Visible for tests. */
    fun resetForTest() {
        initialized = false
    }
}
