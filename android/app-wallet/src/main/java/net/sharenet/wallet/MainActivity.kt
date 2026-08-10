package net.sharenet.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import net.sharenet.wallet.di.WalletAppContainer
import net.sharenet.wallet.navigation.WalletNavGraph
import net.sharenet.wallet.ui.theme.ShareNetWalletTheme

class MainActivity : ComponentActivity() {

    lateinit var container: WalletAppContainer
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        container = WalletAppContainer(this)
        setContent {
            ShareNetWalletTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    WalletNavGraph()
                }
            }
        }
    }

    // NFC reader mode is driven from TapToPayScreen via DisposableEffect;
    // alternatively enable here:
    // override fun onResume() { super.onResume(); nfcReader.enable() }
    // override fun onPause() { nfcReader.disable(); super.onPause() }
}
