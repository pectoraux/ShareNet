package net.sharenet.assistant

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import net.sharenet.assistant.di.AssistantAppContainer
import net.sharenet.assistant.navigation.AssistantNavGraph
import net.sharenet.assistant.ui.theme.ShareNetAssistantTheme

class MainActivity : ComponentActivity() {

    lateinit var container: AssistantAppContainer
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        container = AssistantAppContainer(applicationContext)
        // Tiered model selection — auto-picks 1B vs 4B; weights come via ShareNet catalog
        // val tier = TieredModelSelector.select(this) — wired inside container when needed
        setContent {
            ShareNetAssistantTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AssistantNavGraph()
                }
            }
        }
    }
}
