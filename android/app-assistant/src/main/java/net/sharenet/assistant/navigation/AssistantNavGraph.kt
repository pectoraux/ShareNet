package net.sharenet.assistant.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import net.sharenet.assistant.ui.ChatScreen
import net.sharenet.assistant.ui.ContributionScreen
import net.sharenet.assistant.ui.SettingsScreen

@Composable
fun AssistantNavGraph() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = AssistantDestination.Chat) {
        composable<AssistantDestination.Chat> {
            ChatScreen(
                onNavigateSettings = { nav.navigate(AssistantDestination.Settings) },
                onNavigateContribution = { nav.navigate(AssistantDestination.Contribution) },
            )
        }
        composable<AssistantDestination.Settings> {
            SettingsScreen(onBack = { nav.popBackStack() })
        }
        composable<AssistantDestination.Contribution> {
            ContributionScreen(onBack = { nav.popBackStack() })
        }
    }
}
