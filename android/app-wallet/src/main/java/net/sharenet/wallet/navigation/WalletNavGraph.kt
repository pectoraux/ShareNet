package net.sharenet.wallet.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import net.sharenet.wallet.ui.BalanceScreen
import net.sharenet.wallet.ui.HistoryScreen
import net.sharenet.wallet.ui.SettlementScreen
import net.sharenet.wallet.ui.TapToPayScreen

@Composable
fun WalletNavGraph() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = WalletDestination.TapToPay) {
        composable<WalletDestination.TapToPay> {
            TapToPayScreen(
                onNavigateBalance = { nav.navigate(WalletDestination.Balance) },
                onNavigateHistory = { nav.navigate(WalletDestination.History) },
                onNavigateSettlement = { nav.navigate(WalletDestination.Settlement) },
            )
        }
        composable<WalletDestination.Balance> { BalanceScreen(onBack = { nav.popBackStack() }) }
        composable<WalletDestination.History> { HistoryScreen(onBack = { nav.popBackStack() }) }
        composable<WalletDestination.Settlement> { SettlementScreen(onBack = { nav.popBackStack() }) }
    }
}
