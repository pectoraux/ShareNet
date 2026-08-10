package net.sharenet.wallet.navigation

import kotlinx.serialization.Serializable

sealed interface WalletDestination {
    @Serializable data object TapToPay : WalletDestination
    @Serializable data object Balance : WalletDestination
    @Serializable data object History : WalletDestination
    @Serializable data object Settlement : WalletDestination
}
