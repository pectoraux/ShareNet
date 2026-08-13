package net.sharenet.assistant.navigation

import kotlinx.serialization.Serializable

sealed interface AssistantDestination {
    @Serializable data object Chat : AssistantDestination
    @Serializable data object Settings : AssistantDestination
    @Serializable data object Contribution : AssistantDestination
}
