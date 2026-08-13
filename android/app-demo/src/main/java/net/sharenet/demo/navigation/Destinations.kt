package net.sharenet.demo.navigation

import kotlinx.serialization.Serializable

/**
 * Navigation destinations for app-demo.
 */
sealed interface DemoDestination {
    @Serializable
    data object Catalog : DemoDestination

    @Serializable
    data class BlobDetail(val blobId: String) : DemoDestination

    @Serializable
    data object Publish : DemoDestination
}
