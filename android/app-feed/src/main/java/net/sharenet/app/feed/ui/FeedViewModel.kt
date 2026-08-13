package net.sharenet.app.feed.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.sharenet.crypto.BlobId
import net.sharenet.feed.domain.AppStoreItem
import net.sharenet.feed.domain.AppStoreRepository
import net.sharenet.feed.domain.FeedItem
import net.sharenet.feed.domain.FeedRepository
import net.sharenet.feed.domain.LauncherRepository

class FeedViewModel(
    private val repository: FeedRepository,
    private val appStoreRepository: AppStoreRepository,
    private val launcherRepository: LauncherRepository
) : ViewModel() {

    val feed: StateFlow<List<FeedItem>> = repository.observeFeed()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val libraryItems: StateFlow<List<AppStoreItem>> = appStoreRepository.observeLibrary()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val storeItems: StateFlow<List<AppStoreItem>> = appStoreRepository.observeStore()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val reviewQueue: StateFlow<List<AppStoreItem>> = appStoreRepository.observeReviewQueue()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val activeApps = launcherRepository.observeActiveApps()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val userStats = appStoreRepository.observeUserStats()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 
            net.sharenet.feed.domain.UserStats(0, false, false))

    fun like(blobId: BlobId) = viewModelScope.launch { repository.like(blobId) }

    fun submitApp(name: String, desc: String) = viewModelScope.launch {
        appStoreRepository.submitApp(name, desc, "Local Dev", "UTILITY")
    }

    fun approveApp(appId: String) = viewModelScope.launch { appStoreRepository.approveApp(appId) }

    fun installApp(appId: String) = viewModelScope.launch { appStoreRepository.installApp(appId) }

    fun uninstallApp(appId: String) = viewModelScope.launch { appStoreRepository.uninstallApp(appId) }

    fun launchApp(appId: String) = viewModelScope.launch { launcherRepository.launchApp(appId) }

    fun closeApp(appId: String) = viewModelScope.launch { launcherRepository.closeApp(appId) }

    fun toggleBridging(enabled: Boolean) = viewModelScope.launch { appStoreRepository.toggleBridging(enabled) }
}
