package net.sharenet.app.feed

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.room.Room
import kotlinx.coroutines.flow.first
import net.sharenet.app.feed.ui.*
import net.sharenet.feed.data.*
import net.sharenet.feed.domain.RealAppStoreRepository
import net.sharenet.feed.domain.RealFeedRepository
import net.sharenet.feed.domain.RealLauncherRepository
import net.sharenet.sdk.SdkModule
import net.sharenet.sdk.ShareNetSdk

class MainActivity : ComponentActivity() {

    private lateinit var db: FeedDatabase
    private lateinit var viewModel: FeedViewModel
    private lateinit var sdk: ShareNetSdk

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Manual DI
        db = Room.databaseBuilder(applicationContext, FeedDatabase::class.java, "feed.db")
            .fallbackToDestructiveMigration()
            .build()
        
        sdk = SdkModule.create(this)
        
        val feedRepo = RealFeedRepository(db.postDao(), db.actionDao())
        val storeRepo = RealAppStoreRepository(db.appDao(), db.userStatsDao())
        val launcherRepo = RealLauncherRepository(db.activeAppDao(), db.appDao())
        
        viewModel = FeedViewModel(feedRepo, storeRepo, launcherRepo)

        // Pre-populate with dummy data if empty
        lifecycleScope.launchWhenStarted {
            val posts = db.postDao().observeAll().first()
            if (posts.isEmpty()) {
                db.userStatsDao().upsert(UserStatsEntity(isNetworkAdmin = true, civicPoints = 100))
                
                db.postDao().upsert(
                    PostEntity(
                        blobIdHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e01",
                        caption = "Welcome to ShareNet Feed! This is an offline-first post.",
                        publisherIdHex = "system",
                        publishedAt = System.currentTimeMillis(),
                        mimeType = "video/sharenet-feed-post"
                    )
                )

                db.appDao().upsert(
                    AppEntity(
                        id = "app_chat_clone",
                        name = "Chat Clone",
                        description = "Offline messaging via mesh connections.",
                        developerName = "ShareNet Core",
                        category = "SOCIAL",
                        status = "APPROVED"
                    )
                )
            }
        }

        setContent {
            MaterialTheme {
                MainContainer(viewModel)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainContainer(viewModel: FeedViewModel) {
    val navController = rememberNavController()
    var currentTab by remember { mutableStateOf("launcher") }
    var showProfile by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("ShareNet Hub") },
                actions = {
                    IconButton(onClick = { showProfile = true }) { Text("👤") }
                }
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = currentTab == "launcher",
                    onClick = { currentTab = "launcher"; navController.navigate("launcher") },
                    icon = { Text("📱") },
                    label = { Text("Launcher") }
                )
                NavigationBarItem(
                    selected = currentTab == "library",
                    onClick = { currentTab = "library"; navController.navigate("library") },
                    icon = { Text("⬛") },
                    label = { Text("Library") }
                )
                NavigationBarItem(
                    selected = currentTab == "store",
                    onClick = { currentTab = "store"; navController.navigate("store") },
                    icon = { Text("🚀") },
                    label = { Text("Store") }
                )
            }
        }
    ) { padding ->
        NavHost(navController, startDestination = "launcher", modifier = Modifier.padding(padding)) {
            composable("launcher") { ActiveLauncherScreen(viewModel) }
            composable("library") { LibraryScreen(viewModel) }
            composable("store") { AppStoreScreen(viewModel) }
        }

        if (showProfile) {
            ProfileSheet(viewModel, onDismiss = { showProfile = false })
        }
    }
}


