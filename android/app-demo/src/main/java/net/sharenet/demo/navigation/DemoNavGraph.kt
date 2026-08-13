package net.sharenet.demo.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.toRoute
import net.sharenet.demo.ui.BlobDetailScreen
import net.sharenet.demo.ui.CatalogScreen
import net.sharenet.demo.ui.PublishScreen

@Composable
fun DemoNavGraph() {
    val navController = rememberNavController()
    NavHost(
        navController = navController,
        startDestination = DemoDestination.Catalog,
    ) {
        composable<DemoDestination.Catalog> {
            CatalogScreen(
                onBlobClick = { blobId ->
                    navController.navigate(DemoDestination.BlobDetail(blobId))
                },
                onPublishClick = {
                    navController.navigate(DemoDestination.Publish)
                },
            )
        }
        composable<DemoDestination.BlobDetail> { backStackEntry ->
            val dest = backStackEntry.toRoute<DemoDestination.BlobDetail>()
            BlobDetailScreen(
                blobId = dest.blobId,
                onBack = { navController.popBackStack() },
            )
        }
        composable<DemoDestination.Publish> {
            PublishScreen(
                onBack = { navController.popBackStack() },
                onPublished = { blobId ->
                    navController.navigate(DemoDestination.BlobDetail(blobId)) {
                        popUpTo<DemoDestination.Catalog>()
                    }
                },
            )
        }
    }
}
