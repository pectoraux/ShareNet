package net.sharenet.app.feed.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.VerticalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import net.sharenet.feed.domain.FeedItem

@Composable
fun VerticalFeedScreen(viewModel: FeedViewModel) {
    val feed by viewModel.feed.collectAsState()
    val pagerState = rememberPagerState(pageCount = { feed.size })

    if (feed.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("No feed items yet")
        }
    } else {
        VerticalPager(state = pagerState) { page ->
            FeedItemFull(item = feed[page], onLike = { viewModel.like(it) })
        }
    }
}

@Composable
fun FeedItemFull(item: FeedItem, onLike: (net.sharenet.crypto.BlobId) -> Unit) {
    Box(modifier = Modifier.fillMaxSize()) {
        // Video placeholder
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.fillMaxSize()) {
            Box(contentAlignment = Alignment.Center) {
                Text("Video: ${item.blobId.toHex().take(8)}", style = MaterialTheme.typography.displaySmall)
            }
        }
        
        // Overlay info
        Column(
            modifier = Modifier.align(Alignment.BottomStart).padding(16.dp).fillMaxWidth()
        ) {
            Text(item.publisherId, style = MaterialTheme.typography.titleMedium)
            Text(item.caption, style = MaterialTheme.typography.bodyLarge)
            Spacer(modifier = Modifier.height(100.dp)) // padding for buttons
        }

        // Overlay actions
        Column(
            modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            IconButton(onClick = { onLike(item.blobId) }) {
                Text(if (item.isLiked) "❤️" else "🤍", style = MaterialTheme.typography.headlineMedium)
            }
            Text("${item.likeCount}")
            IconButton(onClick = { }) {
                Text("💬", style = MaterialTheme.typography.headlineMedium)
            }
            Text("${item.commentCount}")
        }
    }
}
