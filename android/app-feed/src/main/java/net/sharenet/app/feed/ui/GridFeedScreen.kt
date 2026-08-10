package net.sharenet.app.feed.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import net.sharenet.feed.domain.FeedItem

@Composable
fun GridFeedScreen(viewModel: FeedViewModel) {
    val feed by viewModel.feed.collectAsState()

    LazyVerticalGrid(
        columns = GridCells.Fixed(3),
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(1.dp),
        horizontalArrangement = Arrangement.spacedBy(1.dp),
        verticalArrangement = Arrangement.spacedBy(1.dp)
    ) {
        items(feed) { item ->
            FeedItemThumb(item)
        }
    }
}

@Composable
fun FeedItemThumb(item: FeedItem) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.aspectRatio(1f)
    ) {
        Box(modifier = Modifier.padding(8.dp)) {
            Text(item.caption, style = MaterialTheme.typography.labelSmall, maxLines = 2)
        }
    }
}
