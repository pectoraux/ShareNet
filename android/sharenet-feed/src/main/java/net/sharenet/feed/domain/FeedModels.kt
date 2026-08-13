package net.sharenet.feed.domain

import net.sharenet.crypto.BlobId

data class FeedItem(
    val blobId: BlobId,
    val caption: String,
    val publisherId: String,
    val publishedAt: Long,
    val likeCount: Int,
    val commentCount: Int,
    val isLiked: Boolean,
    val isPending: Boolean = false,
)

enum class ActionType {
    POST, LIKE, COMMENT
}
