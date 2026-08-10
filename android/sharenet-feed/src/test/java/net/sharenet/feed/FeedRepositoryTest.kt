package net.sharenet.feed

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import net.sharenet.crypto.BlobId
import net.sharenet.feed.data.*
import net.sharenet.feed.domain.RealFeedRepository
import org.junit.Before
import org.junit.Test
import java.util.*

class FeedRepositoryTest {

    private lateinit var repository: RealFeedRepository
    private lateinit var postDao: PostDao
    private lateinit var actionDao: ActionDao

    @Before
    fun setup() {
        postDao = FakePostDao()
        actionDao = FakeActionDao()
        repository = RealFeedRepository(postDao, actionDao)
    }

    @Test
    fun `like post updates local state and queues action`() = runTest {
        val blobId = BlobId("0123456789abcdef0123456789abcdef".toByteArray())
        val post = PostEntity(blobId.toHex(), "Hello", "pub1", 1000L, "video/mp4")
        postDao.upsert(post)

        repository.like(blobId)

        val updated = postDao.getById(blobId.toHex())
        assertThat(updated?.isLiked).isTrue()
        assertThat(updated?.likeCount).isEqualTo(1)

        val pending = actionDao.getPending()
        assertThat(pending).hasSize(1)
        assertThat(pending[0].type).isEqualTo("LIKE")
    }

    @Test
    fun `observeFeed emits posts from DAO`() = runTest {
        val blobId = BlobId("0123456789abcdef0123456789abcdef".toByteArray())
        postDao.upsert(PostEntity(blobId.toHex(), "Hello", "pub1", 1000L, "video/mp4"))

        val feed = repository.observeFeed().first()
        assertThat(feed).hasSize(1)
        assertThat(feed[0].caption).isEqualTo("Hello")
    }
}

private class FakePostDao : PostDao {
    private val posts = mutableMapOf<String, PostEntity>()
    override fun observeAll() = kotlinx.coroutines.flow.flowOf(posts.values.toList())
    override suspend fun getById(blobIdHex: String) = posts[blobIdHex]
    override suspend fun upsert(post: PostEntity) { posts[post.blobIdHex] = post }
    override suspend fun updateLike(blobIdHex: String, liked: Boolean, delta: Int) {
        val p = posts[blobIdHex] ?: return
        posts[blobIdHex] = p.copy(isLiked = liked, likeCount = p.likeCount + delta)
    }
}

private class FakeActionDao : ActionDao {
    private val actions = mutableMapOf<String, ActionEntity>()
    override suspend fun getPending() = actions.values.filter { it.status == "PENDING" }
    override suspend fun upsert(action: ActionEntity) { actions[action.id] = action }
    override suspend fun updateStatus(id: String, status: String) {
        actions[id] = actions[id]?.copy(status = status) ?: return
    }
    override suspend fun delete(id: String) { actions.remove(id) }
}
