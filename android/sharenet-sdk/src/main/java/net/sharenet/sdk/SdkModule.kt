package net.sharenet.sdk

import android.content.Context
import androidx.room.Room
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import net.sharenet.attest.AttestDatabase
import net.sharenet.attest.DefaultFraudControls
import net.sharenet.attest.InMemoryUploader
import net.sharenet.attest.PointsLedger
import net.sharenet.attest.ReceiptManager
import net.sharenet.catalog.CatalogStore
import net.sharenet.catalog.ManifestStore
import net.sharenet.catalog.PublisherRegistry
import net.sharenet.catalog.RevocationList
import net.sharenet.catalog.db.CatalogDatabase
import net.sharenet.content.BlobStore
import net.sharenet.content.DiskBlobStore
import net.sharenet.content.LocalAvailability
import net.sharenet.content.db.ContentDatabase
import net.sharenet.crypto.AndroidKeystoreWrapper
import net.sharenet.crypto.CryptoProvider
import net.sharenet.crypto.FakeCryptoProvider
import net.sharenet.crypto.IdentityStore
import net.sharenet.crypto.Keypair
import net.sharenet.crypto.KeystoreCryptoProvider
import net.sharenet.crypto.TinkCryptoProvider
import net.sharenet.transport.DefaultGovernor
import net.sharenet.transport.Governor
import net.sharenet.transport.NearbyTransport
import net.sharenet.transport.Transport

/**
 * Dependency factory for [ShareNetSdk].
 */
object SdkModule {

    private const val PINNED_ROOT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e00"

    /**
     * Production factory.
     */
    fun create(
        context: Context,
        identityProvider: (suspend () -> Keypair)? = null,
    ): ShareNetSdk {
        val appContext = context.applicationContext
        
        // 1. Security & Identity
        val keystoreWrapper = AndroidKeystoreWrapper(appContext)
        val identityStore = IdentityStore(appContext, keystoreWrapper)
        val crypto = KeystoreCryptoProvider(keystoreWrapper)
        
        // 2. Storage
        val blobsDir = appContext.getDir("sharenet_blobs", Context.MODE_PRIVATE)
        val contentDb = Room.databaseBuilder(appContext, ContentDatabase::class.java, "content.db")
            .fallbackToDestructiveMigration()
            .build()
        val blobStore = DiskBlobStore(blobsDir, contentDb)
        
        // 3. Catalog
        val catalogDb = Room.databaseBuilder(appContext, CatalogDatabase::class.java, "catalog.db")
            .fallbackToDestructiveMigration()
            .build()
        val publisherRegistry = PublisherRegistry(catalogDb, crypto, PINNED_ROOT)
        val manifestStore = ManifestStore(catalogDb, crypto, publisherRegistry)
        val revocationList = RevocationList(catalogDb, crypto, publisherRegistry, blobStore)
        
        // Wrap ManifestStore to fulfill CatalogStore interface
        val catalogStore = object : CatalogStore {
            override suspend fun put(entry: net.sharenet.crypto.CatalogEntry) = manifestStore.put(entry)
            override suspend fun listByCategory(category: net.sharenet.crypto.Category) = 
                manifestStore.listAll().filter { it.category == category }
            override suspend fun listAvailable() = manifestStore.listAll()
            override suspend fun get(blobId: net.sharenet.crypto.BlobId) = manifestStore.get(blobId)
            override fun observe(category: net.sharenet.crypto.Category?) = 
                kotlinx.coroutines.flow.flow { emit(manifestStore.listAll().filter { category == null || it.category == category }) }
            override suspend fun isRevoked(blobId: net.sharenet.crypto.BlobId) = revocationList.isRevoked(blobId)
        }

        // 4. Transport
        val governor = DefaultGovernor(appContext)
        val transport = NearbyTransport(appContext, governor)

        // 5. Attestation
        val attestDb = Room.databaseBuilder(appContext, AttestDatabase::class.java, "attest.db")
            .fallbackToDestructiveMigration()
            .build()
        val pointsLedger = PointsLedger(attestDb.pointsLedgerDao())
        val receiptManager = ReceiptManager(
            crypto = crypto,
            receiptDao = attestDb.receiptDao(),
            pointsLedger = pointsLedger,
            fraudControls = DefaultFraudControls(),
            uploader = InMemoryUploader(),
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
        )

        val identity: suspend () -> Keypair = identityProvider ?: {
            identityStore.getOrCreateIdentity()
        }

        return DefaultShareNetSdk(
            blobStore = blobStore,
            catalogStore = catalogStore,
            transport = transport,
            receiptManager = receiptManager,
            crypto = crypto,
            identityProvider = identity,
            localAvailability = object : LocalAvailability {
                override suspend fun query(blobId: net.sharenet.crypto.BlobId) = null
                override suspend fun listAll(): List<net.sharenet.content.BlobAvailability> = emptyList()
            },
            governor = governor,
        )
    }

    /**
     * Fake factory for unit tests — no Android [Context] required for the fakes.
     */
    fun createFake(
        crypto: CryptoProvider = FakeCryptoProvider,
        identityProvider: (suspend () -> Keypair)? = null,
    ): ShareNetSdk {
        val blobStore = InMemoryBlobStore()
        val catalogStore = InMemoryCatalogStore()
        val fakeTransport = FakeLoopbackTransport()
        val governor = FakeInMemoryGovernor()
        
        return DefaultShareNetSdk(
            blobStore = blobStore,
            catalogStore = catalogStore,
            transport = fakeTransport,
            receiptManager = null,
            crypto = crypto,
            identityProvider = identityProvider ?: { crypto.generateKeypair() },
            localAvailability = object : LocalAvailability {
                override suspend fun query(blobId: net.sharenet.crypto.BlobId) = null
                override suspend fun listAll(): List<net.sharenet.content.BlobAvailability> = emptyList()
            },
            governor = governor,
        )
    }
}

// ---------------------------------------------------------------------------
// Minimal in-memory stubs so the SDK compiles without real core-* impls.
// Replace with real Room/SQLCipher impls at the app layer.
// ---------------------------------------------------------------------------

private class InMemoryBlobStore : BlobStore {
    private val map = mutableMapOf<String, ByteArray>()
    private val pins = mutableSetOf<String>()

    override suspend fun put(blobId: net.sharenet.crypto.BlobId, data: ByteArray, mimeType: String) {
        map[blobId.toHex()] = data.copyOf()
    }

    override suspend fun get(blobId: net.sharenet.crypto.BlobId): ByteArray? = map[blobId.toHex()]?.copyOf()

    override suspend fun delete(blobId: net.sharenet.crypto.BlobId) {
        map.remove(blobId.toHex())
    }

    override suspend fun has(blobId: net.sharenet.crypto.BlobId): Boolean = map.containsKey(blobId.toHex())

    override suspend fun list(): List<net.sharenet.crypto.BlobId> =
        map.keys.map { net.sharenet.crypto.BlobId.fromHex(it) }

    override suspend fun pin(blobId: net.sharenet.crypto.BlobId) { pins += blobId.toHex() }

    override suspend fun unpin(blobId: net.sharenet.crypto.BlobId) { pins -= blobId.toHex() }

    override suspend fun isPinned(blobId: net.sharenet.crypto.BlobId): Boolean = pins.contains(blobId.toHex())

    override suspend fun sizeBytes(): Long = map.values.sumOf { it.size.toLong() }

    override suspend fun lruEvict(quotaBytes: Long): Int {
        // Simple mock: delete all unpinned if over quota
        if (sizeBytes() <= quotaBytes) return 0
        val toRemove = map.keys.filter { !pins.contains(it) }
        toRemove.forEach { map.remove(it) }
        return toRemove.size
    }
}

private class InMemoryCatalogStore : CatalogStore {
    private val entries = mutableListOf<net.sharenet.crypto.CatalogEntry>()
    private val flow = kotlinx.coroutines.flow.MutableStateFlow<List<net.sharenet.crypto.CatalogEntry>>(emptyList())
    override suspend fun put(entry: net.sharenet.crypto.CatalogEntry) {
        entries.removeAll { it.manifest.blobId == entry.manifest.blobId }; entries += entry
        flow.value = entries.toList()
    }
    override suspend fun listByCategory(category: net.sharenet.crypto.Category) = entries.filter { it.category == category }
    override suspend fun listAvailable() = entries.toList()
    override suspend fun get(blobId: net.sharenet.crypto.BlobId) = entries.find { it.manifest.blobId == blobId }
    override fun observe(category: net.sharenet.crypto.Category?) = flow as kotlinx.coroutines.flow.Flow<List<net.sharenet.crypto.CatalogEntry>>
    override suspend fun isRevoked(blobId: net.sharenet.crypto.BlobId) = false
}

private class FakeLoopbackTransport : Transport {
    private val _incoming = kotlinx.coroutines.flow.MutableSharedFlow<net.sharenet.transport.Payload>(extraBufferCapacity = 64)
    override val incoming: kotlinx.coroutines.flow.Flow<net.sharenet.transport.Payload> = _incoming
    override val discoveredEndpoints: kotlinx.coroutines.flow.Flow<Set<net.sharenet.transport.EndpointId>> =
        kotlinx.coroutines.flow.MutableStateFlow(emptySet())
    override val connectionStates: kotlinx.coroutines.flow.Flow<Map<net.sharenet.transport.EndpointId, net.sharenet.transport.ConnectionState>> =
        kotlinx.coroutines.flow.MutableStateFlow(emptyMap())
    override fun startDiscovery(serviceId: String) {}
    override fun stopDiscovery() {}
    override fun startAdvertising(serviceId: String, endpointName: String) {}
    override fun stopAdvertising() {}
    override fun connect(endpointId: net.sharenet.transport.EndpointId) {}
    override fun disconnect(endpointId: net.sharenet.transport.EndpointId) {}
    override suspend fun send(endpointId: net.sharenet.transport.EndpointId, payload: ByteArray) {
        _incoming.emit(net.sharenet.transport.Payload(endpointId, payload))
    }
}

private class FakeInMemoryGovernor : Governor {
    private val _wifiOnly = kotlinx.coroutines.flow.MutableStateFlow(false)
    override val wifiOnly: kotlinx.coroutines.flow.StateFlow<Boolean> = _wifiOnly
    private val _snapshot = kotlinx.coroutines.flow.MutableStateFlow(
        net.sharenet.transport.GovernorSnapshot(80, true, false, true)
    )
    override val snapshot: kotlinx.coroutines.flow.StateFlow<net.sharenet.transport.GovernorSnapshot> = _snapshot
    override fun canTransfer(priority: net.sharenet.transport.TransferPriority) = net.sharenet.transport.GovernorDecision.Allowed
    override suspend fun setWifiOnly(enabled: Boolean) { _wifiOnly.value = enabled }
}
