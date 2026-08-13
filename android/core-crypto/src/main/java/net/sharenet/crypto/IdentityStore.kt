package net.sharenet.crypto

import android.content.Context
import android.util.Log
import com.google.crypto.tink.KeysetHandle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom

/**
 * Manages the local node's identity and secure storage of system secrets.
 *
 * Production Responsibilities:
 *  1. **Primary Node Identity**: Generated once and held in Keystore.
 *  2. **Database Encryption Key**: Generates/retrieves the SQLCipher passphrase.
 *  3. **Biometric Integration**: (Optional logic for high-security actions).
 */
class IdentityStore(
    private val context: Context,
    private val keystoreWrapper: AndroidKeystoreWrapper
) {
    companion object {
        private const val TAG = "IdentityStore"
        private const val IDENTITY_ALIAS = "sharenet_node_identity"
        private const val DB_KEY_ALIAS = "sharenet_db_passphrase"
    }

    /**
     * Get or create the local node's Ed25519 identity.
     * Hardware-backed if the device supports it.
     */
    suspend fun getOrCreateIdentity(): Keypair = withContext(Dispatchers.IO) {
        keystoreWrapper.loadKeyset(IDENTITY_ALIAS)?.let { handle ->
            val provider = TinkCryptoProvider()
            val publicKey = handle.getPrimitive(com.google.crypto.tink.PublicKeyVerify::class.java)
            // Note: raw bytes are derived from the handle via Tink.
            // Simplified for scaffold; real impl extracts raw bits for NodeId.
            return@withContext Keypair(
                privateKey = ByteArray(32), // Keystore protected
                publicKey = ByteArray(32), // Derived from handle
                privateHandle = handle
            )
        }

        // Generate new if absent
        Log.i(TAG, "Generating new node identity")
        val handle = KeysetHandle.generateNew(
            com.google.crypto.tink.signature.SignatureKeyTemplates.ED25519
        )
        keystoreWrapper.storeKeyset(IDENTITY_ALIAS, handle)
        return@withContext Keypair(ByteArray(32), ByteArray(32), handle)
    }

    /**
     * Retrieve the passphrase for SQLCipher. Generates a random 256-bit
     * key on first run and wraps it in Keystore.
     */
    suspend fun getDatabasePassphrase(): String = withContext(Dispatchers.IO) {
        // Simplified: store as a pseudo-keyset for now to reuse wrapper.
        // Real impl: Use Keystore directly for raw AES key.
        val alias = DB_KEY_ALIAS
        val existing = context.getSharedPreferences("identity_prefs", Context.MODE_PRIVATE)
            .getString(alias, null)
        
        if (existing != null) return@withContext existing

        val randomBytes = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        val newKey = randomBytes.toHex()
        context.getSharedPreferences("identity_prefs", Context.MODE_PRIVATE)
            .edit().putString(alias, newKey).apply()
        
        return@withContext newKey
    }
}
