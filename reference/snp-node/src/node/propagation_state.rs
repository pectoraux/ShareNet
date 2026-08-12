//! N2.1.1.1 review-gate fix #2 — Persistent propagation acceptance state.
//!
//! `PropagationStateStore` mirrors `AdvertisementAcceptanceStore`'s persistence
//! pattern (atomic write-to-temp-then-rename, fail-closed on corruption,
//! transactional accept). It persists the highest `propagation_sequence` seen
//! per sender NodeId so that replay attacks cannot succeed across restart.
//!
//! ## Why this exists
//!
//! Before this fix, `TopologyGraph::propagation_state` was a `HashMap<[u8;32],
//! u64>` in memory. `TopologyGraph::open()` loaded the `PeerDirectory` from
//! disk but initialized `propagation_state: HashMap::new()` — so after
//! restart, an old propagation message could become acceptable again,
//! violating the same replay-state principle already established for node
//! advertisements (ADR-0003 / spec §20).
//!
//! ## On-disk format
//!
//! ```text
//! Header:  magic (4) = b"SNPS" (ShareNet Propagation State)
//!          version (1) = 1
//! Entries: sender_node_id (32) + highest_sequence (8) = 40 bytes each
//! ```
//!
//! No fsync is claimed (same as `AdvertisementAcceptanceStore`).

use std::collections::HashMap;
use std::path::PathBuf;

/// Persistence file magic: `b"SNPS"` (ShareNet Propagation State).
const PROPAGATION_PERSIST_MAGIC: &[u8; 4] = b"SNPS";

/// Persistence file format version.
const PROPAGATION_PERSIST_VERSION: u8 = 1;

/// Header size: magic (4) + version (1) = 5 bytes.
const PROPAGATION_HEADER_SIZE: usize = 5;

/// On-disk entry: sender NodeId (32) + highest sequence (8) = 40 bytes.
const PROPAGATION_ENTRY_SIZE: usize = 40;

/// Errors from the propagation state store.
#[derive(Debug)]
pub enum PropagationStateError {
    /// Persistence write failed. The in-memory state was NOT advanced.
    PersistenceFailed(std::io::Error),
    /// The persistence file is corrupted. The store was NOT loaded.
    CorruptPersistence(String),
}

impl std::fmt::Display for PropagationStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PersistenceFailed(e) => write!(f, "propagation persistence failed: {e}"),
            Self::CorruptPersistence(msg) => write!(f, "corrupt propagation persistence: {msg}"),
        }
    }
}

impl std::error::Error for PropagationStateError {}

/// Persistent store of the highest `propagation_sequence` seen per sender.
///
/// Keyed by sender NodeId (NOT global, NOT target node) — per ADR-0003 the
/// propagation sequence is a per-sender state machine.
///
/// ## Transactional semantics
///
/// `accept_sequence()` follows the same persist-then-mutate pattern as
/// `AdvertisementAcceptanceStore::accept()`:
///   1. Compute the new floor.
///   2. Persist to disk (atomic write-to-temp-then-rename).
///   3. Only if persistence succeeds, update in-memory state.
///   4. If persistence fails, return `Err` and leave in-memory state unchanged.
///
/// Lower/equal sequences are rejected without persistence (no state change).
#[derive(Debug, Clone)]
pub struct PropagationStateStore {
    /// Map: sender NodeId → highest accepted propagation_sequence.
    state: HashMap<[u8; 32], u64>,
    /// Optional file path for persistence. Empty = in-memory mode.
    path: PathBuf,
}

impl Default for PropagationStateStore {
    fn default() -> Self {
        Self {
            state: HashMap::new(),
            path: PathBuf::new(),
        }
    }
}

impl PropagationStateStore {
    /// Create a new empty in-memory store (not persisted).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a persistent store backed by a file. If the file exists, the
    /// propagation state is loaded from it. If not, the store starts empty.
    ///
    /// ## Fail-closed
    ///
    /// If the file is corrupted (truncated, invalid magic/version, trailing
    /// bytes, duplicate NodeIds), this method returns
    /// `PropagationStateError::CorruptPersistence`.
    ///
    /// # Errors
    /// Returns `PropagationStateError::CorruptPersistence` for corrupted files.
    /// Returns `PropagationStateError::PersistenceFailed` (wrapped io::Error)
    /// for I/O failures.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, PropagationStateError> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            state: HashMap::new(),
            path,
        };
        if store.path.exists() {
            store.load()?;
        }
        Ok(store)
    }

    /// Load propagation state from the persistence file. Fails closed on
    /// any corruption.
    fn load(&mut self) -> Result<(), PropagationStateError> {
        let data = std::fs::read(&self.path)
            .map_err(|e| PropagationStateError::CorruptPersistence(format!("read error: {e}")))?;

        if data.len() < PROPAGATION_HEADER_SIZE {
            return Err(PropagationStateError::CorruptPersistence(format!(
                "file too short: {} bytes < {} header",
                data.len(),
                PROPAGATION_HEADER_SIZE
            )));
        }

        if &data[..4] != PROPAGATION_PERSIST_MAGIC {
            return Err(PropagationStateError::CorruptPersistence(format!(
                "invalid magic: expected {:?}, got {:?}",
                PROPAGATION_PERSIST_MAGIC,
                &data[..4]
            )));
        }

        if data[4] != PROPAGATION_PERSIST_VERSION {
            return Err(PropagationStateError::CorruptPersistence(format!(
                "unsupported version: expected {}, got {}",
                PROPAGATION_PERSIST_VERSION, data[4]
            )));
        }

        let entries_data = &data[PROPAGATION_HEADER_SIZE..];
        if entries_data.len() % PROPAGATION_ENTRY_SIZE != 0 {
            return Err(PropagationStateError::CorruptPersistence(format!(
                "trailing bytes: {} bytes after header is not a multiple of {}",
                entries_data.len(),
                PROPAGATION_ENTRY_SIZE
            )));
        }

        let mut seen = std::collections::HashSet::new();
        let mut offset = 0;
        while offset < entries_data.len() {
            let mut sender = [0u8; 32];
            sender.copy_from_slice(&entries_data[offset..offset + 32]);
            let mut seq_buf = [0u8; 8];
            seq_buf.copy_from_slice(&entries_data[offset + 32..offset + 40]);
            let sequence = u64::from_le_bytes(seq_buf);
            offset += PROPAGATION_ENTRY_SIZE;

            if !seen.insert(sender) {
                return Err(PropagationStateError::CorruptPersistence(format!(
                    "duplicate sender NodeId entry at offset {}",
                    offset - PROPAGATION_ENTRY_SIZE
                )));
            }

            self.state.insert(sender, sequence);
        }
        Ok(())
    }

    /// Persist the state to the file using atomic write-to-temp-then-rename.
    fn persist(&self) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // in-memory mode
        }
        let mut data =
            Vec::with_capacity(PROPAGATION_HEADER_SIZE + self.state.len() * PROPAGATION_ENTRY_SIZE);
        data.extend_from_slice(PROPAGATION_PERSIST_MAGIC);
        data.push(PROPAGATION_PERSIST_VERSION);
        for (sender, sequence) in &self.state {
            data.extend_from_slice(sender);
            data.extend_from_slice(&sequence.to_le_bytes());
        }
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Get the highest accepted propagation_sequence for a sender, if any.
    ///
    /// This survives restart — the floor is persisted (review-gate fix #2).
    #[must_use]
    pub fn highest_sequence(&self, sender: &[u8; 32]) -> Option<u64> {
        self.state.get(sender).copied()
    }

    /// Accept a new propagation_sequence for a sender.
    ///
    /// ## Transactional semantics
    ///
    /// - If `sequence` <= the current floor, returns `Ok(false)` (stale/dup)
    ///   without persistence.
    /// - If `sequence` > the current floor:
    ///   1. Persist the new floor to disk.
    ///   2. Only if persistence succeeds, update in-memory state.
    ///   3. Return `Ok(true)`.
    /// - If persistence fails, return `Err` and leave in-memory state unchanged.
    ///
    /// # Errors
    /// Returns `PropagationStateError::PersistenceFailed` if the state could
    /// not be persisted. The in-memory state is NOT advanced in this case.
    pub fn accept_sequence(
        &mut self,
        sender: [u8; 32],
        sequence: u64,
    ) -> Result<bool, PropagationStateError> {
        match self.state.get(&sender) {
            Some(&known) if sequence <= known => {
                // Stale or duplicate — no state change, no persistence.
                return Ok(false);
            }
            _ => {}
        }
        // Persist FIRST, then mutate in-memory.
        let old = self.state.insert(sender, sequence);
        if let Err(e) = self.persist() {
            // Rollback: restore the old state.
            match old {
                Some(prev) => {
                    self.state.insert(sender, prev);
                }
                None => {
                    self.state.remove(&sender);
                }
            }
            return Err(PropagationStateError::PersistenceFailed(e));
        }
        Ok(true)
    }

    /// Number of senders tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.len()
    }

    /// Is the store empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}
