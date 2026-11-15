//! The node's zk proof caches: prepared verifying keys and the verified
//! results of proofs against registered keys (`zk.verify_groth16`,
//! `zk.warm_verified_proofs`), which the node clears for every block. They
//! only save work: both key on the verifying key's bytes
//! (their digest), so a cached result is the result verifying the same
//! proof against the same bytes returns, and no outcome depends on what a
//! node has cached, even after the registry's bytes for a key id changed.
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use xian_zk::{
    prepare_groth16_bn254_vk, verify_groth16_bn254_grouped, verify_groth16_bn254_prepared,
    Groth16Bn254BatchItem, PreparedGroth16Bn254Key, VerifierError,
};

/// How many prepared keys and proof results the caches keep.
const PREPARED_KEYS: usize = 128;
const VERIFIED_PROOFS: usize = 2048;

/// The SHA3-256 digest of a verifying key's hex bytes: the caches' name for
/// those bytes.
type KeyDigest = [u8; 32];

/// A registered verifying key's bytes as `zk_registry` holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisteredKey {
    vk_hex: String,
    digest: KeyDigest,
}

impl RegisteredKey {
    pub(crate) fn new(vk_hex: String) -> Self {
        let digest = Sha3_256::digest(vk_hex.as_bytes()).into();
        Self { vk_hex, digest }
    }
}

/// A proof of a registered key with its public inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisteredProof {
    pub(crate) key: RegisteredKey,
    pub(crate) proof_hex: String,
    pub(crate) public_inputs: Vec<String>,
}

impl RegisteredProof {
    /// A proof's cache key: the key's bytes (their digest), the proof and
    /// the inputs.
    fn cache_key(&self) -> ProofKey {
        (
            self.key.digest,
            self.proof_hex.clone(),
            self.public_inputs.clone(),
        )
    }
}

type ProofKey = (KeyDigest, String, Vec<String>);

/// A least-recently-used map (`cachetools.LRUCache`): a read refreshes an
/// entry; a new entry evicts the least recently used one when full.
struct Lru<K, V> {
    capacity: usize,
    tick: u64,
    entries: HashMap<K, (V, u64)>,
    recency: BTreeMap<u64, K>,
}

impl<K: Clone + Eq + Hash, V: Clone> Lru<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            entries: HashMap::new(),
            recency: BTreeMap::new(),
        }
    }

    fn touch(&mut self, key: &K) -> Option<u64> {
        let (_, used) = self.entries.get_mut(key)?;
        self.recency.remove(used);
        self.tick += 1;
        *used = self.tick;
        self.recency.insert(self.tick, key.clone());
        Some(self.tick)
    }

    fn get(&mut self, key: &K) -> Option<V> {
        self.touch(key)?;
        self.entries.get(key).map(|(value, _)| value.clone())
    }

    fn put(&mut self, key: K, value: V) {
        if self.touch(&key).is_none() {
            while self.entries.len() >= self.capacity {
                let Some((_, oldest)) = self.recency.pop_first() else {
                    break;
                };
                self.entries.remove(&oldest);
            }
            self.tick += 1;
            self.recency.insert(self.tick, key.clone());
            self.entries.insert(key.clone(), (value, self.tick));
            return;
        }
        if let Some((cached, _)) = self.entries.get_mut(&key) {
            *cached = value;
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.recency.clear();
    }
}

type PreparedKeys = Lru<KeyDigest, Arc<PreparedGroth16Bn254Key>>;

static PREPARED: LazyLock<Mutex<PreparedKeys>> =
    LazyLock::new(|| Mutex::new(Lru::new(PREPARED_KEYS)));
static VERIFIED: LazyLock<Mutex<Lru<ProofKey, bool>>> =
    LazyLock::new(|| Mutex::new(Lru::new(VERIFIED_PROOFS)));

/// A cache is consistent after any panic: each change is one map update.
fn locked<T>(cache: &Mutex<T>) -> MutexGuard<'_, T> {
    cache.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `zk.verify_groth16` after its checks: the cached result, else the proof
/// verified with the key's prepared form (prepared once per key bytes) and
/// its result cached.
pub(crate) fn verify_registered(proof: &RegisteredProof) -> Result<bool, VerifierError> {
    let cache_key = proof.cache_key();
    if let Some(verified) = locked(&VERIFIED).get(&cache_key) {
        return Ok(verified);
    }
    let prepared = prepared_key(&proof.key)?;
    let verified =
        verify_groth16_bn254_prepared(&prepared, &proof.proof_hex, &proof.public_inputs)?;
    locked(&VERIFIED).put(cache_key, verified);
    Ok(verified)
}

fn prepared_key(key: &RegisteredKey) -> Result<Arc<PreparedGroth16Bn254Key>, VerifierError> {
    if let Some(prepared) = locked(&PREPARED).get(&key.digest) {
        return Ok(prepared);
    }
    let prepared = Arc::new(prepare_groth16_bn254_vk(&key.vk_hex)?);
    locked(&PREPARED).put(key.digest, prepared.clone());
    Ok(prepared)
}

/// `zk.warm_verified_proofs` after its checks and charge: each proof's
/// cached result, the others verified together (the first failing one fails
/// the call) and their results cached.
pub(crate) fn warm(proofs: &[RegisteredProof]) -> Result<Vec<bool>, VerifierError> {
    let mut results: Vec<Option<bool>> = {
        let mut verified = locked(&VERIFIED);
        proofs
            .iter()
            .map(|proof| verified.get(&proof.cache_key()))
            .collect()
    };
    let pending: Vec<usize> = (0..proofs.len())
        .filter(|index| results[*index].is_none())
        .collect();
    if pending.is_empty() {
        return Ok(results.into_iter().flatten().collect());
    }
    let items: Vec<Groth16Bn254BatchItem> = pending
        .iter()
        .map(|index| batch_item(&proofs[*index]))
        .collect();
    let verified = verify_groth16_bn254_grouped(&items)?;
    let mut cache = locked(&VERIFIED);
    for (index, result) in pending.into_iter().zip(verified) {
        cache.put(proofs[index].cache_key(), result);
        results[index] = Some(result);
    }
    Ok(results.into_iter().flatten().collect())
}

fn batch_item(proof: &RegisteredProof) -> Groth16Bn254BatchItem {
    Groth16Bn254BatchItem {
        vk_hex: proof.key.vk_hex.clone(),
        proof_hex: proof.proof_hex.clone(),
        public_inputs: proof.public_inputs.clone(),
    }
}

/// `zk.clear_prepared_vk_cache`.
pub(crate) fn clear_prepared() {
    locked(&PREPARED).clear();
}

/// `zk.clear_verified_proof_cache` (the node clears it for every block).
pub(crate) fn clear_verified() {
    locked(&VERIFIED).clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use xian_zk::build_demo_vector;

    fn proof(vk_hex: &str, proof_hex: &str, inputs: &[String]) -> RegisteredProof {
        RegisteredProof {
            key: RegisteredKey::new(vk_hex.to_owned()),
            proof_hex: proof_hex.to_owned(),
            public_inputs: inputs.to_vec(),
        }
    }

    #[test]
    fn results_follow_the_key_bytes() {
        let demo = build_demo_vector().unwrap();
        let wrong = vec![format!("0x{}", "00".repeat(31) + "05")];
        let real = |inputs: &[String]| proof(&demo.vk_hex, &demo.proof_hex, inputs);
        let garbage = |inputs: &[String]| proof("0x1234", &demo.proof_hex, inputs);
        assert_eq!(verify_registered(&real(&demo.public_inputs)), Ok(true));
        assert_eq!(warm(&[real(&demo.public_inputs)]), Ok(vec![true]));
        // The same proof and inputs over other key bytes: those bytes are
        // verified, whatever is cached for the first ones.
        assert!(verify_registered(&garbage(&demo.public_inputs)).is_err());
        assert!(warm(&[garbage(&demo.public_inputs)]).is_err());
        assert_eq!(verify_registered(&real(&wrong)), Ok(false));
        assert_eq!(
            warm(&[real(&wrong), real(&demo.public_inputs)]),
            Ok(vec![false, true])
        );
    }

    #[test]
    fn the_least_recently_used_entry_is_evicted_first() {
        let mut lru = Lru::new(2);
        lru.put("a", 1);
        lru.put("b", 2);
        assert_eq!(lru.get(&"a"), Some(1));
        lru.put("c", 3);
        assert_eq!(lru.get(&"b"), None);
        assert_eq!(lru.get(&"a"), Some(1));
        assert_eq!(lru.get(&"c"), Some(3));
        lru.put("c", 4);
        lru.put("d", 5);
        assert_eq!(lru.get(&"a"), None);
        assert_eq!(lru.get(&"c"), Some(4));
        assert_eq!(lru.entries.len(), 2);
        assert_eq!(lru.recency.len(), 2);
        lru.clear();
        assert_eq!(lru.get(&"c"), None);
    }
}
