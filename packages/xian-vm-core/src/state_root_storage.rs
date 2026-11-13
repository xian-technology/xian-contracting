//! The state root of committed storage: every hashed key with the exact bytes
//! LMDB holds for it, read from one snapshot. Values are not decoded; a leaf
//! commits to the stored bytes themselves (see `state_root.rs`).
use crate::lmdb_env::{LmdbEnv, LmdbError};
use crate::state_root::{leaf_hash, StateRootTree, TreeBuilder};

/// A stored JSON `null`: the key reads as absent, as the driver reads it.
const ABSENT: &[u8] = b"null";

/// The keys the state root hashes: every key that does not start with `__`,
/// and the node keys and node key prefixes listed.
pub struct HashedKeys {
    node_keys: Vec<String>,
    node_prefixes: Vec<String>,
}

impl HashedKeys {
    pub fn new(node_keys: Vec<String>, node_prefixes: Vec<String>) -> Self {
        Self {
            node_keys,
            node_prefixes,
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        !key.starts_with("__")
            || self.node_keys.iter().any(|node_key| node_key == key)
            || self
                .node_prefixes
                .iter()
                .any(|prefix| key.starts_with(prefix.as_str()))
    }
}

#[derive(Debug)]
pub enum StorageRootError {
    Lmdb(LmdbError),
    /// A stored key that is not UTF-8 text (the node only writes text keys).
    KeyNotText(Vec<u8>),
}

impl From<LmdbError> for StorageRootError {
    fn from(error: LmdbError) -> Self {
        Self::Lmdb(error)
    }
}

/// The tree of every hashed entry committed in `env`, from one read snapshot.
pub fn storage_state_root(
    env: &LmdbEnv,
    hashed: &HashedKeys,
) -> Result<StateRootTree, StorageRootError> {
    let mut builder = TreeBuilder::default();
    let mut not_text = None;
    env.read(|txn| {
        txn.scan_from(b"", |key, stored| {
            let Ok(text) = std::str::from_utf8(key) else {
                not_text = Some(key.to_vec());
                return Ok(false);
            };
            if stored != ABSENT && hashed.contains(text) {
                builder
                    .push(text.to_owned(), leaf_hash(text, stored))
                    .expect("LMDB yields keys in ascending byte order");
            }
            Ok(true)
        })
    })?;
    match not_text {
        Some(key) => Err(StorageRootError::KeyNotText(key)),
        None => Ok(builder.finish()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb_env::OpenOptions;

    fn hashed_keys() -> HashedKeys {
        HashedKeys::new(
            vec!["__fee_policy".to_owned(), "__execution_policy".to_owned()],
            vec!["__n:".to_owned(), "__runtime_features.".to_owned()],
        )
    }

    fn storage(name: &str, entries: &[(&[u8], &[u8])]) -> LmdbEnv {
        let dir =
            std::env::temp_dir().join(format!("xian-state-root-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let options = OpenOptions {
            map_size: 1 << 24,
            max_dbs: 1,
            readahead: true,
            writemap: false,
            sync: false,
            metasync: false,
            readonly: false,
            lock: true,
        };
        let env = LmdbEnv::open(&dir, options).unwrap();
        env.write(|txn| {
            entries
                .iter()
                .try_for_each(|(key, value)| txn.put(key, value))
        })
        .unwrap();
        env
    }

    #[test]
    fn the_hashed_keys_are_contract_state_and_the_listed_node_keys() {
        let keys = hashed_keys();
        for key in ["__local", "__n", "__fee_policyx", "__runtime_features"] {
            assert!(!keys.contains(key), "{key}");
        }
        for key in [
            "con.a",
            "_x",
            "__fee_policy",
            "__execution_policy",
            "__n:alice",
            "__runtime_features.zk",
        ] {
            assert!(keys.contains(key), "{key}");
        }
    }

    #[test]
    fn the_storage_root_hashes_the_stored_bytes_of_every_hashed_key() {
        // Values are hashed as stored, whether or not they decode.
        let entries: &[(&[u8], &[u8])] = &[
            (b"con.b", br#"{"y":1,"x":2}"#),
            (b"con.a", b"1"),
            (b"__local", b"2"),
            (b"__n:alice", b"3"),
            (b"con.null", b"null"),
            (b"con.raw", br#"{"__bytes__":"ff27"}"#),
            (b"con.bad", b"1.5"),
        ];
        let (tree, expected) = (
            storage_state_root(&storage("scan", entries), &hashed_keys()).unwrap(),
            StateRootTree::from_leaves(vec![
                ("__n:alice".to_owned(), leaf_hash("__n:alice", b"3")),
                ("con.a".to_owned(), leaf_hash("con.a", b"1")),
                ("con.b".to_owned(), leaf_hash("con.b", br#"{"y":1,"x":2}"#)),
                ("con.bad".to_owned(), leaf_hash("con.bad", b"1.5")),
                (
                    "con.raw".to_owned(),
                    leaf_hash("con.raw", br#"{"__bytes__":"ff27"}"#),
                ),
            ])
            .unwrap(),
        );
        assert_eq!(tree.root_hash(), expected.root_hash());
        assert_eq!(tree.len(), 5);
    }

    #[test]
    fn a_key_that_is_not_text_is_refused() {
        let env = storage("bytes", &[(b"con.a", b"1"), (b"con.\xff", b"1")]);
        assert!(matches!(
            storage_state_root(&env, &hashed_keys()),
            Err(StorageRootError::KeyNotText(key)) if key == b"con.\xff"
        ));
    }

    #[test]
    fn a_closed_environment_reports_the_storage_error() {
        let env = storage("closed", &[(b"con.a", b"1")]);
        env.close();
        assert!(matches!(
            storage_state_root(&env, &hashed_keys()),
            Err(StorageRootError::Lmdb(LmdbError::Closed))
        ));
    }

    #[test]
    fn empty_storage_has_the_empty_root() {
        let tree = storage_state_root(&storage("empty", &[]), &hashed_keys()).unwrap();
        assert_eq!(tree.root_hash(), crate::state_root::empty_root());
        assert!(tree.is_empty());
    }
}
