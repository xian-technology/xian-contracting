//! The state root of committed storage, read in Rust: the work node startup
//! did in Python (decode every stored value, render its ABCI JSON, hash it).
//!
//! The leaf JSON of a stored value is Python's
//! `encode_abci_json(decode(stored))`: the V2 stored encoding of the value
//! with dictionary keys sorted, datetimes as their `str()` and bytes as their
//! UTF-8 text. Entries whose outcome only Python decides are handed back with
//! their stored bytes, and the caller settles them as before: keys or values
//! that do not decode (Python raises), text the VM cannot hold (lone
//! surrogates), bytes that are not UTF-8 (Python writes their repr) and
//! bytearrays or timedeltas (`json.dumps` raises).
use crate::lmdb_env::{LmdbEnv, LmdbError};
use crate::state_root::{leaf_hash, Hash, StateRootTree, TreeBuilder};
use crate::stored_value::decode_stored_value;
use crate::stored_value_encoder::encode_stored_value;
use crate::VmValue;
use std::borrow::Cow;

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

/// `(key, stored value)` entries handed back to Python, in key order.
pub type HandedBack = Vec<(Vec<u8>, Vec<u8>)>;

/// The tree of every hashed entry committed in `env` (one read snapshot), and
/// the entries handed back.
pub fn storage_state_root(
    env: &LmdbEnv,
    hashed: &HashedKeys,
) -> Result<(StateRootTree, HandedBack), LmdbError> {
    env.read(|txn| {
        let mut builder = TreeBuilder::default();
        let mut handed_back = Vec::new();
        txn.scan_from(b"", |key, stored| {
            match stored_leaf(key, stored, hashed) {
                Leaf::Hashed(key, leaf) => builder
                    .push(key.to_owned(), leaf)
                    .expect("LMDB yields keys in ascending byte order"),
                Leaf::Skipped => {}
                Leaf::HandedBack => handed_back.push((key.to_vec(), stored.to_vec())),
            }
            Ok(true)
        })?;
        Ok((builder.finish(), handed_back))
    })
}

enum Leaf<'a> {
    Hashed(&'a str, Hash),
    /// A node-local key, or a stored `null` (Python reads it as absent).
    Skipped,
    HandedBack,
}

fn stored_leaf<'a>(key: &'a [u8], stored: &[u8], hashed: &HashedKeys) -> Leaf<'a> {
    let (Ok(key), Ok(value)) = (std::str::from_utf8(key), decode_stored_value(stored)) else {
        return Leaf::HandedBack;
    };
    if matches!(value, VmValue::None) || !hashed.contains(key) {
        return Leaf::Skipped;
    }
    match abci_json(&value) {
        Some(json) => Leaf::Hashed(key, leaf_hash(key, &json)),
        None => Leaf::HandedBack,
    }
}

/// `encode_abci_json(value)` for a decoded stored value, or None when only
/// Python can render it.
pub(crate) fn abci_json(value: &VmValue) -> Option<Vec<u8>> {
    let value = abci_value(value)?;
    encode_stored_value(&value).ok()
}

/// `normalize_for_abci_json`, as far as it differs from the stored form.
fn abci_value(value: &VmValue) -> Option<Cow<'_, VmValue>> {
    match value {
        VmValue::Dict(entries) => sorted_dict(entries),
        VmValue::List(items) | VmValue::Tuple(items) => abci_list(value, items),
        VmValue::DateTime(time) => Some(text(time.to_string())),
        VmValue::Bytes(bytes) => String::from_utf8(bytes.clone()).ok().map(text),
        other => written_as_stored(other).then_some(Cow::Borrowed(value)),
    }
}

fn text(value: String) -> Cow<'static, VmValue> {
    Cow::Owned(VmValue::String(value))
}

/// Values `encode_abci_json` writes as storage does (sets as their codec
/// envelope); bytearrays and timedeltas it refuses.
fn written_as_stored(value: &VmValue) -> bool {
    matches!(
        value,
        VmValue::None
            | VmValue::Bool(_)
            | VmValue::Int(_)
            | VmValue::String(_)
            | VmValue::Decimal(_)
            | VmValue::Set(_)
            | VmValue::FrozenSet(_)
    )
}

/// A list or tuple (both written as a JSON array), borrowed when no item changes.
fn abci_list<'a>(value: &'a VmValue, items: &'a [VmValue]) -> Option<Cow<'a, VmValue>> {
    let items = items.iter().map(abci_value).collect::<Option<Vec<_>>>()?;
    if items.iter().all(|item| matches!(item, Cow::Borrowed(_))) {
        return Some(Cow::Borrowed(value));
    }
    Some(Cow::Owned(VmValue::List(
        items.into_iter().map(Cow::into_owned).collect(),
    )))
}

/// A dictionary with its keys in code point order (decoded keys are text).
fn sorted_dict(entries: &[(VmValue, VmValue)]) -> Option<Cow<'_, VmValue>> {
    let mut sorted = entries
        .iter()
        .map(|(key, item)| match key {
            VmValue::String(key) => Some((key.clone(), abci_value(item)?.into_owned())),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let entries = sorted
        .into_iter()
        .map(|(key, item)| (VmValue::String(key), item))
        .collect();
    Some(Cow::Owned(VmValue::Dict(entries)))
}

#[cfg(test)]
mod tests {
    //! Expected JSON is Python's `encode_abci_json(decode(stored))`.
    use super::*;
    use crate::lmdb_env::OpenOptions;

    const ABCI_JSON: &[(&str, &str)] = &[
        ("1", "1"),
        ("true", "true"),
        ("[]", "[]"),
        ("{}", "{}"),
        (
            r#"{"b":1,"a":{"d":2,"c":[{"z":1,"y":2}]}}"#,
            r#"{"a":{"c":[{"y":2,"z":1}],"d":2},"b":1}"#,
        ),
        (
            r#"{"__time__":[2024,1,2,3,4,5,6]}"#,
            r#""2024-01-02 03:04:05.000006""#,
        ),
        (
            r#"{"__time__":[1,1,1,0,0,0,0]}"#,
            r#""0001-01-01 00:00:00""#,
        ),
        (r#"{"__bytes__":"6f6b"}"#, r#""ok""#),
        (r#"{"__fixed__":"-1.5"}"#, r#"{"__fixed__":"-1.5"}"#),
        (
            r#"{"__big_int__":"9007199254740992"}"#,
            r#"{"__big_int__":"9007199254740992"}"#,
        ),
        (r#" [ 1 , {"b" : 2 , "a" : 1} ] "#, r#"[1,{"a":1,"b":2}]"#),
        (
            r#"[[{"__time__":[2020,2,29,0,0,0,0]}],1]"#,
            r#"[["2020-02-29 00:00:00"],1]"#,
        ),
        (
            r#"{"__set__":{"codec":"xian-set-1","items":[["int","1"],["str","x"]]}}"#,
            r#"{"__set__":{"codec":"xian-set-1","items":[["int","1"],["str","x"]]}}"#,
        ),
        (r#"{"a":"\/","a":3}"#, r#"{"a":3}"#),
    ];

    /// Stored values whose leaf Python decides (it raises or renders a repr).
    const HANDED_BACK: &[&str] = &[
        r#"{"__bytes__":"ff27"}"#,
        r#"{"a":[{"__bytes__":"ff"}]}"#,
        r#"{"__bytearray__":"6162"}"#,
        r#"{"__delta__":[1,5]}"#,
        r#""\ud800""#,
        r#"{"a":1.5}"#,
        "not json",
    ];

    fn decoded_json(stored: &str) -> Option<String> {
        let value = decode_stored_value(stored.as_bytes()).ok()?;
        abci_json(&value).map(|json| String::from_utf8(json).unwrap())
    }

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
    fn stored_values_render_the_abci_json_python_does() {
        for (stored, expected) in ABCI_JSON {
            assert_eq!(decoded_json(stored).as_deref(), Some(*expected), "{stored}");
        }
    }

    #[test]
    fn text_is_written_with_python_ascii_escapes() {
        // Python writes non-ASCII as lower-case u-escapes, astral text as surrogate pairs.
        let escape = |codes: &[&str]| -> String {
            codes
                .iter()
                .map(|code| format!("{}u{code}", '\\'))
                .collect()
        };
        let stored = format!("\"{}\"", escape(&["00e9", "2028", "d83d", "de00", "007f"]));
        assert_eq!(decoded_json(&stored), Some(stored.clone()));
        let raw = "\"\u{e9}\u{2028}\u{1f600}\"";
        assert_eq!(
            decoded_json(raw),
            Some(format!("\"{}\"", escape(&["00e9", "2028", "d83d", "de00"])))
        );
    }

    #[test]
    fn values_only_python_can_render_are_handed_back() {
        for stored in HANDED_BACK {
            assert_eq!(decoded_json(stored), None, "{stored}");
            assert!(matches!(
                stored_leaf(b"con.a", stored.as_bytes(), &hashed_keys()),
                Leaf::HandedBack
            ));
        }
        assert!(matches!(
            stored_leaf(b"con.\xff", b"1", &hashed_keys()),
            Leaf::HandedBack
        ));
    }

    #[test]
    fn node_local_keys_and_stored_nulls_are_skipped() {
        let keys = hashed_keys();
        for key in ["__local", "__n", "__fee_policyx", "__runtime_features"] {
            assert!(!keys.contains(key), "{key}");
            assert!(matches!(
                stored_leaf(key.as_bytes(), b"1", &keys),
                Leaf::Skipped
            ));
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
        assert!(matches!(
            stored_leaf(b"con.a", b"null", &keys),
            Leaf::Skipped
        ));
        // A node-local value Python would refuse to render is never rendered.
        assert!(matches!(
            stored_leaf(b"__local", br#"{"__delta__":[1,5]}"#, &keys),
            Leaf::Skipped
        ));
    }

    #[test]
    fn the_storage_root_hashes_every_consensus_entry_in_one_pass() {
        let env = storage(
            "scan",
            &[
                (b"con.b", br#"{"y":1,"x":2}"#),
                (b"con.a", b"1"),
                (b"__local", b"2"),
                (b"__n:alice", b"3"),
                (b"con.null", b"null"),
                (b"con.raw", br#"{"__bytes__":"ff27"}"#),
                (b"__local.bad", b"1.5"),
            ],
        );
        let (tree, handed_back) = storage_state_root(&env, &hashed_keys()).unwrap();
        let expected = StateRootTree::from_leaves(vec![
            ("__n:alice".to_owned(), leaf_hash("__n:alice", b"3")),
            ("con.a".to_owned(), leaf_hash("con.a", b"1")),
            ("con.b".to_owned(), leaf_hash("con.b", br#"{"x":2,"y":1}"#)),
        ])
        .unwrap();
        assert_eq!(tree.root_hash(), expected.root_hash());
        assert_eq!(tree.len(), 3);
        assert_eq!(
            handed_back,
            vec![
                (b"__local.bad".to_vec(), b"1.5".to_vec()),
                (b"con.raw".to_vec(), br#"{"__bytes__":"ff27"}"#.to_vec()),
            ]
        );
    }

    #[test]
    fn empty_storage_has_the_empty_root() {
        let (tree, handed_back) =
            storage_state_root(&storage("empty", &[]), &hashed_keys()).unwrap();
        assert_eq!(tree.root_hash(), crate::state_root::empty_root());
        assert!(handed_back.is_empty());
    }
}
