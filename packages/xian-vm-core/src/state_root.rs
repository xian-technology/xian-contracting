//! The consensus state root (`xian-state-root-v2`): a treap over the hashed
//! state keys whose shape and hashes depend only on the set of (key, leaf).
//!
//! - leaf = sha256("xian-state-root-v2:leaf:" | len8(key) | key | len8(json) | json),
//!   where `json` is the value's ABCI JSON and `len8` a big-endian u64 length;
//! - priority = sha256("xian-state-root-v2:priority:" | key) as a big-endian
//!   number; a parent's priority is lower than its children's;
//! - node hash = sha256("xian-state-root-v2:node:" | left | leaf | right), an
//!   empty subtree hashing to sha256("xian-state-root-v2:empty").
//!
//! Keys are ordered by their UTF-8 bytes, which is Python's code point order.
//! Distinct keys have distinct priorities (sha256), so the treap, and with it
//! the root, is the same whichever order leaves were added in.
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::sync::OnceLock;

pub type Hash = [u8; 32];

const EMPTY_TAG: &[u8] = b"xian-state-root-v2:empty";
const LEAF_PREFIX: &[u8] = b"xian-state-root-v2:leaf:";
const NODE_PREFIX: &[u8] = b"xian-state-root-v2:node:";
const PRIORITY_PREFIX: &[u8] = b"xian-state-root-v2:priority:";
const NIL: u32 = u32::MAX;
const LEFT: usize = 0;
const RIGHT: usize = 1;

/// The root of an empty state.
pub fn empty_root() -> Hash {
    static EMPTY: OnceLock<Hash> = OnceLock::new();
    *EMPTY.get_or_init(|| Sha256::digest(EMPTY_TAG).into())
}

/// The leaf hash of `key` holding a value whose ABCI JSON is `value_json`.
pub fn leaf_hash(key: &str, value_json: &[u8]) -> Hash {
    let mut digest = Sha256::new();
    digest.update(LEAF_PREFIX);
    for part in [key.as_bytes(), value_json] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn priority(key: &str) -> Hash {
    let mut digest = Sha256::new();
    digest.update(PRIORITY_PREFIX);
    digest.update(key.as_bytes());
    digest.finalize().into()
}

/// A key that does not follow the previous one in a one-pass build (after
/// sorting: a key given twice).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateKey(pub String);

struct Node {
    key: Box<str>,
    priority: Hash,
    leaf: Hash,
    hash: Hash,
    /// `[left, right]` subtrees.
    children: [u32; 2],
}

/// The side of `node` that holds `key`, or None when `key` is the node's.
fn side_of(key: &str, node: &Node) -> Option<usize> {
    match key.cmp(&node.key) {
        Ordering::Equal => None,
        Ordering::Less => Some(LEFT),
        Ordering::Greater => Some(RIGHT),
    }
}

/// The treap, its nodes in an arena (`NIL` is an empty link).
pub struct StateRootTree {
    nodes: Vec<Node>,
    free: Vec<u32>,
    root: u32,
}

impl Default for StateRootTree {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            root: NIL,
        }
    }
}

impl StateRootTree {
    /// A tree of `leaves`, in any order.
    pub fn from_leaves(mut leaves: Vec<(String, Hash)>) -> Result<Self, DuplicateKey> {
        leaves.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut builder = TreeBuilder::default();
        for (key, leaf) in leaves {
            builder.push(key, leaf)?;
        }
        Ok(builder.finish())
    }

    pub fn root_hash(&self) -> Hash {
        self.hash_of(self.root)
    }

    pub fn len(&self) -> usize {
        self.nodes.len() - self.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn leaf_hash(&self, key: &str) -> Option<Hash> {
        let mut at = self.root;
        while at != NIL {
            let node = &self.nodes[at as usize];
            match side_of(key, node) {
                None => return Some(node.leaf),
                Some(side) => at = node.children[side],
            }
        }
        None
    }

    /// Add `key` or replace its leaf.
    pub fn set(&mut self, key: &str, leaf: Hash) {
        self.root = self.insert(self.root, key, leaf);
    }

    /// Remove `key`; false when it was absent.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.len();
        self.root = self.delete(self.root, key);
        self.len() != before
    }

    fn hash_of(&self, at: u32) -> Hash {
        if at == NIL {
            empty_root()
        } else {
            self.nodes[at as usize].hash
        }
    }

    fn priority_of(&self, at: u32) -> &Hash {
        &self.nodes[at as usize].priority
    }

    fn refresh(&mut self, at: u32) -> u32 {
        let node = &self.nodes[at as usize];
        let mut digest = Sha256::new();
        digest.update(NODE_PREFIX);
        digest.update(self.hash_of(node.children[LEFT]));
        digest.update(node.leaf);
        digest.update(self.hash_of(node.children[RIGHT]));
        self.nodes[at as usize].hash = digest.finalize().into();
        at
    }

    /// A detached node; its hash is set by the caller's refresh.
    fn alloc(&mut self, key: &str, leaf: Hash) -> u32 {
        let node = Node {
            key: key.into(),
            priority: priority(key),
            leaf,
            hash: [0; 32],
            children: [NIL; 2],
        };
        match self.free.pop() {
            Some(at) => {
                self.nodes[at as usize] = node;
                at
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        }
    }

    fn release(&mut self, at: u32) {
        let node = &mut self.nodes[at as usize];
        node.key = "".into();
        node.children = [NIL; 2];
        self.free.push(at);
    }

    fn insert(&mut self, at: u32, key: &str, leaf: Hash) -> u32 {
        if at == NIL {
            let new = self.alloc(key, leaf);
            return self.refresh(new);
        }
        let Some(side) = side_of(key, &self.nodes[at as usize]) else {
            self.nodes[at as usize].leaf = leaf;
            return self.refresh(at);
        };
        let below = self.nodes[at as usize].children[side];
        let child = self.insert(below, key, leaf);
        self.nodes[at as usize].children[side] = child;
        if self.priority_of(child) < self.priority_of(at) {
            return self.rotate(at, side);
        }
        self.refresh(at)
    }

    /// Lift the child of `at` on `side` above it.
    fn rotate(&mut self, at: u32, side: usize) -> u32 {
        let child = self.nodes[at as usize].children[side];
        self.nodes[at as usize].children[side] = self.nodes[child as usize].children[1 - side];
        self.nodes[child as usize].children[1 - side] = self.refresh(at);
        self.refresh(child)
    }

    fn delete(&mut self, at: u32, key: &str) -> u32 {
        if at == NIL {
            return NIL;
        }
        let Some(side) = side_of(key, &self.nodes[at as usize]) else {
            let [left, right] = self.nodes[at as usize].children;
            self.release(at);
            return self.merge(left, right);
        };
        let below = self.nodes[at as usize].children[side];
        let child = self.delete(below, key);
        self.nodes[at as usize].children[side] = child;
        self.refresh(at)
    }

    /// One subtree of the keys of `left` then `right`, the lighter root on top.
    fn merge(&mut self, left: u32, right: u32) -> u32 {
        if left == NIL {
            return right;
        }
        if right == NIL {
            return left;
        }
        let (top, side) = if self.priority_of(left) < self.priority_of(right) {
            (left, RIGHT)
        } else {
            (right, LEFT)
        };
        let inner = self.nodes[top as usize].children[side];
        let merged = if side == RIGHT {
            self.merge(inner, right)
        } else {
            self.merge(left, inner)
        };
        self.nodes[top as usize].children[side] = merged;
        self.refresh(top)
    }
}

/// Builds a tree in one pass from leaves in ascending key order: each node
/// takes the lighter nodes of the right spine as its left subtree (a
/// Cartesian tree), and every hash is computed once at the end.
#[derive(Default)]
pub struct TreeBuilder {
    tree: StateRootTree,
    spine: Vec<u32>,
}

impl TreeBuilder {
    /// Append the leaf of `key`, which must follow every key pushed before.
    pub fn push(&mut self, key: String, leaf: Hash) -> Result<(), DuplicateKey> {
        if let Some(&last) = self.spine.last() {
            if *self.tree.nodes[last as usize].key >= *key {
                return Err(DuplicateKey(key));
            }
        }
        let at = self.tree.alloc(&key, leaf);
        let mut lighter = NIL;
        while let Some(&top) = self.spine.last() {
            if self.tree.priority_of(top) < self.tree.priority_of(at) {
                break;
            }
            lighter = top;
            self.spine.pop();
        }
        self.tree.nodes[at as usize].children[LEFT] = lighter;
        if let Some(&top) = self.spine.last() {
            self.tree.nodes[top as usize].children[RIGHT] = at;
        }
        self.spine.push(at);
        Ok(())
    }

    pub fn finish(mut self) -> StateRootTree {
        self.tree.root = self.spine.first().copied().unwrap_or(NIL);
        // Children before parents: a node is refreshed once both subtrees are.
        let mut pending = vec![(self.tree.root, false)];
        while let Some((at, children_done)) = pending.pop() {
            if at == NIL {
                continue;
            }
            if children_done {
                self.tree.refresh(at);
            } else {
                let [left, right] = self.tree.nodes[at as usize].children;
                pending.extend([(at, true), (left, false), (right, false)]);
            }
        }
        self.tree
    }
}

#[cfg(test)]
mod tests {
    //! Roots pinned from the Python treap the node used before (xian-abci
    //! `tests/unit/state_root_reference.py`).
    use super::*;

    fn int_leaves<'a>(items: impl IntoIterator<Item = (&'a str, i64)>) -> Vec<(String, Hash)> {
        items
            .into_iter()
            .map(|(key, value)| (key.to_owned(), leaf_hash(key, value.to_string().as_bytes())))
            .collect()
    }

    fn numbered(indices: impl Iterator<Item = i64>) -> Vec<(String, Hash)> {
        indices
            .map(|index| {
                let key = format!("con_x.v:{index}");
                let leaf = leaf_hash(&key, index.to_string().as_bytes());
                (key, leaf)
            })
            .collect()
    }

    fn incremental(leaves: &[(String, Hash)]) -> StateRootTree {
        let mut tree = StateRootTree::default();
        for (key, leaf) in leaves {
            tree.set(key, *leaf);
        }
        tree
    }

    fn hex_root(tree: &StateRootTree) -> String {
        hex::encode(tree.root_hash())
    }

    const TWO_HUNDRED: &str = "00705c1589e656029482e02094faad609a5f39fc8b61a7044b1b06401020c1f5";
    const ODD: &str = "dfc68304459e2010012fd2f4c5db945740fc14584ac1d56124496a5872c25471";

    #[test]
    fn hashes_match_the_python_definition() {
        assert_eq!(
            hex::encode(empty_root()),
            "1b8cced727c37a3d8c770c4e67e9c2e798a145dd6b96086f398fad3c54e7ccc0"
        );
        assert_eq!(
            hex::encode(leaf_hash("currency.balances:alice", b"1")),
            "ed6669f4697c4b09733c4a127d46510f089b8ac9f772a95ee23f5febb4246c3d"
        );
        let two = int_leaves([("currency.balances:alice", 1), ("currency.balances:bob", 2)]);
        assert_eq!(
            hex_root(&StateRootTree::from_leaves(two).unwrap()),
            "7e3c87527d71b6fdf2c2bc2512147371b94e43ec3ca4cdc33feabe94936ba654"
        );
    }

    #[test]
    fn an_empty_tree_has_the_empty_root() {
        let tree = StateRootTree::from_leaves(Vec::new()).unwrap();
        assert_eq!(tree.root_hash(), empty_root());
        assert!(tree.is_empty());
        assert_eq!(StateRootTree::default().root_hash(), empty_root());
    }

    #[test]
    fn one_pass_and_incremental_builds_give_the_python_root() {
        let leaves = numbered(0..200);
        assert_eq!(
            hex_root(&StateRootTree::from_leaves(leaves.clone()).unwrap()),
            TWO_HUNDRED
        );
        assert_eq!(hex_root(&incremental(&leaves)), TWO_HUNDRED);
        let reversed: Vec<_> = leaves.iter().rev().cloned().collect();
        assert_eq!(hex_root(&incremental(&reversed)), TWO_HUNDRED);
        assert_eq!(StateRootTree::from_leaves(leaves).unwrap().len(), 200);
    }

    #[test]
    fn keys_order_by_code_point_like_python() {
        let keys = ["b", "a\u{1f600}", "a\u{ffff}", "a\u{e9}", "a\u{7f}", "a"];
        let leaves = int_leaves(keys.iter().rev().copied().zip(1..));
        assert_eq!(
            hex_root(&StateRootTree::from_leaves(leaves).unwrap()),
            "0fd99f66c6768c03ea090b7b69bc6565f8871c7166206be6a1df12e40e5578c4"
        );
    }

    #[test]
    fn removing_keys_gives_the_root_of_the_rest() {
        let mut tree = StateRootTree::from_leaves(numbered(0..200)).unwrap();
        for index in (0..200).step_by(2) {
            assert!(tree.remove(&format!("con_x.v:{index}")));
        }
        assert!(!tree.remove("con_x.v:0"));
        assert_eq!(hex_root(&tree), ODD);
        assert_eq!(tree.len(), 100);
        // Freed nodes are reused and the root follows the key set only.
        for (key, leaf) in numbered((0..200).step_by(2)) {
            tree.set(&key, leaf);
        }
        assert_eq!(hex_root(&tree), TWO_HUNDRED);
        assert_eq!(tree.len(), 200);
    }

    #[test]
    fn replacing_a_leaf_changes_the_root_and_reverting_restores_it() {
        let mut tree = StateRootTree::from_leaves(numbered(0..50)).unwrap();
        let before = tree.root_hash();
        let original = tree.leaf_hash("con_x.v:7").unwrap();
        tree.set("con_x.v:7", leaf_hash("con_x.v:7", b"8"));
        assert_ne!(tree.root_hash(), before);
        tree.set("con_x.v:7", original);
        assert_eq!(tree.root_hash(), before);
        assert_eq!(tree.leaf_hash("con_x.v:none"), None);
        assert_eq!(tree.len(), 50);
    }

    #[test]
    fn a_key_given_twice_is_refused() {
        let mut leaves = numbered(0..3);
        leaves.push(leaves[1].clone());
        assert_eq!(
            StateRootTree::from_leaves(leaves).err(),
            Some(DuplicateKey("con_x.v:1".to_owned()))
        );
        let mut builder = TreeBuilder::default();
        builder.push("b".to_owned(), [0; 32]).unwrap();
        assert!(builder.push("a".to_owned(), [0; 32]).is_err());
    }
}
