//! Hash index of a V2 dictionary. Entries stay in one insertion-ordered
//! vector; the index maps a key hash to the entries holding that hash, so a
//! lookup compares the needle only with those entries.
//!
//! `key_hash` must give equal keys equal hashes under V2 equality. It follows
//! the cases of that equality: integers by value (V2 never equates a bool
//! with a number), text and bytes by payload, tuples item by item. Set
//! equality is a containment test between sets of equal size, so a frozenset
//! hashes by its size alone. Callables, handles and descriptors are equal
//! only to themselves or to an equal object of their own kind and share one
//! hash per kind. Binary floats and raw Decimals (and their tuples) do not
//! exist in V2; a key holding one has no hash and its dictionary keeps the
//! linear scan.
//!
//! The hash function is fixed (FNV-1a over a tagged encoding), so collisions,
//! and with them the number of compared entries, are the same on every node.
//! Each comparison is metered, which makes engineered collisions cost their
//! author. Archival V1 never builds an index.
use crate::{VmExecutionError, VmValue};
use std::borrow::Cow;
use std::collections::HashMap;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Accounted heap bytes the index adds to each entry: one bucket slot and
/// one entry id.
pub(crate) const INDEX_BYTES_PER_ENTRY: usize =
    std::mem::size_of::<(u64, Bucket)>() + std::mem::size_of::<u64>();

/// Hash of a dictionary key under V2 equality; `None` for keys V2 cannot hold.
/// Counts one unit of element work per visited key node and one per 8
/// hashed payload bytes.
pub(crate) fn key_hash(key: &VmValue) -> Result<Option<u64>, VmExecutionError> {
    let mut hasher = KeyHasher(FNV_OFFSET);
    Ok(hasher.add(key)?.then_some(hasher.0))
}

struct KeyHasher(u64);

impl KeyHasher {
    fn add(&mut self, key: &VmValue) -> Result<bool, VmExecutionError> {
        crate::work_meter::count(1)?;
        key.with_resolved(|key| match key {
            VmValue::Tuple(items) => self.items(items),
            VmValue::FrozenSet(items) => {
                self.length(6, items.len());
                Ok(true)
            }
            VmValue::Float(_) | VmValue::RawDecimal(_) | VmValue::DecimalTuple(_) => Ok(false),
            scalar => {
                let (tag, payload) = encoding(scalar);
                self.payload(tag, &payload)?;
                Ok(true)
            }
        })
    }

    fn items(&mut self, items: &[VmValue]) -> Result<bool, VmExecutionError> {
        self.length(5, items.len());
        for item in items {
            if !self.add(item)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn length(&mut self, tag: u8, length: usize) {
        self.write(&[tag]);
        self.write(&(length as u64).to_le_bytes());
    }

    fn payload(&mut self, tag: u8, bytes: &[u8]) -> Result<(), VmExecutionError> {
        crate::work_meter::count(crate::work_meter::searched(bytes.len()))?;
        self.length(tag, bytes.len());
        self.write(bytes);
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
        }
    }
}

/// Tag and payload of a key that is neither a container nor a V1-only number.
/// Equal keys share both: integers by value (V2 never equates a bool with a
/// number), text, bytes and names by content.
fn encoding(value: &VmValue) -> (u8, Cow<'_, [u8]>) {
    match value {
        VmValue::None => (0, Cow::Borrowed(&[])),
        VmValue::Bool(value) => (1, Cow::Owned(vec![u8::from(*value)])),
        VmValue::Int(value) => {
            let (sign, mut digits) = value.to_bytes_le();
            digits.push(sign as u8);
            (2, Cow::Owned(digits))
        }
        VmValue::String(text) => (3, Cow::Borrowed(text.as_bytes())),
        VmValue::Bytes(bytes) => (4, Cow::Borrowed(bytes)),
        VmValue::Builtin(name) => (7, Cow::Borrowed(name.as_bytes())),
        VmValue::FunctionRef(name) => (8, Cow::Borrowed(name.as_bytes())),
        VmValue::TypeMarker(name) => (9, Cow::Borrowed(name.as_bytes())),
        other => (10 + kind(other), Cow::Borrowed(&[])),
    }
}

/// Kinds of keys compared by identity or by their whole structure.
fn kind(value: &VmValue) -> u8 {
    match value {
        VmValue::DeploymentHandle => 0,
        VmValue::ContractHandle(_) => 1,
        VmValue::HostCallable(_) => 2,
        VmValue::BoundMethod(_) => 3,
        VmValue::InterfaceSubject(_) => 4,
        VmValue::InterfaceDescriptor(_) => 5,
        _ => 6,
    }
}

/// Ids of the entries sharing one key hash, in entry order. Distinct keys
/// rarely share a hash, so one id is stored inline.
#[derive(Clone, Debug)]
pub(crate) enum Bucket {
    One(u64),
    Many(Vec<u64>),
}

impl Bucket {
    fn ids(&self) -> &[u64] {
        match self {
            Self::One(id) => std::slice::from_ref(id),
            Self::Many(ids) => ids,
        }
    }

    fn push(&mut self, id: u64) {
        match self {
            Self::One(first) => *self = Self::Many(vec![*first, id]),
            Self::Many(ids) => ids.push(id),
        }
    }

    /// Remove `id`; true when the bucket is now empty.
    fn remove(&mut self, id: u64) -> bool {
        match self {
            Self::One(_) => true,
            Self::Many(ids) => {
                ids.retain(|other| *other != id);
                if let [only] = ids.as_slice() {
                    *self = Self::One(*only);
                }
                false
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DictIndex {
    /// One id per entry, in entry order. Ids increase with insertion and are
    /// never reused, so an entry's position is a binary search away.
    ids: Vec<u64>,
    next_id: u64,
    buckets: HashMap<u64, Bucket>,
}

impl DictIndex {
    /// Index every entry; `None` when a key has no hash.
    pub(crate) fn build(entries: &[(VmValue, VmValue)]) -> Result<Option<Self>, VmExecutionError> {
        let mut index = Self::default();
        for (key, _) in entries {
            let Some(hash) = key_hash(key)? else {
                return Ok(None);
            };
            index.push(hash)?;
        }
        Ok(Some(index))
    }

    /// Position of the first entry with `hash` whose key `matches`, trying
    /// entries in insertion order like the linear scan.
    pub(crate) fn find(
        &self,
        entries: &[(VmValue, VmValue)],
        hash: u64,
        mut matches: impl FnMut(&VmValue) -> Result<bool, VmExecutionError>,
    ) -> Result<Option<usize>, VmExecutionError> {
        let Some(bucket) = self.buckets.get(&hash) else {
            return Ok(None);
        };
        for id in bucket.ids() {
            let position = self.position(*id);
            if matches(&entries[position].0)? {
                return Ok(Some(position));
            }
        }
        Ok(None)
    }

    fn position(&self, id: u64) -> usize {
        self.ids
            .binary_search(&id)
            .expect("indexed entry id is present")
    }

    /// Record an entry appended with key hash `hash`: one unit of work.
    fn push(&mut self, hash: u64) -> Result<(), VmExecutionError> {
        crate::work_meter::count(1)?;
        let id = self.next_id;
        self.next_id += 1;
        self.ids.push(id);
        self.buckets
            .entry(hash)
            .and_modify(|bucket| bucket.push(id))
            .or_insert(Bucket::One(id));
        Ok(())
    }

    /// Forget the entry at `position`, whose key hash is `hash`.
    fn remove(&mut self, position: usize, hash: u64) {
        let id = self.ids.remove(position);
        let bucket = self.buckets.get_mut(&hash).expect("indexed hash");
        if bucket.remove(id) {
            self.buckets.remove(&hash);
        }
    }

    /// Keep `index` in step with an entry appended with key hash `hash`; a
    /// key without a hash drops the index.
    pub(crate) fn pushed(
        index: &mut Option<Self>,
        hash: Option<u64>,
    ) -> Result<(), VmExecutionError> {
        match (index.as_mut(), hash) {
            (Some(built), Some(hash)) => built.push(hash),
            (_, None) => {
                *index = None;
                Ok(())
            }
            (None, Some(_)) => Ok(()),
        }
    }

    /// Keep `index` in step with removing the entry at `position`.
    pub(crate) fn removed(index: &mut Option<Self>, position: usize, hash: Option<u64>) {
        match (index.as_mut(), hash) {
            (Some(built), Some(hash)) => built.remove(position, hash),
            _ => *index = None,
        }
    }
}
