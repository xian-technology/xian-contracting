//! The node's state store: one LMDB environment per state directory, owned by
//! Rust and shared with the Python storage layer.
//!
//! LMDB is the pinned upstream release in `vendor/lmdb` (see its README): the
//! release that wrote existing node state, so files open without migration.
//! Only the unnamed main database is used, as before. Read transactions are not
//! bound to a thread (`MDB_NOTLS`, as the previous binding opened them).
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard};

#[allow(non_camel_case_types)]
mod ffi {
    use super::*;

    pub enum MDB_env {}
    pub enum MDB_txn {}
    pub enum MDB_cursor {}
    pub type MDB_dbi = c_uint;

    #[repr(C)]
    pub struct MDB_val {
        pub mv_size: usize,
        pub mv_data: *mut c_void,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct MDB_envinfo {
        pub me_mapaddr: usize,
        pub me_mapsize: usize,
        pub me_last_pgno: usize,
        pub me_last_txnid: usize,
        pub me_maxreaders: c_uint,
        pub me_numreaders: c_uint,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct MDB_stat {
        pub ms_psize: c_uint,
        pub ms_depth: c_uint,
        pub ms_branch_pages: usize,
        pub ms_leaf_pages: usize,
        pub ms_overflow_pages: usize,
        pub ms_entries: usize,
    }

    pub const MDB_RDONLY: c_uint = 0x20000;
    pub const MDB_NOSYNC: c_uint = 0x10000;
    pub const MDB_NOMETASYNC: c_uint = 0x40000;
    pub const MDB_WRITEMAP: c_uint = 0x80000;
    pub const MDB_NOTLS: c_uint = 0x200000;
    pub const MDB_NOLOCK: c_uint = 0x400000;
    pub const MDB_NORDAHEAD: c_uint = 0x800000;
    pub const MDB_NOTFOUND: c_int = -30798;
    pub const MDB_MAP_FULL: c_int = -30792;
    pub const MDB_FIRST: c_int = 0;
    pub const MDB_NEXT: c_int = 8;
    pub const MDB_SET_RANGE: c_int = 17;

    extern "C" {
        pub fn mdb_strerror(err: c_int) -> *const c_char;
        pub fn mdb_env_create(env: *mut *mut MDB_env) -> c_int;
        pub fn mdb_env_open(
            env: *mut MDB_env,
            path: *const c_char,
            flags: c_uint,
            mode: u16,
        ) -> c_int;
        pub fn mdb_env_close(env: *mut MDB_env);
        pub fn mdb_env_set_mapsize(env: *mut MDB_env, size: usize) -> c_int;
        pub fn mdb_env_set_maxdbs(env: *mut MDB_env, dbs: MDB_dbi) -> c_int;
        pub fn mdb_env_info(env: *mut MDB_env, stat: *mut MDB_envinfo) -> c_int;
        pub fn mdb_txn_begin(
            env: *mut MDB_env,
            parent: *mut MDB_txn,
            flags: c_uint,
            txn: *mut *mut MDB_txn,
        ) -> c_int;
        pub fn mdb_txn_commit(txn: *mut MDB_txn) -> c_int;
        pub fn mdb_txn_abort(txn: *mut MDB_txn);
        pub fn mdb_dbi_open(
            txn: *mut MDB_txn,
            name: *const c_char,
            flags: c_uint,
            dbi: *mut MDB_dbi,
        ) -> c_int;
        pub fn mdb_stat(txn: *mut MDB_txn, dbi: MDB_dbi, stat: *mut MDB_stat) -> c_int;
        pub fn mdb_drop(txn: *mut MDB_txn, dbi: MDB_dbi, del: c_int) -> c_int;
        pub fn mdb_get(
            txn: *mut MDB_txn,
            dbi: MDB_dbi,
            key: *mut MDB_val,
            data: *mut MDB_val,
        ) -> c_int;
        pub fn mdb_put(
            txn: *mut MDB_txn,
            dbi: MDB_dbi,
            key: *mut MDB_val,
            data: *mut MDB_val,
            flags: c_uint,
        ) -> c_int;
        pub fn mdb_del(
            txn: *mut MDB_txn,
            dbi: MDB_dbi,
            key: *mut MDB_val,
            data: *mut MDB_val,
        ) -> c_int;
        pub fn mdb_cursor_open(
            txn: *mut MDB_txn,
            dbi: MDB_dbi,
            cursor: *mut *mut MDB_cursor,
        ) -> c_int;
        pub fn mdb_cursor_close(cursor: *mut MDB_cursor);
        pub fn mdb_cursor_get(
            cursor: *mut MDB_cursor,
            key: *mut MDB_val,
            data: *mut MDB_val,
            op: c_int,
        ) -> c_int;
    }
}

/// The longest storage key, in UTF-8 bytes: LMDB 0.9's `MDB_MAXKEYSIZE`.
///
/// LMDB refuses a longer key only when the block commits, after every node
/// already agreed on the block's state root, so the chain would halt. Storage
/// keys are therefore a consensus rule fixed at this value: V2 fails the
/// transaction that forms a longer key, and the storage layer refuses to stage
/// one. It is a constant rather than a value read from the backend because a
/// rule must not move with the store (LMDB 1.0 derives its limit from the page
/// size); a test pins that the vendored LMDB stores exactly this many bytes.
pub const MAX_STORAGE_KEY_BYTES: usize = 511;

/// Why `key` cannot be stored, or `None` when it can.
pub fn storage_key_error(key: &str) -> Option<String> {
    (key.len() > MAX_STORAGE_KEY_BYTES).then(|| {
        format!(
            "Storage key is too long ({} bytes). Max is {MAX_STORAGE_KEY_BYTES}.",
            key.len()
        )
    })
}

/// A key and value borrowed from the map for one transaction.
type Entry<'t> = (&'t [u8], &'t [u8]);
/// A key and value copied out of the map.
pub type OwnedEntry = (Vec<u8>, Vec<u8>);

/// An LMDB failure. `MapFull` means the write did not fit the current map size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LmdbError {
    MapFull,
    Closed,
    Other(String),
}

impl std::fmt::Display for LmdbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MapFull => f.write_str("MDB_MAP_FULL: Environment mapsize limit reached"),
            Self::Closed => f.write_str("LMDB environment is closed"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for LmdbError {}

fn check(code: c_int, what: &str) -> Result<(), LmdbError> {
    match code {
        0 => Ok(()),
        ffi::MDB_MAP_FULL => Err(LmdbError::MapFull),
        _ => {
            // SAFETY: mdb_strerror returns a static NUL-terminated string.
            let text = unsafe { CStr::from_ptr(ffi::mdb_strerror(code)) };
            Err(LmdbError::Other(format!(
                "{what}: {}",
                text.to_string_lossy()
            )))
        }
    }
}

/// How to open an environment; mirrors the options the storage layer used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenOptions {
    pub map_size: usize,
    pub max_dbs: u32,
    pub readahead: bool,
    pub writemap: bool,
    pub sync: bool,
    pub metasync: bool,
    pub readonly: bool,
    pub lock: bool,
}

impl OpenOptions {
    fn flags(&self) -> c_uint {
        let mut flags = ffi::MDB_NOTLS;
        for (enabled, flag) in [
            (!self.readahead, ffi::MDB_NORDAHEAD),
            (self.writemap, ffi::MDB_WRITEMAP),
            (!self.sync, ffi::MDB_NOSYNC),
            (!self.metasync, ffi::MDB_NOMETASYNC),
            (self.readonly, ffi::MDB_RDONLY),
            (!self.lock, ffi::MDB_NOLOCK),
        ] {
            if enabled {
                flags |= flag;
            }
        }
        flags
    }
}

/// Directories with an open environment in this process. LMDB must not open
/// one environment twice in a process: closing either drops the other's locks.
static OPEN_PATHS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn claim_path(path: &Path) -> Result<PathBuf, LmdbError> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| LmdbError::Other(format!("mdb_env_open: {error}")))?;
    let mut open = OPEN_PATHS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if open.contains(&canonical) {
        return Err(LmdbError::Other(format!(
            "LMDB environment {} is already open in this process",
            canonical.display()
        )));
    }
    open.push(canonical.clone());
    Ok(canonical)
}

fn release_path(path: &Path) {
    OPEN_PATHS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|open| open != path);
}

struct EnvState {
    env: *mut ffi::MDB_env,
    dbi: ffi::MDB_dbi,
    path: PathBuf,
    /// Read snapshots held open by cursors, ended if the environment closes.
    readers: HashMap<u64, Reader>,
    next_reader: u64,
}

/// A cursor and the read transaction it lives in.
struct Reader {
    txn: *mut ffi::MDB_txn,
    cursor: *mut ffi::MDB_cursor,
}

impl Reader {
    /// Close the cursor, then end its transaction. LMDB 1.0 reads the
    /// transaction while closing a cursor (despite documenting that a read
    /// cursor may be closed after its transaction ended), so the order matters.
    ///
    /// # Safety
    /// Both handles must be live.
    unsafe fn end(self) {
        ffi::mdb_cursor_close(self.cursor);
        ffi::mdb_txn_abort(self.txn);
    }
}

// SAFETY: the environment is opened with MDB_NOTLS, so transactions are not
// bound to the thread that began them; all access goes through the mutex.
unsafe impl Send for EnvState {}

/// A shared handle on one open environment.
#[derive(Clone)]
pub struct LmdbEnv {
    state: Arc<Mutex<EnvState>>,
}

impl LmdbEnv {
    pub fn open(path: &Path, options: OpenOptions) -> Result<Self, LmdbError> {
        let c_path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| LmdbError::Other("LMDB path contains NUL".into()))?;
        let claimed = claim_path(path)?;
        let opened = Self::open_claimed(&c_path, options, claimed.clone());
        if opened.is_err() {
            release_path(&claimed);
        }
        opened
    }

    fn open_claimed(
        c_path: &CString,
        options: OpenOptions,
        path: PathBuf,
    ) -> Result<Self, LmdbError> {
        let mut env = ptr::null_mut();
        // SAFETY: plain LMDB environment setup; env is closed on every error path.
        unsafe {
            check(ffi::mdb_env_create(&mut env), "mdb_env_create")?;
            let opened = check(
                ffi::mdb_env_set_mapsize(env, options.map_size),
                "set_mapsize",
            )
            .and_then(|_| check(ffi::mdb_env_set_maxdbs(env, options.max_dbs), "maxdbs"))
            .and_then(|_| {
                check(
                    ffi::mdb_env_open(env, c_path.as_ptr(), options.flags(), 0o644),
                    "mdb_env_open",
                )
            })
            .and_then(|_| open_main_db(env, options.readonly));
            match opened {
                Ok(dbi) => Ok(Self {
                    state: Arc::new(Mutex::new(EnvState {
                        env,
                        dbi,
                        path,
                        readers: HashMap::new(),
                        next_reader: 0,
                    })),
                }),
                Err(error) => {
                    ffi::mdb_env_close(env);
                    Err(error)
                }
            }
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, EnvState>, LmdbError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.env.is_null() {
            return Err(LmdbError::Closed);
        }
        Ok(state)
    }

    /// Close now. Open cursors are invalidated; later calls fail with `Closed`.
    pub fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.env.is_null() {
            return;
        }
        for (_, reader) in state.readers.drain() {
            // SAFETY: each registered reader is live.
            unsafe { reader.end() };
        }
        // SAFETY: no transaction of this environment is live any more.
        unsafe { ffi::mdb_env_close(state.env) };
        state.env = ptr::null_mut();
        release_path(&state.path);
    }

    pub fn is_closed(&self) -> bool {
        self.state().is_err()
    }

    pub fn map_size(&self) -> Result<usize, LmdbError> {
        let state = self.state()?;
        let mut info = ffi::MDB_envinfo::default();
        // SAFETY: env is open.
        check(
            unsafe { ffi::mdb_env_info(state.env, &mut info) },
            "mdb_env_info",
        )?;
        Ok(info.me_mapsize)
    }

    /// Grow (or set) the map size. No write transaction may be open, which the
    /// mutex guarantees for this process.
    pub fn set_map_size(&self, size: usize) -> Result<(), LmdbError> {
        let state = self.state()?;
        // SAFETY: env is open and this process has no write transaction.
        check(
            unsafe { ffi::mdb_env_set_mapsize(state.env, size) },
            "set_mapsize",
        )
    }

    /// Run `read` inside one read transaction (a consistent snapshot).
    pub fn read<R>(
        &self,
        read: impl FnOnce(&Txn<'_>) -> Result<R, LmdbError>,
    ) -> Result<R, LmdbError> {
        let state = self.state()?;
        let txn = begin(state.env, ffi::MDB_RDONLY)?;
        let view = Txn {
            txn,
            dbi: state.dbi,
            _state: std::marker::PhantomData,
        };
        let result = read(&view);
        // SAFETY: read transactions are released by aborting them.
        unsafe { ffi::mdb_txn_abort(txn) };
        result
    }

    /// Run `write` in one write transaction, committed only if it succeeds.
    pub fn write(
        &self,
        write: impl FnOnce(&Txn<'_>) -> Result<(), LmdbError>,
    ) -> Result<(), LmdbError> {
        let state = self.state()?;
        let txn = begin(state.env, 0)?;
        let view = Txn {
            txn,
            dbi: state.dbi,
            _state: std::marker::PhantomData,
        };
        match write(&view) {
            // SAFETY: commit consumes the transaction, also on failure.
            Ok(()) => check(unsafe { ffi::mdb_txn_commit(txn) }, "mdb_txn_commit"),
            Err(error) => {
                // SAFETY: the transaction is live and not yet committed.
                unsafe { ffi::mdb_txn_abort(txn) };
                Err(error)
            }
        }
    }

    /// A cursor over `[start, ..)` in key order, reading one snapshot until it
    /// is dropped or the environment closes.
    pub fn cursor_from(&self, start: &[u8]) -> Result<SnapshotCursor, LmdbError> {
        let mut state = self.state()?;
        let txn = begin(state.env, ffi::MDB_RDONLY)?;
        let mut cursor = ptr::null_mut();
        // SAFETY: txn is a live read transaction on this environment's main db.
        if let Err(error) = check(
            unsafe { ffi::mdb_cursor_open(txn, state.dbi, &mut cursor) },
            "mdb_cursor_open",
        ) {
            unsafe { ffi::mdb_txn_abort(txn) };
            return Err(error);
        }
        let id = state.next_reader;
        state.next_reader += 1;
        state.readers.insert(id, Reader { txn, cursor });
        Ok(SnapshotCursor {
            env: self.clone(),
            id,
            start: Some(start.to_vec()),
        })
    }
}

impl Drop for EnvState {
    fn drop(&mut self) {
        for (_, reader) in self.readers.drain() {
            // SAFETY: registered readers are live.
            unsafe { reader.end() };
        }
        if !self.env.is_null() {
            // SAFETY: last handle; no transactions remain.
            unsafe { ffi::mdb_env_close(self.env) };
            release_path(&self.path);
        }
    }
}

unsafe fn open_main_db(env: *mut ffi::MDB_env, readonly: bool) -> Result<ffi::MDB_dbi, LmdbError> {
    let txn = begin(env, if readonly { ffi::MDB_RDONLY } else { 0 })?;
    let mut dbi = 0;
    if let Err(error) = check(
        ffi::mdb_dbi_open(txn, ptr::null(), 0, &mut dbi),
        "mdb_dbi_open",
    ) {
        ffi::mdb_txn_abort(txn);
        return Err(error);
    }
    if readonly {
        ffi::mdb_txn_abort(txn);
        Ok(dbi)
    } else {
        check(ffi::mdb_txn_commit(txn), "mdb_txn_commit").map(|_| dbi)
    }
}

fn begin(env: *mut ffi::MDB_env, flags: c_uint) -> Result<*mut ffi::MDB_txn, LmdbError> {
    let mut txn = ptr::null_mut();
    // SAFETY: env is open; the caller owns the returned transaction.
    check(
        unsafe { ffi::mdb_txn_begin(env, ptr::null_mut(), flags, &mut txn) },
        "mdb_txn_begin",
    )?;
    Ok(txn)
}

fn val(bytes: &[u8]) -> ffi::MDB_val {
    ffi::MDB_val {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr() as *mut c_void,
    }
}

fn empty_val() -> ffi::MDB_val {
    ffi::MDB_val {
        mv_size: 0,
        mv_data: ptr::null_mut(),
    }
}

/// # Safety
/// `value` must come from LMDB within a live transaction.
unsafe fn bytes_of<'t>(value: &ffi::MDB_val) -> &'t [u8] {
    if value.mv_size == 0 {
        return &[];
    }
    std::slice::from_raw_parts(value.mv_data as *const u8, value.mv_size)
}

/// One transaction's view of the main database; borrowed slices live as long
/// as the transaction.
pub struct Txn<'e> {
    txn: *mut ffi::MDB_txn,
    dbi: ffi::MDB_dbi,
    _state: std::marker::PhantomData<&'e ()>,
}

impl<'e> Txn<'e> {
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, LmdbError> {
        let mut key = val(key);
        let mut data = empty_val();
        // SAFETY: live transaction; data points into the map while it lives.
        match unsafe { ffi::mdb_get(self.txn, self.dbi, &mut key, &mut data) } {
            ffi::MDB_NOTFOUND => Ok(None),
            code => check(code, "mdb_get").map(|_| Some(unsafe { bytes_of(&data) })),
        }
    }

    pub fn entries(&self) -> Result<usize, LmdbError> {
        let mut stat = ffi::MDB_stat::default();
        // SAFETY: live transaction.
        check(
            unsafe { ffi::mdb_stat(self.txn, self.dbi, &mut stat) },
            "mdb_stat",
        )?;
        Ok(stat.ms_entries)
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), LmdbError> {
        let mut key = val(key);
        let mut data = val(value);
        // SAFETY: live write transaction.
        check(
            unsafe { ffi::mdb_put(self.txn, self.dbi, &mut key, &mut data, 0) },
            "mdb_put",
        )
    }

    /// Delete `key`; a missing key is not an error.
    pub fn delete(&self, key: &[u8]) -> Result<(), LmdbError> {
        let mut key = val(key);
        // SAFETY: live write transaction.
        match unsafe { ffi::mdb_del(self.txn, self.dbi, &mut key, ptr::null_mut()) } {
            ffi::MDB_NOTFOUND => Ok(()),
            code => check(code, "mdb_del"),
        }
    }

    /// Remove every entry, keeping the database.
    pub fn clear(&self) -> Result<(), LmdbError> {
        // SAFETY: live write transaction.
        check(unsafe { ffi::mdb_drop(self.txn, self.dbi, 0) }, "mdb_drop")
    }

    /// Visit entries from `start` (inclusive) in key order until `visit`
    /// returns false.
    pub fn scan_from(
        &self,
        start: &[u8],
        mut visit: impl FnMut(&[u8], &[u8]) -> Result<bool, LmdbError>,
    ) -> Result<(), LmdbError> {
        let mut cursor = ptr::null_mut();
        // SAFETY: live transaction; the cursor is closed before returning.
        check(
            unsafe { ffi::mdb_cursor_open(self.txn, self.dbi, &mut cursor) },
            "mdb_cursor_open",
        )?;
        let result = (|| {
            let mut first = true;
            loop {
                let entry = unsafe { cursor_step(cursor, if first { Some(start) } else { None }) }?;
                first = false;
                let Some((key, value)) = entry else {
                    return Ok(());
                };
                if !visit(key, value)? {
                    return Ok(());
                }
            }
        })();
        // SAFETY: cursor belongs to this live transaction.
        unsafe { ffi::mdb_cursor_close(cursor) };
        result
    }
}

/// # Safety
/// `cursor` must be live; returned slices live as long as its transaction.
unsafe fn cursor_step<'t>(
    cursor: *mut ffi::MDB_cursor,
    start: Option<&[u8]>,
) -> Result<Option<Entry<'t>>, LmdbError> {
    let (mut key, op) = match start {
        Some(start) if !start.is_empty() => (val(start), ffi::MDB_SET_RANGE),
        Some(_) => (empty_val(), ffi::MDB_FIRST),
        None => (empty_val(), ffi::MDB_NEXT),
    };
    let mut data = empty_val();
    match ffi::mdb_cursor_get(cursor, &mut key, &mut data, op) {
        ffi::MDB_NOTFOUND => Ok(None),
        code => check(code, "mdb_cursor_get").map(|_| Some((bytes_of(&key), bytes_of(&data)))),
    }
}

/// A key-ordered cursor that keeps its read snapshot between steps.
pub struct SnapshotCursor {
    env: LmdbEnv,
    id: u64,
    start: Option<Vec<u8>>,
}

// SAFETY: MDB_NOTLS read transactions may move between threads; every step
// holds the environment mutex.
unsafe impl Send for SnapshotCursor {}

impl SnapshotCursor {
    /// The next entry, copied out of the map; `None` once the range ends.
    pub fn next_entry(&mut self) -> Result<Option<OwnedEntry>, LmdbError> {
        let state = self.env.state()?;
        let reader = state.readers.get(&self.id).ok_or(LmdbError::Closed)?;
        let start = self.start.take();
        // SAFETY: the reader is registered, so its transaction and cursor live.
        let entry = unsafe { cursor_step(reader.cursor, start.as_deref()) }?;
        Ok(entry.map(|(key, value)| (key.to_vec(), value.to_vec())))
    }
}

impl Drop for SnapshotCursor {
    fn drop(&mut self) {
        let mut state = self
            .env
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A reader the closed environment already ended is gone from the map.
        if let Some(reader) = state.readers.remove(&self.id) {
            // SAFETY: the reader was still registered, so it is live.
            unsafe { reader.end() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> OpenOptions {
        OpenOptions {
            map_size: 1 << 20,
            max_dbs: 1,
            readahead: true,
            writemap: false,
            sync: true,
            metasync: true,
            readonly: false,
            lock: true,
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("xian-lmdb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_vendored_engine_is_lmdb_0_9_37() {
        extern "C" {
            fn mdb_version(
                major: *mut c_int,
                minor: *mut c_int,
                patch: *mut c_int,
            ) -> *const c_char;
        }
        let (mut major, mut minor, mut patch) = (0, 0, 0);
        // SAFETY: mdb_version only writes the three integers.
        unsafe { mdb_version(&mut major, &mut minor, &mut patch) };
        assert_eq!((major, minor, patch), (0, 9, 37));
    }

    #[test]
    fn writes_commit_atomically_and_read_back_in_key_order() {
        let dir = temp_dir("order");
        let env = LmdbEnv::open(&dir, options()).unwrap();
        env.write(|txn| {
            txn.put(b"b", b"2")?;
            txn.put(b"a", b"1")?;
            txn.put(b"c", b"3")
        })
        .unwrap();
        let failed = env.write(|txn| {
            txn.put(b"d", b"4")?;
            Err(LmdbError::Other("abort".into()))
        });
        assert!(failed.is_err());
        let mut seen = Vec::new();
        env.read(|txn| {
            txn.scan_from(b"b", |key, value| {
                seen.push((key.to_vec(), value.to_vec()));
                Ok(true)
            })
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![
                (b"b".to_vec(), b"2".to_vec()),
                (b"c".to_vec(), b"3".to_vec())
            ]
        );
        assert_eq!(env.read(|txn| txn.entries()).unwrap(), 3);
        assert_eq!(
            env.read(|txn| Ok(txn.get(b"d")?.map(<[u8]>::to_vec)))
                .unwrap(),
            None
        );
        env.close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_storage_key_limit_is_the_largest_key_lmdb_stores() {
        let dir = temp_dir("maxkey");
        let env = LmdbEnv::open(&dir, options()).unwrap();
        let largest = vec![b'k'; MAX_STORAGE_KEY_BYTES];
        env.write(|txn| txn.put(&largest, b"1")).unwrap();
        let refused = env
            .write(|txn| txn.put(&[largest.as_slice(), b"k"].concat(), b"1"))
            .unwrap_err();
        assert!(refused.to_string().contains("MDB_BAD_VALSIZE"), "{refused}");
        assert_eq!(
            storage_key_error("k".repeat(MAX_STORAGE_KEY_BYTES).as_str()),
            None
        );
        assert_eq!(
            storage_key_error(&"\u{e9}".repeat(256)).as_deref(),
            Some("Storage key is too long (512 bytes). Max is 511.")
        );
        env.close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn one_directory_opens_once_per_process_until_closed() {
        let dir = temp_dir("twice");
        let env = LmdbEnv::open(&dir, options()).unwrap();
        let again = LmdbEnv::open(&dir, options()).err().unwrap();
        assert!(again.to_string().contains("already open in this process"));
        env.close();
        LmdbEnv::open(&dir, options()).unwrap().close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_full_map_reports_map_full_and_grows() {
        let dir = temp_dir("full");
        let env = LmdbEnv::open(
            &dir,
            OpenOptions {
                map_size: 64 << 10,
                ..options()
            },
        )
        .unwrap();
        let big = vec![7u8; 128 << 10];
        assert_eq!(
            env.write(|txn| txn.put(b"k", &big)),
            Err(LmdbError::MapFull)
        );
        env.set_map_size(1 << 20).unwrap();
        assert!(env.map_size().unwrap() >= 1 << 20);
        env.write(|txn| txn.put(b"k", &big)).unwrap();
        env.close();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_cursor_keeps_its_snapshot_and_fails_after_close() {
        let dir = temp_dir("cursor");
        let env = LmdbEnv::open(&dir, options()).unwrap();
        env.write(|txn| {
            txn.put(b"a", b"1")?;
            txn.put(b"b", b"2")
        })
        .unwrap();
        let mut cursor = env.cursor_from(b"").unwrap();
        env.write(|txn| txn.delete(b"b")).unwrap();
        assert_eq!(
            cursor.next_entry().unwrap(),
            Some((b"a".to_vec(), b"1".to_vec()))
        );
        assert_eq!(
            cursor.next_entry().unwrap(),
            Some((b"b".to_vec(), b"2".to_vec()))
        );
        assert_eq!(cursor.next_entry().unwrap(), None);
        let mut open = env.cursor_from(b"a").unwrap();
        env.close();
        assert_eq!(open.next_entry(), Err(LmdbError::Closed));
        assert_eq!(env.map_size(), Err(LmdbError::Closed));
        drop(cursor);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
