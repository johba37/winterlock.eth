//! What the board keeps in its flash partition, as records in an append-only log ([`log`]):
//!
//! ```text
//!   FORMAT   "WLBS", format 1, partition size        always the first record, at offset 0
//!   SEED     the seed, how it came (setup, recovery)  in the first 4 KB sector, erased first
//!   MEMBER   the member key, its 1,024 kept leaves     so the 11.7 s derivation happens once
//!   PIN      a 32-byte salt, the PIN's check value
//!   READY    the owner address                         setup is complete
//!   PIN_TRY  a PIN was entered (written before it is checked)
//!   PIN_OK   the PIN was right: the tries start again
//!   TREE     a key tree: chain, Safe, start, height, salt, root, and its 1,024 leaves
//!   CERT     the member key is about to sign a tree's certificate (a stateless signature)
//!   USE      a one-time key signs a hash (the key log)
//!   WIPE     the board is being erased
//! ```
//!
//! At start the log is read once. Records before READY must be exactly FORMAT, SEED, MEMBER,
//! PIN, READY, one after the other; anything else there means a setup that didn't finish, and the
//! board erases itself. After READY, a torn record (a power cut while it was written) is skipped:
//! only the last write before a cut can be torn, and nothing that depends on a record is done
//! until the record has been written and read back.
//!
//! The tree's leaves are kept (24 KB per tree) so a signature needs only the 1,023 node hashes
//! above them (about 0.1 s on the board), not the 42 s it takes to make the leaves again. The
//! nodes are public; keeping them on the board also means the app holds nothing the board needs.

pub mod log;

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use embedded_storage::nor_flash::NorFlash;
use winterlock_core::keylog::{KeyLogStore, KeyUse};
use winterlock_core::{leansphincs, owner, wots};

use self::log::{Found, Log, LogError, record_size};

pub mod rec {
    pub const FORMAT: u8 = 0x01;
    pub const SEED: u8 = 0x02;
    pub const MEMBER: u8 = 0x03;
    pub const PIN: u8 = 0x04;
    pub const READY: u8 = 0x05;
    pub const PIN_TRY: u8 = 0x10;
    pub const PIN_OK: u8 = 0x11;
    pub const TREE: u8 = 0x20;
    pub const CERT: u8 = 0x21;
    pub const USE: u8 = 0x22;
    pub const WIPE: u8 = 0x30;
}

pub const FORMAT_MAGIC: [u8; 4] = *b"WLBS";
pub const FORMAT_VERSION: u16 = 1;
/// The tallest tree the store keeps (the board makes height 10).
pub const MAX_HEIGHT: u8 = 10;
const TREE_FIXED: usize = 8 + 20 + 8 + 1 + 32 + 24;
const USE_LEN: usize = 8 + 20 + 24 + 8 + 8 + 1 + 8 + 32;
const CERT_LEN: usize = 8 + 20 + 24 + 32;
const MEMBER_LEAVES: usize = 16 << keys_b();
const fn keys_b() -> u32 {
    crate::keys::MEMBER_B
}

/// How the seed came to the board.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum How {
    Setup = 0,
    Recovered = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Flash,
    /// No room left (the WIPE record's room is always kept).
    Full,
    /// A record didn't read back as written.
    NotDurable,
    /// The storage holds something the board can't read.
    Damaged,
    /// Not in a state that allows it (no seed, already set up).
    State,
}

impl From<LogError> for StoreError {
    fn from(e: LogError) -> Self {
        match e {
            LogError::Flash => StoreError::Flash,
            LogError::Full => StoreError::Full,
            LogError::ReadBack => StoreError::NotDurable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// No seed: set up or recover.
    Blank,
    /// Set up: the PIN unlocks it.
    Ready,
    /// The log can't be read as the board wrote it: it signs nothing until erased.
    Damaged(&'static str),
}

/// What happened when the store was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    /// The partition was empty and is now formatted.
    Formatted,
    /// It held a board's records as they should be.
    Read,
    /// It was erased: a setup that didn't finish, an erase that was cut short, or three wrong
    /// PINs that were counted before the erase.
    Wiped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub member_key: [u8; 32],
    pub owner: [u8; 20],
    pub how: How,
}

/// A key tree the board made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    pub chain: u64,
    pub safe: [u8; 20],
    pub start: u64,
    pub height: u8,
    pub salt: [u8; 32],
    pub root: wots::Value,
    /// The TREE record's payload offset.
    offset: u32,
    /// A CERT record exists: the member key signed (or was about to sign) its certificate.
    pub certified: bool,
    /// One bit per one-time key: used.
    used: Vec<u32>,
    /// The USE records' payload offsets.
    uses: Vec<u32>,
}

impl TreeEntry {
    pub fn keys(&self) -> u32 {
        1 << self.height
    }

    pub fn used_keys(&self) -> u32 {
        self.uses.len() as u32
    }

    fn is_used(&self, k: u64) -> bool {
        k < self.keys() as u64 && self.used[(k / 32) as usize] & (1 << (k % 32)) != 0
    }

    fn mark(&mut self, k: u64) {
        self.used[(k / 32) as usize] |= 1 << (k % 32);
    }

    /// The tree as the core's key log knows it.
    pub fn tree_ref(&self) -> winterlock_core::keylog::TreeRef {
        winterlock_core::keylog::TreeRef { chain: self.chain, safe: self.safe, root: self.root, start: self.start, height: self.height as u32 }
    }
}

struct Reading {
    next: u8,
    next_at: u32,
    seed_at: Option<u32>,
    how: How,
    member: Option<(u32, [u8; 32])>,
    pin: Option<([u8; 32], [u8; 32])>,
    owner: Option<[u8; 20]>,
    ready: bool,
    broken: bool,
    wipe: bool,
    damaged: Option<&'static str>,
    tries: u8,
    trees: Vec<TreeEntry>,
    stateless: u32,
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

impl Reading {
    fn visit(&mut self, f: Found, h: &[u8]) {
        let len = f.len as usize;
        if !self.ready {
            if f.ty == rec::WIPE {
                self.wipe = true;
            }
            let ok_len = match f.ty {
                rec::FORMAT => len == 10 && h[..4] == FORMAT_MAGIC && u16::from_be_bytes([h[4], h[5]]) == FORMAT_VERSION,
                rec::SEED => len == 33 && h[32] <= 1,
                rec::MEMBER => len == 32 + MEMBER_LEAVES,
                rec::PIN => len == 64,
                rec::READY => len == 20,
                _ => false,
            };
            if f.ty != self.next || f.offset != self.next_at || !ok_len {
                self.broken = true;
                return;
            }
            self.next_at = f.offset + record_size(f.len);
            match f.ty {
                rec::FORMAT => self.next = rec::SEED,
                rec::SEED => {
                    self.seed_at = Some(f.payload());
                    self.how = if h[32] == 1 { How::Recovered } else { How::Setup };
                    self.next = rec::MEMBER;
                }
                rec::MEMBER => {
                    self.member = Some((f.payload(), h[..32].try_into().unwrap()));
                    self.next = rec::PIN;
                }
                rec::PIN => {
                    self.pin = Some((h[..32].try_into().unwrap(), h[32..64].try_into().unwrap()));
                    self.next = rec::READY;
                }
                _ => {
                    self.owner = Some(h[..20].try_into().unwrap());
                    self.ready = true;
                    self.next = 0;
                }
            }
            return;
        }
        let bad = |s: &mut Self, why: &'static str| {
            s.damaged.get_or_insert(why);
        };
        match f.ty {
            rec::PIN_TRY if len == 0 => self.tries = self.tries.saturating_add(1),
            rec::PIN_OK if len == 0 => self.tries = 0,
            rec::WIPE if len == 0 => self.wipe = true,
            rec::TREE if len >= TREE_FIXED => {
                let height = h[36];
                if height == 0 || height > MAX_HEIGHT || len != TREE_FIXED + wots::N * (1usize << height) {
                    return bad(self, "a key tree record of the wrong size");
                }
                let root: wots::Value = h[69..93].try_into().unwrap();
                if self.trees.iter().any(|t| t.root == root) {
                    return bad(self, "a key tree recorded twice");
                }
                let keys = 1usize << height;
                self.trees.push(TreeEntry {
                    chain: be64(&h[0..]),
                    safe: h[8..28].try_into().unwrap(),
                    start: be64(&h[28..]),
                    height,
                    salt: h[37..69].try_into().unwrap(),
                    root,
                    offset: f.payload(),
                    certified: false,
                    used: vec![0; keys.div_ceil(32)],
                    uses: Vec::new(),
                });
            }
            rec::CERT if len == CERT_LEN => {
                self.stateless += 1;
                let root: wots::Value = h[28..52].try_into().unwrap();
                match self.trees.iter_mut().find(|t| t.root == root) {
                    Some(t) => t.certified = true,
                    None => bad(self, "a certificate record for a tree the board doesn't have"),
                }
            }
            rec::USE if len == USE_LEN => {
                let (chain, safe, root) = (be64(h), <[u8; 20]>::try_from(&h[8..28]).unwrap(), <wots::Value>::try_from(&h[28..52]).unwrap());
                let (start, nonce, slot, k) = (be64(&h[52..]), be64(&h[60..]), h[68], be64(&h[69..]));
                let Some(t) = self.trees.iter_mut().find(|t| t.chain == chain && t.safe == safe && t.root == root) else {
                    return bad(self, "a key use for a tree the board doesn't have");
                };
                if start != t.start || owner::key_index(nonce, start, slot, t.height as u32) != Ok(k) {
                    return bad(self, "a key use that doesn't match its tree");
                }
                if t.is_used(k) {
                    return bad(self, "a one-time key recorded twice");
                }
                t.mark(k);
                t.uses.push(f.payload());
            }
            _ => bad(self, "a record the board doesn't know"),
        }
    }
}

/// The board's storage: the log, and what it says, read once at start.
pub struct Store<F> {
    log: RefCell<Log<F>>,
    phase: Phase,
    seed_at: Option<u32>,
    identity: Option<Identity>,
    member_at: Option<u32>,
    pin: Option<([u8; 32], [u8; 32])>,
    tries: u8,
    trees: Vec<TreeEntry>,
    stateless: u32,
}

impl<F: NorFlash> Store<F> {
    /// Reads the partition and acts on what it finds: formats an empty one, finishes an erase
    /// that was cut short, erases a setup that didn't finish or three wrong PINs.
    pub fn open(flash: F) -> Result<(Store<F>, Opened), StoreError> {
        let mut log = Log::new(flash);
        let mut r = Reading {
            next: rec::FORMAT,
            next_at: 0,
            seed_at: None,
            how: How::Setup,
            member: None,
            pin: None,
            owner: None,
            ready: false,
            broken: false,
            wipe: false,
            damaged: None,
            tries: 0,
            trees: Vec::new(),
            stateless: 0,
        };
        let scanned = log.scan(|f, h| r.visit(f, h))?;
        let mut store = Store {
            log: RefCell::new(log),
            phase: Phase::Blank,
            seed_at: None,
            identity: None,
            member_at: None,
            pin: None,
            tries: 0,
            trees: Vec::new(),
            stateless: 0,
        };
        let empty = scanned.records == 0 && scanned.skipped == 0 && store.log.borrow().end() == 0;
        if empty {
            store.format()?;
            return Ok((store, Opened::Formatted));
        }
        let blank = r.next == rec::SEED && !r.broken && scanned.records == 1 && scanned.skipped == 0;
        if blank {
            return Ok((store, Opened::Read));
        }
        if r.wipe || !r.ready || r.tries >= crate::board::PIN_TRIES {
            store.wipe_now()?;
            return Ok((store, Opened::Wiped));
        }
        let (Some(seed_at), Some((member_at, member_key)), Some(owner)) = (r.seed_at, r.member, r.owner) else {
            unreachable!("ready means the prefix is complete")
        };
        store.seed_at = Some(seed_at);
        store.member_at = Some(member_at);
        store.identity = Some(Identity { member_key, owner, how: r.how });
        store.pin = r.pin;
        store.tries = r.tries;
        store.trees = r.trees;
        store.stateless = r.stateless;
        store.phase = match r.damaged {
            Some(why) => Phase::Damaged(why),
            None => Phase::Ready,
        };
        Ok((store, Opened::Read))
    }

    fn format(&mut self) -> Result<(), StoreError> {
        let size = self.log.borrow().size();
        let mut p = [0u8; 10];
        p[..4].copy_from_slice(&FORMAT_MAGIC);
        p[4..6].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        p[6..].copy_from_slice(&size.to_be_bytes());
        self.log.get_mut().append(rec::FORMAT, &[&p])?;
        Ok(())
    }

    fn reset(&mut self) {
        self.phase = Phase::Blank;
        self.seed_at = None;
        self.identity = None;
        self.member_at = None;
        self.pin = None;
        self.tries = 0;
        self.trees.clear();
        self.stateless = 0;
    }

    fn wipe_now(&mut self) -> Result<(), StoreError> {
        self.reset();
        self.log.get_mut().wipe()?;
        self.format()
    }

    /// Erases the seed and the key log: a WIPE record first (so an erase cut short is finished at
    /// the next start), then the partition, starting with the sector that holds the seed.
    pub fn wipe(&mut self) -> Result<(), StoreError> {
        // the room for this record is always kept; a failure here still erases
        let _ = self.log.get_mut().append(rec::WIPE, &[]);
        self.wipe_now()
    }

    fn append(&mut self, ty: u8, parts: &[&[u8]]) -> Result<u32, StoreError> {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        let log = self.log.get_mut();
        if log.end() + record_size(len as u32) + record_size(0) > log.size() {
            return Err(StoreError::Full);
        }
        Ok(log.append(ty, parts)?)
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Wrong PINs in a row so far.
    pub fn tries(&self) -> u8 {
        self.tries
    }

    pub fn trees(&self) -> &[TreeEntry] {
        &self.trees
    }

    /// Stateless signatures recorded (tree certificates).
    pub fn stateless_signatures(&self) -> u32 {
        self.stateless
    }

    /// Looks at the flash itself (a test, or a tool that copies a simulated one).
    pub fn with_flash<R>(&self, f: impl FnOnce(&F) -> R) -> R {
        f(&self.log.borrow().flash)
    }

    /// (bytes in use, partition size)
    pub fn usage(&self) -> (u32, u32) {
        let l = self.log.borrow();
        (l.end(), l.size())
    }

    /// Writes a new board's records: the seed, the member key and its leaves, the PIN, then READY.
    /// Only on a blank board. If any write fails, the board erases what it wrote.
    #[allow(clippy::too_many_arguments)]
    pub fn setup(&mut self, seed: &[u8; 32], how: How, member_key: &[u8; 32], leaves: &[leansphincs::Node], pin_salt: &[u8; 32], pin_check: &[u8; 32], owner: &[u8; 20]) -> Result<(), StoreError> {
        if self.phase != Phase::Blank || leaves.len() * 16 != MEMBER_LEAVES {
            return Err(StoreError::State);
        }
        let leaves_bytes: &[u8] = leaves.as_flattened();
        let r = (|| -> Result<(u32, u32), StoreError> {
            let s = self.append(rec::SEED, &[seed, &[how as u8]])?;
            let m = self.append(rec::MEMBER, &[member_key, leaves_bytes])?;
            self.append(rec::PIN, &[pin_salt, pin_check])?;
            self.append(rec::READY, &[owner])?;
            Ok((s, m))
        })();
        match r {
            Ok((s, m)) => {
                self.seed_at = Some(s + log::HEADER);
                self.member_at = Some(m + log::HEADER);
                self.identity = Some(Identity { member_key: *member_key, owner: *owner, how });
                self.pin = Some((*pin_salt, *pin_check));
                self.tries = 0;
                self.phase = Phase::Ready;
                Ok(())
            }
            Err(e) => {
                let _ = self.wipe_now();
                Err(e)
            }
        }
    }

    /// The PIN's salt and check value.
    pub fn pin(&self) -> Option<&([u8; 32], [u8; 32])> {
        self.pin.as_ref()
    }

    /// Counts a PIN try, durably, before the PIN is checked. Returns the tries in a row.
    pub fn pin_try(&mut self) -> Result<u8, StoreError> {
        self.ready()?;
        self.append(rec::PIN_TRY, &[])?;
        self.tries = self.tries.saturating_add(1);
        Ok(self.tries)
    }

    /// The PIN was right: the count starts again.
    pub fn pin_ok(&mut self) -> Result<(), StoreError> {
        self.ready()?;
        if self.tries > 0 {
            self.append(rec::PIN_OK, &[])?;
            self.tries = 0;
        }
        Ok(())
    }

    fn ready(&self) -> Result<(), StoreError> {
        match self.phase {
            Phase::Ready => Ok(()),
            Phase::Damaged(_) => Err(StoreError::Damaged),
            Phase::Blank => Err(StoreError::State),
        }
    }

    pub fn seed(&self) -> Result<[u8; 32], StoreError> {
        let at = self.seed_at.ok_or(StoreError::State)?;
        let mut s = [0u8; 32];
        self.log.borrow_mut().read(at, &mut s)?;
        Ok(s)
    }

    /// The member key's kept leaves.
    pub fn member_leaves(&self) -> Result<Vec<leansphincs::Node>, StoreError> {
        let at = self.member_at.ok_or(StoreError::State)?;
        let mut v = vec![[0u8; 16]; MEMBER_LEAVES / 16];
        self.log.borrow_mut().read(at + 32, v.as_flattened_mut())?;
        Ok(v)
    }

    /// Records a new key tree (its salt, root and leaves). Returns its index.
    pub fn add_tree(&mut self, chain: u64, safe: &[u8; 20], start: u64, height: u8, salt: &[u8; 32], tree: &wots::Tree) -> Result<usize, StoreError> {
        self.ready()?;
        if height == 0 || height > MAX_HEIGHT || tree.height != height as u32 || tree.k != height as u32 || self.trees.iter().any(|t| t.root == tree.root) {
            return Err(StoreError::State);
        }
        let mut fixed = [0u8; TREE_FIXED];
        fixed[..8].copy_from_slice(&chain.to_be_bytes());
        fixed[8..28].copy_from_slice(safe);
        fixed[28..36].copy_from_slice(&start.to_be_bytes());
        fixed[36] = height;
        fixed[37..69].copy_from_slice(salt);
        fixed[69..93].copy_from_slice(&tree.root);
        let at = self.append(rec::TREE, &[&fixed, tree.leaves().as_flattened()])?;
        let keys = 1usize << height;
        self.trees.push(TreeEntry {
            chain,
            safe: *safe,
            start,
            height,
            salt: *salt,
            root: tree.root,
            offset: at + log::HEADER,
            certified: false,
            used: vec![0; keys.div_ceil(32)],
            uses: Vec::new(),
        });
        Ok(self.trees.len() - 1)
    }

    /// A tree's leaves, from flash.
    pub fn tree_leaves(&self, i: usize) -> Result<Vec<wots::Value>, StoreError> {
        let t = self.trees.get(i).ok_or(StoreError::State)?;
        let mut v = vec![[0u8; wots::N]; 1 << t.height];
        self.log.borrow_mut().read(t.offset + TREE_FIXED as u32, v.as_flattened_mut())?;
        Ok(v)
    }

    /// Records that the member key is about to sign tree `i`'s certificate (digest `digest`).
    pub fn record_certificate(&mut self, i: usize, digest: &[u8; 32]) -> Result<(), StoreError> {
        self.ready()?;
        let t = self.trees.get(i).ok_or(StoreError::State)?;
        let mut p = [0u8; CERT_LEN];
        p[..8].copy_from_slice(&t.chain.to_be_bytes());
        p[8..28].copy_from_slice(&t.safe);
        p[28..52].copy_from_slice(&t.root);
        p[52..].copy_from_slice(digest);
        self.append(rec::CERT, &[&p])?;
        self.trees[i].certified = true;
        self.stateless += 1;
        Ok(())
    }

    fn tree_index(&self, chain: u64, safe: &[u8; 20], root: &wots::Value) -> Option<usize> {
        self.trees.iter().position(|t| t.chain == chain && t.safe == *safe && t.root == *root)
    }
}

impl<F: NorFlash> KeyLogStore for Store<F> {
    type Error = StoreError;

    fn find_use(&self, chain: u64, safe: &[u8; 20], root: &wots::Value, key_index: u64) -> Result<Option<[u8; 32]>, StoreError> {
        let Some(i) = self.tree_index(chain, safe, root) else {
            return Ok(None);
        };
        let t = &self.trees[i];
        if !t.is_used(key_index) {
            return Ok(None);
        }
        let mut log = self.log.borrow_mut();
        for &at in &t.uses {
            // key index and hash: the payload's last 40 bytes
            let mut b = [0u8; 40];
            log.read(at + (USE_LEN - 40) as u32, &mut b)?;
            if be64(&b) == key_index {
                return Ok(Some(b[8..].try_into().unwrap()));
            }
        }
        Err(StoreError::Damaged)
    }

    fn append_use(&mut self, u: &KeyUse) -> Result<(), StoreError> {
        self.ready()?;
        let i = self.tree_index(u.chain, &u.safe, &u.root).ok_or(StoreError::State)?;
        if self.trees[i].is_used(u.key_index) || u.start != self.trees[i].start {
            return Err(StoreError::State);
        }
        let mut p = [0u8; USE_LEN];
        p[..8].copy_from_slice(&u.chain.to_be_bytes());
        p[8..28].copy_from_slice(&u.safe);
        p[28..52].copy_from_slice(&u.root);
        p[52..60].copy_from_slice(&u.start.to_be_bytes());
        p[60..68].copy_from_slice(&u.nonce.to_be_bytes());
        p[68] = u.slot;
        p[69..77].copy_from_slice(&u.key_index.to_be_bytes());
        p[77..].copy_from_slice(&u.hash);
        let at = self.append(rec::USE, &[&p])?;
        let t = &mut self.trees[i];
        t.mark(u.key_index);
        t.uses.push(at + log::HEADER);
        Ok(())
    }
}
