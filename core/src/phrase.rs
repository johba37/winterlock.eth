//! The recovery phrase (phrase.py): 24 BIP-39 English words that encode the 32-byte seed itself.
//! The seed is the phrase's BIP-39 entropy, not BIP-39's PBKDF2 seed, and there is no passphrase.
//! The checksum is the first byte of SHA-256(seed).
//!
//! Parsing is forgiving as in Python: any case and spacing, commas and semicolons, numbering
//! ("1." "2)" "3:") and abbreviations of four letters or more. A problem is named: which word,
//! or the checksum. The pairing check code (member.py's `check_code`) is here too, since it
//! speaks the same words.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

use crate::keccak::keccak256_parts;
use crate::wordlist::{DIGITS, SPACES, WORDS as LIST};

/// Words in a phrase.
pub const WORDS: usize = 24;
/// Words asked in a backup check.
pub const CHECK_WORDS: usize = 3;
/// Words in a pairing check code.
pub const CHECK_CODE_WORDS: usize = 5;

/// What's wrong with a phrase as typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhraseError {
    /// Not 24 words (after numbering is dropped).
    WordCount(usize),
    /// Word `position` (1-based), as typed, isn't a word of the list or a unique abbreviation.
    UnknownWord { position: usize, token: String },
    /// Every word is on the list but the checksum doesn't match.
    Checksum,
}

impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhraseError::WordCount(n) => write!(f, "a recovery phrase has {WORDS} words; this has {n}"),
            PhraseError::UnknownWord { position, token } => {
                write!(f, "word {position} ('{token}') isn't a word of the BIP-39 English list")
            }
            PhraseError::Checksum => f.write_str(
                "the words don't match their checksum: one of them is wrong, or two are swapped",
            ),
        }
    }
}

/// The BIP-39 English list.
pub fn wordlist() -> &'static [&'static str; 2048] {
    &LIST
}

/// The index of a word of the list.
pub fn index_of(word: &str) -> Option<u16> {
    LIST.binary_search(&word).ok().map(|i| i as u16)
}

fn is_space(c: char) -> bool {
    SPACES.contains(&c)
}

fn is_digit(c: char) -> bool {
    c.is_ascii_digit() || (c as u32 > 0x7f && DIGITS.iter().any(|&(a, b)| a <= c && c <= b))
}

/// Python's `str.strip()`.
fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// The phrase of a seed.
pub fn to_phrase(seed: &[u8; 32]) -> [&'static str; WORDS] {
    let check = Sha256::digest(seed)[0];
    let mut bits = [0u8; 33];
    bits[..32].copy_from_slice(seed);
    bits[32] = check;
    core::array::from_fn(|i| LIST[bits11(&bits, i)])
}

fn bits11(b: &[u8], i: usize) -> usize {
    let mut v = 0usize;
    for k in 0..11 {
        let bit = 11 * i + k;
        v = (v << 1) | ((b[bit / 8] >> (7 - bit % 8)) & 1) as usize;
    }
    v
}

/// A word of the list from what a member typed: the word itself, or an abbreviation of four
/// letters or more that only one word starts with. Case doesn't matter.
pub fn word(token: &str) -> Option<&'static str> {
    let t = strip(token).to_lowercase();
    if let Some(i) = index_of(&t) {
        return Some(LIST[i as usize]);
    }
    if t.chars().count() >= 4 {
        let mut hits = LIST.iter().filter(|w| w.starts_with(t.as_str()));
        if let (Some(w), None) = (hits.next(), hits.next()) {
            return Some(w);
        }
    }
    None
}

/// Numbering such as "1", "2.", "3)" or "4:" (Python: `\d+[.):]?`).
fn is_numbering(t: &str) -> bool {
    let t = t.strip_suffix(['.', ')', ':']).unwrap_or(t);
    !t.is_empty() && t.chars().all(is_digit)
}

/// The tokens a member typed, numbering left out (Python: `re.split(r"[\s,;]+", text.strip())`).
fn tokens(text: &str) -> Vec<&str> {
    strip(text)
        .split(|c: char| is_space(c) || c == ',' || c == ';')
        .filter(|t| !t.is_empty() && !is_numbering(t))
        .collect()
}

/// The 24 words of a phrase as typed. Fails on the first problem.
pub fn parse(text: &str) -> Result<[&'static str; WORDS], PhraseError> {
    let toks = tokens(text);
    if toks.len() != WORDS {
        return Err(PhraseError::WordCount(toks.len()));
    }
    let mut out = [""; WORDS];
    for (n, t) in toks.iter().enumerate() {
        out[n] = word(t).ok_or_else(|| PhraseError::UnknownWord {
            position: n + 1,
            token: String::from(*t),
        })?;
    }
    Ok(out)
}

/// The seed that 24 words of the list encode, if their checksum matches.
pub fn from_words(words: &[&str; WORDS]) -> Result<[u8; 32], PhraseError> {
    let mut bits = [0u8; 33];
    for (i, w) in words.iter().enumerate() {
        let ix = index_of(w).ok_or_else(|| PhraseError::UnknownWord {
            position: i + 1,
            token: String::from(*w),
        })?;
        for k in 0..11 {
            if (ix >> (10 - k)) & 1 == 1 {
                let bit = 11 * i + k;
                bits[bit / 8] |= 0x80 >> (bit % 8);
            }
        }
    }
    let seed: [u8; 32] = bits[..32].try_into().unwrap();
    if Sha256::digest(seed)[0] != bits[32] {
        return Err(PhraseError::Checksum);
    }
    Ok(seed)
}

/// The seed a phrase encodes, as typed. Also takes a legacy seed backup: 64 hex digits, with or
/// without 0x.
pub fn to_seed(text: &str) -> Result<[u8; 32], PhraseError> {
    let raw = strip(text);
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() == 64 && hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Ok(crate::hex::decode_array(hex).unwrap());
    }
    from_words(&parse(raw)?)
}

/// Whether `answer` is word `position` (1-based) of `words`, as typed. As in Python, position 0
/// is the last word (phrase.py indexes `words[position - 1]`); past the end is false (Python
/// raises IndexError).
pub fn matches(words: &[&str], position: usize, answer: &str) -> bool {
    let Some(&w) = (if position == 0 { words.last() } else { words.get(position - 1) }) else {
        return false;
    };
    word(answer) == Some(w)
}

/// The pairing check code: five words from keccak256("winterlock.device-pairing.v1" ‖ owner ‖
/// device ‖ key), 11 bits each from the top. The same words mean the same owner, device number
/// and key.
pub fn check_code(owner: &[u8; 20], device: u8, key: &[u8; 32]) -> [&'static str; CHECK_CODE_WORDS] {
    let h = keccak256_parts(&[b"winterlock.device-pairing.v1", owner, &[device], key]);
    core::array::from_fn(|i| LIST[bits11(&h, i)])
}

/// The check code as one line, words separated by spaces.
pub fn check_code_text(owner: &[u8; 20], device: u8, key: &[u8; 32]) -> String {
    check_code(owner, device, key).join(" ")
}
