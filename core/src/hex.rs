//! Hex in and out, and EIP-55 addresses.

use alloc::string::String;
use alloc::vec::Vec;

use crate::keccak::keccak256;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex, without 0x.
pub fn encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 * b.len());
    for &x in b {
        s.push(DIGITS[(x >> 4) as usize] as char);
        s.push(DIGITS[(x & 15) as usize] as char);
    }
    s
}

/// "0x" and lowercase hex.
pub fn encode0x(b: &[u8]) -> String {
    let mut s = String::from("0x");
    s.push_str(&encode(b));
    s
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Bytes from hex, with or without 0x; None if it isn't hex of whole bytes.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    b.chunks_exact(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// A fixed number of bytes from hex.
pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    decode(s)?.try_into().ok()
}

/// 32 bytes from 64 hex digits at compile time (constants and tests).
pub const fn h32(s: &str) -> [u8; 32] {
    hex_const::<32>(s)
}

/// 20 bytes from 40 hex digits (an address, without 0x) at compile time.
pub const fn h20(s: &str) -> [u8; 20] {
    hex_const::<20>(s)
}

const fn hex_const<const N: usize>(s: &str) -> [u8; N] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not hex"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 2 * N);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// The EIP-55 checksummed spelling of an address ("0x" and 40 digits), as abi.checksum.
pub fn checksum(addr: &[u8; 20]) -> String {
    let lower = encode(addr);
    let h = keccak256(lower.as_bytes());
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for (i, c) in lower.bytes().enumerate() {
        let nib = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 15;
        s.push(if c.is_ascii_alphabetic() && nib >= 8 { c.to_ascii_uppercase() } else { c } as char);
    }
    s
}

/// An address from text, as abi.address: 40 hex digits with or without 0x; a mixed-case spelling
/// must carry the right EIP-55 checksum.
pub fn parse_address(s: &str) -> Result<[u8; 20], crate::Error> {
    let a: [u8; 20] = decode_array(s).ok_or(crate::Error::Invalid("not an address"))?;
    let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let mixed = body.bytes().any(|c| c.is_ascii_lowercase()) && body.bytes().any(|c| c.is_ascii_uppercase());
    if mixed && checksum(&a)[2..] != *body {
        return Err(crate::Error::Invalid("bad address checksum"));
    }
    Ok(a)
}
