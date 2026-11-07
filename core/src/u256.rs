//! A 256-bit unsigned integer for the SafeTx fields that need one (value, gas fields, nonce):
//! big-endian bytes, decimal in and out, and amounts shown exactly.

use alloc::string::String;
use core::fmt;

/// A uint256 as its 32-byte big-endian word.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub const ZERO: U256 = U256([0; 32]);

    pub const fn from_u64(v: u64) -> U256 {
        U256::from_u128(v as u128)
    }

    pub const fn from_u128(v: u128) -> U256 {
        let b = v.to_be_bytes();
        let mut w = [0u8; 32];
        let mut i = 0;
        while i < 16 {
            w[16 + i] = b[i];
            i += 1;
        }
        U256(w)
    }

    pub const fn from_be_bytes(b: [u8; 32]) -> U256 {
        U256(b)
    }

    pub const fn to_be_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// The value if it fits in a u64.
    pub fn to_u64(&self) -> Option<u64> {
        if self.0[..24].iter().any(|&b| b != 0) {
            return None;
        }
        Some(u64::from_be_bytes(self.0[24..].try_into().unwrap()))
    }

    fn limbs(&self) -> [u64; 4] {
        // little-endian limbs
        core::array::from_fn(|i| u64::from_be_bytes(self.0[24 - 8 * i..32 - 8 * i].try_into().unwrap()))
    }

    fn from_limbs(l: [u64; 4]) -> U256 {
        let mut w = [0u8; 32];
        for (i, limb) in l.iter().enumerate() {
            w[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        U256(w)
    }

    /// From decimal digits (no sign, no separators); None if empty, not decimal or above 2^256 - 1.
    pub fn from_dec_str(s: &str) -> Option<U256> {
        if s.is_empty() {
            return None;
        }
        let mut l = [0u64; 4];
        for c in s.bytes() {
            if !c.is_ascii_digit() {
                return None;
            }
            let mut carry = (c - b'0') as u128;
            for limb in l.iter_mut() {
                let v = (*limb as u128) * 10 + carry;
                *limb = v as u64;
                carry = v >> 64;
            }
            if carry != 0 {
                return None;
            }
        }
        Some(U256::from_limbs(l))
    }

    /// (self / d, self % d)
    fn divmod_small(&self, d: u64) -> (U256, u64) {
        let mut l = self.limbs();
        let mut rem: u128 = 0;
        for limb in l.iter_mut().rev() {
            let cur = (rem << 64) | *limb as u128;
            *limb = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        (U256::from_limbs(l), rem as u64)
    }

    /// Decimal digits.
    pub fn to_dec_string(&self) -> String {
        if self.is_zero() {
            return String::from("0");
        }
        let mut digits = [0u8; 78];
        let mut n = 0;
        let mut v = *self;
        while !v.is_zero() {
            let (q, r) = v.divmod_small(10);
            digits[n] = b'0' + r as u8;
            n += 1;
            v = q;
        }
        digits[..n].iter().rev().map(|&c| c as char).collect()
    }

    /// The amount in units of 10^decimals, exactly: whole part, then the fraction without trailing
    /// zeros (0.1 ETH is "0.1", never 0.100000000000000006).
    pub fn format_units(&self, decimals: usize) -> String {
        let digits = self.to_dec_string();
        let padded = if digits.len() <= decimals {
            let mut p = String::with_capacity(decimals + 1);
            for _ in 0..decimals + 1 - digits.len() {
                p.push('0');
            }
            p.push_str(&digits);
            p
        } else {
            digits
        };
        let (whole, frac) = padded.split_at(padded.len() - decimals);
        let frac = frac.trim_end_matches('0');
        let mut out = String::from(whole);
        if !frac.is_empty() {
            out.push('.');
            out.push_str(frac);
        }
        out
    }

    /// "<amount> ETH (<wei with thousands separators> wei)", as the Python signer's safe.fmt_eth.
    pub fn fmt_eth(&self) -> String {
        let mut out = self.format_units(18);
        out.push_str(" ETH (");
        let d = self.to_dec_string();
        for (i, c) in d.chars().enumerate() {
            if i > 0 && (d.len() - i) % 3 == 0 {
                out.push(',');
            }
            out.push(c);
        }
        out.push_str(" wei)");
        out
    }
}

impl From<u64> for U256 {
    fn from(v: u64) -> U256 {
        U256::from_u64(v)
    }
}

impl From<u128> for U256 {
    fn from(v: u128) -> U256 {
        U256::from_u128(v)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_dec_string())
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U256({})", self.to_dec_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;
    use alloc::string::ToString;

    #[test]
    fn decimal() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(U256::from_dec_str(max).unwrap().0, [0xff; 32]);
        assert_eq!(U256::from_dec_str(max).unwrap().to_dec_string(), max);
        assert!(U256::from_dec_str("115792089237316195423570985008687907853269984665640564039457584007913129639936").is_none());
        assert_eq!(U256::from_u64(1234567).to_string(), "1234567");
        assert_eq!(U256::from_u64(100_000_000_000_000_000).format_units(18), "0.1");
        assert_eq!(U256::from_u128(10u128.pow(19)).format_units(18), "10");
        assert_eq!(U256::ZERO.format_units(18), "0");
        assert_eq!(U256::from_u64(1).fmt_eth(), "0.000000000000000001 ETH (1 wei)");
        assert_eq!(U256::from_u64(1234).fmt_eth(), "0.000000000000001234 ETH (1,234 wei)");
    }
}
