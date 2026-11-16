//! What a Safe transaction does, decoded on the board from its fields (never taken from the
//! app): an ETH transfer, an ERC-20 `transfer` of a token on the built-in list, an `approveHash`
//! of a parent Safe's transaction whose fields came along, an `execTransaction` on a parent Safe
//! (the parent's transaction is in the call), a cancel (an empty call from the Safe to itself), or
//! anything else, shown as its target, value and selector and marked as not decoded. A delegate
//! call is refused.
//!
//! Names: this code calls the Safe whose transaction is approved or executed the parent Safe. The
//! screens and the refusals' texts call it the nested Safe, as Safe's own app does: there, a Safe
//! owned by another Safe is nested in it, and the owning Safe (here the member's) is the parent.

use alloc::boxed::Box;
use alloc::vec::Vec;

use winterlock_core::U256;
use winterlock_core::hex::h20;
use winterlock_core::safe::{Operation, SafeTx};

/// A token the board names: only addresses checked against the issuer's or the chain's own
/// documentation, and their decimals and symbol read on-chain (2026-11-10, Ethereum and Base on
/// 2026-11-11):
/// - USDC: Circle's "USDC contract addresses" page (developers.circle.com), mainnet and testnet
/// - WETH on Arbitrum One: Arbitrum's "Contract addresses" page (docs.arbitrum.io)
/// - WETH on Ethereum: ethereum.org's "Wrapped Ether" page
/// - WETH on Base: Base's "Base Contracts" page (docs.base.org), WETH9
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub chain: u64,
    pub address: [u8; 20],
    pub symbol: &'static str,
    pub decimals: u8,
}

pub const TOKENS: &[Token] = &[
    Token { chain: 42161, address: h20("af88d065e77c8cC2239327C5EDb3A432268e5831"), symbol: "USDC", decimals: 6 },
    Token { chain: 42161, address: h20("82aF49447D8a07e3bd95BD0d56f35241523fBab1"), symbol: "WETH", decimals: 18 },
    Token { chain: 11155111, address: h20("1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"), symbol: "USDC", decimals: 6 },
    Token { chain: 421614, address: h20("75faf114eafb1BDbe2F0316DF893fd58CE46AA4d"), symbol: "USDC", decimals: 6 },
    Token { chain: 1, address: h20("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), symbol: "USDC", decimals: 6 },
    Token { chain: 1, address: h20("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), symbol: "WETH", decimals: 18 },
    Token { chain: 8453, address: h20("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), symbol: "USDC", decimals: 6 },
    Token { chain: 8453, address: h20("4200000000000000000000000000000000000006"), symbol: "WETH", decimals: 18 },
];

pub fn token(chain: u64, address: &[u8; 20]) -> Option<&'static Token> {
    TOKENS.iter().find(|t| t.chain == chain && t.address == *address)
}

/// transfer(address,uint256)
pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// approveHash(bytes32)
pub const APPROVE_HASH: [u8; 4] = [0xd4, 0xd9, 0xbd, 0xcd];
/// execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)
pub const EXEC_TRANSACTION: [u8; 4] = [0x6a, 0x76, 0x12, 0x02];

/// What a call does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// An empty call from the Safe to itself: it only uses up its nonce.
    Cancel,
    Eth { to: [u8; 20], value: U256 },
    Token { token: &'static Token, to: [u8; 20], amount: U256 },
    /// approveHash on a parent Safe (the call's target) of the parent transaction whose fields
    /// came along and hash to the call's argument.
    Approve { parent_safe: [u8; 20], parent_hash: [u8; 32], parent: Box<Decoded> },
    /// execTransaction on a parent Safe (the call's target): what the parent's transaction does
    /// and its refund fields, read from the call itself, and the length of the signatures passed
    /// along. The parent's nonce isn't in the call: it is the parent Safe's own when this runs.
    Exec { parent_safe: [u8; 20], action: Box<Action>, refund: Option<Refund>, signatures: usize },
    /// Not decoded: the target, the value and the first four bytes of the data.
    Raw { to: [u8; 20], value: U256, selector: Option<[u8; 4]>, data_len: usize },
}

/// A decoded transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub action: Action,
    pub nonce: U256,
    /// safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, when any is set: with a gas price,
    /// the Safe pays whoever executes it.
    pub refund: Option<Refund>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refund {
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
}

impl Decoded {
    /// Whether the member must confirm a second time: something the board can't show in full.
    pub fn needs_second(&self) -> bool {
        self.refund.is_some()
            || match &self.action {
                Action::Raw { .. } => true,
                Action::Approve { parent, .. } => parent.needs_second(),
                Action::Exec { action, refund, .. } => refund.is_some() || matches!(**action, Action::Raw { .. }),
                _ => false,
            }
    }
}

/// Why the board refuses to sign a transaction at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    DelegateCall,
    ParentDelegateCall,
    /// The parent's fields don't hash to approveHash's argument.
    ParentMismatch,
    /// Parent fields came along with a call that isn't approveHash.
    ParentUnused,
}

impl Refusal {
    pub fn text(self) -> &'static str {
        match self {
            Refusal::DelegateCall => "delegate calls are refused",
            Refusal::ParentDelegateCall => "the nested Safe's transaction is a delegate call: refused",
            Refusal::ParentMismatch => "the nested Safe's fields don't hash to the approveHash argument",
            Refusal::ParentUnused => "a nested Safe's fields came with a call that isn't approveHash",
        }
    }
}

fn refund(t: &SafeTx) -> Option<Refund> {
    let set = !t.safe_tx_gas.is_zero() || !t.base_gas.is_zero() || !t.gas_price.is_zero() || t.gas_token != [0; 20] || t.refund_receiver != [0; 20];
    set.then_some(Refund {
        safe_tx_gas: t.safe_tx_gas,
        base_gas: t.base_gas,
        gas_price: t.gas_price,
        gas_token: t.gas_token,
        refund_receiver: t.refund_receiver,
    })
}

/// A call's action, without parent fields (approveHash shows as not decoded then).
fn action(chain: u64, safe: &[u8; 20], t: &SafeTx) -> Action {
    if t.to == *safe && t.value.is_zero() && t.data.is_empty() {
        return Action::Cancel;
    }
    if t.data.is_empty() {
        return Action::Eth { to: t.to, value: t.value };
    }
    if t.value.is_zero()
        && t.data.len() == 68
        && t.data[..4] == TRANSFER
        && t.data[4..16] == [0; 12]
        && let Some(tok) = token(chain, &t.to)
    {
        return Action::Token { token: tok, to: t.data[16..36].try_into().unwrap(), amount: U256::from_be_bytes(t.data[36..68].try_into().unwrap()) };
    }
    raw(t)
}

fn raw(t: &SafeTx) -> Action {
    Action::Raw { to: t.to, value: t.value, selector: (t.data.len() >= 4).then(|| t.data[..4].try_into().unwrap()), data_len: t.data.len() }
}

/// Decodes a Safe transaction of `safe` on `chain`, with its parent's fields if it is an
/// approveHash on a parent Safe.
pub fn decode(chain: u64, safe: &[u8; 20], t: &SafeTx, parent: Option<&SafeTx>) -> Result<Decoded, Refusal> {
    if t.operation == Operation::DelegateCall {
        return Err(Refusal::DelegateCall);
    }
    let is_approve = t.value.is_zero() && t.data.len() == 36 && t.data[..4] == APPROVE_HASH;
    if parent.is_none()
        && let Some(e) = exec_call(safe, t)
    {
        if e.operation == Operation::DelegateCall {
            return Err(Refusal::ParentDelegateCall);
        }
        // one level: the parent's own approveHash or execTransaction shows as not decoded
        let exec = Action::Exec { parent_safe: t.to, action: Box::new(action(chain, &t.to, &e)), refund: refund(&e), signatures: e.nonce.to_u64().unwrap_or(0) as usize };
        return Ok(Decoded { action: exec, nonce: t.nonce, refund: refund(t) });
    }
    let action = match (is_approve, parent) {
        (true, Some(p)) => {
            if p.operation == Operation::DelegateCall {
                return Err(Refusal::ParentDelegateCall);
            }
            let parent_hash: [u8; 32] = t.data[4..36].try_into().unwrap();
            // the parent Safe is the call's target, on the same chain
            if p.hash(chain, &t.to) != parent_hash {
                return Err(Refusal::ParentMismatch);
            }
            // one level: a parent's own approveHash shows as not decoded
            let pa = action(chain, &t.to, p);
            Action::Approve { parent_safe: t.to, parent_hash, parent: Box::new(Decoded { action: pa, nonce: p.nonce, refund: refund(p) }) }
        }
        (false, Some(_)) => return Err(Refusal::ParentUnused),
        (_, None) => action(chain, safe, t),
    };
    Ok(Decoded { action, nonce: t.nonce, refund: refund(t) })
}

/// The parent Safe's transaction in `t`, if `t` is a call of execTransaction on another Safe in
/// exactly the encoding Solidity's own encoder gives: ten head words, then the data and the
/// signatures, each with its length and zero padding, and nothing after. Any other encoding (a
/// contract may accept more: other offsets, bytes after the end) isn't read, so the call shows
/// as not decoded. The returned transaction's `nonce` holds the signatures' length: the parent's
/// nonce isn't in the call.
fn exec_call(safe: &[u8; 20], t: &SafeTx) -> Option<SafeTx> {
    if t.to == *safe || !t.value.is_zero() || t.data.len() < 4 || t.data[..4] != EXEC_TRANSACTION {
        return None;
    }
    let b = &t.data[4..];
    const HEAD: usize = 10 * 32;
    if b.len() < HEAD + 64 {
        return None;
    }
    let word = |at: usize| -> Option<[u8; 32]> { b.get(at..at.checked_add(32)?)?.try_into().ok() };
    let address = |at: usize| -> Option<[u8; 20]> {
        let w = word(at)?;
        (w[..12] == [0; 12]).then(|| w[12..].try_into().unwrap())
    };
    // a length or an offset: it must fit the call
    let small = |at: usize| -> Option<usize> {
        let w = word(at)?;
        if w[..24] != [0; 24] {
            return None;
        }
        let v = u64::from_be_bytes(w[24..].try_into().unwrap());
        (v <= b.len() as u64).then_some(v as usize)
    };
    // the bytes of a length-prefixed value at `at`, zero-padded to a word; and where it ends
    let bytes = |at: usize| -> Option<(&[u8], usize)> {
        let len = small(at)?;
        let start = at.checked_add(32)?;
        let end = start.checked_add(len.checked_add(31)? / 32 * 32)?;
        let padded = b.get(start..end)?;
        padded[len..].iter().all(|&x| x == 0).then_some((&padded[..len], end))
    };
    let operation = match small(3 * 32)? {
        0 => Operation::Call,
        1 => Operation::DelegateCall,
        _ => return None,
    };
    if small(2 * 32)? != HEAD {
        return None;
    }
    let (data, data_end) = bytes(HEAD)?;
    if small(9 * 32)? != data_end {
        return None;
    }
    let (signatures, end) = bytes(data_end)?;
    if end != b.len() {
        return None;
    }
    Some(SafeTx {
        to: address(0)?,
        value: U256(word(32)?),
        data: data.to_vec(),
        operation,
        safe_tx_gas: U256(word(4 * 32)?),
        base_gas: U256(word(5 * 32)?),
        gas_price: U256(word(6 * 32)?),
        gas_token: address(7 * 32)?,
        refund_receiver: address(8 * 32)?,
        nonce: U256::from_u64(signatures.len() as u64),
    })
}

/// Formats a token or ETH amount exactly: "1,234.5" (no trailing zeros).
pub fn amount(v: &U256, decimals: u8) -> alloc::string::String {
    let s = v.format_units(decimals as usize);
    // group the whole part in thousands
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (s.as_str(), None),
    };
    let mut g = alloc::string::String::new();
    for (i, c) in whole.chars().enumerate() {
        if i > 0 && (whole.len() - i) % 3 == 0 {
            g.push(',');
        }
        g.push(c);
    }
    if let Some(f) = frac {
        g.push('.');
        g.push_str(f);
    }
    g
}

/// The decoded actions for display: the transaction's, then for an approval, its parent's.
/// Why the member's own owner contract can't take what `d` sends it, if it sends it something:
/// ETH or an empty call (the contract has no receive, fallback or payable function, so the Safe's
/// call reverts and the transaction can never execute) or a known token (the contract can't move
/// it, so it would stay there for good). The first wired board signed 0.01 ETH to its own owner
/// contract (2026-11-15): valid on-chain, never executable. A call with data and no ETH stays
/// allowed: the Safe may call its owner (to enrol, for one).
pub fn to_own_owner(d: &Decoded, owner: &[u8; 20]) -> Option<&'static str> {
    for a in actions(d) {
        match a {
            Action::Eth { to, .. } if to == owner => return Some("ETH to your own owner contract: it can't receive ETH, so this could never execute"),
            Action::Raw { to, value, .. } if to == owner && !value.is_zero() => {
                return Some("ETH to your own owner contract: it can't receive ETH, so this could never execute");
            }
            Action::Token { to, .. } if to == owner => return Some("tokens to your own owner contract: it can't move them, so they would be stuck"),
            _ => {}
        }
    }
    None
}

pub fn actions(d: &Decoded) -> Vec<&Action> {
    let mut v = alloc::vec![&d.action];
    match &d.action {
        Action::Approve { parent, .. } => v.push(&parent.action),
        Action::Exec { action, .. } => v.push(action),
        _ => {}
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(amount(&U256::from_u64(1_234_500_000), 6), "1,234.5");
        assert_eq!(amount(&U256::from_u64(5), 18), "0.000000000000000005");
        assert_eq!(amount(&U256::from_u64(0), 18), "0");
        assert_eq!(amount(&U256::from_u128(1_000_000_000_000_000_000_000), 18), "1,000");
    }

    #[test]
    fn transfers_and_refusals() {
        let safe = [0x5a; 20];
        let usdc = TOKENS[0];
        let mut data = alloc::vec::Vec::from(TRANSFER);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[7; 20]);
        data.extend_from_slice(&U256::from_u64(2_500_000).0);
        let t = SafeTx { to: usdc.address, data: data.clone(), ..Default::default() };
        let d = decode(42161, &safe, &t, None).unwrap();
        assert!(matches!(d.action, Action::Token { amount, .. } if amount == U256::from_u64(2_500_000)));
        assert!(!d.needs_second());
        // the same call on another chain, or to another contract: not decoded
        assert!(matches!(decode(1, &safe, &t, None).unwrap().action, Action::Raw { .. }));
        // each chain's own USDC and WETH are named there and nowhere else
        for (chain, sym, addr) in [
            (1, "USDC", "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            (1, "WETH", "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            (8453, "USDC", "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            (8453, "WETH", "4200000000000000000000000000000000000006"),
        ] {
            let t = SafeTx { to: h20(addr), data: data.clone(), ..Default::default() };
            assert!(matches!(decode(chain, &safe, &t, None).unwrap().action, Action::Token { token, .. } if token.symbol == sym && token.chain == chain));
            assert!(matches!(decode(42161, &safe, &t, None).unwrap().action, Action::Raw { .. }));
        }
        let mut dc = t.clone();
        dc.operation = Operation::DelegateCall;
        assert_eq!(decode(42161, &safe, &dc, None), Err(Refusal::DelegateCall));
        let cancel = SafeTx { to: safe, ..Default::default() };
        assert_eq!(decode(42161, &safe, &cancel, None).unwrap().action, Action::Cancel);
        let mut gas = cancel.clone();
        gas.gas_price = U256::from_u64(1);
        assert!(decode(42161, &safe, &gas, None).unwrap().needs_second());
    }

    /// execTransaction's call data as Solidity's encoder gives it.
    fn exec_data(p: &SafeTx, signatures: &[u8]) -> Vec<u8> {
        let pad = |n: usize| n.div_ceil(32) * 32;
        let word = |n: usize| U256::from_u64(n as u64).0;
        let address = |a: &[u8; 20]| {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(a);
            w
        };
        let mut d = Vec::from(EXEC_TRANSACTION);
        d.extend_from_slice(&address(&p.to));
        d.extend_from_slice(&p.value.0);
        d.extend_from_slice(&word(320));
        d.extend_from_slice(&word(p.operation as usize));
        d.extend_from_slice(&p.safe_tx_gas.0);
        d.extend_from_slice(&p.base_gas.0);
        d.extend_from_slice(&p.gas_price.0);
        d.extend_from_slice(&address(&p.gas_token));
        d.extend_from_slice(&address(&p.refund_receiver));
        d.extend_from_slice(&word(320 + 32 + pad(p.data.len())));
        for b in [&p.data[..], signatures] {
            d.extend_from_slice(&word(b.len()));
            d.extend_from_slice(b);
            d.resize(d.len() + pad(b.len()) - b.len(), 0);
        }
        d
    }

    #[test]
    fn exec_on_a_parent_safe() {
        let (safe, parent, bob) = ([0x5a; 20], [0x7e; 20], [0xb0; 20]);
        let on = |data: Vec<u8>| SafeTx { to: parent, data, nonce: U256::from_u64(3), ..Default::default() };
        let exec = |d: &Decoded| match &d.action {
            Action::Exec { parent_safe, action, refund, signatures } => (*parent_safe, (**action).clone(), refund.clone(), *signatures),
            a => panic!("not an execution: {a:?}"),
        };
        let raw = |t: &SafeTx| matches!(decode(42161, &safe, t, None).unwrap().action, Action::Raw { selector: Some(EXEC_TRANSACTION), .. });

        // an ETH transfer: the parent's action, no nonce, the signatures' length
        let send = SafeTx { to: bob, value: U256::from_u64(7), ..Default::default() };
        let t = on(exec_data(&send, &[1; 130]));
        let d = decode(42161, &safe, &t, None).unwrap();
        assert_eq!(exec(&d), (parent, Action::Eth { to: bob, value: U256::from_u64(7) }, None, 130));
        assert_eq!(d.nonce, U256::from_u64(3));
        assert!(!d.needs_second());
        assert_eq!(actions(&d).len(), 2);
        // no signatures, and data of a length that needs padding
        assert_eq!(exec(&decode(42161, &safe, &on(exec_data(&send, &[])), None).unwrap()).3, 0);

        // a token transfer of the parent's, on the chain the token is on
        let usdc = TOKENS[0];
        let mut transfer = Vec::from(TRANSFER);
        transfer.extend_from_slice(&[0; 12]);
        transfer.extend_from_slice(&bob);
        transfer.extend_from_slice(&U256::from_u64(2_500_000).0);
        let token = SafeTx { to: usdc.address, data: transfer, ..Default::default() };
        assert!(matches!(exec(&decode(42161, &safe, &on(exec_data(&token, &[1; 65])), None).unwrap()).1, Action::Token { amount, .. } if amount == U256::from_u64(2_500_000)));

        // a cancel of the parent's: an empty call from the parent to itself
        let cancel = SafeTx { to: parent, ..Default::default() };
        assert_eq!(exec(&decode(42161, &safe, &on(exec_data(&cancel, &[1; 65])), None).unwrap()).1, Action::Cancel);

        // a call the board can't read, or refund fields: a second confirmation
        let other = SafeTx { to: bob, data: alloc::vec![0x12, 0x34, 0x56, 0x78, 9], ..Default::default() };
        let d = decode(42161, &safe, &on(exec_data(&other, &[1; 65])), None).unwrap();
        assert!(matches!(exec(&d).1, Action::Raw { data_len: 5, .. }));
        assert!(d.needs_second());
        let paid = SafeTx { gas_price: U256::from_u64(5), refund_receiver: [0xee; 20], ..send.clone() };
        let d = decode(42161, &safe, &on(exec_data(&paid, &[1; 65])), None).unwrap();
        assert_eq!(exec(&d).2.unwrap().refund_receiver, [0xee; 20]);
        assert!(d.needs_second());
        // one level: the parent's own approveHash or execTransaction isn't read
        let deeper = SafeTx { to: bob, data: exec_data(&send, &[1; 65]), ..Default::default() };
        assert!(matches!(exec(&decode(42161, &safe, &on(exec_data(&deeper, &[1; 65])), None).unwrap()).1, Action::Raw { .. }));

        // the parent's delegate call is refused, as for an approval
        let dc = SafeTx { operation: Operation::DelegateCall, ..send.clone() };
        assert_eq!(decode(42161, &safe, &on(exec_data(&dc, &[1; 65])), None), Err(Refusal::ParentDelegateCall));
        // parent fields don't go with it
        assert_eq!(decode(42161, &safe, &t, Some(&send)), Err(Refusal::ParentUnused));
        // ETH to the member's own owner contract
        assert!(to_own_owner(&d, &bob).is_some());

        // not read: a value sent along, the Safe calling itself
        assert!(raw(&SafeTx { value: U256::from_u64(1), ..t.clone() }));
        assert!(matches!(decode(42161, &parent, &t, None).unwrap().action, Action::Raw { .. }));

        // only the encoding Solidity's encoder gives is read. Every shorter call, and bytes after
        // the end (Safe's app appends the transaction's fields: the app takes them off)
        let good = exec_data(&other, &[1; 67]);
        for n in 4..good.len() {
            assert!(raw(&on(good[..n].to_vec())), "cut to {n} bytes");
        }
        for extra in [1, 32, 516] {
            let mut d = good.clone();
            d.resize(d.len() + extra, 0);
            assert!(raw(&on(d)), "{extra} more bytes");
        }
        // an address with bytes above it, an operation that is neither, padding that isn't zero,
        // offsets and lengths that don't say what the encoder would (a length one longer reads a
        // zero byte of the padding as data, which is that encoding of another call)
        let at = |word: usize, byte: usize| 4 + 32 * word + byte;
        let data_len = at(10, 31);
        let sig_len = at(12, 31);
        for (i, v) in [(at(0, 0), 1), (at(7, 11), 1), (at(8, 3), 0xff), (at(3, 31), 2), (at(3, 0), 1), (at(2, 31), 0x60), (at(2, 0), 0x80), (at(9, 31), 0xa0), (at(9, 1), 1), (at(11, 5), 1), (data_len, 4), (data_len, 0x45), (at(10, 0), 0xff), (sig_len, 66), (at(12, 23), 1), (good.len() - 1, 1)] {
            let mut d = good.clone();
            assert_ne!(d[i], v);
            d[i] = v;
            assert!(raw(&on(d)), "byte {i} set to {v}");
        }
        // any one byte changed: read as another call in that encoding, or not read; never a panic
        for i in 0..good.len() {
            let mut d = good.clone();
            d[i] ^= 0x80;
            match decode(42161, &safe, &on(d), None) {
                Ok(Decoded { action: Action::Exec { .. } | Action::Raw { .. }, .. }) | Err(Refusal::ParentDelegateCall) => {}
                x => panic!("byte {i}: {x:?}"),
            }
        }
    }
}
