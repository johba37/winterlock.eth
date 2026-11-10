//! What a Safe transaction does, decoded on the board from its fields (never taken from the
//! app): an ETH transfer, an ERC-20 `transfer` of a token on the built-in list, an `approveHash`
//! of a parent Safe's transaction whose fields came along, a cancel (an empty call from the Safe to
//! itself), or anything else, shown as its target, value and selector and marked as not decoded.
//! A delegate call is refused.

use alloc::boxed::Box;
use alloc::vec::Vec;

use winterlock_core::U256;
use winterlock_core::hex::h20;
use winterlock_core::safe::{Operation, SafeTx};

/// A token the board names: only addresses checked against the issuer's or the chain's own
/// documentation, and their decimals and symbol read on-chain (2026-11-10):
/// - USDC: Circle's "USDC contract addresses" page (developers.circle.com), mainnet and testnet
/// - WETH on Arbitrum One: Arbitrum's "Contract addresses" page (docs.arbitrum.io)
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
];

pub fn token(chain: u64, address: &[u8; 20]) -> Option<&'static Token> {
    TOKENS.iter().find(|t| t.chain == chain && t.address == *address)
}

/// transfer(address,uint256)
pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// approveHash(bytes32)
pub const APPROVE_HASH: [u8; 4] = [0xd4, 0xd9, 0xbd, 0xcd];

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
            Refusal::ParentDelegateCall => "the parent Safe's transaction is a delegate call: refused",
            Refusal::ParentMismatch => "the parent's fields don't hash to the approveHash argument",
            Refusal::ParentUnused => "parent fields came with a call that isn't approveHash",
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
pub fn actions(d: &Decoded) -> Vec<&Action> {
    let mut v = alloc::vec![&d.action];
    if let Action::Approve { parent, .. } = &d.action {
        v.push(&parent.action);
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
        let mut dc = t.clone();
        dc.operation = Operation::DelegateCall;
        assert_eq!(decode(42161, &safe, &dc, None), Err(Refusal::DelegateCall));
        let cancel = SafeTx { to: safe, ..Default::default() };
        assert_eq!(decode(42161, &safe, &cancel, None).unwrap().action, Action::Cancel);
        let mut gas = cancel.clone();
        gas.gas_price = U256::from_u64(1);
        assert!(decode(42161, &safe, &gas, None).unwrap().needs_second());
    }
}
