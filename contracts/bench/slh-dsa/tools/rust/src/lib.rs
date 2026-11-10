//! SLH-DSA-SHA2-128s through RustCrypto's slh-dsa: the functions the native binary and the WebAssembly timing share.
use slh_dsa::{Sha2_128s, Signature, SigningKey, VerifyingKey};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// slh_keygen_internal from seed = SK.seed | SK.prf | PK.seed (48 bytes); returns the 64-byte secret key.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn keygen(seed: &[u8]) -> Vec<u8> {
    SigningKey::<Sha2_128s>::slh_keygen_internal(&seed[..16], &seed[16..32], &seed[32..48]).to_vec()
}

/// Pure SLH-DSA (FIPS 205 Algorithm 22) with a context; an empty `opt_rand` signs deterministically.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn sign(sk: &[u8], message: &[u8], ctx: &[u8], opt_rand: &[u8]) -> Vec<u8> {
    let sk = SigningKey::<Sha2_128s>::try_from(sk).expect("secret key");
    let rand = if opt_rand.is_empty() { None } else { Some(opt_rand) };
    let sig: Signature<Sha2_128s> = sk.try_sign_with_context(message, ctx, rand).expect("context");
    sig.to_vec()
}

/// slh_sign_internal on M' as given.
pub fn sign_internal(sk: &[u8], m_prime: &[u8], opt_rand: &[u8]) -> Vec<u8> {
    let sk = SigningKey::<Sha2_128s>::try_from(sk).expect("secret key");
    let rand = if opt_rand.is_empty() { None } else { Some(opt_rand) };
    sk.slh_sign_internal(&[m_prime], rand).to_vec()
}

/// The public key (PK.seed | PK.root) of a secret key.
pub fn public_key(sk: &[u8]) -> Vec<u8> {
    let sk = SigningKey::<Sha2_128s>::try_from(sk).expect("secret key");
    let vk: &VerifyingKey<Sha2_128s> = sk.as_ref();
    vk.to_vec()
}

/// Pure SLH-DSA verification (Algorithm 24), or the internal interface (Algorithm 20).
pub fn verify(pk: &[u8], message: &[u8], ctx: &[u8], sig: &[u8], internal: bool) -> bool {
    let (Ok(vk), Ok(sig)) = (VerifyingKey::<Sha2_128s>::try_from(pk), Signature::<Sha2_128s>::try_from(sig)) else {
        return false;
    };
    if internal {
        vk.slh_verify_internal(&[message], &sig).is_ok()
    } else {
        vk.try_verify_with_context(message, ctx, &sig).is_ok()
    }
}
