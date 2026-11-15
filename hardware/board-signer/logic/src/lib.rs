//! Winterlock's board signer without its hardware (docs/notes/signer-app.md, "The board"): button
//! events and USB requests in, 128x64 screens and answers out, over winterlock-core for all of its
//! cryptography and a NOR flash partition for its storage. The firmware
//! (`hardware/board-signer/firmware`) runs it on an ESP32; the tests, the screen renderer and the
//! virtual board run it on a computer.
//!
//! - [`board`]: the flows (setup, unlock, recovery, enrolment, confirming transactions, erase)
//! - [`store`]: the flash partition as an append-only log of records, and the key log
//! - [`proto`]: the USB link's frames and messages
//! - [`decode`]: what a Safe transaction does, from its fields; the built-in token list
//! - [`keys`]: every key derived from the seed, in one place
//! - [`ui`]: screens and the frame buffer
//! - [`input`]: the two buttons, debounced
//! - [`sim`]: a NOR flash in memory that can lose power at any write
//!
//! Nothing here reads a clock or has randomness of its own: the [`platform::Platform`] gives
//! random bytes, the display, the link and the second core.

#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::large_enum_variant, clippy::manual_is_multiple_of)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod board;
pub mod crc;
pub mod decode;
pub mod input;
pub mod keys;
pub mod platform;
pub mod proto;
pub mod sim;
pub mod store;
pub mod ui;

pub use board::Board;
pub use platform::Platform;
