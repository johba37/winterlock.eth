//! What the board needs from its hardware (or from a test or the virtual board).

use crate::ui::{Frame, Screen};

pub trait Platform {
    /// Fills `out` from the hardware random number generator.
    fn random(&mut self, out: &mut [u8]);
    /// Shows a screen (its model, and the frame drawn from it).
    fn show(&mut self, screen: &Screen, frame: &Frame);
    /// Sends a frame's bytes to the app.
    fn send(&mut self, bytes: &[u8]);
    /// Runs `here` on this core and `there` on the other at the same time, and returns when both
    /// are done. A platform with one core runs them one after the other.
    fn both(&mut self, here: &mut (dyn FnMut() + Send), there: &mut (dyn FnMut() + Send));
}

/// 32 secret bytes, zeroed when dropped.
pub struct Secret(pub [u8; 32]);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0 = [0; 32];
        // keeps the compiler from dropping the zeroing as a dead store
        core::hint::black_box(&mut self.0);
    }
}
