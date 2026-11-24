//! How much of the stack the run used: the free stack is painted with a pattern before the run;
//! the highest word that no longer holds it gives the peak. (As in esp32-core-check.)

use core::ptr::addr_of;

const PAINT: u32 = 0xA5A5_5A5A;
/// Bytes left unpainted at the low end: esp-hal's stack guard word (under a watchpoint).
const SKIP: usize = 256;

unsafe extern "C" {
    static _stack_end_cpu0: u32;
    static _stack_start_cpu0: u32;
}

fn bounds() -> (usize, usize) {
    let lo = addr_of!(_stack_end_cpu0) as usize + SKIP;
    let hi = addr_of!(_stack_start_cpu0) as usize;
    (lo, hi)
}

fn stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: reads a1, the stack pointer.
    unsafe { core::arch::asm!("mov {0}, a1", out(reg) sp) };
    sp
}

/// Paints the free stack below where it is now (with interrupts off).
pub fn paint() {
    let (lo, _) = bounds();
    let top = stack_pointer() - 2048;
    critical_section::with(|_| {
        let mut a = lo;
        while a < top {
            // SAFETY: free stack below the current frame, with interrupts off.
            unsafe { (a as *mut u32).write_volatile(PAINT) };
            a += 4;
        }
    });
}

/// (peak use, size) of the stack, in bytes.
pub fn used() -> (usize, usize) {
    let (lo, hi) = bounds();
    let words = (hi - lo) / 4;
    // SAFETY: reads within the stack; the pattern only changes where the stack grew.
    let untouched = (0..words)
        .take_while(|&i| unsafe { (lo as *const u32).add(i).read_volatile() } == PAINT)
        .count();
    ((words - untouched) * 4, hi - lo + SKIP)
}
