//! The second core, and how much of each core's stack the run used.
//!
//! Work for the second core runs as a closure on its own stack, started for each job and parked
//! when it's done. Both stacks are painted with a pattern before use; the highest byte that no
//! longer holds the pattern gives the peak use.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering};

use esp_hal::system::{CpuControl, Stack};
use esp_hal::time::{Duration, Instant};

/// The second core's stack. The jobs here need a few KB; this leaves a wide margin.
pub const APP_STACK_SIZE: usize = 32 * 1024;
static mut APP_STACK: Stack<APP_STACK_SIZE> = Stack::new();
static APP_DONE: AtomicBool = AtomicBool::new(false);

const PAINT: u32 = 0xA5A5_5A5A;
/// Bytes left unpainted at the low end of each stack: esp-hal's stack guard word (60 bytes
/// up, under a watchpoint) and, on the second core, the closure it copies there.
const SKIP: usize = 256;

pub struct Dual<'d> {
    cpu: CpuControl<'d>,
    pub runs: u32,
}

impl<'d> Dual<'d> {
    pub fn new(cpu: CpuControl<'d>) -> Self {
        // SAFETY: the second core isn't running; nothing else touches its stack.
        unsafe {
            let mem = addr_of_mut!((*addr_of_mut!(APP_STACK)).mem).cast::<u32>();
            for i in 0..APP_STACK_SIZE / 4 {
                mem.add(i).write_volatile(PAINT);
            }
        }
        Dual { cpu, runs: 0 }
    }

    /// Runs `here` on this core and `there` on the second core at the same time; returns once
    /// both are done. Err if the second core didn't start: then only `here` ran.
    pub fn run(&mut self, here: impl FnOnce(), there: impl FnOnce() + Send) -> Result<(), &'static str> {
        APP_DONE.store(false, Ordering::Release);
        // SAFETY: the second core is parked between jobs, so nothing else uses its stack.
        let stack = unsafe { &mut *addr_of_mut!(APP_STACK) };
        let started = self.cpu.start_app_core(stack, move || {
            crate::enable_fpu();
            there();
            APP_DONE.store(true, Ordering::Release);
        });
        here();
        let guard = started.map_err(|_| "the second core was already running")?;
        let t = Instant::now();
        while !APP_DONE.load(Ordering::Acquire) {
            if t.elapsed() > Duration::from_secs(600) {
                return Err("the second core didn't finish within 10 minutes");
            }
            core::hint::spin_loop();
        }
        drop(guard); // parks the second core
        self.runs += 1;
        Ok(())
    }
}

#[cfg(feature = "test-hooks")]
fn high_water(lo: *const u32, words: usize) -> usize {
    // SAFETY: reads within the stack; the pattern only changes where a stack grew.
    let untouched = (0..words).take_while(|&i| unsafe { lo.add(i).read_volatile() } == PAINT).count();
    (words - untouched) * 4
}

/// (peak use, size) of the second core's stack, in bytes.
#[cfg(feature = "test-hooks")]
pub fn app_stack_used() -> (usize, usize) {
    let mem = unsafe { addr_of!((*addr_of!(APP_STACK)).mem).cast::<u32>() };
    let lo = unsafe { mem.add(SKIP / 4) };
    (high_water(lo, (APP_STACK_SIZE - SKIP) / 4), APP_STACK_SIZE)
}

unsafe extern "C" {
    static _stack_end_cpu0: u32;
    static _stack_start_cpu0: u32;
}

fn main_stack() -> (usize, usize) {
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

/// Paints the first core's free stack, below where it is now (with interrupts off).
pub fn paint_main_stack() {
    let (lo, _) = main_stack();
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

/// (peak use, size) of the first core's stack, in bytes. Counts from the stack's top, so the
/// frames above the painted part count as used.
#[cfg(feature = "test-hooks")]
pub fn main_stack_used() -> (usize, usize) {
    let (lo, hi) = main_stack();
    let words = (hi - lo) / 4;
    let used_from_lo = high_water(lo as *const u32, words);
    (used_from_lo, hi - lo + SKIP)
}
