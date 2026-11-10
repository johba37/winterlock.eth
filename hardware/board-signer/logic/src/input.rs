//! The two buttons: left is back or no, right is next or yes, and both held for about a second
//! confirm. The firmware samples the pins (it knows whether they are active high or low) and
//! feeds the levels to [`Buttons`], which debounces them and turns them into events.
//!
//! A single press counts when it is released, so pressing both never starts with a left or right
//! press. Both pressed together count once they have been held for [`Timing::hold_ms`]; letting
//! go of both earlier counts as nothing. Nothing counts until both buttons have been seen
//! released once: a button held at start, a stuck one, or a pin that reads pressed all the time
//! (an emulator) never confirms anything.

/// A button event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    /// Both held for about a second.
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// How long a level must hold before it counts (contact bounce).
    pub debounce_ms: u32,
    /// How long both must be held to confirm.
    pub hold_ms: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Timing { debounce_ms: 20, hold_ms: 1000 }
    }
}

#[derive(Clone, Copy, Debug)]
struct Debounced {
    stable: bool,
    candidate: bool,
    since: u64,
}

impl Debounced {
    fn new() -> Self {
        Debounced { stable: false, candidate: false, since: 0 }
    }

    fn sample(&mut self, now: u64, level: bool, debounce: u32) -> bool {
        if level != self.candidate {
            self.candidate = level;
            self.since = now;
        } else if level != self.stable && now.saturating_sub(self.since) >= debounce as u64 {
            self.stable = level;
        }
        self.stable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gesture {
    Idle,
    /// A press is under way: which buttons took part, when both went down, whether it fired.
    Pressing { left: bool, right: bool, both_since: Option<u64>, fired: bool, both_seen: bool },
}

/// Debounces two buttons and turns them into [`Button`] events.
pub struct Buttons {
    timing: Timing,
    armed: bool,
    left: Debounced,
    right: Debounced,
    gesture: Gesture,
}

impl Buttons {
    pub fn new(timing: Timing) -> Self {
        Buttons { timing, armed: false, left: Debounced::new(), right: Debounced::new(), gesture: Gesture::Idle }
    }

    /// One sample of both levels (true: pressed) at `now_ms`; sample every few milliseconds.
    pub fn sample(&mut self, now_ms: u64, left_down: bool, right_down: bool) -> Option<Button> {
        let l = self.left.sample(now_ms, left_down, self.timing.debounce_ms);
        let r = self.right.sample(now_ms, right_down, self.timing.debounce_ms);
        if !self.armed {
            // both seen released before anything counts
            self.armed = !left_down && !right_down && !l && !r;
            return None;
        }
        match &mut self.gesture {
            Gesture::Idle => {
                if l || r {
                    let both_since = (l && r).then_some(now_ms);
                    self.gesture = Gesture::Pressing { left: l, right: r, both_since, fired: false, both_seen: l && r };
                }
                None
            }
            Gesture::Pressing { left, right, both_since, fired, both_seen } => {
                *left |= l;
                *right |= r;
                if l && r {
                    *both_seen = true;
                    let t0 = *both_since.get_or_insert(now_ms);
                    if !*fired && now_ms.saturating_sub(t0) >= self.timing.hold_ms as u64 {
                        *fired = true;
                        return Some(Button::Both);
                    }
                } else {
                    *both_since = None;
                }
                if !l && !r {
                    let ev = match (*fired || *both_seen, *left, *right) {
                        (false, true, false) => Some(Button::Left),
                        (false, false, true) => Some(Button::Right),
                        _ => None,
                    };
                    self.gesture = Gesture::Idle;
                    return ev;
                }
                None
            }
        }
    }

    /// Whether either button is down now (debounced), e.g. to wait for a release.
    pub fn any_down(&self) -> bool {
        self.left.stable || self.right.stable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Runs a script of (duration ms, left, right) at a 1 ms sample rate.
    fn run(script: &[(u64, bool, bool)]) -> Vec<(u64, Button)> {
        let mut b = Buttons::new(Timing::default());
        let mut t = 0;
        let mut out = Vec::new();
        for &(d, l, r) in script {
            for _ in 0..d {
                if let Some(e) = b.sample(t, l, r) {
                    out.push((t, e));
                }
                t += 1;
            }
        }
        out
    }

    #[test]
    fn single_presses_count_on_release() {
        let e = run(&[(50, false, false), (100, true, false), (100, false, false), (80, false, true), (100, false, false)]);
        assert_eq!(e.iter().map(|x| x.1).collect::<Vec<_>>(), [Button::Left, Button::Right]);
        // pressed from 50 to 150 ms: it counts once the release has held for 20 ms
        assert!(e[0].0 >= 170 && e[0].0 < 175, "left counts once released: {}", e[0].0);
    }

    #[test]
    fn bounce_is_ignored() {
        // a press that chatters for 10 ms at each edge is one press
        let mut s = alloc::vec![(20, false, false)];
        for _ in 0..5 {
            s.push((1, true, false));
            s.push((1, false, false));
        }
        s.push((100, true, false));
        for _ in 0..5 {
            s.push((1, false, false));
            s.push((1, true, false));
        }
        s.push((100, false, false));
        assert_eq!(run(&s).len(), 1);
        // a 10 ms blip is not a press
        assert!(run(&[(20, false, false), (10, true, false), (100, false, false)]).is_empty());
    }

    #[test]
    fn nothing_counts_until_both_were_released() {
        // pressed from the start and held 3 s: no Both, no Left
        assert!(run(&[(3000, true, true), (100, false, false)]).is_empty());
        assert!(run(&[(3000, true, false), (100, false, false)]).is_empty());
        // then a real press counts
        let e = run(&[(3000, true, true), (100, false, false), (100, false, true), (100, false, false)]);
        assert_eq!(e.iter().map(|x| x.1).collect::<Vec<_>>(), [Button::Right]);
    }

    #[test]
    fn both_held_confirms_once() {
        // left first, right 60 ms later, both held 1.5 s: one Both, no Left
        let e = run(&[(10, false, false), (60, true, false), (1500, true, true), (100, false, false)]);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].1, Button::Both);
        assert!(e[0].0 >= 1070 && e[0].0 <= 1100, "fires after about a second: {}", e[0].0);
        // both for half a second, then released: nothing
        assert!(run(&[(10, false, false), (500, true, true), (100, false, false)]).is_empty());
        // both, then one released and pressed again: the hold restarts
        let e = run(&[(10, false, false), (700, true, true), (50, true, false), (700, true, true), (100, false, false)]);
        assert!(e.is_empty(), "{e:?}");
    }
}
