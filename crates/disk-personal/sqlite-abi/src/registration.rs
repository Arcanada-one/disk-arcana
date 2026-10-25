//! Monotonic registration identities; retirement never restores capacity.
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) fn reserve(counter: &AtomicU64) -> Option<u64> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= 128 {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(previous) => return Some(previous),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_capacity_and_refusal_never_wrap_or_restore() {
        let counter = AtomicU64::new(0);
        for expected in 0..128 {
            assert_eq!(reserve(&counter), Some(expected));
        }
        for _ in 0..3 {
            assert_eq!(reserve(&counter), None);
            assert_eq!(counter.load(Ordering::Relaxed), 128);
        }
        let overflow = AtomicU64::new(u64::MAX);
        assert_eq!(reserve(&overflow), None);
        assert_eq!(overflow.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn last_slot_returns_original_identity_then_refuses() {
        let counter = AtomicU64::new(127);
        assert_eq!(reserve(&counter), Some(127));
        assert_eq!(reserve(&counter), None);
        assert_eq!(counter.load(Ordering::Relaxed), 128);
    }

    #[test]
    fn contended_reservations_are_unique_and_never_exceed_capacity() {
        let counter = AtomicU64::new(0);
        let mut ids = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    let counter = &counter;
                    scope
                        .spawn(move || (0..32).filter_map(|_| reserve(counter)).collect::<Vec<_>>())
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        ids.sort_unstable();
        assert_eq!(ids, (0..128).collect::<Vec<_>>());
        assert_eq!(counter.load(Ordering::Relaxed), 128);
        assert_eq!(reserve(&counter), None);
    }
}
