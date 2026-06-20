//! Happy-eyeballs racing: dial a set of strategies concurrently, first success wins.

use std::future::Future;
use std::io;

use futures::stream::{FuturesUnordered, StreamExt};

use crate::{BootstrapStrategy, BoxedTlsStream};

/// Race `count` dials concurrently via `dial_one(i)`, returning `(winning_index, value)` for the first
/// that resolves `Ok`. If every dial fails, returns all the errors (in completion order). The losing
/// futures are dropped (cancelled) as soon as a winner is found.
///
/// Generic over the dial so it is unit-testable without a network and reusable beyond TLS. `count == 0`
/// yields `Err(vec![])`.
pub async fn race_with<F, Fut, T>(count: usize, dial_one: F) -> Result<(usize, T), Vec<io::Error>>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    // Unbounded == a window as wide as the field.
    race_windowed(count, count, dial_one).await
}

/// Like [`race_with`] but with **bounded concurrency**: at most `window` dials are in flight at once,
/// refilling as each finishes, so a large `count` doesn't open every connection simultaneously
/// (design §3.1). Returns `(winning_index, value)` for the first `Ok`; the losers are dropped. If all
/// fail, returns every error in completion order. `window` is clamped to at least 1; `count == 0`
/// yields `Err(vec![])`. With `window >= count` this is exactly [`race_with`] (unbounded).
pub async fn race_windowed<F, Fut, T>(
    count: usize,
    window: usize,
    mut dial_one: F,
) -> Result<(usize, T), Vec<io::Error>>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    use futures::future::LocalBoxFuture;
    use futures::FutureExt as _;

    // `LocalBoxFuture<'_, (usize, io::Result<T>)>` is a type-erased pinned box that does not
    // require `Send` or `'static`, giving both push sites the same concrete element type for
    // `FuturesUnordered` without unsafe code and without new crate dependencies.
    let window = window.max(1);
    let mut set: FuturesUnordered<LocalBoxFuture<'_, (usize, io::Result<T>)>> =
        FuturesUnordered::new();
    let mut next = 0;
    while next < count && set.len() < window {
        let i = next;
        set.push(dial_one(i).map(move |r| (i, r)).boxed_local());
        next += 1;
    }
    let mut errors = Vec::new();
    while let Some((i, res)) = set.next().await {
        match res {
            Ok(v) => return Ok((i, v)),
            Err(e) => {
                errors.push(e);
                if next < count {
                    let i = next;
                    set.push(dial_one(i).map(move |r| (i, r)).boxed_local());
                    next += 1;
                }
            }
        }
    }
    Err(errors)
}

/// Race a slice of [`BootstrapStrategy`]s, returning the first that dials successfully (and its index
/// into `strategies`), or every error if all fail. Concurrent — the slower compositions are cancelled
/// once one connects.
pub async fn race(
    strategies: &[BootstrapStrategy],
) -> Result<(usize, BoxedTlsStream), Vec<io::Error>> {
    race_with(strategies.len(), |i| crate::dial(&strategies[i])).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn first_ok_wins_and_reports_its_index() {
        let res = race_with(3, |i| async move {
            if i == 1 {
                Ok::<_, io::Error>(110)
            } else {
                Err(io::Error::other("declined"))
            }
        })
        .await;
        assert_eq!(res.unwrap(), (1, 110));
    }

    #[tokio::test]
    async fn an_immediate_ok_beats_a_slow_ok() {
        // index 0 sleeps before succeeding; index 1 is ready immediately, so it wins.
        let res = race_with(2, |i| async move {
            if i == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<_, io::Error>(0)
            } else {
                Ok::<_, io::Error>(1)
            }
        })
        .await;
        assert_eq!(res.unwrap(), (1, 1));
    }

    #[tokio::test]
    async fn all_failures_are_collected() {
        let res = race_with(3, |_| async move { Err::<i32, _>(io::Error::other("x")) }).await;
        assert_eq!(res.unwrap_err().len(), 3);
    }

    #[tokio::test]
    async fn empty_set_yields_no_errors() {
        let res = race_with(0, |_| async move { Ok::<i32, io::Error>(0) }).await;
        assert!(res.unwrap_err().is_empty());
    }

    #[tokio::test]
    async fn windowed_never_exceeds_the_window_and_runs_all() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let inflight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        // 10 dials, window 3, all fail → every dial runs (10 errors) but never >3 concurrently.
        let res = race_windowed(10, 3, |_| {
            let inflight = Arc::clone(&inflight);
            let max_seen = Arc::clone(&max_seen);
            async move {
                let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(5)).await;
                inflight.fetch_sub(1, Ordering::SeqCst);
                Err::<i32, _>(io::Error::other("decline"))
            }
        })
        .await;
        assert_eq!(res.unwrap_err().len(), 10, "all dials should run");
        assert!(
            max_seen.load(Ordering::SeqCst) <= 3,
            "max in flight {} exceeded the window",
            max_seen.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn windowed_first_ok_wins_with_refill() {
        // Window 2; index 5 is the only Ok. It can only start after earlier failures refill the
        // window, so this also exercises refill. It must still win.
        let res = race_windowed(8, 2, |i| async move {
            if i == 5 {
                Ok::<_, io::Error>(55)
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Err(io::Error::other("decline"))
            }
        })
        .await;
        assert_eq!(res.unwrap().1, 55);
    }

    #[tokio::test]
    async fn windowed_with_window_larger_than_count_is_unbounded() {
        let res = race_windowed(3, 99, |i| async move {
            if i == 2 {
                Ok::<_, io::Error>(2)
            } else {
                Err(io::Error::other("x"))
            }
        })
        .await;
        assert_eq!(res.unwrap(), (2, 2));
    }

    #[tokio::test]
    async fn windowed_empty_yields_no_errors() {
        let res = race_windowed(0, 4, |_| async move { Ok::<i32, io::Error>(0) }).await;
        assert!(res.unwrap_err().is_empty());
    }
}
