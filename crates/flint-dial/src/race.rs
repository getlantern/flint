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
pub async fn race_with<F, Fut, T>(
    count: usize,
    mut dial_one: F,
) -> Result<(usize, T), Vec<io::Error>>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut set = FuturesUnordered::new();
    for i in 0..count {
        let fut = dial_one(i);
        set.push(async move { (i, fut.await) });
    }
    let mut errors = Vec::new();
    while let Some((i, res)) = set.next().await {
        match res {
            Ok(v) => return Ok((i, v)),
            Err(e) => errors.push(e),
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
}
