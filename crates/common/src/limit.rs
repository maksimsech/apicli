use std::{
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fieldkit_vault::Store;

use crate::{
    Failure,
    rate::{Bucket, Limits, Wait},
};

pub fn take(
    store: &Store,
    key: &str,
    label: &str,
    limits: &Limits,
    wait: Option<f64>,
) -> Result<(), Failure> {
    let deadline = wait.map(|seconds| now().saturating_add((seconds.max(0.0) * 1000.0) as u64));
    loop {
        let current = now();
        let result = store.update_buckets::<Bucket, _>(|buckets| {
            buckets
                .entry(key.to_string())
                .or_default()
                .take(limits, current)
        })?;
        let Err(wait) = result else {
            return Ok(());
        };
        if deadline.is_some_and(|deadline| current.saturating_add(wait.millis()) <= deadline) {
            sleep(Duration::from_millis(wait.millis()));
            continue;
        }
        let seconds = wait.millis() as f64 / 1000.0;
        let reason = match wait {
            Wait::Rate(_) => format!("rate limited on {label} ({limits}), retry in {seconds:.1}s"),
            Wait::Daily(_) => format!(
                "the daily limit for {label} is used up ({limits}), it resets in {seconds:.0}s"
            ),
            Wait::Upstream(_) => {
                format!("{label} answered 429 Too Many Requests, retry in {seconds:.0}s")
            }
        };
        return Err(Failure::Limited(format!(
            "{reason}\nrerun with --wait to wait for it"
        )));
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
