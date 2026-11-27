// Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Waiting for capacity — what the node does when the issuance service answers
//! a submission with `insufficient_capacity`.
//!
//! That answer is one verdict for the whole set, and it consumes nothing: the
//! service refuses the set before persisting anything, so every commitment in
//! it stays available and the same set (same bytes, same `request_id`) can be
//! submitted again while the commitments are valid. The service accepts a
//! submission as long as it receives it no later than each member's
//! `expires_at`.
//!
//! Capacity often arrives shortly after a refusal (a top-up, an automatic
//! refill). So instead of recording the refusal as final at
//! once, the node keeps the set in its outbox and submits it again on a
//! schedule, until the service admits it or the window closes:
//!
//! - **Window.** It closes [`CAPACITY_WAIT_MARGIN`] before the EARLIEST
//!   `expires_at` among the members. Past an expiry the service would reject
//!   that member on its own; the margin absorbs clock skew between the node and
//!   the service and the duration of the request itself.
//! - **Schedule.** Counted from when the node first took the set: 1 minute,
//!   then 2, then 5, then every 15 minutes. Capacity added automatically
//!   typically lands within minutes, so the early probes are close together;
//!   after that the cause usually waits on a person, and a 15-minute step keeps
//!   a day-long wait to about a hundred refusals, each of which the service
//!   answers before persisting anything. The last attempt is
//!   placed exactly at the end of the window.
//!
//! While it waits, every member reads `accepted_for_retry` with the figures of
//! the latest refusal (`required`, `available`, `missing`); waiting does not
//! count as a failed delivery attempt, so it never dead-letters. When the
//! window closes, the last refusal is recorded as the final
//! `insufficient_capacity`. Any other answer on a later attempt is recorded
//! exactly as it would be on a first submission.
//!
//! This is node behaviour only: the issuance service still answers each
//! submission at once, and `insufficient_capacity` remains a terminal outcome.

use std::time::Duration;

use capacity_artifacts::SubmissionSetV1;

use crate::store::{CapacityShortfall, OperationState};

/// How long before the earliest commitment expiry the node stops resubmitting.
pub const CAPACITY_WAIT_MARGIN: Duration = Duration::from_secs(5 * 60);

/// The waits between attempts, by time already spent waiting: while less than
/// `.0` has elapsed, wait `.1`. Past the last threshold, [`CAPACITY_WAIT_STEP`].
const SCHEDULE: [(Duration, Duration); 3] = [
    (Duration::from_secs(60), Duration::from_secs(60)),
    (Duration::from_secs(3 * 60), Duration::from_secs(2 * 60)),
    (Duration::from_secs(8 * 60), Duration::from_secs(5 * 60)),
];

/// The steady wait between attempts once the first ones have passed.
pub const CAPACITY_WAIT_STEP: Duration = Duration::from_secs(15 * 60);

fn ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX / 4)
}

/// The end of the wait window for `set`, in epoch milliseconds: the earliest
/// member `expires_at` minus [`CAPACITY_WAIT_MARGIN`]. `None` when the set has
/// no members or a member's `expires_at` does not parse — the node then does
/// not wait, and records the refusal as final.
pub fn deadline_ms(set: &SubmissionSetV1) -> Option<i64> {
    let mut earliest: Option<i64> = None;
    for cert in &set.certificates {
        let raw = &cert.capacity_evidence.projected_commitment.expires_at;
        let at = chrono::DateTime::parse_from_rfc3339(raw)
            .ok()?
            .timestamp_millis();
        earliest = Some(earliest.map_or(at, |e| e.min(at)));
    }
    Some(earliest? - ms(CAPACITY_WAIT_MARGIN))
}

/// When to submit again after a refusal at `now_ms`, for a set the node has
/// held since `waiting_since_ms`. `None` once the window has closed: the
/// refusal is then final.
pub fn next_attempt_ms(now_ms: i64, waiting_since_ms: i64, deadline_ms: i64) -> Option<i64> {
    if now_ms >= deadline_ms {
        return None;
    }
    let elapsed = now_ms.saturating_sub(waiting_since_ms).max(0);
    let wait = SCHEDULE
        .iter()
        .find(|(below, _)| elapsed < ms(*below))
        .map_or(CAPACITY_WAIT_STEP, |(_, wait)| *wait);
    Some(now_ms.saturating_add(ms(wait)).min(deadline_ms))
}

/// The state every member holds while the node waits for capacity.
pub fn waiting_state(capacity: Option<CapacityShortfall>, deadline_ms: i64) -> OperationState {
    let until = chrono::DateTime::from_timestamp_millis(deadline_ms)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default();
    OperationState::AcceptedForRetry {
        error: format!(
            "insufficient_capacity: the node submits the set again until {until}, \
             while its commitments are valid"
        ),
        capacity,
    }
}

/// Whether a refusal at `now_ms` should be waited out, and if so when the next
/// attempt is due and what the members read meanwhile. `None` means record
/// the refusal as final.
pub fn plan(
    set: &SubmissionSetV1,
    capacity: &Option<CapacityShortfall>,
    now_ms: i64,
    waiting_since_ms: i64,
) -> Option<(i64, OperationState)> {
    let deadline = deadline_ms(set)?;
    let next = next_attempt_ms(now_ms, waiting_since_ms, deadline)?;
    Some((next, waiting_state(capacity.clone(), deadline)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000;

    #[test]
    fn the_schedule_is_one_two_five_then_fifteen_minutes() {
        let deadline = 24 * 60 * MIN;
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..6 {
            let next = next_attempt_ms(now, 0, deadline).unwrap();
            waits.push((next - now) / MIN);
            now = next;
        }
        assert_eq!(waits, vec![1, 2, 5, 15, 15, 15]);
    }

    #[test]
    fn the_last_attempt_lands_on_the_deadline_and_then_it_is_final() {
        let deadline = 10 * MIN;
        assert_eq!(next_attempt_ms(9 * MIN, 0, deadline), Some(deadline));
        assert_eq!(next_attempt_ms(deadline, 0, deadline), None);
        assert_eq!(next_attempt_ms(deadline + 1, 0, deadline), None);
    }

    #[test]
    fn a_clock_behind_the_admission_time_starts_the_schedule_from_the_beginning() {
        assert_eq!(next_attempt_ms(0, 5 * MIN, 60 * MIN), Some(MIN));
    }
}
