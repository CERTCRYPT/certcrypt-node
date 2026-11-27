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

//! Writing a submit's outcome into the journal — shared by the `/v1/issue`
//! handler and the outbox relay, so the two cannot drift apart.
//!
//! The rule both follow: **an id the issuer was given is never replaced.** A
//! submit that the issuance service could not answer at once hands the issuer one
//! `accepted_for_retry` record per member. When the relay (or a resubmit)
//! later gets the service's answer, each member's outcome is written OVER that
//! record. Minting fresh ids at that point would leave the issuer polling
//! records that never change, holding ids for the real outcomes it has no way
//! to learn.

use std::collections::HashMap;
use std::sync::Arc;

use certcrypt_node_core::operator_receipt::OperatorReceipt;

use crate::store::{JournalError, JournalStore, OperationRecord, OperationState};
use crate::upstream::MemberStatus;

/// The journal state for one member outcome reported by the issuance service.
pub(crate) fn member_state(status: MemberStatus) -> OperationState {
    match status {
        MemberStatus::Accepted { operation_id } => OperationState::Accepted {
            upstream_operation_id: operation_id,
        },
        MemberStatus::Rejected {
            reason_code,
            message,
        } => OperationState::Rejected {
            reason_code,
            message,
        },
        MemberStatus::ReplayDetected { message } => OperationState::ReplayDetected { message },
        MemberStatus::Unknown => {
            OperationState::submission_failed("upstream returned an unrecognized member status")
        }
    }
}

/// One member outcome to record.
pub(crate) struct MemberOutcome {
    pub commitment_index: usize,
    pub state: OperationState,
}

/// One member as recorded: the id the issuer polls.
#[derive(Debug, Clone)]
pub(crate) struct RecordedMember {
    pub operation_id: String,
    pub commitment_index: usize,
    pub state: OperationState,
}

/// Record each member's outcome for `request_id`, reusing the id of any
/// record this request already holds for the same `commitment_index`. A
/// member with no such record gets a fresh id. `receipt` replaces the stored
/// receipt only when present.
pub(crate) async fn record_members(
    store: &Arc<dyn JournalStore>,
    contract_id: &str,
    request_id: &str,
    submission_set_id: &str,
    members: Vec<MemberOutcome>,
    receipt: Option<OperatorReceipt>,
) -> Result<Vec<RecordedMember>, JournalError> {
    let existing = existing_by_index(store, contract_id, request_id).await?;
    let mut out = Vec::with_capacity(members.len());
    for m in members {
        let previous = existing.get(&m.commitment_index);
        let operation_id = previous
            .map(|r| r.operation_id.clone())
            .unwrap_or_else(|| format!("op_{}", ulid::Ulid::new()));
        let record = OperationRecord {
            operation_id: operation_id.clone(),
            contract_id: contract_id.to_string(),
            request_id: request_id.to_string(),
            submission_set_id: Some(submission_set_id.to_string()),
            commitment_index: Some(m.commitment_index),
            state: m.state.clone(),
            operator_receipt: receipt
                .clone()
                .or_else(|| previous.and_then(|r| r.operator_receipt.clone())),
        };
        let s = store.clone();
        crate::blocking::store_call(move || s.put(record))
            .await
            .unwrap_or_else(|e| {
                Err(JournalError::Backend(format!(
                    "journal call did not complete: {e}"
                )))
            })?;
        out.push(RecordedMember {
            operation_id,
            commitment_index: m.commitment_index,
            state: m.state,
        });
    }
    Ok(out)
}

/// Give each of the `members` of a submit that could not be answered yet an
/// `accepted_for_retry` record, so the issuer holds the ids the eventual
/// outcomes will be written to. A member that already has a record (an earlier
/// attempt of the same request) keeps it untouched — in particular one that
/// already holds a real outcome is never turned back into "waiting".
pub(crate) async fn record_waiting(
    store: &Arc<dyn JournalStore>,
    contract_id: &str,
    request_id: &str,
    submission_set_id: &str,
    members: usize,
    waiting: &OperationState,
    receipt: Option<OperatorReceipt>,
) -> Result<Vec<RecordedMember>, JournalError> {
    let existing = existing_by_index(store, contract_id, request_id).await?;
    let mut out = Vec::with_capacity(members);
    let mut missing = Vec::new();
    for i in 0..members {
        match existing.get(&i) {
            Some(r) => out.push(RecordedMember {
                operation_id: r.operation_id.clone(),
                commitment_index: i,
                state: r.state.clone(),
            }),
            None => missing.push(MemberOutcome {
                commitment_index: i,
                state: waiting.clone(),
            }),
        }
    }
    out.extend(
        record_members(
            store,
            contract_id,
            request_id,
            submission_set_id,
            missing,
            receipt,
        )
        .await?,
    );
    out.sort_by_key(|m| m.commitment_index);
    Ok(out)
}

/// Write a whole-request outcome (the service answered without evaluating any
/// member) over every record of `request_id` that is still waiting on
/// delivery. Records already holding a real outcome are left alone.
pub(crate) async fn settle_waiting_records(
    store: &Arc<dyn JournalStore>,
    contract_id: &str,
    request_id: &str,
    state: OperationState,
) -> Result<(), JournalError> {
    let s = store.clone();
    let (c, r) = (contract_id.to_string(), request_id.to_string());
    let records = crate::blocking::store_call(move || s.list_by_request(&c, &r))
        .await
        .unwrap_or_else(|e| {
            Err(JournalError::Backend(format!(
                "journal call did not complete: {e}"
            )))
        })?;
    for mut record in records {
        if !matches!(record.state, OperationState::AcceptedForRetry { .. }) {
            continue;
        }
        record.state = state.clone();
        let s = store.clone();
        crate::blocking::store_call(move || s.put(record))
            .await
            .unwrap_or_else(|e| {
                Err(JournalError::Backend(format!(
                    "journal call did not complete: {e}"
                )))
            })?;
    }
    Ok(())
}

async fn existing_by_index(
    store: &Arc<dyn JournalStore>,
    contract_id: &str,
    request_id: &str,
) -> Result<HashMap<usize, OperationRecord>, JournalError> {
    let s = store.clone();
    let (c, r) = (contract_id.to_string(), request_id.to_string());
    let records = crate::blocking::store_call(move || s.list_by_request(&c, &r))
        .await
        .unwrap_or_else(|e| {
            Err(JournalError::Backend(format!(
                "journal call did not complete: {e}"
            )))
        })?;
    Ok(records
        .into_iter()
        .filter_map(|r| r.commitment_index.map(|i| (i, r)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryJournal;

    fn retry() -> OperationState {
        OperationState::AcceptedForRetry {
            error: "down".into(),
            capacity: None,
        }
    }

    #[tokio::test]
    async fn a_delayed_answer_lands_on_the_ids_the_issuer_already_holds() {
        let store: Arc<dyn JournalStore> = Arc::new(MemoryJournal::new());
        let first = record_members(
            &store,
            "c:A",
            "req-1",
            "set-1",
            (0..3)
                .map(|i| MemberOutcome {
                    commitment_index: i,
                    state: retry(),
                })
                .collect(),
            None,
        )
        .await
        .unwrap();

        let later = record_members(
            &store,
            "c:A",
            "req-1",
            "set-1",
            (0..3)
                .map(|i| MemberOutcome {
                    commitment_index: i,
                    state: OperationState::Accepted {
                        upstream_operation_id: format!("UP-{i}"),
                    },
                })
                .collect(),
            None,
        )
        .await
        .unwrap();

        for (a, b) in first.iter().zip(later.iter()) {
            assert_eq!(a.operation_id, b.operation_id, "same id, new outcome");
        }
        assert_eq!(store.list_scoped("c:A").unwrap().len(), 3, "no new records");
        let got = store
            .get_scoped("c:A", &first[1].operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            got.state,
            OperationState::Accepted {
                upstream_operation_id: "UP-1".into()
            }
        );
    }

    #[tokio::test]
    async fn waiting_never_overwrites_a_real_outcome() {
        let store: Arc<dyn JournalStore> = Arc::new(MemoryJournal::new());
        let accepted = OperationState::Accepted {
            upstream_operation_id: "UP-0".into(),
        };
        let first = record_members(
            &store,
            "c:A",
            "req-1",
            "set-1",
            vec![MemberOutcome {
                commitment_index: 0,
                state: accepted.clone(),
            }],
            None,
        )
        .await
        .unwrap();
        // A resubmit of the same request whose answer was lost in transit.
        let waiting = record_waiting(&store, "c:A", "req-1", "set-1", 2, &retry(), None)
            .await
            .unwrap();
        assert_eq!(waiting.len(), 2);
        assert_eq!(waiting[0].operation_id, first[0].operation_id);
        assert_eq!(waiting[0].state, accepted, "the real outcome stays");
        assert_eq!(waiting[1].state, retry());
    }

    #[tokio::test]
    async fn another_scope_never_shares_ids() {
        let store: Arc<dyn JournalStore> = Arc::new(MemoryJournal::new());
        let a = record_members(
            &store,
            "c:A",
            "req-1",
            "set-1",
            vec![MemberOutcome {
                commitment_index: 0,
                state: retry(),
            }],
            None,
        )
        .await
        .unwrap();
        let b = record_members(
            &store,
            "c:B",
            "req-1",
            "set-1",
            vec![MemberOutcome {
                commitment_index: 0,
                state: retry(),
            }],
            None,
        )
        .await
        .unwrap();
        assert_ne!(a[0].operation_id, b[0].operation_id);
    }

    #[tokio::test]
    async fn a_whole_request_answer_settles_only_waiting_records() {
        let store: Arc<dyn JournalStore> = Arc::new(MemoryJournal::new());
        let recorded = record_members(
            &store,
            "c:A",
            "req-1",
            "set-1",
            vec![
                MemberOutcome {
                    commitment_index: 0,
                    state: retry(),
                },
                MemberOutcome {
                    commitment_index: 1,
                    state: OperationState::InsufficientCapacity { capacity: None },
                },
            ],
            None,
        )
        .await
        .unwrap();
        let rejected = OperationState::PreEvaluationRejected {
            reason_code: "idempotency_conflict".into(),
            message: "m".into(),
        };
        settle_waiting_records(&store, "c:A", "req-1", rejected.clone())
            .await
            .unwrap();
        let r0 = store
            .get_scoped("c:A", &recorded[0].operation_id)
            .unwrap()
            .unwrap();
        let r1 = store
            .get_scoped("c:A", &recorded[1].operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(r0.state, rejected);
        assert_eq!(
            r1.state,
            OperationState::InsufficientCapacity { capacity: None },
            "left alone"
        );
    }
}
