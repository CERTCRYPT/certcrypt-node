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

//! `certcrypt-node` — the issuer-side node HTTP server.
//!
//! The issuer application is a client of this node; the node is the only
//! component that talks to the issuance service. This crate wires:
//!
//! - [`http`] — the HTTP surface the issuer client consumes (issue / status).
//! - [`upstream`] — the client that submits closed submission sets upstream.
//! - [`store`] / [`sqlite_journal`] — the operation journal: an in-memory
//!   backend for tests, and embedded SQLite as the durable default.
//! - [`outbox`] — the transactional outbox that makes submission durable across
//!   an issuance-service outage, a restart, or a client that goes away.
//! - [`capacity_wait`] — how long a set refused for `insufficient_capacity` is
//!   kept and submitted again while its commitments are valid.
//! - [`blocking`] — how the SQLite stores are opened ([`StoreOptions`]) and kept
//!   off the async executor.
//! - [`retention`] — how long the stores remember ([`RetentionPolicy`], 30-day
//!   floor) and the background sweep that purges them.
//!
//! Submission-set construction and signing live in [`certcrypt_node_core`]; this crate
//! is the operational shell around it.
//!
//! # Embedding this crate
//!
//! Everything the bundled `certcrypt-node` binary does is available here — the
//! binary has no private configuration path. Build a [`NodeState`], choose your
//! limits, and serve the router:
//!
//! ```no_run
//! use certcrypt_node::{router_with_limits, HttpLimits};
//! # fn example(state: certcrypt_node::NodeState) -> axum::Router {
//! let limits = HttpLimits::default().with_max_concurrent_requests(128);
//! router_with_limits(state, limits)
//! # }
//! ```
//!
//! Configuration is explicit by default. [`HttpLimits::from_env_prefixed`] reads
//! the environment only if you call it, and under whatever variable prefix you
//! pass — this crate claims no global namespace of its own.

pub mod auth;
pub mod background_lock;
pub mod blocking;
pub mod capacity_wait;
pub mod domain_binding;
pub mod http;
mod journaling;
pub mod ops;
pub mod outbox;
pub mod relay;
pub mod retention;
pub mod sqlite_journal;
pub mod store;
pub mod upstream;

pub use auth::{AuthedIssuer, IssuerVerifier};
pub use blocking::{Durability, StoreOptions};
pub use http::{router, router_with_limits, DeploymentRules, HttpLimits, Lifecycle, NodeState};
pub use outbox::{MemoryOutbox, OutboxEntry, OutboxError, OutboxState, OutboxStore, SqliteOutbox};
pub use retention::{RetentionError, RetentionPolicy, RetentionSweeper, MIN_RETENTION};
pub use sqlite_journal::SqliteJournal;
pub use store::{
    JournalError, JournalStore, MemoryJournal, OperationRecord, OperationState, PurgeOutcome,
};
pub use upstream::{
    CapacityShortfall, ClaimNodeLinkResponse, FlatOutcome, MemberOutcome, MemberStatus,
    OpenNodeLinkResponse, SubmissionSetResponse, SubmitResponse, UpstreamClient, UpstreamError,
};
