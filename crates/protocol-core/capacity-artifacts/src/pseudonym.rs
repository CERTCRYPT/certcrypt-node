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

//! Operation-scoped pseudonyms.
//!
//! Stable identifiers (`holder_id`, `pool_id`, `authorization_id`, …) are
//! correlators: shipping them in clear to the offline verifier would link all
//! of a holder's certificates and break the `zero-data.unlinkable` profile.
//! Instead, the capacity evidence carries **operation-scoped pseudonyms**:
//!
//! ```text
//! pseudonym(field) := SHA3-256( framed(operation_salt) || framed(domain_tag) || framed(stable_id) )
//! ```
//!
//! Hash: **SHA3-256** (FIPS 202 fixed-output), not SHAKE-256. The output is a
//! fixed 32 bytes, so the XOF buys nothing and carries its prefix hazard (an
//! output is a prefix of every longer output for the same input);
//! SHA3-256 is the conventional fixed-length choice and aligns with CCCP/1 §7.1.
//!
//! Properties:
//! - **Reproducible offline without issuer secrets** — `operation_salt` is
//!   public (travels in the package); the hash is standard SHA3-256.
//! - **Not linkable across operations** — a fresh `operation_salt` per
//!   operation makes the same `holder_id` produce unrelated pseudonyms.
//! - **Not invertible** — SHA3-256 over the id with a public salt does not
//!   reveal the id to an observer who does not already hold it.
//! - **Domain-separated** — `domain_tag` keeps `holder`/`pool`/`authorization`
//!   namespaces from colliding even on equal input values.
//!
//! Pseudonyms do NOT replace signature verification (that is closed by the
//! operation-key tree in `capacity_verify::holder_keyset`); they let the
//! package's internal bindings (commitment ↔ authorization ↔ certificate) be
//! checked without exposing stable ids.

use sha3::{Digest, Sha3_256};

/// Domain tag separating pseudonym namespaces. New tags may be added;
/// never reuse a tag for a different field meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Holder,
    Pool,
    Authorization,
}

impl Domain {
    fn tag(self) -> &'static str {
        match self {
            Domain::Holder => "holder",
            Domain::Pool => "pool",
            Domain::Authorization => "authorization",
        }
    }
}

/// Derive an operation-scoped pseudonym for `stable_id` under `operation_salt`
/// and `domain`. `operation_salt` is the public per-operation salt carried in
/// the package; identical inputs yield an identical pseudonym (so the verifier
/// can recompute bindings), different salts yield unrelated pseudonyms.
///
/// Domain separation is length-prefixed so that concatenation is unambiguous:
/// no choice of `operation_salt` / `stable_id` can forge a collision across
/// domains or across field boundaries.
pub fn derive(operation_salt: &[u8], domain: Domain, stable_id: &str) -> String {
    let mut hasher = Sha3_256::new();
    absorb_framed(&mut hasher, operation_salt);
    absorb_framed(&mut hasher, domain.tag().as_bytes());
    absorb_framed(&mut hasher, stable_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// Absorb a field with an 8-byte big-endian length prefix, so the boundaries
/// between salt / domain / id are unambiguous (prevents `a||b` colliding with
/// `a'||b'`).
fn absorb_framed(hasher: &mut Sha3_256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let salt = b"operation-salt-abc";
        let a = derive(salt, Domain::Holder, "holder:123");
        let b = derive(salt, Domain::Holder, "holder:123");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn different_salt_unlinkable() {
        // Same holder id, different operation → unrelated pseudonyms.
        let a = derive(b"salt-op-1", Domain::Holder, "holder:123");
        let b = derive(b"salt-op-2", Domain::Holder, "holder:123");
        assert_ne!(a, b);
    }

    #[test]
    fn domain_separation() {
        let salt = b"same-salt";
        // Same input value, different domain → different pseudonym.
        let h = derive(salt, Domain::Holder, "x");
        let p = derive(salt, Domain::Pool, "x");
        let a = derive(salt, Domain::Authorization, "x");
        assert_ne!(h, p);
        assert_ne!(h, a);
        assert_ne!(p, a);
    }

    #[test]
    fn framing_prevents_boundary_collision() {
        // Without length-framing, ("ab","c") and ("a","bc") could collide.
        // domain is fixed; vary only the salt/id split.
        let x = derive(b"ab", Domain::Holder, "c");
        let y = derive(b"a", Domain::Holder, "bc");
        assert_ne!(x, y);
    }
}
