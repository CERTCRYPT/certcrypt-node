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

//! Wire-format type for `operator.domain-binding/1` — an optional, mutual
//! declaration between a node's operator key and an HTTPS origin.
//!
//! The operator key signs a statement naming a host name; the origin publishes
//! it at `https://<domain_ascii>/.well-known/certcrypt-node.json`. Anyone holding
//! the operator identifier can check that both declare each other.
//!
//! Claims boundary: the binding associates a key with an origin. It is not
//! identity proofing, endorsement or certification of an operator, and it is
//! never part of an independence proof or of its verification.
//!
//! This module fixes the bytes: the member set, the signed payload, the signed
//! message (with its domain-separation prefix), the statement digest, and the
//! canonical form of the host name. Signature verification needs an ML-DSA-65
//! implementation and lives with the caller.

use crate::canonical::canonicalize;
use crate::errors::ArtifactError;
use crate::operator_recognition::{derive_operator_id, OPERATOR_KEY_ALG_ACTIVE};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const DOMAIN_BINDING_ARTIFACT_TYPE: &str = "operator.domain-binding/1";
/// Domain-separation prefix of the signed message (`operator.recognition/1` §10).
pub const DOMAIN_BINDING_SIGNING_PREFIX: &str = "certcrypt:operator-domain-binding:1|";
/// The only binding method `/1` admits.
pub const DOMAIN_BINDING_METHOD_HTTPS_WELL_KNOWN: &str = "https-well-known";
/// Path of the published resource on the bound origin.
pub const WELL_KNOWN_PATH: &str = "/.well-known/certcrypt-node.json";
/// Body limit of the published resource, after any content decoding.
pub const WELL_KNOWN_MAX_BYTES: usize = 65_536;
/// Maximum number of statements in the published resource.
pub const WELL_KNOWN_MAX_ENTRIES: usize = 8;
/// Maximum validity of a `bind` statement.
pub const BIND_MAX_VALIDITY_DAYS: i64 = 90;
/// Tolerance for an `issued_at` in the future.
pub const ISSUED_AT_FUTURE_TOLERANCE_SECONDS: i64 = 300;
/// Largest sequence number (2^53 − 1), so every JSON implementation agrees.
pub const SEQUENCE_MAX: u64 = 9_007_199_254_740_991;

pub const INTENT_BIND: &str = "bind";
pub const INTENT_UNBIND: &str = "unbind";

/// Top-level names that never resolve in the public DNS. A binding to a name
/// under one of them could not be checked by anyone outside the operator's own
/// network, and fetching it would reach private infrastructure.
/// localhost (RFC 6761 §6.3), local (RFC 6762), home.arpa (RFC 8375) and the
/// rest of arpa, invalid (RFC 6761 §6.4), test (RFC 6761 §6.2), onion
/// (RFC 7686), alt (RFC 9476), and the top-level name ICANN reserved for
/// private networks.
const NON_PUBLIC_TLDS: &[&str] = &[
    "localhost",
    "local",
    "arpa",
    "invalid",
    "test",
    "onion",
    "alt",
    "internal",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorDomainBindingV1 {
    pub artifact_type: String,
    pub intent: String,
    pub domain_binding_method: String,
    pub operator_id: String,
    /// Standard base64 (with padding) of the 1952-byte ML-DSA-65 public key.
    pub operator_public_key: String,
    pub domain_ascii: String,
    /// Decimal string, no leading zeros, 1..=SEQUENCE_MAX.
    pub sequence: String,
    /// RFC 3339 UTC, whole seconds (`YYYY-MM-DDTHH:MM:SSZ`).
    pub issued_at: String,
    pub valid_until: String,
    pub signature_alg: String,
    pub signature_b64: String,
}

/// The statement without its signature: what JCS canonicalizes into the
/// signed payload.
#[derive(Debug, Clone, Serialize)]
struct OperatorDomainBindingV1NoSig<'a> {
    artifact_type: &'a str,
    intent: &'a str,
    domain_binding_method: &'a str,
    operator_id: &'a str,
    operator_public_key: &'a str,
    domain_ascii: &'a str,
    sequence: &'a str,
    issued_at: &'a str,
    valid_until: &'a str,
}

/// Inputs to build an unsigned statement (the node fills these, then signs).
#[derive(Debug, Clone)]
pub struct DomainBindingInputs {
    pub intent: String,
    pub operator_public_key_b64: String,
    /// Any host name the operator typed; normalised with `normalize_domain`.
    pub domain: String,
    pub sequence: u64,
    pub issued_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// The published resource at `WELL_KNOWN_PATH`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WellKnownBindings {
    pub bindings: Vec<OperatorDomainBindingV1>,
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ArtifactError {
    ArtifactError::InvalidField {
        field,
        reason: reason.into(),
    }
}

/// RFC 3339 UTC with whole seconds, exactly as the statement carries it.
pub fn format_instant(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Parse an instant carried by a statement; refuses any other spelling.
pub fn parse_instant(field: &'static str, s: &str) -> Result<DateTime<Utc>, ArtifactError> {
    let t = DateTime::parse_from_rfc3339(s)
        .map_err(|e| invalid(field, format!("not RFC 3339: {e}")))?
        .with_timezone(&Utc);
    if format_instant(&t) != s {
        return Err(invalid(
            field,
            "must be UTC with whole seconds (YYYY-MM-DDTHH:MM:SSZ)",
        ));
    }
    Ok(t)
}

/// Parse a sequence number; refuses leading zeros, signs and out-of-range values.
pub fn parse_sequence(s: &str) -> Result<u64, ArtifactError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(invalid(
            "sequence",
            "must be a decimal string without leading zeros",
        ));
    }
    let n: u64 = s.parse().map_err(|_| invalid("sequence", "out of range"))?;
    if n == 0 || n > SEQUENCE_MAX {
        return Err(invalid("sequence", "must be between 1 and 2^53 - 1"));
    }
    Ok(n)
}

/// Canonical host name of a binding: IDNA (UTS #46, non-transitional, strict
/// STD3 rules, DNS length checks) to the ASCII form, lowercase, no trailing
/// dot; refuses IP literals, wildcards, single-label names and names under a
/// top-level name that never resolves publicly. The node runs this on what the
/// operator typed; a consumer checks that the carried value is already its own
/// canonical form (`validate_domain_ascii`). Whether the name is itself a
/// public suffix is checked by the consumer against the Public Suffix List.
pub fn normalize_domain(input: &str) -> Result<String, ArtifactError> {
    let trimmed = input.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(invalid("domain_ascii", "empty"));
    }
    if trimmed.contains('*') || trimmed.contains('_') {
        return Err(invalid(
            "domain_ascii",
            "wildcards and underscores are not allowed",
        ));
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok() || trimmed.starts_with('[') {
        return Err(invalid("domain_ascii", "IP literals are not allowed"));
    }
    let ascii = idna::domain_to_ascii_strict(trimmed)
        .map_err(|_| invalid("domain_ascii", "not a valid internationalized host name"))?;
    let ascii = ascii.to_ascii_lowercase();
    if ascii.len() > 253 {
        return Err(invalid("domain_ascii", "longer than 253 octets"));
    }
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 {
        return Err(invalid(
            "domain_ascii",
            "a fully qualified host name is required",
        ));
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid(
                "domain_ascii",
                "every label must be 1 to 63 octets",
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(invalid(
                "domain_ascii",
                "labels are letters, digits and inner hyphens",
            ));
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(
            "domain_ascii",
            "an all-numeric top-level label looks like an address",
        ));
    }
    if NON_PUBLIC_TLDS.contains(&tld) {
        return Err(invalid(
            "domain_ascii",
            "names under this top-level name never resolve publicly",
        ));
    }
    Ok(ascii)
}

/// A carried `domain_ascii` must already be its own canonical form.
pub fn validate_domain_ascii(domain_ascii: &str) -> Result<(), ArtifactError> {
    let canonical = normalize_domain(domain_ascii)?;
    if canonical != domain_ascii {
        return Err(invalid("domain_ascii", "not in canonical A-label form"));
    }
    Ok(())
}

impl OperatorDomainBindingV1 {
    /// Build the unsigned statement (signature fields empty).
    pub fn unsigned(inputs: &DomainBindingInputs) -> Result<Self, ArtifactError> {
        let pk = B64
            .decode(inputs.operator_public_key_b64.as_bytes())
            .map_err(|e| invalid("operator_public_key", format!("base64: {e}")))?;
        let s = Self {
            artifact_type: DOMAIN_BINDING_ARTIFACT_TYPE.into(),
            intent: inputs.intent.clone(),
            domain_binding_method: DOMAIN_BINDING_METHOD_HTTPS_WELL_KNOWN.into(),
            operator_id: derive_operator_id(&pk),
            operator_public_key: inputs.operator_public_key_b64.clone(),
            domain_ascii: normalize_domain(&inputs.domain)?,
            sequence: inputs.sequence.to_string(),
            issued_at: format_instant(&inputs.issued_at),
            valid_until: format_instant(&inputs.valid_until),
            signature_alg: OPERATOR_KEY_ALG_ACTIVE.into(),
            signature_b64: String::new(),
        };
        parse_sequence(&s.sequence)?;
        Ok(s)
    }

    /// `JCS(statement − {signature_alg, signature_b64})`.
    pub fn signed_payload_jcs(&self) -> Result<Vec<u8>, ArtifactError> {
        canonicalize(&OperatorDomainBindingV1NoSig {
            artifact_type: &self.artifact_type,
            intent: &self.intent,
            domain_binding_method: &self.domain_binding_method,
            operator_id: &self.operator_id,
            operator_public_key: &self.operator_public_key,
            domain_ascii: &self.domain_ascii,
            sequence: &self.sequence,
            issued_at: &self.issued_at,
            valid_until: &self.valid_until,
        })
    }

    /// `"certcrypt:operator-domain-binding:1|" || signed_payload_jcs` — the
    /// bytes the operator key signs.
    pub fn signing_message(&self) -> Result<Vec<u8>, ArtifactError> {
        let mut msg = DOMAIN_BINDING_SIGNING_PREFIX.as_bytes().to_vec();
        msg.extend_from_slice(&self.signed_payload_jcs()?);
        Ok(msg)
    }

    /// SHA3-256 of the signed payload: the statement's identity with sequence.
    pub fn statement_digest(&self) -> Result<[u8; 32], ArtifactError> {
        Ok(Sha3_256::digest(self.signed_payload_jcs()?).into())
    }

    /// The canonical statement, signature included.
    pub fn artifact_jcs(&self) -> Result<Vec<u8>, ArtifactError> {
        canonicalize(self)
    }

    /// Every check of `operator.domain-binding/1` §4–§7.1 that needs no
    /// signature verification and no state: member values, `operator_id`
    /// derived from `operator_public_key`, canonical host name, sequence and
    /// instants, the bind validity limit and the future tolerance at `now`.
    pub fn validate_structure(&self, now: DateTime<Utc>) -> Result<(), ArtifactError> {
        if self.artifact_type != DOMAIN_BINDING_ARTIFACT_TYPE {
            return Err(invalid(
                "artifact_type",
                format!("expected {DOMAIN_BINDING_ARTIFACT_TYPE:?}"),
            ));
        }
        if self.intent != INTENT_BIND && self.intent != INTENT_UNBIND {
            return Err(invalid("intent", "must be \"bind\" or \"unbind\""));
        }
        if self.domain_binding_method != DOMAIN_BINDING_METHOD_HTTPS_WELL_KNOWN {
            return Err(invalid(
                "domain_binding_method",
                "only \"https-well-known\" is admitted",
            ));
        }
        if self.signature_alg != OPERATOR_KEY_ALG_ACTIVE {
            return Err(invalid(
                "signature_alg",
                format!("expected {OPERATOR_KEY_ALG_ACTIVE:?}"),
            ));
        }
        let pk = B64
            .decode(self.operator_public_key.as_bytes())
            .map_err(|e| invalid("operator_public_key", format!("base64: {e}")))?;
        if derive_operator_id(&pk) != self.operator_id {
            return Err(invalid(
                "operator_id",
                "does not derive from operator_public_key",
            ));
        }
        if self.signature_b64.is_empty() || B64.decode(self.signature_b64.as_bytes()).is_err() {
            return Err(invalid("signature_b64", "missing or not standard base64"));
        }
        validate_domain_ascii(&self.domain_ascii)?;
        parse_sequence(&self.sequence)?;
        let issued = parse_instant("issued_at", &self.issued_at)?;
        let until = parse_instant("valid_until", &self.valid_until)?;
        if issued >= until {
            return Err(invalid("valid_until", "must be later than issued_at"));
        }
        if issued > now + Duration::seconds(ISSUED_AT_FUTURE_TOLERANCE_SECONDS) {
            return Err(invalid("issued_at", "too far in the future"));
        }
        if self.intent == INTENT_BIND && until > issued + Duration::days(BIND_MAX_VALIDITY_DAYS) {
            return Err(invalid(
                "valid_until",
                "a bind is valid for at most 90 days",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn inputs() -> DomainBindingInputs {
        DomainBindingInputs {
            intent: INTENT_BIND.into(),
            operator_public_key_b64: B64.encode(vec![7u8; 1952]),
            domain: "Nodes.Example.ORG.".into(),
            sequence: 7,
            issued_at: Utc.with_ymd_and_hms(2026, 11, 18, 10, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2027, 2, 16, 10, 0, 0).unwrap(),
        }
    }

    #[test]
    fn unsigned_normalises_and_derives() {
        let s = OperatorDomainBindingV1::unsigned(&inputs()).unwrap();
        assert_eq!(s.domain_ascii, "nodes.example.org");
        assert_eq!(s.sequence, "7");
        assert_eq!(s.issued_at, "2026-11-18T10:00:00Z");
        assert!(s.operator_id.starts_with("op:") && s.operator_id.len() == 25);
    }

    #[test]
    fn signed_payload_excludes_signature_and_message_carries_prefix() {
        let mut s = OperatorDomainBindingV1::unsigned(&inputs()).unwrap();
        let before = s.signed_payload_jcs().unwrap();
        s.signature_b64 = B64.encode([1u8; 8]);
        assert_eq!(
            before,
            s.signed_payload_jcs().unwrap(),
            "signature is not part of the payload"
        );
        let payload = String::from_utf8(before.clone()).unwrap();
        assert!(!payload.contains("signature"));
        assert!(payload.starts_with("{\"artifact_type\":\"operator.domain-binding/1\""));
        let msg = s.signing_message().unwrap();
        assert!(msg.starts_with(DOMAIN_BINDING_SIGNING_PREFIX.as_bytes()));
        assert_eq!(&msg[DOMAIN_BINDING_SIGNING_PREFIX.len()..], &before[..]);
        assert_eq!(
            s.statement_digest().unwrap(),
            <[u8; 32]>::from(Sha3_256::digest(&before))
        );
    }

    #[test]
    fn prefix_does_not_collide_with_other_operator_key_contexts() {
        for other in [
            "certcrypt:read:2|",
            "certcrypt:node-link-request:1|",
            "certcrypt:node-link-claim:1|",
            "certcrypt:activate:1|",
        ] {
            assert!(
                !DOMAIN_BINDING_SIGNING_PREFIX.starts_with(other)
                    && !other.starts_with(DOMAIN_BINDING_SIGNING_PREFIX)
            );
        }
        assert!(
            !DOMAIN_BINDING_SIGNING_PREFIX.starts_with('{'),
            "a receipt is JCS and starts with an opening brace"
        );
        assert!(
            DOMAIN_BINDING_SIGNING_PREFIX.contains(':'),
            "a submit message starts with a ULID, which has no ':'"
        );
    }

    #[test]
    fn structure_checks() {
        let now = Utc.with_ymd_and_hms(2026, 11, 18, 10, 1, 0).unwrap();
        let mut s = OperatorDomainBindingV1::unsigned(&inputs()).unwrap();
        s.signature_b64 = B64.encode([1u8; 8]);
        s.validate_structure(now).unwrap();

        let mut t = s.clone();
        t.valid_until = "2027-02-17T10:00:00Z".into();
        assert!(t.validate_structure(now).is_err(), "over 90 days");
        let mut t = s.clone();
        t.intent = INTENT_UNBIND.into();
        t.valid_until = "2027-02-17T10:00:00Z".into();
        t.validate_structure(now).unwrap();
        let mut t = s.clone();
        t.sequence = "07".into();
        assert!(t.validate_structure(now).is_err(), "leading zero");
        let mut t = s.clone();
        t.sequence = "9007199254740992".into();
        assert!(t.validate_structure(now).is_err(), "above 2^53-1");
        let mut t = s.clone();
        t.issued_at = "2026-11-18T10:00:00.000Z".into();
        assert!(t.validate_structure(now).is_err(), "fractional seconds");
        let mut t = s.clone();
        t.domain_ascii = "Nodes.example.org".into();
        assert!(t.validate_structure(now).is_err(), "not canonical");
        let mut t = s.clone();
        t.operator_id = "op:AAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(
            t.validate_structure(now).is_err(),
            "operator_id not derived"
        );
        let mut t = s.clone();
        t.domain_binding_method = "dns-txt-dnssec".into();
        assert!(t.validate_structure(now).is_err(), "method reserved");
        let early = Utc.with_ymd_and_hms(2026, 11, 18, 9, 50, 0).unwrap();
        assert!(
            s.validate_structure(early).is_err(),
            "issued_at beyond the future tolerance"
        );
    }

    #[test]
    fn host_names() {
        assert_eq!(
            normalize_domain("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            normalize_domain("NODES.example.org.").unwrap(),
            "nodes.example.org"
        );
        // Every top-level name that never resolves publicly, generated from the
        // list itself so no such host name is spelled out here.
        for tld in NON_PUBLIC_TLDS {
            let name = format!("node.{tld}");
            assert!(normalize_domain(&name).is_err(), "{name:?} must be refused");
        }
        let private_v4 = std::net::Ipv4Addr::new(10, 1, 2, 3).to_string();
        let loopback_v6 = format!("[{}]", std::net::Ipv6Addr::LOCALHOST);
        for bad in [
            "",
            "localhost",
            "example",
            "a.123",
            "-a.example.org",
            "a..example.org",
            "*.example.org",
            "_srv.example.org",
            private_v4.as_str(),
            loopback_v6.as_str(),
        ] {
            assert!(normalize_domain(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(validate_domain_ascii("xn--bcher-kva.example").is_ok());
        assert!(
            validate_domain_ascii("bücher.example").is_err(),
            "U-label is not the carried form"
        );
    }

    #[test]
    fn unknown_members_are_refused() {
        let s = OperatorDomainBindingV1::unsigned(&inputs()).unwrap();
        let mut v = serde_json::to_value(&s).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<OperatorDomainBindingV1>(v).is_err());
    }
}
