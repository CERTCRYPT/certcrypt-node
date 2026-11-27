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

//! The examples in `openapi/node.openapi.yaml` are part of the contract: the
//! published HTTP reference turns them into runnable requests and sample
//! responses. Two checks keep them honest:
//!
//! - every example (request and response bodies, parameters, and the
//!   `example`/`examples` inside schemas) is valid against the schema it
//!   illustrates, validated as JSON Schema 2020-12 (the dialect of OpenAPI 3.1)
//!   with every `$ref` resolved inside the document;
//! - every operation carries a complete set: an example for each required
//!   parameter, for its JSON request body, and for its success response.

use std::path::PathBuf;

use serde_json::{json, Map, Value};

const HTTP_METHODS: [&str; 8] = [
    "get", "post", "put", "delete", "patch", "head", "options", "trace",
];

fn document() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../openapi/node.openapi.yaml");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yaml_ng::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn resolve<'a>(doc: &'a Value, value: &'a Value) -> &'a Value {
    let mut v = value;
    while let Some(r) = v.get("$ref").and_then(Value::as_str) {
        let pointer = r
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("only local $refs are supported: {r}"));
        v = doc
            .pointer(pointer)
            .unwrap_or_else(|| panic!("dangling $ref {r}"));
    }
    v
}

/// Every violation of `instance` against `schema`, which may use `$ref`s into
/// the document's `components`.
fn violations(doc: &Value, schema: &Value, instance: &Value) -> Vec<String> {
    let mut root: Map<String, Value> = match schema {
        Value::Object(m) => m.clone(),
        Value::Bool(_) => return Vec::new(),
        other => panic!("schema is not an object: {other}"),
    };
    root.insert("components".into(), doc["components"].clone());
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&Value::Object(root))
        .unwrap_or_else(|e| panic!("the document holds an invalid schema: {e}\n{schema}"));
    validator
        .iter_errors(instance)
        .map(|e| format!("at `{}`: {e}", e.instance_path()))
        .collect()
}

/// `example` and `examples.*.value` of a media type or parameter object.
fn object_examples<'a>(doc: &'a Value, obj: &'a Value) -> Vec<(String, &'a Value)> {
    let mut out = Vec::new();
    if let Some(ex) = obj.get("example") {
        out.push(("example".to_string(), ex));
    }
    if let Some(map) = obj.get("examples").and_then(Value::as_object) {
        for (k, ex) in map {
            if let Some(v) = resolve(doc, ex).get("value") {
                out.push((format!("examples.{k}"), v));
            }
        }
    }
    out
}

/// (label, operation, path-level parameters) for every operation.
fn operations(doc: &Value) -> Vec<(String, &Value, Vec<&Value>)> {
    let mut out = Vec::new();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        let shared: Vec<&Value> = item
            .get("parameters")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        for (method, op) in item.as_object().expect("path item") {
            if HTTP_METHODS.contains(&method.as_str()) {
                out.push((
                    format!("{} {path}", method.to_uppercase()),
                    op,
                    shared.clone(),
                ));
            }
        }
    }
    out
}

#[test]
fn openapi_examples_match_their_schemas() {
    let doc = document();
    let mut failures = Vec::new();
    let mut checked = 0usize;
    let mut check = |at: String, schema: &Value, value: &Value| {
        checked += 1;
        let errors = violations(&doc, schema, value);
        if !errors.is_empty() {
            failures.push(format!("{at}:\n    {}", errors.join("\n    ")));
        }
    };

    for (at, op, shared) in operations(&doc) {
        let own: Vec<&Value> = op
            .get("parameters")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        for p in shared.iter().chain(own.iter()).map(|p| resolve(&doc, p)) {
            for (label, value) in object_examples(&doc, p) {
                check(
                    format!("{at} parameter {} {label}", p["name"]),
                    &p["schema"],
                    value,
                );
            }
        }
        let mut media: Vec<(String, &Value)> = Vec::new();
        if let Some(content) = op
            .get("requestBody")
            .map(|b| resolve(&doc, b))
            .and_then(|b| b.get("content"))
        {
            for (ct, mt) in content.as_object().expect("content") {
                media.push((format!("{at} requestBody {ct}"), mt));
            }
        }
        for (status, resp) in op["responses"].as_object().expect("responses") {
            if let Some(content) = resolve(&doc, resp).get("content") {
                for (ct, mt) in content.as_object().expect("content") {
                    media.push((format!("{at} {status} {ct}"), mt));
                }
            }
        }
        for (where_, mt) in media {
            let Some(schema) = mt.get("schema") else {
                continue;
            };
            for (label, value) in object_examples(&doc, mt) {
                check(format!("{where_} {label}"), schema, value);
            }
        }
    }

    // `example` / `examples` written inside a schema, checked against the
    // schema object that holds them.
    fn walk(at: String, schema: &Value, out: &mut Vec<(String, Value, Value)>) {
        match schema {
            Value::Object(map) => {
                if let Some(ex) = map.get("example") {
                    out.push((at.clone(), schema.clone(), ex.clone()));
                }
                if let Some(Value::Array(list)) = map.get("examples") {
                    for ex in list {
                        out.push((at.clone(), schema.clone(), ex.clone()));
                    }
                }
                for (k, v) in map {
                    if k != "example" && k != "examples" {
                        walk(format!("{at}.{k}"), v, out);
                    }
                }
            }
            Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    walk(format!("{at}[{i}]"), v, out);
                }
            }
            _ => {}
        }
    }
    let mut in_schemas = Vec::new();
    walk(
        "components.schemas".into(),
        &doc["components"]["schemas"],
        &mut in_schemas,
    );
    for (at, schema, value) in &in_schemas {
        check(format!("{at}: {value}"), schema, value);
    }

    assert!(checked > 0, "found no examples in the document");
    assert!(
        failures.is_empty(),
        "{} example(s) in openapi/node.openapi.yaml do not match their schema:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_operation_carries_complete_examples() {
    let doc = document();
    let mut missing = Vec::new();
    let has_example = |v: &Value| v.get("example").is_some() || v.get("examples").is_some();
    for (at, op, shared) in operations(&doc) {
        let own: Vec<&Value> = op
            .get("parameters")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        for p in shared.iter().chain(own.iter()).map(|p| resolve(&doc, p)) {
            // Header proofs are minted per request by an SDK; a fixed example
            // value would be invalid the moment it was read.
            if p["required"] == true && p["in"] != "header" && !has_example(p) {
                missing.push(format!("{at}: parameter {}", p["name"]));
            }
        }
        if let Some(body) = op.get("requestBody").map(|b| resolve(&doc, b)) {
            if !has_example(&body["content"]["application/json"]) {
                missing.push(format!("{at}: request body"));
            }
        }
        let success = op["responses"]
            .as_object()
            .expect("responses")
            .iter()
            .find(|(status, _)| status.starts_with('2'))
            .map(|(_, r)| resolve(&doc, r));
        match success {
            Some(r) if has_example(&r["content"]["application/json"]) => {}
            _ => missing.push(format!("{at}: success response")),
        }
    }
    assert!(
        missing.is_empty(),
        "operations without examples in openapi/node.openapi.yaml:\n  {}",
        missing.join("\n  ")
    );
}

/// The checker itself must refuse: a validator that accepted everything would
/// make both tests above pass over any document.
#[test]
fn the_checker_rejects_an_invalid_example() {
    let doc = document();
    let schema = json!({"$ref": "#/components/schemas/RedriveAccepted"});
    assert!(violations(
        &doc,
        &schema,
        &json!({"request_id": "x", "state": "pending"})
    )
    .is_empty());
    assert!(!violations(&doc, &schema, &json!({"request_id": "x", "state": "done"})).is_empty());
    assert!(!violations(&doc, &schema, &json!({"state": "pending"})).is_empty());
}
