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

//! The OpenAPI document (`openapi/node.openapi.yaml`) must describe exactly the
//! routes the router mounts.
//!
//! An axum `Router` cannot be introspected, so the router side is read from the
//! source: every `.route("<path>", <method>(..)[.<method>(..)])` call in
//! `src/http.rs`, with `:param` rewritten to `{param}`. The document side is the
//! `paths` mapping of the YAML, read with a small indentation-based reader (the
//! document keeps `paths` as a plain block mapping, which is all this needs).
//!
//! On mismatch the failure lists every (METHOD, path) pair missing on each side.

use std::collections::BTreeSet;
use std::path::PathBuf;

const HTTP_METHODS: [&str; 8] = [
    "get", "post", "put", "delete", "patch", "head", "options", "trace",
];

type Route = (String, String);

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Blank out `//` comments (outside string literals) so a commented-out route
/// is not counted. Byte offsets are preserved.
fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_str = false;
    let mut in_comment = false;
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
                out.push(c);
            } else {
                out.push(' ');
            }
            continue;
        }
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                in_comment = true;
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

/// `:param` / `*param` (axum 0.7 captures) → `{param}` (OpenAPI templating).
fn axum_path_to_openapi(path: &str) -> String {
    path.split('/')
        .map(
            |seg| match seg.strip_prefix(':').or_else(|| seg.strip_prefix('*')) {
                Some(name) => format!("{{{name}}}"),
                None => seg.to_string(),
            },
        )
        .collect::<Vec<_>>()
        .join("/")
}

fn router_routes() -> BTreeSet<Route> {
    let path = crate_dir().join("src/http.rs");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    // Unit tests at the bottom of the file are not part of the router.
    let raw = raw.split("#[cfg(test)]").next().unwrap_or(&raw);
    let src = strip_line_comments(raw);

    let mut routes = BTreeSet::new();
    let mut rest = src.as_str();
    while let Some(pos) = rest.find(".route(") {
        let after = &rest[pos + ".route(".len()..];
        // The call's argument list, up to its balanced closing paren.
        let mut depth = 1usize;
        let mut end = None;
        for (i, c) in after.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("unbalanced .route( call in src/http.rs");
        let args = &after[..end];

        let q1 = args.find('"').expect(".route( call without a path literal");
        let q2 = q1 + 1 + args[q1 + 1..].find('"').expect("unterminated path literal");
        let route_path = axum_path_to_openapi(&args[q1 + 1..q2]);

        // Method routers after the literal: `get(h)`, `post(h)`, `get(a).post(b)`.
        let handlers = &args[q2 + 1..];
        let mut found = false;
        for m in HTTP_METHODS {
            let needle = format!("{m}(");
            let mut search = handlers;
            while let Some(i) = search.find(&needle) {
                let prev = handlers[..handlers.len() - search.len() + i]
                    .chars()
                    .next_back();
                let is_ident_boundary =
                    !matches!(prev, Some(c) if c.is_ascii_alphanumeric() || c == '_');
                if is_ident_boundary {
                    routes.insert((m.to_uppercase(), route_path.clone()));
                    found = true;
                }
                search = &search[i + needle.len()..];
            }
        }
        assert!(
            found,
            "could not find a method router in .route({})",
            args.trim()
        );
        rest = &after[end..];
    }
    routes
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// A block-mapping key on this line, without quotes; `None` for anything else.
fn mapping_key(line: &str) -> Option<String> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with('-') {
        return None;
    }
    let colon = if t.starts_with('\'') || t.starts_with('"') {
        let q = t.chars().next()?;
        let close = t[1..].find(q)? + 1;
        close + t[close..].find(':')?
    } else {
        t.find(':')?
    };
    let key = t[..colon].trim().trim_matches(|c| c == '\'' || c == '"');
    Some(key.to_string())
}

fn openapi_routes() -> BTreeSet<Route> {
    let path = crate_dir().join("../../openapi/node.openapi.yaml");
    let doc =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let mut routes = BTreeSet::new();
    let mut in_paths = false;
    let mut path_indent: Option<usize> = None;
    let mut method_indent: Option<usize> = None;
    let mut current: Option<String> = None;
    let mut saw_paths = false;

    for line in doc.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let ind = indent_of(line);
        if ind == 0 {
            in_paths = t == "paths:";
            saw_paths |= in_paths;
            continue;
        }
        if !in_paths {
            continue;
        }
        let pi = *path_indent.get_or_insert(ind);
        if ind < pi {
            panic!("unexpected dedent inside `paths`: {line:?}");
        }
        if ind == pi {
            let key = mapping_key(line).unwrap_or_else(|| panic!("bad path key: {line:?}"));
            assert!(
                key.starts_with('/'),
                "path key must start with '/': {key:?}"
            );
            current = Some(key);
            method_indent = None;
            continue;
        }
        let mi = *method_indent.get_or_insert(ind);
        if ind == mi {
            if let (Some(key), Some(p)) = (mapping_key(line), current.as_ref()) {
                if HTTP_METHODS.contains(&key.as_str()) {
                    routes.insert((key.to_uppercase(), p.clone()));
                }
            }
        }
    }
    assert!(saw_paths, "no top-level `paths:` in {}", path.display());
    routes
}

#[test]
fn openapi_document_matches_router_routes() {
    let router = router_routes();
    let documented = openapi_routes();
    assert!(!router.is_empty(), "parsed no routes from src/http.rs");

    let fmt = |set: Vec<&Route>| {
        if set.is_empty() {
            "  (none)".to_string()
        } else {
            set.iter()
                .map(|(m, p)| format!("  {m} {p}"))
                .collect::<Vec<_>>()
                .join("\n")
        }
    };
    let undocumented: Vec<&Route> = router.difference(&documented).collect();
    let unrouted: Vec<&Route> = documented.difference(&router).collect();
    assert!(
        undocumented.is_empty() && unrouted.is_empty(),
        "openapi/node.openapi.yaml is out of sync with the router in src/http.rs\n\
         In the router but missing from the OpenAPI document:\n{}\n\
         In the OpenAPI document but not mounted by the router:\n{}",
        fmt(undocumented),
        fmt(unrouted),
    );
}

#[test]
fn route_parser_handles_params_and_multiline_calls() {
    assert_eq!(
        axum_path_to_openapi("/v1/outbox/dead/:request_id/redrive"),
        "/v1/outbox/dead/{request_id}/redrive"
    );
    let input = "a // .route(\"/x\", get(h))\nb \"//keep\"";
    let stripped = strip_line_comments(input);
    assert_eq!(stripped.len(), input.len());
    assert!(!stripped.contains(".route("));
    assert!(stripped.ends_with("b \"//keep\""));
}
