// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// <https://www.apache.org/licenses/LICENSE-2.0>
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************

//! Dummy library used by the SBOM smoke test.
//!
//! It exists purely so that the SBOM generator has a Rust target with real
//! external crate dependencies to traverse.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A greeting rendered as JSON.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Greeting {
    pub greeting: String,
    pub language: String,
}

impl Greeting {
    /// Builds a greeting for `name`.
    pub fn new(name: &str) -> Self {
        Self {
            greeting: format!("Hello, {name}!"),
            language: "rust".to_owned(),
        }
    }
}

/// Renders the greeting for `name` as a JSON document.
pub fn greet(name: &str) -> Result<String> {
    Ok(serde_json::to_string(&Greeting::new(name))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greet_renders_json() {
        assert_eq!(
            greet("SBOM").unwrap(),
            r#"{"greeting":"Hello, SBOM!","language":"rust"}"#
        );
    }

    #[test]
    fn greeting_round_trips() {
        let original = Greeting::new("SBOM");
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: Greeting = serde_json::from_str(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
