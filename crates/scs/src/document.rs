// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The SCS JSON documents (DVV SCS specification v1.3).
//!
//! Each document maps to and from a JSON value by hand: unknown fields
//! are ignored on the way in, and encoding emits stable key order
//! through the value map's ordering.

use serde_json::Value;

use crate::purpose::SignPurpose;
use crate::values;

/// Read a required string field.
fn get_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, ()> {
    value.get(key).and_then(Value::as_str).ok_or(())
}

/// Read an optional string field: absent or null is `None`, a
/// present non-string refuses the document.
fn opt_str(value: &Value, key: &str) -> Result<Option<String>, ()> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(()),
    }
}

/// Read an optional boolean field with its default.
fn opt_bool(value: &Value, key: &str, default: bool) -> Result<bool, ()> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(()),
    }
}

/// Read a string array field, empty when absent or null.
fn str_array_or_empty(value: &Value, key: &str) -> Result<Vec<String>, ()> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(()))
            .collect(),
        Some(_) => Err(()),
    }
}

/// Read an optional object field.
fn opt_object<T>(
    value: &Value,
    key: &str,
    decode: fn(&Value) -> Result<T, ()>,
) -> Result<Option<T>, ()> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(object) => decode(object).map(Some),
    }
}

/// Read a string field with its default when absent or null.
fn str_or_default(value: &Value, key: &str, default: &str) -> Result<String, ()> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(default.to_owned()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(()),
    }
}

/// The `/version` response document (v1.3 sec.2.5.2).
///
/// The list-valued fields are comma-separated strings, not JSON
/// arrays -- callers split them client-side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDocument {
    /// Accepted application object identifiers; none are required.
    pub application_oids: String,
    /// Accepted `contentType` values.
    pub content_types: String,
    /// Accepted `hashAlgorithm` values.
    pub hash_algorithms: String,
    /// Accepted request methods.
    pub http_methods: String,
    /// Whether the certificate selector is honoured.
    pub selector_available: bool,
    /// Accepted `signatureAlgorithm` values.
    pub signature_algorithms: String,
    /// Accepted `signatureType` values.
    pub signature_types: String,
    /// The protocol version.
    pub version: String,
}

impl VersionDocument {
    /// The document this service publishes.
    #[must_use]
    pub fn current() -> Self {
        Self {
            application_oids: String::new(),
            content_types: "data,digest".to_owned(),
            hash_algorithms: "SHA256,SHA384,SHA512".to_owned(),
            http_methods: "POST".to_owned(),
            selector_available: true,
            signature_algorithms: "RSA,ECDSA".to_owned(),
            signature_types: "signature,cms-pades".to_owned(),
            version: values::VERSION.to_owned(),
        }
    }

    /// Encode the document.
    #[must_use]
    pub fn encode(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "applicationOIDs".to_owned(),
            Value::String(self.application_oids.clone()),
        );
        map.insert(
            "contentTypes".to_owned(),
            Value::String(self.content_types.clone()),
        );
        map.insert(
            "hashAlgorithms".to_owned(),
            Value::String(self.hash_algorithms.clone()),
        );
        map.insert(
            "httpMethods".to_owned(),
            Value::String(self.http_methods.clone()),
        );
        map.insert(
            "selectorAvailable".to_owned(),
            Value::Bool(self.selector_available),
        );
        map.insert(
            "signatureAlgorithms".to_owned(),
            Value::String(self.signature_algorithms.clone()),
        );
        map.insert(
            "signatureTypes".to_owned(),
            Value::String(self.signature_types.clone()),
        );
        map.insert("version".to_owned(), Value::String(self.version.clone()));
        Value::Object(map)
    }
}

/// The `/sign` request document (v1.3 sec.2.6.2).
///
/// `content` is base64 of either the raw data to sign
/// (`contentType == "data"`) or a pre-computed digest
/// (`contentType == "digest"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequestDocument {
    /// Base64 of the data or digest to sign.
    pub content: String,
    /// `data` or `digest`.
    pub content_type: String,
    /// The requested digest name, when the caller sent one.
    pub hash_algorithm: Option<String>,
    /// The certificate selector, when the caller sent one.
    pub selector: Option<SignSelector>,
    /// The requested signature form, when the caller sent one.
    pub signature_type: Option<String>,
}

/// The selector object narrowing which certificate may sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignSelector {
    /// Requested key usages, by their X.509 names; empty when the
    /// caller sent none.
    pub keyusages: Vec<String>,
}

impl SignSelector {
    /// Decode the selector.
    fn decode(value: &Value) -> Result<Self, ()> {
        Ok(Self {
            keyusages: str_array_or_empty(value, "keyusages")?,
        })
    }
}

impl SignRequestDocument {
    /// Decode the request document.
    pub fn decode(value: &Value) -> Result<Self, ()> {
        Ok(Self {
            content: get_str(value, "content")?.to_owned(),
            content_type: get_str(value, "contentType")?.to_owned(),
            hash_algorithm: opt_str(value, "hashAlgorithm")?,
            selector: opt_object(value, "selector", SignSelector::decode)?,
            signature_type: opt_str(value, "signatureType")?,
        })
    }

    /// The card key this request selects.
    #[must_use]
    pub fn purpose(&self) -> SignPurpose {
        let qualified = self.selector.as_ref().is_some_and(|selector| {
            selector
                .keyusages
                .iter()
                .any(|usage| usage.eq_ignore_ascii_case("nonRepudiation"))
        });
        if qualified {
            SignPurpose::Qualified
        } else {
            SignPurpose::Authentication
        }
    }
}

/// The `/sign` response document (v1.3 sec.2.6.3).
///
/// HTTP status is always 200; the `status` / `reasonCode` /
/// `reasonText` triple carries the actual outcome. The signature
/// fields are omitted -- not nulled -- on failure, as the
/// specification's examples print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignResponseDocument {
    /// Base64 DER certificate chain on success, leaf first; empty on
    /// failure and then omitted from the encoding.
    pub chain: Vec<String>,
    /// The specification reason code.
    pub reason_code: u16,
    /// The human-readable reason.
    pub reason_text: String,
    /// Base64 signature on success.
    pub signature: Option<String>,
    /// The composed algorithm name on success.
    pub signature_algorithm: Option<String>,
    /// The signature form on success.
    pub signature_type: Option<String>,
    /// `ok` or `failed`.
    pub status: String,
    /// The protocol version.
    pub version: String,
}

impl SignResponseDocument {
    /// A successful response.
    #[must_use]
    pub fn ok(signature: String, signature_algorithm: String, chain: Vec<String>) -> Self {
        Self {
            chain,
            reason_code: values::REASON_OK,
            reason_text: "OK: Signature generated".to_owned(),
            signature: Some(signature),
            signature_algorithm: Some(signature_algorithm),
            signature_type: Some("signature".to_owned()),
            status: "ok".to_owned(),
            version: values::VERSION.to_owned(),
        }
    }

    /// A refused response carrying the specification reason.
    #[must_use]
    pub fn failed(reason_code: u16, reason_text: String) -> Self {
        Self {
            chain: Vec::new(),
            reason_code,
            reason_text,
            signature: None,
            signature_algorithm: None,
            signature_type: None,
            status: "failed".to_owned(),
            version: values::VERSION.to_owned(),
        }
    }

    /// Encode the document, omitting success-only fields when absent.
    #[must_use]
    pub fn encode(&self) -> Value {
        let mut map = serde_json::Map::new();
        if !self.chain.is_empty() {
            map.insert(
                "chain".to_owned(),
                Value::Array(
                    self.chain
                        .iter()
                        .map(|entry| Value::String(entry.clone()))
                        .collect(),
                ),
            );
        }
        map.insert("reasonCode".to_owned(), Value::from(self.reason_code));
        map.insert(
            "reasonText".to_owned(),
            Value::String(self.reason_text.clone()),
        );
        if let Some(signature) = &self.signature {
            map.insert("signature".to_owned(), Value::String(signature.clone()));
        }
        if let Some(algorithm) = &self.signature_algorithm {
            map.insert(
                "signatureAlgorithm".to_owned(),
                Value::String(algorithm.clone()),
            );
        }
        if let Some(signature_type) = &self.signature_type {
            map.insert(
                "signatureType".to_owned(),
                Value::String(signature_type.clone()),
            );
        }
        map.insert("status".to_owned(), Value::String(self.status.clone()));
        map.insert("version".to_owned(), Value::String(self.version.clone()));
        Value::Object(map)
    }
}

/// The `begin` payload: the relying service's key, certificate, and
/// certificate selector (v1.3 sec.2.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginDocument {
    /// The certificate selector, when sent.
    pub selector: Option<BeginSelector>,
    /// Base64 DER certificate authorising the transaction.
    pub server_cert: String,
    /// Base64 DER SPKI of the service's P-256 agreement key.
    pub server_key: String,
    /// Whether the key-algorithm selector is binding; false when
    /// absent.
    pub strict_key_policy: bool,
    /// The protocol version of the transaction.
    pub version: String,
}

/// The `begin` payload's certificate selector; only the fields this
/// service acts on are read, the rest are accepted for protocol
/// compatibility while certificate selection remains local
/// (v1.3 sec.2.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginSelector {
    /// Accepted key algorithms, lowercase (`rsa`, `ec`).
    pub keyalgorithms: Vec<String>,
    /// Requested key usages, by their X.509 names.
    pub keyusages: Vec<String>,
}

impl BeginSelector {
    /// Decode the selector.
    fn decode(value: &Value) -> Result<Self, ()> {
        Ok(Self {
            keyalgorithms: str_array_or_empty(value, "keyalgorithms")?,
            keyusages: str_array_or_empty(value, "keyusages")?,
        })
    }
}

impl BeginDocument {
    /// Decode the `begin` payload.
    pub fn decode(value: &Value) -> Result<Self, ()> {
        Ok(Self {
            selector: opt_object(value, "selector", BeginSelector::decode)?,
            server_cert: get_str(value, "serverCert")?.to_owned(),
            server_key: get_str(value, "serverKey")?.to_owned(),
            strict_key_policy: opt_bool(value, "strictKeyPolicy", false)?,
            version: get_str(value, "version")?.to_owned(),
        })
    }
}

/// The `begin` response payload this service signs (v1.3 sec.2.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginResponseDocument {
    /// Base64 DER certificate chain, leaf first.
    pub chain: Vec<String>,
    /// The specification reason code.
    pub reason_code: u16,
    /// The human-readable reason.
    pub reason_text: String,
    /// Always `ok`; a refused begin answers an error body instead.
    pub status: String,
    /// Base64 DER SPKI of this service's ephemeral agreement key.
    pub transaction: String,
    /// The protocol version.
    pub version: String,
}

impl BeginResponseDocument {
    /// Encode the response payload.
    #[must_use]
    pub fn encode(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "chain".to_owned(),
            Value::Array(
                self.chain
                    .iter()
                    .map(|entry| Value::String(entry.clone()))
                    .collect(),
            ),
        );
        map.insert("reasonCode".to_owned(), Value::from(self.reason_code));
        map.insert(
            "reasonText".to_owned(),
            Value::String(self.reason_text.clone()),
        );
        map.insert("status".to_owned(), Value::String(self.status.clone()));
        map.insert(
            "transaction".to_owned(),
            Value::String(self.transaction.clone()),
        );
        map.insert("version".to_owned(), Value::String(self.version.clone()));
        Value::Object(map)
    }
}

/// The `execute` payload carried inside the JWE (v1.3 sec.2.7.3).
///
/// `displayText` is accepted and ignored: the holder's consent screen
/// is the platform's, and the receipt carries origin and digest
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteDocument {
    /// Base64 of the content or digest to sign.
    pub content: String,
    /// `data` or `digest`; `data` when absent.
    pub content_type: String,
    /// The digest name; SHA256 when absent.
    pub hash_algorithm: String,
    /// The key algorithm name; per the card key when absent (v1.3
    /// sec.2.6.1).
    pub signature_algorithm: Option<String>,
    /// `signature` or `cms-pades`; `signature` when absent.
    pub signature_type: String,
    /// The protocol version of the transaction.
    pub version: String,
}

impl ExecuteDocument {
    /// Decode the `execute` payload.
    pub fn decode(value: &Value) -> Result<Self, ()> {
        Ok(Self {
            content: get_str(value, "content")?.to_owned(),
            content_type: str_or_default(value, "contentType", "data")?,
            hash_algorithm: str_or_default(value, "hashAlgorithm", "SHA256")?,
            signature_algorithm: opt_str(value, "signatureAlgorithm")?,
            signature_type: str_or_default(value, "signatureType", "signature")?,
            version: get_str(value, "version")?.to_owned(),
        })
    }
}

/// The `execute` response payload, encrypted back to the caller
/// (v1.3 sec.2.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteResponseDocument {
    /// Base64 DER certificate chain, leaf first.
    pub chain: Vec<String>,
    /// The specification reason code.
    pub reason_code: u16,
    /// The human-readable reason.
    pub reason_text: String,
    /// Base64 of the signature or SignedData.
    pub signature: String,
    /// The composed algorithm name.
    pub signature_algorithm: String,
    /// The signature form that was produced.
    pub signature_type: String,
    /// Always `ok`; a refused execute answers an error body instead.
    pub status: String,
    /// The protocol version.
    pub version: String,
}

impl ExecuteResponseDocument {
    /// Encode the response payload.
    #[must_use]
    pub fn encode(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "chain".to_owned(),
            Value::Array(
                self.chain
                    .iter()
                    .map(|entry| Value::String(entry.clone()))
                    .collect(),
            ),
        );
        map.insert("reasonCode".to_owned(), Value::from(self.reason_code));
        map.insert(
            "reasonText".to_owned(),
            Value::String(self.reason_text.clone()),
        );
        map.insert(
            "signature".to_owned(),
            Value::String(self.signature.clone()),
        );
        map.insert(
            "signatureAlgorithm".to_owned(),
            Value::String(self.signature_algorithm.clone()),
        );
        map.insert(
            "signatureType".to_owned(),
            Value::String(self.signature_type.clone()),
        );
        map.insert("status".to_owned(), Value::String(self.status.clone()));
        map.insert("version".to_owned(), Value::String(self.version.clone()));
        Value::Object(map)
    }
}

/// A compact JWS protected header, as far as this service reads it
/// (v1.3 sec.2.7; RFC 7515).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoseHeaderDocument {
    /// The JWS algorithm name.
    pub alg: String,
}

impl JoseHeaderDocument {
    /// Decode the protected header.
    pub fn decode(value: &Value) -> Result<Self, ()> {
        Ok(Self {
            alg: get_str(value, "alg")?.to_owned(),
        })
    }
}

/// The signed response JWT's protected header (v1.3 sec.2.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeaderDocument {
    /// The JWS algorithm name.
    pub alg: String,
    /// The signing certificate's key identifier.
    pub kid: String,
    /// Always `JWT`.
    pub typ: String,
}

impl ResponseHeaderDocument {
    /// Encode the protected header.
    #[must_use]
    pub fn encode(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("alg".to_owned(), Value::String(self.alg.clone()));
        map.insert("kid".to_owned(), Value::String(self.kid.clone()));
        map.insert("typ".to_owned(), Value::String(self.typ.clone()));
        Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BeginDocument, ExecuteDocument, SignRequestDocument, SignResponseDocument, VersionDocument,
    };
    use crate::purpose::SignPurpose;
    use crate::values;
    use serde_json::Value;

    /// Decode one JSON text for the document tests.
    fn parse(text: &str) -> Value {
        serde_json::from_str(text).expect("test JSON parses")
    }

    /// The published version document names the served surface.
    #[test]
    fn version_document_names_the_surface() {
        let current = VersionDocument::current();
        assert_eq!(current.version, values::VERSION);
        assert_eq!(current.http_methods, "POST");
        assert_eq!(current.content_types, "data,digest");
        assert!(current.selector_available);
        let encoded = serde_json::to_string(&current.encode()).expect("encodes");
        assert!(encoded.starts_with("{\"applicationOIDs\":"), "{encoded}");
    }

    /// The selector's key usages pick the card key.
    #[test]
    fn purpose_follows_non_repudiation() {
        let plain =
            SignRequestDocument::decode(&parse(r#"{"content":"eA==","contentType":"data"}"#))
                .expect("decodes");
        assert_eq!(plain.purpose(), SignPurpose::Authentication);
        let qualified = SignRequestDocument::decode(&parse(
            r#"{"content":"eA==","contentType":"data","selector":{"keyusages":["nonRepudiation"]}}"#,
        ))
        .expect("decodes");
        assert_eq!(qualified.purpose(), SignPurpose::Qualified);
    }

    /// Success-only fields are omitted -- not nulled -- on failure.
    #[test]
    fn failed_response_omits_success_fields() {
        let failed = SignResponseDocument::failed(values::REASON_BAD_REQUEST, "nope".to_owned());
        let encoded = serde_json::to_string(&failed.encode()).expect("encodes");
        assert!(!encoded.contains("signature"), "{encoded}");
        assert!(!encoded.contains("chain"), "{encoded}");
        assert!(encoded.contains("\"status\":\"failed\""), "{encoded}");
    }

    /// The transaction documents decode with the specification's
    /// optionality.
    #[test]
    fn transaction_documents_apply_defaults() {
        let begin = BeginDocument::decode(&parse(
            r#"{"version":"1.3","serverKey":"eA==","serverCert":"eA=="}"#,
        ))
        .expect("decodes");
        assert!(!begin.strict_key_policy);
        assert_eq!(begin.selector, None);
        let execute = ExecuteDocument::decode(&parse(r#"{"version":"1.3","content":"eA=="}"#))
            .expect("decodes");
        assert_eq!(execute.content_type, "data");
        assert_eq!(execute.hash_algorithm, "SHA256");
        assert_eq!(execute.signature_algorithm, None);
        assert_eq!(execute.signature_type, "signature");
    }
}
