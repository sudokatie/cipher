//! Client certificate authentication and access control.
//!
//! Provides mutual TLS (mTLS) support for verifying client certificates.

mod client_auth;
mod policy;

pub use client_auth::{ClientAuthenticator, ClientIdentity, AuthResult};
pub use policy::{AccessPolicy, PolicyRule, PolicyAction};
