#![warn(missing_docs)]

//! In OpenSSL _Capabilities_ describe some of the services that a provider can offer.
//! Applications can query the capabilities to discover those services.
//!
//! This crate currently supports two such capabilities:
//!
//! * [`tls_group`]
//! * [`tls_sigalg`]
//!
//! Refer to [provider-base(7ossl)](https://docs.openssl.org/3.5/man7/provider-base/#capabilities)

pub mod tls_group;

pub use tls_group::as_params as tls_group_as_params;
pub use tls_group::TLSGroup;

pub mod tls_sigalg;
pub use tls_sigalg::as_params as tls_sigalg_as_params;
pub use tls_sigalg::TLSSigAlg;

pub use crate::{DTLSVersion, TLSVersion};
