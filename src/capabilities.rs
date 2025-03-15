#![warn(missing_docs)]

//! In OpenSSL _Capabilities_ describe some of the services that a provider can offer.
//! Applications can query the capabilities to discover those services.
//!
//! This crate currently supports two such capabilities:
//!
//! * [`tls_group`]
//! * [`tls_sigalg`]
//!
//! Refer to [provider-base(7ossl)](https://docs.openssl.org/master/man7/provider-base/#capabilities)

pub mod tls_group;

pub use tls_group::as_params as tls_group_as_params;
pub use tls_group::TLSGroup;

pub mod tls_sigalg;
pub use tls_sigalg::as_params as tls_sigalg_as_params;
pub use tls_sigalg::TLSSigAlg;

pub use crate::{DTLSVersion, TLSVersion};

#[doc(hidden)]
/// An internal macro to handle optional params
#[macro_export]
macro_rules! __hidden__optional_param {
    ($new_fn:ident, $param_key:ident, $cnst:expr) => {{
        const IGNORED: &CStr = c"__ignored__";
        match $cnst {
            //None => OSSLParam::new_const_utf8string(IGNORED, Some(IGNORED)),
            None => OSSLParam::new_const_utf8string(IGNORED, None),
            Some(value) => OSSLParam::$new_fn($param_key, Some(value)),
        }
    }};
}

/// An internal macro to handle optional params
#[doc(hidden)]
pub use __hidden__optional_param as optional_param;
