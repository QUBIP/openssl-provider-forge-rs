//! This module provides utilities for [`signature`][provider-signature(7ossl)]
//! [Operations][provider(7ossl)#Operations] in the context of
//! [OpenSSL Providers][provider(7ossl)].
//!
//! # References
//!
//! - [provider-signature(7ossl)]
//! - [provider(7ossl)]
//!
//! [provider(7ossl)]: https://docs.openssl.org/master/man7/provider/
//! [provider(7ossl)#Operations]: https://docs.openssl.org/master/man7/provider/#operations
//! [provider-signature(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/

use std::error::Error;

pub use crypto::signature::{SignatureEncoding, Signer, Verifier};

#[derive(Debug)]
pub enum VerificationError {
    InvalidSignature,
    GenericVerificationError,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        match self {
            VerificationError::InvalidSignature => write!(f, "error: verification failed"),
            VerificationError::GenericVerificationError => {
                write!(f, "error: generic internal failure")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

impl From<crypto::signature::Error> for VerificationError {
    fn from(value: crypto::signature::Error) -> Self {
        value
            .source()
            .map_or(VerificationError::GenericVerificationError, |e| {
                if let Some(ver_err) = e.downcast_ref::<VerificationError>() {
                    match ver_err {
                        VerificationError::InvalidSignature => VerificationError::InvalidSignature,
                        VerificationError::GenericVerificationError => {
                            VerificationError::GenericVerificationError
                        }
                    }
                } else {
                    VerificationError::GenericVerificationError
                }
            })
    }
}
