//! This module provides traits, macros, and helper functions to facilitate the implementation
//! of [Operations][provider(7ossl)#Operations] for [OpenSSL Providers][provider(7ossl)]
//! (see [provider(7ossl)] for more details).
//!
//! # Purpose
//!
//! The utilities in this module are designed to streamline the process of implementing
//! [Operations][provider(7ossl)#Operations]
//! within an [OpenSSL Provider][provider(7ossl)],
//! ensuring consistency and reducing boilerplate code.
//!
//! # Usage
//!
//! This module is intended for developers working on OpenSSL Providers who need reusable
//! components to implement operations efficiently.
//!
//! It includes:
//! - Traits for defining common operation behaviors.
//! - Macros to simplify repetitive tasks.
//! - Helper functions for common tasks.
//!
//! [provider(7ossl)]: https://docs.openssl.org/master/man7/provider/
//! [provider(7ossl)#Operations]: https://docs.openssl.org/master/man7/provider/#operations
//!
//! # Examples
//! (Add examples here once the module is populated with functionality.)
//!

pub mod keymgmt;
pub mod signature;
pub mod transcoders;
