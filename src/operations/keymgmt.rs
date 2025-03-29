//! This module provides utilities for [`keymgmt`][provider-keymgmt(7ossl)]
//! [Operations][provider(7ossl)#Operations] in the context of
//! [OpenSSL Providers][provider(7ossl)].
//!
//! # Purpose
//! The `keymgmt` module contains tools and abstractions to facilitate the implementation
//! of [key management functionality][provider-keymgmt(7ossl)]
//! for [OpenSSL Providers][provider(7ossl)].
//!
//! # References
//!
//! - [provider-keymgmt(7ossl)]
//! - [provider(7ossl)]
//!
//!
//! [provider(7ossl)]: https://docs.openssl.org/master/man7/provider/
//! [provider(7ossl)#Operations]: https://docs.openssl.org/master/man7/provider/#operations
//! [provider-keymgmt(7ossl)]: https://docs.openssl.org/master/man7/provider-keymgmt/

/// This submodule defines the `Selection` bitflags used in OpenSSL key management operations.
///
/// # Purpose
/// The `selection` submodule provides a type-safe representation of key selection flags
/// used in OpenSSL's key management APIs. These flags specify which parts of a key
/// (e.g., private key, public key, domain parameters) are being targeted in a given operation.
///
/// # Features
/// - Defines the `Selection` bitflags for OpenSSL key management operations.
/// - Provides constants for common key selection options, such as `PRIVATE_KEY`, `PUBLIC_KEY`,
///   and `KEYPAIR`.
/// - Implements a `TryFrom<u32>` conversion for safely handling raw OpenSSL flag values.
///
/// # Examples
///
/// ```rust
/// use openssl_provider_forge::operations::keymgmt::selection::Selection;
///
/// // Example: Creating a Selection flag for a keypair
/// let keypair_selection = Selection::KEYPAIR;
///
/// // Example: Converting a raw u32 value into a Selection
/// let raw_value: u32 = 0x03; // Example value
/// match Selection::try_from(raw_value) {
///     Ok(selection) => println!("Valid selection: {:?}", selection),
///     Err(e) => eprintln!("Error: {:?}", e),
/// }
/// ```
pub mod selection {
    use crate::bindings;
    use bitflags::bitflags;
    use std::fmt::Debug;
    use std::result::Result::Ok;

    bitflags! {
        /// Represents key selection flags used in OpenSSL key management operations.
        ///
        /// # Purpose
        /// The `Selection` struct provides a type-safe way to represent and manipulate
        /// key selection flags in OpenSSL's key management APIs. These flags specify
        /// which parts of a key (e.g., private key, public key, domain parameters) are
        /// being targeted in a given operation.
        ///
        /// # Features
        /// - Includes constants for common key selection options:
        ///   - `PRIVATE_KEY`: Selects the private key.
        ///   - `PUBLIC_KEY`: Selects the public key.
        ///   - `DOMAIN_PARAMETERS`: Selects the domain parameters.
        ///   - `OTHER_PARAMETERS`: Selects other parameters.
        ///   - `ALL_PARAMETERS`: Selects all parameters.
        ///   - `KEYPAIR`: Selects both the private and public key.
        ///   - `ALL`: Selects all key components.
        /// - Implements a `TryFrom<u32>` conversion to safely handle raw OpenSSL flag values.
        ///
        /// # Example
        /// ```rust
        /// use openssl_provider_forge::operations::keymgmt::selection::Selection;
        ///
        /// // Example: Creating a Selection flag for a keypair
        /// let keypair_selection = Selection::KEYPAIR;
        ///
        /// // Example: Converting a raw u32 value into a Selection
        /// let raw_value: u32 = 0x03; // Example value
        /// match Selection::try_from(raw_value) {
        ///     Ok(selection) => println!("Valid selection: {:?}", selection),
        ///     Err(e) => eprintln!("Error: {:?}", e),
        /// }
        /// ```
        #[derive(Debug,Clone,Copy)]
        pub struct Selection: u32 {
            const PRIVATE_KEY = bindings::OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
            const PUBLIC_KEY = bindings::OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
            const DOMAIN_PARAMETERS = bindings::OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
            const OTHER_PARAMETERS = bindings::OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;

            const ALL_PARAMETERS = bindings::OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
            const KEYPAIR = bindings::OSSL_KEYMGMT_SELECT_KEYPAIR;
            const ALL = bindings::OSSL_KEYMGMT_SELECT_ALL;
        }
    }

    impl TryFrom<u32> for Selection {
        type Error = crate::OurError;

        fn try_from(value: u32) -> Result<Self, Self::Error> {
            match Selection::from_bits(value) {
                Some(s) => Ok(s),
                None => Err(anyhow::anyhow!(
                    "Invalid OSSL_KEYMGMT_SELECT flag value: {:?}",
                    value
                )),
            }
        }
    }
}
