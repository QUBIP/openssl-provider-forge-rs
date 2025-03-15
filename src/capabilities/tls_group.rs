//! TLS Group capability support for OpenSSL providers.
//!
//! This module defines the [`TLSGroup`] trait which represents a TLS group that can be
//! supported by an OpenSSL provider. It also provides the [`as_params`] macro to convert
//! a type implementing [`TLSGroup`] into an OpenSSL parameter array.
//!
//! TLS groups are used during TLS handshakes for key exchange (KEX) or key encapsulation
//! methods (KEM). By implementing this capability, providers can extend the list of groups
//! that `libssl` supports.
//!
//! Refer to [provider-base(7ossl)](https://docs.openssl.org/master/man7/provider-base/#tls-group-capability)
//!
//! # Examples
//!
//! ```rust
//! use openssl_provider_forge::capabilities::tls_group;
//! use tls_group::*;
//!
//! // Define a TLS group
//! pub struct X25519MLKEM768Group;
//!
//! impl TLSGroup for X25519MLKEM768Group {
//!     const IANA_GROUP_NAME: &'static CStr = c"X25519MLKEM768";
//!     const IANA_GROUP_ID: u32 = 0x4588;
//!     const GROUP_NAME_INTERNAL: &'static CStr = c"X25519MLKEM768";
//!     const GROUP_ALG: &'static CStr = c"X25519MLKEM768";
//!     const SECURITY_BITS: u32 = 192;
//!     const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3; // TLS 1.3
//!     const MAX_TLS: TLSVersion = TLSVersion::None; // no set version
//!     const MIN_DTLS: DTLSVersion = DTLSVersion::Disabled;
//!     const MAX_DTLS: DTLSVersion = DTLSVersion::Disabled;
//!     const IS_KEM: bool = true;
//! }
//!
//! // Convert to OpenSSL parameters
//! let params = tls_group::as_params!(X25519MLKEM768Group);
//!
//! // These parameters can now be used with OpenSSL provider functions
//! ```

pub use std::ffi::CStr;

pub use crate::bindings::{
    OSSL_CAPABILITY_TLS_GROUP_ALG, OSSL_CAPABILITY_TLS_GROUP_ID, OSSL_CAPABILITY_TLS_GROUP_IS_KEM,
    OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,
    OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,
    OSSL_CAPABILITY_TLS_GROUP_NAME, OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
    OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
};

pub use super::{DTLSVersion, TLSVersion};

#[cfg(doc)]
use crate::osslparams::*;

/// The "TLS-GROUP" capability can be queried by `libssl` to discover the list of
/// TLS groups that a provider can support.
///
/// Each group supported can be used for key exchange (KEX) or key encapsulation
/// method (KEM) during a TLS handshake.
///
/// TLS clients can advertise the list of TLS groups they support in the
/// supported_groups extension, and TLS servers can select a group from the
/// offered list that they also support.
///
/// In this way a provider can add to the list of groups that `libssl` already
/// supports with additional ones.
pub trait TLSGroup {
    /// The name of the group as given in the
    /// [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
    const IANA_GROUP_NAME: &CStr;

    /// The TLS group id value as given in the
    /// [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
    const IANA_GROUP_ID: u32;

    /// group name according to this provider
    const GROUP_NAME_INTERNAL: &CStr;

    /// keymgmt algorithm name
    const GROUP_ALG: &CStr;

    /// number of bits of security
    const SECURITY_BITS: u32;

    /// min TLS
    const MIN_TLS: TLSVersion;
    /// max TLS (default to no set maximum version)
    const MAX_TLS: TLSVersion = TLSVersion::None;

    /// min DTLS (do not use this group at all with DTLS)
    const MIN_DTLS: DTLSVersion = DTLSVersion::Disabled;
    /// max DTLS (do not use this group at all with DTLS)
    const MAX_DTLS: DTLSVersion = DTLSVersion::Disabled;

    /// is KEM: yes
    const IS_KEM: bool = false;
}

/// Converts a type implementing [`TLSGroup`] into an OpenSSL parameter array.
///
/// This macro generates a constant array of [`CONST_OSSL_PARAM`] values that represent
/// all the properties of a TLS group in a format that OpenSSL can understand. The resulting
/// parameter array can be used with OpenSSL provider functions that require TLS group information.
///
/// The macro performs a compile-time check to ensure that the provided type implements
/// the [`TLSGroup`] trait.
///
/// # Parameters
///
/// * `$group_type`: The type implementing [`TLSGroup`] that should be converted to parameters
///
/// # Returns
///
/// A reference to a static array of [`CONST_OSSL_PARAM`] values representing the TLS group properties.
///
/// # Examples
///
/// ```rust
/// use openssl_provider_forge::capabilities::tls_group;
/// use tls_group::*;
///
/// // Define a custom TLS group for the NIST P-256 curve
/// pub struct P256MLKEM768Group;
///
/// impl TLSGroup for P256MLKEM768Group {
///     const IANA_GROUP_NAME: &'static CStr = c"SecP256r1MLKEM768";
///     const IANA_GROUP_ID: u32 = 4587;
///
///     // Internal name used by the provider
///     const GROUP_NAME_INTERNAL: &'static CStr = c"SecP256r1MLKEM768";
///
///     // Key management algorithm
///     const GROUP_ALG: &'static CStr = c"SecP256r1MLKEM768";
///
///     const SECURITY_BITS: u32 = 192;
///
///     const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
///     // use default values for MAX_TLS, MIN_DTLS, MAX_DTLS
///     const IS_KEM: bool = true;
/// }
///
/// // Convert the TLS group to OpenSSL parameters
/// let params = tls_group::as_params!(P256MLKEM768Group);
///
/// // The params can now be used with OpenSSL provider functions
/// // For example, they could be returned from a provider's get_capabilities function
/// ```
///
/// # Notes
///
/// The generated parameter array is properly terminated with a
/// [`CONST_OSSL_PARAM::END`] marker as required by OpenSSL.
#[macro_export]
macro_rules! capability_tls_group_as_params {
    ($group_type:ty) => {{
        use $crate::osslparams::*;
        use $crate::capabilities::tls_group::*;

        // This static assertion will cause a compile error if $group_type doesn't implement TLSGroup
        const _: fn() = || {
            // This function is never called, it only exists for type checking
            fn assert_implements_tls_group<T: TLSGroup>() {}
            assert_implements_tls_group::<$group_type>()
        };

        // Convert bool to const u32
        const IS_KEM_AS_UINT: u32 = if <$group_type>::IS_KEM { 1 } else { 0 };

        // Convert to const i32
        const MIN_TLS: i32 = <$group_type>::MIN_TLS as i32;
        const MAX_TLS: i32 = <$group_type>::MAX_TLS as i32;
        const MIN_DTLS: i32 = <$group_type>::MIN_DTLS as i32;
        const MAX_DTLS: i32 = <$group_type>::MAX_DTLS as i32;

        // Now create the parameter list
        const OSSL_PARAM_ARRAY: &[CONST_OSSL_PARAM] = &[
            // IANA group name
            OSSLParam::new_const_utf8string(
                OSSL_CAPABILITY_TLS_GROUP_NAME,
                Some(<$group_type>::IANA_GROUP_NAME)
            ),
            // group name according to the provider
            OSSLParam::new_const_utf8string(
                OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                Some(<$group_type>::GROUP_NAME_INTERNAL),
            ),
            // keymgmt algorithm name
            OSSLParam::new_const_utf8string(OSSL_CAPABILITY_TLS_GROUP_ALG, Some(<$group_type>::GROUP_ALG)),
            // IANA group ID
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_ID, Some(&<$group_type>::IANA_GROUP_ID)),
            // number of bits of security
            OSSLParam::new_const_uint(
                OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
                Some(&<$group_type>::SECURITY_BITS),
            ),
            // min TLS version
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, Some(&MIN_TLS)),
            // min TLS version
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, Some(&MAX_TLS)),
            // min DTLS
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, Some(&MIN_DTLS)),
            // max DTLS
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, Some(&MAX_DTLS)),
            // is KEM
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, Some(&IS_KEM_AS_UINT)),
            // IMPORTANT: always terminate a params array!!!
            CONST_OSSL_PARAM::END,
        ];
        OSSL_PARAM_ARRAY
    }};
}
pub use capability_tls_group_as_params as as_params;
