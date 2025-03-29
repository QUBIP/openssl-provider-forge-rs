//! TLS Signature Algorithm capability support for OpenSSL providers.
//!
//! This module defines the [`TLSSigAlg`] trait which represents a TLS signature
//! algorithm that can be supported by an OpenSSL provider.
//!
//! It also provides the [`as_params`] macro to convert
//! a type implementing [`TLSSigAlg`] into an OpenSSL parameter array.
//!
//! Refer to [provider-base(7ossl)](https://docs.openssl.org/master/man7/provider-base/#tls-sigalg-capability).
//!
//! # Examples
//!
//! ## Define a custom TLS Signature Algorithm (minimal example only with required definitions)
//!
//! ```rust
//! use openssl_provider_forge::capabilities::tls_sigalg;
//! use tls_sigalg::*;
//!
//! // Define a custom TLS Signature Algorithm
//! pub struct TLSSigAlgCap;
//!
//! impl TLSSigAlg for TLSSigAlgCap {
//!     const SIGALG_IANA_NAME: &CStr = c"ed448";
//!
//!     const SIGALG_CODEPOINT: u32 = 0x0808;
//!
//!     const SIGALG_NAME: &CStr = c"EDWARDS448";
//!
//!     const SECURITY_BITS: u32 = 192;
//!     const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
//!     // use default values for MAX_TLS, MIN_DTLS, MAX_DTLS
//! }
//!
//! // Convert the TLS group to OpenSSL parameters
//! let params = tls_sigalg::as_params!(TLSSigAlgCap);
//!
//! // The params can now be used with OpenSSL provider functions
//! // For example, they could be returned from a provider's get_capabilities function
//! assert_ne!(params.len(), 0);
//! ```
//!
//! ## Define a custom TLS Signature Algorithm (with some optional definitions)
//!
//! ```rust
//! use openssl_provider_forge::capabilities::tls_sigalg;
//! use tls_sigalg::*;
//!
//! // Define a custom TLS Signature Algorithm
//! pub struct TLSSigAlgCap;
//!
//! impl TLSSigAlg for TLSSigAlgCap {
//!     const SIGALG_IANA_NAME: &CStr = c"xorhmacsha2sig";
//!     const SIGALG_NAME: &CStr = Self::SIGALG_IANA_NAME;
//!     const SIGALG_HASH_NAME: Option<&CStr> = Some(c"SHA256");
//!     const SIGALG_OID: Option<&CStr> = Some(c"1.3.6.1.4.1.16604.998888.2");
//!     const SIGALG_CODEPOINT: u32 = 0xFFFF;
//!
//!     const SECURITY_BITS: u32 = 128;
//!     const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
//!     const MAX_TLS: TLSVersion = TLSVersion::TLSv1_3;
//!     const MIN_DTLS: DTLSVersion = DTLSVersion::DTLSv1_2;
//!     const MAX_DTLS: DTLSVersion = DTLSVersion::DTLSv1_2;
//! }
//!
//! // Convert the TLS group to OpenSSL parameters
//! let params = tls_sigalg::as_params!(TLSSigAlgCap);
//!
//! // The params can now be used with OpenSSL provider functions
//! // For example, they could be returned from a provider's get_capabilities function
//! assert_ne!(params.len(), 0);
//! ```

pub use crate::bindings::ffi_c_types::*;
pub use crate::bindings::{
    OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME,
    OSSL_CAPABILITY_TLS_SIGALG_HASH_OID, OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,
    OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE, OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID,
    OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS, OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,
    OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS, OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,
    OSSL_CAPABILITY_TLS_SIGALG_NAME, OSSL_CAPABILITY_TLS_SIGALG_OID,
    OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, OSSL_CAPABILITY_TLS_SIGALG_SIG_NAME,
    OSSL_CAPABILITY_TLS_SIGALG_SIG_OID,
};

pub use super::{DTLSVersion, TLSVersion};

#[cfg(doc)]
use crate::osslparams::*;

/// The "TLS-SIGALG" capability can be queried by `libssl` to discover the list
/// of TLS signature algorithms that a provider can support.
///
/// Each signature supported can be used for client- or server-authentication in
/// addition to the built-in signature algorithms.
///
/// TLS 1.3 clients can advertise the list of TLS signature algorithms they
/// support in the `signature_algorithms` extension, and TLS servers can select
/// an algorithm from the offered list that they also support.
///
/// In this way a provider can add to the list of signature algorithms
/// that `libssl` already supports with additional ones.
///
/// Refer to [provider-base(7ossl)](https://docs.openssl.org/master/man7/provider-base/#tls-sigalg-capability).
///
/// # Examples
///
/// ## Define a custom TLS Signature Algorithm (minimal example only with required definitions)
///
/// ```rust
/// # use openssl_provider_forge::bindings;
/// # use openssl_provider_forge::capabilities;
/// use capabilities::tls_sigalg;
/// use tls_sigalg::*;
///
/// // Define a custom TLS Signature Algorithm
/// pub struct TLSSigAlgCap;
///
/// impl TLSSigAlg for TLSSigAlgCap {
///     const SIGALG_IANA_NAME: &CStr = c"ed448";
///
///     const SIGALG_CODEPOINT: u32 = 0x0808;
///
///     const SIGALG_NAME: &CStr = c"EDWARDS448";
///
///     const SECURITY_BITS: u32 = 192;
///     const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
///     // use default values for MAX_TLS, MIN_DTLS, MAX_DTLS
/// }
///
/// // Convert the TLS group to OpenSSL parameters
/// let params = tls_sigalg::as_params!(TLSSigAlgCap);
///
/// // The params can now be used with OpenSSL provider functions
/// // For example, they could be returned from a provider's get_capabilities function
/// assert_ne!(params.len(), 0);
/// ```
///
/// ## Define a custom TLS Signature Algorithm (with some optional definitions)
///
/// ```rust
/// # use openssl_provider_forge::bindings;
/// # use openssl_provider_forge::capabilities;
/// use capabilities::tls_sigalg;
/// use tls_sigalg::*;
///
/// // Define a custom TLS Signature Algorithm
/// pub struct TLSSigAlgCap;
///
/// impl TLSSigAlg for TLSSigAlgCap {
///     const SIGALG_IANA_NAME: &CStr = c"xorhmacsha2sig";
///     const SIGALG_NAME: &CStr = Self::SIGALG_IANA_NAME;
///     const SIGALG_HASH_NAME: Option<&CStr> = Some(c"SHA256");
///     const SIGALG_OID: Option<&CStr> = Some(c"1.3.6.1.4.1.16604.998888.2");
///     const SIGALG_CODEPOINT: u32 = 0xFFFF;
///
///     const SECURITY_BITS: u32 = 128;
///     const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
///     const MAX_TLS: TLSVersion = TLSVersion::TLSv1_3;
///     const MIN_DTLS: DTLSVersion = DTLSVersion::DTLSv1_2;
///     const MAX_DTLS: DTLSVersion = DTLSVersion::DTLSv1_2;
/// }
///
/// // Convert the TLS group to OpenSSL parameters
/// let params = tls_sigalg::as_params!(TLSSigAlgCap);
///
/// // The params can now be used with OpenSSL provider functions
/// // For example, they could be returned from a provider's get_capabilities function
/// assert_ne!(params.len(), 0);
/// ```
pub trait TLSSigAlg {
    /// The name of the signature algorithm as given in the [IANA TLS SignatureScheme registry][IANA:tls-signaturescheme] as "Description".
    ///
    /// > This value must be supplied
    ///
    /// [IANA:tls-signaturescheme]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
    const SIGALG_IANA_NAME: &CStr;

    /// The TLS algorithm ID value as given in the [IANA TLS SignatureScheme registry][IANA:tls-signaturescheme].
    ///
    /// > This value must be supplied
    ///
    /// ## NOTE
    ///
    /// > It is possible to register the same code point from within different
    /// > providers. Users should note that if no property query is specified, or
    /// > more than one implementation matches the property query then it is
    /// > unspecified which implementation for a particular code point will be
    /// > used.
    ///
    /// [IANA:tls-signaturescheme]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
    const SIGALG_CODEPOINT: u32;

    /// A name for the full (possibly composite hash-and-signature) signature algorithm.
    ///
    /// > This value must be supplied
    ///
    /// ## NOTE
    ///
    /// - Note this is also the name that
    ///   [`SSL_CONF_cmd(-sigalgs)`][SSL_CONF_cmd(3ossl):cli]/[`SSL_CONF_cmd(SignatureAlgorithms)`][SSL_CONF_cmd(3ossl):conf]
    ///   will support.
    /// - Quote from [provider-base(7ossl)](https://docs.openssl.org/master/man7/provider-base/#tls-sigalg-capability):
    ///   > The provider may, but is not obligated to, provide a signature
    ///   > implementation with this name;
    ///   > if it doesn't, this is assumed to be a composite of a pure signature
    ///   > algorithm and a hash algorithm, which must be given with
    ///   > [`Self::SIGALG_SIG_NAME`] and [`Self::SIGALG_HASH_NAME`].
    ///
    /// [SSL_CONF_cmd(3ossl):cli]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-command-line-commands
    /// [SSL_CONF_cmd(3ossl):conf]: https://docs.openssl.org/master/man3/SSL_CONF_cmd/#supported-configuration-file-commands
    const SIGALG_NAME: &CStr;

    /// The OID of the [`Self::SIGALG_NAME`] algorithm in canonical numeric text form.
    ///
    /// > This value is optional
    ///
    /// ## NOTE
    ///
    /// > If this parameter is given, `OBJ_create()` will be used to create an
    /// > `OBJ` and a `NID` for this `OID`, using the [`Self::SIGALG_NAME`]
    /// > parameter for its (short) name.
    /// > Otherwise, it's assumed to already exist in the object database,
    /// > possibly done by the provider with the `core_obj_create()` upcall.
    const SIGALG_OID: Option<&CStr> = None;

    /// The name of the pure signature algorithm that is part of a composite
    /// [`Self::SIGALG_NAME`].
    ///
    /// > This value is optional
    ///
    /// ## NOTE
    ///
    /// > If [`Self::SIGALG_NAME`] is implemented by the provider, this parameter
    /// > is redundant and **must not be given**.
    const SIGALG_SIG_NAME: Option<&CStr> = None;

    /// The OID of the [`Self::SIGALG_SIG_NAME`] algorithm in canonical numeric text form.
    ///
    /// > This value is optional
    ///
    /// ## NOTE
    ///
    /// > If this parameter is given, `OBJ_create()` will be used to create an
    /// > `OBJ` and a `NID` for this `OID`, using the [`Self::SIGALG_SIG_NAME`]
    /// > parameter for its (short) name.
    /// > Otherwise, it's assumed to already exist in the object database,
    /// > possibly done by the provider with the `core_obj_create()` upcall.
    const SIGALG_SIG_OID: Option<&CStr> = None;

    /// The name of the hash algorithm that is part of a composite
    /// [`Self::SIGALG_NAME`].
    ///
    /// > This value is optional
    ///
    /// ## NOTE
    ///
    /// > If [`Self::SIGALG_NAME`] is implemented by the provider, this parameter
    /// > is redundant and **must not be given**.
    const SIGALG_HASH_NAME: Option<&CStr> = None;

    /// The OID of the [`Self::SIGALG_HASH_NAME`] algorithm in canonical numeric
    /// text form.
    ///
    /// > This value is optional
    ///
    /// ## NOTE
    ///
    /// > If this parameter is given, `OBJ_create()` will be used to create an
    /// > `OBJ` and a `NID` for this `OID`, using the [`Self::SIGALG_HASH_NAME`]
    /// > parameter for its (short) name.
    /// > Otherwise, it's assumed to already exist in the object database,
    /// > possibly done by the provider with the `core_obj_create()` upcall.
    const SIGALG_HASH_OID: Option<&CStr> = None;

    /// The key type of the public key of applicable certificates.
    ///
    /// > This value is optional
    ///
    /// ## NOTE
    ///
    /// > If this parameter isn't present, it's assumed to be the same as
    /// > [`Self::SIGALG_SIG_NAME`] if that's present,
    /// > otherwise [`Self::SIGALG_NAME`].
    const SIGALG_KEYTYPE: Option<&CStr> = None;

    /// The OID of the [`Self::SIGALG_KEYTYPE`] in canonical numeric text form.
    ///
    /// > This value is optional
    ///
    /// ## NOTE
    ///
    /// > If this parameter is given, `OBJ_create()` will be used to create an
    /// > `OBJ` and a `NID` for this `OID`, using the [`Self::SIGALG_KEYTYPE`]
    /// > parameter for its (short) name.
    /// > Otherwise, it's assumed to already exist in the object database,
    /// > possibly done by the provider with the `core_obj_create()` upcall.
    const SIGALG_KEYTYPE_OID: Option<&CStr> = None;

    /// The number of bits of security offered by keys of this algorithm.
    ///
    /// > This value must be supplied
    ///
    /// ## NOTE
    ///
    /// > The number of bits should be comparable with the ones given in Table 2
    /// > and 3 of the
    /// > [NIST SP800-57 Part 1](https://doi.org/10.6028/NIST.SP.800-57pt1r5)
    /// > document.
    /// >
    /// > This number is used to determine the security strength of the
    /// > algorithm if no digest algorithm has been registered that otherwise
    /// > defines the security strength.
    /// > If the signature algorithm implements its
    /// > own digest internally, this value needs to be set to properly reflect
    /// > the overall security strength.
    const SECURITY_BITS: u32;

    /// This parameters can be used to describe the minimum TLS version
    /// supported by the signature algorithm.
    const MIN_TLS: TLSVersion;

    /// This parameters can be used to describe the maximum TLS version
    /// supported by the signature algorithm.
    ///
    /// We default to no set maximum version.
    const MAX_TLS: TLSVersion = TLSVersion::None;

    // There aren't any OSSL_CAPABILITY_TLS_SIGALG_{MAX,MIN}_DTLS constants in OpenSSL 3.2, so
    // we currently don't generate any bindings for those constants, and they can't be used
    // unless we manually defined them. But later versions of OpenSSL will have them, so the
    // values are here for later.

    /// This parameters can be used to describe the minimum DTLS version
    /// supported by the signature algorithm.
    ///
    /// We default to not use this signature algorithm at all with DTLS.
    const MIN_DTLS: DTLSVersion = DTLSVersion::Disabled;

    /// This parameters can be used to describe the minimum DTLS version
    /// supported by the signature algorithm.
    ///
    /// We default to not use this signature algorithm at all with DTLS.
    const MAX_DTLS: DTLSVersion = DTLSVersion::Disabled;
}

/// Converts a type implementing [`TLSSigAlg`] into an OpenSSL parameter array.
///
/// This macro generates a constant array of [`CONST_OSSL_PARAM`] values that represent
/// all the properties of a TLS Signature Algorithm in a format that OpenSSL can understand. The resulting
/// parameter array can be used with OpenSSL provider functions that require TLS Signature Algorithm information.
///
/// The macro performs a compile-time check to ensure that the provided type implements
/// the [`TLSSigAlg`] trait.
///
/// # Parameters
///
/// * `$group_type`: The type implementing [`TLSSigAlg`] that should be converted to parameters
///
/// # Returns
///
/// A reference to a static array of [`CONST_OSSL_PARAM`] values representing the TLS Signature Algorithm properties.
///
/// # Examples
///
/// ```rust
/// # use openssl_provider_forge::bindings;
/// # use openssl_provider_forge::capabilities;
/// use capabilities::tls_sigalg;
/// use bindings::CONST_OSSL_PARAM;
/// use tls_sigalg::*;
///
/// # mod some_module {
/// #     use openssl_provider_forge::capabilities::tls_sigalg;
/// #     use tls_sigalg::*;
/// #
/// #     pub(super) struct TLSSigAlgCapability;
/// #
/// #     impl TLSSigAlg for TLSSigAlgCapability {
/// #         const SIGALG_IANA_NAME: &CStr = c"ed448";
/// #
/// #         const SIGALG_CODEPOINT: u32 = 0x0808;
/// #
/// #         const SIGALG_NAME: &CStr = c"EDWARDS448";
/// #
/// #         const SECURITY_BITS: u32 = 192;
/// #         const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
/// #         // use default values for MAX_TLS, MIN_DTLS, MAX_DTLS
/// #     }
/// # };
/// #
/// // Some module implemented `TLSSigAlg` for some `TLSSigAlgCapability`
/// use some_module::TLSSigAlgCapability;
///
/// // Convert the TLS group to OpenSSL parameters
/// let params: &[CONST_OSSL_PARAM] = tls_sigalg::as_params!(TLSSigAlgCapability);
///
/// // The params can now be used with OpenSSL provider functions
/// // For example, they could be returned from a provider's get_capabilities function
/// assert_ne!(params.len(), 0);
/// ```
///
/// - See [`TLSSigAlg`] for more examples.
///
/// # Notes
///
/// The generated parameter array is properly terminated with a
/// [`CONST_OSSL_PARAM::END`] marker as required by OpenSSL.
#[macro_export]
macro_rules! capability_tls_sigalg_as_params {
    ($group_type:ty) => {{
        use $crate::osslparams::*;
        use $crate::capabilities::tls_sigalg::*;
        use $crate::capabilities::optional_param;

        // This static assertion will cause a compile error if $group_type doesn't implement TLSSigAlg
        const _: fn() = || {
            // This function is never called, it only exists for type checking
            fn assert_implements_tls_sigalg<T: TLSSigAlg>() {}
            assert_implements_tls_sigalg::<$group_type>()
        };

        // Convert to const i32
        const MIN_TLS: i32 = <$group_type>::MIN_TLS as i32;
        const MAX_TLS: i32 = <$group_type>::MAX_TLS as i32;
        const MIN_DTLS: i32 = <$group_type>::MIN_DTLS as i32;
        const MAX_DTLS: i32 = <$group_type>::MAX_DTLS as i32;

        // Now create the parameter list
        const OSSL_PARAM_ARRAY: &[CONST_OSSL_PARAM] = &[
            // IANA name for the sigalg
            OSSLParam::new_const_utf8string(
                OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,
                Some(<$group_type>::SIGALG_IANA_NAME)
            ),
            // IANA code point for the sigalg
            OSSLParam::new_const_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, Some(&<$group_type>::SIGALG_CODEPOINT)),

            // A name for the full (possibly composite hash-and-signature) signature algorithm.
            OSSLParam::new_const_utf8string(
                OSSL_CAPABILITY_TLS_SIGALG_NAME,
                Some(<$group_type>::SIGALG_NAME)
            ),
            // A name for the full (possibly composite hash-and-signature) signature algorithm.
            OSSLParam::new_const_utf8string(
                OSSL_CAPABILITY_TLS_SIGALG_NAME,
                Some(<$group_type>::SIGALG_NAME)
            ),

            // The OID of the "sigalg-name" algorithm in canonical numeric text form. [optional]
            {optional_param!(new_const_utf8string, OSSL_CAPABILITY_TLS_SIGALG_OID, <$group_type>::SIGALG_OID)},
            // The name of the pure signature algorithm that is part of a composite "sigalg-name". [optional]
            {optional_param!(new_const_utf8string, OSSL_CAPABILITY_TLS_SIGALG_SIG_NAME, <$group_type>::SIGALG_SIG_NAME)},
            // The OID of the "sig-name" algorithm in canonical numeric text form. [optional]
            {optional_param!(new_const_utf8string, OSSL_CAPABILITY_TLS_SIGALG_SIG_OID, <$group_type>::SIGALG_SIG_OID)},
            // The name of the hash algorithm that is part of a composite "sigalg-name". [optional]
            {optional_param!(new_const_utf8string, OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME, <$group_type>::SIGALG_HASH_NAME)},
            // The OID of the "hash-name" algorithm in canonical numeric text form. [optional]
            {optional_param!(new_const_utf8string, OSSL_CAPABILITY_TLS_SIGALG_HASH_OID, <$group_type>::SIGALG_HASH_OID)},
            // The key type of the public key of applicable certificates. [optional]
            {optional_param!(new_const_utf8string, OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE, <$group_type>::SIGALG_KEYTYPE)},
            // The OID of the "key-type" in canonical numeric text form. [optional]
            {optional_param!(new_const_utf8string, OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID, <$group_type>::SIGALG_KEYTYPE_OID)},

            // number of bits of security
            OSSLParam::new_const_uint(
                OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,
                Some(&<$group_type>::SECURITY_BITS),
            ),
            // min TLS version
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, Some(&MIN_TLS)),
            // min TLS version
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, Some(&MAX_TLS)),
            // min DTLS
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS, Some(&MIN_DTLS)),
            // max DTLS
            OSSLParam::new_const_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS, Some(&MAX_DTLS)),
            // IMPORTANT: always terminate a params array!!!
            CONST_OSSL_PARAM::END,
        ];
        OSSL_PARAM_ARRAY
    }};
}
pub use capability_tls_sigalg_as_params as as_params;

#[cfg(test)]
mod tests {
    #![expect(unused_imports)]
    use crate as openssl_provider_forge;
    use crate::tests::common::OurError;

    #[expect(dead_code)]
    fn setup() -> Result<(), OurError> {
        crate::tests::common::setup()
    }

    #[cfg(any())]
    #[test]
    fn test_basic_usage() {
        setup().expect("setup() failed");

        use openssl_provider_forge::capabilities::tls_sigalg;
        use tls_sigalg::*;

        // Define a custom TLS Signature Algorithm
        pub struct TLSSigAlgCap;

        impl TLSSigAlg for TLSSigAlgCap {
            const SIGALG_IANA_NAME: &CStr = c"xorhmacsha2sig";
            const SIGALG_NAME: &CStr = Self::SIGALG_IANA_NAME;
            const SIGALG_HASH_NAME: Option<&CStr> = Some(c"SHA256");
            const SIGALG_OID: Option<&CStr> = Some(c"1.3.6.1.4.1.16604.998888.2");
            const SIGALG_CODEPOINT: u32 = 0xFFFF;

            const SECURITY_BITS: u32 = 128;
            const MIN_TLS: TLSVersion = TLSVersion::TLSv1_3;
            const MAX_TLS: TLSVersion = TLSVersion::TLSv1_3;
            const MIN_DTLS: DTLSVersion = DTLSVersion::DTLSv1_2;
            const MAX_DTLS: DTLSVersion = DTLSVersion::DTLSv1_2;
        }

        // Convert the TLS group to OpenSSL parameters
        let params = tls_sigalg::as_params!(TLSSigAlgCap);

        // The params can now be used with OpenSSL provider functions
        // For example, they could be returned from a provider's get_capabilities function
        assert_ne!(params.len(), 0);

        log::debug!("{params:#?}");
    }
}
