//! [LICENSE]: ../LICENSE
//! [!NOTE]: # "ℹ️ NOTE"
//! [!CAUTION]: # "⚠️ CAUTION"
#![doc = include_str!("../README.md")]

pub mod bindings;
pub mod capabilities;
pub mod operations;
pub mod ossl_callback;
pub mod osslparams;
pub mod upcalls;

pub use crypto;

pub type OurError = anyhow::Error;

use num_enum::{Default, IntoPrimitive, TryFromPrimitive};

// FIXME: remove this later on
/// **Deprecated**: This re-export is DEPRECATED and will be removed in a future
/// version, prefer using directly [`operations::keymgmt`].
#[deprecated(note = "use directly `operations::keymgmt` instead")]
pub use operations::keymgmt;

/// Represents TLS protocol versions
///
/// # Examples
///
/// ## Pick a specific TLS version
///
/// ```rust
/// # use openssl_provider_forge::TLSVersion;
///
/// // Create a specific TLS version
/// let tls_version = TLSVersion::TLSv1_2;
///
/// // Convert to raw value
/// let raw_value: i32 = tls_version.into();
/// assert_eq!(raw_value, 0x0303);
/// ```
/// ## Convert from raw values
///
/// ```rust
/// # use openssl_provider_forge::TLSVersion;
/// // Convert from raw values
/// let version_from_raw = TLSVersion::try_from(0x0304).unwrap();
/// assert_eq!(version_from_raw, TLSVersion::TLSv1_3);
///
/// let disabled_version_from_raw = TLSVersion::try_from(-1).unwrap();
/// assert_eq!(disabled_version_from_raw, TLSVersion::Disabled);
///
/// let none_version_from_raw = TLSVersion::try_from(0).unwrap();
/// assert_eq!(none_version_from_raw, TLSVersion::None);
/// ```
///
/// ## Using default version
///
/// ```rust
/// # use openssl_provider_forge::TLSVersion;
/// // Using default version
/// let default_version = TLSVersion::default();
/// assert_eq!(default_version, TLSVersion::None);
/// ```
///
/// ## Compare versions
///
/// ```rust
/// # use openssl_provider_forge::TLSVersion;
/// // Compare versions
/// assert!(TLSVersion::TLSv1_3 > TLSVersion::TLSv1_2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(i32)]
pub enum TLSVersion {
    /// No defined version (0)
    #[default]
    None = 0,
    /// Protocol should not be used (-1)
    Disabled = -1,
    /// SSL v3.0 (0x0300)
    SSLv3_0 = 0x300,
    /// TLS v1.0 (0x0301)
    TLSv1_0 = 0x0301,
    /// TLS v1.1 (0x0302)
    TLSv1_1 = 0x0302,
    /// TLS v1.2 (0x0303)
    TLSv1_2 = 0x0303,
    /// TLS v1.3 (0x0304)
    TLSv1_3 = 0x0304,
}

impl PartialOrd for TLSVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (TLSVersion::None, _) => None,
            (TLSVersion::Disabled, _) => None,
            (_, TLSVersion::None) => None,
            (_, TLSVersion::Disabled) => None,
            (&s, &o) => {
                let (s, o): (i32, i32) = (s.into(), o.into());
                Some(s.cmp(&o))
            }
        }
    }
}

/// Represents DTLS protocol versions
/// # Examples
///
/// ## Pick a specific TLS version
///
/// ```rust
/// # use openssl_provider_forge::DTLSVersion;
///
/// // Create a specific TLS version
/// let dtls_version = DTLSVersion::DTLSv1_2;
///
/// // Convert to raw value
/// let raw_value: i32 = dtls_version.into();
/// assert_eq!(raw_value, 0xFEFD);
/// ```
///
/// ## Convert from raw values
///
/// ```rust
/// # use openssl_provider_forge::DTLSVersion;
/// // Convert from raw values
/// let version_from_raw = DTLSVersion::try_from(0xFEFD).unwrap();
/// assert_eq!(version_from_raw, DTLSVersion::DTLSv1_2);
///
/// let disabled_version_from_raw = DTLSVersion::try_from(-1).unwrap();
/// assert_eq!(disabled_version_from_raw, DTLSVersion::Disabled);
///
/// let none_version_from_raw = DTLSVersion::try_from(0).unwrap();
/// assert_eq!(none_version_from_raw, DTLSVersion::None);
/// ```
///
/// ## Using default version
///
/// ```rust
/// # use openssl_provider_forge::DTLSVersion;
/// // Using default version
/// let default_version = DTLSVersion::default();
/// assert_eq!(default_version, DTLSVersion::None);
/// ```
///
/// ## Compare versions
///
/// ```rust
/// # use openssl_provider_forge::DTLSVersion;
/// // Compare versions
/// assert!(DTLSVersion::DTLSv1_2 > DTLSVersion::DTLSv1_0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, TryFromPrimitive, IntoPrimitive, Default)]
#[repr(i32)]
pub enum DTLSVersion {
    /// No defined version (0)
    #[default]
    None = 0,
    /// Protocol should not be used (-1)
    Disabled = -1,
    /// DTLS v1.0 (0xFEFF) - corresponds to TLS v1.1
    DTLSv1_0 = 0xFEFF,
    /// DTLS v1.2 (0xFEFD) - corresponds to TLS v1.2
    DTLSv1_2 = 0xFEFD,
}

impl PartialOrd for DTLSVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (DTLSVersion::None, _) => None,
            (DTLSVersion::Disabled, _) => None,
            (_, DTLSVersion::None) => None,
            (_, DTLSVersion::Disabled) => None,
            (&s, &o) => {
                let (s, o): (i32, i32) = (s.into(), o.into());
                // Reverse ordering otherwise
                Some(o.cmp(&s))
            }
        }
    }
}

/// Match on a `Result`, evaluating to the wrapped value if it is `Ok` or
/// returning `ERROR_RET` (which must already be defined) if it is `Err`.
///
/// This macro should be used in `extern "C"` functions that will be directly
/// called by OpenSSL. In other functions, `Result`s should be handled in the
/// usual Rust way.
///
/// If invoked with an `Err` value, this macro also calls [`log::error!`] to log
/// the error.
///
/// Before invoking this macro, an identifier `ERROR_RET` must be in scope, and
/// the type of its value must be the same as (or coercible to) the return type
/// of the function in which `handleResult!` is being invoked.
#[macro_export]
macro_rules! handleResult {
    ($e:expr) => {
        match ($e) {
            Ok(r) => r,
            Err(e) => {
                log::error!("{:#?}", e);
                return ERROR_RET;
            }
        }
    };
}

#[cfg(test)]
pub(crate) mod tests;
