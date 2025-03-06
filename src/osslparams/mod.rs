#![warn(missing_docs)]
//! This module contains supported data types and functionality for working
//! with _OpenSSL Parameters_ (see [OSSL_PARAM(3ossl)]).
//!
//! [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/

use crate::bindings::{
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use std::{ffi::CStr, marker::PhantomData};

pub mod data;

#[cfg(test)]
mod tests;

/// This enum provides different parameter data types as defined by [OSSL_PARAM(3ossl)].
///
/// Each variant corresponds to a specific parameter data type
/// and wraps a corresponding struct type ([`IntData`], [`UIntData`], [`Utf8PtrData`], etc.).
/// This allows for storing different struct types in a collection together,
/// simplifying operations on various parameter types in a unified way.
///
/// [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/
#[derive(Debug)]
pub enum OSSLParam<'a> {
    /// Represents a [OSSL_PARAM(3ossl)] of type [`OSSL_PARAM_UTF8_PTR`]:
    ///
    /// ## TODO(🛠️): quote more documentation for this type from [OSSL_PARAM(3ossl)]
    ///
    /// [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/
    Utf8Ptr(Utf8PtrData<'a>),

    /// Represents a [OSSL_PARAM(3ossl)] of type [`OSSL_PARAM_UTF8_STRING`]:
    ///
    /// > The parameter data is a printable string.
    ///
    /// [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/
    Utf8String(Utf8StringData<'a>),

    /// Represents a [OSSL_PARAM(3ossl)] of type [`OSSL_PARAM_INTEGER`].
    ///
    /// > The parameter data is a signed integer of arbitrary length,
    /// > organized in native form, i.e. most significant byte first on
    /// > Big-Endian systems, and least significant byte first on Little-Endian
    /// > systems.
    ///
    /// [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/
    Int(IntData<'a>),

    /// Represents a [OSSL_PARAM(3ossl)] of type [`OSSL_PARAM_UNSIGNED_INTEGER`].
    ///
    /// > The parameter data is an unsigned integer of arbitrary length,
    /// > organized in native form, i.e. most significant byte first on
    /// > Big-Endian systems, and least significant byte first on Little-Endian
    /// > systems.
    ///
    /// [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/
    UInt(UIntData<'a>),

    /// Represents a [OSSL_PARAM(3ossl)] of type [`OSSL_PARAM_OCTET_STRING`]:
    ///
    /// > The parameter data is an arbitrary string of bytes.
    ///
    /// [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/
    OctetString(OctetStringData<'a>),
    // FIXME: support for OctetPtr is currently missing
}

impl<'a> OSSLParam<'a> {
    /// Creates a new _constant OpenSSL parameter_ ([`CONST_OSSL_PARAM`])
    /// of type [`OSSLParam::Utf8Ptr`].
    ///
    /// # Arguments
    ///
    /// * `key` and `value` are the [`CONST_OSSL_PARAM`] fields to be set.
    /// * `value` is actually an [`Option`]:
    ///   * [`None`] will create a new `NULL` [`CONST_OSSL_PARAM`]
    ///   * `Some(_)` will set the inner value of the new [`CONST_OSSL_PARAM`]
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub const fn new_const_utf8ptr(key: &'a KeyType, value: Option<&'a CStr>) -> CONST_OSSL_PARAM {
        let (data, data_size) = match value {
            Some(value) => {
                //let v = value.as_ptr();
                //let v = v as *mut std::ffi::c_void;
                //let sz = value.count_bytes();
                //(v, sz)
                let _ = value;
                todo!()
            }
            None => (std::ptr::null_mut(), 0),
        };
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_UTF8_PTR,
            data,
            data_size,
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    /// Creates a new _constant OpenSSL parameter_ ([`CONST_OSSL_PARAM`])
    /// of type [`OSSLParam::Utf8String`].
    ///
    /// # Arguments
    ///
    /// * `key` and `value` are the [`CONST_OSSL_PARAM`] fields to be set.
    /// * `value` is actually an [`Option`]:
    ///   * [`None`] will create a new `NULL` [`CONST_OSSL_PARAM`]
    ///   * `Some(_)` will set the inner value of the new [`CONST_OSSL_PARAM`]
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub const fn new_const_utf8string(
        key: &'a KeyType,
        value: Option<&'a CStr>,
    ) -> CONST_OSSL_PARAM {
        let (data, data_size) = match value {
            Some(value) => {
                let v = value.as_ptr();
                let v = v as *mut std::ffi::c_void;
                let sz = value.count_bytes();
                (v, sz)
            }
            None => (std::ptr::null_mut(), 0),
        };
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data,
            data_size,
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    /// Creates a new _constant OpenSSL parameter_ ([`CONST_OSSL_PARAM`])
    /// of type [`OSSLParam::Int`].
    ///
    /// # Arguments
    ///
    /// * `key` and `value` are the [`CONST_OSSL_PARAM`] fields to be set.
    /// * `value` is actually an [`Option`]:
    ///   * [`None`] will create a new `NULL` [`CONST_OSSL_PARAM`]
    ///   * `Some(_)` will set the inner value of the new [`CONST_OSSL_PARAM`]
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub const fn new_const_int<T>(key: &'a KeyType, value: Option<&'a T>) -> CONST_OSSL_PARAM
    where
        T: crate::osslparams::data::int::PrimIntMarker,
    {
        let (data, data_size) = match value {
            Some(value) => {
                let v = std::ptr::from_ref(value);
                let v = v as *mut std::ffi::c_void;
                let sz = size_of::<T>();
                (v, sz)
            }
            None => (std::ptr::null_mut(), 0),
        };
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_INTEGER,
            data,
            data_size,
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    /// Creates a new _constant OpenSSL parameter_ ([`CONST_OSSL_PARAM`])
    /// of type [`OSSLParam::UInt`].
    ///
    /// # Arguments
    ///
    /// * `key` and `value` are the [`CONST_OSSL_PARAM`] fields to be set.
    /// * `value` is actually an [`Option`]:
    ///   * [`None`] will create a new `NULL` [`CONST_OSSL_PARAM`]
    ///   * `Some(_)` will set the inner value of the new [`CONST_OSSL_PARAM`]
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub const fn new_const_uint<T>(key: &'a KeyType, value: Option<&'a T>) -> CONST_OSSL_PARAM
    where
        T: crate::osslparams::data::uint::PrimUIntMarker,
    {
        let (data, data_size) = match value {
            Some(value) => {
                let v = std::ptr::from_ref(value);
                let v = v as *mut std::ffi::c_void;
                let sz = size_of::<T>();
                (v, sz)
            }
            None => (std::ptr::null_mut(), 0),
        };
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            data: data as *mut std::ffi::c_void,
            data_size,
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    /// Creates a new _constant OpenSSL parameter_ ([`CONST_OSSL_PARAM`])
    /// of type [`OSSLParam::OctetString`].
    ///
    /// # Arguments
    ///
    /// * `key` and `value` are the [`CONST_OSSL_PARAM`] fields to be set.
    /// * `value` is actually an [`Option`]:
    ///   * [`None`] will create a new `NULL` [`CONST_OSSL_PARAM`]
    ///   * `Some(_)` will set the inner value of the new [`CONST_OSSL_PARAM`]
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub const fn new_const_octetstring(
        key: &'a KeyType,
        value: Option<&'a [i8]>,
    ) -> CONST_OSSL_PARAM {
        let (data, data_size) = match value {
            Some(value) => {
                //let v = std::ptr::from_ref(value);
                //let _v = v as *mut std::ffi::c_void;
                //let sz = todo!();
                //(v, sz)
                let _ = value;
                todo!()
            }
            None => (std::ptr::null_mut(), 0),
        };
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_OCTET_STRING,
            data,
            data_size,
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    // FIXME: what about octetptr?
}

/// This is an inner type, to represent in Rust the contents of an [`OSSL_PARAM`]
/// of [`Utf8Ptr`][`OSSLParam::Utf8Ptr`] type.
#[derive(Debug)]
pub struct Utf8PtrData<'a> {
    param: &'a mut OSSL_PARAM,
}

/// This is an inner type, to represent in Rust the contents of an [`OSSL_PARAM`]
/// of [`Utf8String`][`OSSLParam::Utf8String`] type.
pub struct Utf8StringData<'a> {
    param: &'a mut OSSL_PARAM,
}

impl std::fmt::Debug for Utf8StringData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = OSSLParam::try_from(self.param as *const OSSL_PARAM);
        match p {
            Ok(p) => {
                let v: Option<&CStr> = p.get();
                f.debug_struct("Utf8StringData")
                    .field("param", &self.param)
                    .field(".key", &p.get_key())
                    .field(".value", &v)
                    .finish()
            }
            Err(e) => f
                .debug_struct("Utf8StringData")
                .field("!ERROR", &format!("{e:?}"))
                .finish(),
        }
    }
}

/// This is an inner type, to represent in Rust the contents of an [`OSSL_PARAM`]
/// of [`Int`][`OSSLParam::Int`] type.
pub struct IntData<'a> {
    param: &'a mut OSSL_PARAM,
}

impl std::fmt::Debug for IntData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = OSSLParam::try_from(self.param as *const OSSL_PARAM);
        match p {
            Ok(p) => {
                let v: Option<i64> = p.get();
                f.debug_struct("IntData")
                    .field("param", &self.param)
                    .field(".key", &p.get_key())
                    .field(".value", &v)
                    .finish()
            }
            Err(e) => f
                .debug_struct("IntData")
                .field("!ERROR", &format!("{e:?}"))
                .finish(),
        }
    }
}

/// This is an inner type, to represent in Rust the contents of an [`OSSL_PARAM`]
/// of [`UInt`][`OSSLParam::UInt`] type.
pub struct UIntData<'a> {
    param: &'a mut OSSL_PARAM,
}

impl std::fmt::Debug for UIntData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = OSSLParam::try_from(self.param as *const OSSL_PARAM);
        match p {
            Ok(p) => {
                let v: Option<u64> = p.get();
                f.debug_struct("UIntData")
                    .field("param", &self.param)
                    .field(".key", &p.get_key())
                    .field(".value", &v)
                    .finish()
            }
            Err(e) => f
                .debug_struct("UIntData")
                .field("!ERROR", &format!("{e:?}"))
                .finish(),
        }
    }
}

#[derive(Debug)]
/// This is an inner type, to represent in Rust the contents of an [`OSSL_PARAM`]
/// of [`OctetString`][`OSSLParam::OctetString`] type.
pub struct OctetStringData<'a> {
    param: &'a mut OSSL_PARAM,
}

/// A type alias used for returning descriptive error messages in operations
/// involving [`OSSLParam`].
pub type OSSLParamError = String;

/// A type alias to represent the [`key`][`CONST_OSSL_PARAM::key`] field of an [`OSSL_PARAM`].
///
/// It is represented as [`CStr`] (which provides a Rust interface to C-style strings).
///
/// # Examples
///
/// ```rust
/// use openssl_provider_forge::bindings;
/// use openssl_provider_forge::osslparams::{KeyType, OSSLParam, CONST_OSSL_PARAM};
///
/// // Define 2 keys, one from the OpenSSL bindings, one arbitrarily defined
/// let key_1: &KeyType = bindings::OSSL_PROV_PARAM_STATUS;
/// let key_2: &KeyType = c"My_arbitrary_key_name";
///
/// // Create a params list with the keys defined above
/// let params = [
///     OSSLParam::new_const_int(key_1, Some(&1)),
///     OSSLParam::new_const_int(key_2, Some(&42)),
///     CONST_OSSL_PARAM::END
/// ];
/// ```
pub type KeyType = CStr;

impl<'a> OSSLParam<'a> {
    /// Sets the value of the [`OSSLParam`] to the provided value of type `T`.
    ///
    /// Updates the [`OSSLParam`] to store the given value, adjusting the return size accordingly.
    /// Performs type checks to ensure the value can be safely converted from the provided data type
    /// (`i32`, `i64`, `u32`, etc.). If the data pointer is `NULL` or the conversion fails,
    /// an appropriate error is returned.
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub fn set<T>(&mut self, value: T) -> Result<(), OSSLParamError>
    where
        Self: OSSLParamSetter<T>,
    {
        self.set_inner(value)
    }

    /// Extracts the inner value from an [`OSSLParam`] if it matches the expected type.
    ///
    /// This function provides
    /// a simple, safe, and consistent way to extract
    /// the inner value if the `OSSLParam` matches
    /// the expected type.
    ///
    /// # Return value
    ///
    /// Returns `Some(T)` if the value matches the type, otherwise returns `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_provider_forge::osslparams::*;
    /// use openssl_provider_forge::bindings::OSSL_PARAM;
    ///
    /// # let my_external_param = OSSLParam::new_const_int(c"arbitrary_key", Some(&42));
    /// # let EXTERNAL_OSSL_PARAM_PTR: *const OSSL_PARAM = std::ptr::from_ref(&my_external_param).cast();
    /// // EXTERNAL_OSSL_PARAM_PTR is a `*OSSL_PARAM`, from which
    /// // we create a "rich" OSSLParam Rust object (i.e., `my_param`).
    /// // We can then safely manipulate `my_param` using Rust methods.
    /// let my_param = OSSLParam::try_from(EXTERNAL_OSSL_PARAM_PTR).unwrap();
    ///
    /// // Assuming the external OSSL_PARAM had `int` type, the following would retrieve the value.
    /// if let Some(value) = my_param.get::<i64>() {
    ///     println!("The value is: {}", value);
    /// }
    /// ```
    ///
    pub fn get<T>(&self) -> Option<T>
    where
        Self: OSSLParamGetter<T>,
    {
        self.get_inner()
    }

    /// Retrieves the C FFI representation of this [`OSSLParam`], regardless of its variant.
    ///
    /// # Return value
    ///
    /// This function returns a **`const` pointer to [`OSSL_PARAM`]** which can be passed
    /// to OpenSSL functions through the FFI layer.
    ///
    /// > ⚠️ Users of this crate should prefer to read or manipulate _OpenSSL Parameters_ via
    /// > the [`OSSLParam`] Rust abstraction.
    /// >
    /// > **The pointers returned by functions such as this
    /// > are only meant to be used when crossing the FFI boundary**.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use openssl_provider_forge::osslparams::*;
    /// let p = OSSLParam::new_const_int(c"a_key", Some(&42));
    /// let param = OSSLParam::try_from(&p).unwrap();
    /// let ffi_param = param.get_c_struct();
    /// println!("Retrieved param: {:?}", ffi_param);
    ///
    /// let rich_type = OSSLParam::try_from(ffi_param).unwrap();
    /// assert_eq!(rich_type.get_key(), Some(c"a_key")); // same as the key defined when `p` was declared
    /// assert_eq!(rich_type.get(), Some(42)); // same as the value defined when `p` was declared
    /// ```
    ///
    pub fn get_c_struct(&self) -> *const OSSL_PARAM {
        match self {
            OSSLParam::Utf8Ptr(d) => d.param,
            OSSLParam::Utf8String(d) => d.param,
            OSSLParam::Int(d) => d.param,
            OSSLParam::UInt(d) => d.param,
            OSSLParam::OctetString(d) => d.param,
        }
    }

    /// Retrieves the C FFI representation of this [`OSSLParam`], regardless of its variant,
    /// as a mutable pointer to [`OSSL_PARAM`].
    ///
    /// This is equivalent to [`OSSLParam::get_c_struct`] and **the same caveats apply**.
    ///
    /// # Return value
    ///
    /// This function returns a **`mut` pointer to [`OSSL_PARAM`]** which can be passed
    /// to OpenSSL functions through the FFI layer.
    ///
    /// > ⚠️ Users of this crate should prefer to read or manipulate _OpenSSL Parameters_ via
    /// > the [`OSSLParam`] Rust abstraction.
    /// >
    /// > **The pointers returned by functions such as this
    /// > are only meant to be used when crossing the FFI boundary**.
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub fn get_c_struct_mut(&mut self) -> *mut OSSL_PARAM {
        match self {
            OSSLParam::Utf8Ptr(d) => d.param,
            OSSLParam::Utf8String(d) => d.param,
            OSSLParam::Int(d) => d.param,
            OSSLParam::UInt(d) => d.param,
            OSSLParam::OctetString(d) => d.param,
        }
    }

    /// Retrieves the [`key` (i.e., the name)][`CONST_OSSL_PARAM::key`]
    /// of this [`OSSLParam`], as a [`Option<&KeyType>`][`KeyType`].
    ///
    /// # Return value
    ///
    /// * Returns `Some(key: &KeyType)` for valid [`OSSLParam`] references.
    /// * It returns `None` if the inner [`key`][`CONST_OSSL_PARAM::key`] field
    ///   is `NULL`,
    ///   which should only happen for the terminating items
    ///   at the end of [`OSSL_PARAM`] lists.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssl_provider_forge::osslparams::*;
    /// use openssl_provider_forge::bindings::OSSL_PARAM;
    ///
    /// # let my_external_param = OSSLParam::new_const_int(c"arbitrary_key", Some(&42));
    /// # let EXTERNAL_OSSL_PARAM_PTR: *const OSSL_PARAM = std::ptr::from_ref(&my_external_param).cast();
    /// // EXTERNAL_OSSL_PARAM_PTR is a `*OSSL_PARAM`, from which
    /// // we create a "rich" OSSLParam Rust object (i.e., `my_param`).
    /// // We can then safely manipulate `my_param` using Rust methods.
    /// let my_param = OSSLParam::try_from(EXTERNAL_OSSL_PARAM_PTR).unwrap();
    ///
    /// let key = my_param.get_key();
    /// println!("Retrieved key: {:?}", key);
    /// assert_eq!(key, Some(c"arbitrary_key"));
    /// ```
    pub fn get_key(&self) -> Option<&KeyType> {
        let cptr: *const OSSL_PARAM = self.get_c_struct();
        if cptr.is_null() {
            return None;
        }
        let r = &(unsafe { *cptr });
        if r.key.is_null() {
            return None;
        }
        let k = unsafe { CStr::from_ptr(r.key) };
        Some(k)
    }

    /// Returns the value of the [`data_type`][`CONST_OSSL_PARAM::data_type`] field
    /// of the underlying [`OSSL_PARAM`] structure.
    ///
    /// # Return value
    ///
    /// > ## 🛠️ TODO
    /// >
    /// > Document in which cases we get `Some(_)` and when the user should expect a `None`
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    pub fn get_data_type(&self) -> Option<u32> {
        let cptr: *const OSSL_PARAM = self.get_c_struct();
        // FIXME: cptr could be NULL
        let r = &(unsafe { *cptr });
        Some(r.data_type)
        // FIXME: should we return None if cptr is NULL or if it is an END item (i.e., its `key` is NULL)?
    }

    /// Checks if this _parameter_ has been modified.
    ///
    /// This function checks if the parameter represented by this [`OSSLParam`]
    /// has been set or updated.
    ///
    /// It corresponds to [OSSL_PARAM_modified(3ossl)].
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    /// [OSSL_PARAM_modified(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM_modified/
    //
    // We achieve this by inspecting the `return_size` field of the underlying C struct:
    // According to OpenSSL documentation, if the `return_size` differs
    // from the constant `OSSL_PARAM_UNMODIFIED`,
    // the parameter is considered to have been modified.
    pub fn modified(&mut self) -> bool {
        // FIXME: could the struct pointer be NULL?
        //        We should always perform check,
        //        or comment on why they are not necessary,
        //        before any unsafe block.
        unsafe { (*self.get_c_struct()).return_size != OSSL_PARAM_UNMODIFIED }
    }

    /// Retrieves the name of the enum variant as a `String`.
    ///
    /// Provides the name of the current variant, such as `"Int"` for `OSSLParam::Int`.
    ///
    /// Mostly we use this internally for debugging purposes.
    ///
    /// # Examples
    ///
    /// > ℹ️ _This method is not `pub`, so we cannot compile these examples._
    /// >
    /// > _Instead their functionality is tested via unit tests._
    ///
    /// ## Get the variant name of a single [`CONST_OSSL_PARAM`]
    ///
    /// ```ignore
    /// # use openssl_provider_forge::osslparams::*;
    /// let param = OSSLParam::new_const_int(c"some_key", Some(&42i64));
    /// let param: OSSLParam = OSSLParam::try_from(&param).unwrap();
    ///
    /// let variant = param.variant_name();
    ///
    /// println!("Variant name: {}", variant); // Outputs: "Int"
    /// assert_eq!(variant, "Int");
    /// ```
    ///
    /// ## Get variant names, iterating over an [`OSSLParam`] list
    ///
    /// ```ignore
    /// use openssl_provider_forge::osslparams::{OSSLParam, CONST_OSSL_PARAM};
    ///
    /// // NOTE: it's very important valid lists of parameters are ALWAYS terminated by END item
    /// let params_list = [
    ///     OSSLParam::new_const_int(c"foo", Some(&1i32)),              // This is an Int
    ///     OSSLParam::new_const_uint(c"bar", Some(&42u64)),            // This is a UInt
    ///     OSSLParam::new_const_utf8string(c"baz", Some(c"a string")), // This is a Utf8String
    ///     CONST_OSSL_PARAM::END
    /// ];
    ///
    /// let params = OSSLParam::try_from(&params_list[0]).unwrap();
    ///
    /// let mut counter = 0;
    /// for p in params {
    ///     let key = p.get_key();
    ///     assert!(key.is_some());
    ///
    ///     let variant = p.variant_name();
    ///
    ///     match counter {
    ///         0 => {
    ///             assert_eq!(variant, "Int");
    ///         },
    ///         1 => {
    ///             assert_eq!(variant, "UInt");
    ///         },
    ///         2 => {
    ///             assert_eq!(variant, "Utf8String");
    ///         },
    ///         _ => unreachable!(),
    ///     }
    ///     counter += 1;
    /// }
    ///
    /// assert_eq!(counter, 3);
    /// assert_eq!(counter, params_list.len() - 1 );
    ///
    /// ```
    fn variant_name(&self) -> String {
        let s = format!("{:?}", self);
        s.split("(")
            .next()
            .unwrap_or_else(|| unreachable!())
            .to_owned()
    }
}

/// A trait for setting type-safe values on the inner data of an [`OSSLParam`] enum.
///
/// This trait ensures type safety when setting values on [`OSSLParam`].
///
/// Modules within [`self::data`] implement this trait on [`OSSLParam`] for
/// various types `T`.
pub trait OSSLParamSetter<T> {
    /// This method sets the inner value for this specific type `T`.
    ///
    /// It checks if the inner variant support values of type `T` before delegating
    /// safely to an inner `set` method.
    ///
    /// # Return values
    ///
    /// It returns an [`OSSLParamError`] if the operation fails, or [`Ok(())`] otherwise.
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    fn set_inner(&mut self, value: T) -> Result<(), OSSLParamError>;
}

/// A trait for safely retrieving type-specific values from an [`OSSLParam`] enum.
///
/// This trait ensures type safety when getting values on [`OSSLParam`].
///
/// Modules within [`self::data`] implement this trait on [`OSSLParam`] for
/// various types `T`.
pub trait OSSLParamGetter<T> {
    /// This method extracts the inner value for this specific type `T`.
    ///
    /// It checks if the inner variant support values of type `T` before delegating
    /// safely to an inner `get` method.
    ///
    /// # Return values
    ///
    /// It returns `Some(T)` if the parameter’s data matches type `T`, otherwise `None`.
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    fn get_inner(&self) -> Option<T>;
}

/// A marker trait for types representing OpenSSL parameter data.
///
/// Provides a common abstraction for OpenSSL parameter types, allowing the use of trait objects
/// and simplifying type management.
///
/// It's implemented by all [`OSSLParam`] data types for consistency and flexibility.
pub trait OSSLParamData {
    /// This function returns an OSSLParam of the given type and using the given key, but setting its value to NULL.
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    fn new_null(key: &KeyType) -> Self
    where
        Self: Sized;
}

/// A trait for typed operations on inner OpenSSL parameter data.
///
/// Extends [`OSSLParamData`] to provide methods for setting values and creating null parameters,
/// ensuring type-safe manipulation of C struct data for parameters storing specific Rust types.
pub trait TypedOSSLParamData<T>: OSSLParamData {
    /// Sets the value of the parameter to the provided type `T`.
    ///
    /// This method updates the [`OSSLParam`] to store the given value, adjusting the
    /// return size accordingly.
    /// It performs type checks to determine if the value can
    /// be safely converted to the target data type ([`i32`] or [`i64`]`, or [`u32`], etc. ).
    ///
    /// # Return values
    ///
    /// It returns an [`OSSLParamError`] if the inner data pointer is `NULL` or the conversion fails,
    /// otherwise `Ok(())`.
    ///
    /// # Examples
    ///
    /// ## TODO(🛠️): add examples
    ///
    fn set(&mut self, value: T) -> Result<(), OSSLParamError>;
}

macro_rules! setter_type_err_string {
    ($param:expr, $value:ident) => {
        format!(
            "Type {} could not be stored in OSSLParam::{}",
            std::any::type_name_of_val(&$value),
            $param.variant_name()
        )
    };
}
pub(crate) use setter_type_err_string;

macro_rules! new_null_param {
    ($constructor:ident, $data_type:ident, $key:expr) => {
        $constructor {
            param: Box::leak(Box::new(crate::bindings::OSSL_PARAM {
                key: $key.as_ptr().cast(),
                data_type: $data_type,
                data: std::ptr::null::<std::ffi::c_void>() as *mut std::ffi::c_void,
                data_size: 0,
                return_size: 0,
            })),
        }
    };
}
pub(crate) use new_null_param;

macro_rules! impl_setter {
    ($t:ty, $variant:ident) => {
        impl<'a> $crate::osslparams::OSSLParamSetter<$t> for OSSLParam<'a> {
            fn set_inner(&mut self, value: $t) -> Result<(), OSSLParamError> {
                if let OSSLParam::$variant(d) = self {
                    d.set(value)
                } else {
                    Err($crate::osslparams::setter_type_err_string!(self, value))
                }
            }
        }
    };
}
pub(crate) use impl_setter;

impl<'a> TryFrom<&mut OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;
    fn try_from(value: &mut OSSL_PARAM) -> Result<Self, Self::Error> {
        OSSLParam::try_from(value as *mut OSSL_PARAM)
    }
}

impl<'a> TryFrom<&CONST_OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;
    fn try_from(value: &CONST_OSSL_PARAM) -> Result<Self, Self::Error> {
        let ptr = std::ptr::from_ref(value);
        OSSLParam::try_from(ptr as *mut OSSL_PARAM)
    }
}

/// Converts a mutable raw pointer ([`*mut OSSL_PARAM`][`OSSL_PARAM`]) into an [`OSSLParam`] enum.
impl<'a> TryFrom<*mut OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;
    /// Ensures the pointer is not null and that the `data_type` matches an expected OpenSSL parameter type.
    ///
    /// # Examples
    ///
    /// ## Converting from a `NULL` pointer
    ///
    /// ```rust
    /// use openssl_provider_forge::bindings::OSSL_PARAM;
    /// use openssl_provider_forge::osslparams::OSSLParam;
    ///
    /// // Assume we have a raw pointer `param_ptr` of type `*mut OSSL_PARAM`.
    /// // For demonstration, we are using a null pointer here:
    /// let param_ptr: *mut OSSL_PARAM = std::ptr::null_mut();
    ///
    /// // Attempt to convert the pointer into an `OSSLParam`.
    /// let ret = OSSLParam::try_from(param_ptr);
    ///
    /// assert!(ret.is_err(), "try_from() should fail because cannot convert from a NULL pointer");
    ///
    /// match ret {
    ///     Ok(param) => unreachable!(),
    ///     Err(e) => println!("Failed to convert: {:?}", e),
    /// }
    /// ```
    ///
    /// ## Converting a valid pointer to [`OSSL_PARAM`]
    ///
    /// ```rust
    /// use openssl_provider_forge::osslparams::*;
    ///
    /// let key = c"arbitrary key";
    /// let mut my_data: i64 = -127;
    ///
    /// let mut raw_param = OSSL_PARAM {
    ///    key: std::ptr::from_ref(key) as *const std::ffi::c_char,
    ///    data_type: OSSL_PARAM_INTEGER,
    ///    data: std::ptr::from_mut(&mut my_data) as *mut std::ffi::c_void,
    ///    data_size: size_of::<i64>(),
    ///    return_size: OSSL_PARAM_UNMODIFIED,
    /// };
    ///
    /// let param_ptr: *mut OSSL_PARAM = std::ptr::from_mut(&mut raw_param);
    ///
    /// // Attempt to convert the pointer into an `OSSLParam`.
    /// let ret = OSSLParam::try_from(param_ptr);
    ///
    /// assert!(ret.is_ok());
    ///
    /// let mut param = match ret {
    ///     Ok(param) => param,
    ///     Err(e) => {
    ///         println!("Failed to convert: {:?}", e);
    ///         unreachable!()
    ///     },
    /// };
    ///
    /// assert_eq!(param.get_key(), Some(c"arbitrary key"));
    /// assert_eq!(param.get(), Some(-127i64));
    /// assert_eq!(my_data, -127);
    ///
    /// // Edit its inner data
    /// assert!(param.set(333i64).is_ok());
    /// assert_eq!(param.get(), Some(333i64));
    ///
    /// // The contents of `my_data` have been changed accordingly as well,
    /// // as `param::data` point at that memory address.
    /// assert_eq!(my_data, 333);
    /// ```
    ///
    fn try_from(p: *mut OSSL_PARAM) -> std::result::Result<Self, Self::Error> {
        match unsafe { p.as_mut() } {
            Some(p) => match p.data_type {
                OSSL_PARAM_UTF8_PTR => Ok(OSSLParam::Utf8Ptr(Utf8PtrData::try_from(
                    p as *mut OSSL_PARAM,
                )?)),
                OSSL_PARAM_UTF8_STRING => Ok(OSSLParam::Utf8String(Utf8StringData::try_from(
                    p as *mut OSSL_PARAM,
                )?)),
                OSSL_PARAM_INTEGER => Ok(OSSLParam::Int(IntData::try_from(p as *mut OSSL_PARAM)?)),
                OSSL_PARAM_UNSIGNED_INTEGER => {
                    Ok(OSSLParam::UInt(UIntData::try_from(p as *mut OSSL_PARAM)?))
                }
                OSSL_PARAM_OCTET_STRING => Ok(OSSLParam::OctetString(OctetStringData::try_from(
                    p as *mut OSSL_PARAM,
                )?)),
                _ => Err("Couldn't convert to OSSLParam from *mut OSSL_PARAM".to_string()),
            },
            None => Err("Couldn't convert to OSSLParam from null pointer".to_string()),
        }
    }
}

/// Converts a raw pointer ([`*const OSSL_PARAM`][`OSSL_PARAM`]) into an [`OSSLParam`] enum.
impl<'a> TryFrom<*const OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;

    /// Ensures the pointer is not null and that the `data_type` matches an expected OpenSSL parameter type.
    ///
    /// # Examples
    ///
    /// ## Converting from a `NULL` pointer
    ///
    /// ```rust
    /// use openssl_provider_forge::bindings::OSSL_PARAM;
    /// use openssl_provider_forge::osslparams::OSSLParam;
    ///
    /// // Assume we have a raw pointer `param_ptr` of type `*mut OSSL_PARAM`.
    /// // For demonstration, we are using a null pointer here:
    /// let param_ptr: *const OSSL_PARAM = std::ptr::null();
    ///
    /// // Attempt to convert the pointer into an `OSSLParam`.
    /// let ret = OSSLParam::try_from(param_ptr);
    ///
    /// assert!(ret.is_err(), "try_from() should fail because cannot convert from a NULL pointer");
    ///
    /// match ret {
    ///     Ok(param) => unreachable!(),
    ///     Err(e) => println!("Failed to convert: {:?}", e),
    /// }
    /// ```
    ///
    /// ## Converting a valid pointer to [`OSSL_PARAM`]
    ///
    /// ```ignore
    /// use openssl_provider_forge::osslparams::*;
    ///
    /// let key = c"arbitrary key";
    /// const MY_DATA: i64 = -127;
    ///
    /// let raw_param = OSSL_PARAM {
    ///    key: std::ptr::from_ref(key) as *const std::ffi::c_char,
    ///    data_type: OSSL_PARAM_INTEGER,
    ///    data: std::ptr::from_ref(&MY_DATA) as *mut std::ffi::c_void,
    ///    data_size: size_of::<i64>(),
    ///    return_size: OSSL_PARAM_UNMODIFIED,
    /// };
    ///
    /// let param_ptr: *const OSSL_PARAM = std::ptr::from_ref(&raw_param);
    ///
    /// // Attempt to convert the pointer into an `OSSLParam`.
    /// let ret = OSSLParam::try_from(param_ptr);
    ///
    /// assert!(ret.is_ok());
    ///
    /// let mut param = match ret {
    ///     Ok(param) => param,
    ///     Err(e) => {
    ///         println!("Failed to convert: {:?}", e);
    ///         unreachable!()
    ///     },
    /// };
    ///
    /// assert_eq!(param.get_key(), Some(c"arbitrary key"));
    /// assert_eq!(param.get(), Some(-127i64));
    /// assert_eq!(MY_DATA, -127);
    ///
    /// // Try to edit its inner data
    /// assert!(param.set(333i64).is_err(), "This should fail with SEGFAULT, because `param::data` points to read-only memory");
    /// assert_eq!(param.get(), Some(-127i64));
    ///
    /// // The contents of `MY_DATA` cannot be changed!
    /// assert_eq!(MY_DATA, -127);
    /// ```
    ///
    fn try_from(p: *const OSSL_PARAM) -> std::result::Result<Self, Self::Error> {
        let m = p as *mut OSSL_PARAM;
        OSSLParam::try_from(m)
    }
}

impl<'a> From<&mut OSSLParam<'a>> for *mut OSSL_PARAM {
    fn from(val: &mut OSSLParam<'a>) -> Self {
        match val {
            OSSLParam::Utf8Ptr(d) => d.param as *mut OSSL_PARAM,
            OSSLParam::Utf8String(d) => d.param as *mut OSSL_PARAM,
            OSSLParam::Int(d) => d.param as *mut OSSL_PARAM,
            OSSLParam::UInt(d) => d.param as *mut OSSL_PARAM,
            OSSLParam::OctetString(d) => d.param as *mut OSSL_PARAM,
        }
    }
}

impl<'a> From<&OSSLParam<'a>> for *const OSSL_PARAM {
    fn from(val: &OSSLParam<'a>) -> Self {
        match val {
            OSSLParam::Utf8Ptr(d) => d.param as *const OSSL_PARAM,
            OSSLParam::Utf8String(d) => d.param as *const OSSL_PARAM,
            OSSLParam::Int(d) => d.param as *const OSSL_PARAM,
            OSSLParam::UInt(d) => d.param as *const OSSL_PARAM,
            OSSLParam::OctetString(d) => d.param as *const OSSL_PARAM,
        }
    }
}

impl<'a> From<OSSLParam<'a>> for *mut OSSL_PARAM {
    fn from(mut val: OSSLParam<'a>) -> Self {
        (&mut val).into()
    }
}

impl<'a> From<OSSLParam<'a>> for *const OSSL_PARAM {
    fn from(val: OSSLParam<'a>) -> Self {
        (&val).into()
    }
}

impl OSSL_PARAM {
    /// Represents the end marker for an OpenSSL parameter list.
    pub const END: Self = Self {
        key: std::ptr::null(),
        data_type: 0,
        data: std::ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    };
}

/// Provides an end-of-parameter list marker for [OSSL_PARAM] arrays
/// to terminate them.
pub const OSSL_PARAM_END: OSSL_PARAM = OSSL_PARAM::END;

/// A single-element array containing the [OSSL_PARAM_END] marker.
/// Used to represent an empty parameter list in OpenSSL operations.
pub const EMPTY_PARAMS: [OSSL_PARAM; 1] = [OSSL_PARAM_END];

/// An iterator for a properly END-terminated sequence of [`OSSL_PARAM`]s.
///
/// **⚠ WARNING**: this implementation assumes the list is properly terminated with an END item.
///
/// # Examples
///
/// ```rust
/// use openssl_provider_forge::osslparams::*;
/// use std::ffi::CStr;
///
/// // NOTE: it's very important valid lists of parameters are ALWAYS terminated by END item
/// let params_list = [
///     OSSLParam::new_const_int(c"foo", Some(&1i32)),
///     OSSLParam::new_const_uint(c"bar", Some(&42u64)),
///     OSSLParam::new_const_utf8string(c"baz", Some(c"a string")),
///     CONST_OSSL_PARAM::END
/// ];
///
/// let first = params_list.first().unwrap();
/// let p = OSSLParam::try_from(first).unwrap();
///
/// // here we explicitly get an `OSSLParamIterator`,
/// // but we can also directly iterate over
/// // an `OSSLParam as it implements `IntoIterator`:
/// // e.g., `for i in p { todo!("do something with _i_"); }`.
/// let iterator: OSSLParamIterator = p.into_iter();
///
/// let mut counter = 0;
/// for i in iterator {
///     let key = i.get_key();
///     assert!(key.is_some());
///
///     match counter {
///         0 => {
///             assert_eq!(key, Some(c"foo"));
///             assert_eq!(i.get::<i32>(), Some(1));
///         },
///         1 => {
///             assert_eq!(key, Some(c"bar"));
///             assert_eq!(i.get::<u64>(), Some(42));
///         },
///         2 => {
///             assert_eq!(key, Some(c"baz"));
///             assert_eq!(i.get::<&CStr>(), Some(c"a string"));
///         },
///         _ => unreachable!(),
///     }
///     counter += 1;
/// }
///
/// assert_eq!(counter, 3);
/// assert_eq!(counter, params_list.len() - 1 );
/// ```
///
/// ## Idiomatic `for` loops via [`IntoIterator`]
///
/// [`OSSLParam`] implements [`IntoIterator`], returning a [`OSSLParamIterator`]
/// so it is possible to directly do a
/// `for` loop given an [`OSSLParam`] variable,
/// **assuming it belongs to a properly END-terminated list**.
///
/// ```rust
/// use openssl_provider_forge::osslparams::*;
///
/// // NOTE: it's very important valid lists of parameters are ALWAYS terminated by END item
/// let params_list = [
///     OSSLParam::new_const_int(c"foo", Some(&1i32)),
///     OSSLParam::new_const_int(c"bar", Some(&42i32)),
///     OSSLParam::new_const_int(c"baz", Some(&-1i32)),
///     CONST_OSSL_PARAM::END
/// ];
///
/// let params = OSSLParam::try_from(&params_list[0]).unwrap();
///
/// let mut sum = 0;
/// for p in params {
///     let key = p.get_key();
///     assert!(key.is_some());
///
///     let v = p.get::<i32>().unwrap();
///     sum += v;
/// }
///
/// assert_eq!(sum, 42);
/// ```
///
pub struct OSSLParamIterator<'a> {
    ptr: *mut OSSL_PARAM,
    phantom: PhantomData<OSSLParam<'a>>,
}

impl OSSLParamIterator<'_> {
    fn new(ptr: *const OSSL_PARAM) -> Self {
        OSSLParamIterator {
            ptr: ptr as *mut OSSL_PARAM,
            phantom: PhantomData,
        }
    }
}

impl<'a> Iterator for OSSLParamIterator<'a> {
    type Item = OSSLParam<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match unsafe { self.ptr.as_ref() } {
            Some(p) => {
                if p.key.is_null() {
                    // we've reached OSSL_PARAM_END
                    return None;
                }
                let param = OSSLParam::try_from(self.ptr);
                self.ptr = unsafe { self.ptr.offset(1) };
                param.ok()
            }
            None => return None,
        }
    }
}

/// [`OSSLParam`] implements [`IntoIterator`], so it is possible to directly do a
/// for loop given an [`OSSLParam`] variable,
/// **assuming it belongs to a properly END-terminated list**.
///
/// # Example
///
/// ```rust
/// use openssl_provider_forge::osslparams::{OSSLParam, CONST_OSSL_PARAM, OSSLParamGetter};
/// use std::ffi::CStr;
///
/// // NOTE: it's very important valid lists of parameters are ALWAYS terminated by END item
/// let params_list = [
///     OSSLParam::new_const_int(c"foo", Some(&1i32)),
///     OSSLParam::new_const_uint(c"bar", Some(&42u64)),
///     OSSLParam::new_const_utf8string(c"baz", Some(c"a string")),
///     CONST_OSSL_PARAM::END
/// ];
///
/// let params = OSSLParam::try_from(&params_list[0]).unwrap();
///
/// let mut counter = 0;
/// for p in params {
///     let key = p.get_key();
///     assert!(key.is_some());
///
///     match counter {
///         0 => {
///             assert_eq!(key, Some(c"foo"));
///             assert_eq!(p.get::<i32>(), Some(1));
///         },
///         1 => {
///             assert_eq!(key, Some(c"bar"));
///             assert_eq!(p.get::<u64>(), Some(42));
///         },
///         2 => {
///             assert_eq!(key, Some(c"baz"));
///             assert_eq!(p.get::<&CStr>(), Some(c"a string"));
///         },
///         _ => unreachable!(),
///     }
///     counter += 1;
/// }
///
/// assert_eq!(counter, 3);
/// assert_eq!(counter, params_list.len() - 1 );
/// ```
///
impl<'a> IntoIterator for OSSLParam<'a> {
    type Item = Self;
    type IntoIter = OSSLParamIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        OSSLParamIterator::new(self.get_c_struct())
    }
}

/// This type has exactly the same C representation as [`OSSL_PARAM`] ([OSSL_PARAM(3ossl)])
/// but we
/// explicitly implement [Send] and [Sync] traits for it, as we only represent immutable static
/// params with this type which are safe to be passed around threads (as they
/// can never be written at runtime, but only read).
///
/// [OSSL_PARAM(3ossl)]: https://docs.openssl.org/master/man3/OSSL_PARAM/
///
/// # NOTES (from [OSSL_PARAM(3ossl)])
///
/// > The key names and associated types are defined by the entity that offers
/// > these parameters, i.e. names for parameters provided by the OpenSSL
/// > libraries are defined by the libraries, and names for parameters provided by
/// > providers are defined by those providers, except for the pointer form of
/// > strings (see data type descriptions below).
/// >
/// > Entities that want to set or
/// > request parameters need to know what those keys are and of what type, any
/// > functionality between those two entities should remain oblivious and just
/// > pass the `OSSL_PARAM` array along.
///
/// > Both when setting and requesting parameters, the functions that are called
/// > will have to decide what is and what is not an error.
/// > The recommended behaviour is:
/// >
/// > * Keys that a _setter_ or _responder_ doesn't recognise should simply be
/// >   ignored. That in itself isn't an error.
/// > * If the keys that a called _setter_ recognises form a consistent enough
/// >   set of data, that call should succeed.
/// > * Apart from the [`Self::return_size`], a responder must never change the
/// >   fields of an `OSSL_PARAM`.
/// >   To return a value, it should change the contents of
/// >   the memory that [`Self::data`] points at.
/// > * If the data type for a key that it's associated with is incorrect, the
/// >   called function may return an error.
/// >
/// > The called function may also try to convert the data to a suitable form
/// > (for example, it's plausible to pass a large number as an octet string, so
/// > even though a given key is defined as an [`OSSL_PARAM_UNSIGNED_INTEGER`],
/// > is plausible to pass the value as an [`OSSL_PARAM_OCTET_STRING`]),
/// > but this is in no way mandatory.
/// >
/// > * If [`Self::data`] for a [`OSSL_PARAM_OCTET_STRING`] or a
/// >   [`OSSL_PARAM_UTF8_STRING`] is `NULL`, the _responder_ should set
/// >   [`Self::return_size`] to the size of the item to be returned and return
/// >   success.
/// >   Later the _responder_ will be called again with [`Self::data`] pointing at
/// >   the place for the value to be put.
/// > * If a _responder_ finds that some data sizes are too small for the
/// >   requested data, it must set [`Self::return_size`] for each such [`OSSL_PARAM`]
/// >   item to the minimum required size, and eventually return an error.
/// > * For the integer type parameters ([`OSSL_PARAM_UNSIGNED_INTEGER`] and
/// >   [`OSSL_PARAM_INTEGER`]), a _responder_ may choose to return an error if the
/// >   [`Self::data_size`] isn't a suitable size (even if [`Self::data_size`] is
/// >   bigger than needed).
/// >   If the _responder_ finds the size suitable, it must
/// >   fill all [`Self::data_size`] bytes and ensure correct padding for the native
/// >   endianness, and set [`Self::return_size`] to the same value as
/// >   [`Self::data_size`].
///
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct CONST_OSSL_PARAM {
    /// name of the parameter
    ///
    /// > The identity of the parameter in the form of a string.
    /// >
    /// > In an [`OSSL_PARAM`] array, an item with this field set to `NULL` is considered a terminating item.
    pub key: *const ::std::os::raw::c_char,

    /// declare what kind of content is in data
    ///
    /// > ## ️🛠️ TODO: quote details from [manpage](https://docs.openssl.org/master/man3/OSSL_PARAM/)
    pub data_type: ::std::os::raw::c_uint,

    /// value being passed in or out
    ///
    /// > ## ️🛠️ TODO: quote details from [manpage](https://docs.openssl.org/master/man3/OSSL_PARAM/)
    pub data: *const ::std::os::raw::c_void,

    /// data size
    ///
    /// > ## ️🛠️ TODO: quote details from [manpage](https://docs.openssl.org/master/man3/OSSL_PARAM/)
    pub data_size: usize,

    /// returned size
    ///
    /// > When an array of `OSSL_PARAM` is used to request data, the _responder_
    /// > must set this field to indicate size of the parameter data, including
    /// > padding as the case may be. In case the [`Self::data_size`] is an unsuitable size
    /// > for the data, the _responder_ must still set this field to indicate the
    /// > minimum data size required. (further notes on this in "NOTES").
    ///
    /// > When the OSSL_PARAM is used as a parameter descriptor, return_size
    /// > should be ignored.
    pub return_size: usize,
}

// SAFETY: This is only valid if the C API guarantees that the data pointed by the inner pointers is actually immutable and thread-safe.
unsafe impl Send for CONST_OSSL_PARAM {}
unsafe impl Sync for CONST_OSSL_PARAM {}

/// [`CONST_OSSL_PARAM`] implements [`std::ops::Deref`], so we
/// can deref [`&CONST_OSSL_PARAM`][`CONST_OSSL_PARAM`] into a [`&OSSL_PARAM`][`OSSL_PARAM`]
///
/// # Examples
///
/// ```rust
/// use openssl_provider_forge::osslparams::*;
///
/// // NOTE: it's very important valid lists of parameters are ALWAYS terminated by END item
/// let params_list = [
///     OSSLParam::new_const_int(c"foo", Some(&1i32)),
///     CONST_OSSL_PARAM::END
/// ];
///
/// let c: CONST_OSSL_PARAM = params_list[0];
///
/// // We can deref `c` directly into a `&OSSL_PARAM`
/// let t: &OSSL_PARAM = &c;
/// ```
///
impl std::ops::Deref for CONST_OSSL_PARAM {
    type Target = OSSL_PARAM;

    fn deref(&self) -> &Self::Target {
        let ptr: *const Self = std::ptr::from_ref(self);
        assert!(!ptr.is_null());
        let ptr: *const Self::Target = ptr as *const Self::Target;
        unsafe { &*ptr }
    }
}

impl From<&CONST_OSSL_PARAM> for *const OSSL_PARAM {
    fn from(param: &CONST_OSSL_PARAM) -> Self {
        param as *const CONST_OSSL_PARAM as *const OSSL_PARAM
    }
}

impl CONST_OSSL_PARAM {
    /// Represents the end marker for a [`CONST_OSSL_PARAM`] list.
    pub const END: Self = Self {
        key: std::ptr::null(),
        data_type: 0,
        data: std::ptr::null(),
        data_size: 0,
        return_size: 0,
    };
}
