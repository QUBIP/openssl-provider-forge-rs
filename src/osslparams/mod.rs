#![warn(missing_docs)]
//! The `OSSLParam` module provides types and functionality for working with OpenSSL parameters.
//!
//! It includes various utilities for handling data types such as integers, unsigned integers, and
//! UTF-8 pointers, enabling type-safe manipulation of OpenSSL parameter structures.
use crate::bindings::{
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use std::{ffi::CStr, marker::PhantomData};

pub mod data;

#[cfg(test)]
mod tests;

// List of supported types: https://docs.openssl.org/master/man3/OSSL_PARAM/#supported-types
/// The `OSSLParam` enum represents different parameter data types used by OpenSSL.
///
/// Each variant of `OSSLParam` corresponds to a specific parameter data type and wraps
/// a corresponding struct type (`IntData`, `UIntData`, `Utf8PtrData`). This allows for
/// storing different struct types in a collection together, simplifying operations on
/// various parameter types in a unified way.
#[derive(Debug)]
pub enum OSSLParam<'a> {
    /// represents a `Utf8Ptr` parameter.
    ///
    /// wraps a `utf8ptrdata` struct that handles the `utf8ptr` data type.
    Utf8Ptr(Utf8PtrData<'a>),
    /// represents a `Utf8PtrStringData` parameter.
    ///
    /// wraps a `Utf8PtrStringData` struct that handles the `Utf8PtrStringData` data type.
    Utf8String(Utf8StringData<'a>),
    /// Represents an `Integer` parameter.
    ///
    /// Wraps an `IntData` struct that handles the `Integer` data type.
    Int(IntData<'a>),
    /// Represents an `Unsigned Integer` parameter.
    ///
    /// Wraps an `UIntData` struct that handles the `Unsigned Integer` data type.
    UInt(UIntData<'a>),
    /// represents a `OctetStringData` parameter.
    ///
    /// wraps a `OctetStringData` struct that handles the `OctetStringData` data type.
    OctetString(OctetStringData<'a>),
}

impl<'a> OSSLParam<'a> {
    /// Creates a new constant OpenSSL parameter with a UTF-8 string pointer.
    /// Pass None as the value to get a NULL OSSL_PARAM with given key and type
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
    /// Creates a new constant OpenSSL parameter from a UTF-8 string.
    /// Pass None as the value to get a NULL OSSL_PARAM with given key and type
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
    /// Creates a new constant OpenSSL parameter from an integer value.
    /// Pass None as the value to get a NULL OSSL_PARAM with given key and type
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
    /// Creates a new constant OpenSSL parameter from an unsigned integer value.
    /// Pass None as the value to get a NULL OSSL_PARAM with given key and type
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
    /// Creates a new constant OpenSSL parameter from an octet string.
    /// Pass None as the value to get a NULL OSSL_PARAM with given key and type
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
}

/// Handles the `Utf8Ptr` data type and contains a field `param`,
/// which is a `C` structure from OpenSSL using `bindgen`.
#[derive(Debug)]
pub struct Utf8PtrData<'a> {
    param: &'a mut OSSL_PARAM,
}

/// Holds a mutable reference to an OpenSSL `OSSL_PARAM` representing a UTF-8 string.
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

/// Handles the `Integer` data type and contains a field `param`,
/// which is a `C` structure from OpenSSL using `bindgen`.
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

/// This Rust structure handles `Unsigned Integer` data type and contains a single field `param`
/// which is actually a `C` structure coming from OpenSSL using `bindgen`.
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
/// Holds a mutable reference to an OpenSSL `OSSL_PARAM` representing an octet string.
pub struct OctetStringData<'a> {
    param: &'a mut OSSL_PARAM,
}

/// A type alias for errors related to OpenSSL parameters.
///
/// `OSSLParamError` is represented by a `String`, typically used for returning
/// descriptive error messages in operations involving `OSSLParam`.
pub type OSSLParamError = String;

/// This is the type used by OpenSSL bindings to represent the `key` field of an `OSSL_PARAM`.
///
/// `KeyType` is represented as [`CStr`] (which provides a Rust interface to C-style strings).
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
    /// Sets the value of the parameter to the provided type `T`.
    ///
    /// Updates the `OSSLParam` to store the given value, adjusting the return size accordingly.
    /// Performs type checks to ensure the value can be safely converted to the target data type
    /// (`i32`, `i64`, `u32`, etc.). If the data pointer is `NULL` or the conversion fails,
    /// an appropriate error is returned.
    pub fn set<T>(&mut self, value: T) -> Result<(), OSSLParamError>
    where
        Self: OSSLParamSetter<T>,
    {
        self.set_inner(value)
    }

    /// Extracts the inner value from `OSSLParam` if it matches the expected type.
    ///
    /// The `get` function acts as a convenience wrapper around `get_inner`, providing
    /// a simple and consistent way to extract the inner value if the `OSSLParam` matches
    /// the expected type. Returns `Some(T)` if the value matches the type, otherwise returns `None`.
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

    /// Retrieves the `param` field from the inner data of the `OSSLParam` enum, regardless of its variant.
    ///
    /// The `get_c_struct` function retrieves the `param`field from the inner data of enum,
    /// regardless of the variant (e.g., `Utf8Ptr`, `Int`, or `UInt`).
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

    /// Returns a mutable pointer to the underlying OpenSSL `OSSL_PARAM` structure,
    /// allowing direct modification of the parameter in OpenSSL operations.
    pub fn get_c_struct_mut(&mut self) -> *mut OSSL_PARAM {
        match self {
            OSSLParam::Utf8Ptr(d) => d.param,
            OSSLParam::Utf8String(d) => d.param,
            OSSLParam::Int(d) => d.param,
            OSSLParam::UInt(d) => d.param,
            OSSLParam::OctetString(d) => d.param,
        }
    }

    /// Retrieves the key associated with the `OSSLParam` as a reference to `KeyType`.
    ///
    /// The `get_key`function retrieves the key associated with the `OSSLParam` as a reference to `KeyType`.
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

    /// Returns the data type of the underlying OpenSSL `OSSL_PARAM` structure.
    pub fn get_data_type(&self) -> Option<u32> {
        let cptr: *const OSSL_PARAM = self.get_c_struct();
        let r = &(unsafe { *cptr });
        Some(r.data_type)
    }

    // corresponds to OSSL_PARAM_modified()
    /// Checks if the parameter has been modified.
    ///
    /// The `modified` function checks if the parameter represented by the `OSSLParam` has been set,
    /// by inspecting the `return_size` field of the underlying C struct. If the `return_size` differs
    /// from the constant `OSSL_PARAM_UNMODIFIED`, the parameter is considered to have been modified.
    #[allow(dead_code)]
    pub fn modified(&mut self) -> bool {
        unsafe { (*self.get_c_struct()).return_size != OSSL_PARAM_UNMODIFIED }
    }

    /// Retrieves the name of the enum variant as a `String`.
    ///
    /// Provides the name of the current variant, such as `"Int"` for `OSSLParam::Int`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let param = OSSLParam::Int(42);
    /// let variant = param.variant_name();
    /// println!("Variant name: {}", variant); // Outputs: "Int"
    /// ```
    fn variant_name(&self) -> String {
        let s = format!("{:?}", self);
        s.split("(")
            .next()
            .unwrap_or_else(|| unreachable!())
            .to_owned()
    }
}

/// A trait for setting type-safe values on the inner data of an `OSSLParam` enum.
///
/// The `OSSLParamSetter` trait ensures type safety when setting values on `OSSLParam`.
/// The `set_inner` function verifies the correct variant for type `T` and delegates
/// the operation to the inner data struct's `set` method.
pub trait OSSLParamSetter<T> {
    /// The `set_inner` function verifies the correct variant for type `T` and delegates
    /// the operation to the inner data struct's `set` method.
    fn set_inner(&mut self, value: T) -> Result<(), OSSLParamError>;
}

/// A trait for safely retrieving type-specific values from the `OSSLParam` enum.
///
/// The `OSSLParamGetter` trait provides a method `get_inner` to extract the inner value.
/// It returns `Some(T)` if the parameter’s data matches type `T`, otherwise `None`.
pub trait OSSLParamGetter<T> {
    /// The `get_inner` function extracts the inner value for this type.
    /// It returns `Some(T)` if the parameter’s data matches type `T`, otherwise `None`.
    fn get_inner(&self) -> Option<T>;
}

/// A marker trait for types representing OpenSSL parameter data.
///
/// `OSSLParamData` provides a common abstraction for OpenSSL parameter types, allowing the use of trait objects
/// and simplifying type management. Implemented by all `OSSLParam` data types for consistency and flexibility.
pub trait OSSLParamData {
    /// This function returns an OSSLParam of the given type and using the given key, but setting its value to NULL.
    fn new_null(key: &KeyType) -> Self
    where
        Self: Sized;
}

/// A trait for typed operations on inner OpenSSL parameter data.
///
/// Extends `OSSLParamData` to provide methods for setting values and creating null parameters,
/// ensuring type-safe manipulation of C struct data for parameters storing specific Rust types.
pub trait TypedOSSLParamData<T>: OSSLParamData {
    /// Sets the value of the parameter to the provided type `T`.
    ///
    /// The `set` function updates the `OSSLParam` to store the given value, adjusting the
    /// return size accordingly. It performs type checks to determine if the value can
    /// be safely converted to the target data type (`i32` or `i64, or u23, ...`). If the data pointer
    /// is `NULL` or the conversion fails, an appropriate error is returned.
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

/// Converts a raw pointer (`*mut OSSL_PARAM`) into an `OSSLParam` enum.
impl<'a> TryFrom<*mut OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;
    /// Ensures the pointer is not null and that the `data_type` matches an expected OpenSSL parameter type.
    ///
    /// # Examples
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
    /// assert!(ret.is_err()); // should fail because cannot convert from a null pointer
    ///
    /// match ret {
    ///     Ok(param) => println!("Successfully converted to OSSLParam."),
    ///     Err(e) => println!("Failed to convert: {:?}", e),
    /// }
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

impl<'a> TryFrom<*const OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;
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

/// Provides an end-of-parameter list marker for `OSSL_PARAM` arrays.
/// Used to terminate `OSSL_PARAM` arrays, indicating the end of the parameter list.
pub const OSSL_PARAM_END: OSSL_PARAM = OSSL_PARAM::END;

/// A single-element array containing the `OSSL_PARAM_END` marker.
/// Used to represent an empty parameter list in OpenSSL operations.
pub const EMPTY_PARAMS: [OSSL_PARAM; 1] = [OSSL_PARAM_END];

/*
 * core::ffi:c_size_t is only in nightly, and unstable
 *
 * https://github.com/rust-lang/rust/issues/88345 seems to have stalled,
 * so for now we just assume c_size_t and usize are the same.
 *
 * TODO: revisit if c_size_t goes stable
 */
// const OSSL_PARAM_UNMODIFIED: usize = core::ffi::c_size_t::MAX;
const OSSL_PARAM_UNMODIFIED: usize = usize::MAX;

/// An iterator over a sequence of OpenSSL `OSSL_PARAM` structures.
/// Allows traversal of parameters using a raw pointer, with lifetime tracking via `PhantomData`.
///
/// # Examples
///
/// ```rust
/// use openssl_provider_forge::osslparams::{OSSLParam, OSSLParamIterator, CONST_OSSL_PARAM, OSSLParamGetter};
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
/// // here we explicitly get an OSSLParamIterator,
/// // but we can also directly iterate over
/// // an OSSLParam as it implements IntoIterator:
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
///     counter = counter + 1;
/// }
///
/// assert_eq!(counter, 3);
/// assert_eq!(counter, params_list.len() - 1 );
///
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

/// OSSLParam implements IntoIterator, so it is possible to directly do a
/// for loop given an OSSLParam variable.
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
///     counter = counter + 1;
/// }
///
/// assert_eq!(counter, 3);
/// assert_eq!(counter, params_list.len() - 1 );
///
/// ```
///
impl<'a> IntoIterator for OSSLParam<'a> {
    type Item = Self;
    type IntoIter = OSSLParamIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        OSSLParamIterator::new(self.get_c_struct())
    }
}

/// This struct holds a key-value pair along with metadata describing the parameter's type,
/// size, and the memory location of the data.
/// It is commonly used when interacting with OpenSSL APIs that require parameter lists.
///
/// # NOTE
///
/// This has exactly the same C representation as bindings::OSSL_PARAM but we
/// explicitly implement Send and Sync traits for it, as we only represent immutable static
/// params with this type which are safe to be passed around threads (as they
/// can never be written at runtime, but only read)
///
/// # 🔧 **TODO**
///
/// - [ ] copy doc from <https://docs.openssl.org/master/man3/OSSL_PARAM/> for each field
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct CONST_OSSL_PARAM {
    /// name of the parameter.
    pub key: *const ::std::os::raw::c_char,
    /// The type of the data (e.g., string, integer) represented by the parameter.
    pub data_type: ::std::os::raw::c_uint,
    /// A pointer to the actual data, which can be of varying types based on `data_type`.
    pub data: *const ::std::os::raw::c_void,
    /// The size of the data in bytes.
    pub data_size: usize,
    /// The size of the data returned after the operation, typically used for output buffers.
    pub return_size: usize,
}

// SAFETY: This is only valid if the C API guarantees that the data pointed by the inner pointers is actually immutable and thread-safe.
unsafe impl Send for CONST_OSSL_PARAM {}
unsafe impl Sync for CONST_OSSL_PARAM {}

impl std::ops::Deref for CONST_OSSL_PARAM {
    type Target = OSSL_PARAM;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self as *const Self as *const Self::Target) }
    }
}

impl From<&CONST_OSSL_PARAM> for *const OSSL_PARAM {
    fn from(param: &CONST_OSSL_PARAM) -> Self {
        param as *const CONST_OSSL_PARAM as *const OSSL_PARAM
    }
}

impl CONST_OSSL_PARAM {
    /// Represents the end marker for OpenSSL parameters.
    pub const END: Self = Self {
        key: std::ptr::null(),
        data_type: 0,
        data: std::ptr::null(),
        data_size: 0,
        return_size: 0,
    };
}
