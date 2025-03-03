#![warn(missing_docs)]
//! The `OSSLParam` module provides types and functionality for working with OpenSSL parameters.
//!
//! It includes various utilities for handling data types such as integers, unsigned integers, and
//! UTF-8 pointers, enabling type-safe manipulation of OpenSSL parameter structures.

use std::{ffi::CStr, marker::PhantomData};

use crate::bindings::{
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};

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
    pub fn new_const_utf8ptr(key: &'a KeyType, value: &'a CStr) -> CONST_OSSL_PARAM {
        let _ = value;
        let _ = key;
        todo!()
    }

    /// Creates a new constant OpenSSL parameter from a UTF-8 string.
    pub const fn new_const_utf8string(key: &'a KeyType, value: &'a CStr) -> CONST_OSSL_PARAM {
        let vl = value.count_bytes();
        let v = value.as_ptr() as *mut std::ffi::c_void;
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_UTF8_STRING,
            data: v,
            data_size: vl,
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    /// Creates a new constant OpenSSL parameter from an integer value.
    pub const fn new_const_int<T>(key: &'a KeyType, value: &'a T) -> CONST_OSSL_PARAM
    where
        T: crate::osslparams::data::int::PrimIntMarker,
    {
        let v = std::ptr::from_ref(value);
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_INTEGER,
            data: v as *mut std::ffi::c_void,
            data_size: size_of::<T>(),
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    /// Creates a new constant OpenSSL parameter from an unsigned integer value.
    pub const fn new_const_uint<T>(key: &'a KeyType, value: &'a T) -> CONST_OSSL_PARAM
    where
        T: crate::osslparams::data::uint::PrimUIntMarker,
    {
        let v = std::ptr::from_ref(value);
        CONST_OSSL_PARAM {
            key: key.as_ptr().cast(),
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            data: v as *mut std::ffi::c_void,
            data_size: size_of::<T>(),
            return_size: OSSL_PARAM_UNMODIFIED,
        }
    }

    /// Creates a new constant OpenSSL parameter from an octet string.
    pub fn new_const_octetstring(key: &'a KeyType, value: &'a [i8]) -> CONST_OSSL_PARAM {
        let _ = key;
        let _ = value;
        todo!()
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

/// A type alias for keys used in OpenSSL parameters.
///
/// `KeyType` is represented by [`CStr`], which provides an interface to C-style strings.
///
/// # Examples
///
/// ```rust
/// use rust_openssl_core_provider::osslparams::KeyType;
/// use std::ffi::CStr;
///
/// let key: KeyType = CStr::c"my_key".unwrap();
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
    /// let param = OSSLParam::Int(42);
    /// let inner_param = param.get_c_struct();
    /// println!("Retrieved param: {:?}", inner_param);
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
    /// # Examples
    ///
    /// ```rust
    /// let key = my_param.get_key();
    /// println!("Retrieved key: {:?}", key);
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

    // right now this method is just here to show we can return &dyn OSSLParamData if we need it

    /// Returns a reference to the inner content of any `OSSLParam` variant through a common interface.
    ///
    /// The `inner_data` function returns a reference to the inner data of the `OSSLParam` enum as a `&dyn`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let param = OSSLParam::Int(42);
    /// let data = param.inner_data();
    /// // `data` can now be used via the `OSSLParamData` trait.
    /// println!("Accessed inner data: {:?}", data);
    /// ```
    ///
    #[allow(dead_code)]
    fn inner_data(&self) -> &dyn OSSLParamData {
        match self {
            OSSLParam::Utf8Ptr(d) => d,
            OSSLParam::Utf8String(d) => d,
            OSSLParam::Int(d) => d,
            OSSLParam::UInt(d) => d,
            OSSLParam::OctetString(d) => d,
        }
    }
    /// Retrieves the name of the enum variant as a `String`.
    ///
    /// Provides the name of the current variant, such as `"Int"` for `OSSLParam::Int`.
    ///
    /// # Examples
    ///
    /// ```rust
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
    /// Sets the value of the parameter if it matches the correct variant.
    ///
    /// Matches the `OSSLParam` variant (e.g., `Utf8Ptr`, `Int`, `UInt`) and sets the value if the type matches.
    /// Returns `Ok(c_int)` on success, or `Err(String)` if the type does not match.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut param = OSSLParam::Int(0);
    /// match param.set_inner(100) {
    ///     Ok(_) => println!("Value set successfully."),
    ///     Err(e) => println!("Failed to set value: {}", e),
    /// }
    /// ```
    fn set_inner(&mut self, value: T) -> Result<(), OSSLParamError>;
}

/// A trait for safely retrieving type-specific values from the `OSSLParam` enum.
///
/// The `OSSLParamGetter` trait provides a method `get_inner` to extract the inner value.
/// It returns `Some(T)` if the parameter’s data matches type `T`, otherwise `None`.
pub trait OSSLParamGetter<T> {
    /// Retrieves the inner value if the `OSSLParam` variant matches.
    ///
    /// The `get_inner` function extracts the inner value if the `OSSLParam` matches the
    /// expected variant (e.g., `Int`, `UInt`, `Utf8Ptr`). Returns `Some(T)` if the type matches,
    /// otherwise returns `None`
    ///
    /// # Examples
    ///
    /// ```rust
    /// let param = MyParam::Int(42);
    ///
    /// if let Some(value) = param.get_inner() {
    ///     println!("Retrieved value: {}", value);
    /// } else {
    ///     println!("The type did not match or could not retrieve value.");
    /// }
    /// ```
    ///
    fn get_inner(&self) -> Option<T>;
}

/// A marker trait for types representing OpenSSL parameter data.
///
/// `OSSLParamData` provides a common abstraction for OpenSSL parameter types, allowing the use of trait objects
/// and simplifying type management. Implemented by all `OSSLParam` data types for consistency and flexibility.
pub trait OSSLParamData {
    /// Creates a new instance of the parameter with default or null values.
    ///
    /// This function initializes an `OSSLParam` with default values that represent an uninitialized or null state.
    /// It is useful when a parameter needs to be created without an initial value, allowing it to be set later.
    /// # Examples
    ///
    /// ```rust
    /// // Assume KeyType is some type that represents a key for the parameter.
    /// let key: KeyType = KeyType::new("example_key");
    ///
    /// // Create a new instance of OSSLParam with a null value.
    /// let param = OSSLParam::new_null(&key);
    ///
    /// // The `param` is now initialized with a null value, ready to be assigned later.
    /// println!("Parameter with key '{}' created with null value.", key);
    /// ```
    ///
    /// # Explanation
    /// - The `new_null` function takes a reference to a `KeyType` as input and uses it to initialize the `param` field.
    /// - It creates an instance of `IntData` (or any other relevant data type) with `data` set to null (`std::ptr::null()`).
    /// - This means the parameter is created but has no initial data assigned—it's essentially a placeholder.
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

/// Converts a raw pointer (`*mut ossl_param_st`) into an `OSSLParam` enum.
impl<'a> TryFrom<*mut OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;

    /// Ensures the pointer is not null and that the `data_type` matches an expected OpenSSL parameter type.
    /// # Examples
    ///
    /// ```rust
    /// use osslparams::OSSLParam;
    ///
    /// // Assume we have a raw pointer `param_ptr` of type `*mut ossl_param_st`.
    /// // For demonstration, we are using a null pointer here:
    /// let param_ptr: *mut ossl_param_st = std::ptr::null_mut();
    ///
    /// // Attempt to convert the pointer into an `OSSLParam`.
    /// match OSSLParam::try_from(param_ptr) {
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
///
/// # Examples
///
/// ```rust
/// // Creating an array of `OSSL_PARAM` with a termination marker.
/// let params = [
///     OSSLParam::Int(42),
///     OSSLParam::Utf8Ptr("example_key".to_string()),
///     OSSL_PARAM_END, // Marks the end of the parameter list.
/// ];
///
/// // The `OSSL_PARAM_END` signals the end of the parameters, ensuring correct handling.
/// assert_eq!(params[2].key, std::ptr::null());
/// ```
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

impl<'a> IntoIterator for OSSLParam<'a> {
    type Item = Self;

    type IntoIter = OSSLParamIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        OSSLParamIterator::new(self.get_c_struct())
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]

/// This struct holds a key-value pair along with metadata describing the parameter's type,
/// size, and the memory location of the data.
/// It is commonly used when interacting with OpenSSL APIs that require parameter lists.
pub struct CONST_OSSL_PARAM {
    /// A pointer to a C-style string representing the parameter's key.
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
    type Target = crate::bindings::ossl_param_st;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self as *const Self as *const Self::Target) }
    }
}

impl From<&CONST_OSSL_PARAM> for *const crate::bindings::ossl_param_st {
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
