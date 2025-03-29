//! These are `bindgen`-generated FFI (Foreign Function Interface)
//! definitions for
//! `OpenSSL 3.2+`, and
//! specifically for its `Core` ([openssl-core.h(7ossl)])
//! and `Provider` ([provider(7ossl)], [provider-base(7ossl)]) APIs.
//!
//! [provider(7ossl)]: https://docs.openssl.org/3.2/man7/provider/
//! [provider-base(7ossl)]: https://docs.openssl.org/3.2/man7/provider-base/
//! [openssl-core.h(7ossl)]: https://docs.openssl.org/3.2/man7/openssl-core.h/

// We encapsulate the output of bindgen in a inner module, so we can
// disable clippy and other lints for the generated code
#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod inner_bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// Then we export as pub all the symbols from the inner module.
/// These are `bindgen`-generated FFI (Foreign Function Interface)
/// definitions for
/// `OpenSSL 3.2+`, and
/// specifically for its `Core` ([openssl-core.h(7ossl)])
/// and `Provider` ([provider(7ossl)], [provider-base(7ossl)]) APIs.
///
/// [provider(7ossl)]: https://docs.openssl.org/3.2/man7/provider/
/// [provider-base(7ossl)]: https://docs.openssl.org/3.2/man7/provider-base/
/// [openssl-core.h(7ossl)]: https://docs.openssl.org/3.2/man7/openssl-core.h/
pub use inner_bindings::*;

/// We bundle here the definitions of FFI-types for C-compatible types
/// for easily re-exporting them in bulk.
pub mod ffi_c_types {
    pub use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
    pub use std::ffi::{CStr, CString};
}

pub use ffi_c_types::*;

/// This is the value assigned to
/// [`OSSL_PARAM::return_size`][`CONST_OSSL_PARAM::return_size`]
/// when defining an `OSSL_PARAM`.
///
/// It is [defined as a macro in `openssl/params.h`](https://github.com/openssl/openssl/blob/8d6fd6142b0b55ce029df6d7b63dda5f7cb8ce54/include/openssl/params.h#L22)
/*
 * core::ffi:c_size_t is only in nightly, and unstable
 *
 * https://github.com/rust-lang/rust/issues/88345 seems to have stalled,
 * so for now we just assume c_size_t and usize are the same.
 *
 * TODO: revisit if c_size_t goes stable
 */
// const OSSL_PARAM_UNMODIFIED: usize = core::ffi::c_size_t::MAX;
pub const OSSL_PARAM_UNMODIFIED: usize = usize::MAX;

/// We alias under this namespace the `CONST_OSSL_PARAM` type available under `crate::osslparams`
pub use crate::osslparams::CONST_OSSL_PARAM;

// Why we need to cast the function itself, in the call to `transmute`: the name
// of a function, like `OSSL_provider_teardown`, is actually a zero-sized type
// that uniquely identifies that function. It's not a pointer to it, unless you
// cast it. See:
// https://users.rust-lang.org/t/casting-function-pointers-with-different-linkage/31488/2
#[macro_export]
macro_rules! generic_non_null_fn_ptr {
    ($address:expr) => {
        std::mem::transmute::<*const (), unsafe extern "C" fn()>($address as _)
    };
}
pub use generic_non_null_fn_ptr;

pub type GenericNullableFnPtr = ::std::option::Option<unsafe extern "C" fn()>;

impl OSSL_DISPATCH {
    pub const END: Self = Self {
        function_id: 0,
        function: None,
    };

    pub const fn new(fnid: c_int, fnpt: GenericNullableFnPtr) -> Self {
        Self {
            function_id: fnid,
            function: fnpt,
        }
    }
}

impl Default for OSSL_DISPATCH {
    fn default() -> Self {
        Self::END
    }
}

/// A convenience macro to quickly declare a OSSL_DISPATCH table entry
#[macro_export]
macro_rules! dispatch_table_entry {
    ( $f_id:expr, $f_type:ty, $f_name:expr ) => {{
        // This function "does nothing" (and is optimized away entirely in a release build), but it
        // prevents the code it's used in from compiling at all if it's called with an argument _f
        // that is not of type F.
        // Defining it inside the macro prevents it from being visible as an export of this module.
        //const fn check_dispatch_table_entry_type<F>(_f: F) {}
        //check_dispatch_table_entry_type::<$f_type>(Some($f_name));
        let _: Option<$f_type> = None;
        $crate::bindings::OSSL_DISPATCH::new(
            // Why we need to cast the function ID: bindgen has to guess
            // at the type for `#define`d constants, and it guesses u32,
            // which conflicts with the type of the `function_id` field.
            $f_id as i32,
            Some(unsafe { $crate::bindings::generic_non_null_fn_ptr!($f_name) }),
        )
    }};
}
pub use dispatch_table_entry;

impl OSSL_ALGORITHM {
    pub const END: Self = Self {
        algorithm_names: std::ptr::null(),
        property_definition: std::ptr::null(),
        implementation: std::ptr::null(),
        algorithm_description: std::ptr::null(),
    };
}

impl Default for OSSL_ALGORITHM {
    fn default() -> Self {
        Self::END
    }
}
