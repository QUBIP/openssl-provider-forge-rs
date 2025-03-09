use super::*;
use std::ptr;

// Tests for the TryFrom implementations

#[test]
fn test_int_data_try_from() {
    setup().expect("setup() failed");

    let mut ossl_param = OSSL_PARAM {
        data: std::ptr::null_mut(),
        data_type: OSSL_PARAM_INTEGER,
        return_size: 0,
        data_size: 0,
        key: ptr::null(),
    };

    let result = IntData::try_from(&mut ossl_param as *mut OSSL_PARAM);

    // Check that the result is Ok and properly returns IntData
    assert!(result.is_ok());
}

#[test]
fn test_utf8_ptr_try_from() {
    setup().expect("setup() failed");

    let mut ossl_param = OSSL_PARAM {
        data: std::ptr::null_mut(),
        data_type: OSSL_PARAM_UTF8_PTR,
        return_size: 0,
        data_size: 0,
        key: ptr::null(),
    };

    let result = Utf8PtrData::try_from(&mut ossl_param as *mut OSSL_PARAM);

    // Check that the result is Ok and properly returns Utf8PtrData
    assert!(result.is_ok());
}

#[test]
fn test_uint_try_from() {
    setup().expect("setup() failed");

    let mut ossl_param = OSSL_PARAM {
        data: std::ptr::null_mut(),
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        return_size: 0,
        data_size: 0,
        key: ptr::null(),
    };

    // Attempt to convert a UIntData param to Utf8PtrData, should fail
    let result = Utf8PtrData::try_from(&mut ossl_param as *mut OSSL_PARAM);

    // Check that the result is Err due to mismatched data type
    assert!(result.is_err());
}
