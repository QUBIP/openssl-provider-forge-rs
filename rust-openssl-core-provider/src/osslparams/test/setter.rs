use super::*;

#[allow(unused_imports)]
use std::ptr;

//Tests for set method

#[test]
fn test_int_data() {
    let mut int_data = IntData {
        param: &mut ossl_param_st {
            data: ptr::null_mut(),
            return_size: 0,
            data_type: OSSL_PARAM_INTEGER,
            key: ptr::null(),
            data_size: 0,
        },
    };

    let value: i64 = -2;
    let result = int_data.set(value);

    assert_eq!(result, Ok(()));
}

#[test]
fn test_uint_data_() {
    let mut uint_data = UIntData {
        param: &mut ossl_param_st {
            data: ptr::null_mut(),
            return_size: 0,
            data_type: OSSL_PARAM_UNSIGNED_INTEGER,
            key: ptr::null(),
            data_size: 0,
        },
    };

    let value: u64 = 50;
    let result = uint_data.set(value);

    assert_eq!(result, Ok(()));
    
}

// In the above 2 tests, we declared a mut variables 'int_data' and 'uint_data' of type IntData & UIntData respectively.
// Setting all the fields of the struct to the null except 'data type'. Later, using set() method to fee the result with the test value.

#[test]
fn test_utf8_ptr_data_set() {
    let mut ossl_param = ossl_param_st {
        data: std::ptr::null_mut(),
        data_type: OSSL_PARAM_UTF8_PTR,
        return_size: 0,
        data_size: std::mem::size_of::<*const CStr>(),
        key: ptr::null(),
    };

    // Allocate memory for a pointer that will store the UTF-8 string
    let mut pointer_to_utf8: *const i8 = std::ptr::null();
    ossl_param.data = &mut pointer_to_utf8 as *mut *const i8 as *mut std::ffi::c_void;

    // Create an instance of Utf8PtrData pointing to the dummy ossl_param_st
    let mut utf8_data = Utf8PtrData {
        param: &mut ossl_param,
    };

    // Create a valid CStr (must end with a null terminator)
    let value = c"test_value";

    // Set the value using the set method
    let result = utf8_data.set(value);
    
    assert_eq!(result, Ok(()));

    // Check that ossl_param.data now points to the address of `value`
    // We expect the memory address of `pointer_to_utf8` to match `value.as_ptr()`
    assert!(
        !pointer_to_utf8.is_null(),
        "Pointer to UTF-8 data was not set correctly"
    );
    assert_eq!(
        pointer_to_utf8,
        value.as_ptr() as *const i8,
        "Incorrect UTF-8 data pointer"
    );

    // Check that the return_size is correctly set to the length of the CStr (excluding the null terminator)
    assert_eq!(
        ossl_param.return_size,
        value.to_bytes().len(),
        "Incorrect return_size"
    );
}

