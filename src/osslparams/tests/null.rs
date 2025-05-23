use super::*;

// Tests for the null methods

#[test]
fn test_utf8_ptr_data_new_null() {
    setup().expect("setup() failed");

    let key = c"test_key";
    let utf8_data = Utf8PtrData::new_null(&key);
    assert!(
        utf8_data.param.data_type == OSSL_PARAM_UTF8_PTR,
        "Failed to create new null UTF-8 parameter"
    );
}

#[test]
fn test_int_data_new_null() {
    setup().expect("setup() failed");

    let key = c"test_key";
    let int_data = IntData::new_null(&key);
    assert!(
        int_data.param.data_type == OSSL_PARAM_INTEGER,
        "Failed to create new null integer parameter"
    );
}

#[test]
fn test_uint_data_new_null() {
    setup().expect("setup() failed");

    let key = c"test_key";
    let uint_data = UIntData::new_null(&key);
    assert!(
        uint_data.param.data_type == OSSL_PARAM_UNSIGNED_INTEGER,
        "Failed to create new null unsigned integer parameter"
    );
}
