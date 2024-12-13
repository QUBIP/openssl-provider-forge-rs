use super::*;

// Tests for the null methods

#[test]
fn test_utf8_ptr_data_new_null() {
    let key = c"test_key";
    let utf8_data = Utf8PtrData::new_null(&key);
    assert!(
        utf8_data.param.is_null() == false,
        "Failed to create new null UTF-8 parameter"
    );
}

#[test]
fn test_int_data_new_null() {
    let key = c"test_key";
    let int_data = IntData::new_null(&key);
    assert!(
        int_data.param.is_null() == false,
        "Failed to create new null integer parameter"
    );
}

#[test]
fn test_uint_data_new_null() {
    let key = c"test_key";
    let uint_data = UIntData::new_null(&key);
    assert!(
        uint_data.param.is_null() == false,
        "Failed to create new null unsigned integer parameter"
    );
}
