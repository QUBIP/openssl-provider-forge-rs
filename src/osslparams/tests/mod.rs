use super::*;

use crate::tests::common;
use common::OurError;

mod iterator;
mod null; // new_null tests
mod setter; // set tests
mod tryfrom; // try_from tests

mod generic {
    use super::*;
    use std::ptr;

    fn setup() -> Result<(), OurError> {
        common::setup()
    }

    #[test]
    fn test_basic_usage() {
        setup().expect("setup() failed");

        let mut ossl_param = OSSL_PARAM {
            data: std::ptr::null_mut(),
            data_type: OSSL_PARAM_INTEGER,
            data_size: size_of::<i32>(),
            return_size: 0,
            key: ptr::null(),
        };
        let result = IntData::try_from(&mut ossl_param as *mut OSSL_PARAM);
        log::debug!("IntData::try_from returned: {result:?}");
        // Check that the result is Ok and properly returns IntData
        assert!(result.is_ok());

        ossl_param.data_type = 0;
        let result = IntData::try_from(&mut ossl_param as *mut OSSL_PARAM);
        log::debug!("(expected an error) {result:?}");
        assert!(result.is_err());

        let k = c"test_key";
        let op_utf8str = OSSLParam::new_const_utf8string(k, Some(c"test_value"));
        let t: *const OSSL_PARAM = std::ptr::from_ref(&op_utf8str);
        let result = Utf8StringData::try_from(t as *mut OSSL_PARAM);
        log::debug!("{result:?}");
        // Check that the result is Ok
        assert!(result.is_ok());

        let op = OSSLParam::try_from(t as *mut OSSL_PARAM);
        assert!(op.is_ok());
        let op = op.unwrap();
        log::debug!("{op:?}");
        assert_eq!(op.get_data_type().unwrap(), OSSL_PARAM_UTF8_STRING);
        assert_eq!(op.get_key().unwrap(), k);
        assert_eq!(op.get::<&CStr>(), Some(c"test_value"));
    }

    #[test]
    /// This tests duplicates an `ignored` doctest in the documentation for variant_name()
    ///
    /// variant_name() is a private method, so we cannot test it in doctests, but we want
    /// to keep there a valid example, therefore we test it here.
    ///
    /// If this test breaks, please fix also the corresponding example in the doccomment.
    fn test_variant_name_simple() {
        let param = OSSLParam::new_const_int(c"some_key", Some(&42i64));
        let param: OSSLParam = OSSLParam::try_from(&param).unwrap();

        let variant = param.variant_name();

        println!("Variant name: {}", variant); // Outputs: "Int"
        assert_eq!(variant, "Int");
    }

    #[test]
    /// This tests duplicates an `ignored` doctest in the documentation for variant_name()
    ///
    /// variant_name() is a private method, so we cannot test it in doctests, but we want
    /// to keep there a valid example, therefore we test it here.
    ///
    /// If this test breaks, please fix also the corresponding example in the doccomment.
    fn test_variant_name_list() {
        // NOTE: it's very important valid lists of parameters are ALWAYS terminated by END item
        let params_list = [
            OSSLParam::new_const_int(c"foo", Some(&1i32)), // This is an Int
            OSSLParam::new_const_uint(c"bar", Some(&42u64)), // This is a UInt
            OSSLParam::new_const_utf8string(c"baz", Some(c"a string")), // This is a Utf8String
            CONST_OSSL_PARAM::END,
        ];

        let params = OSSLParam::try_from(&params_list[0]).unwrap();

        let mut counter = 0;
        for p in params {
            let key = p.get_key();
            assert!(key.is_some());

            let variant = p.variant_name();

            match counter {
                0 => {
                    assert_eq!(variant, "Int");
                }
                1 => {
                    assert_eq!(variant, "UInt");
                }
                2 => {
                    assert_eq!(variant, "Utf8String");
                }
                _ => unreachable!(),
            }
            counter += 1;
        }

        assert_eq!(counter, 3);
        assert_eq!(counter, params_list.len() - 1);
    }
}
