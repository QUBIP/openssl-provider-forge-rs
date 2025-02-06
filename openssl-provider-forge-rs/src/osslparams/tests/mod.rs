use super::*;

mod iterator;
mod null; // new_null tests
mod setter; // set tests
mod tryfrom; // try_from tests

mod generic {
    use super::*;
    use std::ptr;

    #[test]
    fn test_basic_usage() {
        //pretty_env_logger::try_init().expect("Failed initializing logger subsystem");
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
        let mut op_utf8str = OSSLParam::new_const_utf8string(k, c"test_value");
        let result = Utf8StringData::try_from(&mut op_utf8str as *mut OSSL_PARAM);
        log::debug!("{result:?}");
        // Check that the result is Ok
        assert!(result.is_ok());

        let op = OSSLParam::try_from(&mut op_utf8str as *mut OSSL_PARAM);
        assert!(op.is_ok());
        let op = op.unwrap();
        log::debug!("{op:?}");
        assert_eq!(op.get_data_type().unwrap(), OSSL_PARAM_UTF8_STRING);
        assert_eq!(op.get_key().unwrap(), k);
        assert_eq!(op.get::<&CStr>(), Some(c"test_value"));
    }
}
