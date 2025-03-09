use super::*;

// Tests for the Iterator use of OSSLParams

#[test]
fn test_params_iterator() {
    setup().expect("setup() failed");

    let a = [
        {
            let d = c"an arbitrary string";
            let dl = d.count_bytes() + 1;
            OSSL_PARAM {
                key: c"AnArbitraryKey".as_ptr(),
                data: d.as_ptr() as *mut std::ffi::c_void,
                data_type: OSSL_PARAM_UTF8_PTR,
                return_size: 0,
                data_size: dl,
            }
        },
        {
            let d = c"more data";
            let dl = d.count_bytes() + 1;
            OSSL_PARAM {
                key: c"B".as_ptr(),
                data: d.as_ptr() as *mut std::ffi::c_void,
                data_type: OSSL_PARAM_UTF8_PTR,
                return_size: 0,
                data_size: dl,
            }
        },
        OSSL_PARAM_END,
    ];
    let params_iter = OSSLParamIterator::new(&a[0]);

    let mut i = 0;
    for p in params_iter {
        println!("{p:?}");
        assert_eq!(p.get_data_type(), Some(a[i].data_type));
        i += 1;
    }

    assert_eq!(i, a.len() - 1);
}

#[test]
fn test_params_intoiterator() {
    setup().expect("setup() failed");

    let a = [
        {
            let d = c"an arbitrary string";
            let dl = d.count_bytes() + 1;
            OSSL_PARAM {
                key: c"AnArbitraryKey".as_ptr(),
                data: d.as_ptr() as *mut std::ffi::c_void,
                data_type: OSSL_PARAM_UTF8_STRING,
                return_size: 0,
                data_size: dl,
            }
        },
        {
            let d = c"more data";
            let dl = d.count_bytes() + 1;
            OSSL_PARAM {
                key: c"B".as_ptr(),
                data: d.as_ptr() as *mut std::ffi::c_void,
                data_type: OSSL_PARAM_UTF8_STRING,
                return_size: 0,
                data_size: dl,
            }
        },
        OSSL_PARAM_END,
    ];

    let first = std::ptr::from_ref(a.first().unwrap());
    let params = OSSLParam::try_from(first).unwrap();

    let mut i = 0;
    for p in params {
        println!("{p:?}");
        i += 1;
    }

    assert_eq!(i, a.len() - 1);
}
