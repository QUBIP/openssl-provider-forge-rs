use std::slice::from_raw_parts;

use crate::bindings::{OSSL_PARAM, OSSL_PARAM_OCTET_STRING};
use crate::osslparams::{
    impl_setter, new_null_param, KeyType, OSSLParam, OSSLParamData, OSSLParamError,
    OSSLParamGetter, OctetStringData, TypedOSSLParamData,
};

// TODO: don't leak the buffer
// TODO, maybe: let the user specify how big the buffer should be
impl OSSLParamData for OctetStringData {
    fn new_null(key: &KeyType) -> Self
    where
        Self: Sized,
    {
        let param_data = new_null_param!(OctetStringData, OSSL_PARAM_OCTET_STRING, key);
        let bufsize = 1024;
        let buf = Box::into_raw(vec![0u8; bufsize].into_boxed_slice());
        unsafe {
            (*param_data.param).data = buf as *mut std::ffi::c_void;
        }
        unsafe {
            (*param_data.param).data_size = bufsize;
        }
        param_data
    }
}

impl_setter!(&[u8], OctetString);

// A potential issue here (which I think is the same with Utf8String) is that this returns a slice
// which points to the same underlying memory used internally by the param, whereas the
// corresponding C function takes a buffer as an argument and actually copies the value into it.
// Taking a buffer as an argument feels very un-Rust-y as an interface design choice, but we may
// want to copy the bytes into some owned thing and return that instead.
impl<'a> OSSLParamGetter<&'a [u8]> for OSSLParam {
    fn get_inner(&self) -> Option<&'a [u8]> {
        if let OSSLParam::OctetString(d) = self {
            unsafe {
                let slice = from_raw_parts((*d.param).data as *const u8, (*d.param).data_size);
                Some(slice)
            }
        } else {
            None
        }
    }
}

// This function can leave old data in the param's data buffer if the new data is shorter than what
// was previously written to the buffer, which bothers me, but I believe it matches the way the
// corresponding C function is implemented in OSSL, so maybe it's fine....
impl<'a> TypedOSSLParamData<&'a [u8]> for OctetStringData {
    fn set(&mut self, value: &'a [u8]) -> Result<(), OSSLParamError> {
        if (self.param).is_null() {
            return Err("self.param was null".to_string());
        }
        let p = unsafe { &mut *self.param };
        let len = value.len();
        p.return_size = len;
        if p.data.is_null() {
            // https://github.com/openssl/openssl/blob/85f17585b0d8b55b335f561e2862db14a20b1e64/crypto/params.c#L1398
            // ?????
            return Ok(());
        }
        if p.data_size < len {
            return Err("p.data_size in param is too small to fit the octet string".to_string());
        }
        // Set the inner contents of the param
        unsafe {
            std::ptr::copy(value.as_ptr(), p.data as *mut u8, len);
        };
        Ok(())
    }
}

impl TryFrom<*mut OSSL_PARAM> for OctetStringData {
    type Error = OSSLParamError;

    fn try_from(param: *mut OSSL_PARAM) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) => {
                if param.data_type != OSSL_PARAM_OCTET_STRING {
                    Err("tried to make OctetStringData from ossl_param_st with data_type != OSSL_PARAM_OCTET_STRING".to_string())
                } else {
                    Ok(OctetStringData { param })
                }
            }
            None => Err("tried to make OctetStringData from null pointer".to_string()),
        }
    }
}
