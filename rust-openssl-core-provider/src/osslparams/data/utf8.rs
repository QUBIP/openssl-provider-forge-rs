use std::ffi::{c_char, CStr};

use crate::bindings::{ossl_param_st, OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING};
use crate::osslparams::{
    new_null_param, setter_type_err_string, KeyType, OSSLParam, OSSLParamData, OSSLParamError,
    OSSLParamGetter, OSSLParamSetter, TypedOSSLParamData, Utf8PtrData, Utf8StringData,
};

impl OSSLParamData for Utf8PtrData {
    fn new_null(key: &KeyType) -> Self where Self: Sized {
        new_null_param!(Utf8PtrData, OSSL_PARAM_UTF8_PTR, key)
    }
}

// TODO: don't leak the buffer
// TODO, maybe: let the user specify how big the buffer should be
impl OSSLParamData for Utf8StringData {
    fn new_null(key: &KeyType) -> Self where Self: Sized {
        let param_data = new_null_param!(Utf8StringData, OSSL_PARAM_UTF8_STRING, key);
        let bufsize = 1024;
        let buf = Box::into_raw(vec![0u8; bufsize].into_boxed_slice());
        unsafe { (*param_data.param).data = buf as *mut std::ffi::c_void; }
        unsafe { (*param_data.param).data_size = bufsize; }
        param_data
    }
}

// For these, we can't use impl_setter!, because that macro only lets you specify one enum variant
// per Rust type.
impl OSSLParamSetter<*const CStr> for OSSLParam {
    fn set_inner(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        if let OSSLParam::Utf8Ptr(d) = self {
            d.set(value)
        } else if let OSSLParam::Utf8String(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

impl OSSLParamSetter<&'static CStr> for OSSLParam {
    fn set_inner(&mut self, value: &'static CStr) -> Result<(), OSSLParamError> {
        if let OSSLParam::Utf8Ptr(d) = self {
            d.set(value)
        } else if let OSSLParam::Utf8String(d) = self {
            d.set(value)
        } else {
            Err(setter_type_err_string!(self, value))
        }
    }
}

impl<'a> OSSLParamGetter<&'a CStr> for OSSLParam {
    fn get_inner(&self) -> Option<&'a CStr> {
        if let OSSLParam::Utf8Ptr(d) = self {
            unsafe {
                let ptr = (*d.param).data as *const *mut c_char;
                Some(CStr::from_ptr(*ptr))
            }
        } else if let OSSLParam::Utf8String(d) = self {
            let _ = d;
            todo!()
        } else {
            None
        }
    }
}

impl TypedOSSLParamData<*const CStr> for Utf8PtrData {
    fn set(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        let p = unsafe { &mut *self.param };
        if p.data.is_null() {
            p.return_size = 0;
        } else {
            match unsafe { value.as_ref() } {
                Some(cstr) => {
                    p.return_size = cstr.to_bytes().len();
                    unsafe { *(p.data as *mut *const c_char) = cstr.as_ptr() };
                },
                None => return Err("couldn't get &CStr from *const CStr".to_string()),
            }
        }
        Ok(())
    }
}

impl TypedOSSLParamData<*const CStr> for Utf8StringData {
    fn set(&mut self, value: *const CStr) -> Result<(), OSSLParamError> {
        if (self.param).is_null() {
            return Err("self.param was null".to_string());
        }
        let p = unsafe { &mut *self.param };
        if p.data.is_null() {
            p.return_size = 0;
        } else {
            if value.is_null() {
                return Err("value was null".to_string());
            }
            // Set the inner contents of the param
            match unsafe { value.as_ref() } {
                Some(cstr) => {
                    let len = cstr.to_bytes().len();
                    p.return_size = len;
                    if p.data.is_null() {
                        // https://github.com/openssl/openssl/blob/85f17585b0d8b55b335f561e2862db14a20b1e64/crypto/params.c#L1398
                        // ?????
                        return Ok(());
                    }
                    if p.data_size < len {
                        return Err("p.data_size in param is too small to fit the string".to_string());
                    }
                    unsafe {
                        std::ptr::copy(cstr.as_ptr(), p.data as *mut c_char, len);
                    };
                },
                None => return Err("couldn't get &CStr from *const CStr".to_string()),
            }
        }
        Ok(())
    }
}

/* We don't need to `impl TypedOSSLParamData<&'static CStr> for Utf8PtrData` separately,
 * because Rust can implicitly convert a &'static CStr reference to a raw *const CStr pointer.
 * However, if we want to add an explicit non-static lifetime to an impl of it over CStr, I
 * think things would get more complicated.
*/

impl TryFrom<*mut ossl_param_st> for Utf8PtrData {
    type Error = OSSLParamError;

    fn try_from(param: *mut ossl_param_st) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) =>
                if param.data_type != OSSL_PARAM_UTF8_PTR {
                    Err("tried to make Utf8PtrData from ossl_param_st with data_type != OSSL_PARAM_UTF8_PTR".to_string())
                } else {
                    Ok(Utf8PtrData { param })
                },
            None => Err("tried to make Utf8PtrData from null pointer".to_string()),
        }
    }
}

impl TryFrom<*mut ossl_param_st> for Utf8StringData {
    type Error = OSSLParamError;

    fn try_from(param: *mut ossl_param_st) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) =>
                if param.data_type != OSSL_PARAM_UTF8_STRING {
                    Err("tried to make Utf8StringData from ossl_param_st with data_type != OSSL_PARAM_UTF8_STRING".to_string())
                } else {
                    Ok(Utf8StringData { param })
                },
            None => Err("tried to make Utf8StringData from null pointer".to_string()),
        }
    }
}
