use num_traits::ToPrimitive;

use crate::bindings::{OSSL_PARAM, OSSL_PARAM_INTEGER};
use crate::osslparams::{
    impl_setter, new_null_param, IntData, KeyType, OSSLParam, OSSLParamData, OSSLParamError,
    OSSLParamGetter, TypedOSSLParamData,
};

trait PrimIntMarker: num_traits::PrimInt {}

impl PrimIntMarker for i8 {}
impl PrimIntMarker for i16 {}
impl PrimIntMarker for i32 {}
impl PrimIntMarker for i64 {}

impl OSSLParamData for IntData<'_> {
    fn new_null(key: &KeyType) -> Self {
        let param_data = new_null_param!(IntData, OSSL_PARAM_INTEGER, key);
        let buf = Box::into_raw(Box::new(0i64));
        param_data.param.data = buf as *mut std::ffi::c_void;
        param_data.param.data_size = size_of::<i64>();
        param_data
    }
}

// TODO: Allow setting with at least u32, if not the full spectrum of unsigned int primitives, for
// symmetry with the fact that we will allow that for UIntData param type (see TODO in uint.rs).
impl_setter!(i8, Int);
impl_setter!(i16, Int);
impl_setter!(i32, Int);
impl_setter!(i64, Int);

impl OSSLParamGetter<i32> for OSSLParam<'_> {
    fn get_inner(&self) -> Option<i32> {
        if let OSSLParam::Int(d) = self {
            let param = &*d.param;
            let data = param.data;
            let data_size = param.data_size;
            // ^ check that this stuff isn't null etc
            match data_size {
                s if s == size_of::<i32>() => {
                    let val = unsafe { std::ptr::read(data as *const i32) };
                    // here we can check stuff about val
                    Some(val)
                }
                s if s == size_of::<i64>() => {
                    // we can have debug assertions for the pointer we're giving to read()
                    // being non-null, being properly aligned, any other stuff we can check at
                    // runtime (although "validity" is probably too nebulous)
                    unsafe { std::ptr::read(data as *const i64).to_i32() }
                }
                _ => None,
            }
        } else {
            None
        }
    }
}

/* Implementing cross-signedness getters (e.g. impling TypedOSSLParamGetter<u64> for
 * OSSLParam::IntData) is out of scope. If the user wants to get a u64 from that then they can get
 * a i64 from it and cast it themselves.
 */

impl OSSLParamGetter<i64> for OSSLParam<'_> {
    fn get_inner(&self) -> Option<i64> {
        if let OSSLParam::Int(d) = self {
            let data = d.param.data;
            match d.param.data_size {
                s if s == size_of::<i32>() => {
                    Some(unsafe { std::ptr::read(data as *const i32) } as i64)
                }
                s if s == size_of::<i64>() => Some(unsafe { std::ptr::read(data as *const i64) }),
                _ => None,
            }
        } else {
            None
        }
    }
}

impl<T: PrimIntMarker> TypedOSSLParamData<T> for IntData<'_> {
    // https://github.com/openssl/openssl/blob/7f62adaf2b088de38ad2e534d0bfae2ff7ae01f2/crypto/params.c#L780-L796
    fn set(&mut self, value: T) -> Result<(), OSSLParamError> {
        let p = &mut *self.param;
        p.return_size = size_of::<i64>();
        if p.data.is_null() {
            Ok(())
        } else {
            match p.data_size {
                s if s == size_of::<i32>() => {
                    if let Some(x) = value.to_i32() {
                        p.return_size = size_of::<i32>();
                        unsafe { std::ptr::write(p.data as *mut i32, x) };
                        Ok(())
                    } else {
                        Err("value could not be converted to i32".to_string())
                    }
                }
                s if s == size_of::<i64>() => {
                    if let Some(x) = value.to_i64() {
                        unsafe { std::ptr::write(p.data as *mut i64, x) };
                        Ok(())
                    } else {
                        Err("value could not be converted to i64".to_string())
                    }
                }
                _ => Err("param.data_size was neither the size of i32 nor of i64".to_string()),
            }
        }
    }
}

impl TryFrom<*mut OSSL_PARAM> for IntData<'_> {
    type Error = &'static str;

    fn try_from(param: *mut OSSL_PARAM) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) => {
                if param.data_type != OSSL_PARAM_INTEGER {
                    Err("tried to make IntData from ossl_param_st with data_type != OSSL_PARAM_INTEGER")
                } else {
                    Ok(IntData { param })
                }
            }
            None => Err("tried to make IntData from null pointer"),
        }
    }
}
