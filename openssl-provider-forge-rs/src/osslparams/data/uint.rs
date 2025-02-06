use crate::bindings::{OSSL_PARAM, OSSL_PARAM_UNSIGNED_INTEGER};
use crate::osslparams::{
    impl_setter, new_null_param, KeyType, OSSLParam, OSSLParamData, OSSLParamError,
    OSSLParamGetter, TypedOSSLParamData, UIntData,
};

pub trait PrimUIntMarker: num_traits::PrimInt {}

impl PrimUIntMarker for u8 {}
impl PrimUIntMarker for u16 {}
impl PrimUIntMarker for u32 {}
impl PrimUIntMarker for u64 {}

impl OSSLParamData for UIntData<'_> {
    fn new_null(key: &KeyType) -> Self
    where
        Self: Sized,
    {
        let param_data = new_null_param!(UIntData, OSSL_PARAM_UNSIGNED_INTEGER, key);
        let buf = Box::into_raw(Box::new(0u64));
        param_data.param.data = buf as *mut std::ffi::c_void;
        param_data.param.data_size = size_of::<u64>();
        param_data
    }
}

/* We can't have both `impl<T: PrimIntMarker> OSSLParamSetter<T> for OSSLParam` and
 * `impl<T: PrimUIntMarker> OSSLParamSetter<T> for OSSLParam`, because Rust has no reasonably
 * readable/non-convoluted way to indicate to the coherence checker that PrimIntMarker and
 * PrimUIntMarker will never both be implemented for the same type. Basically we can only have
 * *one* marker trait that we ever use as a bound on the T in `impl<T> ... for OSSLParam`, which is
 * kind of useless.
 *
 * You might think that using the nightly features marker_trait_attr and negative_impls would fix
 * this by letting us write something like this:
 *
 *      #[marker]
 *      pub(crate) trait PrimIntMarker {}
 *      #[marker]
 *      pub(crate) trait PrimUIntMarker {}
 *      impl<T: PrimIntMarker> !PrimUIntMarker for T {}
 *      impl<T: PrimUIntMarker> !PrimIntMarker for T {}
 *
 * but it won't work, because (aiui) the relevant coherence rule for generics is something like
 * "you can't have two trait implementations that could ever theoretically overlap", and the
 * compiler doesn't take negative trait bounds into account when making that determination (and
 * it doesn't take visibility into account either, so the traits not being public doesn't help). So
 * with these nightly features we're free to *tell* the compiler that the traits will never
 * overlap, but there's no way for the compiler to *use* the information to deduce that it's okay
 * to have both `impl<T: M>` and `impl<T: N>` for the same `X<T> for Y`.
 */

// TODO: Allow setting with at least i32, if not the full spectrum of signed int primitives. It's
// way too annoying to have to write e.g. p.set(1 as u32) when setting constants. (All the
// typechecking for these things happens at runtime, so unfortunately the compiler can't infer the
// "right" type to use.)
impl_setter!(u8, UInt);
impl_setter!(u16, UInt);
impl_setter!(u32, UInt);
impl_setter!(u64, UInt);

impl OSSLParamGetter<u64> for OSSLParam<'_> {
    fn get_inner(&self) -> Option<u64> {
        if let OSSLParam::UInt(d) = self {
            let data = d.param.data;
            match d.param.data_size {
                s if s == size_of::<u32>() => {
                    Some(unsafe { std::ptr::read(data as *const u32) } as u64)
                }
                s if s == size_of::<u64>() => Some(unsafe { std::ptr::read(data as *const u64) }),
                _ => None,
            }
        } else {
            None
        }
    }
}

/* However, when we're doing `impl ... for UIntData`, we can use the marker trait, because it
 * doesn't risk overlapping with other impls like `impl ... for OSSLParam` does.
 */

impl<T: PrimUIntMarker> TypedOSSLParamData<T> for UIntData<'_> {
    // https://github.com/openssl/openssl/blob/7f62adaf2b088de38ad2e534d0bfae2ff7ae01f2/crypto/params.c#L937-L951
    fn set(&mut self, value: T) -> Result<(), OSSLParamError> {
        let p = &mut *self.param;
        p.return_size = size_of::<u64>();
        if p.data.is_null() {
            Ok(())
        } else {
            match p.data_size {
                s if s == size_of::<u32>() => {
                    if let Some(x) = value.to_u32() {
                        p.return_size = size_of::<u32>();
                        unsafe { std::ptr::write(p.data as *mut u32, x) };
                        Ok(())
                    } else {
                        Err("value could not be converted to u32".to_string())
                    }
                }
                s if s == size_of::<u64>() => {
                    if let Some(x) = value.to_u64() {
                        unsafe { std::ptr::write(p.data as *mut u64, x) };
                        Ok(())
                    } else {
                        Err("value could not be converted to u64".to_string())
                    }
                }
                _ => Err("param.data_size was neither the size of u32 nor of u64".to_string()),
            }
        }
    }
}

impl TryFrom<*mut OSSL_PARAM> for UIntData<'_> {
    type Error = &'static str;

    fn try_from(param: *mut OSSL_PARAM) -> Result<Self, Self::Error> {
        match unsafe { param.as_mut() } {
            Some(param) => {
                if param.data_type != OSSL_PARAM_UNSIGNED_INTEGER {
                    Err("tried to make UIntData from OSSL_PARAM with data_type != OSSL_PARAM_UNSIGNED_INTEGER")
                } else {
                    Ok(UIntData { param })
                }
            }
            None => Err("tried to make UIntData from null pointer"),
        }
    }
}
