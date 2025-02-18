use std::ffi::CStr;

use crate::bindings::{
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};

pub mod data;

#[cfg(test)]
mod tests;

// List of supported types: https://docs.openssl.org/master/man3/OSSL_PARAM/#supported-types
#[derive(Debug)]
pub enum OSSLParam<'a> {
    Utf8Ptr(Utf8PtrData<'a>),
    Utf8String(Utf8StringData<'a>),
    Int(IntData<'a>),
    UInt(UIntData<'a>),
    OctetString(OctetStringData<'a>),
}

#[derive(Debug)]
pub struct Utf8PtrData<'a> {
    param: &'a mut OSSL_PARAM,
}

#[derive(Debug)]
pub struct Utf8StringData<'a> {
    param: &'a mut OSSL_PARAM,
}

#[derive(Debug)]
pub struct IntData<'a> {
    param: &'a mut OSSL_PARAM,
}

#[derive(Debug)]
pub struct UIntData<'a> {
    param: &'a mut OSSL_PARAM,
}

#[derive(Debug)]
pub struct OctetStringData<'a> {
    param: &'a mut OSSL_PARAM,
}

pub type OSSLParamError = String;

pub type KeyType = CStr;

impl<'a> OSSLParam<'a> {
    pub fn set<T>(&mut self, value: T) -> Result<(), OSSLParamError>
    where
        Self: OSSLParamSetter<T>,
    {
        self.set_inner(value)
    }

    pub fn get<T>(&self) -> Option<T>
    where
        Self: OSSLParamGetter<T>,
    {
        self.get_inner()
    }

    // TODO: rename this to get_c_struct_mut and make a non-mut version of it, and use the non-mut
    // version where appropriate (particularly in get_key() and in modified(), just below here)
    pub fn get_c_struct(&mut self) -> *mut OSSL_PARAM {
        match self {
            OSSLParam::Utf8Ptr(d) => d.param,
            OSSLParam::Utf8String(d) => d.param,
            OSSLParam::Int(d) => d.param,
            OSSLParam::UInt(d) => d.param,
            OSSLParam::OctetString(d) => d.param,
        }
    }

    pub fn get_key(&mut self) -> &KeyType {
        unsafe { CStr::from_ptr((*self.get_c_struct()).key) }
    }

    // corresponds to OSSL_PARAM_modified()
    #[allow(dead_code)]
    pub fn modified(&mut self) -> bool {
        unsafe { (*self.get_c_struct()).return_size != OSSL_PARAM_UNMODIFIED }
    }

    // right now this method is just here to show we can return &dyn OSSLParamData if we need it
    #[allow(dead_code)]
    fn inner_data(&self) -> &dyn OSSLParamData {
        match self {
            OSSLParam::Utf8Ptr(d) => d,
            OSSLParam::Utf8String(d) => d,
            OSSLParam::Int(d) => d,
            OSSLParam::UInt(d) => d,
            OSSLParam::OctetString(d) => d,
        }
    }

    // returns e.g. "Int" if self is an OSSLParam::Int(IntData)
    fn variant_name(&self) -> String {
        let s = format!("{:?}", self);
        s.split("(").next().unwrap().to_owned()
    }
}

pub trait OSSLParamSetter<T> {
    fn set_inner(&mut self, value: T) -> Result<(), OSSLParamError>;
}

pub trait OSSLParamGetter<T> {
    fn get_inner(&self) -> Option<T>;
}

pub trait OSSLParamData {
    fn new_null(key: &KeyType) -> Self
    where
        Self: Sized;
}

pub trait TypedOSSLParamData<T>: OSSLParamData {
    fn set(&mut self, value: T) -> Result<(), OSSLParamError>;
}

macro_rules! setter_type_err_string {
    ($param:expr, $value:ident) => {
        format!(
            "Type {} could not be stored in OSSLParam::{}",
            std::any::type_name_of_val(&$value),
            $param.variant_name()
        )
    };
}

pub(crate) use setter_type_err_string;

macro_rules! new_null_param {
    ($constructor:ident, $data_type:ident, $key:expr) => {
        $constructor {
            param: Box::leak(Box::new(crate::bindings::OSSL_PARAM {
                key: $key.as_ptr().cast(),
                data_type: $data_type,
                data: std::ptr::null::<std::ffi::c_void>() as *mut std::ffi::c_void,
                data_size: 0,
                return_size: 0,
            })),
        }
    };
}

pub(crate) use new_null_param;

macro_rules! impl_setter {
    ($t:ty, $variant:ident) => {
        impl<'a> $crate::osslparams::OSSLParamSetter<$t> for OSSLParam<'a> {
            fn set_inner(&mut self, value: $t) -> Result<(), OSSLParamError> {
                if let OSSLParam::$variant(d) = self {
                    d.set(value)
                } else {
                    Err($crate::osslparams::setter_type_err_string!(self, value))
                }
            }
        }
    };
}

pub(crate) use impl_setter;

impl<'a> TryFrom<&mut OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;

    fn try_from(value: &mut OSSL_PARAM) -> Result<Self, Self::Error> {
        OSSLParam::try_from(value as *mut OSSL_PARAM)
    }
}

impl<'a> TryFrom<*mut OSSL_PARAM> for OSSLParam<'a> {
    type Error = OSSLParamError;

    fn try_from(p: *mut OSSL_PARAM) -> std::result::Result<Self, Self::Error> {
        match unsafe { p.as_mut() } {
            Some(p) => match p.data_type {
                OSSL_PARAM_UTF8_PTR => Ok(OSSLParam::Utf8Ptr(
                    Utf8PtrData::try_from(p as *mut OSSL_PARAM).unwrap(),
                )),
                OSSL_PARAM_UTF8_STRING => Ok(OSSLParam::Utf8String(
                    Utf8StringData::try_from(p as *mut OSSL_PARAM).unwrap(),
                )),
                OSSL_PARAM_INTEGER => Ok(OSSLParam::Int(
                    IntData::try_from(p as *mut OSSL_PARAM).unwrap(),
                )),
                OSSL_PARAM_UNSIGNED_INTEGER => Ok(OSSLParam::UInt(
                    UIntData::try_from(p as *mut OSSL_PARAM).unwrap(),
                )),
                OSSL_PARAM_OCTET_STRING => Ok(OSSLParam::OctetString(
                    OctetStringData::try_from(p as *mut OSSL_PARAM).unwrap(),
                )),
                _ => Err("Couldn't convert to OSSLParam from *mut OSSL_PARAM".to_string()),
            },
            None => Err("Couldn't convert to OSSLParam from null pointer".to_string()),
        }
    }
}

pub const OSSL_PARAM_END: OSSL_PARAM = OSSL_PARAM {
    key: std::ptr::null(),
    data_type: 0,
    data: std::ptr::null_mut(),
    data_size: 0,
    return_size: 0,
};

pub const EMPTY_PARAMS: [OSSL_PARAM; 1] = [OSSL_PARAM_END];

/*
 * core::ffi:c_size_t is only in nightly, and unstable
 *
 * https://github.com/rust-lang/rust/issues/88345 seems to have stalled,
 * so for now we just assume c_size_t and usize are the same.
 *
 * TODO: revisit if c_size_t goes stable
 */
// const OSSL_PARAM_UNMODIFIED: usize = core::ffi::c_size_t::MAX;
const OSSL_PARAM_UNMODIFIED: usize = usize::MAX;

pub fn ossl_param_locate_raw(params: *mut OSSL_PARAM, key: &KeyType) -> Option<OSSLParam> {
    let mut i = 0;
    loop {
        let p = unsafe { &mut *params.offset(i) };
        if p.key.is_null() {
            return None;
        } else if unsafe { CStr::from_ptr(p.key) } == key {
            match OSSLParam::try_from(&mut *p) {
                Ok(param) => return Some(param),
                Err(_) => {
                    eprintln!("Unimplemented param data type: {:?}", p.data_type);
                    return None;
                }
            }
        }
        i += 1;
    }
}

impl<'a> From<&mut OSSL_PARAM> for Vec<OSSLParam<'a>> {
    fn from(params: &mut OSSL_PARAM) -> Self {
        let mut v: Vec<OSSLParam> = Vec::new();
        let mut i = 0;
        loop {
            let p = unsafe { &mut *(params as *mut OSSL_PARAM).offset(i) };
            if p.key.is_null() {
                break;
            } else {
                match OSSLParam::try_from(&mut *p) {
                    Ok(param) => v.push(param),
                    Err(_) => {
                        eprintln!("Unimplemented param data type: {:?}", p.data_type);
                    }
                }
            }
            i += 1;
        }
        v
    }
}
