use super::OurError;
use crate::bindings::{OSSL_CALLBACK, OSSL_PARAM};
use anyhow::{anyhow, Ok};
use std::ffi::{c_int, c_void};

type InnerCB = unsafe extern "C" fn(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int;

pub struct OSSLCallback {
    cb_fn: InnerCB,
    args: *mut c_void,
}

impl OSSLCallback {
    pub fn try_new(cb: OSSL_CALLBACK, args: *mut c_void) -> Result<Self, OurError> {
        let cb_fn: InnerCB = if let Some(cb_fn) = cb {
            cb_fn
        } else {
            return Err(anyhow!("Passed NULL callback"));
        };

        Ok(Self { cb_fn, args })
    }

    pub fn call(&self, params: *const OSSL_PARAM) -> c_int {
        let cb_fn = self.cb_fn;
        unsafe { cb_fn(params, self.args) }
    }
}
