//! [LICENSE]: ../LICENSE
//! [!NOTE]: # "ℹ️ NOTE"
//! [!CAUTION]: # "⚠️ CAUTION"
#![doc = include_str!("../README.md")]

pub mod bindings;
pub mod capabilities;
pub mod ossl_callback;
pub mod osslparams;

pub type OurError = anyhow::Error;

pub mod keymgmt {
    pub mod selection {
        use super::super::bindings;
        use anyhow::anyhow;
        use bitflags::bitflags;
        use std::fmt::Debug;
        use std::result::Result::Ok;

        bitflags! {
        #[derive(Debug)]
                        pub struct Selection: u32 {
            const PRIVATE_KEY = bindings::OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
            const PUBLIC_KEY = bindings::OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
            const DOMAIN_PARAMETERS = bindings::OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
            const OTHER_PARAMETERS = bindings::OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;

            const ALL_PARAMETERS = bindings::OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
            const KEYPAIR = bindings::OSSL_KEYMGMT_SELECT_KEYPAIR;
            const ALL = bindings::OSSL_KEYMGMT_SELECT_ALL;
                        }
                    }

        impl TryFrom<u32> for Selection {
            type Error = crate::OurError;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                match Selection::from_bits(value) {
                    Some(s) => Ok(s),
                    None => Err(anyhow!(
                        "Invalid OSSL_KEYMGMT_SELECT flag value: {:?}",
                        value
                    )),
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
