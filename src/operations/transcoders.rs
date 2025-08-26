//! This module provides utilities for [`decoder`][provider-decoder(7ossl)]
//! [Operations][provider(7ossl)#Operations] in the context of
//! [OpenSSL Providers][provider(7ossl)].
//!
//! # Purpose
//! The `keymgmt` module contains tools and abstractions to facilitate the implementation
//! of [key management functionality][provider-keymgmt(7ossl)]
//! for [OpenSSL Providers][provider(7ossl)].
//!
//! # References
//!
//! - [provider-decoder(7ossl)]
//! - [provider(7ossl)]
//!
//!
//! [provider(7ossl)]: https://docs.openssl.org/master/man7/provider/
//! [provider(7ossl)#Operations]: https://docs.openssl.org/master/man7/provider/#operations
//! [provider-decoder(7ossl)]: https://docs.openssl.org/master/man7/provider-decoder/

pub use crate::decoder_make_does_selection_fn as make_does_selection_fn;

use super::keymgmt::selection::Selection;
use crate::bindings::CStr;
use crate::bindings::OSSL_DISPATCH;

pub trait Decoder {
    const PROPERTY_DEFINITION: &'static CStr;
    const DISPATCH_TABLE: &'static [OSSL_DISPATCH];
}

pub trait Encoder {
    const PROPERTY_DEFINITION: &'static CStr;
    const DISPATCH_TABLE: &'static [OSSL_DISPATCH];
}

pub trait DoesSelection {
    const SELECTION_MASK: Selection;
    const SUPPORT_GUESSING: bool = true;

    fn does_selection(selection: Selection) -> bool {
        log::trace!("Called!");

        log::trace!("selection: {:#b}", selection);
        log::trace!("we're offering: {:#b}", Self::SELECTION_MASK);

        if selection.is_empty() {
            return Self::SUPPORT_GUESSING;
        }

        let checks = [
            Selection::PRIVATE_KEY,
            Selection::PUBLIC_KEY,
            Selection::ALL_PARAMETERS,
        ];
        for check in checks {
            if selection.contains(check) {
                return Self::SELECTION_MASK.contains(check);
            }
        }

        return false;
    }
}

mod macros {
    #[macro_export]
    macro_rules! decoder_make_does_selection_fn {
        ( $fn_name:ident, $decoder_type:ty ) => {
            // based on oqsprov/oqs_decode_der2key.c:der2key_check_selection() in the OQS provider
            pub(super) unsafe extern "C" fn $fn_name(
                vprovctx: *mut c_void,
                selection: c_int,
            ) -> c_int {
                const ERROR_RET: c_int = 0;
                log::trace!("Called!");

                const _: fn() = || {
                    fn assert_impl<T: DoesSelection>() {}
                    assert_impl::<$decoder_type>();
                };

                let _provctx: &OpenSSLProvider<'_> = $crate::handleResult!(vprovctx.try_into());

                let selection = $crate::handleResult!(Selection::try_from(selection as u32));

                match <$decoder_type>::does_selection(selection) {
                    true => return 1,
                    false => return 0,
                }
            }
        };
    }
}
