pub use crate::OurError;

use std::sync::Once;

static INIT: Once = Once::new();

fn try_init_logging() -> Result<(), OurError> {
    env_logger::Builder::from_default_env()
        //.filter_level(log::LevelFilter::Debug)
        .format_timestamp(None) // Optional: disable timestamps
        .format_module_path(true) // Optional: disable module path
        .format_target(false) // Optional: disable target
        .format_source_path(true)
        .is_test(cfg!(test))
        .try_init()
        .map_err(OurError::from)
}

pub(crate) fn setup() -> Result<(), OurError> {
    INIT.call_once(|| {
        try_init_logging().expect("Failed to initialize the logging system");
    });

    Ok(())
}
