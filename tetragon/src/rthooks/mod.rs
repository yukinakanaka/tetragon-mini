mod runner;

use crate::api::RuntimeHookRequest;
use runner::Runner;
use std::sync::{LazyLock, Mutex};
use thiserror::Error;

pub(crate) static GLOBAL_RUNNER: LazyLock<Mutex<Runner>> =
    LazyLock::new(|| Mutex::new(Runner::with_watcher()));

#[derive(Error, Debug)]
pub enum RtHookError {
    #[error("container creation callback failed: {0}")]
    CreateContainerError(String),

    #[error("callback registration failed: {0}")]
    RegistrationError(String),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

// TODO: refactor using trait or builder pattern
pub struct Callbacks {
    pub create_container:
        Option<Box<dyn Fn(&RuntimeHookRequest) -> Result<(), RtHookError> + Send + Sync>>,
}

pub fn register_callbacks_at_init(callbacks: Callbacks) {
    let mut global_runner = GLOBAL_RUNNER.lock().unwrap();
    global_runner.register_callback(callbacks);
}
