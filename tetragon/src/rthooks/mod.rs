pub mod args;
pub mod runner;

use crate::api::RuntimeHookRequest;
use crate::cgidmap;
use runner::Runner;
use std::sync::{LazyLock, Mutex};
use thiserror::Error;

pub(crate) static GLOBAL_RUNNER: LazyLock<Mutex<Runner>> =
    LazyLock::new(|| Mutex::new(Runner::with_watcher()));

// TODO: refactor more smart initialization
pub fn init_runner() -> &'static Mutex<Runner> {
    let runner = &GLOBAL_RUNNER;
    cgidmap::rthooks::register_callback();
    runner
}

#[derive(Error, Debug)]
pub enum RtHookError {
    #[error("container creation callback failed: {0}")]
    CreateContainerError(String),

    #[error("callback registration failed: {0}")]
    RegistrationError(String),

    #[error("some hooks failed: {0}")]
    RunHooksError(String),

    #[error("event type is not supported: {0}")]
    UnsupportedEvent(String),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

// TODO: refactor using trait or builder pattern
pub type CreateContainerCallback =
    Box<dyn Fn(&mut args::CreateContainerArg) -> Result<(), RtHookError> + Send + Sync>;
pub struct Callbacks {
    pub create_container: CreateContainerCallback,
}

pub fn register_callbacks_at_init(callbacks: Callbacks) {
    let mut global_runner = GLOBAL_RUNNER.lock().unwrap();
    global_runner.register_callback(callbacks);
}

pub fn run_hooks(request: &RuntimeHookRequest) -> Result<(), RtHookError> {
    let global_runner = GLOBAL_RUNNER.lock().unwrap();
    global_runner.run_hooks(request)
}
