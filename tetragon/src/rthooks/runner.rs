use crate::api::RuntimeHookRequest;
use crate::rthooks::{Callbacks, RtHookError};

#[derive(Default)]
pub struct Runner {
    pub callbacks: Vec<Callbacks>,
    // TODO: watcher   watcher.PodAccessor
}

impl Runner {
    pub(crate) fn with_watcher() -> Self {
        Runner {
            callbacks: vec![],
            // watcher: watcher.PodAccessor::new(),
        }
    }
    pub fn register_callback(&mut self, callback: Callbacks) {
        self.callbacks.push(callback);
    }

    // TODO: call callbacks asynchronously
    pub fn run_hooks(&self, request: &RuntimeHookRequest) -> Result<(), RtHookError> {
        for callback in &self.callbacks {
            if let Some(create_container) = &callback.create_container {
                create_container(request)?;
            }
        }
        Ok(())
    }
}
