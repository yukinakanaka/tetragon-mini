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
        let errors: Vec<String> = self
            .callbacks
            .iter()
            .filter_map(|callback| {
                let create_container = &callback.create_container;
                create_container(request)
                    .err()
                    .map(|e| format!("create_container callback failed: {}", e))
            })
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(RtHookError::RunHooksError(errors.join("; ")))
        }
    }
}
