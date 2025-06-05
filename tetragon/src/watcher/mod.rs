use futures::{Stream, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::{api::Api, runtime::watcher, Client};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::*;

mod delayed_init;
use ahash::AHashMap;
use async_stream::stream;
use delayed_init::DelayedInit;
use parking_lot::RwLock;
use std::fmt::Debug;
use thiserror::Error;

use crate::k8s::util::extract_container_ids;

type ContainerID = String;
type PodCacheInner = Arc<RwLock<AHashMap<ContainerID, Arc<Pod>>>>;

#[derive(Debug)]
pub struct PodInformer {
    running_cache: PodCacheInner,
    running_cache_buffer: AHashMap<ContainerID, Arc<Pod>>,
    running_ready_tx: Option<delayed_init::Initializer<()>>,
    running_ready_rx: Arc<DelayedInit<()>>,

    terminated_cache: PodCacheInner,
    terminated_cache_buffer: AHashMap<ContainerID, Arc<Pod>>,
    terminated_ready_tx: Option<delayed_init::Initializer<()>>,
    terminated_ready_rx: Arc<DelayedInit<()>>,

    terminated_cache_max_size: usize,

    event_sender: broadcast::Sender<watcher::Event<Pod>>,
}

impl PodInformer {
    pub fn new() -> Self {
        Self::with_terminated_cache_limit(1000)
    }

    pub fn with_terminated_cache_limit(max_size: usize) -> Self {
        let (running_ready_tx, running_ready_rx) = DelayedInit::new();
        let (terminated_ready_tx, terminated_ready_rx) = DelayedInit::new();
        let (event_sender, _) = broadcast::channel(1000);
        Self {
            running_cache: Default::default(),
            running_cache_buffer: Default::default(),
            terminated_cache: Default::default(),
            terminated_cache_buffer: Default::default(),
            running_ready_tx: Some(running_ready_tx),
            running_ready_rx: Arc::new(running_ready_rx),
            terminated_ready_tx: Some(terminated_ready_tx),
            terminated_ready_rx: Arc::new(terminated_ready_rx),
            terminated_cache_max_size: max_size,
            event_sender,
        }
    }

    pub async fn run(self, stop: impl std::future::Future<Output = ()>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api = Api::<Pod>::default_namespaced(client);
        let use_watchlist = std::env::var("WATCHLIST")
            .map(|s| s == "1")
            .unwrap_or(false);
        let wc = if use_watchlist {
            watcher::Config::default().streaming_lists()
        } else {
            watcher::Config::default()
        };
        let stream = reflector(self, watcher(api, wc));
        let mut stream = Box::pin(stream);

        futures::pin_mut!(stop);
        loop {
            tokio::select! {
                _ = stream.next() => {}
                _ = &mut stop => {
                    info!("Stopping PodInformer");
                    break;
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn as_running_cache(&self) -> PodCache {
        PodCache {
            store: self.running_cache.clone(),
            ready_rx: self.running_ready_rx.clone(),
        }
    }

    #[must_use]
    pub fn as_terminated_cache(&self) -> PodCache {
        PodCache {
            store: self.terminated_cache.clone(),
            ready_rx: self.terminated_ready_rx.clone(),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<watcher::Event<Pod>> {
        self.event_sender.subscribe()
    }

    pub fn apply_watcher_event(&mut self, event: &watcher::Event<Pod>) {
        if let Err(e) = self.event_sender.send(event.clone()) {
            warn!("Event sender has no receivers. {:?}", e);
        }
        match event {
            watcher::Event::Apply(pod) => {
                let pod = Arc::new(pod.clone());

                let Some((running_ids, terminated_ids)) = extract_container_ids(&pod) else {
                    tracing::warn!("Pod has no container IDs, skipping: {:?}", pod);
                    return;
                };

                running_ids.iter().for_each(|id| {
                    self.running_cache.write().insert(id.clone(), pod.clone());
                });

                terminated_ids.iter().for_each(|id| {
                    self.running_cache.write().remove(id);
                    self.insert_to_terminated_cache(id.clone(), pod.clone());
                });
            }
            watcher::Event::Delete(pod) => {
                let pod = Arc::new(pod.clone());

                let Some((running_ids, terminated_ids)) = extract_container_ids(&pod) else {
                    tracing::warn!("Pod has no container IDs, skipping: {:?}", pod);
                    return;
                };

                running_ids.iter().for_each(|id| {
                    self.running_cache.write().insert(id.clone(), pod.clone());
                });

                terminated_ids.iter().for_each(|id| {
                    self.running_cache.write().remove(id);
                    self.insert_to_terminated_cache(id.clone(), pod.clone());
                });
            }
            watcher::Event::Init => {
                self.running_cache_buffer = AHashMap::new();
                self.terminated_cache_buffer = AHashMap::new();
            }
            watcher::Event::InitApply(pod) => {
                let pod = Arc::new(pod.clone());

                let Some((running_ids, terminated_ids)) = extract_container_ids(&pod) else {
                    tracing::warn!("Pod has no container IDs, skipping: {:?}", pod);
                    return;
                };

                running_ids.iter().for_each(|id| {
                    self.running_cache_buffer.insert(id.clone(), pod.clone());
                });

                terminated_ids.iter().for_each(|id| {
                    self.terminated_cache_buffer.insert(id.clone(), pod.clone());
                });
            }
            watcher::Event::InitDone => {
                let mut running_cache = self.running_cache.write();

                // Swap the buffer into the store
                std::mem::swap(&mut *running_cache, &mut self.running_cache_buffer);

                let mut terminated_cache = self.terminated_cache.write();
                // Swap the buffer into the store
                std::mem::swap(&mut *terminated_cache, &mut self.terminated_cache_buffer);

                // Clear the buffer
                // This is preferred over self.buffer.clear(), as clear() will keep the allocated memory for reuse.
                // This way, the old buffer is dropped.
                self.running_cache_buffer = AHashMap::new();
                self.terminated_cache_buffer = AHashMap::new();

                // Mark as ready after the Restart, "releasing" any calls to Store::wait_until_ready()
                if let Some(running_ready_tx) = self.running_ready_tx.take() {
                    running_ready_tx.init(())
                }
                if let Some(terminated_ready_tx) = self.terminated_ready_tx.take() {
                    terminated_ready_tx.init(())
                }
            }
        }
        debug!("running pods: {:?}", self.running_cache.read().keys());
        debug!("terminated pods: {:?}", self.terminated_cache.read().keys());
    }

    fn insert_to_terminated_cache(&self, key: ContainerID, value: Arc<Pod>) {
        let mut cache = self.terminated_cache.write();
        cache.insert(key, value);

        if cache.len() > self.terminated_cache_max_size {
            let excess = cache.len() - self.terminated_cache_max_size;
            let keys_to_remove: Vec<ContainerID> = cache.keys().take(excess).cloned().collect();

            for key in keys_to_remove {
                cache.remove(&key);
            }

            tracing::warn!(
                "Terminated cache size exceeded limit ({}). Removed {} entries.",
                self.terminated_cache_max_size,
                excess
            );
        }
    }
}

impl Default for PodInformer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
#[error("informer was dropped before store became ready")]
pub struct InformerDropped(delayed_init::InitDropped);

#[derive(Debug, Clone)]
pub struct PodCache {
    store: PodCacheInner,
    ready_rx: Arc<DelayedInit<()>>,
}

impl PodCache {
    pub async fn wait_until_ready(&self) -> Result<(), InformerDropped> {
        self.ready_rx.get().await.map_err(InformerDropped)
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<Arc<Pod>> {
        let store = self.store.read();
        store
            .get(key)
            // Clone to let go of the entry lock ASAP
            .cloned()
    }

    /// Return a full snapshot of the current values
    #[must_use]
    pub fn state(&self) -> Vec<Arc<Pod>> {
        let s = self.store.read();
        s.values().cloned().collect()
    }

    /// Return the number of elements in the store
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.read().len()
    }

    /// Return whether the store is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.read().is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct PodStore {
    pub running: PodCache,
    pub terminated: PodCache,
}

impl PodStore {
    /// Wait until the store is ready
    pub async fn wait_until_ready(&self) -> Result<(), InformerDropped> {
        self.running.wait_until_ready().await?;
        self.terminated.wait_until_ready().await?;
        Ok(())
    }

    /// Get a pod by its container ID from either running or terminated pods
    #[must_use]
    pub fn get(&self, container_id: &str) -> Option<Arc<Pod>> {
        self.running
            .get(container_id)
            .or_else(|| self.terminated.get(container_id))
    }
}

#[must_use]
pub fn pod_informer() -> (PodStore, PodInformer) {
    let i = PodInformer::default();

    (
        PodStore {
            running: i.as_running_cache(),
            terminated: i.as_terminated_cache(),
        },
        i,
    )
}

pub fn reflector<W>(mut informer: PodInformer, stream: W) -> impl Stream<Item = W::Item>
where
    W: Stream<Item = watcher::Result<watcher::Event<Pod>>>,
{
    let mut stream = Box::pin(stream);
    stream! {
        while let Some(event) = stream.next().await {
            match event {
                Ok(ev) => {
                    informer.apply_watcher_event(&ev);
                    yield Ok(ev);
                },
                Err(ev) => yield Err(ev)
            }
        }
    }
}
