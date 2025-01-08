use crate::process::ProcessInternal;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::LazyLock;
use tokio::sync::Mutex;

pub static CACHE: LazyLock<Mutex<LruCache<String, ProcessInternal>>> =
    LazyLock::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap())));

pub async fn cache_add(process: ProcessInternal) -> anyhow::Result<()> {
    let mut cache = CACHE.lock().await;
    let exec_id = process.process.exec_id.clone();

    cache.put(exec_id.clone(), process);

    Ok(())
}

pub async fn cache_get(exec_id: &String) -> Option<ProcessInternal> {
    let mut cache = CACHE.lock().await;
    cache.get(exec_id).cloned()
}
