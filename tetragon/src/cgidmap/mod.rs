use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use tracing::*;
use uuid::Uuid;

type CgroupID = u64;
type ContainerID = String;
type PodID = Uuid;

pub(crate) static CGID_MAP: LazyLock<Mutex<CgidMap>> = LazyLock::new(|| Mutex::new(CgidMap::new()));

#[derive(Clone, Debug)]
struct Entry {
    cg_id: CgroupID,
    cont_id: ContainerID,
    pod_id: PodID,
    invalid: bool,
}

pub(crate) struct CgidMap {
    entries: Vec<Entry>,
    cg_map: HashMap<CgroupID, usize>,
    cont_map: HashMap<ContainerID, usize>,
    invalid_cnt: usize,
    // TODO
    // log logrus.FieldLogger
    // *logger.DebugLogger
    // criResolver *criResolver
}

impl CgidMap {
    fn new() -> Self {
        CgidMap {
            entries: Vec::with_capacity(1024),
            cg_map: HashMap::new(),
            cont_map: HashMap::new(),
            invalid_cnt: 0,
        }
    }

    fn add_entry_alloc_id(&mut self, e: Entry) -> usize {
        let len = self.entries.len();

        if self.entries.capacity() > len || self.invalid_cnt == 0 {
            self.entries.push(e);
            return len;
        }

        if let Some(invalid_index) = self.entries.iter_mut().position(|entry| entry.invalid) {
            self.entries[invalid_index] = e;
            return invalid_index;
        }

        warn!("invalid count is wrong. Please report this message to Tetragon developers");
        self.entries.push(e);
        len
    }

    fn add_entry(&mut self, entry: Entry) {
        let idx = self.add_entry_alloc_id(entry.clone());
        self.cg_map.insert(entry.cg_id, idx);
        self.cont_map.insert(entry.cont_id.clone(), idx);
    }

    fn update_entry(&mut self, idx: usize, new_entry: Entry) {
        let old_entry = &mut self.entries[idx];
        if old_entry.pod_id != new_entry.pod_id {
            warn!("invalid entry in cgidmap: mismatching pod id, please report this message to Tetragon developers: old pod ID {}, new pod ID {}, container ID {}", old_entry.pod_id, new_entry.pod_id, new_entry.cont_id);
            old_entry.pod_id = new_entry.pod_id;
        }

        if old_entry.cg_id != new_entry.cg_id {
            warn!("invalid entry in cgidmap: mismatching cg id, please report this message to Tetragon developers: old cgroup ID {} new cgroup ID {}, container ID {}, pod ID {}", old_entry.cg_id, new_entry.cg_id, new_entry.cont_id, new_entry.pod_id);
            old_entry.cg_id = new_entry.cg_id;
        }
    }
}

pub async fn add(pod_id: PodID, cont_id: ContainerID, cg_id: CgroupID) {
    let entry = Entry {
        cg_id,
        cont_id: cont_id.clone(),
        pod_id,
        invalid: false,
    };

    let mut map = CGID_MAP.lock().unwrap();
    if let Some(&idx) = map.cont_map.get(&cont_id) {
        map.update_entry(idx, entry);
        return;
    }
    map.add_entry(entry);
}

pub async fn get(cg_id: CgroupID) -> Option<ContainerID> {
    let map = CGID_MAP.lock().unwrap();
    if let Some(&idx) = map.cg_map.get(&cg_id) {
        let entry = &map.entries[idx];
        return Some(entry.cont_id.clone());
    }
    None
}

// Update updates the cgid map for the container ids of a given pod
pub async fn update(pod_id: PodID, cont_ids: &mut HashSet<ContainerID>) {
    let mut remove_cg = Vec::new();
    let mut remove_cont = Vec::new();
    let mut invalid_count = 0;

    let mut map = CGID_MAP.lock().unwrap();
    map.entries.iter_mut().for_each(|e| {
        // skip invalid entries
        if e.invalid {
            return;
        }
        // skip entries that are not for the given pod
        if e.pod_id != pod_id {
            return;
        }
        // container is still part of the pod, leave it as is
        if cont_ids.take(&e.cont_id).is_some() {
            debug!("container {} is still part of pod {}", e.cont_id, pod_id);
            return;
        }
        // container was removed from pod
        debug!("container {} was removed {}", e.cont_id, pod_id);
        e.invalid = true;

        // collect IDs to remove from maps after iteration to avoid modifying maps during iteration
        remove_cg.push(e.cg_id);
        remove_cont.push(e.cont_id.clone());
        invalid_count += 1;
    });

    for cg_id in remove_cg {
        map.cg_map.remove(&cg_id);
    }
    for cont_id in remove_cont {
        map.cont_map.remove(&cont_id);
    }
    map.invalid_cnt += invalid_count;

    // if cont_ids.is_empty() {
    //     return;
    // }

    // TODO: schedule unmapped ids to be resolved by the CRI resolver
    // unmappedIDs := make([]unmappedID, 0, len(tmp))
    // for id := range tmp {
    // 	unmappedIDs = append(unmappedIDs, unmappedID{
    // 		podID:  podID,
    // 		contID: id,
    // 	})
    // }
    // if m.criResolver != nil {
    // 	m.criResolver.enqeue(unmappedIDs)
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn teardown() {
        let mut map = CGID_MAP.lock().unwrap();
        map.entries.clear();
        map.cg_map.clear();
        map.cont_map.clear();
        map.invalid_cnt = 0;
    }

    #[tokio::test]
    async fn test_add() {
        let pod_id = Uuid::parse_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d1").unwrap();
        let cont_id = "container001".to_string();
        let cg_id = 123450001;

        add(pod_id, cont_id.clone(), cg_id).await;

        {
            let map = CGID_MAP.lock().unwrap();
            assert_eq!(map.entries.len(), 1);
            let entry = &map.entries[0];
            assert_eq!(entry.cont_id, cont_id);
            assert_eq!(entry.cg_id, cg_id);
        }

        teardown().await;
    }

    #[tokio::test]
    async fn test_get() {
        let pod_id = Uuid::parse_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d2").unwrap();
        let cont_id = "container002".to_string();
        let cg_id = 123450002;

        add(pod_id, cont_id.clone(), cg_id).await;

        let result = get(cg_id).await;
        assert_eq!(result, Some(cont_id));

        teardown().await;
    }

    #[tokio::test]
    async fn test_update_partialy_container_remove() {
        let pod_id = Uuid::parse_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d3").unwrap();
        let cont_id1 = "container003-1".to_string();
        let cg_id1 = 123450003;
        let cont_id2 = "container003-2".to_string();
        let cg_id2 = 678900003;

        add(pod_id, cont_id1.clone(), cg_id1).await;
        add(pod_id, cont_id2.clone(), cg_id2).await;

        {
            let map = CGID_MAP.lock().unwrap();
            assert_eq!(map.entries.len(), 2);
            assert_eq!(map.cg_map.len(), 2);
            assert_eq!(map.cont_map.len(), 2);
        }

        // Simulate the removal of container1
        let mut cont_ids = HashSet::new();
        cont_ids.insert(cont_id1.clone());

        update(pod_id, &mut cont_ids).await;

        {
            let map = CGID_MAP.lock().unwrap();
            assert_eq!(map.entries.len(), 2);
            assert_eq!(map.cg_map.len(), 1);
            assert_eq!(map.cont_map.len(), 1);
        }

        teardown().await;
    }

    #[tokio::test]
    async fn test_update_all_container_remove() {
        let pod_id = Uuid::parse_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d4").unwrap();
        let cont_id1 = "container004-1".to_string();
        let cg_id1 = 123450004;
        let cont_id2 = "container004-2".to_string();
        let cg_id2 = 678900004;

        add(pod_id, cont_id1.clone(), cg_id1).await;
        add(pod_id, cont_id2.clone(), cg_id2).await;

        {
            let map = CGID_MAP.lock().unwrap();
            assert_eq!(map.entries.len(), 2);
            assert_eq!(map.cg_map.len(), 2);
            assert_eq!(map.cont_map.len(), 2);
        }

        // Simulate the removal of container1 and cotnainer2
        let mut cont_ids = HashSet::new();

        update(pod_id, &mut cont_ids).await;

        {
            let map = CGID_MAP.lock().unwrap();
            assert_eq!(map.entries.len(), 2);
            assert!(map.entries.iter().all(|e| e.invalid));
            assert_eq!(map.cg_map.len(), 0);
            assert_eq!(map.cont_map.len(), 0);
        }
        teardown().await;
    }
}
