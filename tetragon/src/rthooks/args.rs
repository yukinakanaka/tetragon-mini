use crate::api;
use crate::cgroups;
use std::path::Path;
use tracing::*;

const UID_STRING_LEN: usize = "00000000-0000-0000-0000-000000000000".len();

pub struct CreateContainerArg {
    req: api::CreateContainer,
    // watcher: Arc<dyn watcher::PodAccessor>,

    // cached values
    cgroup_id: Option<u64>,
    pod: Option<k8s_openapi::api::core::v1::Pod>,
    host_cgroup_path: String,
}

impl CreateContainerArg {
    // TODO: support watcher
    // pub fn new(req: api::CreateContainer, watcher) -> Self {
    pub fn new(req: api::CreateContainer) -> Self {
        Self {
            req,
            // watcher,
            cgroup_id: None,
            pod: None,
            host_cgroup_path: String::new(),
        }
    }

    pub fn host_cgroup_path(&mut self) -> Result<String, std::io::Error> {
        if self.host_cgroup_path.is_empty() {
            let cg_path = &self.req.cgroups_path;
            let cg_root = cgroups::linux::host_cgroup_root()?;
            self.host_cgroup_path = Path::new(&cg_root)
                .join(cg_path)
                .to_string_lossy()
                .into_owned();
        }
        info!("host cgroup path: {}", self.host_cgroup_path);
        Ok(self.host_cgroup_path.clone())
    }

    pub fn cgroup_id(&mut self) -> Result<u64, std::io::Error> {
        if let Some(id) = self.cgroup_id {
            return Ok(id);
        }

        // retrieve the cgroup id from the host cgroup path.
        //
        // NB: A better solution might be to hook into cgroup creation routines and create a
        // mapping between directory and cgroup id that we maintain in user-space. Then, we can find
        // the id using this mapping.
        let path = self.host_cgroup_path()?;
        let cg_id = cgroups::linux::get_cgroup_id_from_sub_cgroup(&path)?;

        self.cgroup_id = Some(cg_id);
        info!("cgroup id: {}", cg_id);
        Ok(cg_id)
    }

    pub fn pod_id(&self) -> String {
        if !self.req.pod_uid.is_empty() {
            return self.req.pod_uid.clone();
        }
        pod_id_from_cgroup_path(&self.req.cgroups_path)
    }

    pub fn container_id(&self) -> String {
        if !self.req.container_id.is_empty() {
            return self.req.container_id.clone();
        }
        container_id_from_cgroup_path(&self.req.cgroups_path)
    }

    pub fn pod(&mut self) -> Result<&k8s_openapi::api::core::v1::Pod, std::io::Error> {
        if self.pod.is_some() {
            return Ok(self.pod.as_ref().unwrap());
        }

        let pod = if let Some(h) = self.req.annotations.get("kubernetes.io/config.hash") {
            // NB: this is a static pod, so we need to find its mirror in the API server
            self.find_mirror_pod(h)?
        } else {
            self.find_pod()?
        };

        self.pod = Some(pod);
        Ok(self.pod.as_ref().unwrap())
    }

    fn find_mirror_pod(
        &self,
        hash: &str,
    ) -> Result<k8s_openapi::api::core::v1::Pod, std::io::Error> {
        // TODO: implement using watcher
        // retry(5, Duration::from_millis(10), || {
        //     self.watcher.find_mirror_pod(hash)
        // })
        let dummy_pod = k8s_openapi::api::core::v1::Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("mirror-{}", hash)),
                ..Default::default()
            },
            ..Default::default()
        };
        Ok(dummy_pod)
    }

    fn find_pod(&self) -> Result<k8s_openapi::api::core::v1::Pod, std::io::Error> {
        // TODO: implement using watcher
        // let pod_id = self.pod_id()?;

        // retry(5, Duration::from_millis(10), || {
        //     self.watcher.find_pod(&pod_id)
        // })
        let dummy_pod = k8s_openapi::api::core::v1::Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("findpod".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        Ok(dummy_pod)
    }
}

fn pod_id_from_cgroup_path(p: &str) -> String {
    let pod_path = Path::new(p).parent().unwrap_or(Path::new(""));
    let mut pod_id_str = pod_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    if let Some(stripped) = pod_id_str.strip_suffix(".slice") {
        pod_id_str = stripped.to_string();
    }

    if pod_id_str.len() > UID_STRING_LEN {
        // pod prefixを削除
        pod_id_str = pod_id_str[pod_id_str.len() - UID_STRING_LEN..].to_string();
    }

    pod_id_str
}

fn container_id_from_cgroup_path(p: &str) -> String {
    let mut container_id = Path::new(p)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    // crio has cgroups paths such as crio-<ID> and crio-conmon-<ID>. Strip those prefixes.
    if let Some(idx) = container_id.rfind('-') {
        container_id = container_id[idx + 1..].to_string();
    }

    if let Some(stripped) = container_id.strip_suffix(".scope") {
        container_id = stripped.to_string();
    }

    container_id
}

// fn retry<R, F, E>(n_retries: usize, timeout: Duration, mut f: F) -> Result<R, E>
// where
//     F: FnMut() -> Result<R, E>,
//     E: std::fmt::Display,
// {
//     let mut last_err: Option<E> = None;

//     for i in 0..=n_retries {
//         match f() {
//             Ok(val) => return Ok(val),
//             Err(e) => {
//                 last_err = Some(e);

//                 if i < n_retries {
//                     sleep(timeout);
//                 }
//             }
//         }
//     }

//     Err(last_err.unwrap())
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pod_id_from_cgroup_path() {
        let test_cases = vec![
            (
                "/kubepods/besteffort/pod05e102bf-8744-4942-a241-9b6f07983a53/f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
                "05e102bf-8744-4942-a241-9b6f07983a53",
            ),
            (
                "/kubepods/besteffort/pod897277d4-5e6f-4999-a976-b8340e8d075e/crio-a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
                "897277d4-5e6f-4999-a976-b8340e8d075e",
            ),
            (
                "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod4c9f1974_5c46_44c2_b42f_3bbf0e98eef9.slice/cri-containerd-bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba.scope",
                "4c9f1974_5c46_44c2_b42f_3bbf0e98eef9",
            ),
        ];

        for (path, expected_id) in test_cases {
            assert_eq!(pod_id_from_cgroup_path(path), expected_id);
        }
    }

    #[test]
    fn test_container_id_from_cgroup_path() {
        let test_cases = vec![
            (
                "/kubepods/besteffort/pod05e102bf-8744-4942-a241-9b6f07983a53/f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
                "f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
            ),
            (
                "/kubepods/besteffort/pod897277d4-5e6f-4999-a976-b8340e8d075e/crio-a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
                "a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
            ),
            (
                "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod4c9f1974_5c46_44c2_b42f_3bbf0e98eef9.slice/cri-containerd-bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba.scope",
                "bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba",
            ),
            (
                "kubepods-besteffort.slice/kubepods-besteffort-pod3b673e1d_289e_4210_8ceb_5a253b48d390.slice/cri-containerd-5da35096936fefa0c7a7280a439fb8c680568820a20d410c7b9e30955d88a147.scope",
                "5da35096936fefa0c7a7280a439fb8c680568820a20d410c7b9e30955d88a147",
            ),
        ];

        for (path, expected_id) in test_cases {
            assert_eq!(container_id_from_cgroup_path(path), expected_id);
        }
    }
}
