# OCI Hook in CRI-O

OCI Hook documentation:
https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md

## Prerequisties
- Use [cri-o](https://cri-o.io/) as a Container Runtime
- [grpcurl](https://github.com/fullstorydev/grpcurl?tab=readme-ov-file#installation)

## Install oci-hook
- Set your tetragon-mini directory in PROJECT_DIR in `set-oci-hook.sh`
- Move to contrib/tetragon-rthooks
```
cd contrib/tetragon-rthooks
```
- Run the `set-oci-hook.sh`
```
sudo ./install-oci-hook.sh
```

## Test oci-hook
Run a test pod:
```
kubectl run --image ngix oci-hook-test
```

Check the hook script's log
```
cat /opt/oci-hook/oci-hook.log
```

Example output:
```
[2025-06-10 16:02:42] Start /opt/oci-hook/oci-hook.sh
[2025-06-10 16:02:42] Received context: {"ociVersion":"1.0","id":"51d5adf740c79d44a315d8bdd03a91c22b9af4b692d2764b1133e63dcdd2670b",...
[2025-06-10 16:02:42] Raw cgroup path: kubepods-besteffort-podcbe1997c_18fc_4588_8499_605e8807a30f.slice:crio:51d5adf740c79d44a315d8bdd03a91c22b9af4b692d2764b1133e63dcdd2670b
[2025-06-10 16:02:42] Sending request to tetragon service
[2025-06-10 16:02:42] gRPC command with JSON:
{ "createContainer": { "cgroupsPath": "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podcbe1997c_18fc_4588_8499_605e8807a30f.slice/crio-51d5adf740c79d44a315d8bdd03a91c22b9af4b692d2764b1133e63dcdd2670b.scope", ...
[2025-06-10 16:02:42] gRPC command:
Failed to dial target host "[::1]:10001": dial tcp [::1]:10001: connect: connection refused
[2025-06-10 16:02:42] End /opt/oci-hook/oci-hook.sh
```

## Uninstall oci-hook
- Move to contrib/tetragon-rthooks
```
cd contrib/tetragon-rthooks
```
- Run the `uninstall-oci-hook.sh`
```
sudo ./uninstall-oci-hook.sh
```
