# OCI Hook in CRI-O

OCI Hook documentation:
https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md

## Prepare the Hook Script
Create a directory to store the hook script:
```
mkdir /opt/oci-hook
```

Copy the hook script to the directory:
```
cp examples/oci-hook/oci-hook-example.sh /opt/oci-hook/
```

Make the script executable:
```
chmod +x /opt/oci-hook/oci-hook-example.sh
```

## Configure the Hook

Copy the hook configuration file to the appropriate directory:
```
cp examples/oci-hook/oci-hook-example.json /usr/share/containers/oci/hooks.d/
```

## Test the Hook
Run a test pod:
```
kubectl run --image ngix oci-hook-example-pod
```

Check the hook script's log
```
cat /opt/oci-hook/oci-hook-example.log
```

Example output:
```
[2025-05-17 23:32:23] Start /opt/oci-hook/oci-hook-example.sh
[2025-05-17 23:32:23] Args: arg2
[2025-05-17 23:32:23] End /opt/oci-hook/oci-hook-example.sh
```

---
## Prepare the Hook Script
Create a directory to store the hook script:
```
mkdir /opt/oci-hook
```

Copy the hook script to the directory:
```
cp examples/oci-hook/call-tetragon.sh /opt/oci-hook/
```

Make the script executable:
```
chmod +x /opt/oci-hook/call-tetragon.sh
```

## Configure the Hook

Copy the hook configuration file to the appropriate directory:
```
cp examples/oci-hook/call-tetragon.json /usr/share/containers/oci/hooks.d/
```


---
Create docker secret
```
kubectl create secret docker-registry my-docker-secret \
--docker-username=xxx \
--docker-password=yyy \
--docker-email=zzz
```

Run pod with imagePullSecret
```
kubectl run test-nginx \
  --image=docker.io/library/nginx:latest \
  --image-pull-policy=Always \
  --overrides='
{
  "spec": {
    "imagePullSecrets": [
      {
        "name": "my-docker-secret"
      }
    ]
  }
}'
```
