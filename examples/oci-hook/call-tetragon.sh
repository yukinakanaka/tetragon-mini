#!/bin/bash

# Constants
LOG_FILE="/opt/oci-hook/call-tetragon.log"
PROJECT_DIR="/home/yukinakamura.linux/tetragon-mini"
GRPC_PORT="10001"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

convert_cgroup_path() {
    local input="$1"
    
    local base_slice=$(echo "$input" | cut -d':' -f1)
    local container_runtime=$(echo "$input" | cut -d':' -f2)
    local container_id=$(echo "$input" | cut -d':' -f3)
    
    local pod_id=${base_slice#kubepods-besteffort-}
    pod_id=${pod_id%.slice}
    
    echo "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-${pod_id}.slice/${container_runtime}-${container_id}.scope"
}

# Main execution starts here
log "Start $0 with args: $*"

# Read container context from stdin
read -r context
log "Received context: $context"

Process container information

# Extract values from context
ROOT_DIR=$(echo "$context" | jq -r '.root')
CONTAINER_NAME=$(echo ${context} | jq -r '.annotations."io.kubernetes.container.name"')
CONTAINER_ID=$(echo ${context} | jq -r '.annotations."io.kubernetes.cri-o.ContainerID"')
POD_NAME=$(echo ${context} | jq -r '.annotations."io.kubernetes.pod.name"')
POD_UID=$(echo ${context} | jq -r '.annotations."io.kubernetes.pod.uid"')
POD_NAMESPACE=$(echo ${context} | jq -r '.annotations."io.kubernetes.pod.namespace"')
ANNOTATIONS=$(echo "$context" | jq -r '.annotations')

# Get and parse cgroup path
# BUNDLE=$(echo "$context" | jq -r '.bundle')
RUN_CONFIG="$(pwd)/config.json"
if [[ ! -f "$RUN_CONFIG" ]]; then
    log "Error: Config file not found: $RUN_CONFIG"
    exit 1
fi
CGROUP_PATH_RAW=$(jq -r '.linux.cgroupsPath' "$RUN_CONFIG")
log "Raw cgroup path: $CGROUP_PATH_RAW"
CGROUP_PATH=$(convert_cgroup_path "$CGROUP_PATH_RAW")

# Create input JSON for RuntimeHook
JSON_DATA='{
    "createContainer": {
        "cgroupsPath": "'$CGROUP_PATH'",
        "rootDir": "'$ROOT_DIR'",
        "containerName": "'$CONTAINER_NAME'",
        "containerID": "'$CONTAINER_ID'",
        "podName": "'$POD_NAME'",
        "podUID": "'$POD_UID'",
        "podNamespace": "'$POD_NAMESPACE'",
        "annotations": '$ANNOTATIONS'
    }
}'


# Send request to tetragon service
cd "${PROJECT_DIR}" || { log "Error: Could not change to ${PROJECT_DIR}"; exit 1; }

log "Sending request to tetragon service"
log "gRPC command with JSON:"
echo $JSON_DATA >> "$LOG_FILE"
log "gRPC command:"

/usr/local/bin/grpcurl -plaintext \
    -d "$JSON_DATA" \
    --import-path "$PROJECT_DIR/tetragon/proto" \
    -proto "$PROJECT_DIR/tetragon/proto/sensors.proto" \
    "[::1]:$GRPC_PORT" tetragon.FineGuidanceSensors/RuntimeHook >> "$LOG_FILE" 2>&1

log "End $0"
