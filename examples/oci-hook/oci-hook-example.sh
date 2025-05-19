#!/bin/bash

log_file="/opt/oci-hook/oci-hook-example.log"

function log {
    local message="$1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message" >> "$log_file"
}


log "Start $0"

read -r context
log "Received context: $context"

log "Args: $*"

log "End $0"
