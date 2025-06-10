#!/bin/bash
set -e

# Create a directory to store the hook script:
mkdir -p /opt/oci-hook

# Copy the hook script to the directory:
cp ./oci-hook.sh /opt/oci-hook/

# Make the script executable:
chmod +x /opt/oci-hook/oci-hook.sh

# Congfigure the hook script to be used by the OCI runtime:
cp ./oci-hook.json /usr/share/containers/oci/hooks.d/

echo "OCI hook installed successfully."
ls -la /opt/oci-hook/oci-hook.sh
ls -la /usr/share/containers/oci/hooks.d/oci-hook.json
