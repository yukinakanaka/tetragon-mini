#!/bin/bash

rm -f /opt/oci-hook/*
rm /usr/share/containers/oci/hooks.d/oci-hook.json

echo "OCI hook uninstalled successfully."
