#!/bin/bash
set -e

REMOTE_USER="dayat" # Change if needed, assuming 'pi' or user handles ssh config
REMOTE_HOST="raspi"
REMOTE_DIR="~/ngfw"

echo "Deploying to $REMOTE_HOST..."

# Sync files
# Using rsync to exclude build artifacts and .git
rsync -avz --exclude '.git' --exclude 'build' --exclude '__pycache__' ./ $REMOTE_HOST:$REMOTE_DIR

echo "Files synced."

# Execute build and run on remote
ssh $REMOTE_HOST << EOF
    cd $REMOTE_DIR
    
    # Ensure setup script is executable and run it if flag provided
    chmod +x scripts/setup_pi.sh
    if [ "\$1" == "--setup" ]; then
        echo jalaprang | sudo -S ./scripts/setup_pi.sh
    fi

    # Build
    echo "Building..."
    make

    # Bind Network Devices to DPDK
    echo "Binding network devices..."
    echo jalaprang | sudo -S driverctl set-override 0000:01:00.0 vfio-pci || echo "Failed to bind 0000:01:00.0"
    echo jalaprang | sudo -S driverctl set-override 0000:01:00.1 vfio-pci || echo "Failed to bind 0000:01:00.1"

    # Run (needs sudo for DPDK)
    echo "Starting NGFW..."
    echo jalaprang | sudo -S ./build/l2fwd -l 0-3 -n 4 -- -p 0x3 -T 10
EOF
