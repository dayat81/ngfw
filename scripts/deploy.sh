#!/bin/bash
set -e

REMOTE_USER="pi" # Change if needed, assuming 'pi' or user handles ssh config
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
    if [ "$1" == "--setup" ]; then
        ./scripts/setup_pi.sh
    fi

    # Build
    make

    # Run (needs sudo for DPDK)
    echo "Starting NGFW..."
    sudo ./build/l2fwd -l 0-3 -n 4 -- -p 0x3 -T 10
EOF
