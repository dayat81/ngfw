#!/bin/bash

# Exit on error
set -e

echo "Setting up Raspberry Pi environment..."

# Update and install dependencies
sudo apt-get update
sudo apt-get install -y libdpdk-dev librocksdb-dev python3-pip python3-requests build-essential pkg-config libnuma-dev driverctl

# Load standard drivers
sudo modprobe vfio-pci

# Install Mongoose dependencies if not present (mongoose.c/h should be part of repo, but if not we can curl it)
# We will download it here just in case, or ensure it's in the repo
if [ ! -f mongoose.c ]; then
    echo "Downloading mongoose.c..."
    curl -L -o mongoose.c https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c
fi

if [ ! -f mongoose.h ]; then
    echo "Downloading mongoose.h..."
    curl -L -o mongoose.h https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h
fi

# Configure Hugepages
echo "Configuring Hugepages..."
# Check if hugepages are already configured
if [ ! -d /mnt/huge ]; then
    sudo mkdir -p /mnt/huge
    sudo mount -t hugetlbfs nodev /mnt/huge
    echo "vm.nr_hugepages = 64" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
fi

# Ensure hugepages are allocated now
sudo sysctl -w vm.nr_hugepages=64

echo "Setup complete!"
