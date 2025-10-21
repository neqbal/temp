#!/usr/bin/env bash
# Setup two TAP interfaces and attach them to bridge br0

set -e

BRIDGE="br0"
USER_NAME=$(whoami)

create_tap() {
    local TAP=$1

    # If TAP already exists, skip creation
    if ip link show "$TAP" &>/dev/null; then
        echo "[$TAP] already exists, skipping creation."
    else
        echo "Creating $TAP..."
        sudo ip tuntap add dev "$TAP" mode tap user "$USER_NAME"
    fi

    echo "Bringing $TAP up..."
    sudo ip link set "$TAP" up

    echo "Attaching $TAP to bridge $BRIDGE..."
    sudo ip link set "$TAP" master "$BRIDGE"
}

echo "Setting up TAP interfaces for bridge: $BRIDGE"
create_tap tap0
create_tap tap1

echo "Setup complete."
echo
echo "Current bridge status:"
bridge link | grep "$BRIDGE" || echo "No interfaces attached yet."

exit 0
