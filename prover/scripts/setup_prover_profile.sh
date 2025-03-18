#!/bin/bash

# Import default file names
source "$(dirname "$0")/default_files.sh"

# Usage function
usage() {
    echo "Usage: $0 <source_directory>"
    echo "Creates _prover_profile directory with symlinks to prover files using standard names"
    exit 1
}

if [ "$#" -ne 1 ]; then
    usage
fi

SOURCE_DIR="$1"
PROFILE_DIR="_prover_profile"

# Create profile directory if it doesn't exist
mkdir -p "$PROFILE_DIR"

# Function to create symlink with error checking
create_link() {
    local src="$1"
    local dest="$2"
    if [ -f "$src" ]; then
        ln -sf "$(realpath "$src")" "$dest"
    else
        echo "Warning: Source file not found: $src"
    fi
}

# UBV Circuit files
create_link "$SOURCE_DIR/ubv_pi_6_deg_25_inner_64.gate_config" "$PROFILE_DIR/$UBV_GATE_CONFIG"
create_link "$SOURCE_DIR/ubv_pi_6_deg_25_inner_64.pk" "$PROFILE_DIR/$UBV_PK"
create_link "$SOURCE_DIR/ubv_pi_6_deg_25_inner_64.pk.bps" "$PROFILE_DIR/${UBV_PK}.bps"
create_link "$SOURCE_DIR/ubv_pi_6_deg_25_inner_64.protocol" "$PROFILE_DIR/$UBV_PROTOCOL"
create_link "$SOURCE_DIR/ubv_pi_6_deg_25_inner_64.vk" "$PROFILE_DIR/$UBV_VK"

# Keccak Circuit files
create_link "$SOURCE_DIR/keccak_pi_6_deg_23_inner_64_outer_4.gate_config" "$PROFILE_DIR/$KECCAK_GATE_CONFIG"
create_link "$SOURCE_DIR/keccak_pi_6_deg_23_inner_64_outer_4.pk" "$PROFILE_DIR/$KECCAK_PK"
create_link "$SOURCE_DIR/keccak_pi_6_deg_23_inner_64_outer_4.pk.bps" "$PROFILE_DIR/${KECCAK_PK}.bps"
create_link "$SOURCE_DIR/keccak_pi_6_deg_23_inner_64_outer_4.protocol" "$PROFILE_DIR/$KECCAK_PROTOCOL"
create_link "$SOURCE_DIR/keccak_pi_6_deg_23_inner_64_outer_4.vk" "$PROFILE_DIR/$KECCAK_VK"

# Outer Circuit files
create_link "$SOURCE_DIR/outer_pi_6_deg_26_inner_64_outer_4_ubv_deg_25_keccak_deg_23.gate_config" "$PROFILE_DIR/$OUTER_GATE_CONFIG"
create_link "$SOURCE_DIR/outer_pi_6_deg_26_inner_64_outer_4_ubv_deg_25_keccak_deg_23.pk" "$PROFILE_DIR/$OUTER_PK"
create_link "$SOURCE_DIR/outer_pi_6_deg_26_inner_64_outer_4_ubv_deg_25_keccak_deg_23.pk.bps" "$PROFILE_DIR/${OUTER_PK}.bps"
create_link "$SOURCE_DIR/outer_pi_6_deg_26_inner_64_outer_4_ubv_deg_25_keccak_deg_23.protocol" "$PROFILE_DIR/$OUTER_PROTOCOL"
create_link "$SOURCE_DIR/outer_pi_6_deg_26_inner_64_outer_4_ubv_deg_25_keccak_deg_23.vk" "$PROFILE_DIR/$OUTER_VK"
create_link "$SOURCE_DIR/outer_pi_6_deg_26_inner_64_outer_4_ubv_deg_25_keccak_deg_23.num_instance" "$PROFILE_DIR/$OUTER_INSTANCE_SIZE"

# Config file
create_link "$SOURCE_DIR/upa_config_batch_size_256.json" "$PROFILE_DIR/$CONFIG"

# SRS files
create_link "$SOURCE_DIR/deg_25.srs" "$PROFILE_DIR/$UBV_SRS"      # For UBV/BV circuit
create_link "$SOURCE_DIR/deg_23.srs" "$PROFILE_DIR/$KECCAK_SRS"  # For Keccak circuit
create_link "$SOURCE_DIR/deg_26.srs" "$PROFILE_DIR/$OUTER_SRS"   # For Outer circuit

echo "Prover profile setup complete in $PROFILE_DIR"
