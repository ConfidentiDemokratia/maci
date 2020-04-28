#!/bin/bash

# Used by the CircleCI process to generate a checksum of the snark files so
# that it can cache them.

cd "$(dirname "$0")"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rust.sh
chmod a+x rust.sh
sh rust.sh -y
rm rust.sh
source $HOME/.cargo/env
cargo install zkutil --version 0.2.1
