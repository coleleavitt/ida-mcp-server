#!/bin/bash
set -euo pipefail
IDA_DIR="$HOME/Downloads/Software/IDAPro/ida-pro-9.5-installed"
IDASDK_DIR="$HOME/Downloads/Software/IDAPro/ida-sdk-9.5/src"
cmake -S . -B build-9.5 -DCMAKE_BUILD_TYPE=Release -DIDASDK_DIR="$IDASDK_DIR" -DIDA_INSTALL_DIR="$IDA_DIR"
cmake --build build-9.5
cp build-9.5/ida_mcp_server.so "$IDA_DIR/plugins/"
