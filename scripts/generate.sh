#!/bin/bash

# Navigate to the build directory and generate eBPF artifacts
if [ -d build ]; then
  echo "Generating eBPF artifacts in the build directory..."
  cd build || exit 1
  go generate || exit 1
  cd ..
else
  echo "Build directory not found!"
  exit 1
fi
