#!/bin/bash

cmake -B cmake-build-x86_64-linux-gnu -S . -G Ninja -DCMAKE_BUILD_TYPE=Release
# cmake -B cmake-build-x86_64-linux-gnu-2 -S . -G Ninja -DCMAKE_BUILD_TYPE=Release

cmake --build cmake-build-x86_64-linux-gnu
# cmake --build cmake-build-x86_64-linux-gnu-2

sha256sum ./cmake-build-x86_64-linux-gnu/libdave/cpp/libdave.a
# sha256sum ./cmake-build-x86_64-linux-gnu-2/libdave/cpp/libdave.a
sha256sum ./cmake-build-x86_64-linux-gnu/libdave-jvm.so
# sha256sum ./cmake-build-x86_64-linux-gnu-2/libdave-jvm.so