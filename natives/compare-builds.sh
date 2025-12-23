#!/bin/bash

export VCPKG_ROOT=$PWD/libdave/cpp/vcpkg
export CRYPTO_ALT_DIR=$PWD/libdave/cpp/vcpkg-alts/boringssl
export VCPKG_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake

cmake -B cmake-build-x86_64-linux-gnu -S . -G Ninja -DCMAKE_BUILD_TYPE=Release -DVCPKG_MANIFEST_DIR="${CRYPTO_ALT_DIR}" -DCMAKE_TOOLCHAIN_FILE="${VCPKG_TOOLCHAIN_FILE}"
cmake -B cmake-build-x86_64-linux-gnu-2 -S . -G Ninja -DCMAKE_BUILD_TYPE=Release -DVCPKG_MANIFEST_DIR="${CRYPTO_ALT_DIR}" -DCMAKE_TOOLCHAIN_FILE="${VCPKG_TOOLCHAIN_FILE}"

cmake --build cmake-build-x86_64-linux-gnu
cmake --build cmake-build-x86_64-linux-gnu-2

sha256sum ./cmake-build-x86_64-linux-gnu/libdave/cpp/libdave.a
sha256sum ./cmake-build-x86_64-linux-gnu-2/libdave/cpp/libdave.a
sha256sum ./cmake-build-x86_64-linux-gnu/libdave-jvm.so
sha256sum ./cmake-build-x86_64-linux-gnu-2/libdave-jvm.so