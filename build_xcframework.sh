#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(mktemp -d)"
XCFRAMEWORK_PATH="${ROOT_DIR}/build/Unicorn.xcframework"

mkdir -p "${ROOT_DIR}/build"

UNICORN_LOGGING="${UNICORN_LOGGING:-ON}"
echo "==> Unicorn Logging: ${UNICORN_LOGGING}"

COMMON_CMAKE=(
  -DCMAKE_BUILD_TYPE=Release
  -DUNICORN_ARCH="aarch64"
  -DUNICORN_BUILD_TESTS=OFF
  -DUNICORN_INSTALL=OFF
  -DBUILD_SHARED_LIBS=OFF
  -DUNICORN_LOGGING="${UNICORN_LOGGING}"
)

patch_config_host() {
    local cfg="$1/config-host.h"
    if [ -f "${cfg}" ]; then
        sed -i '' 's/#define HAVE_PTHREAD_JIT_PROTECT 1/\/* HAVE_PTHREAD_JIT_PROTECT removed for non-macOS target *\//' "${cfg}" || sed -i 's/#define HAVE_PTHREAD_JIT_PROTECT 1/\/* HAVE_PTHREAD_JIT_PROTECT removed for non-macOS target *\//' "${cfg}" || true
        echo "    Patched config-host.h"
    fi
}

build_slice() {
    local name="$1"
    local sysroot="$2"
    local archs="$3"
    local extra_args="$4"
    local out_name="$5"

    echo "==> Building Unicorn for ${name}..."
    local build_dir="${ROOT_DIR}/build_${out_name}"
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}"
    pushd "${build_dir}" >/dev/null

    local cc_path
    cc_path="$(xcrun -sdk "${sysroot}" -find clang)"
    local cmake_args=("${COMMON_CMAKE[@]}"
        -DCMAKE_C_COMPILER="${cc_path}"
        -DCMAKE_OSX_SYSROOT="${sysroot}"
        -DCMAKE_OSX_ARCHITECTURES="${archs}"
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
    )
    if [ -n "${extra_args}" ]; then
        for arg in ${extra_args}; do
            cmake_args+=("${arg}")
        done
    fi

    cmake "${ROOT_DIR}" "${cmake_args[@]}"
    patch_config_host "${build_dir}"
    cmake --build . --config Release -j$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
    mkdir -p "${OUTPUT_DIR}/${out_name}"
    cp libunicorn.a "${OUTPUT_DIR}/${out_name}/libunicorn.a"
    popd >/dev/null
    echo "    ${name} done."
}

# ── macOS (native) ──
echo "==> Building Unicorn for macOS..."
BUILD_DIR_MAC="${ROOT_DIR}/build_mac"
rm -rf "${BUILD_DIR_MAC}"
mkdir -p "${BUILD_DIR_MAC}"
pushd "${BUILD_DIR_MAC}" >/dev/null
cmake "${ROOT_DIR}" "${COMMON_CMAKE[@]}" -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"
cmake --build . --config Release -j$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
mkdir -p "${OUTPUT_DIR}/mac"
cp libunicorn.a "${OUTPUT_DIR}/mac/libunicorn.a"
popd >/dev/null
echo "    macOS done."

# ── Slices ──
build_slice "iOS Simulator"      iphonesimulator   "arm64;x86_64"  "-DUNICORN_ENABLE_TCI=ON"                     "ios_sim"
build_slice "iOS Device"         iphoneos          "arm64"         "-DUNICORN_ENABLE_TCI=ON"                     "ios_device"

# ── Bundle into XCFramework ──
echo "==> Creating Unicorn.xcframework..."
rm -rf "${XCFRAMEWORK_PATH}"

XCFRAMEWORK_ARGS=(
  -library "${OUTPUT_DIR}/mac/libunicorn.a" -headers "${ROOT_DIR}/include"
  -library "${OUTPUT_DIR}/ios_sim/libunicorn.a" -headers "${ROOT_DIR}/include"
  -library "${OUTPUT_DIR}/ios_device/libunicorn.a" -headers "${ROOT_DIR}/include"
)

# AnisetteKit targets iOS and macOS; tvOS slices are not required here.
xcodebuild -create-xcframework "${XCFRAMEWORK_ARGS[@]}" -output "${XCFRAMEWORK_PATH}"

rm -rf "${OUTPUT_DIR}"

echo ""
echo "Done! XCFramework: ${XCFRAMEWORK_PATH}"
