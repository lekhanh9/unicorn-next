# MacAuth Mini-macOS ARM64 Emulator

## Overview
MacAuth is a lightweight macOS ARM64e emulation runtime running on iOS (Unicorn Engine) to execute macOS authentication libraries (`AppleIDAuthSupport`, `AuthKit`) and generate Anisette headers (`X-Apple-I-MD`, `X-Apple-I-MD-M`, etc.) for Apple ID requests.

## Architecture
- `src/loader/macho.c`, `src/loader/macho.h`: Mach-O 64-bit ARM64/ARM64e parser and memory mapper.
  - Features an iOS 16+ JIT compatibility layer: strips `MAP_JIT` on `mmap` calls in `libunicorn.2.dylib` via GOT patching, and installs an ARM64 `SIGBUS` handler inspecting ESR Exception Class (`0x20/0x21` for Instruction Abort -> `PROT_READ|PROT_EXEC`, `0x24/0x25` for Data Abort -> `PROT_READ|PROT_WRITE`) to seamlessly handle iOS W^X memory restrictions.
- `src/runtime/darwin_env.c`, `src/runtime/darwin_env.h`: Darwin ARM64 execution environment.
  - Stack: 2MB at `0x7fff00000000` (16-byte aligned SP).
  - Heap: 64MB bump allocator at `0x600000000000`.
  - TLS: 64KB at `0x700000000000`, mapped to `UC_ARM64_REG_TPIDR_EL0`.
- `src/runtime/hooks.c`, `src/runtime/hooks.h`: Trampoline manager and LibSystem stubs (memory, string, threading, time, sysctlbyname).
- `src/mock/iokit.c`, `src/mock/iokit.h`: IOKit hardware registry mock with MacBookPro18,1 profile (M1 Pro) generating virtual `CFString` and `CFData` objects.
- `src/api/anisette.c`, `src/api/anisette.h`: High-level Anisette header generator.

## Build and Test
Compiling on device with clang:
```sh
# Entitlements needed for execution in /tmp or test directory
cat << 'EOF' > /tmp/ent.plist
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>platform-application</key>
    <true/>
    <key>com.apple.private.security.no-sandbox</key>
    <true/>
</dict>
</plist>
EOF

# 1. Mach-O Loader Test:
clang -Wall -Wextra -Iinclude src/loader/macho.c tests/test_macho_loader.c -o /tmp/test_macho_loader -rpath /var/jb/usr/lib /var/jb/usr/lib/libunicorn.2.dylib
ldid -S/tmp/ent.plist /tmp/test_macho_loader
/tmp/test_macho_loader

# 2. Darwin Runtime Test:
clang -Wall -Wextra -Iinclude src/loader/macho.c src/runtime/darwin_env.c src/runtime/hooks.c tests/test_darwin_runtime.c -o /tmp/test_darwin_runtime -rpath /var/jb/usr/lib /var/jb/usr/lib/libunicorn.2.dylib
ldid -S/tmp/ent.plist /tmp/test_darwin_runtime
/tmp/test_darwin_runtime

# 3. IOKit Mock Test:
clang -Wall -Wextra -Iinclude src/loader/macho.c src/runtime/darwin_env.c src/runtime/hooks.c src/mock/iokit.c tests/test_iokit_mock.c -o /tmp/test_iokit_mock -rpath /var/jb/usr/lib /var/jb/usr/lib/libunicorn.2.dylib
ldid -S/tmp/ent.plist /tmp/test_iokit_mock
/tmp/test_iokit_mock

# 4. Full Anisette API Test:
clang -Wall -Wextra -Iinclude src/loader/macho.c src/runtime/darwin_env.c src/runtime/hooks.c src/mock/iokit.c src/api/anisette.c tests/test_anisette_api.c -o /tmp/test_anisette_api -rpath /var/jb/usr/lib /var/jb/usr/lib/libunicorn.2.dylib
ldid -S/tmp/ent.plist /tmp/test_anisette_api
/tmp/test_anisette_api
```
