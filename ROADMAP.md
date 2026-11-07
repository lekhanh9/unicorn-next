# Lộ trình Xây dựng Mini-Darwin Runtime (Unicorn Engine) Giả Lập Anisette

Mục tiêu: Xây dựng một mini-Darwin runtime siêu nhẹ dựa trên **Unicorn Engine (v2)** để nạp và thực thi `libadi.dylib` (hoặc `adi.framework` / `CoreADI`), cho phép sinh đầy đủ bộ Anisette headers (`X-Apple-I-MD*`) phục vụ các ứng dụng sideload (như SideStore, AltStore) mà không cần daemon hay môi trường macOS đầy đủ.

---

## Giai đoạn 1: Chuẩn bị Binary & Phân tích Dependencies

- [ ] **Thu thập binary mục tiêu**:
  - Trích xuất `libadi.dylib` từ macOS (x86_64 hoặc ARM64) hoặc iOS. Ưu tiên ARM64 nếu chạy native/cross trên thiết bị Apple Silicon / iOS.
- [ ] **Phân tích cấu trúc & symbols**:
  - Sử dụng `otool -l`, `jtool2 -l`, hoặc `llvm-readobj` để liệt kê các load commands.
  - Trích xuất danh sách import symbols (`nm -u libadi.dylib`): libc, libSystem, IOKit, CoreFoundation, CommonCrypto.
  - Xác định các hàm export quan trọng liên quan đến quá trình provisioning và tạo OTP (như `vdfProperties`, `requestOtp`, v.v.).

---

## Giai đoạn 2: Xây dựng Mach-O Loader trên Unicorn Memory

- [ ] **Parse Header & Load Commands**:
  - Đọc `mach_header_64` kiểm tra magic (`MH_MAGIC_64`), cputype (`CPU_TYPE_ARM64` hoặc `CPU_TYPE_X86_64`).
  - Lặp qua các load commands: xử lý `LC_SEGMENT_64` (`__TEXT`, `__DATA`, `__DATA_CONST`, `__LINKEDIT`).
- [ ] **Ánh xạ bộ nhớ vào Unicorn (`uc_mem_map`)**:
  - Canh lề theo page size (4KB hoặc 16KB).
  - Phân bổ vùng nhớ theo segment và cấp quyền tương ứng (`UC_PROT_READ`, `UC_PROT_WRITE`, `UC_PROT_EXEC`).
  - Copy bytes của từng segment từ file vào vùng nhớ Unicorn (`uc_mem_write`).
- [ ] **Xử lý Fixups & Symbol Binding**:
  - Parse `LC_DYLD_INFO` hoặc `LC_DYLD_CHAINED_FIXUPS` để rebase các con trỏ nội bộ theo địa chỉ nạp động.
  - Phân tích bảng export/import trong `LC_SYMTAB` và `LC_DYSYMTAB`.
- [ ] **Khởi tạo Môi trường Thực thi**:
  - Cấp phát vùng Stack (ví dụ: `0x70000000` - 2MB) và thiết lập thanh ghi `SP`.
  - Cấp phát vùng Heap đơn giản để phục vụ mock `malloc`.
  - Khởi tạo Thread-Local Storage (TLS): set `TPIDR_EL0` (ARM64) hoặc `FS_BASE` (x86_64).

---

## Giai đoạn 3: Hook LibSystem & Giả Lập Mach/Syscall

- [ ] **Thiết lập Trampoline / Hook Table**:
  - Tạo vùng nhớ dành riêng cho stubs (ví dụ: `0xdead0000`).
  - Gắn hook thực thi (`UC_HOOK_CODE`) tại vùng stub: khi PC nhảy vào địa chỉ stub của symbol nào, kích hoạt handler C tương ứng.
- [ ] **Triển khai các hàm LibSystem cơ bản**:
  - **Quản lý bộ nhớ**: `malloc`, `calloc`, `realloc`, `free`, `posix_memalign`, `memset`, `memcpy`, `memmove`.
  - **Chuỗi & I/O**: `strlen`, `strcmp`, `strncmp`, `strcpy`, `snprintf`, `asprintf`.
  - **Đồng bộ hóa / Threading**: `pthread_mutex_init`, `pthread_mutex_lock`, `pthread_mutex_unlock`, `pthread_once`, `pthread_self`.
  - **Thời gian**: `mach_absolute_time`, `mach_timebase_info`, `gettimeofday`, `clock_gettime`.
  - **Sysctl & Môi trường**: `sysctl`, `sysctlbyname` (mock các giá trị: `hw.machine`, `hw.model`, `kern.osversion`, `kern.osrelease`, `hw.ncpu`).
- [ ] **Bắt Unmapped Memory & Exception**:
  - Gắn `UC_HOOK_MEM_UNMAPPED` để log và cảnh báo ngay khi code nhảy hoặc đọc/ghi vào vùng nhớ chưa được ánh xạ.

---

## Giai đoạn 4: Mock IOKit & Hardware Registry (SMBIOS)

ADI dựa trên IOKit để định danh thiết bị độc nhất (Machine Fingerprint). Cần mock các API IOKit và CoreFoundation tương ứng.

- [ ] **Triển khai Mock IOKit API**:
  - `IOServiceGetMatchingService`
  - `IOServiceMatching`
  - `IOObjectRelease`
  - `IORegistryEntryCreateCFProperty`
- [ ] **Giả lập thông tin phần cứng (Hardware Attributes)**:
  - Mock `IOPlatformExpertDevice`:
    - `IOPlatformSerialNumber`: Serial number giả lập của máy.
    - `IOPlatformUUID`: UUID hệ thống giả lập.
    - `model`: Mã model Mac (ví dụ `MacBookPro16,1` hoặc `Macmini8,1`).
  - Mock IODeviceTree / MAC Address (cho network interface `en0`).
- [ ] **Mini CoreFoundation Bridge**:
  - Tạo bảng quản lý CF object giả lập đơn giản: `CFString`, `CFData`, `CFDictionary`, `CFNumber`.
  - Stub `CFRelease`, `CFRetain`, `CFStringGetCString`.

---

## Giai đoạn 5: Gọi Hàm Export của ADI & Quy Trình Provisioning

- [ ] **Xác định Calling Convention & Entry Points**:
  - Thiết lập tham số qua thanh ghi theo ABI (ARM64: `x0`-`x7`; x86_64: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`).
  - Ghi địa chỉ return pointer giả để dừng emulation khi hoàn tất (`UC_HOOK_CODE` tại địa chỉ return).
- [ ] **Thực thi luồng sinh Anisette**:
  - Khởi tạo session / context ADI.
  - Đưa thông tin client vào context (DSID, Local User ID, Hardware Fingerprint).
  - Kích hoạt tạo mã OTP (`requestOtp` / `adi_requestOTP`).
  - Ký dữ liệu xác thực nếu cần thiết.

---

## Giai đoạn 6: Đóng Gói C-API & Tích Hợp

- [ ] **Thiết kế C-API tinh gọn**:
  ```c
  typedef struct {
      char x_apple_i_md[256];
      char x_apple_i_md_m[256];
      char x_apple_i_md_rinfo[64];
      char x_apple_i_md_lu[128];
      char x_apple_i_srl_no[64];
      char x_apple_i_client_time[64];
  } anisette_headers_t;

  int anisette_runtime_init(const char *libadi_path);
  int anisette_generate_headers(const char *dsid, anisette_headers_t *out_headers);
  void anisette_runtime_destroy(void);
  ```
- [ ] **Unit Tests & Xác thực với Apple ID**:
  - Viết test suite độc lập gọi C-API và xuất kết quả.
  - Gửi request thử nghiệm đến endpoint xác thực của Apple (`https://gsa.apple.com/grandslam/GsService2`) để xác nhận headers hợp lệ.
