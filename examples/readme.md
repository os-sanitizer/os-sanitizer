# Examples
Code snippets to highlight reporting by different os-sanitizer passes. In addition, each example can be built to run multiple times (default: 50,000) with the help of macros to evaluate the overhead.

## Prerequisites
1. Make sure `dir1` is writeable by other users. Do it with: `chmod o+w dir1`.
2. Make sure `05_demo_file.txt` is writeable by other users. Do it with `chmod 666 05_demo_file.txt`.

## Usage
1. Build examples with `make all`. To build example that run multiple times use `make all OPTION='-DMICROBENCHMARK'`.
2. Run individual executable with os-sanitizer running in the background with corresponding option. For example, run `sudo env RUST_LOG=info os-sanitizer --access` in the background and then execute `./01_access`.

## Help with Errors
- To get more details about `errno`: Use `$ errno <errno>`. Installable with `sudo apt install errno`
- Example:
```
$ errno 5
    #define EIO 5
    Input/output error
```

# Pass and Microbenchmark Descriptions

## `access`

The purpose of this pass is to detect TOCTOU vulnerabilities associated with syscalls which access and open user-specified files, namely `do_faccessat`, `vfs_statat, do_statx, and do_sys_openat2.

In the microbenchmark, a local file is accessed by the `access(2)` function, then opened with `open(2)` before being closed with `close(2)` each iteration.

## `fixed-mmap`

This pass detects when `mmap(2)` is invoked with the `MAP_FIXED` flag without allocating a permission-less map ahead of time, leading to partial or full overwrites of map addresses.

In each iteration of the benchmark, `mmap(2)` is used to map a readable, writable, and anonymous memory mapping large enough to hold an integer at a kernel-assigned address.
The base address of this mapping is set to a non-zero value.
Then, `mmap(2)` is used to produce a readable, fixed, and anonymous memory mapping of the same size at the same address before unmapping with `munmap(2)`.

## `rwx-mem`

Memory which is simultaneously writable and executable may be leveraged by an attacker to inject code if an arbitrary write primitive is available.
This pass detects when memory is allocated with the potentially unsafe protections.

In the microbenchmark, a local file is opened with `open(2)`.
Each iteration, the benchmark privately maps the resulting file descriptor with only read permissions using `mmap(2)`.
This mapping is then updated to be writable and executable with `mprotect(2)` before being unmapped with `munmap(2)`.

## `filep-unlocked`

This pass detects when a raceful write operation takes place on a FILE pointer, which can lead to memory corruption, information leakage, and data loss.

Instead of the normal layout, where a single thread iterates in a tight loop, the benchmark must execute multiple threads to induce a true positive scenario.
Before anything else, a local file is opened with `fopen(3)` and `setvbuf(3)` is used to disable buffering on the resulting file pointer.
Four threads are launched, each of which write to the file pointer with `fputc_unlocked(3)` and increment separate counters.
When the signal handler is run for this program at timer completion, the separate counters are summed and this value is reported as the number of iterations.

## `gets`

This pass is simple: if any process invokes `gets(3)`, a report is issued for that process as it is a strictly vulnerable function.

The corresponding benchmark receives its standard input (stdin) from the output of the `yes(1)` command.
Before iterating, `setvbuf(3)` is used to disable buffering on stdin to remove the effect of line length on the benchmark.
`gets(3)` is then executed in a tight loop.

## `snprintf`

This pass identifies all invocations of `snprintf(3)` for which the return value (i.e. the computed length _without the provided limit_) is used as the length argument for a write-like system call.

Before the microbenchmark begins iteration, the special file `/dev/null` is opened with `open(2)`.
Each iteration, `snprintf(3)` is used to write a templated string of 5200 bytes into a stack buffer of size 5120 bytes, and its return value, representing the length of the resulting string should the buffer have been sufficiently sized, is saved.
`write(2)` is then used to write the string, as specified by the length returned by `snprintf(3)`, to the file descriptor for `/dev/null`.

## `printf-mutability`

This pass (referred to as `printf_mut` in the paper) detects when any `printf(3)` function is executed with a non-constant string buffer used as a template, which is almost always unsafe.

Before the microbenchmark begins iteration, the special file `/dev/null` is opened with `open(2)`.
Each iteration, the file descriptor for `/dev/null` is written to using `dprintf(3)` with the template parameter set to `argv[0]`.

## `system-mutability`

This pass (referred to as `system_mut` in the paper) detects when the `system(3)` C API is executed with a non-constant string buffer as a command string, which is often unsafe.

Before the microbenchmark begins iteration, the string `"ls"` is written to a stack buffer.
Each iteration, `system(3)` is executed with the command parameter set to the stack buffer.

## `system-absolute`

This pass (referred to as `system_abs` in the paper) detects when the `system(3)` C API is executed with a non-absolute path, which could allow for command injection on attacker-controlled paths.

Each iteration of the microbenchmark, `system(3)` is executed with the string literal `"ls"`.

## `security-file-open`

This pass (referred to as `sec_file_open` in the paper) acts as the reporter for file permissions issues by checking whether a file presently being opened has permissions that may permit manipulation by other users.
It is implicitly enabled by other passes, e.g. `access`.

Before executing the microbenchmark, a local file is modified to have globally readable and writable file permissions.
Each iteration, `open(2)` is used to open this file and `close(2)` to close it.

## `interceptable-path`

This pass (referred to as `intercept_path` in the paper) detects when `any` member of a kernel-traversed path specified by the user could be intercepted and redirected by an attacker.

Before execution of the microbenchmark, a local directory is changed to be globally writable.
This directory contains a nested directory, which itself contains a file.
Each iteration, the file within nested directories is opened, traversing the writable directory in the process, with `open(2)` and closed with `close(2)`.

## `memcpy`

This pass attempts to detect buffer overflows caused by a call to `memcpy(3)` with the length determined by invoking `strlen(3)` or a similar function with the source buffer.
To prevent known false positives, several filtering programs are applied to corresponding known safe invocations.

In the microbenchmark, `memcpy(3)` is used to copy a 4368 byte string into a destination buffer of 5120 bytes each iteration.
The length of the copy is determined by `strlen(3)`.

## `strcpy`

This pass attempts to detect buffer overflows caused by a call to `strcpy(3)` without a preceding call to `strlen(3)`.
To prevent known false positives, several filtering programs are applied to corresponding known safe invocations.

In the microbenchmark, `strcpy(3)` is used to copy a 4368 byte string into a destination buffer of 5120 bytes each iteration.

## `strncpy`

This pass attempts to detect buffer overflows caused by a call to `strncpy(3)` with the length determined by invoking `strlen(3)` or a similar function with the source buffer.
To prevent known false positives, several filtering programs are applied to corresponding known safe invocations.

Each iteration of the microbenchmark, `strncpy(3)` is used to copy a 4368 byte string into a destination buffer of 5120 bytes.
The length of the copy is determined by `strlen(3)`.

## `sprintf`

This pass identifies all invocations of `sprintf(3)` which have unsafe destinations.
False positives are mitigated individually with filtering passes, similar to the copy passes explained above.

Each iteration of the microbenchmark, `sprintf(3)` is used to write a templated string of 4373 bytes into a stack buffer of 5120 bytes.
