# simdjson Seeded Vulnerability Report

**Library:** simdjson 4.3.0
**Branch:** master (bugs branch)
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-03-12

> **Note:** These bugs are NOT present in the upstream simdjson codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-125 | OOB Read (global table) | `include/simdjson/generic/jsoncharutils.h:33` | ASan global-buffer-overflow (read) | `["\u\xff000"]` |
| 2 | CWE-787 | Heap buffer overflow (write) | `include/simdjson/dom/document-inl.h:45` | ASan heap-buffer-overflow (write) | `["AAA...AAA"]` (220 A's) |
| 3 | CWE-125 | OOB Read (heap table, massive) | `include/simdjson/generic/numberparsing.h:518` | ASan heap/global-buffer-overflow (read) | `1e-343` |
| 4 | CWE-787 | Heap buffer overflow (write) | `include/simdjson/dom/document-inl.h:42` | ASan heap-buffer-overflow (write) | `[` ×128 + `]` ×128 |
| 5 | CWE-190 | Signed integer overflow | `include/simdjson/generic/numberparsing.h:358` | UBSan signed-integer-overflow | `1e9999999999999999999` |

---

## Bug 1 — OOB Read in `hex_to_u32_nocheck`

**File:** `include/simdjson/generic/jsoncharutils.h`, line 33
**Harness:** `fuzz/fuzz_bug_unicode.cpp`
**Sanitizer:** ASan global-buffer-overflow (read)

### Change

```diff
- uint32_t v1 = internal::digit_to_val32[630 + src[0]];
+ uint32_t v1 = internal::digit_to_val32[631 + src[0]]; // BUG1: off-by-one
```

### Description

`hex_to_u32_nocheck` decodes a 4-character hex escape (`\uXXXX`) by indexing
into the global lookup table `digit_to_val32`, which has exactly 886 entries
(valid indices 0–885).  The first hex character uses base offset 630, so the
maximum legitimate index is `630 + 255 = 885`.  Shifting the base to 631 makes
the maximum reachable index `631 + 255 = 886`, which is one past the last valid
element.  When a JSON string contains `\u` followed by a raw byte 0xFF (which
the fuzzer can supply, since simdjson's `hex_to_u32_nocheck` is intentionally
unchecked), the function reads `digit_to_val32[886]`, a one-element out-of-bounds
read that ASan reports as a global-buffer-overflow.

### Trigger Input

```
["\u\xff000"]
```

The 10 bytes are: `5b 22 5c 75 ff 30 30 30 22 5d`.  `src[0]` receives `0xff`,
yielding index `631 + 255 = 886 > 885`.  The three trailing `0` bytes are
arbitrary; only `src[0]` needs to be `0xff`.

### Reproduction

```bash
printf '\x5b\x22\x5c\x75\xff\x30\x30\x30\x22\x5d' | ./fuzz_bug_unicode
```

---

## Bug 2 — Heap Buffer Overflow via Under-Allocated String Buffer

**File:** `include/simdjson/dom/document-inl.h`, line 45
**Harness:** `fuzz/fuzz_bug_string_overflow.cpp`
**Sanitizer:** ASan heap-buffer-overflow (write)

### Change

```diff
- size_t string_capacity = SIMDJSON_ROUNDUP_N(5 * capacity / 3 + SIMDJSON_PADDING, 64);
+ size_t string_capacity = SIMDJSON_ROUNDUP_N(capacity / 3 + SIMDJSON_PADDING, 64); // BUG2
```

### Description

`document::allocate()` provisions a heap `string_buf` into which stage-2
(`parse_string`) copies the decoded content of every JSON string.  The original
formula `5 * capacity / 3` accounts for the worst-case expansion from unicode
escapes; the buggy formula `capacity / 3` allocates only one-fifth as much.
For a JSON string of plain ASCII characters, the decoded output length is
nearly equal to the input length.  For any input whose string content exceeds
`capacity/3 + SIMDJSON_PADDING` bytes, the stage-2 SIMD copy loop writes past
the end of `string_buf`, producing an ASan heap-buffer-overflow.  Because the
original allocation was a factor of five too large, many inputs with long
strings (> ~100 bytes) now trigger the overflow.

### Trigger Input

```
["AAAA...AAAA"]  (220 'A' characters inside the JSON string)
```

Total input is 224 bytes.  `string_capacity = ROUNDUP(224/3 + 64, 64) = 128`.
The string decoder writes 220 bytes into a 128-byte buffer — 92 bytes past the
end.

### Reproduction

```bash
python -c "print('[\"' + 'A'*220 + '\"]', end='')" | ./fuzz_bug_string_overflow
```

---

## Bug 3 — OOB Read in `compute_float_64` via Missing Exponent Lower-Bound

**File:** `include/simdjson/generic/numberparsing.h`, line 518
**Harness:** `fuzz/fuzz_bug_float_bounds.cpp`
**Sanitizer:** ASan heap/global-buffer-overflow (read)

### Change

```diff
- if (simdjson_unlikely(exponent < simdjson::internal::smallest_power) || ...
+ if (simdjson_unlikely(exponent < simdjson::internal::smallest_power - 1) || ... // BUG3
```

### Description

`write_float` guards calls to `compute_float_64` with a range check against
`smallest_power` (−342).  The one-off change `smallest_power - 1` (−343) lets
`exponent == -343` slip past the guard and enter `compute_float_64(-343, ...)`.
Inside that function, the table index is:

```cpp
const uint32_t index = 2 * uint32_t(power - simdjson::internal::smallest_power);
// = 2 * uint32_t(-343 - (-342))
// = 2 * uint32_t(-1)
// = 2 * 4294967295 = 8589934590
```

This astronomically large index is then used to read `power_of_five_128[8589934590]`,
which is billions of elements past the end of that table.  The access lands in
completely unmapped memory and is caught by ASan (or causes a SIGSEGV/SIGBUS).

### Trigger Input

```
1e-343
```

A floating-point literal with exponent −343, exactly one below `smallest_power`.

### Reproduction

```bash
echo -n '1e-343' | ./fuzz_bug_float_bounds
```

---

## Bug 4 — Heap Buffer Overflow via Under-Allocated Tape

**File:** `include/simdjson/dom/document-inl.h`, line 42
**Harness:** `fuzz/fuzz_bug_tape_overflow.cpp`
**Sanitizer:** ASan heap-buffer-overflow (write)

### Change

```diff
- size_t tape_capacity = SIMDJSON_ROUNDUP_N(capacity + 3, 64);
+ size_t tape_capacity = SIMDJSON_ROUNDUP_N(capacity / 2 + 3, 64); // BUG4
```

### Description

`document::allocate()` also provisions a `tape` array of `uint64_t` that the
stage-2 tape-builder writes one entry per JSON structural element (each `[`,
`]`, `{`, `}`, number, string, boolean, or null).  The original formula
`capacity + 3` ensures the tape is at least as large as the input, bounding
the number of structural elements by the input length.  The buggy formula
`capacity / 2 + 3` halves that capacity.  A deeply-nested JSON input composed
entirely of `[` and `]` characters generates one tape entry per character;
with 256-byte input the tape needs 258 slots but receives only
`ROUNDUP(131, 64) = 192`.  After ~192 writes the tape-builder writes to
`tape[192]`, which is one past the allocated array, and ASan reports a
heap-buffer-overflow.

### Trigger Input

```
[[[[...]]]]  (128 '[' followed by 128 ']')
```

256 bytes, requiring 258 tape entries (2 root + 128 opens + 128 closes).
Buffer is `ROUNDUP(131, 64) = 192` entries — overflow after entry 192.

### Reproduction

```bash
python -c "print('[' * 128 + ']' * 128, end='')" | ./fuzz_bug_tape_overflow
```

---

## Bug 5 — Signed Integer Overflow in `parse_exponent`

**File:** `include/simdjson/generic/numberparsing.h`, line 358
**Harness:** `fuzz/fuzz_bug_exponent_ubsan.cpp`
**Sanitizer:** UBSan signed-integer-overflow

### Change

```diff
- SIMDJSON_NO_SANITIZE_UNDEFINED // We deliberately allow overflow here and check later
+ // BUG5: removed SIMDJSON_NO_SANITIZE_UNDEFINED — signed overflow in int64_t callers now triggers UBSan
  simdjson_inline bool parse_digit(const uint8_t c, I &i) {
```

### Description

`parse_digit` is a generic template that accumulates decimal digits via
`i = 10 * i + digit`.  It is intentionally annotated with
`SIMDJSON_NO_SANITIZE_UNDEFINED` because callers that use `uint64_t` (the
mantissa accumulator) rely on silent unsigned wraparound when the value
overflows, catching it with a post-loop check.  However, `parse_exponent`
also calls `parse_digit` with an `int64_t` accumulator (`exp_number`).  With
the annotation removed, the 19th decimal digit in an exponent like
`9999999999999999999` causes `10 * 999999999999999999 + 9` to overflow
`INT64_MAX` (9 223 372 036 854 775 807).  This is C++ signed integer overflow,
which is undefined behavior; UBSan reports a `signed-integer-overflow` at the
multiplication site inside `parse_digit`.  The overflow guard in
`parse_exponent` that would normally truncate `exp_number` runs only *after*
the while-loop completes, so UBSan fires during the 19th digit's iteration.

### Trigger Input

```
1e9999999999999999999
```

The exponent portion contains 19 nines.  After 18 nines `exp_number ≈ 10^18`,
which is within `INT64_MAX`.  The 19th nine triggers the overflow.

### Reproduction

```bash
echo -n '1e9999999999999999999' | ./fuzz_bug_exponent_ubsan
```

---

## Build Instructions

All harnesses use the libFuzzer interface and must be compiled with Clang:

```bash
cd /path/to/simdjson

# Build the simdjson library first (with ASan + UBSan):
cmake -B build-fuzz \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1" \
  -DSIMDJSON_ENABLE_FUZZING=ON \
  -DSIMDJSON_DEVELOPER_MODE=ON
cmake --build build-fuzz --target simdjson

# Compile individual harness (replace NAME with target name):
clang++ -std=c++17 \
  -I include \
  -fsanitize=address,undefined,fuzzer \
  -fno-sanitize-recover=all \
  -g -O1 \
  fuzz/fuzz_bug_<NAME>.cpp \
  build-fuzz/libsimdjson.a \
  -o fuzz_bug_<NAME>

# Run with seed corpus:
./fuzz_bug_<NAME> fuzz/fuzz_bug_<NAME>_corpus/ -max_total_time=60

# Reproduce with known trigger:
./fuzz_bug_<NAME> fuzz/fuzz_bug_<NAME>_corpus/seed_bug<N>.json
```

Available harnesses:

| Harness | Bug | Detected by |
|---------|-----|-------------|
| `fuzz_bug_unicode` | Bug 1 | ASan global-buffer-overflow (read) |
| `fuzz_bug_string_overflow` | Bug 2 | ASan heap-buffer-overflow (write) |
| `fuzz_bug_float_bounds` | Bug 3 | ASan heap/global-buffer-overflow (read) |
| `fuzz_bug_tape_overflow` | Bug 4 | ASan heap-buffer-overflow (write) |
| `fuzz_bug_exponent_ubsan` | Bug 5 | UBSan signed-integer-overflow |

---

## Expected Sanitizer Output

### Bug 1 — ASan global-buffer-overflow (read)
```
==ASAN: global-buffer-overflow on address 0x... READ of size 4
    #0  hex_to_u32_nocheck include/simdjson/generic/jsoncharutils.h:33
    #1  handle_unicode_codepoint src/generic/stage2/stringparsing.h:59
    #2  parse_string src/generic/stage2/stringparsing.h:171
SUMMARY: AddressSanitizer: global-buffer-overflow ... in hex_to_u32_nocheck
```

### Bug 2 — ASan heap-buffer-overflow (write)
```
==ASAN: heap-buffer-overflow on address 0x... WRITE of size 32
    #0  backslash_and_quote::copy_and_find include/simdjson/haswell/stringparsing_defs.h
    #1  parse_string src/generic/stage2/stringparsing.h:155
    #2  tape_builder::visit_string src/generic/stage2/tape_builder.h
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in copy_and_find
```

### Bug 3 — ASan heap/global-buffer-overflow (read)
```
==ASAN: SEGV on unknown address 0x... (or heap-buffer-overflow)
    #0  full_multiplication include/simdjson/generic/numberparsing.h:173
    #1  compute_float_64 include/simdjson/generic/numberparsing.h:173
    #2  write_float include/simdjson/generic/numberparsing.h:535
    #3  parse_number include/simdjson/generic/numberparsing.h:619
SUMMARY: AddressSanitizer: SEGV (or heap-buffer-overflow) in compute_float_64
```

### Bug 4 — ASan heap-buffer-overflow (write)
```
==ASAN: heap-buffer-overflow on address 0x... WRITE of size 8
    #0  tape_writer::append src/generic/stage2/tape_writer.h
    #1  tape_builder::visit_array_start src/generic/stage2/tape_builder.h
    #2  json_iterator::walk_document src/generic/stage2/json_iterator.h
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in tape_writer::append
```

### Bug 5 — UBSan signed-integer-overflow
```
include/simdjson/generic/numberparsing.h:365:7: runtime error: signed integer overflow:
  10 * 999999999999999999 cannot be represented in type 'long long'
    #0  parse_digit<long long> include/simdjson/generic/numberparsing.h:365
    #1  parse_exponent include/simdjson/generic/numberparsing.h:409
    #2  parse_number include/simdjson/generic/numberparsing.h:619
SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow in parse_digit
```

---

## Build System Integration

### CMakeLists.txt additions (fuzz/CMakeLists.txt)

```cmake
implement_fuzzer(fuzz_bug_unicode)
implement_fuzzer(fuzz_bug_string_overflow)
implement_fuzzer(fuzz_bug_float_bounds)
implement_fuzzer(fuzz_bug_tape_overflow)
implement_fuzzer(fuzz_bug_exponent_ubsan)
```

### Makefile (OSS-Fuzz style)

```makefile
all: \
  $(OUT)/fuzz_bug_unicode \
  $(OUT)/fuzz_bug_unicode_seed_corpus.zip \
  $(OUT)/fuzz_bug_string_overflow \
  $(OUT)/fuzz_bug_string_overflow_seed_corpus.zip \
  $(OUT)/fuzz_bug_float_bounds \
  $(OUT)/fuzz_bug_float_bounds_seed_corpus.zip \
  $(OUT)/fuzz_bug_tape_overflow \
  $(OUT)/fuzz_bug_tape_overflow_seed_corpus.zip \
  $(OUT)/fuzz_bug_exponent_ubsan \
  $(OUT)/fuzz_bug_exponent_ubsan_seed_corpus.zip
```

---

## Changelog

### 2026-03-12 — Initial bug injection

Added 5 intentional vulnerabilities spanning 3 source files:
- 2 bugs in `include/simdjson/dom/document-inl.h` (tape and string buffer under-allocation)
- 2 bugs in `include/simdjson/generic/numberparsing.h` (float bounds, UBSan annotation removal)
- 1 bug in `include/simdjson/generic/jsoncharutils.h` (hex table off-by-one)

### 2026-03-12 — Added harnesses and corpora

Added 5 dedicated libFuzzer harnesses (`fuzz/fuzz_bug_*.cpp`) and 5 seed corpus
directories (`fuzz/fuzz_bug_*_corpus/`) each containing one minimal trigger seed.

| Harness | Seed file | Seed bytes (hex) |
|---------|-----------|------------------|
| `fuzz_bug_unicode` | `seed_bug1.json` | `5b 22 5c 75 ff 30 30 30 22 5d` |
| `fuzz_bug_string_overflow` | `seed_bug2.json` | `5b 22 41` ×220 `22 5d` |
| `fuzz_bug_float_bounds` | `seed_bug3.json` | `31 65 2d 33 34 33` (`1e-343`) |
| `fuzz_bug_tape_overflow` | `seed_bug4.json` | `5b` ×128 `5d` ×128 |
| `fuzz_bug_exponent_ubsan` | `seed_bug5.json` | `31 65 39` ×19 (`1e9999999999999999999`) |

---

*This report documents intentional research vulnerabilities.
The upstream simdjson library does not contain these bugs.*
