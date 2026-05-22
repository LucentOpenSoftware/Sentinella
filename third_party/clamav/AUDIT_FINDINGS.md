# ClamAV 1.6.0 — Static Audit Findings (Read-Only)

**Scope:** Static, read-only source audit of `libclamav/`, `clamd/`, `libfreshclam/`,
`clamav-milter/`, `clamscan/`, `sigtool/`, `win32/` in the local `clamav-main`
source tree. No code was modified, no tests were run, no build was performed.

**Method:** Pattern grep for known bug classes + targeted file reads to verify.
Two sub-agents performed parallel scans on parsers and daemons; their findings
were individually re-verified against the source before inclusion in this
report. Several sub-agent findings were rejected as false positives after
verification (notes below).

**Important caveats:**
1. This is a static audit without a running build or test run. Every finding
   below should be **reproduced** (fuzz, PoC, or unit test) before any fix is
   upstreamed to Cisco Talos.
2. ClamAV is actively fuzzed and maintained. Several items listed as "latent"
   may already be tracked internally or intentionally left in place because
   they cannot be reached from current call paths.
3. Severity is subjective. HIGH = potential memory corruption with a
   plausible input-driven trigger; MED = leak, logic error, DoS, or
   information disclosure; LOW = hardening / defense-in-depth.
4. Report all real findings to Cisco Talos via the ClamAV security process
   (`SECURITY.md`), not as public GitHub issues, before any public discussion.

---

## Summary table

| ID  | Severity | File:line                                | Class                       |
|-----|----------|------------------------------------------|-----------------------------|
| 01  | MED      | libclamav/matcher-ac.c:1740              | realloc-loses-original      |
| 02  | MED      | libclamav/bytecode.c:341                 | Leak on OOM error path      |
| 03  | MED      | libclamav/bytecode.c:1085                | realloc-loses-original      |
| 04  | MED      | libclamav/libmspack.c:166                | fread arg order / wrong ret |
| 05  | MED      | libclamav/stats.c:206–253                | Dead code / leak-on-OOM     |
| 06  | MED      | clamd/clamd.c:504, 539                   | realloc-loses-original      |
| 07  | MED      | clamscan/manager.c:1293, 1322            | realloc-loses-original      |
| 08  | MED      | clamdtop/clamdtop.c:994                  | realloc-loses-original      |
| 09  | MED      | clamav-milter/allow_list.c:195           | realloc-loses-original      |
| 10  | MED      | sigtool/sigtool.c:1023                   | realloc-loses-original      |
| 11  | MED      | libfreshclam/libfreshclam_internal.c:735 | Proxy password logged       |
| 12  | LOW      | libclamav/pdf.c:2659–2662                | Parser rejects valid string |
| 13  | LOW      | libclamav/pdf.c:2886–2947 compute_hash_r6| Fragile fixed-size buffer   |
| 14  | LOW      | libclamav/mbox.c:606–627 appendReadStruct| Latent strcpy overflow      |
| 15  | LOW      | libclamav/others_common.c:274            | Wrong printf specifier      |
| 16  | LOW      | libclamav/others.c:2429                  | Wrong printf specifier      |
| 17  | LOW      | libclamav/vba_extract.c:110              | Signed int overflow (UB)    |
| 18  | LOW      | libclamav/matcher-ac.c:1416, 1451, 1510  | 32-bit integer overflow     |
| 19  | LOW      | libclamav/bytecode_vm.c:453              | Format-string hygiene       |
| 20  | LOW      | clamd/server-th.c:162, 191               | Non-async-safe logg in sig  |

---

## Findings

### 01 — MED — matcher-ac.c:1740 realloc-loses-original

```c
ss_matches = ls_matches->matches[subsig_id] =
    realloc(ss_matches, sizeof(struct cli_subsig_matches)
                        + sizeof(uint32_t) * ss_matches->last * 2);
if (ss_matches == NULL) {
    cli_errmsg("lsig_sub_matched: realloc failed ...\n");
    return CL_EMEM;
}
```

On realloc failure:
1. The *original* buffer previously held by `ls_matches->matches[subsig_id]`
   is leaked — realloc does not free on failure, and the original pointer
   was immediately overwritten.
2. `ls_matches->matches[subsig_id]` now holds NULL. If the caller walks the
   match table during cleanup it will miss the still-live (but orphaned)
   original.

**Fix pattern:**
```c
void *tmp = realloc(ss_matches,
                    sizeof(struct cli_subsig_matches)
                    + sizeof(uint32_t) * ss_matches->last * 2);
if (tmp == NULL) { ... return CL_EMEM; }
ss_matches = ls_matches->matches[subsig_id] = tmp;
```

Also: `ss_matches->last * 2` on `uint32_t` can theoretically wrap on a
pathological signature database, though not via scanned input. Defensive
check `ss_matches->last < SOMETHING_SANE` would be prudent.

---

### 02 — MED — bytecode.c:341 leak on OOM error path

```c
ctx->operands = malloc(sizeof(*ctx->operands) * func->numArgs);
if (!ctx->operands) { ... return CL_EMEM; }
ctx->opsizes = malloc(sizeof(*ctx->opsizes) * func->numArgs);
if (!ctx->opsizes) {
    cli_errmsg("bytecode: error allocating memory for opsizes\n");
    return CL_EMEM;    // ctx->operands leaked here
}
```

On second allocation failure, `ctx->operands` is never freed. Not reachable
from arbitrary untrusted input (bytecode is a signed/trusted database), but
it is a straightforward leak on OOM.

**Fix:** free `ctx->operands` (and set to NULL) before returning `CL_EMEM`.

---

### 03 — MED — bytecode.c:1085 realloc-loses-original via cli_safer_realloc

```c
b = bc->dbgnode_cnt;
bc->dbgnode_cnt += numMD;
bc->dbgnodes = cli_safer_realloc(bc->dbgnodes,
                                 bc->dbgnode_cnt * sizeof(*bc->dbgnodes));
if (!bc->dbgnodes) return CL_EMEM;
```

`cli_safer_realloc()` at `libclamav/others_common.c:261` does **not** free
the original on failure (the name is misleading — use
`cli_safer_realloc_or_free()` for that). The original buffer is leaked, and
`bc->dbgnode_cnt` was already incremented so subsequent cleanup of `bc`
will try to walk past the end of whatever (smaller) buffer happens to
replace it.

Secondary: `bc->dbgnode_cnt += numMD;` happens before the realloc, so a
realloc failure leaves `bc` in an inconsistent state (count says N,
buffer holds N‑numMD elements).

**Fix:**
```c
void *tmp = cli_safer_realloc(bc->dbgnodes, (b + numMD) * sizeof(*bc->dbgnodes));
if (!tmp) return CL_EMEM;
bc->dbgnodes = tmp;
bc->dbgnode_cnt = b + numMD;
```

**Related:** The only in-tree direct-assign caller of `cli_safer_realloc`.
All five other call sites in `libclamav/` use the correct intermediate-
variable pattern (or the `CLI_SAFER_REALLOC_OR_GOTO_DONE` macro).

---

### 04 — MED — libmspack.c:166 wrong fread usage, return value is element count not byte count

```c
/* file-descriptor fallback branch */
count = fread(buffer, (size_t)bytes, 1, mspack_handle->f);
if (count < 1) {
    cli_dbgmsg("%s() %d requested %d bytes, read failed (%zu)\n",
               __func__, __LINE__, bytes, count);
    return -1;
}
ret = (int)count;
return ret;
```

`fread(ptr, size, nmemb, stream)` returns *number of elements* read, not
bytes. With `size=bytes` and `nmemb=1`, this always returns `1` on success
(regardless of `bytes`) or `0` on failure.

The function contract (per the fmap branch on lines 149–163) is "return
bytes read or -1". This branch returns `1` on success, so the mspack
library sees a 1-byte read no matter how many bytes were requested,
causing decompression to fail or mis-parse.

Impact:
- The fmap branch is the common case in daemon mode, so this path is not
  on the hot path. However, it *is* taken for non-fmap mspack input
  (standalone `clamscan` against some CAB/CHM/MSI inputs depending on
  build options), turning every such scan into a silent parse failure.
- Not a memory-safety bug, but a functional bug in the CHM/MSI parser
  fallback.

**Fix:** swap the size/nmemb arguments:
```c
count = fread(buffer, 1, (size_t)bytes, mspack_handle->f);
if (count != (size_t)bytes) {
    if (ferror(mspack_handle->f)) return -1;
    /* short read ⇒ return partial count */
}
return (int)count;
```

---

### 05 — MED — stats.c:190–253 dead code + leak in `clamav_stats_add_sample`

Two issues in the same block:

**(a) Dead code at lines 206–219.** The surrounding `if (!sample)` branch
only runs when no existing sample is found, and then unconditionally
`calloc()`'s a fresh `cli_flagged_sample_t`. Because calloc zero-fills,
`sample->virus_name` is always NULL on entry to the check, so the
`if ((sample->virus_name)) { … }` true-branch is unreachable. This also
means an existing sample that matches on md5 never has a new virus name
appended (the function simply `sample->hits++` and returns). Either the
outer `if (!sample)` should have an `else` branch, or the dead code
should be removed.

**(b) Leak of strdup'd strings on realloc/strdup failure at lines 209,
232, 242.** On any of these failures the code does
`free(sample->virus_name); free(sample);` but the `virus_name` array
contains `strdup()`'d strings that are never individually freed. On a
fresh sample there is only one such string (manageable), but the dead
code at 206 implies this function was *intended* to handle multi-name
growth.

---

### 06 — MED — clamd/clamd.c:504, 539 realloc-loses-original (pua_cats)

```c
while (opt) {
    if (!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
        logg(LOGG_ERROR, "Can't allocate memory for pua_cats\n");
        cl_engine_free(engine);
        ret = 1;
        break;
    }
    ...
}
```

Startup-only code (only runs while parsing `ExcludePUA` / `IncludePUA`
config directives), so exploitation requires an attacker controlling
daemon configuration. Still: on OOM the original buffer is leaked, and
after `break` the code exits without freeing `pua_cats`. Low real-world
impact, trivial fix (intermediate variable + explicit free on the error
path).

Same pattern at line 539.

---

### 07 — MED — clamscan/manager.c:1293, 1322 realloc-loses-original

Same pattern as finding 06, in `clamscan` CLI command-line parsing. Even
lower impact (process is exiting anyway on OOM), but flagged for
consistency.

---

### 08 — MED — clamdtop/clamdtop.c:994 realloc-loses-original

```c
global.tasks = realloc(global.tasks, sizeof(*global.tasks) * global.n);
```

`clamdtop` is an interactive UI tool. On OOM the tasks table is lost.
Low impact.

---

### 09 — MED — clamav-milter/allow_list.c:195 realloc-loses-original

```c
if (rxavail < 4 && !(regex = realloc(regex, rxsize + 4))) {
    ...
}
```

Allow-list parsing in the mail filter. OOM leaks the regex buffer being
built. Low impact.

---

### 10 — MED — sigtool/sigtool.c:1023 realloc-loses-original

```c
certs = realloc(certs, certs_count * sizeof(char *));
```

Command-line tool, OOM leak. Low impact but trivial to fix.

---

### 11 — MED — libfreshclam/libfreshclam_internal.c:735 proxy password written to log

```c
if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, g_proxyPassword)) {
    logg(LOGG_ERROR,
         "create_curl_handle: Failed to set CURLOPT_PROXYPASSWORD (%s)!\n",
         g_proxyPassword);
}
```

On the (rare) failure path of `curl_easy_setopt()`, the configured proxy
password is logged in plaintext at `LOGG_ERROR`. Freshclam logs are
commonly written to syslog, a regular file owned by `clamav`, or to
stdout. Depending on deployment this can expose a credential to any user
with log access, log-shipping infrastructure, or crash collectors.

**Fix:** remove `g_proxyPassword` from the format args:
```c
logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_PROXYPASSWORD!\n");
```
The equivalent logg for username at line 731 should also be reviewed
(username is less sensitive but still unnecessary to echo).

---

### 12 — LOW — pdf.c:2659–2662 `pdf_readstring` rejects valid `(...)` strings

```c
for (; paren > 0 && len > 0; q++, len--) { ... }
if (len <= 0) {
    cli_errmsg("pdf_readstring: Invalid, truncated dictionary.\n");
    return NULL;
}
```

The loop exits either because `paren == 0` (balanced close paren found,
valid string) or because `len == 0` (truncation). The check should
distinguish those cases. Currently, any valid string that happens to end
exactly at the buffer boundary (e.g. a dictionary whose last value is
`(foo)` with no trailing whitespace before EOF) is rejected as
"truncated" and the corresponding field is silently dropped. This is a
false-negative on scanning accuracy, not a memory-safety bug.

**Fix:**
```c
if (paren > 0) {
    cli_errmsg("pdf_readstring: Invalid, truncated dictionary.\n");
    return NULL;
}
```

---

### 13 — LOW — pdf.c:2886–2947 `compute_hash_r6` latent stack overflow

```c
unsigned char data[(128 + 64 + 48) * 64];   /* 15360 bytes */
...
for (j = 1; j < 64; j++)
    memcpy(data + j * in_data_len, data, in_data_len);
aes_128cbc_encrypt(data, in_data_len * 64, data, ...);
```

The fixed 15360-byte stack buffer assumes `in_data_len = pwlen +
block_size + (U ? 48 : 0) ≤ 240`. With `block_size ≤ 64` and the
optional 48-byte U, any `pwlen > 128` causes `j * in_data_len` to exceed
15360 and **stack-overflows** in the memcpy loop. Also `data[(in_data_len
* 64) - 1]` at line 2910 reads past the end under the same condition.

*Why it's LOW and not HIGH*: all four in-tree callers
(`pdf.c:2996, 3013, 3224, 3241`) pass a hard-coded empty password
(`char password[] = ""; pwlen = 0;`). The condition is not reachable
from any PDF ClamAV currently scans. But the function takes `pwlen` as a
parameter and has no internal bound check, so a future caller passing
user/attacker-controlled data (e.g. an environment-provided password)
turns this into a straightforward stack overflow.

**Fix:** either validate `pwlen` at function entry (e.g.
`if (pwlen > 127) return;`) or dynamically allocate `data` based on the
actual `in_data_len`.

---

### 14 — LOW — mbox.c:606–627 `appendReadStruct` latent strcpy overflow

```c
#define READ_STRUCT_BUFFER_LEN 1024
typedef struct _ReadStruct {
    char buffer[READ_STRUCT_BUFFER_LEN + 1];
    size_t bufferLen;
    struct _ReadStruct *next;
} ReadStruct;

if (strlen(buffer) > spaceLeft) {
    int part = spaceLeft;                   /* narrowing size_t -> int */
    strncpy(&(rs->buffer[rs->bufferLen]), buffer, part);   /* no NUL */
    rs->bufferLen += part;
    CLI_CALLOC_OR_GOTO_DONE(next, 1, sizeof(ReadStruct));
    rs->next = next;
    strcpy(next->buffer, &(buffer[part]));  /* unbounded */
    ...
}
```

Not currently reachable from `parseEmailFile` (the only caller) because
that function bounds incoming lines with `RFC2821LENGTH = 1000` at the
buffer decl, and 1000 < 2×1024. But:
- The function is statically available and could be called from a new
  site with a longer line.
- The `int part = spaceLeft;` narrowing conversion from `size_t` is
  unnecessary sloppiness.
- The `strncpy` may leave `rs->buffer` un-NUL-terminated if `part`
  exactly equals remaining space (works because `bufferLen` is tracked
  separately, but fragile).

**Fix:** reject (or truncate to) `strlen(buffer) > READ_STRUCT_BUFFER_LEN`
at entry; use `memcpy` + explicit NUL; use `size_t` for `part`.

---

### 15 — LOW — others_common.c:274 wrong printf specifier

```c
cli_errmsg("cli_max_realloc(): Can't re-allocate memory to %lu bytes.\n",
           (unsigned long int)size);
```

`size` is `size_t`. On Windows x64 (LLP64), `unsigned long` is 32 bits
but `size_t` is 64 bits — the cast silently truncates the top 32 bits
of any size ≥ 4 GiB. The sibling function `cli_max_realloc()` at line
321 uses the correct `%zu` specifier. Fix: use `%zu` and drop the cast.

---

### 16 — LOW — others.c:2429 wrong printf specifier

```c
cli_errmsg("cli_rmdirs: Unable to allocate memory for path %u\n",
           strlen(dirname) + strlen(dent->d_name) + 2);
```

`strlen()` returns `size_t`; `%u` expects `unsigned int`. On 64-bit
systems this is undefined behavior. Line 2474 in the same file handles
the same value correctly with `%llu` + cast — one of the two is wrong.

**Fix:** use `%zu` with no cast.

---

### 17 — LOW — vba_extract.c:110 signed int overflow (UB)

```c
static char *get_unicode_name(const char *name, int size, int big_endian)
{
    ...
    newname = (char *)cli_max_malloc(size * 7 + 1);
```

`size` is `int` (> 0 is already checked). `size * 7 + 1` overflows
signed int for any `size > (INT_MAX - 1) / 7 ≈ 306 M`. Signed integer
overflow is undefined behavior in C. `cli_max_malloc` has an internal
`CLI_MAX_ALLOCATION` cap, so even on overflow this is likely caught as a
bogus allocation, but the UB itself is a latent issue and makes this
function unsafe to re-use with a larger `size` type.

**Fix:** change `size` to `size_t`, or perform the multiplication in a
wider type and cap explicitly.

---

### 18 — LOW — matcher-ac.c:1416, 1451, 1510 32-bit integer overflow

```c
data->offset  = (uint32_t *)malloc(reloffsigs * 2 * sizeof(uint32_t));
...
data->lsigcnt[0] = (uint32_t *)calloc(lsigs * 64, sizeof(uint32_t));
```

`reloffsigs` and `lsigs` are `uint32_t`; `reloffsigs * 2 * sizeof(...)`
and `lsigs * 64` are both computed in 32-bit arithmetic before being
passed to `malloc`/`calloc`. On 32-bit builds, this wraps for
`reloffsigs > 2^30 / 4` or `lsigs > 2^26`, yielding under-sized
allocations whose later uses (`lsigs * 64` indexing) run off the end.
On 64-bit builds the wrap can only be triggered by a pathological
signature database.

Only a concern if an attacker can supply a malicious `.cld` or `.cvd`
file to a victim that runs ClamAV with unsigned databases (e.g. custom
signature loading). Flag for hardening.

**Fix:** compute into `size_t` and check against a sane upper bound.

---

### 19 — LOW — bytecode_vm.c:453 format-string hygiene in CHECK_OP macro

```c
#define CHECK_OP(cond, msg)  \
    if ((cond)) {            \
        cli_dbgmsg(msg);     \
        stop = CL_EBYTECODE; \
        break;               \
    }
```

All current call sites (lines 772–785) pass string literals, so there is
no exploitation path today. But the macro accepts any `const char *`,
so a future caller passing an attacker-derived string would be a format-
string vulnerability. Defense-in-depth fix:
```c
#define CHECK_OP(cond, msg) ... cli_dbgmsg("%s", msg); ...
```

---

### 20 — LOW — clamd/server-th.c:162, 191 non-async-safe `logg` in signal handler

```c
void sighandler_th(int sig) {
    ...
    if (action && syncpipe_wake_recv_w != -1)
        if (write(syncpipe_wake_recv_w, "", 1) != 1)
            logg(LOGG_DEBUG_NV, "Failed to write to syncpipe\n");
}
```

`logg()` transitively calls `pthread_mutex_lock`, `stdio` functions, and
potentially `malloc` — none of which are async-signal-safe. Can deadlock
or crash if the signal is delivered while the main thread holds the
logging mutex. The racing condition is narrow (triggered only on a
syncpipe write error, which is already rare), but the code violates the
POSIX signal handler contract.

**Fix:** set a flag and log from the main loop instead, or use `write()`
directly to stderr.

---

## False-positive findings that were investigated and rejected

These were flagged by the exploration sub-agents or initial greps but did
not hold up under direct source review. Listed here so a later reviewer
doesn't re-open them:

- **pdf.c:2762 `cli_max_malloc((q - start) / 2 + 1)` claimed underflow.**
  Rejected: `q` is set by `memchr(q+1, '>', len-1)`; if memchr returns
  non-NULL, `q ≥ start+1`, so `q - start ≥ 1`. No underflow.

- **pdf.c:2669 same class.** Rejected: `q` is the for-loop terminator
  rolled back by one with `q--`. The minimum value is `start - 1` (for
  the `"()"` empty string), producing `len = -1`, which passes
  `cli_max_malloc(0)`. `cli_max_malloc` rejects zero, returns NULL, and
  the function returns NULL cleanly — not a bug.

- **pdfdecode.c:545 off-by-one memcpy.** Rejected: `srclen < 128` branch,
  bounds check at line 525 (`offset + srclen + 1 > length`) matches the
  `memcpy(... srclen + 1)` write and the 531 capacity check does the
  same on the destination. The suggested overflow did not exist.

- **pdfdecode.c:571 repeat fill wrap.** Rejected: `srclen` is `uint8_t`,
  so it cannot exceed 255, and `257 - srclen` is in `(2, 129]`. The
  capacity check at line 556 is consistent. Not a bug.

- **libfreshclam_internal.c:783 realloc-lose-original.** Rejected: the
  code assigns to a local `newBuffer` first and only updates
  `receivedData->buffer` on success. Proper pattern.

- **vba_extract.c:151 dangling pointer on realloc shrink.** Rejected:
  `cli_max_realloc` does not free on failure, so `newname` is still
  valid, and the `return ret ? ret : newname` fallback is correct.

- **vba_extract.c:2034, 2070 integer overflow `count * sizeof(struct
  macro)`.** Rejected: `count` is `uint16_t` (max 65535). The product
  fits comfortably in a `size_t` on any supported platform.

- **7z_iface.c:187 unchecked offset from SzArEx_Extract.** Rejected:
  these are output parameters from the vendored 7z library and are
  trusted by contract. Adding a defensive check would be hardening, not
  a bug fix.

- **clamd/clamd.c:513, 547 sprintf off-by-one.** Rejected: the realloc
  size (`i + strlen + 3`) and the subsequent writes (one `.`, `strlen`
  name chars, one `\0`, plus the trailing `.` and `\0` at 523–524) fit
  exactly with one byte to spare.

- **clamd/scanner.c:106 `strncpy` / terminator overflow.** Rejected:
  `virhash` is declared `char virhash[33]` in `scanner.h:64`.
  `MD5_HASH_SIZE * 2 == 32`, so the `virhash[32] = '\0'` write hits the
  last valid index.

- **crypto.c:1567 Windows PATHSEP malloc size.** Rejected: in C source
  `"\\"` is a one-character string; `strlen(PATHSEP) == 1` on both
  Windows and POSIX. The `+2` sizing is correct on both platforms.

- **clamd/server-th.c:860–868 signed/unsigned quota underflow.**
  Rejected after flow analysis: `buf->quota` can only reach zero from
  above because the `chunksize > quota` check runs before the subtract.
  The only ABI concern would be a pathological `long` width mismatch
  on an unsupported platform.

---

## What this audit did NOT cover

To be honest about the scope:

- **No dynamic analysis.** No fuzzing, no coverage run, no sanitizer
  build, no reproducer.
- **No Rust code** in `libclamav_rust/`. The Rust components (matcher,
  scanner, fuzz harness setup) were not reviewed.
- **No vendored libraries** (`libclamunrar`, `libclammspack`) beyond the
  C shim at `libclamav/libmspack.c`.
- **No cryptographic review.** CA-bundle handling and OpenSSL/libcrypto
  usage were only spot-checked.
- **No build-system review.** CMake files, Windows installer, and CI
  were not examined.
- **No Windows-specific paths.** `win32/compat/` and `clamonacc/` were
  only lightly grepped.
- **No consideration of how sig DB trust boundaries work** in practice —
  some of the "32-bit overflow on attacker sig" findings are only
  relevant if signed-DB verification is being bypassed.

A follow-up audit should:

1. Run the existing fuzz harnesses (`fuzz/`) on the specific files
   flagged above with AFL++ or libFuzzer with ASAN, for at least
   several CPU-days each.
2. Build with `-fsanitize=address,undefined` and run the existing unit
   test and regression suites.
3. Review the Rust crate.
4. Review libfreshclam's libcurl configuration for explicit TLS
   verification (currently relies on libcurl defaults, which are safe
   in stock builds but not all distributions).
5. Review `clamonacc` (on-access scanner) — not covered here at all and
   is kernel-adjacent on Linux.
